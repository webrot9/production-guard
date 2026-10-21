"""FPG001 — a user-owned row looked up by a client-supplied id, without the user.

The bug:

    @router.get("/items/{item_id}")
    async def read_item(item_id: int, user: CurrentUser, db: DB):
        return await db.get(Item, item_id)          # any user, any item

What the rule needs to see before it reports:

1. a route whose caller is identified (a principal dependency: the current
   user, their org, their token) and which is not admin-only;
2. an id the client controls — a path parameter, or an `*_id` query
   parameter — flowing into a lookup: `session.get(Model, id)`, a
   `select/query/update/delete` chain filtering on it, a model classmethod
   (`Item.get(id)`), or a call into your own code that does one of those;
3. no principal anywhere in that lookup, no comparison between the principal
   and the id before it, and no comparison between the principal and the
   row after it;
4. a model that has an owner column. A model without one is not user-owned
   and is skipped; a model the rule cannot resolve is reported at medium
   confidence.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from fastapi_production_guard.analysis import flow
from fastapi_production_guard.analysis.fastapi import DepKind, Route
from fastapi_production_guard.analysis.models import ModelFacts, Ownership, model_facts, model_name
from fastapi_production_guard.analysis.names import call_name, dotted, last_name, tokens
from fastapi_production_guard.analysis.project import FunctionInfo
from fastapi_production_guard.findings import Confidence, Finding, Location
from fastapi_production_guard.rules import ScanContext

RULE = "FPG001"

_SESSION_WORDS = frozenset({"session", "db", "sess", "conn", "connection", "tx", "uow", "s", "database"})
_SQL_MODULES = frozenset({"sa", "sqlalchemy", "sqlmodel", "sql", "orm"})
_QUERY_CONSTRUCTS = frozenset({"select", "update", "delete", "exists"})
_MODEL_METHODS = frozenset(
    {
        "get", "get_or_none", "get_or_404", "filter", "filter_by", "find", "find_one", "find_many",
        "one", "first", "select", "where", "objects", "get_by_id", "fetch", "query", "delete_many",
        "update_many",
    }
)
_LOOKUP_METHODS = frozenset({"get", "get_one", "get_or_404", "one", "first", "scalar", "scalars", "execute"})
_AUTHZ_WORDS = frozenset(
    {
        "check", "ensure", "assert", "verify", "authorize", "authorise", "authorized", "require",
        "can", "permission", "permissions", "permit", "allowed", "allow", "access", "owns", "own",
        "owner", "guard", "where", "filter", "has", "is", "belongs", "validate", "enforce",
        "visible", "accessible",
    }
)
_PUBLICITY_WORDS = frozenset({"public", "published", "visibility", "visible", "shared", "listed"})
_CLIENT_ID_SUFFIXES = ("_id", "_ids", "_uuid", "_slug")
_CLIENT_ID_NAMES = frozenset({"id", "ids", "uuid", "slug", "pk"})


@dataclass
class Lookup:
    node: ast.AST
    fn: FunctionInfo
    text: str
    origin: str  # the client-supplied parameter that reached it
    facts: ModelFacts
    model: str | None
    via: list[str] = field(default_factory=list)
    # Where the analysed function reaches the lookup: the lookup itself, or the
    # call into the helper that performs it. This is the line a person edits.
    site: ast.AST | None = None
    site_fn: FunctionInfo | None = None

    @property
    def anchor(self) -> tuple[FunctionInfo, ast.AST]:
        return (self.site_fn or self.fn, self.site or self.node)


@dataclass
class _Candidate:
    lookup: Lookup
    vars: set[str]
    cleared: bool = False


@dataclass
class _Result:
    unscoped: list[Lookup]
    admin_gated: bool = False


class _Analyzer:
    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self._memo: dict[tuple[int, int, str, frozenset[str]], list[Lookup]] = {}

    # -- entry points ---------------------------------------------------------

    def analyze(
        self,
        fn: FunctionInfo,
        tainted: dict[str, str],
        principal: set[str],
        depth: int = 0,
    ) -> _Result:
        tainted = dict(tainted)
        principal = set(principal)
        instances: dict[str, tuple[str, bool]] = {}
        candidates: list[_Candidate] = []

        for stmt in flow.statements(fn.node.body):
            test = stmt.test if isinstance(stmt, (ast.If, ast.While, ast.Assert)) else None
            if test is not None and principal:
                body = stmt.body if isinstance(stmt, (ast.If, ast.While)) else []
                if self._is_admin_gate(test, principal) and (
                    isinstance(stmt, ast.Assert) or flow.contains_raise_or_return(body)
                ):
                    return _Result([], admin_gated=True)
                # `if item_id != user.id: raise` makes the id the user's own.
                for cmp in (n for n in flow.walk(test) if isinstance(n, ast.Compare)):
                    names = flow.loaded_names(cmp)
                    if names & principal:
                        for t in names & tainted.keys():
                            del tainted[t]

            for cand in candidates:
                if not cand.cleared and cand.vars and self._clears(stmt, cand.vars, principal):
                    cand.cleared = True

            found = self._lookups_in(fn, stmt, tainted, principal, instances, depth)
            targets = flow.assigned_names(stmt)
            walrus = list(flow.walrus_bindings(stmt))
            for lk in found:
                bound = set(targets) | {name for name, _ in walrus}
                cand = _Candidate(lk, bound)
                if bound and self._clears(stmt, bound, principal, after=lk.node):
                    cand.cleared = True
                candidates.append(cand)
            if found:
                continue

            for name, value in [*((t, flow.assigned_value(stmt)) for t in targets), *walrus]:
                if value is None:
                    continue
                vn = flow.loaded_names(value)
                for cand in candidates:
                    if cand.vars & vn:
                        cand.vars.add(name)
                if vn & principal:
                    principal.add(name)
                elif vn & tainted.keys():
                    tainted[name] = tainted[next(iter(vn & tainted.keys()))]
                if isinstance(value, ast.Call):
                    cls = model_name(value.func)
                    if cls and cls in self.ctx.project.classes:
                        instances[name] = (cls, bool(flow.loaded_names(value) & principal))

        return _Result([c.lookup for c in candidates if not c.cleared])

    # -- detection ------------------------------------------------------------

    def _is_admin_gate(self, test: ast.expr, principal: set[str]) -> bool:
        for n in flow.walk(test):
            path = dotted(n)
            # `user.is_superuser`, `current_user.role == "admin"`
            if (
                path
                and path.split(".")[0] in principal
                and any(t in self.ctx.vocab.admin for p in path.split(".")[1:] for t in tokens(p))
            ):
                return True
            if (
                isinstance(n, ast.Constant)
                and isinstance(n.value, str)
                and n.value.lower() in self.ctx.vocab.admin
                and flow.loaded_names(test) & principal
            ):
                return True
        return False

    def _clears(
        self, stmt: ast.stmt, vars_: set[str], principal: set[str], after: ast.AST | None = None
    ) -> bool:
        if not principal:
            return False
        inside = {id(n) for n in ast.walk(after)} if after is not None else set()
        for n in flow.walk_statement(stmt):
            if id(n) in inside:
                continue
            if isinstance(n, ast.Compare):
                names = flow.loaded_names(n)
                if names & vars_ and names & principal:
                    return True
            elif isinstance(n, ast.Call):
                words = set(tokens(call_name(n) or ""))
                if not words & _AUTHZ_WORDS:
                    continue
                names = flow.loaded_names(n)
                if names & vars_ and names & principal:
                    return True
        return False

    def _origin(self, node: ast.AST, tainted: dict[str, str]) -> str | None:
        for name in flow.loaded_names(node):
            if name in tainted:
                return tainted[name]
        return None

    def _lookups_in(
        self,
        fn: FunctionInfo,
        stmt: ast.stmt,
        tainted: dict[str, str],
        principal: set[str],
        instances: dict[str, tuple[str, bool]],
        depth: int,
    ) -> list[Lookup]:
        if not tainted:
            return []
        out: list[Lookup] = []
        claimed: set[int] = set()
        for root in flow.chain_roots(stmt):
            chain = flow.call_chain(root)
            if not chain:
                continue
            lookup = self._query_lookup(fn, root, chain, tainted, principal)
            if lookup is None:
                lookup = self._session_get(fn, chain, tainted, principal)
            if lookup is not None:
                out.append(lookup)
            if lookup is not None or self._is_query(chain):
                claimed.update(id(n) for n in ast.walk(root))
        for node in flow.walk_statement(stmt):
            if not isinstance(node, ast.Call) or id(node) in claimed:
                continue
            lk = self._through_call(fn, node, tainted, principal, instances, depth)
            if lk is not None:
                out.append(lk)
                claimed.update(id(n) for n in ast.walk(node))
        return out

    def _is_query(self, chain: list[tuple[str, ast.Call]]) -> bool:
        return self._query_model(chain) is not None or any(n in {"where", "filter", "filter_by"} for n, _ in chain)

    def _query_model(self, chain: list[tuple[str, ast.Call]]) -> tuple[str | None, ast.Call] | None:
        """The model a query chain reads, if the chain is a query at all."""
        base_name, base = chain[0]
        recv = flow.receiver(base)
        recv_path = dotted(recv) if recv is not None else None
        if base_name in _QUERY_CONSTRUCTS and (recv is None or (recv_path or "").split(".")[-1] in _SQL_MODULES):
            arg = base.args[0] if base.args else None
            return (model_name(arg), base)
        for name, call in chain:
            if name == "query":
                r = flow.receiver(call)
                rp = dotted(r) if r is not None else ""
                if rp and set(tokens(rp.split(".")[-1])) & _SESSION_WORDS:
                    return (model_name(call.args[0]) if call.args else None, call)
        if recv_path:
            head = recv_path.split(".")[0]
            if head[:1].isupper() and base_name in _MODEL_METHODS:
                return (head, base)
        return None

    def _query_lookup(
        self,
        fn: FunctionInfo,
        root: ast.Call,
        chain: list[tuple[str, ast.Call]],
        tainted: dict[str, str],
        principal: set[str],
    ) -> Lookup | None:
        found = self._query_model(chain)
        if found is None:
            return None
        model, base = found
        origin: str | None = None
        for name, call in chain:
            args = flow.call_arguments(call)
            if call is base and name in _QUERY_CONSTRUCTS:
                args = args[1:]
            for a in args:
                origin = origin or self._origin(a, tainted)
        if origin is None:
            return None
        if flow.loaded_names(root) & principal:
            return None
        if self._filters_on_publicity(root):
            return None
        facts = model_facts(self.ctx.project, model, self.ctx.vocab)
        return Lookup(root, fn, self.ctx.snippet(root), origin, facts, model)

    def _filters_on_publicity(self, root: ast.Call) -> bool:
        for n in ast.walk(root):
            if isinstance(n, ast.Attribute) and set(tokens(n.attr)) & _PUBLICITY_WORDS:
                return True
            if isinstance(n, ast.keyword) and n.arg and set(tokens(n.arg)) & _PUBLICITY_WORDS:
                return True
        return False

    def _session_get(
        self,
        fn: FunctionInfo,
        chain: list[tuple[str, ast.Call]],
        tainted: dict[str, str],
        principal: set[str],
    ) -> Lookup | None:
        for name, call in chain:
            if name not in {"get", "get_one"} or len(call.args) < 2:
                continue
            recv = flow.receiver(call)
            recv_last = last_name(recv) if recv is not None else None
            model_arg = call.args[0]
            sessionish = bool(recv_last and set(tokens(recv_last)) & _SESSION_WORDS)
            modelish = model_name(model_arg) is not None or (
                isinstance(model_arg, ast.Attribute) and model_arg.attr in {"model", "model_class", "__model__"}
            )
            if not (sessionish or (modelish and model_name(model_arg) in self.ctx.project.classes)):
                continue
            origin = self._origin(call.args[1], tainted)
            if origin is None or flow.loaded_names(call) & principal:
                continue
            model = model_name(model_arg)
            facts = model_facts(self.ctx.project, model, self.ctx.vocab)
            return Lookup(call, fn, self.ctx.snippet(call), origin, facts, model)
        return None

    def _through_call(
        self,
        fn: FunctionInfo,
        call: ast.Call,
        tainted: dict[str, str],
        principal: set[str],
        instances: dict[str, tuple[str, bool]],
        depth: int,
    ) -> Lookup | None:
        if depth >= self.ctx.max_depth:
            return None
        args = flow.call_arguments(call)
        if not any(self._origin(a, tainted) for a in args):
            return None
        if flow.loaded_names(call) & principal:
            return None
        name = call_name(call)
        if name is None:
            return None
        recv = flow.receiver(call)
        callees: list[FunctionInfo]
        if isinstance(recv, ast.Name) and recv.id in instances:
            cls, bound = instances[recv.id]
            if bound:
                return None  # a repository constructed with the user is scoped by construction
            callees = self.ctx.project.methods_of(cls, name)
        elif isinstance(recv, ast.Name) and recv.id in {"self", "cls"} and fn.class_name:
            callees = self.ctx.project.methods_of(fn.class_name, name)
        elif isinstance(call.func, ast.Name) and name in self.ctx.project.classes:
            return None  # a constructor, not a lookup
        else:
            callees = self.ctx.project.resolve_function(fn.module, call.func, strict=isinstance(call.func, ast.Name))
        callees = [c for c in callees if c != fn]
        if not callees:
            return None

        results: list[Lookup] = []
        for callee in callees:
            mapped = self._map_arguments(call, callee, tainted)
            if not mapped:
                return None  # some definition takes the id somewhere we cannot follow
            key = (id(callee.module), callee.node.lineno, callee.name, frozenset(mapped))
            if key not in self._memo:
                self._memo[key] = self.analyze(callee, mapped, set(), depth + 1).unscoped
            inner = self._memo[key]
            if not inner:
                return None  # at least one definition is scoped: give it the benefit of the doubt
            results.append(inner[0])

        first = results[0]
        via = [f"{self.ctx.snippet(call, 60)} → {first.fn.qualname}() at {first.fn.module.rel}:{first.fn.node.lineno}", *first.via]
        origin = self._origin(call, tainted) or first.origin
        return Lookup(first.node, first.fn, first.text, origin, first.facts, first.model, via, call, fn)

    def _map_arguments(self, call: ast.Call, callee: FunctionInfo, tainted: dict[str, str]) -> dict[str, str]:
        params = [p.arg for p in [*callee.node.args.posonlyargs, *callee.node.args.args]]
        if callee.class_name and params and params[0] in {"self", "cls"}:
            params = params[1:]
        kwonly = {p.arg for p in callee.node.args.kwonlyargs}
        out: dict[str, str] = {}
        for i, a in enumerate(call.args):
            if isinstance(a, ast.Starred):
                return {}
            origin = self._origin(a, tainted)
            if origin and i < len(params):
                out[params[i]] = origin
        for kw in call.keywords:
            origin = self._origin(kw.value, tainted)
            if not origin:
                continue
            if kw.arg is None:
                return {}
            if kw.arg in params or kw.arg in kwonly:
                out[kw.arg] = origin
        return out


def _validated_by_dependency(route: Route, ctx: ScanContext) -> set[str]:
    """Path parameters a principal or permission dependency takes as its own argument.

    FastAPI passes `{organization}` to `get_organization_path(organization)`;
    that dependency exists to decide whether the caller may use that
    organization. The parameter is a tenant selector it has validated, not an
    id the handler still has to scope.
    """
    out: set[str] = set()
    params = set(route.path_params)
    module = route.function.module
    for dep in route.dependencies:
        if dep.kind not in (DepKind.PRINCIPAL, DepKind.AUTHZ) or dep.ref is None:
            continue
        for fn in ctx.project.resolve_function(module, dep.ref):
            out |= params & {p.arg for p in fn.params}
    return out


def _client_ids(route: Route, fn: FunctionInfo, ctx: ScanContext) -> dict[str, str]:
    """Parameters of `fn` the client controls: path parameters and `*_id` query parameters."""
    dep_params = {d.param for d in ctx.routes.function_dependencies(fn)}
    path_params = set(route.path_params) - _validated_by_dependency(route, ctx)
    out: dict[str, str] = {}
    for p in fn.params:
        if p.arg in dep_params or p.arg in {"self", "cls", "request", "response"}:
            continue
        if p.arg in path_params:
            out[p.arg] = p.arg
        elif p.arg.lower() in _CLIENT_ID_NAMES or p.arg.lower().endswith(_CLIENT_ID_SUFFIXES):
            if p.annotation is not None and isinstance(p.annotation, ast.Name) and p.annotation.id[:1].isupper() and p.annotation.id not in {"UUID", "UUID4", "Optional", "Annotated"}:
                continue  # a body model, not an id
            out[p.arg] = p.arg
    return out


def _verb(route: Route) -> str:
    methods = set(route.methods)
    if methods & {"delete"}:
        return "delete"
    if methods & {"put", "patch"}:
        return "modify"
    if methods & {"post"}:
        return "act on"
    return "read"


def _finding(ctx: ScanContext, route: Route, lk: Lookup, principals: list[str], via_dep: str | None) -> Finding | None:
    if lk.facts.ownership is Ownership.UNOWNED:
        return None
    if lk.facts.ownership is Ownership.UNKNOWN and not principals:
        return None
    if lk.facts.ownership is Ownership.AUTHORED and not principals:
        return None
    confidence = Confidence.HIGH if lk.facts.ownership is Ownership.OWNED else Confidence.MEDIUM
    model = lk.model or "row"
    who = f"`{principals[0]}`" if principals else "the current user"
    node = lk.node
    # Report at the line in the route (or dependency) a person would change,
    # with the callee's line in the evidence.
    anchor_fn, anchor_node = lk.anchor
    message = (
        f"{route.label}: `{lk.origin}` comes from the client and reaches `{lk.text}` "
        f"without {who} in the query or an ownership check after it. "
        f"Any signed-in user can {_verb(route)} another user's {model} by changing the id."
    )
    if not principals:
        message = (
            f"{route.label}: the route requires a signed-in user but never reads who it is, "
            f"so `{lk.text}` cannot be scoped to them. Any signed-in user can {_verb(route)} "
            f"another user's {model} by changing `{lk.origin}`."
        )
    evidence = [f"client-supplied `{lk.origin}` ({route.label})"]
    principal_deps = [d.label for d in route.dependencies if d.kind is DepKind.PRINCIPAL]
    if principal_deps:
        evidence.append("caller identified by " + ", ".join(dict.fromkeys(principal_deps)))
    if via_dep:
        evidence.append(f"through dependency `{via_dep}`")
    evidence.extend(lk.via)
    evidence.append(f"lookup `{lk.text}` at {lk.fn.module.rel}:{getattr(node, 'lineno', 0)}")
    if lk.facts.ownership is Ownership.OWNED:
        evidence.append(f"{model} is user-owned: `{lk.facts.owner_column}` ({lk.facts.where})")
    elif lk.facts.ownership is Ownership.AUTHORED:
        evidence.append(
            f"{model} records its creator (`{lk.facts.owner_column}`, {lk.facts.where}) but has no owner "
            f"column; this is an IDOR if a {model} is private to whoever created it"
        )
    else:
        evidence.append(f"could not resolve the model{f' `{lk.model}`' if lk.model else ''}; assuming it is user-owned")
    owner_col = lk.facts.owner_column or "owner_id"
    principal_name = principals[0] if principals else "current_user"
    fix = (
        f"Put the owner in the lookup itself — add `{model}.{owner_col} == {principal_name}.id` "
        f"to the query's filter — and answer 404 when nothing comes back (404, not 403, so the "
        f"id's existence does not leak). One `get_for_user()` on the repository keeps that filter "
        f"in a single place for every route."
    )
    return Finding(
        rule=RULE,
        location=Location(
            anchor_fn.module.rel,
            getattr(anchor_node, "lineno", anchor_fn.node.lineno),
            getattr(anchor_node, "col_offset", 0),
        ),
        message=message,
        confidence=confidence,
        subject=f"{route.label} ({route.function.qualname})",
        fix=fix,
        evidence=tuple(evidence),
    )


def check(ctx: ScanContext) -> list[Finding]:
    analyzer = _Analyzer(ctx)
    findings: dict[tuple[str, int, str], Finding] = {}
    for route in ctx.routes.routes:
        if route.has(DepKind.ADMIN):
            continue
        if any(d.kind is DepKind.AUTHZ and _object_level(ctx, route, d.ref) for d in route.dependencies):
            continue
        if not (route.has(DepKind.PRINCIPAL) or route.has(DepKind.AUTHZ)):
            continue
        # A role-level permission dependency still hands the handler the
        # caller (`authz: AuthorizeRead` is the subject plus its scopes), so
        # its parameter scopes a lookup as well as a user parameter does.
        principals = [
            *route.principal_params(),
            *(d.param for d in route.dependencies if d.kind is DepKind.AUTHZ and d.param),
        ]
        handler_ids = _client_ids(route, route.function, ctx)
        if handler_ids:
            result = analyzer.analyze(route.function, handler_ids, set(principals))
            if not result.admin_gated:
                for lk in result.unscoped:
                    f = _finding(ctx, route, lk, principals, None)
                    if f is not None:
                        findings.setdefault((f.location.path, f.location.line, f.message), f)
        # Dependencies that take a path parameter load the row before the
        # handler runs (`item: Item = Depends(get_item)`): analyse them too,
        # and let the handler's own ownership check clear what they load.
        for dep in route.dependencies:
            if dep.kind not in (DepKind.OTHER, DepKind.AUTHZ) or not dep.callable_name:
                continue
            refs = ctx.project.resolve_function(route.function.module, dep.ref) if dep.ref is not None else []
            for dep_fn in refs:
                ids = {k: v for k, v in _client_ids(route, dep_fn, ctx).items() if k in route.path_params}
                if not ids:
                    continue
                dep_principals = [
                    d.param
                    for d in ctx.routes.function_dependencies(dep_fn)
                    if d.kind in (DepKind.PRINCIPAL, DepKind.AUTHZ) and d.param
                ]
                if any(d.kind is DepKind.ADMIN for d in ctx.routes.function_dependencies(dep_fn)):
                    continue
                result = analyzer.analyze(dep_fn, ids, set(dep_principals))
                if result.admin_gated:
                    continue
                for lk in result.unscoped:
                    if dep.param and _handler_checks(route.function, dep.param, set(principals)):
                        continue
                    f = _finding(ctx, route, lk, dep_principals or principals, dep.callable_name)
                    if f is not None:
                        findings.setdefault((f.location.path, f.location.line, f.message), f)
    return sorted(findings.values(), key=Finding.sort_key)


def _object_level(ctx: ScanContext, route: Route, ref: ast.expr | None) -> bool:
    """Does a permission dependency look at the row the path names?

    FastAPI hands path parameters to dependencies by name, so a permission
    function that takes `item_id`, or a permission class that reads
    `request.path_params`, is checking this object rather than a role. Such
    a route is authorised per row by construction and the rule stands down.
    A permission dependency that does neither (a role check) does not.
    """
    if ref is None:
        return False
    params = set(route.path_params)
    module = route.function.module
    for node in ast.walk(ref):
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        name = last_name(node) or ""
        for fn in ctx.project.resolve_function(module, node):
            if params & {p.arg for p in fn.params} or _mentions(fn.node, params):
                return True
        for cls in ctx.project.classes.get(name, []):
            if _mentions(cls.node, params):
                return True
    return False


def _mentions(node: ast.AST, params: set[str]) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute) and n.attr == "path_params":
            return True
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value in params:
            return True
    return False


def _handler_checks(fn: FunctionInfo, var: str, principal: set[str]) -> bool:
    if not principal:
        return False
    for n in flow.walk(fn.node):
        if isinstance(n, ast.Compare):
            names = flow.loaded_names(n)
            if var in names and names & principal:
                return True
    return False
