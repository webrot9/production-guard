"""FastAPI's shape, as far as the rules need it: routes, path parameters, dependencies.

A route is a function decorated with `<anything>.get/post/put/patch/delete(...)`
or `.api_route(...)`, or registered with `.add_api_route(path, endpoint)`.
Its dependencies come from four places, all of which FastAPI merges at
runtime and all of which matter here, because an admin gate on the router
is what makes an unscoped lookup legitimate:

    def handler(user: CurrentUserDep)                 parameter annotation alias
    def handler(user = Depends(get_current_user))     parameter default
    @router.get("/x", dependencies=[Depends(admin)])  decorator
    APIRouter(dependencies=[...]) / include_router(r, dependencies=[...])
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import StrEnum

from fastapi_production_guard.analysis.names import Vocabulary, dotted, last_name, tokens
from fastapi_production_guard.analysis.project import FunctionInfo, Module, Project

HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
_PATH_PARAM = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?::[^}]*)?\}")
_DEPENDS = frozenset({"Depends", "Security"})


class DepKind(StrEnum):
    PRINCIPAL = "principal"  # who is asking: the user, their org, their token
    ADMIN = "admin"  # grants access to everyone's rows
    AUTHZ = "authz"  # a permission check: object-level or role-level, to be resolved
    INFRA = "infra"  # a session, a repository, settings
    OTHER = "other"


@dataclass
class Dependency:
    kind: DepKind
    # The handler parameter it is bound to; None for decorator/router-level ones.
    param: str | None
    callable_name: str | None
    label: str  # what to print: "CurrentUserDep", "Depends(require_admin)"
    # The expression inside `Depends(...)`, for resolving the callable later.
    ref: ast.expr | None = None


@dataclass
class Route:
    function: FunctionInfo
    methods: tuple[str, ...]
    path: str
    decorator_line: int
    dependencies: list[Dependency] = field(default_factory=list)

    @property
    def path_params(self) -> list[str]:
        return _PATH_PARAM.findall(self.path)

    @property
    def label(self) -> str:
        return f"{'/'.join(m.upper() for m in self.methods)} {self.path or '/'}"

    def has(self, kind: DepKind) -> bool:
        return any(d.kind is kind for d in self.dependencies)

    def principal_params(self) -> list[str]:
        return [d.param for d in self.dependencies if d.kind is DepKind.PRINCIPAL and d.param]


def classify(words: list[str], vocab: Vocabulary) -> DepKind:
    ws = set(words)
    if ws & vocab.admin:
        return DepKind.ADMIN
    if ws & vocab.authz:
        return DepKind.AUTHZ
    if ws & vocab.infra:
        return DepKind.INFRA
    if ws & vocab.principal:
        return DepKind.PRINCIPAL
    return DepKind.OTHER


def _depends_call(node: ast.AST | None) -> ast.Call | None:
    if isinstance(node, ast.Call) and last_name(node.func) in _DEPENDS:
        return node
    return None


def _dep_ref(call: ast.Call) -> ast.expr | None:
    if call.args:
        return call.args[0]
    for kw in call.keywords:
        if kw.arg == "dependency":
            return kw.value
    return None


def _dep_target(call: ast.Call) -> str | None:
    ref = _dep_ref(call)
    return last_name(ref) if ref is not None else None


def _annotated_depends(node: ast.expr | None) -> tuple[ast.Call | None, ast.expr | None]:
    """`Annotated[User, Depends(f)]` → (Depends call, User)."""
    if not isinstance(node, ast.Subscript) or last_name(node.value) != "Annotated":
        return None, None
    elts = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
    if not elts:
        return None, None
    for meta in elts[1:]:
        call = _depends_call(meta)
        if call is not None:
            return call, elts[0]
    return None, elts[0]


class RouteIndex:
    """Every route in the project, with its dependencies resolved."""

    def __init__(self, project: Project, vocab: Vocabulary) -> None:
        self.project = project
        self.vocab = vocab
        self.routes: list[Route] = []
        # (module rel, router variable) -> (prefix, router-level dependencies)
        self._routers: dict[tuple[str, str], tuple[str, list[Dependency]]] = {}
        # child router -> (parent router or None, include prefix, include dependencies)
        self._edges: dict[tuple[str, str], tuple[tuple[str, str] | None, str, list[Dependency]]] = {}
        for m in project.modules:
            self._collect_routers(m)
        for m in project.modules:
            self._collect_includes(m)
        for m in project.modules:
            self._collect_routes(m)

    # -- dependencies ---------------------------------------------------------

    def _alias_depends(self, name: str, _depth: int = 0) -> tuple[ast.Call | None, bool]:
        """Resolve `CurrentUserDep` to the `Depends(...)` inside its Annotated alias.

        Returns (call, resolved). `resolved` is False when no definition was
        found at all, so the caller can fall back to the name alone.
        """
        defs = self.project.assignments.get(name, [])
        for _module, value in defs:
            call, _inner = _annotated_depends(value)
            if call is not None:
                return call, True
            if _depth < 3 and isinstance(value, (ast.Name, ast.Attribute)):
                target = last_name(value)
                if target and target != name:
                    nested, ok = self._alias_depends(target, _depth + 1)
                    if ok:
                        return nested, True
        return None, bool(defs)

    def dependency_from_call(self, call: ast.Call, param: str | None, extra: list[str]) -> Dependency:
        target = _dep_target(call)
        words = tokens(target or "") + [w for e in extra for w in tokens(e)]
        label = f"Depends({target})" if target else "Depends()"
        return Dependency(classify(words, self.vocab), param, target, label, _dep_ref(call))

    def param_dependency(self, arg: ast.arg, default: ast.expr | None) -> Dependency | None:
        ann = arg.annotation
        call = _depends_call(default)
        if call is not None:
            ann_name = last_name(ann) if ann is not None else None
            extra = [arg.arg] + ([ann_name] if ann_name else [])
            if not _dep_target(call) and ann_name:
                # `Depends()` with a class annotation: the class *is* the dependency.
                return Dependency(classify(tokens(ann_name) + tokens(arg.arg), self.vocab), arg.arg, ann_name, ann_name)
            return self.dependency_from_call(call, arg.arg, extra)
        inline, inner = _annotated_depends(ann)
        if inline is not None:
            inner_name = last_name(inner) if inner is not None else None
            return self.dependency_from_call(inline, arg.arg, [arg.arg] + ([inner_name] if inner_name else []))
        alias = last_name(ann) if isinstance(ann, (ast.Name, ast.Attribute)) else None
        if alias is None:
            return None
        resolved_call, found = self._alias_depends(alias)
        if resolved_call is not None:
            d = self.dependency_from_call(resolved_call, arg.arg, [arg.arg, alias])
            d.label = alias
            return d
        if not found and re.search(r"(Dep|Dependency|Depends)$", alias):
            # An alias we cannot see (defined in a library) but named like one.
            return Dependency(classify(tokens(alias) + tokens(arg.arg), self.vocab), arg.arg, None, alias)
        return None

    def _list_dependencies(self, node: ast.expr | None) -> list[Dependency]:
        if not isinstance(node, (ast.List, ast.Tuple)):
            return []
        out: list[Dependency] = []
        for elt in node.elts:
            call = _depends_call(elt)
            if call is not None:
                out.append(self.dependency_from_call(call, None, []))
        return out

    # -- routers ----------------------------------------------------------------

    def _collect_routers(self, m: Module) -> None:
        for node in m.tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if not isinstance(value, ast.Call) or last_name(value.func) not in {"APIRouter", "FastAPI"}:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            prefix = ""
            deps: list[Dependency] = []
            for kw in value.keywords:
                if kw.arg == "prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    prefix = kw.value.value
                elif kw.arg == "dependencies":
                    deps = self._list_dependencies(kw.value)
            for t in targets:
                if isinstance(t, ast.Name):
                    self._routers[(m.rel, t.id)] = (prefix, deps)

    def _collect_includes(self, m: Module) -> None:
        for node in m.nodes:
            if not isinstance(node, ast.Call) or last_name(node.func) != "include_router" or not node.args:
                continue
            ref = node.args[0]
            prefix = ""
            deps: list[Dependency] = []
            for kw in node.keywords:
                if kw.arg == "prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    prefix = kw.value.value
                elif kw.arg == "dependencies":
                    deps = self._list_dependencies(kw.value)
            recv = node.func.value if isinstance(node.func, ast.Attribute) else None
            parent = (m.rel, recv.id) if isinstance(recv, ast.Name) and (m.rel, recv.id) in self._routers else None
            for key in self._resolve_router_ref(m, ref):
                # A router mounted in two places keeps the first mount. Merging
                # them would let an admin-only mount exempt a public one.
                self._edges.setdefault(key, (parent, prefix, deps))

    def _inherited(self, key: tuple[str, str], seen: frozenset[tuple[str, str]] = frozenset()) -> tuple[str, list[Dependency]]:
        """Prefix and dependencies a router receives from every router it is mounted under."""
        edge = self._edges.get(key)
        if edge is None or key in seen:
            return "", []
        parent, prefix, deps = edge
        if parent is None:
            return prefix, list(deps)
        up_prefix, up_deps = self._inherited(parent, seen | {key})
        own_prefix, own_deps = self._routers.get(parent, ("", []))
        return up_prefix + own_prefix + prefix, [*up_deps, *own_deps, *deps]

    def _resolve_router_ref(self, m: Module, ref: ast.expr) -> list[tuple[str, str]]:
        """`admin.router` or `admin_router` in `m` → the (module, variable) that defines it."""
        path = dotted(ref)
        if path is None:
            return []
        parts = path.split(".")
        if len(parts) >= 2:
            alias, var = parts[0], parts[-1]
            imported = m.imports.get(alias)
            mod_name = imported[0] + ("." + imported[1] if imported and imported[1] else "") if imported else alias
            candidates = self.project.module_by_suffix(mod_name.lstrip("."))
            return [(c.rel, var) for c in candidates if (c.rel, var) in self._routers]
        name = parts[0]
        if (m.rel, name) in self._routers:
            return [(m.rel, name)]
        imported = m.imports.get(name)
        if imported and imported[1]:
            candidates = self.project.module_by_suffix(imported[0].lstrip("."))
            return [(c.rel, imported[1]) for c in candidates if (c.rel, imported[1]) in self._routers]
        return []

    # -- routes ---------------------------------------------------------------

    def _collect_routes(self, m: Module) -> None:
        functions: dict[str, FunctionInfo] = {}
        for node in m.nodes:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            info = FunctionInfo(m, node, None)
            # Two handlers may share a name in one module; each is its own route.
            functions.setdefault(node.name, info)
            for dec in node.decorator_list:
                route = self._route_from_decorator(info, dec)
                if route is not None:
                    self.routes.append(route)
        for node in m.nodes:
            if isinstance(node, ast.Call) and last_name(node.func) == "add_api_route" and len(node.args) >= 2:
                path = node.args[0]
                endpoint = last_name(node.args[1])
                if not (isinstance(path, ast.Constant) and isinstance(path.value, str)) or endpoint not in functions:
                    continue
                methods: tuple[str, ...] = ("get",)
                for kw in node.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        methods = tuple(
                            e.value.lower() for e in kw.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
                        ) or methods
                receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
                route = Route(functions[endpoint], methods, path.value, node.lineno)
                self._finish(route, receiver, node.keywords)
                self.routes.append(route)

    def _route_from_decorator(self, info: FunctionInfo, dec: ast.expr) -> Route | None:
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            return None
        verb = dec.func.attr
        if verb not in HTTP_METHODS and verb != "api_route":
            return None
        path_node: ast.expr | None = dec.args[0] if dec.args else None
        for kw in dec.keywords:
            if kw.arg == "path":
                path_node = kw.value
        if not (isinstance(path_node, ast.Constant) and isinstance(path_node.value, str)):
            return None
        path = path_node.value
        # `cache.get("key")` is not a route. FastAPI paths are absolute or empty.
        if path and not path.startswith("/"):
            return None
        methods: tuple[str, ...] = (verb,)
        if verb == "api_route":
            methods = ("get",)
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                    methods = tuple(
                        e.value.lower() for e in kw.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    ) or methods
        route = Route(info, methods, path, dec.lineno)
        self._finish(route, dec.func.value, dec.keywords)
        return route

    def _finish(self, route: Route, receiver: ast.expr | None, keywords: list[ast.keyword]) -> None:
        m = route.function.module
        for kw in keywords:
            if kw.arg == "dependencies":
                route.dependencies.extend(self._list_dependencies(kw.value))
        rname = receiver.id if isinstance(receiver, ast.Name) else None
        if rname is not None:
            prefix, deps = self._routers.get((m.rel, rname), ("", []))
            inc_prefix, inc_deps = self._inherited((m.rel, rname))
            route.dependencies.extend(deps)
            route.dependencies.extend(inc_deps)
            route.path = inc_prefix + prefix + route.path
        route.dependencies.extend(self.function_dependencies(route.function))

    def function_dependencies(self, fn: FunctionInfo) -> list[Dependency]:
        out: list[Dependency] = []
        args = fn.node.args
        positional = [*args.posonlyargs, *args.args]
        defaults: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
        pairs: list[tuple[ast.arg, ast.expr | None]] = list(zip(positional, defaults, strict=True))
        pairs += list(zip(args.kwonlyargs, args.kw_defaults, strict=True))
        for arg, default in pairs:
            dep = self.param_dependency(arg, default)
            if dep is not None:
                out.append(dep)
        return out
