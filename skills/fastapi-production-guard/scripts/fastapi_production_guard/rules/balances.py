"""FPG003 — a balance is read, then written, with nothing serialising the two.

Two requests that each spend the last credit both read "1 left", both pass
the check, both spend. The pattern has three shapes, and the rule knows all
three:

    user.credits -= cost                      # a counter: read-modify-write
    await session.commit()

    balance = await get_balance(user_id)      # a ledger: check, then insert
    if balance < cost: raise ...
    session.add(CreditTransaction(delta=-cost))

    if user.credits < cost: raise ...         # an atomic UPDATE behind a stale check
    await db.execute(update(User).values(credits=User.credits - cost))

What makes them safe, and what the rule accepts:

- the row is read under a lock: `.with_for_update()`, `SELECT ... FOR UPDATE`,
  `session.get(..., with_for_update=True)`, a `lock_*()` helper, an advisory
  lock, a distributed lock (`redis.lock(...)`), or SERIALIZABLE isolation;
- the guard lives in the UPDATE itself:
  `update(User).where(User.credits >= cost).values(credits=User.credits - cost)`
  and the row count is checked;
- optimistic locking (`version_id_col`) on the model.

`asyncio.Lock()` and `threading.Lock()` do not count: they serialise one
process, and production runs several.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from fastapi_production_guard.analysis import flow
from fastapi_production_guard.analysis.models import is_table, model_name
from fastapi_production_guard.analysis.names import call_name, dotted, last_name, tokens
from fastapi_production_guard.analysis.project import FunctionInfo, is_test_path
from fastapi_production_guard.findings import Confidence, Finding, Location
from fastapi_production_guard.rules import ScanContext

RULE = "FPG003"

_LEDGER_WORDS = frozenset(
    {"credit", "credits", "ledger", "transaction", "transactions", "balance", "wallet", "points", "usage",
     "quota", "movement", "movements", "debit", "spend", "charge", "allowance"}
)
# Nouns that, after a balance word in a function name, say the function
# returns a *thing*: `get_balance_transaction` fetches a record, not a number.
_OBJECT_NOUNS = frozenset(
    {"transaction", "transactions", "entry", "entries", "record", "records", "row", "rows", "object",
     "objects", "history", "log", "logs", "event", "events", "item", "items", "summary", "report",
     "wallet", "wallets", "model", "schema", "response", "page", "list", "card"}
)
_AMOUNT_KEYS = frozenset({"amount", "delta", "credits", "points", "quantity", "value", "change", "cost", "units"})
_WRITE_VERBS = frozenset(
    {"grant", "deduct", "add", "consume", "spend", "charge", "refund", "set", "update", "expire", "reset",
     "increment", "decrement", "create", "record", "apply", "debit", "credit", "burn", "award", "topup", "top",
     "use", "reserve", "release", "transfer", "adjust", "insert", "save", "write"}
)
_READ_VERBS = frozenset({"get", "fetch", "read", "load", "compute", "calculate", "current", "remaining", "available", "check", "has", "balance", "of", "sum", "total"})
_DB_CALLS = frozenset({"commit", "flush", "execute", "add", "add_all", "save", "refresh", "scalar", "scalars", "merge"})
_LOCAL_LOCKS = frozenset({"Lock", "RLock", "Semaphore", "BoundedSemaphore", "Condition"})


@dataclass
class _Read:
    node: ast.AST
    text: str
    obj: str | None  # `user` in `user.credits`
    field: str | None


@dataclass
class _Facts:
    lock_line: int | None
    local_lock: bool
    db_context: bool


class _Rule:
    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self.vocab = ctx.vocab
        self._writer_memo: dict[FunctionInfo, bool] = {}

    # -- vocabulary -------------------------------------------------------------

    def _is_balance_read_call(self, name: str) -> bool:
        words = tokens(name)
        positions = [i for i, w in enumerate(words) if w in self.vocab.balance]
        if not positions:
            return False
        if set(words[positions[-1] + 1 :]) & _OBJECT_NOUNS:
            return False
        return not (set(words) & _WRITE_VERBS) or bool(set(words) & {"get", "fetch", "read", "current", "remaining", "available", "compute", "calculate"})

    def _is_table(self, name: str | None) -> bool | None:
        """True/False when the class is found; None when it is not a class of this project."""
        if not name or name not in self.ctx.project.classes:
            return None
        return any(is_table(self.ctx.project, c) for c in self.ctx.project.classes[name])

    def _is_ledger_model(self, name: str | None) -> bool:
        if not self._is_table(name):
            return False
        assert name is not None
        return bool(set(tokens(name)) & _LEDGER_WORDS)

    def _is_lock_call(self, call: ast.Call) -> bool:
        name = call_name(call) or ""
        lowered = name.lower()
        if name in _LOCAL_LOCKS:
            return False
        if "for_update" in lowered or "advisory" in lowered:
            return True
        if any(kw.arg in {"with_for_update", "for_update", "nowait", "skip_locked"} for kw in call.keywords):
            return True
        return "lock" in tokens(name) or "locked" in tokens(name)

    def _facts(self, fn: FunctionInfo) -> _Facts:
        lock_line: int | None = None
        local = False
        db = any(p.arg in {"session", "db", "db_session", "conn", "connection", "tx", "uow"} for p in fn.params)
        for n in flow.walk_body(fn.node):
            line = getattr(n, "lineno", 0)
            if isinstance(n, ast.Call):
                name = call_name(n) or ""
                if name in _LOCAL_LOCKS:
                    local = True
                elif self._is_lock_call(n):
                    lock_line = min(lock_line or line, line)
                if name in _DB_CALLS:
                    db = True
            elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                text = n.value.upper()
                if (
                    "FOR UPDATE" in text
                    or "FOR NO KEY UPDATE" in text
                    or "SERIALIZABLE" in text
                    or ("ADVISORY" in text and "LOCK" in text)
                ):
                    lock_line = min(lock_line or line, line)
            elif isinstance(n, (ast.With, ast.AsyncWith)) and not local:
                # `async with _lock:` where `_lock = asyncio.Lock()` lives at module level
                local = any(isinstance(m, ast.Call) and call_name(m) in _LOCAL_LOCKS for m in fn.module.nodes)
        return _Facts(lock_line, local, db)

    # -- the analysis -------------------------------------------------------------

    def _loaded_locked(self, fn: FunctionInfo, obj: str, before: int) -> bool:
        """Was `obj` assigned from a query that locks the row?"""
        for stmt in flow.statements(fn.node.body):
            if getattr(stmt, "lineno", 0) >= before:
                break
            if obj in flow.assigned_names(stmt):
                value = flow.assigned_value(stmt)
                if value is not None and any(isinstance(c, ast.Call) and self._is_lock_call(c) for c in ast.walk(value)):
                    return True
            for n in flow.walk_statement(stmt):
                # session.refresh(user, with_for_update=True)
                if (
                    isinstance(n, ast.Call)
                    and call_name(n) == "refresh"
                    and n.args
                    and isinstance(n.args[0], ast.Name)
                    and n.args[0].id == obj
                    and self._is_lock_call(n)
                ):
                    return True
        return False

    def _optimistic(self, cls_name: str | None) -> bool:
        if not cls_name:
            return False
        for cls in self.ctx.project.class_and_bases(cls_name):
            for n in ast.walk(cls.node):
                if isinstance(n, ast.Constant) and n.value == "version_id_col":
                    return True
        return False

    def analyze(self, fn: FunctionInfo) -> list[Finding]:
        facts = self._facts(fn)
        derived: dict[str, _Read] = {}  # variable -> the balance read it came from
        attr_reads: dict[tuple[str, str], _Read] = {}  # (obj, field) -> first read
        checked: list[tuple[int, _Read]] = []
        findings: list[Finding] = []
        reported: set[int] = set()

        def locked_before(line: int) -> bool:
            return facts.lock_line is not None and facts.lock_line <= line

        for stmt in flow.statements(fn.node.body):
            line = getattr(stmt, "lineno", 0)
            # 1. reads in this statement
            reads_here: list[_Read] = []
            method_refs = {id(c.func) for c in flow.walk_statement(stmt) if isinstance(c, ast.Call)}
            for n in flow.walk_statement(stmt):
                if (
                    isinstance(n, ast.Attribute)
                    and isinstance(n.ctx, ast.Load)
                    and id(n) not in method_refs
                    and self.vocab.is_balance_field(n.attr)
                ):
                    obj = dotted(n.value)
                    head = obj.split(".")[0] if obj else ""
                    if obj and head[:1].islower() and self._is_table(self._class_of(fn, head)) is not False:
                        r = _Read(n, self.ctx.snippet(n, 50), obj, n.attr)
                        attr_reads.setdefault((obj, n.attr), r)
                        reads_here.append(r)
                elif isinstance(n, ast.Call):
                    name = call_name(n) or ""
                    if (self._is_balance_read_call(name) and not self._writes_balance_by_name(fn, n)) or (name == "sum" and isinstance(n.func, ast.Attribute) and any(
                        # SQL `func.sum(Ledger.delta)`; the builtin `sum()` adds up what is already in memory.
                        isinstance(a, ast.Attribute) and (a.attr in _AMOUNT_KEYS or self.vocab.is_balance_field(a.attr))
                        for a in ast.walk(n)
                    )):
                        reads_here.append(_Read(n, self.ctx.snippet(n, 50), None, None))
            # 2. checks: a comparison that involves a balance
            test = stmt.test if isinstance(stmt, (ast.If, ast.While, ast.Assert)) else None
            if test is not None:
                names = flow.loaded_names(test)
                for var in names & derived.keys():
                    checked.append((line, derived[var]))
                for r in reads_here:
                    if r.obj is not None:
                        checked.append((line, r))
            # 3. writes
            for finding in self._writes(fn, stmt, derived, attr_reads, checked, facts, locked_before):
                if finding.location.line not in reported:
                    reported.add(finding.location.line)
                    findings.append(finding)
            # 4. propagate: a variable assigned from a read (or from a derived value) is derived
            value = flow.assigned_value(stmt) if not isinstance(stmt, (ast.For, ast.AsyncFor, ast.With, ast.AsyncWith)) else None
            targets = flow.assigned_names(stmt) if value is not None else []
            if value is not None and targets:
                vnames = flow.loaded_names(value)
                source: _Read | None = None
                for r in reads_here:
                    if any(n is r.node for n in ast.walk(value)):
                        source = r
                        break
                if source is None:
                    for var in vnames & derived.keys():
                        source = derived[var]
                        break
                if source is not None:
                    for t in targets:
                        derived[t] = source
        return findings

    def _writes_balance_by_name(self, fn: FunctionInfo, call: ast.Call) -> bool:
        callees = self._callees(fn, call)
        return any(self._writes_balance(c) for c in callees)

    def _callees(self, fn: FunctionInfo, call: ast.Call) -> list[FunctionInfo]:
        recv = flow.receiver(call)
        if isinstance(recv, ast.Name) and recv.id in {"self", "cls"} and fn.class_name:
            return self.ctx.project.methods_of(fn.class_name, call_name(call) or "")
        found = self.ctx.project.resolve_function(fn.module, call.func, strict=isinstance(call.func, ast.Name))
        return found if len({(f.module.rel, f.qualname) for f in found}) == 1 else []

    def _writes_balance(self, fn: FunctionInfo, depth: int = 0) -> bool:
        """Does `fn` (or what it calls) change a balance?"""
        if fn in self._writer_memo:
            return self._writer_memo[fn]
        self._writer_memo[fn] = False  # cycles
        result = False
        for n in flow.walk_body(fn.node):
            if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                if any(isinstance(t, ast.Attribute) and self.vocab.is_balance_field(t.attr) for t in targets):
                    result = True
            elif isinstance(n, ast.Call):
                if self._is_ledger_insert(n):
                    result = True
                elif depth < self.ctx.max_depth:
                    for c in self._callees(fn, n):
                        if c != fn and self._writes_balance(c, depth + 1):
                            result = True
            if result:
                break
        self._writer_memo[fn] = result
        return result

    def _is_ledger_insert(self, call: ast.Call) -> bool:
        name = model_name(call.func)
        if not self._is_ledger_model(name):
            return False
        return any(kw.arg in _AMOUNT_KEYS or (kw.arg and self.vocab.is_balance_field(kw.arg)) for kw in call.keywords)

    def _writes(
        self,
        fn: FunctionInfo,
        stmt: ast.stmt,
        derived: dict[str, _Read],
        attr_reads: dict[tuple[str, str], _Read],
        checked: list[tuple[int, _Read]],
        facts: _Facts,
        locked_before: object,
    ) -> list[Finding]:
        assert callable(locked_before)
        out: list[Finding] = []
        line = getattr(stmt, "lineno", 0)

        # W1: obj.credits -= n / obj.credits = obj.credits - n / obj.credits = derived
        if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for t in targets:
                if not (isinstance(t, ast.Attribute) and self.vocab.is_balance_field(t.attr)):
                    continue
                obj = dotted(t.value)
                if not obj:
                    continue
                value = stmt.value
                rmw = isinstance(stmt, ast.AugAssign)
                read: _Read | None = attr_reads.get((obj, t.attr))
                if value is not None and not rmw:
                    vn = flow.loaded_names(value)
                    if any(dotted(n) == f"{obj}.{t.attr}" for n in ast.walk(value)) or vn & derived.keys():
                        rmw = True
                        read = read or next((derived[v] for v in vn & derived.keys()), None)
                if not rmw:
                    continue
                if not facts.db_context:
                    continue  # an in-memory object, not a row
                head = obj.split(".")[0]
                if self._is_table(self._class_of(fn, head)) is False:
                    continue  # a request schema or a dataclass, not a row
                start = read.node.lineno if read is not None and hasattr(read.node, "lineno") else line
                if locked_before(start) or self._loaded_locked(fn, head, line):
                    continue
                if self._optimistic(self._class_of(fn, head)):
                    continue
                in_model = head == "self" and fn.class_name is not None
                confidence = Confidence.MEDIUM if in_model else Confidence.HIGH
                was_checked = any(r.obj == obj for _l, r in checked)
                message = (
                    f"`{self.ctx.snippet(stmt, 60)}` reads the balance and writes it back with nothing holding "
                    f"the row in between. Two concurrent requests both read the same value; one write is lost"
                    + (", and both pass the balance check, so the balance is overspent." if was_checked else ".")
                )
                if in_model:
                    message += " This is a method on the model, so the fix belongs to whoever loads the row."
                out.append(self._finding(fn, stmt, message, confidence, read, facts, kind="counter"))

        for n in flow.walk_statement(stmt):
            if not isinstance(n, ast.Call):
                continue
            # W2: a ledger row built from, or after checking, an unlocked balance read
            if self._is_ledger_insert(n):
                args_derived = flow.loaded_names(n) & derived.keys()
                prior = [r for at, r in checked if at <= line]
                source = derived[next(iter(args_derived))] if args_derived else (prior[-1] if prior else None)
                if source is None:
                    continue
                start = getattr(source.node, "lineno", line)
                if locked_before(start):
                    continue
                message = (
                    f"`{self.ctx.snippet(n, 60)}` writes a ledger row "
                    + ("sized from" if args_derived else "after checking")
                    + f" a balance read by `{source.text}`, and nothing locks the balance between the read and the "
                    "insert. Two concurrent requests both see the same balance, both pass, and both insert: "
                    "the balance goes below zero."
                )
                out.append(self._finding(fn, n, message, Confidence.HIGH, source, facts, kind="ledger"))
                continue
            # W3: update(...).values(credits=Model.credits - n) behind a stale check, without a guard in WHERE
            if call_name(n) == "values":
                chain = flow.call_chain(n)
                if not chain or chain[0][0] != "update":
                    continue
                balance_cols = [kw.arg for kw in n.keywords if kw.arg and self.vocab.is_balance_field(kw.arg)]
                if not balance_cols:
                    continue
                guarded = any(
                    name in {"where", "filter", "filter_by"}
                    and any(
                        isinstance(c, ast.Compare) and any(isinstance(a, ast.Attribute) and a.attr in balance_cols for a in ast.walk(c))
                        for c in ast.walk(call)
                    )
                    for name, call in chain
                )
                prior = [r for at, r in checked if at <= line]
                if guarded or not prior or locked_before(getattr(prior[-1].node, "lineno", line)):
                    continue
                message = (
                    f"The UPDATE is atomic but its guard is not: the balance was checked in Python "
                    f"(`{prior[-1].text}`) and the UPDATE's WHERE clause does not repeat the check, so two "
                    f"concurrent requests both pass and both subtract."
                )
                out.append(self._finding(fn, n, message, Confidence.HIGH, prior[-1], facts, kind="update"))
                continue
            # W4: a stale balance handed to a function that writes balances
            if flow.loaded_names(n) & derived.keys():
                callees = self._callees(fn, n)
                if callees and any(self._writes_balance(c) for c in callees):
                    source = derived[next(iter(flow.loaded_names(n) & derived.keys()))]
                    start = getattr(source.node, "lineno", line)
                    if locked_before(start):
                        continue
                    target = callees[0]
                    message = (
                        f"`{self.ctx.snippet(n, 60)}` passes a value computed from an unlocked balance read "
                        f"(`{source.text}`) to {target.qualname}(), which writes the balance. A concurrent spend "
                        f"between the read and the write makes the value stale."
                    )
                    out.append(self._finding(fn, n, message, Confidence.MEDIUM, source, facts, kind="stale"))
        return out

    def _class_of(self, fn: FunctionInfo, var: str) -> str | None:
        """The class of a variable, when the code says it plainly."""
        if var == "self":
            return fn.class_name
        for p in fn.params:
            if p.arg == var and p.annotation is not None:
                ann = p.annotation
                if isinstance(ann, ast.BinOp):  # `Account | None`
                    ann = ann.left
                if isinstance(ann, ast.Subscript) and last_name(ann.value) in {"Optional", "Annotated"}:
                    ann = ann.slice.elts[0] if isinstance(ann.slice, ast.Tuple) else ann.slice
                return model_name(ann) or last_name(ann)
        for stmt in flow.statements(fn.node.body):
            if var in flow.assigned_names(stmt):
                value = flow.assigned_value(stmt)
                if isinstance(value, ast.Await):
                    value = value.value
                if isinstance(value, ast.Call):
                    if model_name(value.func):
                        return model_name(value.func)  # `x = Model(...)`
                    if call_name(value) in {"get", "get_one"} and value.args and model_name(value.args[0]):
                        return model_name(value.args[0])  # `x = session.get(Model, id)`
                return None
        return None

    def _finding(
        self, fn: FunctionInfo, node: ast.AST, message: str, confidence: Confidence, read: _Read | None, facts: _Facts, *, kind: str
    ) -> Finding:
        evidence = []
        if read is not None:
            evidence.append(f"balance read: `{read.text}` at {fn.module.rel}:{getattr(read.node, 'lineno', '?')}")
        evidence.append(f"write: `{self.ctx.snippet(node, 70)}` at {fn.module.rel}:{getattr(node, 'lineno', '?')}")
        if facts.local_lock:
            evidence.append("a process-local Lock is used here; it does not serialise requests served by other workers")
        else:
            evidence.append(f"no row lock, advisory lock or SERIALIZABLE isolation before the read in {fn.qualname}()")
        fixes = {
            "counter": (
                "Do the check and the write in one statement: `update(User).where(User.id == uid, "
                "User.credits >= cost).values(credits=User.credits - cost)` and treat rowcount 0 as "
                "insufficient credits — or load the row with `.with_for_update()` before reading it. Better "
                "still, keep an append-only ledger and derive the balance."
            ),
            "ledger": (
                "Take a lock that every writer of this balance takes, before reading it: `SELECT ... FOR "
                "UPDATE` on the owner's row (`select(User.id).where(User.id == uid).with_for_update()`) or "
                "`pg_advisory_xact_lock(...)` keyed on the owner. Then read, check and insert inside that "
                "transaction."
            ),
            "update": (
                "Move the check into the UPDATE: `.where(Model.credits >= cost)`, then treat rowcount 0 as "
                "insufficient credits."
            ),
            "stale": (
                "Take the lock before computing the value, not inside the callee, so the read and the write "
                "see the same balance — or move the computation into the function that holds the lock."
            ),
        }
        return Finding(
            rule=RULE,
            location=Location(fn.module.rel, getattr(node, "lineno", fn.node.lineno), getattr(node, "col_offset", 0)),
            message=message,
            confidence=confidence,
            subject=f"{fn.qualname}() in {fn.module.rel}",
            fix=fixes[kind],
            evidence=tuple(evidence),
        )


def check(ctx: ScanContext) -> list[Finding]:
    rule = _Rule(ctx)
    findings: list[Finding] = []
    # Most functions never mention a balance. A substring test on the source
    # is a cheap way not to analyse them, and it can only over-include.
    words = re.compile("|".join(sorted(re.escape(w) for w in ctx.vocab.balance)), re.IGNORECASE)
    for fn in ctx.project.all_functions():
        if is_test_path(fn.module.rel):
            continue
        end = getattr(fn.node, "end_lineno", None) or fn.node.lineno
        if not words.search("\n".join(fn.module.lines[fn.node.lineno - 1 : end])):
            continue
        findings.extend(rule.analyze(fn))
    return sorted(findings, key=Finding.sort_key)
