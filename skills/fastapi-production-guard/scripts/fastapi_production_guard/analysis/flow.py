"""Just enough data flow: statements in source order, and names that carry a value.

The rules ask questions of the form "does the id from the path reach this
query without the user beside it" and "is there a lock before this read".
Answering them precisely needs a real data-flow analysis; answering them
usefully needs three things this module provides:

- the statements of a function in the order they run, top to bottom,
  descending into `if`/`for`/`with`/`try` but never into nested functions;
- the expressions directly owned by a statement (an `if` owns its test, not
  its body), so a statement is never inspected twice;
- forward propagation of a label through assignments: if `x` is tainted and
  `y = UUID(x)`, `y` is tainted too.

Order is by line number. Loops are not iterated to a fixpoint; branches are
not merged. Both simplifications under-report rather than over-report.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator

from fastapi_production_guard.analysis.names import dotted

_NESTED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def statements(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Every statement under `body`, depth-first, in source order."""
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield stmt
        for child_body in _child_bodies(stmt):
            yield from statements(child_body)


def _child_bodies(stmt: ast.stmt) -> Iterator[list[ast.stmt]]:
    if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
        yield stmt.body
        yield stmt.orelse
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        yield stmt.body
    elif isinstance(stmt, (ast.Try, ast.TryStar)):
        yield stmt.body
        for h in stmt.handlers:
            yield h.body
        yield stmt.orelse
        yield stmt.finalbody
    elif isinstance(stmt, ast.Match):
        for case in stmt.cases:
            yield case.body


def own_expressions(stmt: ast.stmt) -> list[ast.AST]:
    """The expressions a statement evaluates itself, excluding nested bodies."""
    if isinstance(stmt, (ast.If, ast.While)):
        return [stmt.test]
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return [stmt.target, stmt.iter]
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return [i for item in stmt.items for i in (item.context_expr, item.optional_vars) if i is not None]
    if isinstance(stmt, (ast.Try, ast.TryStar)):
        return [h.type for h in stmt.handlers if h.type is not None]
    if isinstance(stmt, ast.Match):
        return [stmt.subject]
    return [stmt]


def walk(node: ast.AST) -> Iterator[ast.AST]:
    """`ast.walk`, but stopping at nested functions, lambdas and classes."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        for child in ast.iter_child_nodes(current):
            if isinstance(child, _NESTED_SCOPES):
                continue
            stack.append(child)


def walk_body(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    """Every node of a function's body: not its decorators, not its signature."""
    for stmt in fn.body:
        if isinstance(stmt, _NESTED_SCOPES):
            continue
        yield from walk(stmt)


def walk_statement(stmt: ast.stmt) -> Iterator[ast.AST]:
    for expr in own_expressions(stmt):
        yield from walk(expr)


def loaded_names(node: ast.AST) -> set[str]:
    return {n.id for n in walk(node) if isinstance(n, ast.Name)}


def statement_names(stmt: ast.stmt) -> set[str]:
    out: set[str] = set()
    for expr in own_expressions(stmt):
        out |= loaded_names(expr)
    return out


def assigned_names(stmt: ast.stmt) -> list[str]:
    """Names bound by an assignment statement (not by nested bodies)."""
    targets: list[ast.expr] = []
    if isinstance(stmt, ast.Assign):
        targets = list(stmt.targets)
    elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor)):
        targets = [stmt.target]
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        targets = [i.optional_vars for i in stmt.items if i.optional_vars is not None]
    out: list[str] = []
    for t in targets:
        for n in ast.walk(t):
            if isinstance(n, ast.Name):
                out.append(n.id)
    return out


def assigned_value(stmt: ast.stmt) -> ast.expr | None:
    if isinstance(stmt, (ast.Assign, ast.AugAssign)):
        return stmt.value
    if isinstance(stmt, ast.AnnAssign):
        return stmt.value
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return stmt.iter
    if isinstance(stmt, (ast.With, ast.AsyncWith)) and stmt.items:
        return stmt.items[0].context_expr
    return None


def walrus_bindings(node: ast.AST) -> Iterator[tuple[str, ast.expr]]:
    for n in walk(node):
        if isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
            yield n.target.id, n.value


def call_chain(call: ast.Call) -> list[tuple[str, ast.Call]]:
    """`select(A).where(x).limit(1)` → [("select", …), ("where", …), ("limit", …)].

    Walks down `.func.value` from the outermost call to the base of the
    chain; the base may be a bare call (`select(...)`) or a receiver
    (`session.query(...)`), whose dotted name is kept as the first element.
    """
    out: list[tuple[str, ast.Call]] = []
    node: ast.AST = call
    while True:
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                out.append((func.attr, node))
                node = func.value
                continue
            if isinstance(func, ast.Name):
                out.append((func.id, node))
            break
        if isinstance(node, ast.Attribute):
            node = node.value
            continue
        if isinstance(node, ast.Await):
            node = node.value
            continue
        break
    out.reverse()
    return out


def chain_roots(stmt: ast.stmt) -> list[ast.Call]:
    """The outermost call of every method chain in a statement."""
    inner: set[int] = set()
    calls: list[ast.Call] = []
    for n in walk_statement(stmt):
        if isinstance(n, ast.Call):
            calls.append(n)
            node: ast.AST = n.func
            while isinstance(node, ast.Attribute):
                node = node.value
                if isinstance(node, ast.Await):
                    node = node.value
                if isinstance(node, ast.Call):
                    inner.add(id(node))
                    node = node.func
    roots = [c for c in calls if id(c) not in inner]
    roots.sort(key=lambda c: (c.lineno, c.col_offset))
    return roots


def receiver(call: ast.Call) -> ast.expr | None:
    return call.func.value if isinstance(call.func, ast.Attribute) else None


def receiver_path(call: ast.Call) -> str | None:
    r = receiver(call)
    return dotted(r) if r is not None else None


def call_arguments(call: ast.Call) -> list[ast.expr]:
    return [*call.args, *(kw.value for kw in call.keywords)]


def contains_raise_or_return(body: list[ast.stmt]) -> bool:
    return any(isinstance(s, (ast.Raise, ast.Return)) for s in statements(body))


def position(node: ast.AST) -> tuple[int, int]:
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
