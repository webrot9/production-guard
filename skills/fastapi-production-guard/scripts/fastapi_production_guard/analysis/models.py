"""ORM models: is this class a table, and does a row belong to someone?

FPG001 only matters for rows that belong to a user. `GET /plans/{plan_id}`
reading a public price plan by id is not an IDOR, and flagging it would
teach people to ignore the rule. So before reporting, the rule asks this
module whether the model has an owner: a column named like `user_id` /
`owner_id` / `org_id`, a foreign key into a users-like table, or a
relationship called `owner` or `user`. It reads SQLAlchemy (declarative and
`Mapped[]`), SQLModel and Tortoise/ormar-style field calls alike, because it
only looks at names and the strings inside `ForeignKey(...)`.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import StrEnum

from fastapi_production_guard.analysis.names import Vocabulary, last_name, string_constants
from fastapi_production_guard.analysis.project import ClassInfo, Project


class Ownership(StrEnum):
    OWNED = "owned"
    AUTHORED = "authored"  # records its creator; may or may not be private to them
    UNOWNED = "unowned"
    UNKNOWN = "unknown"


@dataclass
class ModelFacts:
    ownership: Ownership
    owner_column: str | None = None
    where: str | None = None  # "app/models.py:12" of the class definition


_FK_CALLS = frozenset({"ForeignKey", "ForeignKeyField", "ForeignKeyConstraint"})


def _class_attributes(cls: ClassInfo) -> list[tuple[str, ast.AST]]:
    out: list[tuple[str, ast.AST]] = []
    for item in cls.node.body:
        if isinstance(item, ast.Assign):
            for t in item.targets:
                if isinstance(t, ast.Name):
                    out.append((t.id, item.value))
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            out.append((item.target.id, item))
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            last_name(d) in {"declared_attr", "declared_attr.directive"} for d in item.decorator_list
        ):
            out.append((item.name, item))
    return out


def _fk_targets(node: ast.AST) -> list[str]:
    """What a column or relationship in `node` points at: "users.id" → "users"."""
    out: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            name = last_name(n.func)
            if name in _FK_CALLS:
                for s in string_constants(n):
                    out.append(s.split(".")[0])
                for a in n.args:
                    # ForeignKey(User.id)
                    if isinstance(a, ast.Attribute) and isinstance(a.value, ast.Name):
                        out.append(a.value.id)
            elif name == "relationship" and n.args:
                target = n.args[0]
                if isinstance(target, ast.Constant) and isinstance(target.value, str):
                    out.append(target.value)
                elif isinstance(target, ast.Name):
                    out.append(target.id)
            for kw in n.keywords:
                if kw.arg == "foreign_key" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    out.append(kw.value.value.split(".")[0])
    return out


def _owner_like(target: str, vocab: Vocabulary) -> bool:
    t = target.lower()
    return t in vocab.owner_tables or t.rstrip("s") in vocab.owner_tables


def is_table(project: Project, cls: ClassInfo) -> bool:
    for c in project.class_and_bases(cls.name):
        for kw in c.node.keywords:
            if kw.arg == "table" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        for name, _value in _class_attributes(c):
            if name in {"__tablename__", "__table__", "__table_args__"}:
                return True
        if any(b in {"DeclarativeBase", "Base", "Model", "DeclarativeBaseNoMeta"} for b in c.base_names):
            return True
    return False


def model_facts(project: Project, class_name: str | None, vocab: Vocabulary) -> ModelFacts:
    if not class_name:
        return ModelFacts(Ownership.UNKNOWN)
    # `schemas.Item` and `models.Item` routinely share a name; only the table counts.
    tables = [c for c in project.classes.get(class_name, []) if is_table(project, c)]
    if not tables:
        return ModelFacts(Ownership.UNKNOWN)
    cls = tables[0]
    where = f"{cls.module.rel}:{cls.node.lineno}"
    authored: tuple[str, str] | None = None
    for c in [cls, *(b for base in cls.base_names for b in project.class_and_bases(base))]:
        for name, value in _class_attributes(c):
            lname = name.lower()
            targets = _fk_targets(value)
            points_at_owner = any(_owner_like(t, vocab) for t in targets)
            if lname in vocab.author_columns:
                if points_at_owner or not targets:
                    authored = authored or (name, where)
                continue
            if lname in vocab.owner_columns:
                if points_at_owner or (not targets and lname not in {"owner", "user"}):
                    return ModelFacts(Ownership.OWNED, name, where)
                continue
            if points_at_owner and lname.endswith("_id"):
                return ModelFacts(Ownership.OWNED, name, where)
    if authored is not None:
        return ModelFacts(Ownership.AUTHORED, authored[0], authored[1])
    return ModelFacts(Ownership.UNOWNED, where=where)


def model_name(expr: ast.AST | None) -> str | None:
    """The class an expression names, when it plainly names one: `Item`, `models.Item`."""
    if isinstance(expr, ast.Name) and expr.id[:1].isupper():
        return expr.id
    if isinstance(expr, ast.Attribute) and expr.attr[:1].isupper():
        return expr.attr
    return None
