"""The three rules, and what every one of them is handed."""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass

from fastapi_production_guard.analysis.fastapi import RouteIndex
from fastapi_production_guard.analysis.names import Vocabulary
from fastapi_production_guard.analysis.project import FunctionInfo, Project
from fastapi_production_guard.findings import Finding


@dataclass
class ScanContext:
    project: Project
    routes: RouteIndex
    vocab: Vocabulary
    # How many calls deep a rule follows a value into your own code.
    max_depth: int = 3

    def snippet(self, node: ast.AST, limit: int = 90) -> str:
        try:
            text = ast.unparse(node)
        except Exception:  # pragma: no cover - unparse is total on parsed trees
            return "<expression>"
        text = " ".join(text.split())
        return text if len(text) <= limit else text[: limit - 1] + "…"

    def where(self, fn: FunctionInfo, node: ast.AST) -> str:
        return f"{fn.module.rel}:{getattr(node, 'lineno', fn.node.lineno)}"


Rule = Callable[[ScanContext], list[Finding]]


def all_rules() -> dict[str, Rule]:
    from fastapi_production_guard.rules import balances, ownership, webhooks

    return {"FPG001": ownership.check, "FPG002": webhooks.check, "FPG003": balances.check}
