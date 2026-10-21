"""`[tool.fastapi-production-guard]` in pyproject.toml, or a standalone `fpg.toml`.

    [tool.fastapi-production-guard]
    exclude = ["scripts/*", "app/legacy/*"]   # globs, relative to the scanned root
    fail-on = "medium"                        # default "high": medium findings are printed, not failed
    principal-words = ["merchant"]            # dependencies that identify the caller
    admin-words = ["backoffice"]              # dependencies that grant access to everything
    owner-columns = ["shop_id"]               # columns that make a row user-owned
    balance-fields = ["gems"]                 # fields that hold a spendable balance
    max-depth = 3                             # calls followed into your own code

Every list extends the built-in vocabulary rather than replacing it, so a
configuration file can only make the rules see more, never less.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi_production_guard.analysis.names import Vocabulary
from fastapi_production_guard.findings import RULES, Confidence


class ConfigError(Exception):
    pass


@dataclass
class Settings:
    exclude: list[str] = field(default_factory=list)
    include_tests: bool = False
    # Medium findings rest on one assumption the scan could not check (a model
    # it could not resolve, a creator column that may or may not mean
    # private). They are printed for review; failing CI on them by default
    # would teach people to ignore the tool.
    fail_on: Confidence = Confidence.HIGH
    rules: list[str] = field(default_factory=lambda: list(RULES))
    principal_words: frozenset[str] = frozenset()
    admin_words: frozenset[str] = frozenset()
    owner_columns: frozenset[str] = frozenset()
    balance_fields: frozenset[str] = frozenset()
    max_depth: int = 3
    source: str | None = None

    def vocabulary(self) -> Vocabulary:
        return Vocabulary(
            extra_principal=self.principal_words,
            extra_admin=self.admin_words,
            extra_owner_columns=self.owner_columns,
            extra_balance=self.balance_fields,
        )


_KEYS = {
    "exclude", "include-tests", "fail-on", "rules", "principal-words", "admin-words",
    "owner-columns", "balance-fields", "max-depth",
}


def _words(raw: Any, key: str) -> frozenset[str]:
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise ConfigError(f"`{key}` must be a list of strings")
    return frozenset(x.lower() for x in raw)


def _from_table(table: dict[str, Any], source: str) -> Settings:
    unknown = set(table) - _KEYS
    if unknown:
        raise ConfigError(f"{source}: unknown key(s) {', '.join(sorted(unknown))}")
    s = Settings(source=source)
    if "exclude" in table:
        s.exclude = sorted(_words(table["exclude"], "exclude"))
    if "include-tests" in table:
        s.include_tests = bool(table["include-tests"])
    if "fail-on" in table:
        try:
            s.fail_on = Confidence(str(table["fail-on"]).lower())
        except ValueError as exc:
            raise ConfigError(f"{source}: `fail-on` must be \"high\" or \"medium\"") from exc
    if "rules" in table:
        rules = [r.upper() for r in _words(table["rules"], "rules")]
        bad = [r for r in rules if r not in RULES]
        if bad:
            raise ConfigError(f"{source}: unknown rule(s) {', '.join(bad)}")
        s.rules = sorted(rules)
    s.principal_words = _words(table.get("principal-words", []), "principal-words")
    s.admin_words = _words(table.get("admin-words", []), "admin-words")
    s.owner_columns = _words(table.get("owner-columns", []), "owner-columns")
    s.balance_fields = _words(table.get("balance-fields", []), "balance-fields")
    if "max-depth" in table:
        depth = table["max-depth"]
        if not isinstance(depth, int) or not 0 <= depth <= 8:
            raise ConfigError(f"{source}: `max-depth` must be an integer between 0 and 8")
        s.max_depth = depth
    return s


def load_settings(root: Path, explicit: Path | None = None) -> Settings:
    base = root if root.is_dir() else root.parent
    candidates = [explicit] if explicit else [base / "fpg.toml", base / "pyproject.toml"]
    for path in candidates:
        if path is None or not path.is_file():
            if explicit is not None:
                raise ConfigError(f"config file not found: {explicit}")
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: {exc}") from exc
        if path.name == "pyproject.toml":
            table = data.get("tool", {}).get("fastapi-production-guard")
            if table is None:
                continue
        else:
            table = data.get("tool", {}).get("fastapi-production-guard", data)
        if not isinstance(table, dict):
            raise ConfigError(f"{path}: [tool.fastapi-production-guard] must be a table")
        return _from_table(table, str(path))
    return Settings()
