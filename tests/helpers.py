"""Shared helpers. The package is imported from the skill folder, so the
tests exercise exactly the files an agent installs."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

sys.path.insert(0, str(ROOT / "skills" / "fastapi-production-guard" / "scripts"))

from fastapi_production_guard.config import Settings  # noqa: E402
from fastapi_production_guard.scan import ScanResult, scan  # noqa: E402


def run(path: Path, *rules: str, **overrides: object) -> ScanResult:
    settings = Settings(rules=list(rules) or ["FPG001", "FPG002", "FPG003"])
    for key, value in overrides.items():
        setattr(settings, key, value)
    return scan(path, settings)


def located(result: ScanResult) -> set[tuple[str, int]]:
    return {(f.location.path, f.location.line) for f in result.findings}
