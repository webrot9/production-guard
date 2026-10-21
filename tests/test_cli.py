"""The command line contract CI and agents depend on: exit codes, formats, suppressions, config."""

import json
import subprocess
import sys

import pytest

from fastapi_production_guard.cli import main
from tests.helpers import FIXTURES, ROOT

LAUNCHER = ROOT / "skills" / "fastapi-production-guard" / "scripts" / "fpg.py"

VULNERABLE_ROUTE = """
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase): ...
class Doc(Base):
    __tablename__ = "docs"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

def get_current_user(): ...
CurrentUser = Annotated[object, Depends(get_current_user)]
router = APIRouter()

@router.get("/docs/{doc_id}")
async def read(doc_id: int, user: CurrentUser, db=None):
    return await db.get(Doc, doc_id){marker}
"""


def write_app(tmp_path, marker=""):
    (tmp_path / "app.py").write_text(VULNERABLE_ROUTE.replace("{marker}", marker))
    return tmp_path


def test_exit_1_on_a_high_finding_and_0_on_a_clean_tree(tmp_path, capsys):
    assert main(["scan", str(write_app(tmp_path)), "--format", "json"]) == 1
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "x.py").write_text("x = 1\n")
    assert main(["scan", str(clean)]) == 0


def test_json_report_shape(tmp_path, capsys):
    main(["scan", str(write_app(tmp_path)), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["failing"] == 1
    (finding,) = report["findings"]
    assert {"rule", "confidence", "path", "line", "message", "evidence", "fix", "docs"} <= set(finding)
    assert finding["rule"] == "FPG001" and finding["line"] == 19


def test_a_suppression_without_a_reason_does_not_suppress(tmp_path, capsys):
    assert main(["scan", str(write_app(tmp_path, "  # fpg: ignore[FPG001]")), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["findings"][0]["unjustified_suppression"] is True


def test_a_suppression_with_a_reason_does(tmp_path, capsys):
    marker = "  # fpg: ignore[FPG001] docs are shared across the workspace"
    assert main(["scan", str(write_app(tmp_path, marker)), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["suppressed"][0]["reason"] == "docs are shared across the workspace"


def test_fail_on_medium_fails_on_medium_findings(capsys):
    target = str(FIXTURES / "webhooks")
    # The only finding left once FPG002's high ones are excluded is the medium race.
    args = ["scan", target, "--rule", "FPG002", "--exclude", "vulnerable/stripe_hook.py", "--exclude", "vulnerable/paddle_hook.py"]
    assert main(args) == 0
    assert main([*args, "--fail-on", "medium"]) == 1


def test_sarif_is_valid_enough_for_code_scanning(tmp_path, capsys):
    main(["scan", str(write_app(tmp_path)), "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"FPG001", "FPG002", "FPG003"}
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 19


def test_github_annotations(tmp_path, capsys):
    main(["scan", str(write_app(tmp_path)), "--format", "github"])
    assert capsys.readouterr().out.startswith("::error file=app.py,line=19")


def test_config_in_pyproject_is_read_and_typos_are_errors(tmp_path, capsys):
    write_app(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[tool.fastapi-production-guard]\nexclude = ["app.py"]\n')
    assert main(["scan", str(tmp_path)]) == 0
    (tmp_path / "pyproject.toml").write_text('[tool.fastapi-production-guard]\nexlude = ["app.py"]\n')
    assert main(["scan", str(tmp_path)]) == 2
    assert "unknown key(s) exlude" in capsys.readouterr().err


def test_unknown_rule_is_a_usage_error(tmp_path):
    assert main(["scan", str(tmp_path), "--rule", "FPG999"]) == 2


@pytest.mark.parametrize("args", [["--version"], ["rules"]])
def test_the_skill_launcher_runs_with_no_install(args):
    # This is what an agent runs right after `npx skills add`: the folder alone.
    proc = subprocess.run([sys.executable, "-I", str(LAUNCHER), *args], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert "fastapi-production-guard" in proc.stdout or "FPG001" in proc.stdout
