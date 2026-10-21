"""What the three distribution channels require, checked before a release can break them.

skills.sh and Codex read `skills/<name>/SKILL.md` (Agent Skills spec); the
Claude plugin directory reads `.claude-plugin/` and rejects some layouts
outright; PyPI reads `pyproject.toml`. Each has its own copy of the version.
"""

import json
import re
import tomllib

from fastapi_production_guard import __version__
from fastapi_production_guard.findings import RULES
from tests.helpers import ROOT

SKILL_DIR = ROOT / "skills" / "fastapi-production-guard"


def frontmatter() -> tuple[dict[str, object], str]:
    text = (SKILL_DIR / "SKILL.md").read_text()
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    assert match, "SKILL.md must start with YAML frontmatter"
    meta: dict[str, object] = {}
    current: dict[str, str] | None = None
    for line in match.group(1).splitlines():
        if line.startswith("  ") and current is not None:
            key, _, value = line.strip().partition(":")
            current[key] = value.strip().strip('"')
            continue
        key, _, value = line.partition(":")
        if value.strip():
            meta[key] = value.strip()
            current = None
        else:
            current = {}
            meta[key] = current
    return meta, match.group(2)


def test_versions_agree():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]
    meta, _ = frontmatter()
    assert isinstance(meta["metadata"], dict)
    assert pyproject == __version__ == plugin == meta["metadata"]["version"]
    readme = (ROOT / "README.md").read_text()
    for pinned in re.findall(r"fastapi-production-guard[@=]=?(\d+\.\d+\.\d+)", readme):
        assert pinned == __version__, "README pins an old version"
    for pinned in re.findall(r"webrot9/production-guard@v(\d+\.\d+\.\d+)", readme):
        assert pinned == __version__


def test_skill_frontmatter_follows_the_agent_skills_spec():
    meta, _body = frontmatter()
    name = str(meta["name"])
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name) and len(name) <= 64
    assert name == SKILL_DIR.name
    assert 0 < len(str(meta["description"])) <= 1024
    assert len(str(meta.get("compatibility", ""))) <= 500
    # claude.ai uploads reject keys outside the spec's six.
    assert set(meta) <= {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
    assert len((SKILL_DIR / "SKILL.md").read_text().splitlines()) < 500


def test_every_rule_has_a_reference_and_every_link_resolves():
    _, body = frontmatter()
    for rule in RULES:
        assert (SKILL_DIR / "references" / f"{rule}.md").is_file()
    for target in re.findall(r"\]\((references/[^)]+)\)", body):
        assert (SKILL_DIR / target).is_file(), target


def test_layout_the_plugin_directory_accepts():
    # A root SKILL.md hides skills/ from the skills CLI; a top-level bin/ is
    # refused by claude.ai; a root CLAUDE.md fails `claude plugin validate --strict`.
    for forbidden in ("SKILL.md", "bin", "CLAUDE.md"):
        assert not (ROOT / forbidden).exists(), forbidden
    marketplace = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    assert [p["name"] for p in marketplace["plugins"]] == [plugin["name"]]
    assert marketplace["plugins"][0]["source"] == "./"
    assert plugin["license"] == "MIT" and (ROOT / "LICENSE").is_file()
    words = re.sub(r"```.*?```", "", (ROOT / "README.md").read_text(), flags=re.S).split()
    assert len(words) >= 40


def test_the_skill_folder_is_self_contained():
    # `npx skills add` copies this folder and nothing else.
    for path in SKILL_DIR.rglob("*.py"):
        text = path.read_text()
        assert "from tests" not in text and "import tests" not in text, path
