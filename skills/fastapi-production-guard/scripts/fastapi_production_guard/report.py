"""Text for people, JSON for agents, SARIF for code scanning, annotations for Actions."""

from __future__ import annotations

import json
from typing import Any

from fastapi_production_guard import __version__
from fastapi_production_guard.findings import RULE_TITLES, RULES, Confidence, Finding
from fastapi_production_guard.scan import ScanResult

# The rule documents ship inside the skill, so an agent reads the same text
# offline that a person reads on GitHub.
DOCS = "https://github.com/webrot9/production-guard/blob/main/skills/fastapi-production-guard/references"


def rule_url(rule: str) -> str:
    return f"{DOCS}/{rule}.md"


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "rule": f.rule,
        "name": f.rule_name,
        "confidence": f.confidence.value,
        "path": f.location.path,
        "line": f.location.line,
        "column": f.location.column + 1,
        "subject": f.subject,
        "message": f.message,
        "evidence": list(f.evidence),
        "fix": f.fix,
        "docs": rule_url(f.rule),
    }


def to_json(result: ScanResult, threshold: Confidence) -> str:
    unjustified = {id(f) for f in result.unjustified}
    payload = {
        "tool": "fastapi-production-guard",
        "version": __version__,
        "root": str(result.root),
        "summary": {
            "files": result.files,
            "routes": result.routes,
            "findings": len(result.findings),
            "failing": len(result.failing(threshold)),
            "fail_on": threshold.value,
            "suppressed": len(result.suppressed),
            "parse_errors": len(result.errors),
        },
        "findings": [
            {**_finding_dict(f), "unjustified_suppression": id(f) in unjustified} for f in result.findings
        ],
        "suppressed": [{**_finding_dict(s.finding), "reason": s.reason} for s in result.suppressed],
        "parse_errors": [{"path": e.rel, "message": e.message} for e in result.errors],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_text(result: ScanResult, threshold: Confidence, *, color: bool) -> str:
    def c(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    out: list[str] = []
    unjustified = {id(f) for f in result.unjustified}
    for f in result.findings:
        tag = c("1;31", f.rule) if f.confidence is Confidence.HIGH else c("1;33", f.rule)
        out.append(f"{c('1', str(f.location))}  {tag} [{f.confidence.value}] {f.subject}")
        out.append(f"  {f.message}")
        for e in f.evidence:
            out.append(c("2", f"    · {e}"))
        out.append(f"  fix: {f.fix}")
        if id(f) in unjustified:
            out.append(c("33", "  note: the `# fpg: ignore[...]` marker here has no reason, so it does not suppress"))
        out.append(c("2", f"  docs: {rule_url(f.rule)}"))
        out.append("")
    if result.errors:
        shown = result.errors[:3]
        more = len(result.errors) - len(shown)
        names = ", ".join(err.rel for err in shown) + (f" and {more} more" if more else "")
        out.append(c("33", f"{len(result.errors)} file(s) skipped because they are not valid Python: {names}"))
    failing = len(result.failing(threshold))
    summary = (
        f"{len(result.findings)} finding(s), {failing} at or above `{threshold.value}`; "
        f"{len(result.suppressed)} suppressed with a reason; {result.files} files, {result.routes} routes."
    )
    if not result.findings:
        out.append(c("32", "No findings. ") + summary)
    else:
        out.append(summary)
    if result.routes == 0:
        out.append(
            c("33", "No FastAPI routes were found under this path, so FPG001 and FPG002 had nothing to check.")
        )
    return "\n".join(out)


def to_github(result: ScanResult, threshold: Confidence) -> str:
    lines: list[str] = []
    for f in result.findings:
        level = "error" if f.confidence.rank >= threshold.rank else "warning"
        msg = (f.message + " Fix: " + f.fix).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        lines.append(
            f"::{level} file={f.location.path},line={f.location.line},col={f.location.column + 1},"
            f"title={f.rule} {f.rule_name}::{msg}"
        )
    lines.append(to_text(result, threshold, color=False))
    return "\n".join(lines)


def to_sarif(result: ScanResult, threshold: Confidence) -> str:
    rules = [
        {
            "id": rule,
            "name": name,
            "shortDescription": {"text": RULE_TITLES[rule]},
            "helpUri": rule_url(rule),
            "properties": {"tags": ["security"], "precision": "medium"},
        }
        for rule, name in RULES.items()
    ]
    results = [
        {
            "ruleId": f.rule,
            "level": "error" if f.confidence.rank >= threshold.rank else "warning",
            "message": {"text": f"{f.message}\n\nFix: {f.fix}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location.path},
                        "region": {"startLine": f.location.line, "startColumn": f.location.column + 1},
                    }
                }
            ],
            "properties": {"confidence": f.confidence.value, "evidence": list(f.evidence)},
        }
        for f in result.findings
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "fastapi-production-guard",
                        "version": __version__,
                        "informationUri": "https://github.com/webrot9/production-guard",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
