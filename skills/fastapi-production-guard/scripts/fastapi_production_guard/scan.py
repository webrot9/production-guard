"""Run the rules over a tree and apply suppressions."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from fastapi_production_guard.analysis.fastapi import RouteIndex
from fastapi_production_guard.analysis.project import ParseError, load_project
from fastapi_production_guard.config import Settings
from fastapi_production_guard.findings import Confidence, Finding, Suppressed
from fastapi_production_guard.rules import ScanContext, all_rules


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Suppressed] = field(default_factory=list)
    # Suppression markers without a reason do not suppress: an unexplained
    # `ignore` is how a real finding gets buried, so it is reported as one.
    unjustified: list[Finding] = field(default_factory=list)
    errors: list[ParseError] = field(default_factory=list)
    files: int = 0
    routes: int = 0

    def failing(self, threshold: Confidence) -> list[Finding]:
        return [f for f in self.findings if f.confidence.rank >= threshold.rank]


def scan(root: Path, settings: Settings) -> ScanResult:
    project = load_project(root, include_tests=settings.include_tests, exclude=settings.exclude)
    vocab = settings.vocabulary()
    routes = RouteIndex(project, vocab)
    ctx = ScanContext(project=project, routes=routes, vocab=vocab, max_depth=settings.max_depth)
    result = ScanResult(root=project.root, errors=project.errors, files=len(project.modules), routes=len(routes.routes))
    modules = {m.rel: m for m in project.modules}
    rules = all_rules()
    for rule_id in settings.rules:
        for finding in rules[rule_id](ctx):
            module = modules.get(finding.location.path)
            marker = module.suppression_for(finding.location.line, finding.rule) if module else None
            if marker is None:
                result.findings.append(finding)
            elif marker.reason:
                result.suppressed.append(Suppressed(finding, marker.reason))
            else:
                result.findings.append(finding)
                result.unjustified.append(finding)
    result.findings.sort(key=Finding.sort_key)
    return result
