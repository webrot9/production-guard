"""`fastapi-production-guard probe probes.toml`: run every probe, print verdicts, set the exit code."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi_production_guard.probes.checks import (
    ProbeResult,
    Verdict,
    run_ownership,
    run_race,
    run_webhook,
)
from fastapi_production_guard.probes.config import ProbeConfigError, load_probe_file
from fastapi_production_guard.probes.http import Client

# 0: every probe passed. 1: at least one failed. 2: the probe file is wrong.
# 3: nothing failed, but at least one probe could not run a fair test —
# a CI step must not read that as green.
EXIT_PASS, EXIT_FAIL, EXIT_CONFIG, EXIT_INCONCLUSIVE = 0, 1, 2, 3


def run_probes(path: Path, *, only: list[str] | None, output_format: str) -> int:
    try:
        pf = load_probe_file(path)
    except ProbeConfigError as exc:
        print(f"fastapi-production-guard: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    client = Client(pf.base_url, timeout=pf.timeout, auth=pf.auth)
    wanted = set(only or [])
    results: list[ProbeResult] = []
    for o in pf.ownership:
        if not wanted or o.name in wanted:
            results.append(run_ownership(client, o))
    for w in pf.webhook:
        if not wanted or w.name in wanted:
            results.append(run_webhook(client, w))
    for r in pf.race:
        if not wanted or r.name in wanted:
            results.append(run_race(client, r))
    if wanted and not results:
        print(f"fastapi-production-guard: no probe named {', '.join(sorted(wanted))}", file=sys.stderr)
        return EXIT_CONFIG

    if output_format == "json":
        print(json.dumps({"base_url": pf.base_url, "results": [r.__dict__ | {"verdict": r.verdict.value} for r in results]}, indent=2))
    else:
        print(_text(results))
    if any(r.verdict is Verdict.FAIL for r in results):
        return EXIT_FAIL
    if any(r.verdict is Verdict.INCONCLUSIVE for r in results):
        return EXIT_INCONCLUSIVE
    return EXIT_PASS


_RULE = {"ownership": "FPG001", "webhook": "FPG002", "race": "FPG003"}


def _text(results: list[ProbeResult]) -> str:
    out: list[str] = []
    for r in results:
        out.append(f"[{r.verdict.value.upper()}] {_RULE[r.kind]} {r.kind} `{r.name}`: {r.summary}")
        for e in r.evidence:
            out.append(f"    · {e}")
        for n in r.notes:
            out.append(f"    note: {n}")
        out.append("")
    counts = {v: sum(r.verdict is v for r in results) for v in Verdict}
    out.append(f"{counts[Verdict.PASS]} passed, {counts[Verdict.FAIL]} failed, {counts[Verdict.INCONCLUSIVE]} inconclusive.")
    return "\n".join(out)
