"""Command line: `scan`, `probe`, `rules`."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from fastapi_production_guard import __version__
from fastapi_production_guard.config import ConfigError, load_settings
from fastapi_production_guard.findings import RULE_TITLES, RULES, Confidence


def _scan(args: argparse.Namespace) -> int:
    from fastapi_production_guard import report
    from fastapi_production_guard.scan import scan

    root = Path(args.path)
    if not root.exists():
        print(f"fastapi-production-guard: no such path: {root}", file=sys.stderr)
        return 2
    try:
        settings = load_settings(root, Path(args.config) if args.config else None)
    except ConfigError as exc:
        print(f"fastapi-production-guard: {exc}", file=sys.stderr)
        return 2
    if args.rule:
        wanted = [r.upper() for r in args.rule]
        bad = [r for r in wanted if r not in RULES]
        if bad:
            print(f"fastapi-production-guard: unknown rule(s): {', '.join(bad)}", file=sys.stderr)
            return 2
        settings.rules = wanted
    if args.include_tests:
        settings.include_tests = True
    settings.exclude = [*settings.exclude, *(args.exclude or [])]
    threshold = Confidence(args.fail_on) if args.fail_on else settings.fail_on

    result = scan(root, settings)
    fmt = args.format
    if fmt == "json":
        text = report.to_json(result, threshold)
    elif fmt == "sarif":
        text = report.to_sarif(result, threshold)
    elif fmt == "github":
        text = report.to_github(result, threshold)
    else:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        text = report.to_text(result, threshold, color=color)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if result.failing(threshold) else 0


def _rules(_args: argparse.Namespace) -> int:
    for rule, name in RULES.items():
        print(f"{rule}  {name}\n        {RULE_TITLES[rule]}")
    return 0


def _probe(args: argparse.Namespace) -> int:
    from fastapi_production_guard.probes.runner import run_probes

    code: int = run_probes(Path(args.config), only=args.only, output_format=args.format)
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fastapi-production-guard",
        description=(
            "Three executed checks for FastAPI apps. `scan` reads your source; "
            "`probe` sends real requests to a running app."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="analyse source code (exit 1 when a finding fails the threshold)")
    s.add_argument("path", nargs="?", default=".", help="project root or file (default: .)")
    s.add_argument("--format", choices=["text", "json", "sarif", "github"], default="text")
    s.add_argument("--output", "-o", help="write the report to a file instead of stdout")
    s.add_argument("--fail-on", choices=["high", "medium"], help="lowest confidence that fails the scan (default: high)")
    s.add_argument("--rule", action="append", help="run only this rule (repeatable)")
    s.add_argument("--exclude", action="append", help="glob of paths to skip, relative to the root (repeatable)")
    s.add_argument("--include-tests", action="store_true", help="also scan test files")
    s.add_argument("--config", help="explicit config file (default: fpg.toml or pyproject.toml)")
    s.set_defaults(func=_scan)

    p = sub.add_parser("probe", help="send real requests to a running app and check the behaviour")
    p.add_argument("config", help="probe file (TOML); format in skills/fastapi-production-guard/references/probes.md")
    p.add_argument("--only", action="append", help="run only the probe with this name (repeatable)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.set_defaults(func=_probe)

    r = sub.add_parser("rules", help="list the rules")
    r.set_defaults(func=_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    code: int = args.func(args)
    return code
