#!/usr/bin/env python3
"""Run FastAPI Production Guard from the skill folder, with no install step.

    python3 scripts/fpg.py scan .

The package next to this file needs nothing but the standard library
(Python 3.11+), so an agent that has just installed the skill can run it
immediately, offline, without pip, uv or a virtualenv.
"""

import sys
from pathlib import Path

# Kept in syntax any Python 3 can parse, so an old interpreter gets this
# sentence instead of a traceback from somewhere inside the package.
if sys.version_info < (3, 11):  # noqa: UP036
    sys.exit("fastapi-production-guard needs Python 3.11 or newer (found {}.{}).".format(*sys.version_info[:2]))

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi_production_guard.cli import main

raise SystemExit(main())
