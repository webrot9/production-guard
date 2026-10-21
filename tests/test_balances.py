"""FPG003 against the three shapes of a balance race, and the locks that fix them."""

from fastapi_production_guard.findings import Confidence
from tests.helpers import FIXTURES, run

BALANCES = FIXTURES / "balances"


def findings():
    return {(f.location.path, f.location.line): f for f in run(BALANCES, "FPG003").findings}


def test_every_unserialised_write_is_found():
    assert set(findings()) == {
        ("vulnerable/credits.py", 10),  # user.credits -= cost
        ("vulnerable/credits.py", 19),  # user.credits = remaining
        ("vulnerable/credits.py", 27),  # ledger insert after an unlocked check
        ("vulnerable/credits.py", 34),  # ledger insert sized from an unlocked read
        ("vulnerable/credits.py", 42),  # atomic UPDATE behind a stale check
        ("vulnerable/credits.py", 48),  # stale value handed to a writer
        ("safe/local_lock.py", 12),  # asyncio.Lock serialises one process only
    }


def test_confidence():
    f = findings()
    assert f[("vulnerable/credits.py", 27)].confidence is Confidence.HIGH
    assert f[("vulnerable/credits.py", 48)].confidence is Confidence.MEDIUM


def test_process_local_lock_is_named_in_the_evidence():
    f = findings()[("safe/local_lock.py", 12)]
    assert any("process-local Lock" in e for e in f.evidence)


def test_ledger_fix_names_a_lock_every_writer_takes():
    f = findings()[("vulnerable/credits.py", 27)]
    assert "with_for_update" in f.fix
    assert "pg_advisory_xact_lock" in f.fix
