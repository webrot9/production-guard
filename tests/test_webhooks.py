"""FPG002 against webhook fixtures: three that re-run side effects, five that do not."""

from fastapi_production_guard.findings import Confidence
from tests.helpers import FIXTURES, run

WEBHOOKS = FIXTURES / "webhooks"


def by_path():
    return {f.location.path: f for f in run(WEBHOOKS, "FPG002").findings}


def test_handlers_without_dedupe_are_found():
    found = by_path()
    assert set(found) == {
        "vulnerable/stripe_hook.py",
        "vulnerable/paddle_hook.py",
        "vulnerable/clerk_hook.py",
    }


def test_side_effects_behind_a_task_queue_are_followed():
    paddle = by_path()["vulnerable/paddle_hook.py"]
    assert paddle.confidence is Confidence.HIGH
    assert any("process_paddle_event" in e for e in paddle.evidence)
    assert "Paddle" in paddle.message
    assert 'payload["event_id"]' in paddle.fix


def test_check_then_insert_without_unique_constraint_is_a_race():
    clerk = by_path()["vulnerable/clerk_hook.py"]
    assert clerk.confidence is Confidence.MEDIUM
    assert "atomic" in clerk.message


def test_atomic_claims_pass():
    # on_conflict_do_nothing, IntegrityError, SET NX, check + UNIQUE, a helper that claims.
    assert not [p for p in by_path() if p.startswith("safe/")]


def test_suppression_sits_on_the_decorator_line():
    result = run(WEBHOOKS, "FPG002")
    assert [s.finding.subject for s in result.suppressed] == ["POST /webhooks/legacy (legacy)"]


def test_an_authenticated_route_that_manages_webhooks_is_not_a_webhook(tmp_path):
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "def get_current_user(): ...\n"
        "@router.post('/webhooks/endpoints')\n"
        "async def create_endpoint(url: str, user=Depends(get_current_user), db=None):\n"
        "    db.add(Endpoint(url=url, owner=user))\n"
    )
    assert run(tmp_path, "FPG002").findings == []
