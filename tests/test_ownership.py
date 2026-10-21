"""FPG001 against fixtures that encode one idea each.

Every vulnerable handler in `fixtures/ownership/vulnerable/` must be found,
at the line a person would change; nothing in `fixtures/ownership/safe/`
may be. The safe file is the list of things the rule has learned not to
flag — each one a false positive it once produced or would have.
"""

from fastapi_production_guard.findings import Confidence
from tests.helpers import FIXTURES, located, run

OWNERSHIP = FIXTURES / "ownership"

EXPECTED = {
    ("vulnerable/routes.py", 13),  # db.get(Item, item_id)
    ("vulnerable/routes.py", 18),  # select(...).where(Item.id == item_id)
    ("vulnerable/routes.py", 25),  # delete(...).where(...)
    ("vulnerable/routes.py", 30),  # through a module-level helper
    ("vulnerable/routes.py", 36),  # through a repository method
    ("vulnerable/routes.py", 41),  # a None check is not an ownership check
    ("vulnerable/routes.py", 48),  # sync session, add_api_route, creator column
    ("vulnerable/routes.py", 55),  # inside a dependency that loads the row
    ("vulnerable/routes.py", 71),  # router-level auth, no user variable
    ("vulnerable/routes.py", 76),  # the owner id itself comes from the path
}


def test_every_vulnerable_handler_is_found_and_nothing_else():
    result = run(OWNERSHIP, "FPG001")
    assert located(result) == EXPECTED


def test_safe_patterns_produce_no_findings():
    full = run(OWNERSHIP, "FPG001")
    assert not [f for f in full.findings if f.location.path.startswith("safe/")]


def test_without_the_models_the_rule_is_less_sure_not_louder():
    # Scanning the routes without the models: the public `Plan` can no
    # longer be told apart from a user-owned table, so it is reported — at
    # medium, which does not fail the scan by default.
    result = run(OWNERSHIP / "safe", "FPG001")
    assert {f.confidence for f in result.findings} <= {Confidence.MEDIUM}
    assert result.failing(Confidence.HIGH) == []


def test_confidence_reflects_what_was_resolved():
    by_line = {f.location.line: f for f in run(OWNERSHIP, "FPG001").findings}
    assert by_line[13].confidence is Confidence.HIGH  # Item.owner_id
    # Note only records its author: private or not is a product decision.
    assert by_line[48].confidence is Confidence.MEDIUM


def test_finding_names_the_route_the_lookup_and_the_owner_column():
    finding = next(f for f in run(OWNERSHIP, "FPG001").findings if f.location.line == 36)
    assert finding.subject.startswith("GET /items/{item_id}/via-repo")
    joined = " ".join(finding.evidence)
    assert "ItemRepository.get()" in joined
    assert "self.session.get(Item, item_id)" in joined
    assert "owner_id" in joined
    assert "owner_id == user.id" in finding.fix


def test_suppression_with_a_reason_suppresses():
    result = run(OWNERSHIP, "FPG001")
    assert [s.finding.location.line for s in result.suppressed] == [123]
    assert "shared by design" in result.suppressed[0].reason
