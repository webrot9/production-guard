"""The probes against an app that has each bug, and the same app with each fix.

A probe that cannot tell the two apart is not a check, so every probe here
must FAIL on `vulnerable` and PASS on `safe`.
"""

import json
from pathlib import Path

import pytest

from fastapi_production_guard.probes.checks import Verdict, run_ownership, run_race, run_webhook
from fastapi_production_guard.probes.config import ProbeConfigError, load_probe_file
from fastapi_production_guard.probes.http import Client
from fastapi_production_guard.probes.runner import run_probes
from tests.probe_app import PADDLE_SECRET, STRIPE_SECRET, SVIX_SECRET, ProbeApp

PROBES = """
base_url = "{url}"
timeout = 10

[auth.alice]
Authorization = "Bearer ${{ALICE}}"
[auth.bob]
Authorization = "Bearer bob-token"

[[ownership]]
name = "items"
owner = "alice"
attacker = "bob"
create = {{ method = "POST", path = "/items", json = {{ title = "mine" }} }}
requests = [
  {{ method = "GET", path = "/items/{{id}}" }},
  {{ method = "PATCH", path = "/items/{{id}}", json = {{ title = "pwned" }} }},
  {{ method = "DELETE", path = "/items/{{id}}" }},
]

[[webhook]]
name = "paddle"
url = "/webhooks/paddle"
signing = "paddle"
secret = "{paddle}"
payload = {{ event_id = "evt_placeholder", event_type = "transaction.completed" }}
fresh_id = "/event_id"
effect = {{ method = "GET", path = "/credits", as = "alice", value = "/balance" }}

[[webhook]]
name = "clerk"
url = "/webhooks/clerk"
signing = "svix"
secret = "{svix}"
payload = {{ type = "user.created", data = {{ id = "user_1" }} }}
effect = {{ method = "GET", path = "/credits", as = "alice", value = "/balance" }}

[[webhook]]
name = "stripe"
url = "/webhooks/stripe"
signing = "stripe"
secret = "{stripe}"
payload = {{ id = "evt_placeholder", type = "checkout.session.completed" }}
fresh_id = "/id"
effect = {{ method = "GET", path = "/credits", as = "alice", value = "/balance" }}
concurrent = false

[[race]]
name = "spend"
as = "bob"
balance = {{ method = "GET", path = "/credits", value = "/balance" }}
spend = {{ method = "POST", path = "/spend", json = {{}} }}
cost = 1
concurrency = 12
"""


def probe_file(tmp_path: Path, url: str, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("ALICE", "alice-token")
    path = tmp_path / "probes.toml"
    path.write_text(PROBES.format(url=url, paddle=PADDLE_SECRET, svix=SVIX_SECRET, stripe=STRIPE_SECRET))
    return path


def results(tmp_path, monkeypatch, mode):
    with ProbeApp(mode) as app:
        pf = load_probe_file(probe_file(tmp_path, app.url, monkeypatch))
        client = Client(pf.base_url, timeout=pf.timeout, auth=pf.auth)
        out = {o.name: run_ownership(client, o) for o in pf.ownership}
        out |= {w.name: run_webhook(client, w) for w in pf.webhook}
        out |= {r.name: run_race(client, r) for r in pf.race}
        return out


def test_every_probe_fails_on_the_vulnerable_app(tmp_path, monkeypatch):
    r = results(tmp_path, monkeypatch, "vulnerable")
    assert {name: res.verdict for name, res in r.items()} == {
        "items": Verdict.FAIL,
        "paddle": Verdict.FAIL,
        "clerk": Verdict.FAIL,
        "stripe": Verdict.FAIL,
        "spend": Verdict.FAIL,
    }
    assert "bob reached alice's resource" in r["items"].summary
    assert "applied again" in r["paddle"].summary
    assert "updates were lost" in r["spend"].summary or "succeeded on a balance" in r["spend"].summary


def test_every_probe_passes_on_the_safe_app(tmp_path, monkeypatch):
    r = results(tmp_path, monkeypatch, "safe")
    assert {name: res.verdict for name, res in r.items()} == dict.fromkeys(r, Verdict.PASS), {
        n: (x.summary, x.evidence) for n, x in r.items()
    }


def test_a_racy_dedupe_survives_a_retry_but_not_two_copies_at_once(tmp_path, monkeypatch):
    r = results(tmp_path, monkeypatch, "racy")
    assert r["paddle"].verdict is Verdict.FAIL
    assert "not atomic" in r["paddle"].summary


def test_runner_exit_codes_and_json(tmp_path, monkeypatch, capsys):
    with ProbeApp("safe") as app:
        path = probe_file(tmp_path, app.url, monkeypatch)
        assert run_probes(path, only=["items"], output_format="json") == 0
        payload = json.loads(capsys.readouterr().out)
        assert [r["verdict"] for r in payload["results"]] == ["pass"]
    with ProbeApp("vulnerable") as app:
        path = probe_file(tmp_path, app.url, monkeypatch)
        assert run_probes(path, only=["spend"], output_format="text") == 1


def test_an_unreachable_app_is_inconclusive_not_safe(tmp_path, monkeypatch):
    path = probe_file(tmp_path, "http://127.0.0.1:9", monkeypatch)
    assert run_probes(path, only=["items", "spend"], output_format="text") == 3


def test_a_missing_secret_is_a_config_error_not_a_silent_401(tmp_path, monkeypatch):
    path = probe_file(tmp_path, "http://127.0.0.1:9", monkeypatch)
    monkeypatch.delenv("ALICE")
    with pytest.raises(ProbeConfigError, match="ALICE is not set"):
        load_probe_file(path)
