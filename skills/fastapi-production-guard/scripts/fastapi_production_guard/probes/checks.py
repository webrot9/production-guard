"""The three probes. Each returns a verdict built only from what the app answered.

PASS          the property held under the attack the probe made
FAIL          it did not, and the evidence says which request broke it
INCONCLUSIVE  the probe could not set up a fair test (a create that failed,
              an event that changed nothing observable). Never read as PASS.
"""

from __future__ import annotations

import copy
import json
import math
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from fastapi_production_guard.probes.config import OwnershipProbe, RaceProbe, WebhookProbe
from fastapi_production_guard.probes.http import (
    Client,
    ProbeError,
    RequestSpec,
    Response,
    concurrently,
    pointer,
    set_pointer,
)
from fastapi_production_guard.probes.signing import new_delivery_id, sign


class Verdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


@dataclass
class ProbeResult:
    kind: str
    name: str
    verdict: Verdict
    summary: str
    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _order(spec: RequestSpec) -> int:
    # Read first, change second, destroy last: a DELETE that wrongly succeeds
    # must not hide whether the PATCH before it would have.
    return {"GET": 0, "HEAD": 0, "OPTIONS": 0, "DELETE": 2}.get(spec.method, 1)


def run_ownership(client: Client, probe: OwnershipProbe) -> ProbeResult:
    evidence: list[str] = []
    notes: list[str] = []
    rid = probe.id_value
    if probe.create is not None:
        created = client.send(probe.create)
        evidence.append(f"{probe.owner}: {probe.create.method} {probe.create.path} → {created.describe()}")
        if not created.ok:
            return ProbeResult("ownership", probe.name, Verdict.INCONCLUSIVE, f"{probe.owner} could not create the resource, so there is nothing to attack.", evidence)
        try:
            rid = str(pointer(created.json(), probe.id_pointer))
        except KeyError:
            return ProbeResult("ownership", probe.name, Verdict.INCONCLUSIVE, f"the create response has no id at {probe.id_pointer}.", evidence)
    assert rid is not None

    reads = [r for r in probe.requests if _order(r) == 0]
    baseline: Response | None = None
    if reads:
        own = reads[0].rendered(id=rid)
        own.as_ = probe.owner
        baseline = client.send(own)
        evidence.append(f"{probe.owner}: {own.method} {own.path} → {baseline.describe()}")
        if not baseline.ok:
            return ProbeResult(
                "ownership", probe.name, Verdict.INCONCLUSIVE,
                f"{probe.owner} cannot read their own resource either, so a refusal to {probe.attacker} would prove nothing.",
                evidence,
            )

    leaks: list[str] = []
    odd: list[str] = []
    for spec in sorted(probe.requests, key=_order):
        attack = spec.rendered(id=rid)
        attack.as_ = probe.attacker
        resp = client.send(attack)
        line = f"{probe.attacker}: {attack.method} {attack.path} → {resp.describe()}"
        evidence.append(line)
        if resp.ok:
            leaks.append(line)
        elif resp.status not in probe.deny:
            odd.append(line)
        elif resp.status == 403:
            notes.append(f"{attack.method} answers 403 to another user: it confirms the id exists. 404 would not.")

    # A refusal that changed the row anyway is still a leak. Re-read as the owner.
    if baseline is not None and reads:
        own = reads[0].rendered(id=rid)
        own.as_ = probe.owner
        after = client.send(own)
        if not after.ok:
            leaks.append(f"{probe.owner} can no longer read the resource after {probe.attacker}'s requests ({after.describe()}): one of them was carried out despite the answer")
        elif after.body != baseline.body and _changed(baseline, after):
            leaks.append(f"the resource changed after {probe.attacker}'s requests, though they were refused")

    if probe.cleanup is not None:
        client.send(probe.cleanup.rendered(id=rid))

    if leaks:
        return ProbeResult("ownership", probe.name, Verdict.FAIL, f"{probe.attacker} reached {probe.owner}'s resource.", leaks + [e for e in evidence if e not in leaks], notes)
    if odd:
        return ProbeResult(
            "ownership", probe.name, Verdict.INCONCLUSIVE,
            f"{probe.attacker} was not let through, but some answers were neither a success nor one of {probe.deny}.",
            evidence, notes,
        )
    return ProbeResult("ownership", probe.name, Verdict.PASS, f"every request by {probe.attacker} on {probe.owner}'s resource was refused, and it was left unchanged.", evidence, notes)


def _changed(before: Response, after: Response) -> bool:
    """Bodies differ; ignore fields that change on every read (timestamps, etags)."""
    a, b = before.json(), after.json()
    if a is None or b is None:
        return before.body != after.body
    volatile = {"updated_at", "last_seen_at", "accessed_at", "now", "request_id", "etag"}
    if isinstance(a, dict) and isinstance(b, dict):
        return {k: v for k, v in a.items() if k not in volatile} != {k: v for k, v in b.items() if k not in volatile}
    return bool(a != b)


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _fmt(value: float | None) -> str:
    return "?" if value is None else f"{value:g}"


def _event(probe: WebhookProbe) -> bytes:
    """The payload, with every `fresh_id` pointer given a never-seen id."""
    if not probe.fresh_id:
        return probe.payload
    doc = json.loads(probe.payload)
    doc = copy.deepcopy(doc)
    for ptr in probe.fresh_id:
        try:
            set_pointer(doc, ptr, new_delivery_id(probe.signing))
        except (KeyError, IndexError, TypeError) as exc:
            raise ProbeError(f"payload has no {ptr} to replace") from exc
    return json.dumps(doc).encode("utf-8")


def _deliver(client: Client, probe: WebhookProbe, body: bytes, delivery_id: str) -> Response:
    headers = {"Content-Type": "application/json", **probe.headers}
    headers.update(sign(probe.signing, probe.secret, body, delivery_id, header=probe.signature_header))
    return client.send(RequestSpec("POST", probe.url, raw_body=body), extra_headers=headers)


def run_webhook(client: Client, probe: WebhookProbe) -> ProbeResult:
    evidence: list[str] = []
    notes: list[str] = []
    if not probe.fresh_id and probe.signing not in {"svix", "standard-webhooks", "github"}:
        notes.append(
            "no `fresh_id` pointer: if the app has seen this payload's event id before, the first delivery is "
            "itself a replay and the probe cannot tell"
        )
    try:
        body = _event(probe)
        delivery_id = new_delivery_id(probe.signing)
        v0, _ = client.read_value(probe.effect)
        first = _deliver(client, probe, body, delivery_id)
        evidence.append(f"effect before: {v0!r}")
        evidence.append(f"delivery 1 → {first.describe()}")
        if not first.ok:
            return ProbeResult("webhook", probe.name, Verdict.INCONCLUSIVE, "the app rejected the first delivery; check the secret, the signing scheme and the payload.", evidence, notes)
        time.sleep(probe.settle)
        v1, _ = client.read_value(probe.effect)
        evidence.append(f"effect after delivery 1: {v1!r}")
        if v1 == v0:
            return ProbeResult(
                "webhook", probe.name, Verdict.INCONCLUSIVE,
                "the first delivery changed nothing the probe can see; point `effect` at a value this event changes"
                + (" (or raise `settle_seconds` if the work is queued)" if probe.settle == 0 else "") + ".",
                evidence, notes,
            )
        # A retry: same event, same delivery id, a new timestamp and signature.
        time.sleep(1.1 if probe.signing in {"stripe", "paddle", "svix", "standard-webhooks"} else 0)
        second = _deliver(client, probe, body, delivery_id)
        evidence.append(f"delivery 2 (the same event, re-signed) → {second.describe()}")
        time.sleep(probe.settle)
        v2, _ = client.read_value(probe.effect)
        evidence.append(f"effect after delivery 2: {v2!r}")
        if not second.ok and second.status not in (409,):
            notes.append(f"the replay was answered {second.status}; providers retry on anything but 2xx, so this event would be redelivered until they give up")
        if v2 != v1:
            return ProbeResult("webhook", probe.name, Verdict.FAIL, f"the replayed event was applied again: {v0!r} → {v1!r} → {v2!r}.", evidence, notes)

        if probe.concurrent:
            d0, d1 = _number(v0), _number(v1)
            if d0 is None or d1 is None:
                notes.append("the effect is not a number, so the concurrent-delivery check was skipped")
            else:
                step = d1 - d0
                body2 = _event(probe)
                delivery2 = new_delivery_id(probe.signing)
                if not probe.fresh_id and probe.signing not in {"svix", "standard-webhooks", "github"}:
                    notes.append("concurrent check skipped: it needs `fresh_id` to send a new event")
                else:
                    c0 = _number(client.read_value(probe.effect)[0])
                    pair = concurrently(2, lambda _i: _deliver(client, probe, body2, delivery2))
                    evidence.append("two simultaneous copies of a new event → " + ", ".join(r.describe() for r in pair))
                    time.sleep(probe.settle)
                    c1 = _number(client.read_value(probe.effect)[0])
                    evidence.append(f"effect: {_fmt(c0)} → {_fmt(c1)} (one application is {step:+g})")
                    if c0 is not None and c1 is not None and not math.isclose(c1 - c0, step) and math.isclose(c1 - c0, 2 * step):
                        return ProbeResult(
                            "webhook", probe.name, Verdict.FAIL,
                            "two copies of the same event delivered at the same moment were both applied: the dedupe check is not atomic.",
                            evidence, notes,
                        )
    except ProbeError as exc:
        return ProbeResult("webhook", probe.name, Verdict.INCONCLUSIVE, str(exc), evidence, notes)
    return ProbeResult("webhook", probe.name, Verdict.PASS, "a retried delivery of the same event was not applied twice.", evidence, notes)


def run_race(client: Client, probe: RaceProbe) -> ProbeResult:
    evidence: list[str] = []
    notes: list[str] = []
    try:
        b0 = _number(client.read_value(probe.balance)[0])
        if b0 is None:
            raise ProbeError(f"the balance at {probe.balance.value} is not a number")
        evidence.append(f"balance before: {b0:g}")
        cost = probe.cost
        if cost is None:
            one = client.send(probe.spend)
            evidence.append(f"one spend to measure its cost → {one.describe()}")
            if not one.ok:
                raise ProbeError("a single spend was refused, so its cost cannot be measured; set `cost`, or give the user a balance")
            time.sleep(probe.settle)
            b_one = _number(client.read_value(probe.balance)[0])
            if b_one is None or b0 - b_one <= 0:
                raise ProbeError("a successful spend did not lower the balance; set `cost` or point `balance` at the right value")
            cost = b0 - b_one
            b0 = b_one
            evidence.append(f"cost of one spend: {cost:g}; balance now {b0:g}")
        affordable = math.floor(b0 / cost + 1e-9)
        if probe.concurrency <= affordable:
            notes.append(
                f"the user can afford {affordable} spends and the probe sends {probe.concurrency}: overspending cannot "
                "show. Lower the user's balance below the concurrency to test it; lost updates are still detected."
            )
        responses = concurrently(probe.concurrency, lambda _i: client.send(probe.spend))
        ok = sum(r.ok for r in responses)
        refused = sum(1 for r in responses if r.status in probe.refused)
        other = len(responses) - ok - refused
        evidence.append(f"{probe.concurrency} simultaneous spends → {ok} succeeded, {refused} refused, {other} other")
        if other:
            sample = next(r for r in responses if not r.ok and r.status not in probe.refused)
            evidence.append(f"first unexpected answer: {sample.describe()}")
        time.sleep(probe.settle)
        b1 = _number(client.read_value(probe.balance)[0])
        if b1 is None:
            raise ProbeError("the balance is no longer a number")
        evidence.append(f"balance after: {b1:g} (expected {b0 - ok * cost:g} for {ok} successful spends)")
        if ok == 0:
            raise ProbeError("no spend succeeded, so nothing was raced; check the user's balance and the spend request")
        problems = []
        if ok > affordable:
            problems.append(f"{ok} spends succeeded on a balance that pays for {affordable}")
        if b1 < 0:
            problems.append(f"the balance went negative ({b1:g})")
        if not math.isclose(b0 - b1, ok * cost):
            problems.append(f"{ok} spends succeeded but the balance fell by {b0 - b1:g}, not {ok * cost:g}: updates were lost")
        if problems:
            return ProbeResult("race", probe.name, Verdict.FAIL, "; ".join(problems) + ".", evidence, notes)
    except ProbeError as exc:
        return ProbeResult("race", probe.name, Verdict.INCONCLUSIVE, str(exc), evidence, notes)
    return ProbeResult("race", probe.name, Verdict.PASS, f"{ok} of {probe.concurrency} concurrent spends succeeded and the balance moved by exactly that many.", evidence, notes)
