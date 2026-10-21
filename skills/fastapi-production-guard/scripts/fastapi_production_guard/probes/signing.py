"""Signing a webhook delivery the way each provider does, so the app accepts it.

A replay probe is only meaningful if the app *accepts* both deliveries: a
handler that rejects the second one for a bad signature has proved nothing
about idempotency. So each scheme here is the provider's own algorithm,
checked in the tests against the verifier code the providers document.
A retry re-signs with a fresh timestamp and keeps the event id — which is
exactly what a real retry looks like.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
import uuid
from collections.abc import Callable

SCHEMES = ("stripe", "paddle", "svix", "standard-webhooks", "github", "hmac-sha256", "none")


def _hmac_hex(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def stripe(secret: str, body: bytes, delivery_id: str, now: int) -> dict[str, str]:
    # stripe-python: HMAC-SHA256(secret.encode(), f"{t}.{payload}"), header "t=..,v1=.."
    signature = _hmac_hex(secret.encode("utf-8"), f"{now}.".encode() + body)
    return {"Stripe-Signature": f"t={now},v1={signature}"}


def paddle(secret: str, body: bytes, delivery_id: str, now: int) -> dict[str, str]:
    # Paddle Billing: HMAC-SHA256(secret, f"{ts}:{body}"), header "ts=..;h1=.."
    signature = _hmac_hex(secret.encode("utf-8"), f"{now}:".encode() + body)
    return {"Paddle-Signature": f"ts={now};h1={signature}"}


def _svix_key(secret: str) -> bytes:
    return base64.b64decode(secret.split("_", 1)[1]) if secret.startswith("whsec_") else secret.encode("utf-8")


def _svix_signature(secret: str, body: bytes, msg_id: str, now: int) -> str:
    digest = hmac.new(_svix_key(secret), f"{msg_id}.{now}.".encode() + body, hashlib.sha256).digest()
    return "v1," + base64.b64encode(digest).decode("ascii")


def svix(secret: str, body: bytes, delivery_id: str, now: int) -> dict[str, str]:
    # Svix (Clerk, Resend): base64 HMAC over "{id}.{timestamp}.{body}", key = base64(secret after whsec_)
    return {
        "svix-id": delivery_id,
        "svix-timestamp": str(now),
        "svix-signature": _svix_signature(secret, body, delivery_id, now),
    }


def standard_webhooks(secret: str, body: bytes, delivery_id: str, now: int) -> dict[str, str]:
    # standardwebhooks.com (Polar, and Svix under its neutral header names)
    return {
        "webhook-id": delivery_id,
        "webhook-timestamp": str(now),
        "webhook-signature": _svix_signature(secret, body, delivery_id, now),
    }


def github(secret: str, body: bytes, delivery_id: str, now: int) -> dict[str, str]:
    return {
        "X-Hub-Signature-256": "sha256=" + _hmac_hex(secret.encode("utf-8"), body),
        "X-GitHub-Delivery": delivery_id,
    }


def hmac_sha256(secret: str, body: bytes, delivery_id: str, now: int) -> dict[str, str]:
    return {"X-Signature": _hmac_hex(secret.encode("utf-8"), body)}


def none(secret: str, body: bytes, delivery_id: str, now: int) -> dict[str, str]:
    return {}


_SIGNERS: dict[str, Callable[[str, bytes, str, int], dict[str, str]]] = {
    "stripe": stripe,
    "paddle": paddle,
    "svix": svix,
    "standard-webhooks": standard_webhooks,
    "github": github,
    "hmac-sha256": hmac_sha256,
    "none": none,
}


def sign(scheme: str, secret: str, body: bytes, delivery_id: str, *, now: int | None = None, header: str | None = None) -> dict[str, str]:
    headers = _SIGNERS[scheme](secret, body, delivery_id, int(time.time()) if now is None else now)
    if scheme == "hmac-sha256" and header:
        headers = {header: headers["X-Signature"]}
    return headers


def new_delivery_id(scheme: str) -> str:
    return ("msg_" if scheme in {"svix", "standard-webhooks"} else "fpg_") + uuid.uuid4().hex
