"""A tiny app, on the standard library, with each bug the probes look for — or its fix.

`mode="vulnerable"` reproduces the bugs: no ownership filter, no webhook
dedupe, a read-sleep-write balance. `mode="racy"` dedupes webhooks with a
check-then-insert. `mode="safe"` does each thing correctly. The signature
checks are the same algorithms the providers' own SDKs use, so a probe that
gets past them is signing the way the real provider does.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import itertools
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PADDLE_SECRET = "pdl_ntfset_test_secret"
SVIX_SECRET = "whsec_" + base64.b64encode(b"\x01" * 32).decode()
STRIPE_SECRET = "whsec_stripe_test"
TOKENS = {"Bearer alice-token": "alice", "Bearer bob-token": "bob"}


class State:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.items: dict[int, dict[str, object]] = {}
        self.ids = itertools.count(1)
        self.balance = {"alice": 5, "bob": 5}
        self.seen: set[str] = set()
        self.lock = threading.Lock()


def _verify_paddle(header: str, body: bytes) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(";") if "=" in p)
    if abs(time.time() - int(parts.get("ts", 0))) > 300:
        return False
    expected = hmac.new(PADDLE_SECRET.encode(), f"{parts['ts']}:".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("h1", ""))


def _verify_svix(msg_id: str, ts: str, sig: str, body: bytes) -> bool:
    key = base64.b64decode(SVIX_SECRET[len("whsec_"):])
    expected = base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
    return any(hmac.compare_digest(expected, s.split(",", 1)[1]) for s in sig.split() if s.startswith("v1,"))


def _verify_stripe(header: str, body: bytes) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    expected = hmac.new(STRIPE_SECRET.encode(), f"{parts['t']}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))


def make_handler(state: State) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def _send(self, status: int, payload: object = None) -> None:
            body = json.dumps(payload).encode() if payload is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _user(self) -> str | None:
            return TOKENS.get(self.headers.get("Authorization", ""))

        def _body(self) -> bytes:
            return self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))

        def _item(self, user: str) -> tuple[int, dict[str, object] | None]:
            item_id = int(self.path.rsplit("/", 1)[1])
            item = state.items.get(item_id)
            if item is not None and state.mode != "vulnerable" and item["owner"] != user:
                return item_id, None  # 404, not 403
            return item_id, item

        def do_GET(self) -> None:
            user = self._user()
            if user is None:
                return self._send(401)
            if self.path == "/credits":
                return self._send(200, {"balance": state.balance[user]})
            if self.path.startswith("/items/"):
                _, item = self._item(user)
                return self._send(200, item) if item else self._send(404)
            return self._send(404)

        def do_POST(self) -> None:
            body = self._body()
            if self.path.startswith("/webhooks/"):
                return self._webhook(body)
            user = self._user()
            if user is None:
                return self._send(401)
            if self.path == "/items":
                item_id = next(state.ids)
                state.items[item_id] = {"id": item_id, "owner": user, "title": json.loads(body)["title"]}
                return self._send(201, state.items[item_id])
            if self.path == "/spend":
                return self._spend(user)
            return self._send(404)

        def do_PATCH(self) -> None:
            user = self._user()
            if user is None:
                return self._send(401)
            body = json.loads(self._body() or b"{}")
            _, item = self._item(user)
            if item is None:
                return self._send(404)
            item.update({k: v for k, v in body.items() if k == "title"})
            return self._send(200, item)

        def do_DELETE(self) -> None:
            user = self._user()
            if user is None:
                return self._send(401)
            item_id, item = self._item(user)
            if item is None:
                return self._send(404)
            del state.items[item_id]
            return self._send(204)

        def _spend(self, user: str) -> None:
            if state.mode == "vulnerable":
                current = state.balance[user]  # read
                time.sleep(0.05)  # the database round trip
                if current < 1:
                    return self._send(402)
                state.balance[user] = current - 1  # write back a stale value
                return self._send(200, {"ok": True})
            with state.lock:
                if state.balance[user] < 1:
                    return self._send(402)
                state.balance[user] -= 1
            return self._send(200, {"ok": True})

        def _webhook(self, body: bytes) -> None:
            if self.path == "/webhooks/paddle":
                if not _verify_paddle(self.headers.get("Paddle-Signature", ""), body):
                    return self._send(401)
                event_id = json.loads(body)["event_id"]
            elif self.path == "/webhooks/clerk":
                msg_id = self.headers.get("svix-id", "")
                if not _verify_svix(msg_id, self.headers.get("svix-timestamp", ""), self.headers.get("svix-signature", ""), body):
                    return self._send(401)
                event_id = msg_id
            elif self.path == "/webhooks/stripe":
                if not _verify_stripe(self.headers.get("Stripe-Signature", ""), body):
                    return self._send(401)
                event_id = json.loads(body)["id"]
            else:
                return self._send(404)
            if state.mode == "safe":
                with state.lock:  # an atomic claim: INSERT ... ON CONFLICT DO NOTHING
                    if event_id in state.seen:
                        return self._send(200, {"duplicate": True})
                    state.seen.add(event_id)
            elif state.mode == "racy":
                if event_id in state.seen:  # check ...
                    return self._send(200, {"duplicate": True})
                time.sleep(0.05)
                state.seen.add(event_id)  # ... then insert
            state.balance["alice"] += 100
            return self._send(200, {"ok": True})

    return Handler


class ProbeApp:
    def __init__(self, mode: str) -> None:
        self.state = State(mode)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self) -> ProbeApp:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
