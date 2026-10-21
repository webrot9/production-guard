"""A small HTTP client on `urllib`, and the request descriptions probes are written in.

Probes send real requests to a running app, so this is the only part of the
tool that touches the network, and only ever the `base_url` you configure.
"""

from __future__ import annotations

import contextlib
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"})


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    error: str | None = None  # set when no HTTP response arrived at all

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8") or "null")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300

    def describe(self) -> str:
        if self.error:
            return f"no response ({self.error})"
        text = self.body.decode("utf-8", "replace").strip().replace("\n", " ")
        return f"{self.status}" + (f" {text[:120]}" if text else "")


@dataclass
class RequestSpec:
    method: str
    path: str
    as_: str | None = None
    json_body: Any = None
    raw_body: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)
    value: str | None = None  # JSON pointer into the response, for reads

    def rendered(self, **values: str) -> RequestSpec:
        path = self.path
        for key, value in values.items():
            path = path.replace("{" + key + "}", urllib.parse.quote(str(value), safe=""))
        body = _substitute(self.json_body, values)
        return RequestSpec(self.method, path, self.as_, body, self.raw_body, dict(self.headers), self.value)


def _substitute(obj: Any, values: dict[str, str]) -> Any:
    if isinstance(obj, str):
        for key, value in values.items():
            obj = obj.replace("{" + key + "}", str(value))
        return obj
    if isinstance(obj, list):
        return [_substitute(x, values) for x in obj]
    if isinstance(obj, dict):
        return {k: _substitute(v, values) for k, v in obj.items()}
    return obj


def pointer(doc: Any, ptr: str) -> Any:
    """RFC 6901 JSON pointer: "/data/0/id". Raises KeyError when absent."""
    if ptr in ("", "/"):
        return doc
    if not ptr.startswith("/"):
        raise KeyError(f"JSON pointer must start with '/': {ptr!r}")
    current = doc
    for raw in ptr.lstrip("/").split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError) as exc:
                raise KeyError(ptr) from exc
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise KeyError(ptr)
    return current


def set_pointer(doc: Any, ptr: str, value: Any) -> None:
    parts = [p.replace("~1", "/").replace("~0", "~") for p in ptr.lstrip("/").split("/")]
    current = doc
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    last = parts[-1]
    if isinstance(current, list):
        current[int(last)] = value
    else:
        current[last] = value


class Client:
    def __init__(self, base_url: str, *, timeout: float, auth: dict[str, dict[str, str]]) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.auth = auth
        host = urllib.parse.urlsplit(self.base_url).hostname or ""
        handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
        if host in _LOOPBACK:
            # A corporate proxy in the environment must not swallow requests to
            # an app on this machine.
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    def url(self, path: str) -> str:
        return path if path.startswith(("http://", "https://")) else self.base_url + path

    def send(self, spec: RequestSpec, *, extra_headers: dict[str, str] | None = None) -> Response:
        headers = {"Accept": "application/json", "User-Agent": "fastapi-production-guard-probe"}
        if spec.as_ is not None:
            if spec.as_ not in self.auth:
                raise KeyError(f"no [auth.{spec.as_}] section for `as = \"{spec.as_}\"`")
            headers.update(self.auth[spec.as_])
        headers.update(spec.headers)
        headers.update(extra_headers or {})
        data: bytes | None = spec.raw_body
        if data is None and spec.json_body is not None:
            data = json.dumps(spec.json_body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(self.url(spec.path), data=data, method=spec.method.upper(), headers=headers)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return Response(resp.status, dict(resp.headers.items()), resp.read())
        except urllib.error.HTTPError as exc:
            body = exc.read() if exc.fp is not None else b""
            return Response(exc.code, dict(exc.headers.items()) if exc.headers else {}, body)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            return Response(0, {}, b"", error=str(reason))

    def read_value(self, spec: RequestSpec) -> tuple[Any, Response]:
        resp = self.send(spec)
        if not resp.ok:
            raise ProbeError(f"reading {spec.method} {spec.path} failed: {resp.describe()}")
        if spec.value is None:
            return resp.body, resp
        try:
            return pointer(resp.json(), spec.value), resp
        except KeyError as exc:
            raise ProbeError(f"{spec.method} {spec.path} has no {spec.value} in its response: {resp.describe()}") from exc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 302 to a login page is an answer worth seeing, not one to follow."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class ProbeError(Exception):
    """The probe could not establish the facts it needs: inconclusive, not failed."""


def concurrently(n: int, fn: Callable[[int], Response]) -> list[Response]:
    """Run `fn(i)` for i in range(n) on n threads, released at the same instant."""
    barrier = threading.Barrier(n)
    results: list[Response | None] = [None] * n

    def worker(i: int) -> None:
        # A broken barrier (a thread that never started) still sends: late is
        # better than not at all, and the verdict counts what was answered.
        with contextlib.suppress(threading.BrokenBarrierError):
            barrier.wait(timeout=30)
        results[i] = fn(i)

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return [r if r is not None else Response(0, {}, b"", error="worker did not finish") for r in results]
