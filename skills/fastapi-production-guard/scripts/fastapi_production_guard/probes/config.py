"""The probe file: which app, which users, which requests.

    base_url = "http://localhost:8000"

    [auth.alice]
    Authorization = "Bearer ${ALICE_TOKEN}"
    [auth.bob]
    Authorization = "Bearer ${BOB_TOKEN}"

    [[ownership]] ...   [[webhook]] ...   [[race]] ...

`${NAME}` is read from the environment when the file is loaded, so tokens
and webhook secrets never have to be written into it. A variable that is
not set is an error, not an empty string: an empty bearer token produces a
401, and a probe that sees only 401s would otherwise report the app safe.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi_production_guard.probes.http import RequestSpec
from fastapi_production_guard.probes.signing import SCHEMES

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ProbeConfigError(Exception):
    pass


def _expand(obj: Any, where: str) -> Any:
    if isinstance(obj, str):
        def sub(m: re.Match[str]) -> str:
            name = m.group(1)
            if name not in os.environ:
                raise ProbeConfigError(f"{where}: environment variable {name} is not set")
            return os.environ[name]

        return _VAR.sub(sub, obj)
    if isinstance(obj, list):
        return [_expand(x, where) for x in obj]
    if isinstance(obj, dict):
        return {k: _expand(v, where) for k, v in obj.items()}
    return obj


def _request(raw: Any, where: str, *, default_as: str | None = None) -> RequestSpec:
    if not isinstance(raw, dict):
        raise ProbeConfigError(f"{where}: expected a table like {{ method = \"GET\", path = \"/...\" }}")
    unknown = set(raw) - {"method", "path", "as", "json", "body", "headers", "value"}
    if unknown:
        raise ProbeConfigError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    if "path" not in raw:
        raise ProbeConfigError(f"{where}: `path` is required")
    body = raw.get("body")
    return RequestSpec(
        method=str(raw.get("method", "GET")).upper(),
        path=str(raw["path"]),
        as_=raw.get("as", default_as),
        json_body=raw.get("json"),
        raw_body=body.encode("utf-8") if isinstance(body, str) else None,
        headers={str(k): str(v) for k, v in raw.get("headers", {}).items()},
        value=raw.get("value"),
    )


@dataclass
class OwnershipProbe:
    name: str
    owner: str
    attacker: str
    create: RequestSpec | None
    id_pointer: str
    id_value: str | None
    requests: list[RequestSpec]
    deny: list[int]
    cleanup: RequestSpec | None


@dataclass
class WebhookProbe:
    name: str
    url: str
    signing: str
    secret: str
    payload: bytes
    fresh_id: list[str]
    effect: RequestSpec
    settle: float
    concurrent: bool
    headers: dict[str, str]
    signature_header: str | None


@dataclass
class RaceProbe:
    name: str
    as_: str
    balance: RequestSpec
    spend: RequestSpec
    cost: float | None  # None: measure it with one spend first
    concurrency: int
    settle: float
    refused: list[int]


@dataclass
class ProbeFile:
    base_url: str
    timeout: float
    auth: dict[str, dict[str, str]]
    ownership: list[OwnershipProbe] = field(default_factory=list)
    webhook: list[WebhookProbe] = field(default_factory=list)
    race: list[RaceProbe] = field(default_factory=list)


def load_probe_file(path: Path) -> ProbeFile:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ProbeConfigError(f"probe file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ProbeConfigError(f"{path}: {exc}") from exc
    unknown = set(raw) - {"base_url", "timeout", "auth", "ownership", "webhook", "race"}
    if unknown:
        raise ProbeConfigError(f"{path}: unknown key(s) {', '.join(sorted(unknown))}")
    if "base_url" not in raw:
        raise ProbeConfigError(f"{path}: `base_url` is required")
    auth = {
        str(name): {str(k): str(v) for k, v in _expand(headers, f"[auth.{name}]").items()}
        for name, headers in raw.get("auth", {}).items()
    }
    pf = ProbeFile(base_url=_expand(raw["base_url"], "base_url"), timeout=float(raw.get("timeout", 15)), auth=auth)
    names: set[str] = set()

    def unique(name: str, where: str) -> str:
        if name in names:
            raise ProbeConfigError(f"{where}: probe name {name!r} is used twice")
        names.add(name)
        return name

    for i, o in enumerate(raw.get("ownership", [])):
        where = f"[[ownership]] #{i + 1}"
        o = _expand(o, where)
        for key in ("owner", "attacker", "requests"):
            if key not in o:
                raise ProbeConfigError(f"{where}: `{key}` is required")
        if "create" not in o and "id_value" not in o:
            raise ProbeConfigError(f"{where}: give `create` (a request that makes a row) or `id_value` (an existing row of the owner)")
        if o["owner"] == o["attacker"]:
            raise ProbeConfigError(f"{where}: `owner` and `attacker` must be different users")
        for who in (o["owner"], o["attacker"]):
            if who not in auth:
                raise ProbeConfigError(f"{where}: no [auth.{who}] section")
        pf.ownership.append(
            OwnershipProbe(
                name=unique(str(o.get("name", f"ownership-{i + 1}")), where),
                owner=o["owner"],
                attacker=o["attacker"],
                create=_request(o["create"], f"{where}.create", default_as=o["owner"]) if "create" in o else None,
                id_pointer=str(o.get("id", "/id")),
                id_value=str(o["id_value"]) if "id_value" in o else None,
                requests=[_request(r, f"{where}.requests[{j}]") for j, r in enumerate(o["requests"])],
                deny=[int(x) for x in o.get("deny", [401, 403, 404])],
                cleanup=_request(o["cleanup"], f"{where}.cleanup", default_as=o["owner"]) if "cleanup" in o else None,
            )
        )

    for i, w in enumerate(raw.get("webhook", [])):
        where = f"[[webhook]] #{i + 1}"
        w = _expand(w, where)
        for key in ("url", "signing", "payload", "effect"):
            if key not in w:
                raise ProbeConfigError(f"{where}: `{key}` is required")
        if w["signing"] not in SCHEMES:
            raise ProbeConfigError(f"{where}: `signing` must be one of {', '.join(SCHEMES)}")
        if w["signing"] != "none" and not w.get("secret"):
            raise ProbeConfigError(f"{where}: `secret` is required for signing = {w['signing']!r}")
        payload = w["payload"]
        if isinstance(payload, str):
            file = (path.parent / payload).resolve()
            if not file.is_file():
                raise ProbeConfigError(f"{where}: payload file not found: {file}")
            body = file.read_bytes()
        else:
            body = json.dumps(payload).encode("utf-8")
        fresh = w.get("fresh_id", [])
        fresh = [fresh] if isinstance(fresh, str) else list(fresh)
        effect = _request(w["effect"], f"{where}.effect")
        if effect.value is None:
            raise ProbeConfigError(f"{where}.effect: `value` (a JSON pointer to the number the event changes) is required")
        pf.webhook.append(
            WebhookProbe(
                name=unique(str(w.get("name", f"webhook-{i + 1}")), where),
                url=str(w["url"]),
                signing=str(w["signing"]),
                secret=str(w.get("secret", "")),
                payload=body,
                fresh_id=[str(x) for x in fresh],
                effect=effect,
                settle=float(w.get("settle_seconds", 0)),
                concurrent=bool(w.get("concurrent", True)),
                headers={str(k): str(v) for k, v in w.get("headers", {}).items()},
                signature_header=w.get("signature_header"),
            )
        )

    for i, r in enumerate(raw.get("race", [])):
        where = f"[[race]] #{i + 1}"
        r = _expand(r, where)
        for key in ("as", "balance", "spend"):
            if key not in r:
                raise ProbeConfigError(f"{where}: `{key}` is required")
        if r["as"] not in auth:
            raise ProbeConfigError(f"{where}: no [auth.{r['as']}] section")
        balance = _request(r["balance"], f"{where}.balance", default_as=r["as"])
        if balance.value is None:
            raise ProbeConfigError(f"{where}.balance: `value` (a JSON pointer to the balance) is required")
        cost = r.get("cost", "measure")
        concurrency = int(r.get("concurrency", 20))
        if not 2 <= concurrency <= 200:
            raise ProbeConfigError(f"{where}: `concurrency` must be between 2 and 200")
        pf.race.append(
            RaceProbe(
                name=unique(str(r.get("name", f"race-{i + 1}")), where),
                as_=r["as"],
                balance=balance,
                spend=_request(r["spend"], f"{where}.spend", default_as=r["as"]),
                cost=None if cost == "measure" else float(cost),
                concurrency=concurrency,
                settle=float(r.get("settle_seconds", 0)),
                refused=[int(x) for x in r.get("refused", [400, 402, 403, 409, 422, 429])],
            )
        )
    if not (pf.ownership or pf.webhook or pf.race):
        raise ProbeConfigError(f"{path}: no [[ownership]], [[webhook]] or [[race]] probes defined")
    return pf
