"""FPG002 — a webhook's side effects run without deduplicating on the event id.

Every payment and auth provider delivers webhooks at least once. Stripe
retries for three days, Paddle for longer, Svix (Clerk, Resend) on any
non-2xx — and a timeout on *your* side counts as a failure even when your
code finished. A handler that grants credits, sends an email or provisions
a seat on each delivery does it again on each retry.

The rule finds webhook routes (POST, and a path or name that says webhook,
or code that verifies a provider signature), follows the code they reach —
helpers, services, background tasks, `.delay()`ed jobs — and looks for one
of three things keyed on the event id:

- an atomic claim: `INSERT ... ON CONFLICT DO NOTHING`, `on_conflict_do_*`,
  Redis `SET NX`;
- an insert whose unique violation is caught (`except IntegrityError`);
- a lookup of the event id followed by an early return. That one is
  reported anyway (medium) unless the table has a unique constraint on the
  id, because two concurrent deliveries both pass the check.

None of them → finding.
"""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field

from fastapi_production_guard.analysis import flow
from fastapi_production_guard.analysis.fastapi import DepKind, Route
from fastapi_production_guard.analysis.models import model_name
from fastapi_production_guard.analysis.names import (
    call_name,
    dotted,
    last_name,
    string_constants,
    tokens,
)
from fastapi_production_guard.analysis.project import FunctionInfo, Module
from fastapi_production_guard.findings import Confidence, Finding, Location
from fastapi_production_guard.rules import ScanContext

RULE = "FPG002"
_MAX_FUNCTIONS = 250

_PROVIDERS: dict[str, tuple[str, str]] = {
    # token: (display name, where the event id lives)
    "stripe": ("Stripe", '`event["id"]` (or `event.id`)'),
    "paddle": ("Paddle", '`payload["event_id"]`'),
    "clerk": ("Clerk", "the `svix-id` header"),
    "svix": ("Svix", "the `svix-id` header"),
    "resend": ("Resend", "the `svix-id` header"),
    "github": ("GitHub", "the `X-GitHub-Delivery` header"),
    "shopify": ("Shopify", "the `X-Shopify-Event-Id` header"),
    "lemonsqueezy": ("Lemon Squeezy", "the order/subscription id plus `meta.event_name`"),
    "lemon": ("Lemon Squeezy", "the order/subscription id plus `meta.event_name`"),
    "polar": ("Polar", "the `webhook-id` header"),
    "twilio": ("Twilio", "the `I-Twilio-Idempotency-Token` header"),
    "slack": ("Slack", '`payload["event_id"]`'),
    "mailgun": ("Mailgun", '`event-data["id"]`'),
    "sendgrid": ("SendGrid", '`sg_event_id`'),
    "postmark": ("Postmark", "the message id plus record type"),
    "razorpay": ("Razorpay", "the `x-razorpay-event-id` header"),
    "mollie": ("Mollie", "the payment id (Mollie sends ids, not events)"),
    "coinbase": ("Coinbase", '`event["id"]`'),
    "plaid": ("Plaid", "the `webhook_code` plus item id"),
    "linear": ("Linear", "the `Linear-Delivery` header"),
}
_SIGNATURE_HEADERS = frozenset(
    {
        "stripe-signature", "paddle-signature", "svix-signature", "svix-id", "webhook-signature",
        "webhook-id", "x-hub-signature", "x-hub-signature-256", "x-shopify-hmac-sha256",
        "x-signature", "x-twilio-signature", "x-razorpay-signature", "linear-signature",
        "x-github-delivery", "x-slack-signature",
    }
)
_VERIFY_CALLS = frozenset(
    {"construct_event", "verify_signature", "verify_webhook", "verify_webhook_signature", "unwrap", "verify_header"}
)
_ATOMIC_CALLS = frozenset({"on_conflict_do_nothing", "on_conflict_do_update", "setnx", "insert_or_ignore"})
_UNIQUE_ERRORS = frozenset(
    {"IntegrityError", "UniqueViolation", "UniqueViolationError", "DuplicateKeyError", "DuplicateKey"}
)
_EVENT_KEYS = frozenset(
    {
        "id", "event_id", "eventid", "notification_id", "delivery_id", "webhook_id", "message_id",
        "idempotency_key", "svix-id", "webhook-id", "x-github-delivery", "idempotency-key",
        "x-shopify-event-id", "x-shopify-webhook-id", "x-razorpay-event-id", "linear-delivery",
        "sg_event_id", "i-twilio-idempotency-token",
    }
)
_EVENT_HOLDERS = frozenset({"event", "evt", "payload", "notification", "webhook", "message", "msg", "delivery", "body", "data"})
_EVENT_TABLE_WORDS = frozenset(
    {"event", "events", "webhook", "webhooks", "delivery", "deliveries", "idempotency", "processed", "notification", "inbox", "dedup", "dedupe"}
)
_DEDUPE_WORDS = frozenset({"duplicate", "duplicated", "dedupe", "dedup", "deduplicate", "idempotent", "idempotency", "processed", "replay", "seen"})
_TASK_DISPATCH = frozenset({"delay", "apply_async", "send", "kiq", "enqueue", "send_with_options", "s", "si"})
# Effects that happen again on a retry: a new row, a job, a message, money.
_ADDITIVE_CALLS = frozenset(
    {"add", "add_all", "insert", "send", "send_email", "send_mail", "post", "create", "publish", "enqueue",
     "delay", "apply_async", "add_task", "grant", "charge", "refund", "provision", "invite", "kiq",
     "create_task", "notify", "deliver", "issue", "credit", "debit", "deduct", "award"}
)
# Effects that set state, and are usually harmless to repeat.
_SETTING_CALLS = frozenset({"update", "delete", "merge", "upsert", "put", "patch", "save", "execute", "set_status", "mark"})


@dataclass
class _Evidence:
    atomic: list[str] = field(default_factory=list)
    caught: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)
    checked_unique: bool = False
    effects: list[str] = field(default_factory=list)
    settings: list[str] = field(default_factory=list)
    visited: int = 0


def _is_webhook(route: Route) -> bool:
    if "post" not in route.methods:
        return False
    # An incoming webhook is signed, not signed in. A route that identifies a
    # user is the API that *manages* webhooks (create an endpoint, redeliver
    # an event), and deduplication is not its job.
    if any(route.has(k) for k in (DepKind.PRINCIPAL, DepKind.AUTHZ, DepKind.ADMIN)):
        return False
    words = set(tokens(route.path)) | set(tokens(route.function.name))
    if words & {"webhook", "webhooks", "hook", "hooks"}:
        return True
    # The signature (Header(alias="Stripe-Signature")) counts here, the decorators do not.
    for n in [*flow.walk_body(route.function.node), *(d for a in (route.function.node.args.defaults + [k for k in route.function.node.args.kw_defaults if k]) for d in ast.walk(a))]:
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.lower() in _SIGNATURE_HEADERS:
            return True
        if isinstance(n, ast.Call) and call_name(n) in _VERIFY_CALLS:
            return True
    for arg in route.function.params:
        if arg.arg.lower().replace("_", "-") in _SIGNATURE_HEADERS:
            return True
    return False


def _provider(route: Route) -> tuple[str, str] | None:
    words = set(tokens(route.path)) | set(tokens(route.function.name)) | set(tokens(route.function.module.rel))
    for n in flow.walk(route.function.node):
        if n in route.function.node.decorator_list:
            continue
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            words |= set(tokens(n.value))
        elif isinstance(n, ast.Name):
            words |= set(tokens(n.id))
    for p in route.function.params:
        words |= set(tokens(p.arg))
    for token, info in _PROVIDERS.items():
        if token in words:
            return info
    return None


def _references_event_id(fn: FunctionInfo) -> bool:
    for n in flow.walk_body(fn.node):
        if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str):
            key = n.slice.value.lower()
            holder = last_name(n.value) or ""
            # `event["id"]` is the event's id; `row["id"]` is not.
            if key in _EVENT_KEYS - {"id"} or (key == "id" and set(tokens(holder)) & _EVENT_HOLDERS):
                return True
        elif isinstance(n, ast.Call) and call_name(n) == "get" and n.args:
            a = n.args[0]
            if isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.lower() in _EVENT_KEYS:
                return True
        elif isinstance(n, ast.Attribute) and n.attr == "id" and isinstance(n.value, ast.Name):
            if set(tokens(n.value.id)) & _EVENT_HOLDERS:
                return True
        elif isinstance(n, (ast.Name, ast.arg, ast.keyword)):
            ident = n.id if isinstance(n, ast.Name) else n.arg
            if ident is None:
                continue
            if ident.lower().replace("_", "-") in _EVENT_KEYS - {"id"}:
                return True
            w = set(tokens(ident))
            if "id" in w and w & {"event", "evt", "delivery", "svix", "idempotency", "notification", "webhook", "msg", "message"}:
                return True
            if "key" in w and "idempotency" in w:
                return True
    return False


def _inserted_tables(ctx: ScanContext, fn: FunctionInfo) -> set[str]:
    """Models a function writes: `insert(X)`, `session.add(X(...))`, `repo.create(X(...))`."""
    out: set[str] = set()
    for n in flow.walk_body(fn.node):
        if not isinstance(n, ast.Call):
            continue
        for arg in n.args[:1]:
            target = model_name(arg.func) if isinstance(arg, ast.Call) else model_name(arg)
            if target and target in ctx.project.classes and (call_name(n) in {"insert", "add", "merge"} or isinstance(arg, ast.Call)):
                out.add(target)
    return out


def _is_atomic_claim(name: str) -> bool:
    lowered = name.lower()
    return name in _ATOMIC_CALLS or any(
        marker in lowered for marker in ("on_conflict", "do_nothing", "or_ignore", "insert_ignore", "setnx")
    )


def _event_column(name: str) -> bool:
    n = name.lower()
    return n != "id" and (n in _EVENT_KEYS or n.replace("_", "-") in _EVENT_KEYS or "event" in n or "delivery" in n)


def _unique_event_column(ctx: ScanContext, model: str) -> bool:
    """Does the table enforce one row per event id?

    A surrogate integer `id` primary key does not count: it is unique, and it
    is not the event's id. A string `id` primary key does — some tables store
    the provider's event id as their key.
    """
    for cls in ctx.project.class_and_bases(model):
        for item in ast.walk(cls.node):
            if isinstance(item, ast.Call):
                name = last_name(item.func)
                if name in {"UniqueConstraint", "PrimaryKeyConstraint"} and any(
                    _event_column(s) for s in string_constants(item)
                ):
                    return True
                if name == "Index" and any(kw.arg == "unique" for kw in item.keywords) and any(
                    _event_column(s) for s in string_constants(item)
                ):
                    return True
            if not isinstance(item, (ast.Assign, ast.AnnAssign)):
                continue
            target = item.targets[0] if isinstance(item, ast.Assign) else item.target
            if not isinstance(target, ast.Name):
                continue
            stringly = any(isinstance(n, ast.Name) and n.id in {"str", "String", "Text", "VARCHAR"} for n in ast.walk(item))
            if not (_event_column(target.id) or (target.id == "id" and stringly)):
                continue
            for kw in (k for c in ast.walk(item) if isinstance(c, ast.Call) for k in c.keywords):
                if kw.arg in {"unique", "primary_key"} and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
    return False


class _Reach:
    """Functions reachable from a handler, following calls, task dispatch and handler tables."""

    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx

    def functions(self, start: FunctionInfo) -> list[FunctionInfo]:
        seen: list[FunctionInfo] = [start]
        queue: deque[tuple[FunctionInfo, int]] = deque([(start, 0)])
        while queue and len(seen) < _MAX_FUNCTIONS:
            fn, depth = queue.popleft()
            if depth >= self.ctx.max_depth + 2:
                continue
            for target in self._targets(fn):
                if target not in seen:
                    seen.append(target)
                    queue.append((target, depth + 1))
        return seen

    def _targets(self, fn: FunctionInfo) -> list[FunctionInfo]:
        out: list[FunctionInfo] = []
        module = fn.module
        for n in flow.walk_body(fn.node):
            if isinstance(n, ast.Call):
                func = n.func
                # task.delay(...), task.apply_async(...): the task is the receiver
                if isinstance(func, ast.Attribute) and func.attr in _TASK_DISPATCH:
                    out += self._resolve(module, fn, func.value)
                out += self._resolve(module, fn, func)
                # background_tasks.add_task(f, ...), run_in_threadpool(f, ...), create_task(...)
                for a in n.args[:1]:
                    if isinstance(a, (ast.Name, ast.Attribute)):
                        out += [t for t in self._resolve(module, fn, a) if t.name != fn.name]
            elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                # HANDLERS[event_type](...) with HANDLERS a module-level dict of functions
                for m, value in self.ctx.project.assignments.get(n.id, []):
                    if m is module and isinstance(value, ast.Dict):
                        for v in value.values:
                            if isinstance(v, (ast.Name, ast.Attribute)):
                                out += self._resolve(module, fn, v)
        return out

    def _resolve(self, module: Module, fn: FunctionInfo, ref: ast.expr) -> list[FunctionInfo]:
        if isinstance(ref, ast.Attribute) and isinstance(ref.value, ast.Name) and ref.value.id in {"self", "cls"}:
            return self.ctx.project.methods_of(fn.class_name, ref.attr) if fn.class_name else []
        if isinstance(ref, (ast.Name, ast.Attribute)):
            found = self.ctx.project.resolve_function(module, ref, strict=True)
            # A method name on an object of unknown type that several classes
            # define (`get`, `verify`, `process`) would pull half the project
            # in, and with it other features' side effects. Follow it only
            # when it can mean one thing.
            if isinstance(ref, ast.Attribute) and len({(f.module.rel, f.qualname) for f in found}) > 1:
                return []
            return found
        return []


def _examine(ctx: ScanContext, fns: list[FunctionInfo]) -> _Evidence:
    ev = _Evidence(visited=len(fns))
    for fn in fns:
        has_event_id = _references_event_id(fn)
        event_tables = {t for t in _inserted_tables(ctx, fn) if set(tokens(t)) & _EVENT_TABLE_WORDS}
        where = f"{fn.qualname}() at {fn.module.rel}:{fn.node.lineno}"
        for n in flow.walk_body(fn.node):
            if isinstance(n, ast.Call):
                name = call_name(n) or ""
                set_nx = name == "set" and any(
                    kw.arg == "nx" and isinstance(kw.value, ast.Constant) and kw.value.value for kw in n.keywords
                )
                if (_is_atomic_claim(name) or set_nx) and (has_event_id or event_tables):
                    ev.atomic.append(f"`{ctx.snippet(n, 50)}` in {where}")
                if set(tokens(name)) & _DEDUPE_WORDS and has_event_id and not name[:1].isupper():
                    ev.checked.append(f"`{ctx.snippet(n, 50)}` in {where}")
                words = set(tokens(name))
                recv = dotted(flow.receiver(n)) or ""
                label = f"`{(recv + '.') if recv else ''}{name}()` in {fn.qualname}()"
                re_add = name in {"add", "add_all", "merge"} and not (
                    n.args and isinstance(n.args[0], (ast.Call, ast.List))
                )
                if re_add:
                    # `session.add(existing)` re-attaches a row it already has; only
                    # `session.add(Model(...))` inserts one.
                    ev.settings.append(label)
                elif name in _ADDITIVE_CALLS or (words & _ADDITIVE_CALLS and not name[:1].isupper()):
                    ev.effects.append(label)
                elif name in _SETTING_CALLS or words & {"mark", "set", "update", "delete"}:
                    ev.settings.append(label)
            elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Attribute):
                ev.effects.append(f"`{ctx.snippet(n, 40)}` in {fn.qualname}()")
            elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                text = n.value.upper()
                if ("ON CONFLICT" in text or "INSERT OR IGNORE" in text or "INSERT IGNORE" in text) and (has_event_id or event_tables):
                    ev.atomic.append(f"raw SQL with ON CONFLICT in {where}")
            elif isinstance(n, ast.ExceptHandler) and n.type is not None:
                caught = {last_name(t) for t in (n.type.elts if isinstance(n.type, ast.Tuple) else [n.type])}
                if caught & _UNIQUE_ERRORS and (has_event_id or event_tables):
                    ev.caught.append(f"`except {', '.join(sorted(c for c in caught if c))}` in {where}")
            elif isinstance(n, ast.If) and has_event_id and flow.contains_raise_or_return(n.body):
                # `if await seen(event_id): return` / `if existing: return`
                for c in (x for x in ast.walk(n.test) if isinstance(x, ast.Call)):
                    cname = call_name(c) or ""
                    if set(tokens(cname)) & (_DEDUPE_WORDS | {"exists", "get", "first", "scalar", "one", "find"}):
                        ev.checked.append(f"`if {ctx.snippet(n.test, 50)}: return` in {where}")
                        break
        for table in event_tables:
            if _unique_event_column(ctx, table):
                ev.checked_unique = True
        if has_event_id and any(
            isinstance(n, ast.If) and isinstance(n.test, (ast.Name, ast.Compare, ast.UnaryOp)) and flow.contains_raise_or_return(n.body)
            for n in flow.walk_body(fn.node)
        ):
            # `existing = await session.get(ProcessedEvent, event_id)` / `if existing: return`
            for n in flow.walk_body(fn.node):
                if (
                    isinstance(n, ast.Call)
                    and call_name(n) in {"get", "scalar", "first", "one_or_none", "exists", "find_one"}
                    and any(
                        isinstance(a, ast.Name) and model_name(a) and set(tokens(a.id)) & _EVENT_TABLE_WORDS
                        for a in n.args
                    )
                ):
                    ev.checked.append(f"`{ctx.snippet(n, 50)}` then an early return in {where}")
                    if any(_unique_event_column(ctx, a.id) for a in n.args if isinstance(a, ast.Name)):
                        ev.checked_unique = True
                    break
    return ev


def check(ctx: ScanContext) -> list[Finding]:
    reach = _Reach(ctx)
    findings: list[Finding] = []
    for route in ctx.routes.routes:
        if not _is_webhook(route):
            continue
        fns = reach.functions(route.function)
        ev = _examine(ctx, fns)
        if ev.atomic or ev.caught:
            continue
        provider = _provider(route)
        name, id_hint = provider if provider else ("The provider", "the event's id field or delivery-id header")
        fn = route.function
        effects = list(dict.fromkeys(ev.effects))
        if ev.checked and ev.checked_unique:
            continue
        if ev.checked:
            message = (
                f"{route.label}: the handler checks whether it has seen the event before acting, but nothing "
                f"makes the check atomic. {name} can deliver the same event twice at once (a retry racing "
                f"a slow first attempt); both deliveries pass the check and both run the side effects."
            )
            confidence = Confidence.MEDIUM
            evidence = [*ev.checked[:3], "no unique constraint on the event id was found, and no conflict is caught"]
        else:
            message = (
                f"{route.label}: {name} delivers each event at least once, and nothing in this handler or the "
                f"{ev.visited - 1} function(s) it reaches deduplicates on the event id. A retried delivery runs "
                f"every side effect again."
            )
            settings = list(dict.fromkeys(ev.settings))
            confidence = Confidence.HIGH if effects else Confidence.MEDIUM
            evidence = [f"followed {ev.visited} function(s) from {fn.qualname}()"]
            if effects:
                evidence.append("repeats on retry: " + ", ".join(effects[:5]) + (" …" if len(effects) > 5 else ""))
            elif settings:
                evidence.append(
                    "only state-setting effects were recognised (" + ", ".join(settings[:3])
                    + "); if every one of them is safe to repeat, suppress this with that reason"
                )
            else:
                evidence.append("no side effect was recognised; if the handler only forwards the payload, the consumer must deduplicate")
        fix = (
            f"Claim the event before acting on it, in the same transaction as its side effects: insert "
            f"{id_hint} into a table with a UNIQUE constraint on (provider, event_id) and stop on the "
            f"conflict — `insert(ProcessedEvent).values(...).on_conflict_do_nothing()` and check the row "
            f"count, or catch IntegrityError. Then return 200, so the provider stops retrying."
        )
        findings.append(
            Finding(
                rule=RULE,
                # The decorator line, so a suppression comment sits above the route like any other.
                location=Location(fn.module.rel, route.decorator_line, 0),
                message=message,
                confidence=confidence,
                subject=f"{route.label} ({fn.qualname})",
                fix=fix,
                evidence=tuple(evidence),
            )
        )
    return findings
