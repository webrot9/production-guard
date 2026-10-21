# Probes — testing the running app

```bash
python3 scripts/fpg.py probe probes.toml            # or: fastapi-production-guard probe probes.toml
python3 scripts/fpg.py probe probes.toml --only spend --format json
```

| Exit | Meaning |
|---|---|
| 0 | every probe passed |
| 1 | at least one probe failed: the invariant is broken in the running app |
| 2 | the probe file is wrong (the message says where) |
| 3 | nothing failed, but at least one probe could not run a fair test |

**Probes write.** They create rows, deliver webhooks and spend credits. Point
them at a local or staging app with test users — never production.

## The file

```toml
base_url = "http://localhost:8000"
timeout = 15                                   # seconds per request

# One table per test user: the headers that authenticate them.
# ${NAME} is read from the environment; an unset variable is an error.
[auth.alice]
Authorization = "Bearer ${ALICE_TOKEN}"
[auth.bob]
Authorization = "Bearer ${BOB_TOKEN}"


# FPG001 — can bob reach alice's row?
[[ownership]]
name = "documents"
owner = "alice"
attacker = "bob"
create = { method = "POST", path = "/api/documents", json = { title = "probe" } }
id = "/id"                                     # JSON pointer into the create response
# id_value = "42"                              # ...or an existing row of alice's instead of `create`
requests = [
  { method = "GET",    path = "/api/documents/{id}" },
  { method = "PATCH",  path = "/api/documents/{id}", json = { title = "changed by bob" } },
  { method = "DELETE", path = "/api/documents/{id}" },
]
deny = [401, 403, 404]                         # answers that count as refused (default)
cleanup = { method = "DELETE", path = "/api/documents/{id}" }   # as the owner, optional


# FPG002 — is a retried delivery applied twice?
[[webhook]]
name = "paddle-purchase"
url = "/api/webhooks/paddle"
signing = "paddle"                             # stripe | paddle | svix | standard-webhooks | github | hmac-sha256 | none
secret = "${PADDLE_WEBHOOK_SECRET}"
payload = "probes/paddle-transaction-completed.json"   # a file next to this one, or an inline table
fresh_id = "/event_id"                         # pointer(s) given a new unique id each run
effect = { method = "GET", path = "/api/credits", as = "alice", value = "/balance" }
settle_seconds = 0                             # wait before reading `effect` (queued work: 2–5)
concurrent = true                              # also send two copies of one event at once


# FPG003 — do concurrent spends overspend or lose updates?
[[race]]
name = "generate"
as = "bob"
balance = { method = "GET", path = "/api/credits", value = "/balance" }
spend = { method = "POST", path = "/api/generate", json = { prompt = "probe" } }
cost = "measure"                               # or the number one spend costs
concurrency = 20
refused = [400, 402, 403, 409, 422, 429]       # answers that mean "not enough credits" (default)
```

## Making each probe a fair test

**Ownership.** Use two real accounts. The probe first checks that the owner
can read the row — if not, a refusal to the attacker would prove nothing and
the verdict is inconclusive. After the attacker's requests it re-reads the
row as the owner, so a DELETE that answered 404 but deleted anyway is still
caught. A 403 passes but earns a note: it confirms the id exists.

**Webhook.**
- The app must accept the probe's signature. Use the app's real webhook
  secret for that environment; `signing` must match the provider. Svix
  secrets keep their `whsec_` prefix.
- The event must be one the app acts on, for a user the app knows: put that
  user's id in the payload, and point `effect` at a number that event
  changes (a balance, a seat count, a row count endpoint).
- `fresh_id` matters for Stripe and Paddle, whose event id lives in the
  body: without it, a second run sends an id the app has already seen, and
  the "first" delivery is itself a replay. Svix, Standard Webhooks and
  GitHub carry the id in a header the probe generates.
- The concurrent check needs a numeric effect and a `fresh_id` (or a
  header-id scheme). It catches the check-then-insert dedupe that survives a
  sequential retry.

**Race.**
- Give the user a balance **smaller than `concurrency`** spends, or
  overspending cannot show (lost updates still can).
- `cost = "measure"` spends once first to learn the cost; set a number if a
  spend's cost varies.
- If the spend endpoint is rate-limited, add the limiter's status to
  `refused` and expect fewer successes — a 429 is a refusal, not a pass.

## Verdicts

- **PASS** — the invariant held under the attack the probe made.
- **FAIL** — it did not; the evidence lists the requests and answers that
  broke it, in order.
- **INCONCLUSIVE** — the probe could not set up a fair test, and says why.
  Fix the setup and run it again; never count it as a pass.
