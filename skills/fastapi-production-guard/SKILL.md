---
name: fastapi-production-guard
description: Runs three executed checks on a FastAPI codebase and fixes what they find - IDOR (a user-owned row looked up by a client-supplied id without the current user), webhook handlers that do not deduplicate on the provider's event id (Stripe, Paddle, Clerk/Svix, GitHub), and credit/quota/balance updates that race under concurrent requests. Use when reviewing or changing FastAPI routes that take ids, webhook endpoints, or anything that spends credits; when asked for a security review, an IDOR check, an idempotency check or a race-condition check of a Python API; and before declaring such a change done. The verdicts come from a deterministic scanner and from HTTP probes against the running app, not from model judgment.
license: MIT
compatibility: Needs python3 (3.11 or newer) on PATH. The scanner reads local files only and makes no network request; probes send requests only to the base_url in the probe file the user provides.
metadata:
  version: "0.1.0"
  short-description: Executed IDOR, webhook-idempotency and credit-race checks for FastAPI
---

# FastAPI Production Guard

Three invariants, checked by running code rather than by reading it and
forming an opinion:

| Rule | Invariant | Fix reference |
|---|---|---|
| FPG001 | A user-owned row is only ever looked up together with its owner. | [references/FPG001.md](references/FPG001.md) |
| FPG002 | A webhook claims the provider's event id before it acts. | [references/FPG002.md](references/FPG002.md) |
| FPG003 | A balance is read and written under one lock, or in one statement. | [references/FPG003.md](references/FPG003.md) |

Your job is to run the checks, fix what they report, and re-run them. Whether
the code is safe is decided by the scanner's exit code and the probes'
verdicts. Do not replace either with your own reading of the code, in either
direction: do not declare a finding a false positive because the code "looks
fine", and do not declare the code safe because the scan found nothing it
was not designed to find.

`scripts/fpg.py` below is relative to the directory that contains this
file. It needs only `python3` — no install, no virtualenv, no network.

## 1. Scan

From the application's root (the directory holding the FastAPI package):

```bash
python3 <this-skill-dir>/scripts/fpg.py scan . --format json
```

- Exit code `0`: no finding at or above the threshold (default `high`).
  `1`: at least one. `2`: a usage or configuration error — read stderr.
- Every finding has `rule`, `confidence`, `path`, `line`, `message`,
  `evidence` (the facts it rests on, in order) and `fix`.
- `summary.routes == 0` means no FastAPI route was found under that path:
  you are probably in the wrong directory. Say so rather than reporting a
  clean result.

Read the `evidence` before the `message`. It names the exact lookup, the
helper it went through, the owner column, the lock that is missing — which
line to change is in there.

## 2. Fix

For each finding, open `path:line`, read the fix reference for its rule, and
apply the smallest change that establishes the invariant **in the place the
evidence points at**:

- FPG001: put the owner into the query (`Model.owner_id == user.id`), or
  route the lookup through one `get_for_user()` on the repository. Answer
  404 for someone else's row, not 403.
- FPG002: insert the provider's event id into a table with a UNIQUE
  constraint, in the same transaction as the side effects, and stop on the
  conflict. A `SELECT` before the insert is not enough on its own.
- FPG003: lock before reading (`.with_for_update()` on the owner's row, or
  an advisory lock), or move the check into the `UPDATE ... WHERE balance
  >= cost`. `asyncio.Lock` does not count: it serialises one process.

Then run the scan again. A finding is resolved when the scan stops reporting
it, not when the code looks right to you.

Medium-confidence findings rest on one fact the scanner could not establish
(a model it could not resolve, a `creator_id` that may or may not mean
"private"). Do not fix or dismiss them on a guess. Check the fact in the
code, and if the code cannot answer it (is a Note private to its author?),
ask the user.

### Suppressing

Only when the user agrees that the flagged code is intended, and always
with the reason on the same line or the line above:

```python
return await db.get(Plan, plan_id)  # fpg: ignore[FPG001] price plans are public
```

A marker without a reason does not suppress; the scan reports it. Never
rename variables, split functions or otherwise reshape code so that the
scanner stops seeing a pattern that is still there — that hides the bug
from the next reader too.

## 3. Prove it against the running app (when it can run)

The scan finds patterns; the probes test behaviour. If the user can start
the app locally or in staging with two test users, write a probe file and
run it — see [references/probes.md](references/probes.md) for the format
and a complete example:

```bash
python3 <this-skill-dir>/scripts/fpg.py probe probes.toml
```

- `FAIL`: the invariant is broken in the running app. This outranks a clean
  scan.
- `INCONCLUSIVE` (exit code 3): the probe could not set up a fair test — a
  create that failed, an event that changed nothing visible, an app that
  did not answer. Fix the probe setup; never report it as a pass.
- Probes create rows, deliver webhooks and spend credits. Run them only
  against an environment the user has said is safe to write to, never
  production, and with test users only.
- Secrets and tokens go in environment variables (`${NAME}` in the file),
  never in the probe file itself.

## 4. Report

Tell the user, briefly:

1. what the scan reported before and after (rule, `path:line`, one line each);
2. what you changed, per finding;
3. what is suppressed, with each reason, and who agreed to it;
4. probe verdicts, or that probes were not run and why;
5. what the checks do not cover. They see three invariants, in code that
   names things the way FastAPI and SQLAlchemy code usually does. They are
   not a security review of the whole application.

## Limits worth knowing

- Resolution is by name: a lookup reached through a dynamically chosen
  repository, or a balance whose field is called something unusual, may not
  be seen. `[tool.fastapi-production-guard]` in `pyproject.toml` can teach
  it more words (`owner-columns`, `balance-fields`, `principal-words`,
  `admin-words`); see the README.
- FPG001 skips routes with no identified caller (unauthenticated by design)
  and routes behind an admin dependency.
- FPG002 treats an authenticated route as webhook *management*, not an
  incoming webhook.
