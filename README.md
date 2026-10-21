# FastAPI Production Guard

Three checks for FastAPI codebases, run by a program rather than judged by a
model:

| | Invariant | What breaks without it |
|---|---|---|
| **FPG001** | A user-owned row is looked up together with its owner. | Any signed-in user reads, edits or deletes anyone's data by changing an id (IDOR). |
| **FPG002** | A webhook claims the provider's event id before it acts. | Stripe, Paddle or Clerk retries a delivery and your handler grants the credits, sends the email or provisions the seat again. |
| **FPG003** | A balance is read and written under one lock, or in one statement. | Two requests spend the last credit at once; the balance goes negative, or twenty spends lower it by one. |

These are the three bugs that pass code review because nothing in the code
is wrong — something is missing — and that an AI coding agent writes by
default, because the obvious code is the vulnerable code.

It ships as a **command-line tool** and as an **agent skill** for Claude
Code, Codex and the other agents `skills.sh` supports. The skill tells the
agent to run the tool, fix what it reports and run it again. The verdict is
always the tool's exit code, never the agent's opinion.

## Two ways to check

**`scan`** reads your source with Python's `ast` module. It finds the routes
and their dependencies, follows client-supplied ids into your helpers and
repositories, follows webhook handlers into services and queued jobs, and
tracks balance reads to the writes that depend on them. Each finding says
which line to change and the chain of facts it rests on.

**`probe`** sends real requests to your running app: a second user against
the first user's row; a webhook signed the way the provider signs it, replayed,
and sent twice at the same instant; twenty concurrent spends against a
balance that pays for five. The scan finds patterns; the probes prove
behaviour.

## Install

As an agent skill (Claude Code, Codex, Cursor, and others):

```bash
npx skills add webrot9/production-guard
```

As a Claude Code plugin:

```text
/plugin marketplace add webrot9/production-guard
/plugin install fastapi-production-guard@fastapi-production-guard
```

As a command-line tool (the PyPI package and the `v0.1.0` tag the Action
below uses are not published yet; until they are, use the skill or a clone):

```bash
uvx fastapi-production-guard@0.1.0 scan .
# or: pipx run fastapi-production-guard==0.1.0 scan .
```

Or with nothing installed but Python 3.11+, from a clone:

```bash
python3 skills/fastapi-production-guard/scripts/fpg.py scan path/to/app
```

There are no runtime dependencies. The package is the standard library and
about four thousand lines you can read.

## Scan

```text
$ fastapi-production-guard scan .
app/routers/documents.py:41:18  FPG001 [high] GET /documents/{document_id} (read_document)
  GET /documents/{document_id}: `document_id` comes from the client and reaches
  `db.get(Document, document_id)` without `user` in the query or an ownership check
  after it. Any signed-in user can read another user's Document by changing the id.
    · client-supplied `document_id` (GET /documents/{document_id})
    · caller identified by CurrentUser
    · lookup `db.get(Document, document_id)` at app/routers/documents.py:41
    · Document is user-owned: `owner_id` (app/models.py:52)
  fix: Put the owner in the lookup itself — add `Document.owner_id == user.id` to the
  query's filter — and answer 404 when nothing comes back …
```

| Option | |
|---|---|
| `--format text\|json\|sarif\|github` | `json` for agents, `sarif` for GitHub code scanning, `github` for inline annotations |
| `--fail-on high\|medium` | lowest confidence that fails the run (default `high`) |
| `--rule FPG001` | run one rule (repeatable) |
| `--exclude 'scripts/*'` | skip paths (repeatable) |
| `--include-tests` | also scan test files (skipped by default) |

Exit codes: `0` nothing at or above the threshold, `1` findings, `2` usage
or configuration error.

**Confidence.** *High* means every fact the finding rests on was read from
your code. *Medium* means one could not be — a model reached through
`self.model`, a `creator_id` that may or may not make a row private, a
dedupe check with no unique constraint the scanner could find. Medium
findings are printed but do not fail the run unless you ask.

The rule documents say exactly what each rule accepts as safe:
[FPG001](skills/fastapi-production-guard/references/FPG001.md) ·
[FPG002](skills/fastapi-production-guard/references/FPG002.md) ·
[FPG003](skills/fastapi-production-guard/references/FPG003.md).

### Suppressing a finding

On the flagged line or the line above, **with a reason**:

```python
return await db.get(Plan, plan_id)  # fpg: ignore[FPG001] price plans are public
```

A marker without a reason does not suppress anything; the finding is
reported with a note. An unexplained `ignore` is how a real bug gets buried.

### Configuration

`pyproject.toml` (or a standalone `fpg.toml`):

```toml
[tool.fastapi-production-guard]
exclude = ["scripts/*"]
fail-on = "high"
owner-columns = ["shop_id"]        # columns that make a row user-owned
principal-words = ["merchant"]     # dependencies that identify the caller
admin-words = ["backoffice"]       # dependencies that grant access to everything
balance-fields = ["gems"]          # fields that hold a spendable balance
max-depth = 3                      # calls followed into your own code
```

Every list adds to the built-in vocabulary; configuration can make the rules
see more, never less. An unknown key is an error, so a typo cannot silently
switch a check off.

### In CI

```yaml
# .github/workflows/production-guard.yml
name: production-guard
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: webrot9/production-guard@v0.1.0
        with:
          path: .
```

The action prints annotations on the pull request and fails on high
findings. For GitHub code scanning, run with `--format sarif -o fpg.sarif`
and upload the file with `github/codeql-action/upload-sarif`.

## Probe

Describe two test users and the requests that matter, in TOML, and point it
at a local or staging app — **never production**: probes create rows,
deliver webhooks and spend credits.

```toml
base_url = "http://localhost:8000"

[auth.alice]
Authorization = "Bearer ${ALICE_TOKEN}"
[auth.bob]
Authorization = "Bearer ${BOB_TOKEN}"

[[ownership]]
owner = "alice"
attacker = "bob"
create = { method = "POST", path = "/api/documents", json = { title = "probe" } }
requests = [
  { method = "GET", path = "/api/documents/{id}" },
  { method = "DELETE", path = "/api/documents/{id}" },
]

[[race]]
as = "bob"
balance = { method = "GET", path = "/api/credits", value = "/balance" }
spend = { method = "POST", path = "/api/generate", json = { prompt = "probe" } }
concurrency = 20
```

```text
$ fastapi-production-guard probe probes.toml
[FAIL] FPG003 race `race-1`: 12 spends succeeded on a balance that pays for 5;
12 spends succeeded but the balance fell by 2, not 12: updates were lost.
```

Exit codes: `0` all passed, `1` a probe failed, `2` the file is wrong, `3` a
probe could not run a fair test (an inconclusive result is never a pass).
Webhook signing is built in for Stripe, Paddle, Svix (Clerk, Resend),
Standard Webhooks (Polar), GitHub and plain HMAC-SHA256. The full format is
in [references/probes.md](skills/fastapi-production-guard/references/probes.md).

## What it does not do

- It checks three invariants. It is not a security review, a linter or a
  substitute for tests.
- Resolution is by name, not by type inference. Code that picks its
  repository at runtime, or calls a balance something unusual, may not be
  seen; the configuration above extends the vocabulary.
- It is tuned for FastAPI with SQLAlchemy or SQLModel. Other ORMs are
  recognised where they look alike (`Model.get(id)`, `select_for_update`),
  not modelled.
- False negatives are worse than they look and false positives cost trust,
  so when the two conflict the rules choose not to report. Medium findings
  are where they say "probably" instead.

## Data handling

`scan` reads files under the path you give it and nothing else. It makes no
network request and collects no telemetry. `probe` sends HTTP requests only
to the `base_url` in your probe file, with the headers you put there. Neither
writes anywhere except stdout or the `--output` file you name.

## Where the three rules come from

They are the load-bearing invariants of
[The Fabrica](https://www.thefabrica.dev/?utm_source=fastapi-production-guard&utm_medium=readme&utm_campaign=oss),
a commercial FastAPI + Next.js SaaS foundation, where each one is enforced by
the code generator, the repository layer and a test. This project is the
part of that work that is useful on its own, in any codebase. You do not need
The Fabrica to use it, and nothing here calls home.

## Contributing

A false positive or a missed bug is a fixture: add the smallest snippet that
reproduces it under `tests/fixtures/<rule>/safe/` or `vulnerable/`, and the
test that expects the right answer. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
uv run --extra dev ruff check skills tests
uv run --extra dev mypy
uv run --extra dev pytest
```

## License

[MIT](LICENSE).
