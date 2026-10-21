# Contributing

The rules are judged by two numbers: the bugs they find and the correct code
they leave alone. Every change should move one without moving the other, and
the test suite is how that is shown.

## A false positive

1. Reduce it to the smallest code that still triggers the finding.
2. Add it to `tests/fixtures/<rule>/safe/` (ownership, webhooks, balances),
   with a comment saying why it is correct code.
3. Run `uv run --extra dev pytest`: the rule's test now fails. Change the
   rule until it passes **and** every vulnerable fixture is still found.

## A missed bug

The same, under `tests/fixtures/<rule>/vulnerable/`, and add the expected
`(path, line)` to the rule's test.

## A probe

`tests/probe_app.py` is a small standard-library app with each bug (`mode="vulnerable"`)
and each fix (`mode="safe"`). A probe change needs a case where it FAILs on
the first and PASSes on the second.

## The rules for the code

- Standard library only. The skill folder must run on a bare `python3`.
- `ruff check`, `mypy --strict` and `pytest` clean.
- When a heuristic has to choose, it chooses not to report — and the
  choice gets a comment saying what it gives up.
