# Changelog

## 0.1.0

First release.

- `scan`: FPG001 (unscoped lookup of a user-owned row), FPG002 (webhook
  without event-id deduplication), FPG003 (balance read and written without
  serialisation). Text, JSON, SARIF and GitHub annotation output;
  suppressions that require a reason; configuration in `pyproject.toml`.
- `probe`: ownership, webhook replay (sequential and concurrent) and
  concurrent-spend probes against a running app, with Stripe, Paddle, Svix,
  Standard Webhooks, GitHub and HMAC-SHA256 signing.
- Agent skill (`skills/fastapi-production-guard`), Claude Code plugin and
  marketplace manifests, GitHub Action.
