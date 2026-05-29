# Agent Guide -- packmon-server entrypoint

Scope: `cmd/packmon-server/` -- main entrypoint, DI/wiring, graceful shutdown,
the `migrate` subcommand, background workers (feed sync, queue), feed/system
settings bootstrap, and the in-memory `noop` store used in development mode.
Primary owner agent: **backend-engineer**; coordinate with platform-ci-engineer
for runtime/deploy concerns and security-engineer for the dev-mode auth path.

Read `AGENTS.md` (root), `DESIGN.md`, and `SECURITY.md` first.

## Invariants (do not break)

- `packmon-server migrate` is the only path that applies migrations. Normal
  startup reads the schema version and REFUSES to start on mismatch -- it must
  not silently migrate (main.go, "DE-27").
- Graceful shutdown order: stop accepting new traffic (`/readyz` -> 503), cancel
  the context (stops feed sync + queue worker), drain in-flight HTTP requests,
  close the DB pool, exit 0.
- Dev mode (`PACKMON_SERVER_MODE=development`) selects the in-memory `noopStore`
  and is intentionally unauthenticated for local integration tests. It is a
  strict enum (default `production`); a typo fails startup, so it cannot silently
  default-on. Keep it that way.
- System settings (block threshold, rate limits) are loaded from the DB at
  startup via `applyStoredSystemSettings` before the server starts serving.

## Current open landmines (see Audit.md)

> Status (2026-05-29): the items in this section were addressed across the
> Audit.md "Fix-Runde" passes. Audit.md is authoritative; project-wide only the
> external GitLab-runner test remains open. Keep the notes below as guardrails
> so the fixes are not regressed.

- **H3:** in dev mode the unauthenticated path now also covers
  `POST /api/v1/feeds/import` (a data-mutating write). Re-introduce a guard for
  write endpoints; do not let dev mode expose writes.
- **L5:** `noop.go` has no `//go:build dev` tag, so the in-memory unauthenticated
  store compiles into every release binary. Consider gating it behind a build tag
  and/or logging a loud WARN at startup when dev mode is active.

## Tests

```bash
go test ./cmd/packmon-server/...
```
Note: `admin_pages_test.go` / `system_settings_test.go` exercise the noop store,
not real SQL. DB behavior is covered in `tests/integration`.
