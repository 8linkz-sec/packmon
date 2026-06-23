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
  and is intentionally unauthenticated for local integration tests. Sensitive
  write endpoints such as package refresh and feed imports are unauthenticated
  only from a loopback peer; non-loopback callers still need API-key auth. It is
  a strict enum (default `production`); a typo fails startup, so it cannot
  silently default-on. Keep it that way.
- System settings (block threshold, rate limits) are loaded from the DB at
  startup via `applyStoredSystemSettings` before the server starts serving.

## Current Guardrails

These notes are guardrails for behavior that has regressed before. Keep them in
sync with `DESIGN.md` and `SECURITY.md` when the behavior intentionally changes.

- **H3:** dev mode keeps local integration tests keyless, but package refresh
  and feed imports must remain guarded for non-loopback peers. If you touch
  auth or routing, preserve `requiresAuthInDev` and its loopback exception.
- **L5:** `noop.go` has no `//go:build dev` tag, so the in-memory unauthenticated
  store compiles into every release binary. Consider gating it behind a build tag
  and/or logging a loud WARN at startup when dev mode is active.

## Tests

```bash
go test ./cmd/packmon-server/...
```
Note: `admin_pages_test.go` / `system_settings_test.go` exercise the noop store,
not real SQL. DB behavior is covered in `tests/integration`.
