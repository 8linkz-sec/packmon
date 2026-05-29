# Agent Guide -- Feed Syncers & Queue

Scope: `internal/feed/` -- `manager.go` (orchestration/scheduler), `queue.go`
(priority queue), `gitutil.go`, ecosystem/cvss helpers, and the per-source
syncers `osv/`, `ghsa/`, `malicious/`, `vulncheck/`, `nvd/`, `cisakev/`,
`epss/`, `socket/`. Primary owner agent: **data-feeds-engineer**.

Read `AGENTS.md` (root) and `DESIGN.md` (feed source table, priority queue,
health rules) first.

## Invariants (do not break)

- All sources normalize to one schema; dedup key is the advisory ID
  (CVE/GHSA/OSV); the `source` field records provenance. Data is permanent (no
  TTL); re-check priority is driven by oldest `updated_at`.
- Socket.dev is async, rate-limited (500/h), behind the priority queue
  (0 manual, 1 unknown, 2 has-findings, 3 oldest). It is disabled by default.
- Git-based syncers (GHSA, OpenSSF) clone untrusted content. Read files only
  through `os.OpenRoot`/`Root.ReadFile` confinement to prevent path traversal;
  pass fixed argv to `git` (never shell). The `#nosec G204` on the fixed-argv
  `git diff` call is justified because the hash input is a rev-parsed hex.
- Never log API keys (NVD, VulnCheck, Socket). Log only "key not configured".
- Feed health (DESIGN.md sec 3.5): unhealthy if last successful sync > 48h, last
  sync failed, OR zero entries in DB.

## Current open landmines (see Audit.md)

> Status (2026-05-29): the items in this section were addressed across the
> Audit.md "Fix-Runde" passes. Audit.md is authoritative; project-wide only the
> external GitLab-runner test remains open. Keep the notes below as guardrails
> so the fixes are not regressed.

- **L6:** the "zero entries => unhealthy" rule is NOT implemented; health checks
  only cover 48h/failed. There are also two parallel health functions
  (`api/v1/handler.go` and `api/admin/handler.go`) that can drift. Add the
  zero-entries check to both, or unify them.

## Tests

```bash
go test ./internal/feed/...
```
For git syncers, add a regression test that a `../../../` path in a changed-file
list reads nothing outside the repo (see `ghsa/syncer_test.go`).
