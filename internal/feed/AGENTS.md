# Agent Guide -- Feed Syncers & Queue

Scope: `internal/feed/` -- `manager.go` (orchestration/scheduler), `queue.go`
(priority queue), `gitutil.go`, ecosystem/cvss helpers, and the per-source
syncers `osv/`, `ghsa/`, `malicious/`, `vulncheck/`, `nvd/`, `cisakev/`,
`epss/`, `socket/`, `reversinglabs/`, `endoflife/`. Primary owner agent:
**data-feeds-engineer**.

Read `AGENTS.md` (root) and `DESIGN.md` (feed source table, priority queue,
health rules) first.

## Invariants (do not break)

- All sources normalize to one schema; dedup key is the advisory ID
  (CVE/GHSA/OSV); the `source` field records provenance. Data is permanent (no
  TTL); re-check priority is driven by oldest `updated_at`.
- Socket.dev is async, rate-limited (500/h), behind the priority queue
  (0 manual, 1 unknown, 2 has-findings, 3 oldest). It is disabled by default.
- ReversingLabs (`reversinglabs/`) is async, demand-driven, self-mode only, and
  disabled by default. It is NOT a bulk syncer: `/api/v1/check` schedules a
  version lookup (at most once per TTL, default 24h) only for packages no other
  feed covers, and the worker writes `package_reputation_cache`. The scheduler
  and worker MUST share one PURL predicate; unmappable/unsupported packages get
  a terminal `unsupported` cache row (no HTTP call, excluded from due queries).
  `external` mode is rejected at config load; batch size is capped at 5.
- endoflife.date (`endoflife/`) is a free public lifecycle metadata feed with
  no API key. It is self-mode only, stores normalized product/release/package-map
  rows, and must preserve existing cached data on 304, rate-limit, parse, or
  network failures. It has no external import endpoint.
- Git-based syncers (GHSA, OpenSSF) clone untrusted content. Read files only
  through `os.OpenRoot`/`Root.ReadFile` confinement to prevent path traversal;
  pass fixed argv to `git` (never shell). The `#nosec G204` on the fixed-argv
  `git diff` call is justified because the hash input is a rev-parsed hex.
- Never log API keys (NVD, VulnCheck, Socket). Log only "key not configured".
- Feed health (DESIGN.md sec 3.5): unhealthy if last successful sync > 48h, last
  sync failed, OR zero entries in DB.

## Current open landmines (see Audit.md)

Audit.md is authoritative; project-wide only the external GitLab-runner test is
documented as an external validation gap. Keep these guardrails in mind:

- Feed health must continue to surface failed, stale, skipped, and zero-entry
  states to API, admin, and public web consumers.
- Runtime feed reconfiguration must not allow overlapping syncers for the same
  feed name.
- Bulk feed parsers should stream or batch where practical; avoid adding new
  unbounded `io.ReadAll` paths for external feed responses.

## Tests

```bash
go test ./internal/feed/...
```
For git syncers, add a regression test that a `../../../` path in a changed-file
list reads nothing outside the repo (see `ghsa/syncer_test.go`).
