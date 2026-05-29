# Agent Guide -- Scanner & Checker

Scope: `internal/scanner/` -- file discovery (walker), orchestration, dev-dep
filtering, exit-code decision, correlation-ID generation, remote/local/auto
checker selection, webhook dispatch. Primary owner agent: **backend-engineer**;
coordinate with cli-integrations-engineer (the CLI consumes this) and
data-feeds-engineer (local checker hits the DB layer).

Read `AGENTS.md` (root) and `DESIGN.md` first.

## Invariants (do not break)

- Mode `auto`: try remote, fall back to local DB on failure, exit 2 if neither
  works. The fallback to a (possibly stale) local DB MUST surface a user-visible
  warning with the DB age.
- Exit codes are a contract (DESIGN.md): 0 clean, 1 findings
  over threshold, 2 operational error, 3 findings under threshold, 4 parser
  error, 10 internal. Multi-target aggregation must be severity-aware, not a raw
  numeric max.
- Dev dependencies are filtered out by default; `--include-dev` keeps them.
- Correlation-ID is generated client-side and sent as `X-Correlation-ID`.

## Current open landmines (see Audit.md)

> Status (2026-05-29): the items in this section were addressed across the
> Audit.md "Fix-Runde" passes. Audit.md is authoritative; project-wide only the
> external GitLab-runner test remains open. Keep the notes below as guardrails
> so the fixes are not regressed.

- **M6:** exit code 3 is never emitted -- non-blocking findings currently return
  0. CI/N8N consumers distinguish 0 from 3. Emit 3 when findings exist but none
  block, and fix the aggregation so a 3 does not dominate a sibling blocking 1.
- **M7:** the auto-mode local fallback is silent. Add the warning.
- **L1:** the scan pipeline emits no DEBUG logs. DESIGN.md sec 7.1 expects
  "found lock file path=... ecosystem=..." and "parsed N packages". Add them.
- `filterDevPackages` mutates the caller's backing array (`pkgs[:0]`). Safe for
  the single current caller; document/guard if you add another.

## Tests

```bash
go test -race ./internal/scanner/...
```
Cover: default-exclude vs `--include-dev`, each exit-code branch, and the
auto-mode fallback warning.
