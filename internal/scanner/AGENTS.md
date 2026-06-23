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
- Explicit SBOM inputs are package inventory sources only. They are collected
  alongside lockfiles before filtering/checking, and embedded SBOM
  vulnerability/VEX assertions are not scan findings.
- Dev dependencies are filtered out by default; `--include-dev` keeps them.
- Correlation-ID is generated client-side and sent as `X-Correlation-ID`.

## Current Guardrails

Keep these tracked guardrails in mind:

- Exit code 3 is part of the CI contract for non-blocking findings; do not fold
  it back into exit code 0.
- Auto-mode local fallback must remain user-visible so stale local DB data is
  not mistaken for a fresh remote result.
- Explicit SBOM inputs may produce skipped-component warnings; keep them visible
  in CLI terminal output and JSON via the canonical scan result.
## Tests

```bash
go test -race ./internal/scanner/...
```
Cover: default-exclude vs `--include-dev`, each exit-code branch, and the
auto-mode fallback warning.
