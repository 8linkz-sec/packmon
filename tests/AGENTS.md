# Agent Guide -- Tests (ci, e2e, integration)

Scope: `tests/ci/` (GitLab template contract test), `tests/e2e/` (built-binary
smoke tests, build tag `e2e`), `tests/integration/` (Postgres-backed and
production-server tests, build tag `integration`). Primary owner agent:
**test-engineer**; coordinate with platform-ci-engineer for the CI wiring.

Read `AGENTS.md` (root) first for the full command list and verification gate.

## Conventions

- Unit tests live next to the code they test (`*_test.go`). This `tests/`
  tree is for cross-cutting integration/e2e/contract tests only.
- `tests/e2e` and `tests/integration` require built binaries; run them with
  `PACKMON_TEST_BIN_DIR` pointing at the build output. They are gated by build
  tags, so plain `go test ./...` skips them by design.
- `tests/ci/gitlab_template_test.go` parses `ci/gitlab/.packmon-scan.yml` as YAML
  and asserts the contract (runtime mirror default, matching-binary download,
  SHA256 verification against `checksums.txt`, remote-scan call, JSON/SARIF/JUnit
  artifacts). It runs in plain `go test ./...` and via `make test-ci`. Note it
  asserts structure, not shell execution -- a runtime shell bug would still pass.

## Test-strategy reminders (DESIGN.md sec 8)

- Coverage targets: overall >= 80%, parsers >= 90%, API handlers >= 85%, DB layer
  >= 80%, new code per PR >= 80%.
- For every security-sensitive or bug fix, add a regression test that FAILS
  before the fix.
- Prefer negative tests: malformed input, spoofed headers, oversize bodies,
  unauthenticated writes, invalid enum values.

## Known coverage gaps to close (see Audit.md M9 + test-gap notes)

- DB-backed tests for manual advisories, system settings, queue management.
- Negative trust tests in `internal/server/middleware`.
- Parser `Dev`-flag assertions and the `dedup` prod-wins rule.
- The telemetry 404 cardinality path.

## Commands

```bash
make test            # unit + race + coverage
make test-ci         # GitLab template contract
make test-integration
make test-e2e
```
