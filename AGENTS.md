# Agent Operating Guide

This file is the first stop for Codex, Claude, and other coding agents working
in this repository. It explains how to use the project design documents and how
to decide whether a change is complete.

## Canonical Context

- `DESIGN.md` is the product, architecture, and requirements baseline.
- `SECURITY.md` is the security model and audit checklist.
- `README.md` is the developer quick-start.
- `Audit.md` records the latest local audit/fix pass and open validation gaps.
- `docs/superpowers/plans/` holds task-by-task implementation plans for in-flight
  features. Use them to understand intended changes, but prefer `DESIGN.md` and
  `SECURITY.md` as the current reference once a feature lands.
- `CLAUDE.md` is older broad concept context. Do not treat it as more canonical
  than `AGENTS.md`, `DESIGN.md`, or `SECURITY.md` when there is drift.

When auditing, compare implementation against `DESIGN.md` and `SECURITY.md`.
When implementing, keep changes consistent with these files or update the
documents in the same change.

## Project Summary

Packmon is a Go dependency security scanner. It has:

- a cross-platform CLI in `cmd/packmon`;
- a central API/web server in `cmd/packmon-server`;
- parser, scanner, feed, database, telemetry, and server internals under
  `internal/`;
- PostgreSQL for server persistence;
- SQLite for local CLI sync/history;
- OpenAPI contracts under `api/openapi`;
- GitHub/GitLab CI templates and output formats for CI use;
- Go HTML templates, Tailwind, and htmx assets embedded into the server.

The primary production model is internal deployment, normally Docker based.
Packmon is not intended to be a public internet service.

## Subsystem Guides

Each major subsystem has its own `AGENTS.md` with scope, invariants, current
open landmines (cross-referenced to `Audit.md`), and scoped test commands. When
working in or dispatching an agent to a subsystem, read the nearest-ancestor
`AGENTS.md` in addition to this root file.

| Path | Subsystem | Owner agent |
|---|---|---|
| `internal/server/` | HTTP server, auth, middleware, trust boundary | security-engineer |
| `internal/api/` | API v1 + admin handlers, OpenAPI contract | backend-engineer |
| `internal/db/` | Store interface, Postgres, SQLite, migrations | data-feeds-engineer |
| `internal/parser/` | Lock-file parsers (per ecosystem) | backend-engineer |
| `internal/scanner/` | File discovery, checker, exit codes, webhooks | backend-engineer |
| `internal/feed/` | Feed syncers, priority queue | data-feeds-engineer |
| `internal/telemetry/` | Metrics exposition and middleware | platform-ci-engineer |
| `internal/web/` | Templates, htmx, Tailwind, web handlers | frontend-engineer / ui-ux-designer |
| `cmd/packmon/` | CLI client (the agent/binary) | cli-integrations-engineer |
| `cmd/packmon-server/` | Server entrypoint, DI, migrate, dev noop store | backend-engineer |
| `tests/` | ci / e2e / integration cross-cutting tests | test-engineer |

## Non-Negotiable Behaviors

- Malware or malicious package findings always block scans.
- Vulnerability blocking is controlled by severity threshold:
  `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `NONE`.
- `NONE` disables vulnerability blocking only; it does not disable malware
  blocking.
- `POST /api/v1/check`, CLI JSON output, and webhook result payloads use the
  same canonical scan result shape.
- Client local sync always talks to the Packmon server, never directly to OSV,
  GHSA, OpenSSF, VulnCheck, Socket.dev, ReversingLabs, CISA KEV, EPSS, NVD,
  endoflife.date, or public registries.
- Migrations are a separate operational step via `packmon-server migrate`.
  The server must not silently migrate on normal startup.
- Normal startup may run bounded, idempotent feed-data reconciliation only after
  the schema version is verified. These repairs must not perform DDL, update
  `schema_migrations`, or bring an outdated schema current.
- Production `/api/v1/*` endpoints require API-key auth and expected
  User-Agent handling. Health/version/metrics endpoints are exceptions as
  described in `SECURITY.md`.
- `X-Forwarded-*` and `X-Real-IP` are trusted only from configured trusted
  proxies.
- Logs must not contain API keys, passwords, environment values, file contents,
  or full paths in persistent server logs.
- Metrics bind to localhost by default and must not be exposed to untrusted
  networks.
- Web UI assets must be served locally from the repo/binary. Do not add CDN
  runtime dependencies.

## Implementation Guidelines

- Prefer existing patterns and package boundaries over new abstractions.
- Keep changes scoped to the requested behavior and its tests.
- Use structured parsing and typed APIs instead of ad hoc string manipulation
  where reasonable.
- Add tests before or with any behavior change.
- For security-sensitive fixes, add a regression test that would have failed
  before the fix.
- Avoid changing generated/minified assets unless the template/CSS source change
  requires it.
- Do not revert unrelated user changes in the working tree.
- Do not introduce new services or deployment assumptions without updating
  `DESIGN.md` and `SECURITY.md`.

## Common Commands

Use these from the repository root.

```bash
mkdir -p .gotmp
export GOTMPDIR="$PWD/.gotmp"
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
gofumpt -extra -l .
golangci-lint run ./...
govulncheck ./...
gosec ./...
```

Build both binaries:

```bash
go build -o .build/packmon ./cmd/packmon
go build -o .build/packmon-server ./cmd/packmon-server
```

Run tagged integration and E2E tests after building:

```bash
PACKMON_TEST_BIN_DIR=.build go test -count=1 -tags integration ./tests/integration
PACKMON_TEST_BIN_DIR=.build go test -count=1 -tags e2e ./tests/e2e
```

Windows PowerShell equivalent:

```powershell
New-Item -ItemType Directory -Force .gotmp | Out-Null
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
$env:PACKMON_TEST_BIN_DIR = ".build"
go test -count=1 -tags integration .\tests\integration
go test -count=1 -tags e2e .\tests\e2e
```

`make` is convenient where installed:

```bash
make test
make test-ci
make test-integration
make test-e2e
make lint
make security
```

Do not leave `.build/` artifacts behind unless the user asked for them.

## Verification Gate

Before claiming a change is complete, run the smallest commands that prove the
claim. For broad or release-facing changes, run the full local gate:

```bash
mkdir -p .gotmp
export GOTMPDIR="$PWD/.gotmp"
gofumpt -extra -l .
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
golangci-lint run ./...
govulncheck ./...
gosec ./...
```

For changes touching CLI/server binaries, also build both binaries and run the
tagged integration/E2E tests with `PACKMON_TEST_BIN_DIR`.

If a command cannot run because of missing local tooling or external
infrastructure, state that explicitly and provide the command that was blocked.

## Audit Workflow

When asked to audit or review:

1. Read `DESIGN.md` and `SECURITY.md`.
2. Identify the relevant implementation areas.
3. Compare code behavior against the documented requirements.
4. Lead with findings, ordered by severity.
5. Include exact file/line references.
6. Distinguish real defects from external validation gaps.
7. Do not count a documented non-goal as a bug unless the code contradicts the
   documented boundary.

Current known external validation gap: the GitLab shared template still needs a
real GitLab project and registered runner for end-to-end validation.

## Documentation Rules

- Update `DESIGN.md` when requirements, architecture, data flow, operational
  model, or non-goals change.
- Update `SECURITY.md` when auth, trust boundaries, logging, crypto,
  dependency handling, admin behavior, or deployment exposure changes.
- Update `README.md` only for user-facing quick-start and common commands.
- Keep new docs ASCII unless a file already uses non-ASCII intentionally.
- Avoid placeholders such as `TBD`, `TODO`, or "future work" without a concrete
  owner or reason.
