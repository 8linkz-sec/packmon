# packmon

Packmon scans dependency lockfiles for known vulnerabilities and malicious packages.
It can run as a local CLI, as a central API server, or both together.

## What Phase 5 Adds

- production-oriented deployment assets for Helm and Rancher
- onboarding scripts for Bash and PowerShell
- documented backup and restore flow for PostgreSQL
- localhost-only metrics exposure by default
- CLI warnings for stale local advisory data
- operational documentation, ADRs, and E2E test entry points

## Canonical Project Docs

- `AGENTS.md`: operating rules for Codex, Claude, and other coding agents.
- `DESIGN.md`: product requirements, architecture, data flow, and non-goals.
- `SECURITY.md`: security model, invariants, and audit checklist.

Use these files as the baseline for future audits and implementation reviews.

## Quick Start

### CLI only

```bash
go build -o packmon ./cmd/packmon
./packmon scan .
./packmon db info
```

### Local install helpers

```bash
./scripts/install.sh
```

```powershell
./scripts/install.ps1
```

### Development server

```bash
go build -o packmon-server ./cmd/packmon-server
PACKMON_SERVER_MODE=development ./packmon-server
```

The development server uses the in-memory dev store, exposes the web UI, and binds metrics to `127.0.0.1:9090` by default.

### Local Docker stack

```bash
cp .env.example .env
docker compose up --build
```

The Docker stack runs PostgreSQL, applies migrations, and starts `packmon-server` in production mode so synced feed data is persisted.
The PostgreSQL cluster is stored in the named Docker volume `packmon-postgres-data`, so normal `docker compose stop`, `docker compose down`, and `docker compose up` cycles keep the database intact.
Only explicit volume removal such as `docker compose down -v` or `docker volume rm packmon-postgres-data` will delete the database.
The UI ships local Tailwind and htmx assets from the repository, so runtime and normal container builds do not depend on external CDNs.
When you change web templates or Tailwind classes, refresh the generated assets with `npm ci && npm run build:web` before building the image.

## Common Commands

```bash
packmon scan .
packmon scan . --mode remote --server http://localhost:8080 --api-key your-key
packmon config init
packmon scan --all
packmon scan --repo packmon
packmon db sync
packmon db info
packmon db export --output local-db.json
packmon history clear
packmon dashboard
```

## CLI Config

The CLI can read a local `.packmon.yaml` file. Create a starter config with:

```bash
packmon config init
packmon config validate
packmon config show
```

Example:

```yaml
server: "http://localhost:8080"
api_key: "your-api-key"
mode: auto
fail_on: CRITICAL
timeout: 30

repos:
  - name: packmon
    path: "."
  - name: another-service
    path: "../another-service"
    mode: remote
```

Then you can scan configured repositories directly:

```bash
packmon scan --repo packmon
packmon scan --all
packmon db sync
```

Config precedence is: command-line flags > environment variables > `.packmon.yaml` > built-in defaults.

## Server Configuration

Important environment variables:

- `PACKMON_SERVER_MODE=production|development`
- `PACKMON_SERVER_PORT=8080`
- `PACKMON_TRUSTED_PROXIES=10.0.0.0/8,192.168.10.10`
- `PACKMON_BLOCK_THRESHOLD=CRITICAL`
- `PACKMON_RATE_LIMIT_PER_MINUTE=60`
- `PACKMON_RATE_LIMIT_BURST=60`
- `PACKMON_METRICS_HOST=127.0.0.1`
- `PACKMON_METRICS_PORT=9090`
- `PACKMON_API_KEY`
- `PACKMON_DB_HOST`, `PACKMON_DB_PORT`, `PACKMON_DB_NAME`, `PACKMON_DB_USER`, `PACKMON_DB_PASSWORD`
- `PACKMON_ADMIN_INITIAL_PASSWORD`
- `PACKMON_SOCKET_API_KEY`
- `PACKMON_VULNCHECK_API_KEY`

Block threshold and rate-limit values can also be saved from `/admin/settings`; persisted values are loaded when the server starts.
Manual advisories can be managed from `/admin/advisories` as either vulnerability or malicious findings.

For CLI local freshness warnings:

- `PACKMON_DB_WARN_AFTER_DAYS=7`

## Testing

```bash
go test ./...
go test ./tests/ci
make test-integration
make test-e2e
```

`go test ./tests/ci` validates the reusable GitLab template under `ci/gitlab`,
including release binary download defaults, checksum verification, and GitLab
report artifacts. `make test-ci` is available as a wrapper on systems with
`make`. `test-integration` and `test-e2e` build the binaries first and then run
the integration suite under `tests/integration`.

On Windows systems without `make`, use the direct commands:

```powershell
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
$env:PACKMON_TEST_BIN_DIR = ".build"
go test -tags integration .\tests\integration
go test -tags e2e .\tests\e2e
```

## Deployment

Deployment assets live under:

- `deploy/helm/packmon`
- `deploy/rancher`
- `deploy/n8n`

The backup strategy is intentionally simple:

- daily `pg_dump`
- 7-day local retention
- backup files stored outside the application data path

Details are documented in `docs/runbook.md`.
