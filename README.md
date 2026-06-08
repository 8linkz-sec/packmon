# packmon

Packmon scans dependency lockfiles and SBOM inventory for known
vulnerabilities, malicious packages, lifecycle risks, and configured
supply-chain risk findings.
It can run as a local CLI, as a central API server, or both together.

## Current Capabilities

- local CLI, central API/web server, and CI/CD scanner workflows
- production-oriented deployment assets for Helm, Rancher, Docker Compose, and N8N
- onboarding scripts for Bash and PowerShell
- documented backup and restore flow for PostgreSQL
- localhost-only metrics exposure by default
- CLI warnings for stale local advisory data
- free public vulnerability, lifecycle, and outdated-version coverage for the
  canonical package ecosystems; optional account/API-key reputation feeds are
  not required
- operational documentation, ADRs, and integration/E2E test entry points

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
For local-only use, the compose file binds the dashboard to `127.0.0.1:8080` and `.env.example` enables `PACKMON_ALLOW_INSECURE_LOCAL_HTTP=true`; remove that override and configure TLS or a TLS-terminating reverse proxy for shared deployments.
After the server binds its HTTP listener, the container log prints `dashboard_url`, for example `http://localhost:8080/`.
The PostgreSQL cluster is stored in the named Docker volume `packmon-postgres-data`, so normal `docker compose stop`, `docker compose down`, and `docker compose up` cycles keep the database intact.
Only explicit volume removal such as `docker compose down -v` or `docker volume rm packmon-postgres-data` will delete the database.
The UI ships local Tailwind and htmx assets from the repository, so runtime and normal container builds do not depend on external CDNs.
When you change web templates or Tailwind classes, refresh the generated Tailwind v4 and htmx assets with `npm ci && npm run build:web` before building the image.

## Common Commands

```bash
packmon scan .
packmon scan --html report.html .
PACKMON_API_KEY=... packmon scan . --mode remote --server https://packmon.internal:8080 --cacert /etc/packmon/ca.pem --require-remote
packmon config init
packmon scan --all
packmon scan --repo packmon
packmon scan --outdated .
packmon scan --sbom bom.cdx.json .
packmon scan --sbom sbom.spdx.json --list-packages .
packmon scan --sbom bom.cdx.json --outdated .
packmon scan --auto-sbom .
packmon scan --auto-sbom --sbom-only --keep-sbom ./sboms .
packmon db sync
packmon db info
packmon db export --output local-db.json
packmon history clear
packmon dashboard
```

`packmon scan --html report.html .` writes a colorful, self-contained mini
report grouped by finding type. It uses the repo name as its title and links
vulnerability and EOL findings back to their source.

## CLI Config

The CLI can read a local `.packmon.yaml` file. Create a starter config with:

```bash
packmon config init
packmon config validate
packmon config show
```

Example:

```yaml
server: "https://packmon.internal:8080"
api_key_env: "PACKMON_API_KEY"
mode: auto
fail_on: CRITICAL
timeout: 30
cacert: "/etc/packmon/ca.pem"
require_remote: true

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

Config precedence is: command-line flags > environment variables > project `.packmon.yaml` > user-global `~/.packmon/config/packmon.yaml` > built-in defaults.
Store API keys in environment variables or CI secrets. Use `api_key_env` in config files rather than writing plaintext keys to `.packmon.yaml`.

## SBOM Input

`packmon scan --sbom <file>` can be repeated to add CycloneDX JSON/XML or SPDX
JSON package inventory to the normal lockfile scan. The same SBOM inputs are
used by `--list-packages` and `--outdated`.

SBOM files are package-coordinate input only. Packmon does not treat embedded
SBOM vulnerability, VEX, license, or provenance assertions as authoritative
findings; vulnerabilities, malicious packages, reputation, outdated versions,
and lifecycle state still come from Packmon's configured data sources.
CycloneDX dependency edges are used as package graph metadata, so npm
transitive update checks can distinguish a truly wanted update from a newer
registry major that is blocked by the parent dependency range.

### Generate and scan an SBOM in one step

```bash
# Detect the project's ecosystem, generate a CycloneDX SBOM, and scan it:
packmon scan --auto-sbom ./my-project

# Only produce the SBOM (no scan), keeping the files:
packmon scan --auto-sbom --sbom-only --keep-sbom ./sboms ./my-project
```

Kept SBOMs use timestamped snapshot names such as
`go-20260607T131329Z.cdx.json` and `package-20260607T131329Z.cdx.json`, so
repeated automated runs in the same directory do not overwrite previous SBOMs.

This requires the matching local tool on `PATH`: the Go toolchain for Go
modules, `cyclonedx-npm` for npm, `cyclonedx-py` for Python, or `mvn` for
Maven projects. Add `--install-tools` to let Packmon install pinned CycloneDX
generators where automatic installation is supported.

## List-All Reports

`packmon scan --list-all --html <file> <target>` runs the normal findings scan
and adds a full package inventory. The package table includes each package's
input source (`lockfile`, `sbom`, `dockerfile`, or `compose`), scope, relation,
and vulnerability marker. The HTML report intentionally omits noisy `Via` and
`Flags` columns. Its `Packages Needing Attention` section shows actionable
updates, removed packages, and packages with security findings; unknown
latest-status rows stay in `All Packages`. Finding-derived states such as
`Malicious`, `Removed`, `Malware history`, `Supply-chain risk`, and `Lifecycle`
override general latest-version status. Vulnerability findings with a known fix
or update path
render as `Update available`; only vulnerability findings without a known update
path render as `Vulnerable`, and vulnerable packages are not shown as
`Up-to-Date`. Full source paths are deduplicated at the bottom under `Checked
Inventory Sources`. Security finding advisory IDs link to their external
advisory pages where Packmon can derive one. Long Docker digests are shown with
a trailing `..` and a `Copy` button for the full digest. GitHub Actions pinned
by commit SHA are treated as current when the pin matches the dereferenced
latest tag commit, and stale `go.sum` versions are suppressed when Go selected
module versions are available from `go.mod` or generated SBOMs.

Docker inventory is metadata-only. Packmon reads image declarations from
`Dockerfile`, `Dockerfile.*`, `docker-compose.yml`, `docker-compose.yaml`,
`compose.yml`, and `compose.yaml`; it does not build, pull, or layer-scan
images.

## Git Hooks

Install a packmon Git hook in the current repository to scan automatically.
Hooks are per-repository (written to `.git/hooks/`); packmon does not change
`core.hooksPath`.

```bash
packmon hook install                   # install a pre-push hook (default)
packmon hook install --type pre-commit
packmon hook uninstall                 # remove packmon-managed hooks
packmon hook status                    # show hook status for this repo
```

The installed hook runs `packmon scan . --fail-on CRITICAL --quiet`, so a push
(or commit) is blocked only when a CRITICAL vulnerability or lifecycle finding,
malicious package, or supply-chain-risk finding is present. `install` refuses
to overwrite an existing hook that packmon did not create; `uninstall` only
removes packmon-managed hooks. Supported types: `pre-push` (default) and
`pre-commit`. The hook type and fail-on threshold can also be set under a
`hook:` block in `.packmon.yaml`.

## Server Configuration

Important environment variables:

- `PACKMON_SERVER_MODE=production|development`
- `PACKMON_SERVER_PORT=8080`
- `PACKMON_SERVER_PUBLIC_HOST` (host:port clients use to reach the server)
- `PACKMON_TLS_CERT_FILE`, `PACKMON_TLS_KEY_FILE`, `PACKMON_TLS_MIN_VERSION=1.2|1.3`
- `PACKMON_ALLOW_INSECURE_LOCAL_HTTP=false` (loopback-only override for the fail-closed transport check)
- `PACKMON_TRUSTED_PROXIES=10.0.0.0/8,192.168.10.10`
- `PACKMON_SERVER_READ_TIMEOUT=30s`, `PACKMON_SERVER_WRITE_TIMEOUT=30s`, `PACKMON_SERVER_SHUTDOWN_TIMEOUT=5s`
- `PACKMON_BLOCK_THRESHOLD=CRITICAL`
- `PACKMON_RATE_LIMIT_PER_MINUTE=60`
- `PACKMON_RATE_LIMIT_BURST=60`
- `PACKMON_METRICS_HOST=127.0.0.1`
- `PACKMON_METRICS_PORT=9090`
- `PACKMON_DB_HOST`, `PACKMON_DB_PORT`, `PACKMON_DB_NAME`, `PACKMON_DB_USER`, `PACKMON_DB_PASSWORD`
- `PACKMON_DB_SSLMODE` (default `require` in production, `disable` in development)
- `PACKMON_ENCRYPTION_KEY` (encrypts stored feed API keys at rest; without it keys are stored in plaintext and the server logs a startup warning)
- `PACKMON_ADMIN_INITIAL_PASSWORD`
- `PACKMON_ADMIN_SESSION_TIMEOUT=8h`
- `PACKMON_SOCKET_API_KEY`
- `PACKMON_VULNCHECK_API_KEY`
- `PACKMON_NVD_API_KEY`
- `PACKMON_FEED_ENDOFLIFE_ENABLED=true`
- `PACKMON_FEED_ENDOFLIFE_MODE=self`
- `PACKMON_ENDOFLIFE_API_BASE_URL=https://endoflife.date/api/v1`
- `PACKMON_FEED_REVERSINGLABS_ENABLED=false`
- `PACKMON_FEED_REVERSINGLABS_MODE=self`
- `PACKMON_REVERSINGLABS_API_KEY`
- `PACKMON_REVERSINGLABS_LOOKUP_TTL=24h`
- `PACKMON_REVERSINGLABS_BATCH_SIZE=5`

Block threshold and rate-limit values can also be saved from `/admin/settings`; saved values are applied immediately and persisted for future server starts.
Feed enablement, mode, cadence, and feed API keys can be saved from `/admin/feeds`; saved values are applied immediately and persisted for future server starts.
Manual advisories can be managed from `/admin/advisories` as either vulnerability or malicious findings.
API keys can be created, revoked, deleted after revocation, and optionally given an expiration timestamp from `/admin/keys`. Create separate named keys per client class so `last_used_at` and revocation are useful.
The core OSV, GHSA, OpenSSF, CISA KEV, EPSS, NVD-without-key, endoflife.date,
and registry latest-version paths are free public sources.
`PACKMON_SOCKET_API_KEY`, `PACKMON_VULNCHECK_API_KEY`, `PACKMON_NVD_API_KEY`,
and ReversingLabs settings are optional enrichment/reputation inputs and are
not required for baseline vulnerability, lifecycle, or outdated detection.
Lifecycle/EOL findings are available only where package coordinates map to an
endoflife.date product and release cycle. Library packages without official
lifecycle metadata may still be vulnerable or outdated without being reported
as EOL.
ReversingLabs lookups are disabled by default. When enabled, the server performs demand-driven lookups only for supported packages that are not already covered by other feeds, stores normalized cache rows internally, and refreshes each package version at most once per day. Active malware signals are reported as malicious findings; historical malware incident evidence is reported separately as supply-chain reputation risk.

## Client Profiles

- Dev laptops: use the HTTPS server URL, `PACKMON_CA_CERT` or `--cacert` for the internal CA, and `PACKMON_API_KEY` from the user environment or OS secret store.
- CI runners: create a dedicated named key, store it as a CI secret, set `PACKMON_REQUIRE_REMOTE=true`, and prefer an expiration date aligned with your rotation window.
- Segmented production networks: distribute the internal CA bundle to scanners, allow only the Packmon TLS port through the firewall, and make sure the server certificate SAN covers the address clients use.
- N8N: create a dedicated key for the workflow and call `/api/v1/check` or feed import endpoints over HTTPS with `Authorization: Bearer <key>`.

For CLI local freshness warnings:

- `PACKMON_DB_WARN_AFTER_DAYS=7`

## Testing

```bash
mkdir -p .gotmp
GOTMPDIR="$PWD/.gotmp" go test ./...
GOTMPDIR="$PWD/.gotmp" go test ./tests/ci
make test-integration
make test-e2e
```

The `make test*` targets set `GOTMPDIR` to the ignored local `.gotmp` directory
so temporary Go test binaries do not get written to the system temp folder.

`go test ./tests/ci` validates the reusable GitLab template under `ci/gitlab`,
including release binary download defaults, checksum verification, and GitLab
report artifacts. `make test-ci` is available as a wrapper on systems with
`make`. A real GitLab Runner smoke test remains externally dependent on an
available GitLab project and registered runner.

`test-integration` and `test-e2e` build the binaries first and then run the
integration suite under `tests/integration` and the E2E suite under `tests/e2e`.

On Windows systems without `make`, use the direct commands:

```powershell
New-Item -ItemType Directory -Force .gotmp | Out-Null
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
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
