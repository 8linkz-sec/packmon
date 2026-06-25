# packmon

Packmon scans dependency lockfiles and SBOM inventory for known
vulnerabilities, malicious packages, lifecycle risks, and configured
supply-chain risk findings.
It can run as a local CLI, as a central API server, or both together.

## First Local Server + Agent Test

After cloning Packmon, build the local agent and start the local server from the
Packmon repository root.

Windows:

```powershell
cd <path-to-cloned-packmon>
.\scripts\check-requirements.ps1 -Profile agent
.\scripts\check-requirements.ps1 -Profile server
New-Item -ItemType Directory -Force .build | Out-Null
go build -o .build\packmon.exe .\cmd\packmon
.\scripts\start-local-stack.ps1
```

Linux/macOS, or WSL on Windows:

```bash
cd <path-to-cloned-packmon>
bash scripts/check-requirements.sh --profile agent
bash scripts/check-requirements.sh --profile server
mkdir -p .build
go build -o .build/packmon ./cmd/packmon
bash scripts/start-local-stack.sh
```

Use the Windows block from PowerShell. Use the Linux/macOS block only from a
real Linux/macOS shell or WSL, because Git Bash on Windows may not inherit the
same toolchain `PATH` as PowerShell.

Then open the local admin UI:

```text
http://localhost:8080/admin/login
```

- Username: `admin`
- Password: open the generated `.env` in the Packmon repository and use the
  value of `PACKMON_ADMIN_INITIAL_PASSWORD`

Change the bootstrap password under `/admin/settings`, then create an agent API
key under `/admin/keys`.

Run the agent from the repository you want to scan:

```powershell
$env:PACKMON_API_KEY = "<copied-api-key>"
<path-to-cloned-packmon>\.build\packmon.exe scan . `
  --mode remote `
  --server http://localhost:8080 `
  --insecure-allow-http `
  --require-remote `
  --list-all `
  --html packmon-report.html `
  --output-json packmon-report.json
```

Linux/macOS:

```bash
export PACKMON_API_KEY="<copied-api-key>"
<path-to-cloned-packmon>/.build/packmon scan . \
  --mode remote \
  --server http://localhost:8080 \
  --insecure-allow-http \
  --require-remote \
  --list-all \
  --html packmon-report.html \
  --output-json packmon-report.json
```

Packmon is distributed under the private project license in `LICENSE`. The
OpenAPI contract references `LicenseRef-Private`, whose text is also shipped in
`LICENSES/LicenseRef-Private.txt`.

The canonical source and Go module namespace is
`github.com/8linkz-sec/packmon`.

## Current Capabilities

- local CLI, central API/web server, and CI/CD scanner workflows
- production-oriented Docker Compose assets and N8N automation templates
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
- `DESIGN.md`: canonical product requirements, data flow, and non-goals.
- `ARCHITECTURE.md`: concise runtime and deployment architecture map.
- `SECURITY.md`: security model, invariants, and audit checklist.
- `.github/SECURITY.md`: private vulnerability reporting entry point.

Use these files as the baseline for future audits and implementation reviews.

## Quick Start

### Choose Your Test Path

| Goal | Use this path | Needs |
|---|---|---|
| Scan one repository with the agent only | Windows or Linux/macOS below | Packmon release binary only |
| Test the server container plus an agent | `Local Docker stack` below | Source checkout, Docker, Go |
| Build Packmon from source | `Build From Source` below | Source checkout and Go |

For a first functional test, use the agent-only path. Use the Docker path when
you specifically want remote scans, central feed sync, the admin UI, API keys,
or local DB sync from the server.

### Windows

Download or copy `packmon.exe` into the repository or project directory you
want to scan. Then run these commands from that directory:

```powershell
.\packmon.exe version
.\packmon.exe scan --list-all --html packmon-report.html --output-json packmon-report.json .
.\packmon.exe db info
```

This native full scan reads supported lockfiles and existing SBOMs directly. It
does not require Go, Node.js, Python, JDK/Maven, Docker, or repository helper
scripts.

Use `--auto-sbom` only when you explicitly want Packmon to generate CycloneDX
SBOMs before scanning:

```powershell
.\packmon.exe scan --auto-sbom --install-tools --list-all --html packmon-report.html --output-json packmon-report.json .
```

For `--auto-sbom`, Packmon only asks for tools that match the detected target
manifests. For example, Maven is not required unless Maven SBOM generation is
needed.

### Linux And macOS

Use the Packmon release binary for your platform:

- Linux: Packmon ELF binary, normally named `packmon`
- macOS: Packmon Mach-O binary, normally named `packmon`

```bash
chmod +x ./packmon
./packmon version
./packmon scan --list-all --html packmon-report.html --output-json packmon-report.json .
./packmon db info
```

```bash
./packmon scan --auto-sbom --install-tools --list-all --html packmon-report.html --output-json packmon-report.json .
```

If `packmon` is on `PATH`, use `packmon` instead of `.\packmon.exe` or
`./packmon`.

## Source Checkout Requirements

The scripts in `scripts/` are helper tools for a source checkout of this
repository. Release-binary users do not need them.

Profiles are documented in `REQUIREMENTS.md` and listed in
`requirements/packmon-tools.tsv`:

- `full`: normal Packmon runtime, binary only.
- `agent`: source builds.
- `sbom`: optional target-aware CycloneDX generation preflight.
- `web`: generated web assets.
- `server`: Docker/PostgreSQL stack.
- `dev`: Packmon development and CI gates.

### Build From Source

Source builds require Go. The install helpers build both `packmon` and
`packmon-server` and install them under the local Packmon bin directory.

```powershell
.\scripts\check-requirements.ps1 -Profile agent
.\scripts\install.ps1
packmon version
```

```bash
bash scripts/check-requirements.sh --profile agent
./scripts/install.sh
packmon version
```

### Development server

The development server requires a source checkout and the `agent` profile.

```bash
go build -o packmon-server ./cmd/packmon-server
PACKMON_SERVER_MODE=development ./packmon-server
```

The development server uses the in-memory dev store, exposes the web UI, and binds metrics to `127.0.0.1:9090` by default.

### Local Docker stack

The local Docker/PostgreSQL stack requires the `server` profile:

Use this path when you want to test the containerized Packmon server together
with a CLI agent. Start the Docker stack from the Packmon source checkout, then
run the agent commands from the repository you want to scan.

```bash
bash scripts/check-requirements.sh --profile server
```

```powershell
.\scripts\check-requirements.ps1 -Profile server
```

Start the local stack:

```powershell
.\scripts\start-local-stack.ps1
```

```bash
bash scripts/start-local-stack.sh
```

The start helper creates or completes `.env` from `.env.example` with generated local-only secrets for `POSTGRES_PASSWORD`, `PACKMON_DB_PASSWORD`, `PACKMON_ADMIN_INITIAL_PASSWORD`, and `PACKMON_ENCRYPTION_KEY`. It keeps existing non-empty values, makes the Packmon DB password match the local PostgreSQL password when either value is missing, and runs the database migration before starting the server. Helpers do not print generated secret values.

Admins can later adjust `.env`, feed-provider API keys, TLS/proxy settings, and other deployment-specific values before shared or production use.

The local server is now reachable at `http://localhost:8080`. Open the admin UI
and sign in:

```text
http://localhost:8080/admin/login
```

- Username: `admin`
- Password: the generated `PACKMON_ADMIN_INITIAL_PASSWORD` value from `.env`

After the first login, change the bootstrap admin password under
`/admin/settings`. Runtime settings and API-key creation are locked until that
bootstrap password has been changed.

Create the API key that CLI agents need for remote scans:

1. Go to `http://localhost:8080/admin/keys`.
2. Enter a key name such as `local-agent`.
3. Set an RFC3339 UTC expiration timestamp, for example
   `2026-12-31T23:59:59Z`.
4. Enter the current admin password you set under `/admin/settings`.
5. Create the key and copy the displayed token once.

Production `/api/v1/*` endpoints require this API key. A CLI agent cannot run a
remote scan or sync its local DB from the server without it.

From the target repository, run the Windows agent against the local Docker
server:

```powershell
$env:PACKMON_API_KEY = "<copied-api-key>"
.\packmon.exe scan . `
  --mode remote `
  --server http://localhost:8080 `
  --insecure-allow-http `
  --require-remote `
  --list-all `
  --html packmon-report.html `
  --output-json packmon-report.json
```

Linux/macOS:

```bash
export PACKMON_API_KEY="<copied-api-key>"
./packmon scan . \
  --mode remote \
  --server http://localhost:8080 \
  --insecure-allow-http \
  --require-remote \
  --list-all \
  --html packmon-report.html \
  --output-json packmon-report.json
```

Sync the local agent DB from the Docker server when you want local/offline
results to use the same server-side feed data:

```powershell
$env:PACKMON_API_KEY = "<copied-api-key>"
.\packmon.exe db sync `
  --server http://localhost:8080 `
  --insecure-allow-http `
  --full
```

```bash
export PACKMON_API_KEY="<copied-api-key>"
./packmon db sync \
  --server http://localhost:8080 \
  --insecure-allow-http \
  --full
```

The `PACKMON_API_KEY` environment variable is reused by both `scan` and
`db sync`; avoid passing API keys directly on the command line when possible.
The `--insecure-allow-http` flag is only for this loopback Docker setup. For
shared deployments, expose the server over HTTPS and remove that flag.

The Docker stack runs PostgreSQL and `packmon-server` in production mode so synced feed data is persisted. The start helper prepares the database schema with `packmon-migrate` before starting the server; normal server startup only verifies the schema version. The `packmon-migrate` service is a manual Compose profile and receives only database/logging environment values, not admin or feed-provider secrets.
The local Compose database uses a digest-pinned Chainguard PostgreSQL image instead of the official `postgres:*-alpine` image, avoiding the vulnerable Go 1.24.x `gosu` helper present in the official image line.
Compose forwards `PACKMON_VERSION`, `PACKMON_COMMIT`, and `PACKMON_BUILD_DATE` as Docker build args so `packmon-server version`, startup logs, and `/version` report the image source. They default to `dev`, `none`, and `unknown` for local builds.
For local-only use, `.env.example` enables `PACKMON_ALLOW_INSECURE_LOCAL_HTTP=true` with explicit container bind mode while Compose publishes the host port on `127.0.0.1`; remove those local HTTP settings and configure TLS or a TLS-terminating reverse proxy for shared deployments.
The same local Docker profile sets `PACKMON_METRICS_HOST=0.0.0.0` so the metrics listener is reachable through Compose's host-loopback `127.0.0.1:9090:9090` port mapping without exposing that port beyond the host.
After the server binds its HTTP listener, the container log prints `dashboard_url`, for example `http://localhost:8080/`.
The PostgreSQL cluster is stored in the named Docker volume `packmon-postgres-data`, so normal `docker compose stop`, `docker compose down`, and `docker compose up` cycles keep the database intact.
Only explicit volume removal such as `docker compose down -v` or `docker volume rm packmon-postgres-data` will delete the database.
The UI ships local Tailwind and htmx assets from the repository, so runtime and normal container builds do not depend on external CDNs.
When you change web templates or Tailwind classes, use Node.js 20+ and refresh the generated Tailwind v4 and htmx assets with `npm ci --ignore-scripts && npm run build:web` before building the image.

## Common Commands

```bash
packmon scan .
packmon scan --html report.html .
PACKMON_API_KEY=... packmon scan . --mode remote --server https://packmon.internal:8080 --cacert /etc/packmon/ca.pem --require-remote
PACKMON_NO_REPO_METADATA=true packmon scan . --mode remote --server https://packmon.internal:8080
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
packmon history clear --before 2026-01-01
packmon history clear --force
packmon dashboard
packmon dashboard --open
```

`packmon scan --html report.html .` writes a colorful, self-contained mini
report grouped by finding type. It uses the repo name as its title and links
vulnerability and EOL findings back to their source.

`packmon dashboard` prints the local loopback dashboard URL and stays in the
terminal. Pass `--open` to launch the URL in the default browser.

Local scan history is enabled by default for `packmon report` and the local
dashboard. It stores compact scan metadata in the local SQLite database:
repository name, branch, commit SHA when available, scan time, package/finding
counts, finding IDs, and severities. Set `PACKMON_HISTORY_ENABLED=false` to
disable recording, or `PACKMON_HISTORY_MAX_SCANS_PER_REPO=<n>` to change the
per-repository retention cap (`100` by default, `0` disables retention
cleanup). `packmon history clear --before YYYY-MM-DD` uses a UTC date cutoff;
clearing all history without `--repo` or `--before` requires `--force`.

## CLI Config

The CLI can read a local `.packmon.yaml` file. Create a starter config with:

```bash
packmon config init
packmon config validate
packmon config show
```

Example:

```yaml
mode: auto
fail_on: CRITICAL
timeout: 30
# Set to false to omit the optional repository name from remote scan requests and webhooks.
# send_repo_metadata: false

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

The repository selector also applies to single-target inventory views such as
`packmon scan --list-packages --repo packmon`, `packmon scan --outdated --repo
packmon`, and `packmon scan --list-all --repo packmon`. These inventory views
reject multi-target `--all` runs; use `packmon scan --all` for normal
multi-repository scanning.

Remote scans send the repository name by default and never send branch or commit metadata. Use `--no-repo-metadata`, `PACKMON_NO_REPO_METADATA=true`, or `send_repo_metadata: false` to omit the repository name from remote scan requests and webhooks.

Config precedence is: command-line flags > environment variables > project `.packmon.yaml` > user-global `~/.packmon/config/packmon.yaml` > built-in defaults. Auto-discovered project config is treated as repository input and cannot set credential/server routing fields or local write destinations such as `server`, `api_key`, `api_key_env`, `cacert`, `insecure_allow_http`, `require_remote`, webhook URL/secret, `output.format`/`output.file`, or `db.path`. It may opt out of remote repository-name metadata with `send_repo_metadata: false`, but it cannot re-enable metadata if a higher-precedence user config, environment variable, or flag disabled it.
Store API keys in environment variables, CI secrets, OS secret stores, or the user-global config. Use `api_key_env` in trusted user-global or explicit config files rather than writing plaintext keys.

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

This requires only the matching local tool for the target ecosystem on `PATH`:
the Go toolchain for Go modules, `cyclonedx-npm` for npm, `cyclonedx-py` for
Python, or `mvn` for Maven projects. Add `--install-tools` to let Packmon
install pinned CycloneDX generators where automatic installation is supported.
Existing npm/Python CycloneDX tools are version-checked against Packmon's
pinned versions before use; generated-output and cleanup failures are reported
as scan errors. Use the target-aware `sbom` requirements profile in
`REQUIREMENTS.md` before relying on `--auto-sbom` in CI or local full-scan
tests.
Generated Go SBOMs preserve `replace` semantics: versioned replacement modules
use the replacement path/version in the CycloneDX package identity, while local
path replacements keep the original module identity and record replacement
metadata as CycloneDX properties.

## List-All Reports

`packmon scan --list-all --html <file> <target>` runs the normal findings scan
and adds a full package inventory. The package table includes each package's
input source (`lockfile`, `sbom`, `dockerfile`, or `compose`), scope, relation,
report-only technology tags (`angular` for Angular npm packages and `java` for
Maven/Gradle rows), and vulnerability marker. The HTML report intentionally omits noisy `Via` and
`Flags` columns. Its `Packages Needing Attention` section shows actionable
updates, removed packages, packages with security findings, and non-blocking
historical ReversingLabs incident context as `LOW` `Reputation info`; unknown
latest-status rows stay in `All Packages`. Finding-derived states such as
`Malicious`, `Removed`, `Reputation info`, `Supply-chain risk`, and `Lifecycle`
override general latest-version status. Standard scan artifact flags such as
`--output-json`, `--output-sarif`, and `--output-junit` still write the normal
scan result alongside the combined list-all report. Vulnerability findings with
a known fix or update path
render as `Update available`; only vulnerability findings without a known update
path render as `Vulnerable`, and vulnerable packages are not shown as
`Up-to-Date`. Full source paths are deduplicated at the bottom under `Checked
Inventory Sources`. Security finding advisory IDs link to their external
advisory pages where Packmon can derive one. Long Docker digests are shown with
a trailing `..` and a `Copy` button for the full digest. GitHub Actions pinned
by commit SHA are treated as current when the pin matches the dereferenced
latest tag commit, and stale `go.sum` versions are suppressed when Go selected
module versions are available from `go.mod` or generated SBOMs.
Add `--list-all-offline` to keep the findings scan and full inventory report
but skip all public latest-version and Docker registry digest lookups; affected
rows render latest status as `unknown`.

Docker inventory is metadata-only. Packmon reads image declarations from
`Dockerfile`, `Dockerfile.*`, `docker-compose.yml`, `docker-compose.yaml`,
`compose.yml`, and `compose.yaml`; it does not build, pull, or layer-scan
images. Registry digest lookups are best-effort for Packmon's built-in public
registry allowlist; unsupported registries or unsafe network targets are shown
as `unknown`.

For latest-version reports, Packmon keeps lockfile registry/source provenance
local to the CLI. If npm, requirements.txt, Cargo, Bundler, CocoaPods,
Composer, renv, pub, or Maven inputs identify a private or non-default source,
`--outdated` and `--list-all` report latest status as `unknown` instead of
querying the matching public registry.

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
(or commit) is blocked when a CRITICAL vulnerability or lifecycle finding,
malicious package, or active supply-chain-risk finding is present, or when
parser or operational errors prevent complete scan coverage. Historical
ReversingLabs malware-incident evidence is shown as `LOW` reputation info and
does not block by itself. Quiet mode still prints
trust-changing warnings such as remote fallback and partial parse errors to
stderr. `install` refuses to overwrite an existing hook that packmon did not
create; `uninstall` only removes packmon-managed hooks. Supported types:
`pre-push` (default) and `pre-commit`. The hook type and fail-on threshold can
also be set under a
`hook:` block in `.packmon.yaml`.

## Server Configuration

Important environment variables:

- `PACKMON_SERVER_MODE=production|development`
- `PACKMON_SERVER_PORT=8080`
- `PACKMON_SERVER_PUBLIC_HOST` (host:port clients use to reach the server)
- `PACKMON_TLS_CERT_FILE`, `PACKMON_TLS_KEY_FILE`, `PACKMON_TLS_MIN_VERSION=1.2|1.3`
- `PACKMON_ALLOW_INSECURE_LOCAL_HTTP=false` (loopback-only override for the fail-closed transport check)
- `PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE=loopback|container` (`container` is only for local Docker with host-loopback port publishing)
- `PACKMON_TRUSTED_PROXIES=10.0.0.0/8,192.168.10.10` (valid IP addresses or CIDR prefixes)
- `PACKMON_SERVER_READ_TIMEOUT=30s`, `PACKMON_SERVER_WRITE_TIMEOUT=30s`, `PACKMON_SERVER_SHUTDOWN_TIMEOUT=5s`
- `PACKMON_BLOCK_THRESHOLD=CRITICAL`
- `PACKMON_RATE_LIMIT_PER_MINUTE=60`
- `PACKMON_RATE_LIMIT_BURST=60`
- `PACKMON_METRICS_HOST=127.0.0.1`
- `PACKMON_METRICS_PORT=9090`
- `PACKMON_WEB_PRIVACY_URL=/privacy` (footer privacy link; defaults to the built-in notice)
- `PACKMON_WEB_LEGAL_URL` (optional operator legal notice / Impressum URL)
- `PACKMON_DB_HOST`, `PACKMON_DB_PORT`, `PACKMON_DB_NAME`, `PACKMON_DB_USER`, `PACKMON_DB_PASSWORD`
- `PACKMON_DB_SSLMODE` (default `verify-full` in production, `disable` in development)
- `PACKMON_DB_CONNECT_TIMEOUT=10s` (startup schema-check and connection-pool deadline)
- `PACKMON_ENCRYPTION_KEY` (required in production; encrypts stored feed API keys at rest. Development mode may run without it.)
- `PACKMON_ADMIN_INITIAL_PASSWORD` (at least 12 characters)
- `PACKMON_ADMIN_SESSION_TIMEOUT=8h`
- `PACKMON_ADMIN_IDLE_TIMEOUT=15m`
- `PACKMON_SCAN_LOG_RETENTION=2160h` (90-day retention for server `scan_log`; `0` disables pruning)
- `PACKMON_ADMIN_AUDIT_LOG_RETENTION=8760h` (365-day retention for `admin_audit_log`; `0` disables pruning)
- `PACKMON_REFRESH_QUEUE_RETENTION=720h` (30-day retention for completed or failed `refresh_queue` jobs; `0` disables pruning)
- `PACKMON_AUDIT_RETENTION_INTERVAL=24h` (background prune cadence)
- `PACKMON_FEED_IMPORT_SECRET` (required for production `POST /api/v1/feeds/{feed}/import`; send it as `X-Packmon-Feed-Import-Secret`)
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
- `PACKMON_REVERSINGLABS_MAX_SCHEDULE_PER_CHECK=100`
- `PACKMON_REVERSINGLABS_CACHE_RETENTION=168h`
- `PACKMON_REVERSINGLABS_EXCLUDED_NAMESPACES` (comma-separated prefixes such as `npm/@internal/,maven/com.acme:`)

Block threshold and rate-limit values can also be saved from `/admin/settings`; saved values are applied immediately and persisted for future server starts. Saving `NONE` requires an explicit acknowledgement because it disables vulnerability blocking.
Feed enablement, mode, cadence, and feed API keys can be saved from `/admin/feeds`; saved values are applied immediately and persisted for future server starts.
Manual advisories can be managed from `/admin/advisories` as either vulnerability or malicious findings.
API keys can be created with a required RFC3339 UTC expiration timestamp, revoked, and marked deleted after revocation from `/admin/keys`; deletion is a soft-delete that retains lifecycle metadata for auditability. Creation requires the current admin password and expiration must be no more than 90 days in the future. Create separate named keys per client class so `last_used_at` and revocation are useful.
The core OSV, GHSA, OpenSSF, CISA KEV, EPSS, NVD-without-key, endoflife.date,
and registry latest-version paths are free public sources.
This product uses the NVD API but is not endorsed or certified by the NVD.
EPSS is the FIRST Exploit Prediction Scoring System, a third-party
machine-learning/data-driven prediction of exploitation probability in the next
30 days. Packmon stores and syncs the 0..1 EPSS score and percentile as
triage context; default `findings_blocking` decisions remain based on finding
type and severity threshold, not on EPSS.
`PACKMON_SOCKET_API_KEY`, `PACKMON_VULNCHECK_API_KEY`, `PACKMON_NVD_API_KEY`,
and ReversingLabs settings are optional enrichment/reputation inputs and are
not required for baseline vulnerability, lifecycle, or outdated detection.
The Docker `.env.example` keeps account-gated feeds such as VulnCheck,
Socket.dev, and ReversingLabs disabled until the matching API key is supplied
and the feed is explicitly enabled.
Lifecycle/EOL findings are available only where package coordinates map to an
endoflife.date product and release cycle. Library packages without official
lifecycle metadata may still be vulnerable or outdated without being reported
as EOL.
ReversingLabs lookups are disabled by default. When enabled with an API key, the server performs bounded demand-driven lookups only for supported, length-bounded packages that are not already covered by other feeds, percent-encodes outbound PURLs, deduplicates and caps scheduled work per check request, stores normalized cache rows internally, and refreshes each package version at most once per day. Use `PACKMON_REVERSINGLABS_EXCLUDED_NAMESPACES` to suppress private package prefixes before external lookup. Non-finding cache rows are pruned by `PACKMON_REVERSINGLABS_CACHE_RETENTION`. Active malware signals are reported as malicious findings; historical malware incident evidence is reported separately as non-blocking `LOW` reputation info.

## Client Profiles

- Dev laptops: use the HTTPS server URL, `PACKMON_CA_CERT` or `--cacert` for the internal CA, and `PACKMON_API_KEY` from the user environment or OS secret store.
- CI runners: create a dedicated named key, store it as a CI secret, set `PACKMON_REQUIRE_REMOTE=true`, and rotate it before its required expiration.
- Segmented production networks: distribute the internal CA bundle to scanners, allow only the Packmon TLS port through the firewall, and make sure the server certificate SAN covers the address clients use.
- N8N: create a dedicated key for the workflow and call `/api/v1/check` over HTTPS with `Authorization: Bearer <key>` and a `User-Agent` starting with `packmon-n8n/`. For feed import endpoints, also configure `PACKMON_FEED_IMPORT_SECRET` on the server and send the same value as `X-Packmon-Feed-Import-Secret`.

For CLI local freshness warnings:

- `PACKMON_DB_WARN_AFTER_DAYS=7`

## Testing

Run the full local verification gate before release-facing changes:

```bash
bash scripts/bootstrap.sh --profile dev
```

```powershell
.\scripts\bootstrap.ps1 -Profile dev
```

```bash
mkdir -p .gotmp
export GOTMPDIR="$PWD/.gotmp"
PACKAGES="$(go list ./...)"
GOSEC_DIRS="$(go list -f '{{.Dir}}' ./...)"
GOFMT_FILES="$(git ls-files '*.go')"
gofumpt -extra -l ${GOFMT_FILES}
go test -count=1 ./...
go test -count=1 -race -coverprofile=coverage.out ${PACKAGES}
go run ./tools/checkcoverage -profile=coverage.out -min=79.5
go vet ./...
golangci-lint run ./...
govulncheck ${PACKAGES}
gosec -nosec-require-rules -nosec-require-justification ${GOSEC_DIRS}
```

The `make test*` targets set `GOTMPDIR` to the ignored local `.gotmp` directory
so temporary Go test binaries do not get written to the system temp folder.

For a quicker CI-template check:

```bash
GOTMPDIR="$PWD/.gotmp" go test -count=1 ./tests/ci
```

`go test -count=1 ./tests/ci` validates the reusable GitHub workflow and
GitLab template, including release binary download defaults, checksum
verification, report artifacts, degraded feed/local-DB warnings, and
Sigstore/Cosign signing metadata for retained scan-result artifacts.
`make test-ci` is available as a wrapper on systems with `make`. A real GitLab
Runner smoke test remains externally dependent on an available GitLab project
and registered runner.

Build both binaries before tagged integration and E2E tests:

```bash
go build -o .build/packmon ./cmd/packmon
go build -o .build/packmon-server ./cmd/packmon-server
PACKMON_TEST_BIN_DIR=.build go test -count=1 -tags integration ./tests/integration
PACKMON_TEST_BIN_DIR=.build go test -count=1 -tags e2e ./tests/e2e
```

The `test-integration` and `test-e2e` Make targets run the same tagged suites
after building the binaries.

On Windows systems without `make`, use the direct commands:

```powershell
New-Item -ItemType Directory -Force .gotmp | Out-Null
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
$packages = go list ./...
$gosecDirs = go list -f '{{.Dir}}' ./...
$gofmtFiles = git ls-files '*.go'
gofumpt -extra -l $gofmtFiles
go test -count=1 $packages
go test -count=1 -race '-coverprofile=coverage.out' $packages
go run ./tools/checkcoverage '-profile=coverage.out' '-min=79.5'
go vet ./...
golangci-lint run ./...
govulncheck $packages
gosec -nosec-require-rules -nosec-require-justification $gosecDirs
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
$env:PACKMON_TEST_BIN_DIR = ".build"
go test -count=1 -tags integration .\tests\integration
go test -count=1 -tags e2e .\tests\e2e
```

## Deployment

Deployment assets live under:

- `deploy/n8n`

The repository-provided container deployment entry is `docker-compose.yml` at
the root. Packmon no longer maintains first-party Kubernetes deployment
packaging; teams that run it on an orchestrator own those manifests and must
preserve the operational invariants in `DESIGN.md` and `ARCHITECTURE.md`.

The backup strategy is intentionally simple:

- daily `pg_dump`
- 7-day local retention
- backup files stored outside the application data path

Keep restore drills and deployment-specific backup destinations in the
operator-owned runbook for the environment where Packmon runs.
