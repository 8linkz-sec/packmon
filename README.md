# packmon

> [!WARNING]
> **Packmon is 100% vibe-coded.** The entire codebase was written by AI.
> All scan results are provided **without any warranty** — do not rely on them
> as your sole security control, and verify security-relevant findings
> independently before acting on them.

Packmon scans dependency lockfiles and SBOM inventory for known
vulnerabilities, malicious packages, lifecycle risks, and configured
supply-chain risk findings.
It can run as a local CLI, as a central API server, or both together.

## What Packmon Does

- Reads lockfiles and SBOMs and inventories the packages they declare,
  including the transitive dependencies those files enumerate. Dockerfile and
  Compose image references and Chocolatey package declarations (FLARE-VM
  style `config.xml` lists, `choco install` script lines) are collected as
  metadata-only inventory.
- Checks the lockfile/SBOM packages against vulnerability, malicious-package,
  exploit, and lifecycle/end-of-life data. Docker image entries get
  digest-freshness checks only and Chocolatey entries get feed
  latest-version checks only, not vulnerability scanning.
- Reports which packages have a newer version available, with the update path.
- Blocks a build on findings you choose to block on: malicious packages and
  active supply-chain risk always block; vulnerabilities and lifecycle
  findings block from a severity threshold you set.
- Writes results as a self-contained HTML report, JSON, SARIF, or JUnit XML,
  so CI systems and humans read the same scan.

It ships as a local CLI, a central API/web server, and CI/CD scanner workflows,
with production-oriented Docker Compose assets and example N8N workflow
templates (CLI-based starting points, shipped disabled -- see
`deploy/n8n/README.md`), onboarding scripts for Bash and PowerShell, a documented PostgreSQL backup and
restore flow, localhost-only metrics exposure by default, CLI warnings for stale
local advisory data, and operational documentation, ADRs, and integration/E2E
test entry points. Vulnerability, lifecycle, and outdated-version coverage for
the canonical package ecosystems comes from free public sources; the optional
account/API-key reputation feeds are not required.

Every command has built-in help. Run `packmon --help` for the command list and
`packmon scan --help` for the full flag reference; this README covers the
common paths, not every flag.

## Contents

- [What Packmon Does](#what-packmon-does)
- [Quick Start](#quick-start) -- get a binary and run your first scan
- [Usage](#usage) -- recommended scan, common commands, exit codes
- [Source Checkout Requirements](#source-checkout-requirements) -- helper
  scripts, source builds, cross-compilation
- [First Local Server + Agent Test](#first-local-server--agent-test) -- server
  and agent together on one machine
- [Local Docker Stack](#local-docker-stack) -- containerized server in detail
- [Development Server](#development-server)
- [CLI Config](#cli-config) -- `.packmon.yaml`, precedence, registry mirrors
- [SBOM Input](#sbom-input) -- `--sbom` and `--auto-sbom`
- [List-All Reports](#list-all-reports) -- inventory report semantics
- [Git Hooks](#git-hooks)
- [Server Configuration](#server-configuration) -- environment variables
- [Client Profiles](#client-profiles)
- [Testing](#testing) -- local verification gate
- [Deployment](#deployment) -- production server, TLS, backup
- [Troubleshooting](#troubleshooting)
- [Canonical Project Docs](#canonical-project-docs)
- [License](#license)

## Quick Start

### Choose Your Test Path

| Goal | Use this path | Needs |
|---|---|---|
| Scan one repository with the agent only | `Windows` or `Linux And macOS` below | Packmon binary only |
| Test the server container plus an agent | `First Local Server + Agent Test` below | Source checkout, Docker, Go |
| Build Packmon from source | `Build From Source` below | Source checkout and Go |

For a first functional test, use the agent-only path. Use the server path when
you specifically want remote scans, central feed sync, the admin UI, API keys,
or local DB sync from the server.

### Get A Binary

Release automation (GitHub Actions) has been removed; build the CLI from
source with a pinned Go toolchain:

Windows:

```powershell
go build -trimpath -o packmon.exe .\cmd\packmon
```

Linux / macOS:

```bash
go build -trimpath -o packmon ./cmd/packmon
```

### Windows

Place `packmon.exe` anywhere you like (or put it on `PATH`). `packmon scan`
takes the directory to scan as an argument, so the binary does not need to
live inside the project. From the project directory, scan `.`:

```powershell
.\packmon.exe version
.\packmon.exe scan --list-all --html packmon-report.html --output-json packmon-report.json .
.\packmon.exe db info
```

Or scan any project by passing its path:

```powershell
C:\Tools\packmon.exe scan --list-all --html packmon-report.html --output-json packmon-report.json C:\path\to\project
```

Relative report paths such as `packmon-report.html` are written to the current
working directory, not the scanned directory; pass absolute paths if you want
the reports elsewhere.

This native full scan reads supported lockfiles and existing SBOMs directly. It
does not require Go, Node.js, Python, JDK/Maven, Docker, or repository helper
scripts.

Use `--auto-sbom` when you also want Packmon to generate CycloneDX SBOMs before
scanning:

```powershell
.\packmon.exe scan --auto-sbom --install-tools --list-all --html packmon-report.html --output-json packmon-report.json .
```

For `--auto-sbom`, Packmon only asks for tools that match the detected target
manifests. For example, Maven is not required unless Maven SBOM generation is
needed.

### Linux And macOS

Use the Packmon binary for your platform:

- Linux: Packmon ELF binary, normally named `packmon`
- macOS: Packmon Mach-O binary, normally named `packmon`

As on Windows, the binary can live anywhere; pass the directory to scan as an
argument (`.` for the current directory):

```bash
chmod +x ./packmon
./packmon version
./packmon scan --list-all --html packmon-report.html --output-json packmon-report.json .
./packmon db info
```

```bash
/opt/tools/packmon scan --list-all --html packmon-report.html --output-json packmon-report.json /path/to/project
```

```bash
./packmon scan --auto-sbom --install-tools --list-all --html packmon-report.html --output-json packmon-report.json .
```

If `packmon` is on `PATH`, use `packmon` instead of `.\packmon.exe` or
`./packmon`.

## Usage

### The most complete result

For the richest picture of a project, combine SBOM generation, the full
inventory listing, and the HTML report in one run:

```bash
packmon scan . \
  --auto-sbom --install-tools \
  --list-all \
  --html packmon-report.html \
  --output-json packmon-report.json
```

What each flag adds: `--auto-sbom` generates a CycloneDX SBOM with the local
ecosystem tooling and scans it alongside the lockfiles, so packages that no
lockfile declares are still covered (`--install-tools` installs the pinned
generators it needs). Auto-SBOM generation exists for Go, npm, Python, and
Maven projects only; on a project without any of those manifests the scan
aborts with `no supported manifests found for auto-SBOM generation` -- drop
`--auto-sbom --install-tools` there, the normal scan reads that project's
lockfiles (Cargo, NuGet, and the other supported ecosystems) directly.
`--list-all` adds a full package inventory with
available-update information on top of the findings, querying public registries
for latest versions -- add `--list-all-offline` when you have no outbound
network. The lookup phase is rate-limited (crates.io lookups pace at one
request per second, so a large Rust inventory takes several minutes) and
reports its progress every 10 seconds. `--html` writes a self-contained report for a browser or a ticket, and
`--output-json` the same result in the canonical machine shape;
`--output-sarif` and `--output-junit` exist for code scanning and CI test
reporting.

### First run: the feeds have to sync first

A freshly started Packmon server has an **empty advisory database**. The bare
server binary does not sync feeds on startup (`PACKMON_FEED_SYNC_ON_STARTUP`
defaults to `false`); the repository `docker-compose.yml` and the `.env`
seeded from `.env.example` both set it to `true`, so the bundled Compose stack
starts its first sync automatically. Keep that value at `true` in `.env` --
with `false` a fresh stack waits a full `PACKMON_FEED_SYNC_INTERVAL` (`8h`)
before the first import. Until the first sync finishes, a scan can
legitimately come back with zero findings simply because there is nothing to
match against.

On a new server, trigger the sync yourself under `/admin/feeds` and wait for the
feeds to report a successful import before you judge any scan result. The first
full import of the large sources (OSV, GHSA, NVD) takes a while; NVD severity
enrichment over a few thousand CVEs takes hours without a
`PACKMON_NVD_API_KEY`.

The same applies to the local CLI database used by `--mode local`: run
`packmon db sync` against a server whose feeds are populated, and check the
result with `packmon db info`. `PACKMON_DB_WARN_AFTER_DAYS` (default `7`)
controls when Packmon starts warning that local data is stale.

### Common commands

The examples use `.` as the scan target; any directory path works in its
place (`packmon scan /path/to/project`).

```bash
packmon scan .
packmon scan --html report.html .
PACKMON_API_KEY=... packmon scan . --mode remote \
  --server https://packmon.internal:8080 \
  --cacert /etc/packmon/ca.pem \
  --require-remote
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

### Blocking and exit codes

Malicious packages and active supply-chain risk findings always block. Ordinary
vulnerabilities block from the severity threshold set with `--fail-on`
(`CRITICAL` by default; `NONE` disables vulnerability blocking only, never
malware blocking).

| Exit code | Meaning |
|---|---|
| `0` | scan completed, nothing blocking |
| `1` | blocking finding at or above the threshold |
| `2` | operational error (server unreachable, auth failure, config problem) |
| `3` | findings exist, all below the blocking threshold |
| `4` | parser error prevented complete coverage |
| `10` | internal error |

### Local scan history

Local scan history is enabled by default for `packmon report` and the local
dashboard. It stores compact scan metadata in the local SQLite database:
repository name, branch, commit SHA when available, scan time, package/finding
counts, finding IDs, and severities. Set `PACKMON_HISTORY_ENABLED=false` to
disable recording, or `PACKMON_HISTORY_MAX_SCANS_PER_REPO=<n>` to change the
per-repository retention cap (`100` by default, `0` disables count-based
cleanup). Set `PACKMON_HISTORY_MAX_AGE=<duration>` to change automatic
age-based cleanup (`2160h`, 90 days by default; `0` disables age-based
cleanup). Invalid history retention values fail before recording a scan.
`packmon history clear --before YYYY-MM-DD` uses a UTC date cutoff; clearing all
history without `--repo` or `--before` requires `--force`.

## Source Checkout Requirements

The scripts in `scripts/` are helper tools for a source checkout of this
repository. Release-binary users do not need them.

If you already have a source checkout and want a helper to install a release
agent binary, these scripts perform the same checksum and attestation checks
before installing it. They only work against historical pre-removal releases:
the release pipeline that produced GitHub artifact attestations has been
removed, so no new attested releases exist.

```powershell
.\scripts\install-release.ps1 -Version <release-tag> -Arch amd64
```

```bash
./scripts/install-release.sh <release-tag>
```

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
$env:Path = "$HOME\.packmon\bin;$env:Path"
packmon version
```

```bash
bash scripts/check-requirements.sh --profile agent
./scripts/install.sh
export PATH="$HOME/.packmon/bin:$PATH"
packmon version
```

### Cross-Compile For Other Platforms

Packmon builds without CGO, so any platform can build the binaries for all
other platforms by setting `GOOS`/`GOARCH`. From Windows (PowerShell):

```powershell
$env:CGO_ENABLED = "0"
$env:GOOS = "linux";  $env:GOARCH = "amd64"; go build -trimpath -o packmon-linux-amd64 .\cmd\packmon
$env:GOOS = "darwin"; $env:GOARCH = "arm64"; go build -trimpath -o packmon-darwin-arm64 .\cmd\packmon
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
```

From Linux / macOS:

```bash
CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -trimpath -o packmon-linux-amd64 ./cmd/packmon
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o packmon-darwin-arm64 ./cmd/packmon
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o packmon-windows-amd64.exe ./cmd/packmon
```

Supported targets match the historical release matrix: `windows`, `linux`,
and `darwin`, each as `amd64` and `arm64`. The same pattern builds
`packmon-server` from `./cmd/packmon-server`.

### Verify A Historical Release Binary

Assets from historical GitHub releases
(`packmon-<os>-<arch>[.exe]`, `checksums.txt`) can still be verified by
SHA-256 digest before running them. The former GitHub artifact attestations
reference the removed `release.yml` workflow and are no longer produced.

Windows:

```powershell
$ExpectedHash = (Select-String -Path .\checksums.txt `
  -Pattern "\s$([regex]::Escape('packmon-windows-amd64.exe'))$").Line.Split()[0].ToLowerInvariant()
$ActualHash = (Get-FileHash .\packmon-windows-amd64.exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ActualHash -ne $ExpectedHash) { throw "checksum verification failed" }
```

Linux / macOS:

```bash
grep -E ' packmon-linux-amd64$' checksums.txt > packmon-linux-amd64.sha256
sha256sum -c packmon-linux-amd64.sha256
```

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
docker compose run --rm init-secrets   # first run: generate .env with local secrets
docker compose up --build              # migrate runs automatically before the server
```

Linux/macOS, or WSL on Windows:

```bash
cd <path-to-cloned-packmon>
bash scripts/check-requirements.sh --profile agent
bash scripts/check-requirements.sh --profile server
mkdir -p .build
go build -o .build/packmon ./cmd/packmon
docker compose run --rm init-secrets   # first run: generate .env with local secrets
docker compose up --build              # migrate runs automatically before the server
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
key under `/admin/keys`. Before the first scan, start the feed sync under
`/admin/feeds` and wait for a successful import -- a server with unsynced feeds
reports no findings.

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

## Local Docker Stack

The local Docker/PostgreSQL stack requires the `server` profile.

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

```bash
docker compose run --rm init-secrets
docker compose up --build
```

`init-secrets` creates or completes `.env` from `.env.example` with generated
local-only secrets for `POSTGRES_PASSWORD`, `PACKMON_DB_PASSWORD`,
`PACKMON_ADMIN_INITIAL_PASSWORD`, `PACKMON_ENCRYPTION_KEY`, and
`PACKMON_ADMIN_AUDIT_HMAC_KEY` into a UTF-8 `.env`. It keeps existing
non-empty values and never overwrites them; these commands do not print
generated secret values. `docker compose up --build` then runs the database
migration automatically before starting the server. The same two commands
work identically on Windows, macOS, and Linux.

Admins can later adjust `.env`, feed-provider API keys, TLS/proxy settings, and
other deployment-specific values before shared or production use.

Once `packmon-server` finishes starting (its container log prints
`dashboard_url` once the HTTP listener is bound; `docker compose logs -f
packmon-server` shows this live), the local server is reachable at
`http://localhost:8080`. Sign in and change the bootstrap password as described
under `First Local Server + Agent Test`; runtime settings and API-key creation
stay locked until that password has been changed.

Then create the API key that CLI agents need for remote scans:

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

### How the local stack is wired

The Docker stack runs PostgreSQL and `packmon-server` in production mode so
synced feed data is persisted. `docker-compose.override.yml` (auto-loaded by
plain `docker compose` commands run from the repository root) clears the
`packmon-migrate` manual profile so `docker compose up` runs the migration
automatically before starting the server; normal server startup only verifies
the schema version. On the self-contained server file
(`docker compose -f docker-compose.server.yml`, which never loads the local
override) `packmon-migrate` stays a manual Compose profile and receives only
database/logging environment values, not admin or feed-provider secrets. Its
database connection, advisory-lock wait, migration statements, and
post-migration version read are bounded by `PACKMON_DB_CONNECT_TIMEOUT`.

The local Compose database uses a digest-pinned Chainguard PostgreSQL image
instead of the official `postgres:*-alpine` image, avoiding the vulnerable Go
1.24.x `gosu` helper present in the official image line.

Compose forwards `PACKMON_VERSION`, `PACKMON_COMMIT`, and `PACKMON_BUILD_DATE`
as Docker build args so `packmon-server version`, startup logs, and `/version`
report the image source. They default to `dev`, `none`, and `unknown` for local
builds. Compose also supports digest-pinned internal image mirrors through
`PACKMON_POSTGRES_IMAGE`, `PACKMON_GO_BUILDER_IMAGE`, and
`PACKMON_ALPINE_RUNTIME_IMAGE`. Overrides should point at mirrored images with
the same pinned `@sha256` digest policy as the repository defaults.

For local-only use, `.env.example` enables
`PACKMON_ALLOW_INSECURE_LOCAL_HTTP=true` with explicit container bind mode
while Compose publishes the host port on `127.0.0.1`; remove those local HTTP
settings and configure TLS or a TLS-terminating reverse proxy for shared
deployments. The same local Docker profile sets `PACKMON_METRICS_HOST=0.0.0.0`
so the metrics listener is reachable through Compose's host-loopback
`127.0.0.1:9090:9090` port mapping without exposing that port beyond the host.

The PostgreSQL cluster is stored in a project-scoped Docker volume
(`<project>_postgres-data`, by default `packmon_postgres-data`), so normal
`docker compose stop`, `docker compose down`, and `docker compose up` cycles
keep the database intact. Only explicit volume removal such as
`docker compose down -v` or `docker volume rm packmon_postgres-data` will
delete the database.

The UI ships local Tailwind and htmx assets from the repository, so runtime and
normal container builds do not depend on external CDNs. When you change web
templates or Tailwind classes, use Node.js 24.11.0 or newer and refresh the
generated Tailwind v4 and htmx assets with
`npm ci --ignore-scripts && npm run build:web` before building the image.

## Development Server

The development server requires a source checkout and the `agent` profile.

```bash
go build -o packmon-server ./cmd/packmon-server
PACKMON_SERVER_MODE=development ./packmon-server
```

The development server uses the in-memory dev store, exposes the web UI, and
binds metrics to `127.0.0.1:9090` by default.

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

Remote scans send the repository name by default and never send branch or
commit metadata. Use `--no-repo-metadata`,
`PACKMON_NO_REPO_METADATA=true`, or `send_repo_metadata: false` to omit the
repository name from remote scan requests and webhooks.

Config precedence is: command-line flags > environment variables > project
`.packmon.yaml` > user-global `~/.packmon/config/packmon.yaml` > built-in
defaults. Auto-discovered project config is treated as repository input and
cannot set credential/server routing fields, latest-version or Docker registry
mirror URLs, or local write destinations such as `server`, `api_key`,
`api_key_env`, `cacert`,
`insecure_allow_http`, `require_remote`, webhook URL/secret,
`output.format`/`output.file`, or `db.path`. It may opt out of remote
repository-name metadata with `send_repo_metadata: false`, but it cannot
re-enable metadata if a higher-precedence user config, environment variable,
or flag disabled it.
Store API keys in environment variables, CI secrets, OS secret stores, or the
user-global config. Use `api_key_env` in trusted user-global or explicit config
files rather than writing plaintext keys.

The `--api-key` and `--webhook-secret` flags exist for compatibility but
reject secret values by default, because command-line arguments leak into
shell history and are visible to other processes. Setting
`PACKMON_ALLOW_SECRET_FLAGS=true` in the CLI's environment re-enables them --
an explicit opt-in intended for isolated test environments, not for CI or
production. Note that this variable (like `PACKMON_API_KEY`) belongs to the
machine running the CLI; the server-side `.env` file used by Docker Compose
plays no role for CLI settings.

### Registry mirrors

Trusted user-global config or an explicit `--config` file can also set
latest-version mirrors and Docker digest mirrors:

```yaml
registries:
  npm_registry_base_url: "https://npm-mirror.example/registry"
  pypi_api_base_url: "https://pypi-mirror.example/pypi"
  rubygems_api_base_url: "https://rubygems-mirror.example/api/v1/gems"
  cargo_registry_api_base_url: "https://cargo-mirror.example/api/v1/crates"
  cocoapods_trunk_api_base_url: "https://cocoapods-mirror.example/api/v1/pods"
  composer_repository_base_url: "https://composer-mirror.example/p2"
  go_proxy_url: "https://go-proxy.example"
  maven_repository_base_url: "https://maven-mirror.example/repository/maven-public"
  docker_registry_mirrors:
    docker.io: "https://docker-mirror.example/dockerhub"
    ghcr.io: "https://ghcr-mirror.example"
  swiftpm_git_allowed_hosts:
    - git.example.com
  cran_mirror_url: "https://cran-mirror.example"
  pub_hosted_url: "https://pub-mirror.example"
  hex_api_base_url: "https://hex-mirror.example/api"
  nuget_v3_base_url: "https://nuget-mirror.example/v3-flatcontainer"
  # Ordered NuGet v2 feeds for Chocolatey inventory lookups; replaces the
  # default community feed, so list it too if you still want it queried.
  chocolatey_feed_urls:
    - "https://www.myget.org/F/vm-packages/api/v2"
    - "https://community.chocolatey.org/api/v2"
```

The matching environment variables are `PACKMON_NPM_REGISTRY_BASE_URL`,
`PACKMON_PYPI_API_BASE_URL`, `PACKMON_RUBYGEMS_API_BASE_URL`,
`PACKMON_CARGO_REGISTRY_API_BASE_URL`,
`PACKMON_COCOAPODS_TRUNK_API_BASE_URL`,
`PACKMON_COMPOSER_REPOSITORY_BASE_URL`, `PACKMON_CRAN_MIRROR_URL`,
`PACKMON_GO_PROXY_URL`, `PACKMON_MAVEN_REPOSITORY_BASE_URL`,
`PACKMON_DOCKER_REGISTRY_MIRRORS`,
`PACKMON_SWIFTPM_GIT_ALLOWED_HOSTS`,
`PACKMON_PUB_HOSTED_URL`, `PACKMON_HEX_API_BASE_URL`,
`PACKMON_NUGET_V3_BASE_URL`, and `PACKMON_CHOCOLATEY_FEED_URLS`
(comma-separated, ordered).

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

Auto-SBOM generation supports Go, npm, Python, and Maven projects. If the
target contains no manifest from these ecosystems (`go.mod`, `package.json`,
`requirements.txt`/Poetry `pyproject.toml`, `pom.xml`), the scan fails with
`no supported manifests found for auto-SBOM generation`; run without
`--auto-sbom` in that case -- the normal lockfile scan covers the other
supported ecosystems without SBOM generation.
This requires only the matching local tool for the target ecosystem on `PATH`:
the Go toolchain for Go modules, `cyclonedx-npm` for npm, `cyclonedx-py` for
Python, or `mvn` for Maven projects. Add `--install-tools` to let Packmon
install pinned CycloneDX generators where automatic installation is supported.
Yarn, pnpm, and Pipenv lockfiles are scanned by Packmon's native parsers, but
they are not generated as auto-SBOM targets.
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
input source (`lockfile`, `sbom`, `dockerfile`, `compose`, `config.xml`, or
`choco-install`), scope, relation,
and vulnerability marker. The HTML report intentionally
omits noisy `Via` and `Flags` columns. Its `Packages Needing Attention` section
shows actionable updates, removed packages, and packages with security
findings; unknown latest-status rows stay in `All Packages`.
Finding-derived states such as `Malicious`, `Removed`, `Supply-chain risk`,
and `Lifecycle` override general latest-version status.
Standard scan artifact flags such as `--output-json`, `--output-sarif`, and
`--output-junit` still write the normal scan result alongside the combined
list-all report. Vulnerability findings with a known fix or update path render
as `Update available`; only vulnerability findings without a known update path
render as `Vulnerable`, and vulnerable packages are not shown as `Up-to-Date`.
Full source paths are deduplicated at the bottom under `Checked Inventory
Sources`. Security finding advisory IDs link to their external advisory pages
where Packmon can derive one. Long Docker digests are shown with a trailing `..`
and a `Copy` button for the full digest. GitHub Actions pinned by commit SHA are
treated as current when the pin matches the dereferenced latest tag commit, and
stale `go.sum` versions are suppressed when Go selected module versions are
available from `go.mod` or generated SBOMs.
Add `--list-all-offline` to keep the findings scan and full inventory report
but skip all public latest-version and Docker registry digest lookups; affected
rows render latest status as `unknown`.

A package status of `Unknown` in the report always means the latest version
could not be determined (offline mode, unreachable registry, or an
unsupported/private source as described below); it is not a security signal,
and security findings for that package are unaffected. Independent of the
`Unknown` status: for additional reputation and malware coverage on top of the
vulnerability feeds, configure the optional server-side ReversingLabs Spectra
Assure key (`PACKMON_REVERSINGLABS_API_KEY`, see Server Configuration).

Docker inventory is metadata-only. Packmon reads image declarations from
`Dockerfile`, `Dockerfile.*`, `docker-compose.yml`, `docker-compose.yaml`,
`compose.yml`, and `compose.yaml`; it does not build, pull, or layer-scan
images. Registry digest lookups are best-effort for Packmon's built-in public
registry allowlist. Trusted config can route those lookups through explicit
operator mirrors with `PACKMON_DOCKER_REGISTRY_MIRRORS`, using comma-separated
`public-host=https://mirror-base` entries such as
`docker.io=https://docker-mirror.example/dockerhub`. Unsupported registries or
unsafe network targets are shown as `unknown`.

Chocolatey inventory is metadata-only as well. Packmon reads FLARE-VM /
VM-Packages style `config.xml` package lists (a root `<config>` element with
`<packages><package name="..."/>` entries; other `config.xml` files are ignored
by content) and `choco install|upgrade` / `cinst` / `cup` lines in `.ps1`,
`.psm1`, `.bat`, and `.cmd` scripts. Pinned `--version` entries are compared
with the feed's latest release; unpinned entries (config.xml always installs
latest) show `INSTALLED -`, the feed's latest version, and status `unpinned`
and are never counted as available updates. Lookups query the ordered feeds
from `registries.chocolatey_feed_urls` / `PACKMON_CHOCOLATEY_FEED_URLS`
(default: the Chocolatey community feed) at two requests per second; packages
hosted on private feeds such as the FLARE-VM `vm-packages` MyGet feed show
`unknown` until that feed is configured. `--source` arguments inside scripts
are never used as lookup targets.

For latest-version reports, Packmon keeps lockfile registry/source provenance
local to the CLI. If npm, requirements.txt, Cargo, Bundler, CocoaPods,
Composer, renv, pub, Maven, or Hex inputs identify a private or non-default
source, `--outdated` and `--list-all` report latest status as `unknown` instead
of querying the matching public registry. npm, PyPI, RubyGems, Cargo,
CocoaPods, Composer, Go, Maven, CRAN, Pub, Hex, and NuGet packages can use
approved HTTPS mirrors through the registry mirror settings above; loopback HTTP
is accepted only for local tests.
Set `PACKMON_GO_PROXY_URL=off` to disable Go latest-version lookups without
enabling direct VCS fallback.
SwiftPM Git freshness can additionally allow trusted self-hosted or mirrored
Git hosts with `PACKMON_SWIFTPM_GIT_ALLOWED_HOSTS`; values are bare hostnames,
and Packmon still builds the remote as `https://host/path.git` rather than
passing raw lockfile URLs to Git.

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
parser or operational errors prevent complete scan coverage. Quiet mode still prints
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
- `PACKMON_TLS_CERT_FILE`, `PACKMON_TLS_KEY_FILE`,
  `PACKMON_TLS_MIN_VERSION=1.2|1.3`
- `PACKMON_ALLOW_INSECURE_LOCAL_HTTP=false` (loopback-only override for the
  fail-closed transport check)
- `PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE=loopback|container` (`container` is
  only for local Docker with host-loopback port publishing)
- `PACKMON_TRUSTED_PROXIES=10.0.0.0/8,192.168.10.10` (valid IP addresses or CIDR prefixes)
- `PACKMON_SERVER_READ_TIMEOUT=30s`, `PACKMON_SERVER_WRITE_TIMEOUT=30s`,
  `PACKMON_SERVER_SHUTDOWN_TIMEOUT=5s`
- `PACKMON_BLOCK_THRESHOLD=CRITICAL`
- `PACKMON_RATE_LIMIT_PER_MINUTE=60`
- `PACKMON_RATE_LIMIT_BURST=60`
- `PACKMON_METRICS_HOST=127.0.0.1`
- `PACKMON_METRICS_PORT=9090`
- `PACKMON_WEB_PRIVACY_URL=/privacy` (footer privacy link; defaults to the
  built-in notice)
- `PACKMON_WEB_LEGAL_URL` (optional operator legal notice / Impressum URL)
- `PACKMON_WEB_TERMS_URL=/terms` (footer terms link; defaults to the built-in
  operator terms hook)
- `PACKMON_DB_HOST`, `PACKMON_DB_PORT`, `PACKMON_DB_NAME`,
  `PACKMON_DB_USER`, `PACKMON_DB_PASSWORD`
- `PACKMON_DB_SSLMODE` (default `verify-full` in production, `disable` in development)
- `PACKMON_DB_MAX_CONNS=20`
- `PACKMON_DB_MIN_CONNS=2`
- `PACKMON_DB_CONNECT_TIMEOUT=10s` (startup schema-check, connection-pool, and
  explicit migration-operation deadline)
- `PACKMON_ENCRYPTION_KEY` (required in production; encrypts stored feed API
  keys at rest. Development mode may run without it.)
- `PACKMON_ADMIN_AUDIT_HMAC_KEY` (required in production; base64-encoded 32
  random bytes used to HMAC new admin audit digest-chain rows. Development
  mode may run without it and writes legacy `sha256:` audit digests.)
- `PACKMON_ADMIN_INITIAL_PASSWORD` (at least 12 characters)
- `PACKMON_ADMIN_SESSION_TIMEOUT=8h`
- `PACKMON_ADMIN_IDLE_TIMEOUT=15m`
- `PACKMON_SCAN_LOG_RETENTION=720h` (30-day retention for server `scan_log`;
  `0` disables pruning; admins can override this in `/admin/settings`)
- `PACKMON_SCAN_LOG_IDENTITY_MODE=full` controls identity metadata retained in
  server `scan_log` rows. `full` preserves existing behavior, `minimal` omits
  `client_ip`, `api_key_id`, and `api_key_name`, and `none` also omits the
  repository name and normalized client version.
- `PACKMON_ADMIN_AUDIT_LOG_RETENTION=720h` (30-day retention for
  `admin_audit_log`; `0` disables pruning; admins can override this in
  `/admin/settings`)
- `PACKMON_REFRESH_QUEUE_RETENTION=720h` (30-day retention for completed or
  failed `refresh_queue` jobs; `0` disables pruning)
- `PACKMON_PACKAGE_CHECK_STATUS_RETENTION=2160h` (90-day retention for
  Socket.dev `package_check_status` rows; `0` disables pruning)
- `PACKMON_AUDIT_RETENTION_INTERVAL=24h` (background prune cadence)
- `PACKMON_FEED_SYNC_INTERVAL=8h`
- `PACKMON_FEED_SYNC_ON_STARTUP=false` (binary default; the repository
  `docker-compose.yml` and `.env.example` set it to `true` so a fresh Compose
  stack syncs immediately -- a `false` in `.env` overrides the Compose default)
- `PACKMON_FEED_IMPORT_SECRET` (required for production
  `POST /api/v1/feeds/{feed}/import`; send it as
  `X-Packmon-Feed-Import-Secret`)
- `PACKMON_SOCKET_API_KEY`
- `PACKMON_SOCKET_API_BASE_URL=https://socket.dev/api/v1`
- `PACKMON_SOCKET_EXCLUDED_NAMESPACES` (comma-separated prefixes such as
  `npm/@internal/,maven/com.acme:`; suppresses Socket.dev refresh egress)
- `PACKMON_VULNCHECK_API_KEY`
- `PACKMON_VULNCHECK_API_BASE_URL=https://api.vulncheck.com`
- `PACKMON_NVD_API_KEY` (optional; raises the NVD API rate limit from 5 to 50
  requests per 30 seconds -- without it, NVD severity enrichment over a few
  thousand CVEs takes hours. Request a free key at
  https://nvd.nist.gov/developers/request-an-api-key)
- `PACKMON_FEED_OSV_BASE_URL=https://osv-vulnerabilities.storage.googleapis.com`
- `PACKMON_FEED_GHSA_REPO_URL=https://github.com/github/advisory-database.git`
- `PACKMON_FEED_OPENSSF_REPO_URL=https://github.com/ossf/malicious-packages.git`
- `PACKMON_FEED_CISAKEV_CATALOG_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- `PACKMON_FEED_EPSS_SCORES_URL=https://epss.cyentia.com/epss_scores-current.csv.gz`
- `PACKMON_FEED_NVD_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0`
- `PACKMON_FEED_ENDOFLIFE_ENABLED=true`
- `PACKMON_FEED_ENDOFLIFE_MODE=self`
- `PACKMON_ENDOFLIFE_API_BASE_URL=https://endoflife.date/api/v1`
- `PACKMON_FEED_REVERSINGLABS_ENABLED=false`
- `PACKMON_FEED_REVERSINGLABS_MODE=self`
- `PACKMON_REVERSINGLABS_API_KEY`
- `PACKMON_REVERSINGLABS_LOOKUP_TTL=24h`
- `PACKMON_REVERSINGLABS_BATCH_SIZE=5`
- `PACKMON_REVERSINGLABS_MAX_SCHEDULE_PER_CHECK=100`
- `PACKMON_REVERSINGLABS_CACHE_RETENTION=168h` (non-finding cache retention;
  `0` disables pruning)
- `PACKMON_REVERSINGLABS_EXCLUDED_NAMESPACES` (comma-separated prefixes such as `npm/@internal/,maven/com.acme:`)

Block threshold and rate-limit values can also be saved from `/admin/settings`;
saved values are applied immediately and persisted for future server starts.
Saving `NONE` requires an explicit acknowledgement because it disables
vulnerability blocking.
Feed enablement, mode, cadence, and feed API keys can be saved from
`/admin/feeds`; saved values are applied immediately and persisted for future
server starts.
Strict feed imports are operator-visible. When a server rejects imported feed
data, `/admin/feeds` shows bounded rejection diagnostics: rejected-record
counts and reason classes, correlation ID, client/API-key attribution when
available, and the last successful usable import timestamp. The public
`GET /api/v1/feeds/status` response stays limited to feed name, status, last
sync time, entry count, and a redacted error message.
Manual advisories can be managed from `/admin/advisories` as either
vulnerability or malicious findings. The inventory-only ecosystems (Docker,
Chocolatey) are not offered there because Packmon's support for them is
metadata-only inventory, not vulnerability coverage.
API keys can be created with a required RFC3339 UTC expiration timestamp,
revoked, and permanently deleted after revocation from `/admin/keys`; the
delete action stays recorded in the admin audit log. Creation requires
the current admin password and expiration must be no more than 365 days in the
future. Create separate named keys per client class so `last_used_at` and
revocation are useful.
Existing keys created before expiration support may show no expiration. Those
legacy keys do not expire automatically; rotate, revoke, or delete them
manually when you no longer want them accepted.

### Feed sources and attribution

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
Self-sync and enrichment feed URL settings accept HTTPS operator-controlled
mirrors or loopback HTTP test endpoints so deployments can route OSV, GHSA,
OpenSSF, CISA KEV, EPSS, NVD, endoflife.date, VulnCheck, and Socket.dev
traffic through approved caches or relays. The CLI latest-version mirror
settings listed under `Registry mirrors` provide the same routing control for
npm, PyPI, RubyGems, Cargo, CocoaPods, Composer, Go, Maven, CRAN, Pub, Hex, and
NuGet freshness checks. Go uses a single module-proxy root plus `/@latest`;
Maven uses a Maven repository root and `maven-metadata.xml`.
`PACKMON_DOCKER_REGISTRY_MIRRORS` provides the same operator-routing control
for `--list-all` Docker manifest digest checks. It maps supported public
registry hosts to trusted mirror base URLs and does not read Docker credentials,
pull images, or enable arbitrary repository-controlled registries.
The Docker `.env.example` keeps account-gated feeds such as VulnCheck,
Socket.dev, and ReversingLabs disabled until the matching API key is supplied
and the feed is explicitly enabled.
Lifecycle/EOL findings are available only where package coordinates map to an
endoflife.date product and release cycle. Library packages without official
lifecycle metadata may still be vulnerable or outdated without being reported
as EOL.
ReversingLabs lookups are disabled by default. When enabled with an API key,
the server performs bounded demand-driven lookups only for supported,
length-bounded packages that are not already covered by other feeds,
percent-encodes outbound PURLs, deduplicates and caps scheduled work per check
request, stores normalized cache rows internally, and refreshes each package
version at most once per day. Active malware signals are reported as malicious
findings; historical-only incident evidence currently produces no finding (the
package is cached as clean) -- surfacing it as non-blocking reputation info is
a possible future extension. Use
`PACKMON_REVERSINGLABS_EXCLUDED_NAMESPACES` to suppress private package
prefixes before external lookup. Non-finding cache rows are pruned by
`PACKMON_REVERSINGLABS_CACHE_RETENTION`; `0` disables pruning.
Socket.dev refreshes are disabled by default. When enabled with an API key,
manual refresh requests and the worker both honor
`PACKMON_SOCKET_EXCLUDED_NAMESPACES` before queueing or sending package names to
Socket.dev.

## Client Profiles

- Dev laptops: use the HTTPS server URL, `PACKMON_CA_CERT_FILE` or `--cacert`
  for the internal CA, and `PACKMON_API_KEY` from the user environment or OS
  secret store. `PACKMON_CA_CERT` remains a legacy alias.
- CI runners: create a dedicated named key, store it as a CI secret, set
  `PACKMON_REQUIRE_REMOTE=true`, and rotate it before its required expiration.
- Segmented production networks: distribute the internal CA bundle to scanners,
  allow only the Packmon TLS port through the firewall, and make sure the
  server certificate SAN covers the address clients use.
- N8N: create a dedicated key for the workflow and call `/api/v1/check` over
  HTTPS with `Authorization: Bearer <key>` and a `User-Agent` starting with
  `packmon-n8n/`. For feed import endpoints, also configure
  `PACKMON_FEED_IMPORT_SECRET` on the server and send the same value as
  `X-Packmon-Feed-Import-Secret`.

For CLI local freshness warnings:

- `PACKMON_DB_WARN_AFTER_DAYS=7`

When local DB age exceeds this threshold, scan artifacts expose `db_stale` and
`db_age_days`, and `packmon dashboard` must show a visible stale-data warning to
all dashboard viewers. Treat the warning as degraded local coverage and sync the
local DB from the server; stale data alone does not block scans.

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
PACKAGES="$(go list ./... | grep -v /node_modules/)"
GOSEC_DIRS="$(go list -f '{{.Dir}}' ./... | grep -v node_modules)"
GOFMT_FILES="$(git ls-files '*.go')"
gofumpt -extra -l ${GOFMT_FILES}
go test -count=1 ${PACKAGES}
go test -count=1 -race -coverprofile=coverage.out ${PACKAGES}
go run ./tools/checkcoverage -profile=coverage.out -min=79.5
go vet ${PACKAGES}
golangci-lint run ./...
govulncheck ${PACKAGES}
gosec -nosec-require-rules -nosec-require-justification ${GOSEC_DIRS}
```

The `make test*` targets set `GOTMPDIR` to the ignored local `.gotmp` directory
so temporary Go test binaries do not get written to the system temp folder.

For a quicker repository-gate check:

```bash
GOTMPDIR="$PWD/.gotmp" go test -count=1 ./tests/ci
```

`go test -count=1 ./tests/ci` validates repository governance and
configuration gates (Dockerfile hardening, Compose defaults, documentation
cross-references, agent permissions).
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
$packages = go list ./... | Where-Object { $_ -notmatch 'node_modules' }
$gosecDirs = go list -f '{{.Dir}}' ./... | Where-Object { $_ -notmatch 'node_modules' }
$gofmtFiles = git ls-files '*.go'
gofumpt -extra -l $gofmtFiles
go test -count=1 $packages
go test -count=1 -race '-coverprofile=coverage.out' $packages
go run ./tools/checkcoverage '-profile=coverage.out' '-min=79.5'
go vet $packages
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

### Production server

Supply secrets yourself (`.env` or a secrets manager) and run migrations
explicitly using the self-contained server file:

```bash
# Production server (behind your own TLS reverse proxy):
docker compose -f docker-compose.server.yml run --rm packmon-migrate
docker compose -f docker-compose.server.yml up -d
```

`docker-compose.server.yml` needs no base file: it holds the hard `:?` secret
guards (the local `docker-compose.yml` stays permissive so `init-secrets` can
run on a fresh clone); `init-secrets` never overwrites values you set. The
server serves plain HTTP in-container -- terminate TLS at your own reverse
proxy (nginx/Traefik/Caddy) and set `PACKMON_TRUSTED_PROXIES` to the proxy's
IP/CIDR so the server trusts its `X-Forwarded-*` headers. The server port is
published only on `127.0.0.1`, so only a host-local proxy can reach it.

Example nginx front (TLS terminated at the proxy, forwarding to the
loopback-published server):

```nginx
server {
  listen 443 ssl;
  server_name packmon.example.com;
  ssl_certificate     /etc/ssl/packmon/fullchain.pem;
  ssl_certificate_key /etc/ssl/packmon/privkey.pem;
  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

Set `PACKMON_TRUSTED_PROXIES` to the proxy's source address as seen by the
container (e.g. the Docker gateway CIDR).

### Backup

The backup strategy is intentionally simple:

- daily `pg_dump`
- 7-day local retention
- backup files stored outside the application data path

RPO is roughly 24 hours. RTO (Recovery Time Objective) is not a Packmon product
SLA for the repository-provided Compose model; each deployment must document
its own target and validate it with restore drills. Keep restore drills and
deployment-specific backup destinations in the operator-owned runbook for the
environment where Packmon runs.

`docs/runbook.md` holds the operator procedures for backup, restore, upgrade,
rollback, key rotation, alerting, and incident response.

## Troubleshooting

**`required variable ... is missing a value` / the server won't start**
Run the two commands in order: `docker compose run --rm init-secrets` (creates
`.env`), then `docker compose up`. Compose's `:?` guard fails the same way whether
a secret is unset *or* empty.

**All variables appear "missing" even though `.env` exists (Windows)**
Symptom: every `${VAR}` reports missing. Cause: the `.env` was written as UTF-16 /
with a BOM (PowerShell's default), which Docker Compose cannot parse. Check with
`Format-Hex .env | Select-Object -First 1` -- a leading `FF FE` means UTF-16. Fix by
regenerating it: delete `.env` and run `docker compose run --rm init-secrets`
(writes UTF-8/LF from inside the container). Bind mounting to write `.env` requires
Docker Desktop file sharing for the drive.

**`PACKMON_ENCRYPTION_KEY` / `PACKMON_ADMIN_AUDIT_HMAC_KEY` invalid**
These must be base64-encoded 32-byte values. Regenerate with
`docker compose run --rm init-secrets`.

**A scan reports no findings at all**
Check whether the server's feeds have finished their first sync under
`/admin/feeds`. A server with an empty advisory database returns zero findings
for every package. See `Usage` above.

**A remote scan silently used local data**
Without `--require-remote`, `--mode auto` falls back to the local database when
the server is unreachable or rejects the API key. Add `--require-remote` to make
that a hard error instead.

## Canonical Project Docs

- `DESIGN.md`: canonical product requirements, data flow, and non-goals.
- `ARCHITECTURE.md`: concise runtime and deployment architecture map.
- `SECURITY.md`: security model, invariants, and audit checklist.
- `docs/runbook.md`: operator backup, restore, upgrade, rollback, rotation, alerting, and incident response procedures.
- `docs/architecture/system-context.mmd`: system-boundary diagram.
- `docs/adr/README.md`: accepted architecture decision index.
- `docs/data-classification.md`: storage and sensitivity map.
- `docs/deferred-scope.md`: fork-local audit scope that is intentionally not fixed yet.
- `docs/risk-register.md`: risk assessment and treatment register.
- `docs/secure-coding.md`: secure-coding and security-awareness checklist for contributors.
- `docs/supplier-security.md`: supplier and feed-provider security assessment.
- `CONTRIBUTING.md`: human contributor workflow, validation, and documentation rules.
- `.github/SECURITY.md`: private vulnerability reporting entry point.

Use these files as the baseline for future audits and implementation reviews.

## License

Packmon is proprietary software; all rights reserved. The repository and the
container images intentionally ship no license file for Packmon's own code:
without a license grant, no reuse or redistribution rights are given. The
OpenAPI contract declares this via the SPDX identifier `LicenseRef-Private`.

This applies to Packmon's own code only. Third-party open-source components
keep their own permissive licenses (MIT, BSD, Apache-2.0, ISC, 0BSD).
`THIRD_PARTY_NOTICES.md` documents the web assets embedded in the server
binary with their full license texts; the Go modules fetched at build time
carry their license files in the Go module cache. Packmon does not distribute
prebuilt binaries -- users build from source (see `Quick Start`).

The canonical source and Go module namespace is
`github.com/8linkz-sec/packmon`.
