# Packmon Design and Requirements

This document is the canonical product and architecture baseline for Packmon.
Use it to answer "how is this intended to work?" and to compare implementation
against intent during audits.

## Product Goal

Packmon detects vulnerable and malicious dependencies in developer repositories.
It must work as:

- a local CLI for developers;
- a central feed/API server for teams;
- a CI/CD scanner for GitHub Actions and GitLab CI;
- an automation component for N8N workflows.

The expected scale is internal organizational use: hundreds of developers and
tens of thousands of unique packages. Packmon is not designed as a public SaaS
or a public internet-facing API.

## Primary Requirements

- Scan dependency lockfiles and supported manifest-like files across the
  canonical ecosystems.
- Accept explicit CycloneDX and SPDX SBOM files as package inventory inputs.
- Detect known vulnerabilities, malicious package findings, and configured
  supply-chain and lifecycle risk findings.
- Support remote server mode, local SQLite mode, and auto fallback mode.
- Produce human-readable terminal output and machine-readable JSON, SARIF, and
  JUnit files.
- Use stable exit codes for CI:
  - `0`: no findings;
  - `1`: blocking findings;
  - `2`: operational error;
  - `3`: findings below the blocking threshold (non-blocking; treated as a
    passing pipeline by the shipped CI templates);
  - `4`: parser error;
  - `10`: internal bug.
- Treat malicious and supply-chain risk findings as always blocking.
- Let teams configure vulnerability blocking thresholds.
- Keep CLI, API, and webhook scan result schemas aligned.
- Keep server feed data in PostgreSQL.
- Keep local CLI data in SQLite and sync it from the Packmon server only.
- Provide a web dashboard, package search, admin settings, feed status, queue
  management, manual advisories, and API-key management.
- Provide internal monitoring metrics and operational runbook coverage.

## Non-Goals

- Public SaaS multi-tenancy.
- User-account management beyond one shared admin login.
- Client-side direct synchronization from public vulnerability feeds.
- Treating SBOM-embedded vulnerability or VEX statements as authoritative scan
  findings.
- Server-side parsing of repository lockfiles from N8N or CI. Clients parse
  lockfiles and send package lists.
- Automatic database migrations on normal server startup.
- Startup feed-data reconciliation that is bounded, idempotent, and runs only
  after schema-version verification is not a schema migration. It must not alter
  database structure or be required to upgrade an old schema.
- Point-in-time database recovery or WAL archiving managed by Packmon.
- Replay protection for webhooks. This is intentionally omitted for internal
  tooling simplicity.

## Repository Layout

- `cmd/packmon`: CLI entry point and commands.
- `cmd/packmon-server`: server entry point, migration command, dev/noop store.
- `internal/domain`: canonical domain models, severity, scan result schema.
- `internal/parser`: lockfile parsers and ecosystem registry.
- `internal/sbom`: CycloneDX/SPDX inventory parsing and Package URL mapping.
- `internal/scanner`: file discovery, scan orchestration, output writers,
  webhook delivery, local history integration.
- `internal/api/v1`: public API handlers.
- `internal/api/admin`: admin web/API handlers and form processing.
- `internal/server`: HTTP server setup and middleware.
- `internal/db/postgres`: server persistence and PostgreSQL queries.
- `internal/db/sqlite`: local CLI database and sync store.
- `internal/feed`: feed sync interfaces, manager, queue, and feed syncers.
- `internal/web`: public web UI handlers and embedded templates/assets.
- `internal/telemetry`: in-process counters and Prometheus text output.
- `api/openapi`: versioned API contract.
- `ci/gitlab`: reusable GitLab CI template.
- `.github/workflows`: project CI, nightly, release, and Packmon scan workflow.
- `deploy`: Helm, Rancher, and N8N deployment/automation assets.

## Architecture

Packmon has two main runtime surfaces.

The CLI discovers lockfiles, parses explicit SBOM inventory files, applies
config and filters, and checks findings using either a remote server or the
local SQLite database. The CLI owns all repository filesystem access.

The server owns feed synchronization, normalized advisory storage, API checks,
admin UI, web UI, queue operations, and metrics. The server receives package
lists, not source code or lockfile contents.

```text
Developer repo
  -> packmon CLI
     -> parser registry
     -> SBOM inventory importer
     -> scanner/checker
     -> remote /api/v1/check or local SQLite
     -> table + JSON/SARIF/JUnit + optional webhook

Feeds
  -> feed syncers or N8N feed imports
  -> PostgreSQL normalized tables
  -> /api/v1/check, /api/v1/sync, web UI, metrics
```

## Supported Ecosystems

The canonical ecosystem identifiers are lowercase:

```text
npm, pypi, go, maven, cargo, nuget, composer, gem, pub,
cocoapods, swiftpm, hex, cran, actions
```

Feed-specific names must be mapped into this enum at the import boundary.
SwiftPM packages are identified by OSV/PURL SwiftURL name
(`host/owner/repo`, without URL scheme or `.git`) when `Package.resolved`
provides a repository location. GitHub Actions workflow references are
identified as `owner/repo` from external `uses: owner/repo@ref` entries under
`.github/workflows/`.

## CLI Behavior

`packmon scan` is the primary command. It discovers supported lockfiles up to a
configured depth, parses packages from lockfiles and explicit SBOM inputs,
filters ignored ecosystems/packages, and checks findings.

Important behavior:

- stdout is human-readable unless `--quiet` is used.
- JSON, SARIF, JUnit, and HTML reports are written with explicit output-file
  flags. `--html <path>` writes a single self-contained report with no external
  assets or external JavaScript. Findings are grouped by type (Malicious ->
  Supply-Chain/EOL -> Vulnerabilities -> Lifecycle), severity-sorted within
  each group, and each vulnerability/EOL finding links to its source. A scan
  with zero findings still produces a clean "all clear" report. Like the other
  file outputs, `--html` only works when scanning a single target.
- `--include-dev` includes dependencies marked as dev/test scope.
- `--list-all` keeps the findings scan scope identical to a normal scan:
  dev/test packages are checked only when `--include-dev` is set. Its package
  inventory section still lists every detected package by default and annotates
  source (`lockfile`, `sbom`, `dockerfile`, `compose`), scope (`runtime`,
  `dev`, `ci`, `sbom`, `build`), relation (`direct`, `transitive`,
  `workflow`, etc.), npm `via` roots, and optional/peer flags. HTML reports
  omit the noisy `Via` and `Flags` columns, keep full source paths out of
  package rows, and render a deduplicated "Checked Inventory Sources" section
  at the bottom for lockfiles, SBOMs, and Docker inventory files. The HTML
  "Packages Needing Attention" section lists actionable updates, removed
  packages, and packages with security findings; unknown latest-status rows
  remain visible only in "All Packages". Finding-derived states such as
  `Malicious`, `Removed`, `Malware history`, `Supply-chain risk`, and
  `Lifecycle` override general latest-version status. Vulnerability findings
  with a known fix or update path
  render as `Update available`; only vulnerability findings without a known
  update path render as `Vulnerable`, and a package with a security finding is
  never shown as merely `Up-to-Date`. Security finding advisories link to
  canonical external reports when available. Long digest values are shortened
  with `..` in the visible table and exposed through a local copy-to-clipboard
  control containing the full value.
- `--sbom <file>` can be repeated to add CycloneDX JSON/XML or SPDX JSON
  package inventory to scans, `--list-packages`, and `--outdated`.
- SBOM input contributes package coordinates only. Embedded SBOM
  vulnerability, VEX, license, and provenance assertions are not used as
  authoritative Packmon findings. CycloneDX dependency edges are used as
  package graph metadata for scope, relation, `via`, and parent-aware npm
  update resolution.
- `--auto-sbom` detects Go, npm, PyPI, and Maven manifests, invokes the
  matching local ecosystem tooling, validates CycloneDX JSON output, and
  appends the generated SBOM files to the normal scan input. Go modules are
  converted from `go list -mod=readonly -m -json all` output with
  `GOWORK=off`; npm, PyPI, and Maven use CycloneDX generators. `--sbom-only`
  generates SBOM files without running a scan; `--keep-sbom <dir>` keeps
  generated files as timestamped snapshots so repeated runs do not overwrite
  previous SBOMs; `--install-tools` may install missing pinned generator tools
  where automatic installation is supported. Pinned generator versions are
  `cyclonedx-npm` 4.2.1, `cyclonedx-bom` 7.3.0, and
  `cyclonedx-maven-plugin` 2.9.1. Generation runs local external toolchains and
  may cause those toolchains to contact package registries.
- config precedence is flags, environment, project `.packmon.yaml`, user-global
  `~/.packmon/config/packmon.yaml`, defaults.
- local history is stored compactly in SQLite for report/dashboard features.
- stale local DB data produces warnings but does not block scans by itself.
- repo metadata such as name, branch, and commit may be sent to the server for
  scan logging.
- `--outdated` uses free public registry metadata for every canonical
  ecosystem where a package version can be resolved. Private registries,
  branch pins, commit-only pins, and unavailable upstream metadata are reported
  as unknown rather than failing the scan. Its terminal and HTML reports include
  the same package provenance columns (`scope`, `relation`, `via`, and flags)
  as `--list-all`. For npm transitive packages with known immediate parents,
  Packmon resolves the highest version allowed by the parents' dependency
  ranges and does not report a registry-latest major as an actionable update
  when the parent range cannot select it. GitHub Actions pinned by commit SHA
  are not reported as outdated when the pin matches the dereferenced latest tag
  commit. Go inventory suppresses stale `go.sum` versions when `go.mod` or a
  generated Go SBOM provides the selected module version.
- `--list-all` also inventories Docker image declarations from `Dockerfile`,
  `Dockerfile.*`, `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`,
  and `compose.yaml`. Docker rows use ecosystem `docker`, show declared
  tags/digests, record their package source as `dockerfile` or `compose`, and
  resolve public registry manifest digests best-effort. If the local Docker
  CLI can inspect the declared image, Packmon compares the local repo digest
  with the current registry digest and marks `UPDATE yes`, `-`, or `unknown`.
- Docker image inventory is not a container-layer vulnerability scan. Packmon
  does not pull images, scan OS packages inside images, or read private
  registry credentials as part of `--list-all`.

## Server Behavior

The server provides:

- `POST /api/v1/check` for package-list checks;
- `GET /api/v1/sync` for local SQLite sync;
- feed status and import endpoints;
- refresh queue endpoints;
- health, readiness, version, and metrics endpoints;
- public web dashboard/package search;
- admin UI for login, API keys, queue, feed config, advisories, settings, and
  audit log.

Production mode uses PostgreSQL. Development mode uses a local in-memory/noop
store to support fast local integration tests and UI development.

## Data Model

Vulnerabilities are normalized across multiple tables:

- core vulnerability facts;
- aliases such as CVE, GHSA, OSV IDs;
- source records with source-specific IDs and freshness;
- references;
- affected packages and version ranges.

Alias relationships are many-to-many in practice. The project intentionally
uses a composite uniqueness model for vulnerability aliases where needed rather
than assuming a single alias belongs globally to only one record.

Malicious findings are separate entities with stable IDs, package identity,
source, risk type, severity, optional affected versions, summary, and
description.

Package reputation cache rows are version-specific normalized records from
demand-driven reputation sources. They store status, minimal evidence,
timestamps, and refresh scheduling data. `malicious` status produces a
malicious finding. `removed` status produces a blocking `supply_chain_risk`
finding with `risk_type=removed_package`. `risk` status represents
non-active supply-chain reputation evidence, such as ReversingLabs malware
incident history, and produces a blocking `supply_chain_risk` finding with
`risk_type=malware_history`. `clean`, `not_found`, `unsupported`, and transient
`error` statuses do not produce findings.

Lifecycle rows are normalized from product release metadata into package
ecosystem/name mappings and release cycles. Exact end-of-life matches produce a
blocking `supply_chain_risk` finding with `risk_type=eol`. Upcoming
end-of-life and security-support-only states produce `lifecycle` findings and
block only according to severity threshold. Unknown or unmapped lifecycle state
does not produce a finding.

Manual advisories are admin-managed records. They can represent either
vulnerability findings or malicious findings. New manual records without an
operator-supplied ID use stable `manual:<uuid>` IDs.

## Feed Sources

Core server-side vulnerability, malicious-package, and lifecycle coverage must
not depend on paid APIs or account-gated services. Server-side feed sources
include:

- OSV.dev public bulk data, including GitHub Actions advisories;
- GitHub Advisory Database;
- OpenSSF malicious packages;
- CISA KEV;
- EPSS;
- NVD CVE enrichment, optionally with an API key only for higher rate limits.
- endoflife.date public lifecycle metadata, with no API key.

Optional reputation/enrichment sources can be enabled by operators but are not
part of the required free core coverage:

- VulnCheck;
- Socket.dev through async queue behavior;
- ReversingLabs Spectra Assure Community API as an optional server-side,
  demand-driven reputation source. The server stores normalized package
  reputation cache rows and refreshes a package version at most once per 24
  hours when it appears in a check request and no non-ReversingLabs feed already
  covers it. Active malware signals are reported as malicious findings;
  historical malware incident evidence is reported separately as supply-chain
  reputation risk.

OSV/RustSec affected-package records with `database_specific.categories`
containing `malicious` are normalized as malicious package findings, not as
vulnerability findings. Vulnerabilities whose upstream source has no severity
or CVSS data are stored with a conservative `LOW` fallback until alias or NVD
enrichment can raise them. `UNKNOWN` vulnerability severity is not a final
user-facing state.

Feed sync can run inside the server or be supplied externally through N8N feed
import endpoints. Feed failure must not delete existing good data. Check
responses must indicate degraded feed state when data is missing, skipped, or
stale.

ReversingLabs is self-managed only and has no external import endpoint. Initial
enabled ecosystems are `npm`, `pypi`, `gem`, `nuget`, and `maven`.

endoflife.date is self-managed only and has no external import endpoint in
Packmon. The server fetches product release metadata, maps Package URL
identifiers and conservative built-in package mappings to canonical ecosystems,
and stores normalized lifecycle rows. Only packages that can be mapped to an
endoflife.date product and release cycle can receive lifecycle findings.
Unmapped libraries may still be vulnerable or outdated, but they are not
reported as end-of-life.

## Refresh Queue

The refresh queue is package-wide, not version-specific. Jobs are deduplicated
by ecosystem, package name, and source while active.

Queue priority levels are:

- `0`: manual admin trigger;
- `1`: unknown packages never checked before;
- `2`: packages with known findings;
- `3`: oldest `updated_at` / normal re-check work.

Queue statuses include:

- `pending`;
- `processing`;
- `paused`;
- `done`;
- `error`.

Admins can update priority, pause, resume, retry, purge, and clear matching
statuses. Paused jobs must not be dequeued.

## Local SQLite Mode

Local mode uses a compact SQLite database populated from `GET /api/v1/sync`.
It stores enough data for equivalent finding quality but not full server detail.

Remote and local modes should detect the same vulnerability, malicious, synced
reputation, and lifecycle findings when local data is fresh. Local SQLite sync
stores raw lifecycle status booleans and dates, then computes current lifecycle
findings at scan time. Differences are allowed only in detail level and
freshness.

## Web UI

The web UI uses Go templates, Tailwind CSS v4, and htmx. Assets are local and
embedded into the binary. Tailwind v4 uses modern CSS features, so the UI
browser baseline follows Tailwind's v4 targets: Safari 16.4+, Chrome 111+, and
Firefox 128+. The UI should stay operational and utilitarian: dashboard,
package search, package details, scans, admin pages, and forms.

Admin pages are protected by the shared admin session model described in
`SECURITY.md`.

The admin UI exposes `/.well-known/change-password` as a redirect to the
password settings page so password managers can discover the password-change
entry point.

## Configuration

Important server environment variables:

- `PACKMON_SERVER_MODE`;
- `PACKMON_SERVER_PORT`;
- `PACKMON_SERVER_PUBLIC_HOST`;
- `PACKMON_TLS_CERT_FILE`;
- `PACKMON_TLS_KEY_FILE`;
- `PACKMON_TLS_MIN_VERSION`;
- `PACKMON_TRUSTED_PROXIES`;
- `PACKMON_ALLOW_INSECURE_LOCAL_HTTP`;
- `PACKMON_BLOCK_THRESHOLD`;
- `PACKMON_RATE_LIMIT_PER_MINUTE`;
- `PACKMON_RATE_LIMIT_BURST`;
- `PACKMON_METRICS_HOST`;
- `PACKMON_METRICS_PORT`;
- `PACKMON_DB_*`;
- `PACKMON_ADMIN_INITIAL_PASSWORD`;
- `PACKMON_FEED_ENDOFLIFE_ENABLED`;
- `PACKMON_FEED_ENDOFLIFE_MODE`;
- `PACKMON_ENDOFLIFE_API_BASE_URL`;
- feed API keys and feed mode/enabled flags.

Admin system settings can persist selected runtime values such as block
threshold and rate-limit settings. Persisted values are loaded on server start.
Admin feed settings can persist enablement, mode, cadence, and feed API keys.
Feed setting changes are applied to the running process immediately and are
also loaded on future server starts.

CLI configuration may reference API keys via `api_key_env` so project config
files do not need plaintext secrets. Environment variables and flags still take
precedence over project and user-global config.

API keys are named, hashed at rest, track `last_used_at`, support revocation,
and can optionally expire via `expires_at`. Expired keys are not accepted by
production `/api/v1/*` authentication.

## CI/CD Integration

Packmon supports:

- GitHub Actions workflows;
- a GitLab shared CI template under `ci/gitlab`;
- SARIF upload;
- JUnit report files;
- JSON result artifacts;
- optional PR comments;
- optional webhook delivery.

The GitLab template is locally validated by `tests/ci`. A real GitLab runner
validation remains externally dependent on a GitLab project and registered
runner.

## Monitoring and Operations

The metrics endpoint emits Prometheus text metrics for:

- HTTP request count and duration;
- packages scanned and scan findings;
- vulnerability/malicious/finding severity totals;
- feed last sync and age;
- feed timeouts;
- queue size, oldest job, errors, and recovered stuck jobs;
- DB pool state;
- migration version;
- auth login failures and degraded responses.

Metrics bind to `127.0.0.1` by default.

Backups are intentionally simple: periodic `pg_dump`, seven-day local
retention, and storage outside the application data path. External backup
systems are responsible for off-host retention.

## Test and Quality Requirements

Normal local gate:

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

Build and tagged test gate:

```bash
go build -o .build/packmon ./cmd/packmon
go build -o .build/packmon-server ./cmd/packmon-server
GOTMPDIR="$PWD/.gotmp" PACKMON_TEST_BIN_DIR=.build go test -count=1 -tags integration ./tests/integration
GOTMPDIR="$PWD/.gotmp" PACKMON_TEST_BIN_DIR=.build go test -count=1 -tags e2e ./tests/e2e
```

The Docker/PostgreSQL production integration test is the strongest local proxy
for a real deployment:

```bash
PACKMON_TEST_BIN_DIR=.build go test -count=1 -tags integration -run '^TestProductionServerWithPostgresAndAPIKey$' -v ./tests/integration
```

## Open External Validation

The only documented open validation gap is the real GitLab runner test:

- GitLab server/project available;
- runner registered;
- shared template run in a real pipeline;
- binary download and checksum verified in pipeline;
- JSON, SARIF, and JUnit artifacts visible in GitLab.
