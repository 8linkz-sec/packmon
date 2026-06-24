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

The canonical source repository and Go module path are
`github.com/8linkz-sec/packmon`; release metadata, CI templates, generated
report links, and internal imports must use that namespace consistently.

HTTP handlers and middleware own their persistence boundaries. API v1 scan/read,
feed-import, admin, API-key auth, and admin bootstrap code depend on small
consumer-owned store interfaces instead of the monolithic database store, so
unrelated persistence capabilities do not leak across subsystem boundaries.

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
  - `4`: parser error, including partial lockfile/SBOM parse errors when no
    blocking finding has already failed the scan;
  - `10`: internal bug.
- Treat malicious and active supply-chain risk findings as always blocking.
  Historical ReversingLabs malware-incident evidence is `LOW` reputation info
  and does not block by itself.
- Let teams configure vulnerability blocking thresholds. `NONE` disables
  vulnerability blocking only and requires explicit acknowledgement when saved
  from the admin settings UI.
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
- First-party Kubernetes packaging. Operators that run Packmon on Kubernetes
  own those manifests, including migrations, secrets, TLS, health probes,
  network policy, backup scheduling, and rollout behavior.

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
- `deploy`: N8N automation assets only.
- `docker-compose.yml`: the repository-provided container deployment entry for
  local and internal self-hosted starts.

## Architecture

Packmon has two main runtime surfaces.

The CLI discovers lockfiles, parses explicit SBOM inventory files, applies
config and filters, and checks findings using either a remote server or the
local SQLite database. The CLI owns all repository filesystem access.
Parser diagnostics identify the parser/file, line or entry position, and a
generic reason; they do not echo raw dependency-file lines or malformed private
coordinates. Lockfile and SBOM parsers enforce input-size limits before parsing;
Dockerfile and Compose inventory collection has its own bounded input-size
policy for `--list-all` Docker image discovery.

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
  -> feed syncers or N8N feed imports with feed-import secret
  -> PostgreSQL normalized tables
  -> /api/v1/check, /api/v1/sync, web UI, metrics
```

## Deployment Architecture

Packmon's maintained deployment surfaces are intentionally narrow:

- `docker-compose.yml` starts PostgreSQL and the server for local and internal
  self-hosted deployments. Database migrations remain an explicit operator
  step with `docker compose run --build --rm packmon-migrate`; that manual
  service receives only database and logging environment values.
- `deploy/n8n` contains workflow templates that call the Packmon server over
  authenticated HTTPS APIs. Command-node templates use environment variables,
  short-lived `mktemp` files with cleanup traps, and path-minimized webhook
  responses.
- `.github/workflows/packmon-scan.yml` and `ci/gitlab/.packmon-scan.yml`
  provide CI integration templates for consumer repositories.
- `.github/workflows/release.yml` publishes binary release artifacts only; it
  does not publish a container image. Release assets include checksums, a
  CycloneDX SBOM, project license files, third-party notice material, generated
  Go module license notices, and GitHub artifact attestations.

The server process still supports containerized and orchestrated operation, but
the repository no longer maintains first-party Kubernetes deployment packaging.
Teams choosing Kubernetes must provide their own manifests or platform
templates and keep them aligned with Packmon's operational invariants:

- run `packmon-server migrate` as an explicit operator step before server
  rollout;
- provide PostgreSQL and keep its backup/restore lifecycle outside the
  application data path;
- configure in-app TLS or a trusted TLS-terminating proxy before production
  startup; the local insecure HTTP override is limited to loopback and makes
  the main listener bind to `127.0.0.1` unless local Docker explicitly uses
  container bind mode with host-loopback port publishing;
- keep metrics local or protect non-local metrics exposure with network
  controls;
- provide secrets through the platform's secret-management mechanism;
- size replicas, readiness/liveness probes, shutdown grace, and background
  workers according to the single-server architecture unless a separate HA
  design is added.

## Supported Ecosystems

The canonical ecosystem identifiers are lowercase:

```text
npm, pypi, go, maven, cargo, nuget, composer, gem, pub,
cocoapods, swiftpm, hex, cran, actions, docker
```

The `/api/v1/check` scan contract accepts the vulnerability/malware scan
ecosystems in that list except `docker`. Docker is retained as a canonical
metadata-only inventory ecosystem for CLI reports, not as a server-side
vulnerability-scan ecosystem.
CLI ecosystem filters from flags, environment, project config, or repo config
are normalized and validated against this list before scanning; `docker` is
accepted only for `--list-all` inventory filtering.

Feed-specific names must be mapped into this enum at the import boundary.
Package identities are canonicalized anywhere they cross a scan, feed, sync,
or storage boundary. NuGet package IDs are lowercased. PyPI package names use
PEP 503 normalization: lowercase and replace each run of `.`, `_`, or `-` with
a single `-`. Other ecosystem names preserve their registry casing unless a
specific ecosystem rule is added. NuGet version matching follows NuGet's
case-insensitive prerelease-label behavior for both ecosystem ranges and
explicit affected-version lists.
SwiftPM packages are identified by OSV/PURL SwiftURL name
(`host/owner/repo`, without URL scheme or `.git`) when `Package.resolved`
provides a repository location. URL userinfo and non-HTTP(S) repository
schemes are not used as package identity. SwiftPM latest-version lookup is
limited to canonical public Git host identities on the built-in allowlist
(`github.com`, `gitlab.com`, and `bitbucket.org`); full URLs, SCP-like
remotes, local paths, IP/localhost-style identities, and non-allowlisted hosts
are reported as unknown. Git lookup arguments are passed after Git's
end-of-options delimiter. GitHub Actions workflow references are identified as
`owner/repo` from external `uses: owner/repo@ref` entries under
`.github/workflows/`; owner/repo casing is normalized to lowercase because
GitHub repository paths are case-insensitive for advisory matching.

## CLI Behavior

`packmon scan` is the primary command. It discovers supported lockfiles up to a
configured depth, parses packages from lockfiles and explicit SBOM inputs,
filters ignored ecosystems/packages, and checks findings.

Important behavior:

- stdout is human-readable unless `--quiet` is used. `--quiet` suppresses
  routine stdout, but trust-changing warnings such as auto-mode local fallback
  and partial parse errors still go to stderr.
- Canonical `ScanResult.feed_status` is a compact machine-readable status:
  `healthy`, `degraded`, or `error`. Parser and operational failure details are
  carried in optional `scan_error`; partial inventory details remain in
  `parse_errors`.
- Canonical `ScanResult.block_threshold` records the effective
  vulnerability/lifecycle severity threshold used for `findings_blocking`.
  Malicious and active supply-chain risk findings still block independently of
  that threshold; historical ReversingLabs malware-incident evidence is `LOW`
  reputation info and does not block by itself.
- Auto mode reports the actual execution path in `ScanResult.mode`: successful
  server-backed checks report `remote`, while local fallback reports `local`.
- Discovery failures for in-scope files or directories are operational errors;
  unsupported, hidden, vendor, and configured depth-excluded paths are the only
  discovery skips that may be silent.
- JSON, SARIF, JUnit, and HTML reports are written with explicit output-file
  flags. Report outputs are opened through the private output-file helper so
  new files are created with `0600` permissions and existing broader-mode files
  are tightened back to `0600` when overwritten. `--html <path>` writes a
  single self-contained report with no external assets or external JavaScript.
  Findings are grouped by type (Malicious ->
  Supply-Chain/EOL -> Vulnerabilities -> Lifecycle -> Reputation info when
  present), severity-sorted within each group, and each vulnerability/EOL
  finding links to its source. A scan with zero findings still produces a clean
  "all clear" report only when scan coverage is healthy. SARIF, JUnit, and HTML
  artifacts include diagnostics for degraded feed status, local database
  staleness, and partial parse errors so artifact-only CI consumers can
  distinguish clean results from incomplete coverage. SARIF marks parser and
  operational scan failures as unsuccessful invocations with error-level
  notifications; JUnit reports them through errored diagnostic suites. SARIF
  finding results include a source artifact location pointing at the lockfile
  or explicit SBOM path that produced the package so GitHub Code Scanning can
  display the alert. Like the other file outputs, `--html` only works when
  scanning a single target.
- `--include-dev` includes dependencies marked as dev/test scope.
- `--no-repo-metadata` omits the optional repository name from remote
  `/api/v1/check` requests and webhooks. `PACKMON_NO_REPO_METADATA=true` and
  `.packmon.yaml` `send_repo_metadata: false` provide the same privacy opt-out.
- Unknown `--ecosystems` values are configuration errors, not empty successful
  scans. The same validation applies to `PACKMON_ECOSYSTEMS` and
  `.packmon.yaml` ecosystem filters.
- `--repo <name>` uses the same configured repository target for normal scans,
  `--list-packages`, `--outdated`, and `--list-all`. Inventory/reporting views
  that produce a single package table or report reject multi-target `--all`
  runs instead of silently choosing one target.
- `--list-all` keeps the findings scan scope identical to a normal scan:
  dev/test packages are checked only when `--include-dev` is set. Its package
  inventory section still lists every detected package by default and annotates
  source (`lockfile`, `sbom`, `dockerfile`, `compose`), scope (`runtime`,
  `dev`, `ci`, `sbom`, `build`), relation (`direct`, `transitive`,
  `workflow`, etc.), report-only technology tags (`angular` for Angular npm
  packages and `java` for Maven/Gradle rows), npm `via` roots, and
  optional/peer flags. HTML reports
  omit the noisy `Via` and `Flags` columns, keep full source paths out of
  package rows, and render a deduplicated "Checked Inventory Sources" section
  at the bottom for lockfiles, SBOMs, and Docker inventory files. The HTML
  "Packages Needing Attention" section lists actionable updates, current
  ReversingLabs malware/removed-package findings, lifecycle findings,
  vulnerability findings, and non-blocking historical ReversingLabs incident
  context as `LOW` `Reputation info`; unknown latest-status rows remain visible
  only in "All Packages". Finding-derived states such as `Malicious`, `Removed`,
  `Supply-chain risk`, `Lifecycle`, and `Reputation info` override general
  latest-version status. Vulnerability findings with a known fix or update path
  render as `Update available`; only vulnerability findings without a known
  update path render as `Vulnerable`, and a package with a security finding is
  never shown as merely `Up-to-Date`. Security finding advisories link to
  canonical external reports when available. Long digest values are shortened
  with `..` in the visible table and exposed through a local copy-to-clipboard
  control containing the full value. JSON, SARIF, and JUnit output flags still
  write the standard scan result when used with `--list-all`; `--html` writes
  the combined list-all HTML report. `--list-all-offline` preserves the
  findings scan and full package inventory but disables the external
  latest-version and Docker registry digest lookups for the inventory section;
  those rows are reported with unknown latest status.
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
  `GOWORK=off`; versioned Go module replacements are emitted under the
  replacement module path/version with original module metadata preserved as
  CycloneDX properties, while local-path replacements keep the original module
  identity and record the replacement path because they have no registry
  version. npm, PyPI, and Maven use CycloneDX generators. `--sbom-only`
  generates SBOM files without running a scan; `--keep-sbom <dir>` keeps
  generated files as timestamped snapshots so repeated runs do not overwrite
  previous SBOMs; `--install-tools` may install missing pinned generator tools
  where automatic installation is supported. Pinned generator versions are
  `cyclonedx-npm` 4.2.1, `cyclonedx-bom` 7.3.0, and
  `cyclonedx-maven-plugin` 2.9.1. Existing PATH tools for npm and PyPI are
  version-checked before use. Manifest reads, generator output capture, and
  generated-SBOM validation are size-bounded, and cleanup failures are returned
  as operational errors instead of being silently ignored. Generation runs local
  external toolchains and may cause those toolchains to contact package
  registries.
- config precedence is flags, environment, project `.packmon.yaml`, user-global
  `~/.packmon/config/packmon.yaml`, defaults for non-sensitive scan policy.
  Auto-discovered project config is untrusted for credential/server/webhook/DB
  routing and local write-destination fields (`server`, `api_key`,
  `api_key_env`, `cacert`, `insecure_allow_http`, `require_remote`, webhook
  URL/secret, `output.format`/`output.file`, and `db.path`); those values must
  come from flags, environment, user-global config, or an explicit `--config`.
  It may preserve `send_repo_metadata: false` as a privacy opt-out but cannot
  re-enable repository metadata disabled by a higher-precedence source.
  CLI errors for remote scans and local DB sync may show redacted server URL
  context only: scheme, host, and a generic path marker without userinfo,
  query, fragment, or full path. User-visible CLI error snippets are truncated
  at UTF-8 code point boundaries so non-ASCII server diagnostics are not
  corrupted.
- local history is stored compactly in SQLite for report/dashboard features and
  is enabled by default. It records repository name, branch, commit SHA when
  available, scan timestamp, package/finding counts, finding IDs, and finding
  severities. `PACKMON_HISTORY_ENABLED=false` disables recording and
  `PACKMON_HISTORY_MAX_SCANS_PER_REPO` controls per-repository retention
  (`100` by default, `0` disables retention cleanup). `packmon history clear`
  requires `--force` for unfiltered deletion; date-only `--before` cutoffs are
  interpreted as UTC dates and reported that way.
- stale local DB data produces warnings but does not block scans by itself.
- remote scans and webhooks send the repository name by default and never send
  branch or commit metadata. `--no-repo-metadata`,
  `PACKMON_NO_REPO_METADATA=true`, or `send_repo_metadata: false` omit even the
  repository name. Server scan logging persists only a bounded, path-minimized
  repository name when clients send one. Branch, commit, and User-Agent values
  are not retained in new scan-log rows.
- webhook envelopes include the canonical scan result and, when available, only
  the repository name. Branch and commit metadata are not forwarded to webhook
  receivers. Webhook delivery requires HTTPS except for loopback HTTP receivers
  used by local tooling.
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
  generated Go SBOM provides the selected module version. SwiftPM identities
  outside the canonical public-host format are treated as unknown instead of
  being passed to Git. Package-manager source provenance from npm
  `resolved` URLs, requirements index options, Cargo sources, Bundler remotes,
  CocoaPods spec repos, Composer `source`/`dist` URLs, renv source/repository
  fields, pub hosted URLs, and Maven repositories is retained only inside the
  local CLI. When that provenance points outside the ecosystem's public default
  registry, `--outdated` and the `--list-all` freshness phase return unknown
  latest status without querying the public registry for that package name.
  crates.io lookups use an identifying Packmon User-Agent and are serialized at
  one request per second.
- `--list-all` also inventories Docker image declarations from `Dockerfile`,
  `Dockerfile.*`, `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`,
  and `compose.yaml`. Docker rows use ecosystem `docker`, show declared
  tags/digests, record their package source as `dockerfile` or `compose`, and
  resolve public registry manifest digests best-effort for the built-in public
  registry allowlist. Unsupported registries, unsafe token realms, and
  loopback/private/link-local targets degrade to `unknown` without sending a
  registry request. `--list-all-offline` skips this registry digest phase. If
  the local Docker CLI can inspect the declared image, Packmon compares the
  local repo digest with the current registry digest and marks `UPDATE yes`,
  `-`, or `unknown`.
- Docker image inventory is not a container-layer vulnerability scan. Packmon
  does not pull images, scan OS packages inside images, or read private
  registry credentials as part of `--list-all`; `/api/v1/check` rejects
  `ecosystem: "docker"` packages for the same reason.

## Server Behavior

The server provides:

- `POST /api/v1/check` for package-list checks;
- `GET /api/v1/sync` for local SQLite sync;
- feed status and import endpoints;
- refresh queue endpoints;
- health, readiness, version, and metrics endpoints;
- public web dashboard/package search/feed status with primary navigation
  reachable at small/reflow viewport widths;
- admin UI for login, API keys, queue, feed config, advisories, settings, and
  audit log.

Production mode uses PostgreSQL. Development mode uses a local in-memory/noop
store to support fast local integration tests and UI development. Production
startup bounds schema-version and pool-connect checks with
`PACKMON_DB_CONNECT_TIMEOUT` (default `10s`) so unreachable databases fail fast
before HTTP listeners are created.

Server-side operational audit metadata is bounded by retention policy and by
input normalization at write time. Remote scan-log rows include scan ID,
optional bounded and path-minimized repository name, client IP,
package/finding counts, duration, decision evidence, correlation ID, a
`sha256:` digest of the canonical JSON `ScanResult` response, and authenticated
API key metadata when available. New scan-log rows do not retain
branch, commit, or User-Agent values. Admin-audit rows include action, details,
source IP, timestamp, previous-row digest, and row digest; login, lockout, and
logout details do not duplicate the source IP because the typed IP column is the
source of truth. New rows form a `sha256:` digest chain. The admin audit UI
pages through stored rows, keeps full detail JSON reachable from compact table
rows, and shows each row's local integrity status. PostgreSQL-backed privileged
admin writes that manage API
keys, queue state, admin passwords, and manual advisories commit the state
change and required audit row in one transaction. Destructive refresh-queue
clear/purge actions preserve the deleted job identities in audit details before
deleting rows, including job ID, package coordinate, source, priority, prior
status, timestamps, and redacted bounded error text. PostgreSQL maintains
cumulative scan package/finding totals in
`scan_log_totals`; `InsertScanLog` increments the rollup and scan-log pruning
subtracts deleted rows so `/metrics` does not aggregate the full `scan_log`
table on every scrape. The production background services prune `scan_log` rows after
`PACKMON_SCAN_LOG_RETENTION` (default `2160h`, 90 days) and `admin_audit_log`
rows after `PACKMON_ADMIN_AUDIT_LOG_RETENTION` (default `8760h`, 365 days).
Terminal refresh-queue rows (`done` and `error`) are pruned after
`PACKMON_REFRESH_QUEUE_RETENTION` (default `720h`, 30 days). The shared prune
cadence is `PACKMON_AUDIT_RETENTION_INTERVAL` (default `24h`).
Setting a dataset retention to `0` disables pruning for that table.

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
Affected-package rows use the canonical package identity rules from Supported
Ecosystems, so server, local SQLite, SBOM, and direct API scans match the same
package even when upstream feeds preserve case or punctuation variants.
Vulnerability upserts preserve `updated_at` when the effective advisory facts
are unchanged, and affected-package rows are merged per advisory instead of
being wholesale-replaced on every source import. Local sync clients can
therefore use `updated_at` as a meaningful delta boundary across repeated feed
imports and overlapping advisory sources.

Malicious findings are separate entities with stable IDs, package identity,
source, risk type, severity, optional OSV version ranges, optional exact
affected versions, summary, and description. OpenSSF/OSV range events such as
`introduced`, `fixed`, and `last_affected` are preserved so server and local
SQLite scans can match malicious findings by range instead of only by exact
listed versions. PostgreSQL validates malicious exact-version data at the
write boundary: empty, `null`, and JSON string arrays are accepted, while
objects, scalars, malformed JSON, and non-string arrays are rejected with the
finding ID before persistence.

Package reputation cache rows are version-specific normalized records from
demand-driven reputation sources. They store status, minimal evidence,
timestamps, and refresh scheduling data. `malicious` status produces a
malicious finding. `removed` status produces a blocking `supply_chain_risk`
finding with `risk_type=removed_package`. `risk` status represents
non-active supply-chain reputation evidence, such as ReversingLabs malware
incident history, and produces a non-blocking reputation-info finding with
`LOW` severity and `risk_type=malware_history`. `clean`, `not_found`,
`unsupported`, and transient `error` statuses do not produce findings. Package
detail views that are scoped
to an exact version must query these rows by exact package version; unversioned
package detail views may show all finding-producing reputation rows for the
package.

Socket.dev rows that represent malware stay `malicious`; Socket.dev
`supply_chain` and `typosquatting` risk types are exposed as blocking
`supply_chain_risk` findings even when stored in the shared malicious-finding
cache table. Socket package-check status stores only a normalized summary
(`status`, package version, issue counts, and aggregate score), not raw
Socket.dev response bodies or issue descriptions.

Lifecycle rows are normalized from product release metadata into package
ecosystem/name mappings and release cycles. Exact end-of-life matches produce a
blocking `supply_chain_risk` finding with `risk_type=eol`. Upcoming
end-of-life and security-support-only states produce `lifecycle` findings and
block only according to severity threshold. Unknown or unmapped lifecycle state
does not produce a finding.

Manual advisories are admin-managed records. They can represent either
vulnerability findings or malicious findings. New manual records without an
operator-supplied ID use stable `manual:<uuid>` IDs. The admin advisory list is
paginated so older manual coverage remains reachable. Manual advisory
create/update/delete operations write admin-audit records with the affected
record details; PostgreSQL commits the advisory mutation and audit entry in the
same transaction.

## Feed Sources

Core server-side vulnerability, malicious-package, and lifecycle coverage must
not depend on paid APIs or account-gated services. Server-side feed sources
include:

- OSV.dev public bulk data, including GitHub Actions advisories;
- GitHub Advisory Database;
- OpenSSF malicious packages;
- CISA KEV;
- EPSS. EPSS is the FIRST Exploit Prediction Scoring System, a third-party
  machine-learning/data-driven estimate of exploitation probability in the next
  30 days. Packmon stores and syncs the 0..1 score and percentile for triage
  and audit context, but default blocking decisions remain based on finding type
  and severity threshold. EPSS score payloads are complete snapshots:
  malformed, empty, or truncated score files fail closed, and successful
  snapshots atomically update current scores while clearing stale scores that
  disappeared from the payload. Successful self-sync status metadata preserves
  upstream model version and score date where the feed provides them;
- NVD CVE enrichment, optionally with an API key only for higher rate limits.
- endoflife.date public lifecycle metadata, with no API key.

Optional reputation/enrichment sources can be enabled by operators but are not
part of the required free core coverage:

- VulnCheck. When VulnCheck enrichment contributes CVSS or exploit metadata,
  scan findings, package detail views, and local sync payloads carry explicit
  VulnCheck resource attribution alongside the original advisory source;
- Socket.dev through async queue behavior;
- ReversingLabs Spectra Assure Community API as an optional server-side,
  demand-driven reputation source. Demand scheduling runs behind a feed-layer
  scheduler, requires a configured ReversingLabs API key, deduplicates package
  coordinates per check request, and caps newly scheduled lookups per request.
  Package coordinates must fit the documented API name/version limits and are
  percent-encoded as PURLs before outbound lookup. Operators can suppress
  private package namespaces before any external lookup.
  The server stores normalized package reputation cache rows and refreshes a
  package version at most once per 24 hours when it appears in a check request
  and no non-ReversingLabs feed already covers it. Non-finding cache rows are
  pruned by retention policy; active malware signals are reported as malicious
  findings, and historical malware incident evidence is reported separately as
  non-blocking `LOW` reputation info.

OSV/RustSec affected-package records with `database_specific.categories`
containing `malicious` are normalized as malicious package findings, not as
vulnerability findings. Vulnerabilities whose upstream source has no severity
or CVSS data are stored with a conservative `LOW` fallback until alias or NVD
enrichment can raise them. `UNKNOWN` vulnerability severity is not a final
user-facing state.

Feed sync can run inside the server or be supplied externally through N8N feed
import endpoints. Production feed imports require both the normal Bearer API
key and the dedicated `X-Packmon-Feed-Import-Secret` header configured through
`PACKMON_FEED_IMPORT_SECRET`; scan/sync API keys alone cannot mutate feed data.
The external feed-import endpoint is handled by a dedicated write-side API v1
component with its own store interface, separate from the scan/check handler.
PostgreSQL applies vulnerability and malicious feed import mutations and the
optional feed status row in one transaction, and successful imports write a
durable `feed_import` audit row with feed name, imported/deleted counts,
client IP, correlation ID, and API-key identity when available. Malicious feed
imports cannot persist malformed exact-version JSON; invalid rows fail the
transaction instead of becoming all-version blocking findings.
Feed failure must not delete existing good data. Check responses must indicate
degraded feed state when data is missing, skipped, or stale. In
`feed_sync_status`, `last_sync_at` represents the freshness of the last usable
feed data; sync attempts and running heartbeats use `updated_at` so a stuck
sync cannot make stale data appear fresh. `GET /api/v1/feeds/status` returns
a top-level `status` of `healthy` or `degraded` plus a message when feed status
rows are missing or any feed is degraded, while retaining the per-feed list for
automation. Per-feed status can be `configured` for intentionally external
feeds; configured external feeds are not active self-sync data sources and do
not degrade the aggregate status merely because they have zero self-sync rows.
Git-backed self-sync reads cloned advisory JSON through scoped repository roots
with a per-file size limit. GHSA delta sync treats a changed advisory as
removed only when the scoped read reports that the file no longer exists; other
read, parse, or import failures fail the sync attempt and preserve existing
records.

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
Queue workers are registered only when their self-managed feed has the required
API key. Worker job execution and stuck-job reset operations are deadline-bound.
Transient upstream rate limits leave claimed jobs for automatic retry via the
stuck-job reset path instead of completing them as terminal errors. Job
completion is claim-aware: a worker can complete only the processing claim it
originally dequeued, so stale workers cannot finish rows that were reset and
reclaimed. Workers return rate-limit tokens when no upstream request is made,
Socket.dev drains currently available tokens on each wake-up, and
ReversingLabs charges additional 413 fallback requests against the same local
token budget. Request-detached ReversingLabs scheduling is tied to the server
root context so shutdown cancels new background cache mutations.

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
statuses. The admin queue UI exposes status-filtered, paginated job lists so
older jobs remain reachable from the management surface. Paused jobs must not be
dequeued. Queue purge/clear audit details retain the affected job identities
before deletion so cleanup actions remain explainable after rows are gone.

## Local SQLite Mode

Local mode uses a compact SQLite database populated from `GET /api/v1/sync`.
It stores enough data for equivalent finding quality but not full server detail.

Remote and local modes should detect the same vulnerability, malicious, synced
reputation, and lifecycle findings when local data is fresh. Local SQLite sync
stores the source attribution for synced vulnerability and malicious findings
so local JSON, webhook, table, HTML, and summary artifacts can explain whether
a finding came from `manual`, `ghsa`, `osv`, `openssf`, `vulncheck`, or another
server source. Synced malicious exact-version data must be empty, `null`, or a
JSON array of strings; invalid local rows fail sync or lookup instead of being
treated as all-version malicious findings. It stores raw lifecycle status
booleans and dates, then computes current lifecycle findings at scan time.
Differences are allowed only in detail level and freshness.
Reputation sync includes active ReversingLabs `malicious` and `removed` rows
needed for local scan decisions plus non-blocking `risk` rows needed for local
reputation context. Synced `risk` rows are exposed as `LOW`
`malware_history` reputation info, not as their upstream severity, and benign
`clean`, `not_found`, `unsupported`, or transient `error` observations are not
synced.
Local scans query those reputation rows through explicit reputation lookup
methods; `FindMalicious` and `FindMaliciousBatch` remain malicious-package-only
boundaries so package detail views and scanner output do not double-count or
misclassify supply-chain reputation rows.
If a server response contains a `synced_at` timestamp beyond the allowed local
clock-skew tolerance, the client may use it for the current paginated request
sequence but does not persist it as the local freshness marker.

## Web UI

The web UI uses Go templates, Tailwind CSS v4, and htmx. Assets are local and
embedded into the binary. Tailwind v4 uses modern CSS features, so the UI
browser baseline follows Tailwind's v4 targets: Safari 16.4+, Chrome 111+, and
Firefox 128+. The UI should stay operational and utilitarian: dashboard,
package search, package details, scans, admin pages, and forms.
Admin pages share the same header and tab navigation partial. Client-side
behavior is loaded from local static JavaScript and CSS assets so the server
can keep a CSP without `unsafe-inline` for scripts or styles.
Operational diagnostics in feed-status, admin-feed, queue, and audit tables may
show compact previews, but the full redacted text must remain available through
keyboard-operable page content such as native `<details>` disclosures, not only
through hover-only `title` tooltips. Template text previews use UTF-8-safe
truncation so non-ASCII advisory, package, and diagnostic text is not split in
the middle of a code point; CLI/server response snippets follow the same
user-visible truncation rule.
Horizontally scrollable table regions in the web UI and generated HTML reports
must be keyboard-focusable, have an accessible name, and show a visible focus
indicator. Feed-status auto-refresh must preserve the horizontal scroll
position of refreshed table regions so operators can inspect right-side columns
without being reset to the first column on every htmx swap.
Meaningful status, helper, empty-state, and badge text must use contrast-safe
foreground tokens on white and gray-50 surfaces. Form-control borders must meet
the WCAG non-text contrast target, and focus indication must not depend solely
on Tailwind ring box-shadows; the custom stylesheet provides a forced-colors
outline fallback for links, buttons, form controls, summaries, and focusable
regions.
Current public and admin navigation items must expose the active page with
`aria-current="page"` in addition to visual styling.
HTMX-updated status, search, and feed-refresh regions must expose live-region
semantics and `aria-busy` while requests are in flight. User-triggered feed
sync success and error responses render durable status/alert fragments instead
of relying on transient button text. Filled admin action buttons and session
actions use the shared focus-ring token and touch-sized targets. Feed API-key
forms disclose third-party provider quota or billing implications at the point
where an operator stores a key.
Feed-status pages render their initial status tables server-side and use
event-driven htmx refreshes after the page is loaded, not a mandatory immediate
second request. Admin feed runtime partials must avoid full-page-only database
work such as editable config loading and dashboard aggregate queries.

Admin pages are protected by the shared admin session model described in
`SECURITY.md`: one shared admin identity, an `/admin`-scoped session cookie,
CSRF-protected write forms, an absolute session lifetime, a shorter inactivity
timeout, and login lockout that tracks both client IP and the shared admin
account. Failed current-password checks during admin password changes use the
same lockout window.

The admin UI exposes `/.well-known/change-password` as a redirect to the
password settings page so password managers can discover the password-change
entry point.

The shared web layout includes operator-facing notice links. `PACKMON_WEB_PRIVACY_URL`
defaults to the built-in `/privacy` page, which documents the admin session
cookie, CSRF use, admin audit metadata, and scan metadata at a high level.
`PACKMON_WEB_LEGAL_URL` is optional and can point to the deployment operator's
legal notice or Impressum.

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
- `PACKMON_WEB_PRIVACY_URL`;
- `PACKMON_WEB_LEGAL_URL`;
- `PACKMON_DB_*`;
- `PACKMON_ADMIN_INITIAL_PASSWORD`;
- `PACKMON_ADMIN_SESSION_TIMEOUT`;
- `PACKMON_ADMIN_IDLE_TIMEOUT`;
- `PACKMON_FEED_IMPORT_SECRET`;
- `PACKMON_FEED_ENDOFLIFE_ENABLED`;
- `PACKMON_FEED_ENDOFLIFE_MODE`;
- `PACKMON_ENDOFLIFE_API_BASE_URL`;
- feed API keys and feed mode/enabled flags.

Admin system settings can persist selected runtime values such as block
threshold and rate-limit settings. Saving a `NONE` block threshold through the
admin UI requires an explicit acknowledgement because it disables vulnerability
blocking. System-setting audit entries record previous and new block-threshold
and rate-limit values. Persisted values are loaded on server start.
Admin feed settings can persist enablement, mode, cadence, and feed API keys.
Production startup requires `PACKMON_ENCRYPTION_KEY` so persisted feed API keys
are encrypted at rest; development mode is the only plaintext fallback. Feed
setting audit entries record previous and new enablement, mode, cadence, and
whether an API key is configured, but never the raw API key. Feed setting changes
are applied to the running process immediately and are also loaded on future
server starts. HTTP route wiring and API handlers read mutable runtime feed
state through `FeedsSnapshot()` so admin hot-reload writes cannot race with
ReversingLabs scheduling or feed-import-secret decisions.

Production PostgreSQL connections default to `sslmode=verify-full` so the
client verifies both transport encryption and database server identity. Local
development and the repository Compose example may explicitly override
`PACKMON_DB_SSLMODE=disable` for the bundled single-host database, but shared
deployments are expected to keep certificate-verifying database TLS.

Trusted CLI configuration may reference API keys via `api_key_env` so config
files do not need plaintext secrets. Auto-discovered project `.packmon.yaml`
files cannot select API-key environment variables or override the Packmon
server/local DB path. Environment variables and flags still take precedence over
project and user-global config.

API keys are named with a bounded operator label, hashed at rest, track
`last_used_at`, support revocation, soft-delete after revocation, and require an
RFC3339 UTC `expires_at` value no more than 90 days in the future. Creating a
key in the admin UI requires current-password step-up verification before the
secret is generated. Revoked, soft-deleted, or expired keys are not accepted by
production `/api/v1/*` authentication. Soft-deleted rows retain created,
expiration, last-used, revocation, and deletion timestamps for auditability.

## CI/CD Integration

Packmon supports:

- GitHub Actions workflows;
- a GitLab shared CI template under `ci/gitlab`;
- SARIF upload;
- JUnit report files;
- JSON result artifacts;
- GitHub artifact attestations for release binaries and reusable-workflow scan
  result artifacts;
- CycloneDX SBOM and license/notice artifacts for Packmon binary releases;
- GitLab Sigstore/Cosign bundles for retained scan-result checksum manifests;
- optional opt-in PR comments;
- optional webhook delivery.

Reusable CI templates parse `feed_status`, `db_stale`, and `db_age_days` from
the JSON result artifact and surface degraded coverage independently from
finding count or exit-code mapping. GitHub writes an Actions warning, step
summary, and PR-comment coverage warning when comments are enabled. GitLab
writes the same state into the job log.

The GitLab template is locally validated by `tests/ci`. A real GitLab runner
validation remains externally dependent on a GitLab project and registered
runner.

## Monitoring and Operations

The metrics endpoint emits Prometheus text metrics for:

- HTTP request count and duration;
- packages scanned and scan findings from the maintained scan-log rollup;
- current finding totals for vulnerability, malicious, supply-chain-risk, and
  lifecycle finding types plus current severity totals from vulnerability,
  malicious, and reputation-backed findings;
- feed last sync and age;
- feed timeouts;
- queue size, oldest job, errors, and recovered stuck jobs;
- DB pool state;
- migration version;
- auth login failures and degraded responses.

Metrics bind to `127.0.0.1` by default.

Dedicated rate-limit rejection logs are debug-level; the request-completion log
is the warning-level per-request 429 signal. Refresh-queue workers suppress
repeated dequeue/reset database errors inside a short window so a database
outage does not create an unbounded worker log storm. HTTP shutdown logs include
the concrete shutdown error string when a listener fails to stop cleanly.
Request-path log fields use low-cardinality route labels such as
`/api/v1/packages/{ecosystem}/{name...}` or `(unmatched-route)` instead of raw
URL paths, so unauthenticated clients cannot persist arbitrary path text in
server logs.
API v1 handler-level operational warning and error logs include the request
correlation ID, and request-body JSON decode diagnostics are logged and returned
as bounded categories rather than attacker-sized decoder text.
Feed syncers sanitize git subprocess diagnostics, filesystem walker errors, and
persisted `feed_sync_status.last_error` values through the shared diagnostic
redaction path; git-backed feed helpers capture child output instead of wiring
it directly to process stderr.

Backups are intentionally simple: periodic `pg_dump`, seven-day local
retention, and storage outside the application data path. External backup
systems are responsible for off-host retention.

## Test and Quality Requirements

Normal local gate:

```bash
mkdir -p .gotmp
export GOTMPDIR="$PWD/.gotmp"
PACKAGES="$(go list ./...)"
GOSEC_DIRS="$(go list -f '{{.Dir}}' ./...)"
GOFMT_FILES="$(git ls-files '*.go')"
gofumpt -extra -l ${GOFMT_FILES}
go test -count=1 ./...
go test -race -count=1 -coverprofile=coverage.out ${PACKAGES}
go run ./tools/checkcoverage -profile=coverage.out -min=79.5
go vet ./...
golangci-lint run ./...
govulncheck ${PACKAGES}
gosec -nosec-require-rules -nosec-require-justification ${GOSEC_DIRS}
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
- JSON, SARIF, JUnit, checksum, and Sigstore bundle artifacts visible in GitLab.
