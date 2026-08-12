# Packmon Security Model

This document is the canonical security baseline for Packmon. Use it for
security reviews and audits. If implementation and this document drift, either
fix the code or update this file in the same change with a clear rationale.
Contributor secure-coding and security-awareness expectations are documented in
`docs/secure-coding.md`.
Risk treatment decisions are tracked in `docs/risk-register.md`; supplier and
feed-provider security assumptions are tracked in `docs/supplier-security.md`.

## Security Goals

- Prevent unauthorized writes to feed data, admin settings, queue state, API
  keys, and manual advisories.
- Prevent accidental public exposure of internal APIs and metrics.
- Preserve integrity of vulnerability, malicious package, and lifecycle data.
- Avoid leaking secrets, repository paths, file contents, or environment values.
- Provide trustworthy CI outputs for dependency security decisions.
- Keep local developer use safe even when remote services are unavailable.

## Reporting a Vulnerability

Do not file public issues, pull requests, discussions, chat messages, or logs
with exploit details, private package names, credentials, internal URLs, or
personal data.

Use GitHub Private Vulnerability Reporting for this repository when it is
available.

Packmon does not publish or maintain a universal fallback mailbox, form URL,
PGP key, or encrypted reporting destination in this repository. That is an
intentional boundary: private forks, mirrors, packaged distributions, and
internal deployments are operated by their owning organization, and that owner
must provide any deployment-specific confidential reporting contact through its
own disclosure process. If GitHub Private Vulnerability Reporting is unavailable
in the deployment or mirror you use, contact the repository owner or
distributing organization through its own private security contact and reference
this policy.

Packmon web deployments serve `/.well-known/security.txt` with the repository
private-reporting and policy URLs for automated discovery. Deployments that need
a concrete fallback contact should publish that contact in their own wrapper
documentation, hosting metadata, or organization-level security policy.

Include:

- affected Packmon version, release artifact, commit, or container image digest;
- affected deployment mode and relevant configuration names, without secret
  values;
- reproducible steps or a minimal proof of concept;
- expected and observed impact;
- whether exploitation is known or suspected;
- a private contact for follow-up.

Expected handling:

- maintainers acknowledge good-faith reports within two business days;
- critical or actively exploited reports are triaged as soon as possible, with a
  same-business-day target;
- reporters receive status updates when remediation or disclosure timing
  changes;
- public disclosure is coordinated only after a fix, mitigation, or explicit
  maintainer decision.

Cyber Resilience Act and similar regulatory incident reporting remains the
responsibility of the product owner or distributor that makes Packmon available
as a product with digital elements. Where applicable, that owner coordinates
the early warning within 24 hours, the vulnerability or incident notification
within 72 hours, and the final report after remediation, using the technical
triage information from this process.

Good-faith research that follows this policy, avoids privacy violations,
avoids service disruption, and does not exfiltrate data will not be treated by
the project maintainers as a reason for retaliation. This statement is not a
license to access third-party systems or data.

## Triage and Disclosure

Maintainers classify confirmed vulnerabilities with CVSS when enough technical
detail is available, plus product-specific factors such as deployment exposure,
default configuration, authentication requirements, data sensitivity, and
whether a supported Packmon version or release artifact is affected.

Confirmed vulnerabilities that affect supported releases are tracked in a
private advisory during remediation. Maintainers request or attach a CVE or
GitHub Security Advisory when the issue is externally relevant, affects a
distributed release, or downstream operators need a stable advisory ID for
patch intake.

Embargoes are used only to coordinate a fix, mitigation, or operator guidance.
The advisory should include affected versions or image digests, severity,
impact, fixed version, mitigation, required operator action, and reporter credit
when the reporter wants attribution. If public attribution is not desired,
reporter credit is omitted from the advisory and release notes.

## Supported Versions

Security fixes are provided for the latest released Packmon version and the
current `main` branch. Older release lines, forks, modified builds, and
pre-release artifacts are unsupported unless a written support agreement names
them explicitly. Support for a released version ends when a newer security
release is published or 12 months after that release date, whichever comes
first.

Operators should upgrade to the latest security release before requesting
backports. If a fix cannot be backported safely, the supported remediation is
to upgrade.

## Remediation Targets and Security Updates

Maintainers assign severity during triage from exploitability, data exposure,
integrity impact, required privileges, operational mitigations, and whether a
supported Packmon version is affected. Remediation targets are measured from
maintainer validation of an affected supported version.

- Critical or active exploitation: fix or mitigation within 7 calendar days.
- High severity: fix or mitigation within 14 calendar days.
- Medium severity: fix or mitigation within 30 calendar days.
- Low severity: fix, mitigation, or accepted-risk note within 90 calendar days.

Targets are not disclosure promises. Coordinated disclosure, upstream
dependency fixes, or unsafe backport risk may change the release date, but the
private advisory or release notes must record the operator action and current
remediation status.

GitHub Security Advisories, private advisories during embargoed coordination,
and release notes are the security update channel. Public release notes should
identify affected supported versions, the fixed version or image digest,
public CVE/GHSA IDs when available, required operator action, and any temporary
mitigation. Operators should watch repository releases. Operators should
subscribe to repository security advisories and route those notifications into
their internal patch intake for Packmon deployments and mirrors.

## Trust Boundaries

Primary trust boundaries:

- developer workstation filesystem to CLI;
- CLI to Packmon server over HTTP(S);
- CI runner to Packmon server;
- N8N to Packmon server feed import endpoints;
- server to PostgreSQL;
- server to external feeds;
- admin browser to admin UI;
- metrics scraper to metrics endpoint.

The server must never assume arbitrary clients are trusted merely because the
network is internal. Internal network placement is one layer, not the only
control.

## Storage Data Classes

`docs/data-classification.md` maps Packmon data classes across PostgreSQL,
local SQLite, logs, metrics, and web/admin surfaces. Treat that map as the
operator-facing companion to this security model when adding tables, changing
retention, exposing new fields, or answering privacy questions.

High-level rules:

- plaintext API keys are shown only once and are never stored;
- feed provider API keys are encrypted at rest with
  `PACKMON_ENCRYPTION_KEY`;
- local SQLite stores a compact sync/history subset, not full server feed data;
- server logs and metrics must not contain secrets, raw file contents, full
  environment values, or full local paths.

## Public and Protected Endpoints

Allowed without API key:

- `/healthz`;
- `/readyz`;
- `/version`;
- `/metrics`;
- public web dashboard/search pages as implemented for internal viewing.

Protected surfaces:

- `/api/v1/*` in production mode;
- feed import endpoints;
- package refresh trigger endpoints;
- admin pages and admin write actions;
- API key creation/revocation/deletion;
- manual advisory creation/update/delete;
- queue mutation;
- system settings mutation.

Development mode may bypass selected auth behavior to support local tests. Do
not copy development-mode assumptions into production.

## API Authentication

API clients use bearer tokens:

```text
Authorization: Bearer <api-key>
```

Production feed imports are a separate write boundary. `POST
/api/v1/feeds/{feed}/import` requires the Bearer API key and the dedicated
`X-Packmon-Feed-Import-Secret` header configured through
`PACKMON_FEED_IMPORT_SECRET`. A scan or sync API key by itself must not be
enough to create, update, or delete feed data. Vulnerability and malicious feed
imports must commit feed-data mutations and the optional feed status row
atomically in PostgreSQL, and successful imports must write a durable
`feed_import` audit row containing the feed, counts, client IP, correlation ID,
and API-key identity when available.
Rejected imports are security-relevant events. They must preserve bounded,
log-safe diagnostics for the feed, rejection reason class, rejected-record
count, correlation ID, trusted client IP, and authenticated API-key identity
when available. The admin/web UI and feed-status API must surface rejected
imports, the last successful usable import timestamp, and source-level finding
or blocking spikes so operators can distinguish strict validation from hidden
coverage loss in server/agent deployments.

API keys are stored hashed. Plaintext keys are shown only at creation time.
Keys have bounded labels/names for auditability, record `last_used_at`, must
have an RFC3339 UTC `expires_at` timestamp no more than 90 days in the future,
may be revoked, and may be permanently deleted after revocation; the delete
action stays recorded in the admin audit log, and scan history keeps its rows
with the key reference cleared. Creating a new API key from the admin
UI requires current admin password step-up verification; failed step-up attempts
are audit logged.
Expired keys must be treated the same as missing or revoked keys
by API authentication.
API-key authentication failures are security-relevant and must be visible at
the default log level with a bounded reason class, trusted client IP,
correlation ID, and log-safe route label. These logs must never include bearer
tokens or plaintext API keys.
Legacy rows from before API-key expiration support may have `expires_at = NULL`.
Those keys intentionally have no expiration timestamp and therefore do not
expire automatically. Operators must rotate or revoke them manually. New keys
created through the admin UI remain required to have a bounded expiration.
The API-key authentication middleware depends only on API-key lookup and
last-used update methods, not on the full database store surface.

Expected clients include:

- Packmon CLI;
- CI jobs;
- N8N workflows;
- controlled internal automation.

User-Agent validation is a hygiene control, not a primary auth control. It
helps reject accidental or malformed traffic but must not replace API keys.

Client key handling:

- use a separate named key per client class or runner group;
- store keys in CI secrets, OS secret stores, or environment variables;
- reference keys from trusted user-global or explicit config files with
  `api_key_env` rather than plaintext `api_key` values;
- the `--api-key` and `--webhook-secret` CLI flags reject secret values by
  default because argv leaks into shell history and process listings;
  `PACKMON_ALLOW_SECRET_FLAGS=true` is the deliberate opt-out for isolated
  test environments and must not be set on shared or CI machines;
- treat auto-discovered project `.packmon.yaml` as repository input; it must not
  choose API-key environment variables, Packmon server URLs, TLS trust settings,
  webhook URLs/secrets, report output paths, local advisory database paths, or
  latest-version registry mirror URLs;
- rotate keys before their required expiration;
- review `last_used_at` before revoking stale keys.

## Admin Authentication

Packmon intentionally has one shared admin identity, not per-user accounts.

### Privileged Admin Access Compensating Control

Packmon does not implement built-in MFA, per-user admin accounts, SSO, TOTP, or
WebAuthn. Regulated or shared production deployments that require privileged
access assurance must place the `/admin` surface behind a trusted reverse proxy or identity provider
that enforces multi-factor authentication or SSO before traffic reaches Packmon.
Keep Packmon's own one shared admin identity and
current-password step-up controls enabled behind that boundary, and restrict
direct network access to the Packmon listener so administrators cannot bypass
the external control.

Admin properties:

- bootstrap password comes from `PACKMON_ADMIN_INITIAL_PASSWORD` only when no
  admin hash exists yet;
- bootstrap and rotated admin passwords must be at least 12 characters long;
- password is stored as a bcrypt hash;
- existing admin hash takes precedence over bootstrap env;
- sessions authenticated with the bootstrap password may only rotate that
  password; API-key, feed, queue, advisory, and system-setting writes are
  blocked until `password_is_bootstrap` is cleared by a password change;
- login form uses standard username/password fields and browser/vault-friendly
  autocomplete attributes;
- sessions use cookies scoped to `/admin` with HttpOnly and SameSite behavior,
  `Secure` where required, an absolute lifetime, and a server-side inactivity
  timeout;
- the shared web footer links a privacy notice by default; operators can replace
  it with `PACKMON_WEB_PRIVACY_URL` and can add an Impressum/legal notice with
  `PACKMON_WEB_LEGAL_URL`;
- the shared web footer links terms of use by default through
  `PACKMON_WEB_TERMS_URL=/terms`; operators can replace that URL with their own
  AGB or internal-use terms;
- admin write forms require CSRF validation, and invalid CSRF submissions on
  admin mutation routes must emit a structured warning plus an
  `admin_csrf_rejected` audit row with the target action and trusted client IP
  but no form values or secrets;
- failed logins are rate limited by client IP and the shared admin account,
  failed current-password checks on the password-change form use the same
  lockout window, stale partial failures expire, lockout audit events are
  deduplicated per lockout window, and failed as well as locked-out attempts are
  counted in metrics;
- security-sensitive admin writes must fail or roll back when the required
  admin audit row cannot be persisted. PostgreSQL commits API-key lifecycle
  changes, queue mutations, password changes, and manual advisory writes
  atomically with their audit rows. Password changes use a compare-and-swap
  predicate against the previously verified bcrypt hash, and admin-auth/audit
  mutations acquire locks in `admin_auth` then `admin_audit_log` order.
  Refresh-queue clear/purge audit rows must
  preserve an affected-job sample with job IDs, package coordinates, sources,
  priorities, prior statuses, timestamps, redacted bounded error text, and
  total/sample/truncation metadata from the same delete operation;
- new production admin audit rows carry an `hmac-sha256:` previous-row digest
  chain keyed by `PACKMON_ADMIN_AUDIT_HMAC_KEY`; older `sha256:` rows remain
  verifiable as legacy digest-chain rows, and the admin audit UI surfaces local
  row integrity status. System and feed configuration audits include
  previous/new values, but feed API keys are represented only as
  configured/not-configured booleans.

Admin features must not introduce multi-user assumptions without updating this
document and the design.
Runtime feed configuration is lock-protected mutable state. HTTP route wiring
and API handlers must consume it through `FeedsSnapshot()` so admin feed saves
cannot race with request-time ReversingLabs scheduling or feed import
authorization checks.
Admin HTTP handlers and admin bootstrap code depend on focused, consumer-owned
store interfaces for the admin data they mutate or audit, rather than the full
database store interface.

## Authorization Rules

Admins may:

- manage API keys;
- manage manual advisories;
- change feed settings;
- mutate queue state;
- update system settings;
- view paginated admin audit data, including full per-row detail JSON.

API clients may:

- check package lists;
- sync local databases where permitted;
- import feed data if configured and authenticated;
- trigger package refreshes according to rate limits and auth policy.

Public unauthenticated users may not mutate server state.

## Reverse Proxy and Client IP Handling

`X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Real-IP` are trusted only when
the direct peer is configured in `PACKMON_TRUSTED_PROXIES`.

If a proxy is not trusted:

- forwarded IP headers are ignored;
- direct peer address is used for rate limiting and audit;
- host/proto behavior must not trust attacker-supplied headers.

HTTPS redirect behavior must use configured public host data, not arbitrary
request `Host` values.

Production startup must fail unless transport security is configured through
in-app TLS or a trusted TLS-terminating reverse proxy. The only exception is
`PACKMON_ALLOW_INSECURE_LOCAL_HTTP=true`, which is reserved for local Docker
use with a loopback `PACKMON_SERVER_PUBLIC_HOST`. When it is the active
transport path, the main listener binds to `127.0.0.1` by default; Docker
deployments that rely on host-loopback port publishing must explicitly set
`PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE=container`. Trusted proxy entries must
be valid IP addresses or CIDR prefixes. Do not enable the local HTTP override
on shared hosts or network-exposed deployments. When this local-only override
is active, admin session cookies intentionally omit the `Secure` flag so login
works over `http://localhost`; all non-override production deployments must
keep `Secure` session cookies.

## Browser Security Headers

All server-rendered web pages are served with a restrictive Content Security
Policy using local assets only. Script and style policies must stay at
`script-src 'self'` and `style-src 'self'`; admin interactivity belongs in
local static JavaScript and CSS assets, not inline event handlers, inline
scripts, inline styles, or htmx inline evaluation.

## Request Limits

Production API behavior must enforce:

- maximum package count per check request;
- global per-IP rate limiting;
- login-specific rate limiting;
- bounded request body parsing;
- server timeouts for read, write, and shutdown.

Limits are configuration-driven, and selected values may be persisted through
admin system settings.

## Feed Data Integrity

Feed syncers and imports must:

- normalize ecosystem names at import boundaries;
- normalize package identities at scan, feed, sync, and storage boundaries for
  ecosystems with case-insensitive registry names. NuGet names are lowercased;
  PyPI names use PEP 503 normalization (`.`, `_`, and `-` runs collapse to
  `-`); GitHub Actions `owner/repo` identifiers are lowercased;
- evaluate NuGet prerelease version labels case-insensitively in both
  ecosystem ranges and explicit affected-version lists;
- preserve source identity and freshness;
- keep feed freshness separate from sync-attempt heartbeats. `last_sync_at`
  must represent the last usable feed data timestamp, while `updated_at` may
  move for running attempts or status changes;
- preserve malicious-package semantics when an advisory feed exposes them as
  category metadata rather than severity data;
- preserve malicious-package version constraints as OSV ranges and exact
  affected-version lists instead of collapsing ranges to introduced versions;
- reject unsupported stored severity values at the database write boundary.
  Vulnerability severities are persisted only as `CRITICAL`, `HIGH`, `MEDIUM`,
  or `LOW`; missing or upstream-unknown vulnerability severity is normalized to
  `LOW` until enrichment can raise it. Malicious findings may additionally keep
  `UNKNOWN` when the source truly cannot classify severity. Unsupported
  reputation severity is rejected or normalized to blocking-safe defaults;
- reject malicious exact-version payloads at the PostgreSQL write boundary
  unless they are empty, `null`, or JSON arrays of strings;
- expose strict import rejection state through UI/API diagnostics instead of
  relying only on server logs;
- not delete existing good data on failed sync;
- mark feed status as skipped/error/degraded when data is unavailable;
- handle rate limits and timeouts without corrupting stored data;
- write enrichment-derived vulnerability fields and their provenance/source rows
  atomically, so a failed provenance write cannot leave unattributed scan data;
- expose VulnCheck enrichment provenance as user-facing VulnCheck resource
  attribution in scan findings and sync payloads when VulnCheck data changes
  CVSS or exploit metadata;
- prevent path traversal when reading files from cloned feed repositories;
- size-bound advisory JSON reads from cloned feed repositories before parsing;
- avoid shell or option injection when invoking `git`. Git repository
  arguments derived from lockfiles must be validated and passed after `--`;
- avoid trusting raw feed JSON beyond parser validation.

GHSA and malicious package git repositories are external input. Treat changed
file paths from git as untrusted until scoped under the repository root. GHSA
delta sync may tombstone a changed advisory only when the scoped read proves the
file no longer exists; other read errors must fail the sync attempt without
deleting existing data.

ReversingLabs API tokens are sensitive feed API keys and follow the same
handling rules as VulnCheck, NVD, and Socket.dev keys. Packmon stores only
normalized ReversingLabs status and minimal evidence, not full raw reports.
Historical ReversingLabs incident evidence is exposed as non-blocking
`LOW` reputation info, not as an active malicious-package finding unless
active malware signals are present.
Demand-driven ReversingLabs scheduling requires a configured API key, applies
per-request admission limits, deduplicates package coordinates, and supports
operator-configured private namespace exclusions before package coordinates are
sent to the external service. Coordinates are length-bounded before reputation
cache writes and percent-encoded before PURL lookup. Non-finding ReversingLabs
cache rows are pruned by retention policy so clean/unsupported/error rows do
not become a permanent server-side package inventory.
ReversingLabs rate-limit, capacity, and network failures degrade that source
but must not fail scans or delete existing cached blocking data.

Socket.dev status persistence stores normalized check summaries rather than raw
provider response bodies. Socket.dev package-check status rows are pruned by
retention policy so checked package coordinates do not become a permanent
server-side package inventory. Operator-configured Socket.dev private namespace
exclusions are enforced before manual refresh enqueue and again in the worker
before any upstream request, so matching private package coordinates do not
leave the deployment through Socket.dev. Socket.dev malware/protestware signals
remain malicious findings; Socket.dev supply-chain and typosquatting signals
are reported as blocking supply-chain-risk findings.

Self-managed feed URLs and optional enrichment API URLs for OSV, GHSA,
OpenSSF, CISA KEV, EPSS, NVD, endoflife.date, VulnCheck, and Socket.dev must
be absolute HTTPS URLs unless they are loopback HTTP endpoints used for local
tests. Operators may point these controls at internal mirrors or approved
relays, but the mirrored content remains external input and must still pass the
same parser, size, and normalization checks.

VulnCheck backup-link responses are external input. Absolute backup download
URLs returned by the feed must use the same HTTP scheme as the configured
VulnCheck base URL and must not target credentials, localhost, private,
link-local, multicast, unspecified, single-label, or local/internal hosts.
Cross-origin backup URLs may use only default ports and documented S3 backup
hostnames. Redirect targets are checked with the same policy. The advertised
backup SHA-256 digest is required and must match the downloaded bytes before
any backup content is parsed or imported. Streaming backup parsers must consume
the complete top-level JSON payload and reject truncated or trailing data.
Backup download errors must be redacted before they are logged or stored so
signed URL query parameters are not persisted.

Feed status surfaces must treat durable non-success status values as degraded
unless they are explicitly known disabled/running/external states. User-visible
feed status messages are diagnostic summaries only: API, public web, and admin
templates must redact URLs, credentials, bearer tokens, and local paths before
rendering `last_error`.
Post-feed alias severity propagation is part of feed health: failures are
recorded under `alias-severity-propagation` so scans and status views degrade
instead of silently continuing with stale `UNKNOWN` severity rows.

endoflife.date lifecycle metadata is external feed input. Packmon fetches it
server-side, validates and normalizes product/release data, and exposes only
normalized lifecycle rows and findings to scan clients. Raw endoflife.date JSON
is not exposed through scan results. The feed requires no API key, and upstream
rate limits, 304 responses, network failures, or schema parse failures must
degrade feed status without deleting existing cached lifecycle data.

Docker image freshness checks are metadata-only client behavior. The CLI may
execute `docker image inspect` with fixed argv to read local image metadata
when Docker is installed, but it must not execute compose files, build images,
pull images, or log full local Docker errors. Registry checks use public
manifest metadata requests and bearer-token challenges only for the built-in
public registry allowlist by default. Trusted operator config may map supported
public registry hosts to explicit Docker registry mirrors with
`PACKMON_DOCKER_REGISTRY_MIRRORS` or `registries.docker_registry_mirrors`; this
does not let repository-controlled image references add arbitrary registry
targets. Public-registry hosts, bearer-token realms, and resolved addresses are
rejected when they target unsupported hosts, plain HTTP without an explicit
insecure test override, loopback, link-local, private, multicast, or
unspecified addresses. Configured mirror URLs must not contain credentials,
queries, or fragments; HTTPS is required except loopback HTTP test endpoints,
and literal link-local, multicast, or unspecified mirror addresses are rejected.
Private registry credentials are not read. Failures degrade to `unknown` in
reports. The server scan API rejects Docker packages because Packmon does not
provide container-layer vulnerability coverage.
The local Docker inspector abstraction accepts only image references; the
executable and `image inspect` subcommand remain fixed in production code.
CLI ecosystem filters are validated before package discovery so a typo cannot
turn all parser-backed ecosystems off and produce a successful zero-package
security scan; `docker` remains a `--list-all` inventory filter only.

npm transitive update checks may fetch public npm package manifests for
immediate parent packages and child version lists to compute the highest
version allowed by declared parent dependency ranges. This metadata is used
only for report status; private registry credentials are not read, and lookup
failures fall back to normal best-effort latest-version handling.

Vulnerability advisories without upstream severity or CVSS data are treated as
`LOW` until enrichment can raise them. Malicious-package categories from
OSV/RustSec are stored as malicious findings rather than unresolved
vulnerabilities.

## Manual Advisories

Manual advisories are operator-controlled emergency or gap coverage records.
They can represent:

- vulnerability findings;
- malicious package findings.

Security requirements:

- manual IDs generated by Packmon use `manual:<uuid>`;
- operator-supplied IDs must not collide silently with unrelated feed records;
- creating a manual advisory defaults to a vulnerability finding unless an
  operator explicitly selects malicious;
- manual malicious findings block immediately;
- manual vulnerability findings follow the configured vulnerability threshold;
- admin create/update/delete actions are audit logged with record details, and
  PostgreSQL commits the manual advisory mutation and audit row atomically;
- deleting a manual advisory requires an explicit destructive confirmation in
  the admin UI;
- deleting a manual advisory must not delete feed-sourced advisories.

## Scan Result Trust

The canonical scan result is shared by:

- CLI JSON output;
- `POST /api/v1/check` response;
- webhook result object.

Downstream tools should trust `findings_blocking`, `block_threshold`, exit code,
and finding type semantics only if the result was produced by a verified
Packmon binary/server.

Malicious and active supply-chain risk findings always block. Historical
ReversingLabs malware-incident evidence is `LOW` reputation info and does not
block by itself. Vulnerability and `lifecycle` findings block according to the
configured threshold. Exact EOL matches from lifecycle data are represented as
blocking `supply_chain_risk` findings, while upcoming EOL and
security-support-only states remain severity-gated `lifecycle` findings.
`NONE` disables vulnerability blocking only; admin UI saves of `NONE` require
explicit acknowledgement.

`ScanResult.feed_status` is machine-readable (`healthy`, `degraded`, or
`error`). Parser and operational failure details belong in optional
`scan_error`, while per-file partial inventory details stay in `parse_errors`;
do not put free-form operational text back into `feed_status`.
Feed-degraded responses must be visible so CI/N8N can make policy decisions.
SARIF, JUnit, and HTML artifacts must carry degraded-feed, stale-local-DB, and
parse-error diagnostics instead of presenting incomplete coverage as a clean
scan. Partial lockfile/SBOM parse errors exit with parser failure unless a
blocking finding has already failed the scan, and in-scope discovery filesystem
errors are reported as operational failures rather than silently reducing
inventory. SARIF must mark parser and operational scan failures as unsuccessful
invocations with error-level notifications; JUnit must expose the same state as
errored diagnostic suites.

## Webhooks

Webhook delivery is best effort.

Webhook envelopes include the canonical scan result and, unless repo metadata is
disabled, a minimized repository object containing only the repository name when
available. Branch and commit metadata are not forwarded to webhook receivers.

Webhook destinations are trusted operator configuration. Auto-discovered
project `.packmon.yaml` files cannot set webhook URL or secret values. Webhook
delivery requires HTTPS except for loopback HTTP receivers used by local
tooling.

If a webhook secret is configured:

- authenticate payloads with `X-Packmon-Signature: sha256=<hmac>`;
- compute the HMAC-SHA256 message authentication code over the payload body.

This header is shared-secret webhook authentication. It is not an asymmetric
electronic signature, seal, or non-repudiation mechanism because either party
that knows the webhook secret can generate the header value.

If no secret is configured:

- do not send a fake signature header.

Replay protection is intentionally not part of the current design because
Packmon is internal tooling. Reconsider this if webhooks ever cross untrusted
network boundaries.

## Logging and Privacy

Never log:

- API keys;
- passwords;
- full environment variable values;
- file contents;
- full repository paths in persistent server logs;
- raw lockfile contents;
- raw webhook or automation callback URLs;
- sensitive feed API keys.

Parser errors that flow into stderr, JSON, SARIF, JUnit, HTML, webhooks, or
logs may include parser/file names, line numbers, entry indexes, and generic
reasons, but must not echo raw dependency-file snippets, private dependency
coordinates, source URLs, or tokens from malformed entries.
Repository-controlled lockfiles, explicit SBOMs, Dockerfiles, and Compose files
must be size-bounded before expensive parsing so malformed inventory cannot
force unbounded memory or CPU use in developer machines or CI runners.

Allowed:

- ecosystem names;
- package names and versions;
- advisory IDs;
- scan IDs;
- correlation IDs;
- filenames without full path;
- redacted webhook/server URLs that keep only scheme, host, and a generic path
  marker;
- aggregate counts and durations.

Full local paths may appear only in local debug output where explicitly
intended. Server logs must stay path-minimized. Routine request-completion logs
must not include client identifiers such as client IP address or User-Agent.
CLI stderr and scan-result diagnostics for remote scans and local DB sync must
not echo raw `PACKMON_SERVER` or `--server` values; URL-related errors may keep
only a redacted scheme/host/path-marker form and must drop userinfo, query,
fragment, and full path details.
Request-derived log fields such as User-Agent values must be
control-character-normalized, length-bounded, and secret-redacted before they
reach persistent server logs. URL path fields must be converted to route labels
such as `/api/v1/packages/{ecosystem}/{name...}`, `/static/...`, or
`(unmatched-route)` and must not echo dynamic path segments. Security-relevant
rejection logs may include the trusted-proxy-aware `client_ip` value resolved
for the request, but must not log the direct proxy socket address.
API v1 handler-level operational warning and error logs must include the
request correlation ID. JSON request-body decode failures must use bounded,
sanitized error categories in logs and client responses rather than raw decoder
strings that may contain attacker-controlled field names.
Feed-sync diagnostics, including git subprocess stderr/stdout and filesystem
walker errors, must pass through the same diagnostic redaction before they reach
structured logs or `feed_sync_status.last_error`. Git-backed feed helpers must
not stream child-process output directly to process stderr.

The built-in `/privacy` page is a deployment-neutral disclosure for the
first-party admin session cookie and routine Packmon audit/scan metadata. It is
not a substitute for an operator-specific legal notice; production deployments
that need one should set `PACKMON_WEB_LEGAL_URL`.
The page must carry a last-updated date, operator-controlled controller/contact
placeholder, legal-basis guidance, data categories/sources/purposes, retention
mapping, GDPR-style data-subject rights, supervisory-authority complaint rights,
and CCPA/CPRA consumer-rights disclosures for covered California deployments.
It must explicitly describe employee-identifying remote scan-log metadata such
as client IP, API key ID/name, correlation ID, repository name when supplied,
finding IDs/severities, feed status, and request/result digests. It must also
identify that operators can set `PACKMON_SCAN_LOG_IDENTITY_MODE=minimal` to
omit client IP and API-key ID/name from new scan-log rows, or `none` to also
omit repository name and normalized client version. It must also identify
optional outbound recipient categories: Socket.dev and ReversingLabs
package-coordinate lookups when configured, and operator-configured webhook
receivers that receive the canonical scan result payload. Operators are
responsible for their controller/contact details, transfer terms, work-council
or employee-monitoring notices, retention, and access rules.

The built-in `/terms` page is an operator-facing terms hook, not legal advice.
It must provide a stable web surface for deployment-specific acceptable use,
API-key responsibility, third-party feed/provider and webhook disclosure,
suspension/termination, amendment/version, governing-law, and liability/warranty
language. Operators that need binding AGB or contractual terms should replace
`PACKMON_WEB_TERMS_URL` with their approved document.

## Metrics Exposure

Metrics are unauthenticated by design for Prometheus-style scraping, but they
must bind to localhost by default and must not be exposed to untrusted networks.

Production startup rejects `PACKMON_METRICS_HOST` values that do not resolve to
the loopback bind policy (`localhost`, `127.0.0.1`, `::1`, or the implicit
default). Operators that need remote scraping must use node-local collectors,
sidecars, tunnels, or orchestrator-native monitors rather than binding the
unauthenticated plaintext metrics listener to a non-loopback interface.

Metrics may reveal operational counts and feed health. They must not include
secrets or raw package lists.

Operational logs must avoid unbounded warning/error amplification on attacker-
or outage-controlled loops. Rate-limit rejections rely on the bounded request
completion log for the warning-level 429 signal, queue workers suppress repeated
database dequeue/reset failures inside a short window, and graceful-shutdown
logs include concrete shutdown error strings instead of boolean-only failure
flags.
Async reputation workers return local rate-limit tokens when no upstream call
was made, account ReversingLabs 413 fallback calls individually, and cancel
request-detached ReversingLabs scheduling from the server root context during
shutdown.

## Database and Migrations

Server persistence uses PostgreSQL. Local CLI persistence uses SQLite.

Requirements:

- PostgreSQL credentials come from configuration/secrets;
- production PostgreSQL connections default to `sslmode=verify-full`; local
  development and the repository Compose example may explicitly set
  `PACKMON_DB_SSLMODE=disable` only for the bundled local database;
- production startup requires active feed API-key encryption through
  `PACKMON_ENCRYPTION_KEY` configured as base64-encoded 32 random bytes and
  admin audit digest HMAC keying through `PACKMON_ADMIN_AUDIT_HMAC_KEY`
  configured as base64-encoded 32 random bytes; only development mode may run
  without these secrets, using plaintext feed-key storage and legacy `sha256:`
  admin audit digests;
- migrations run through `packmon-server migrate`; the repository Compose
  wrapper uses a manual `packmon-migrate` service scoped to database and logging
  environment values only, and migration database operations are bounded by
  `PACKMON_DB_CONNECT_TIMEOUT`; the migrator writes durable
  `schema_migration_events` rows for started, successful, and failed migration
  attempts without storing environment values or feed secrets;
- normal server startup verifies expected schema version with a bounded
  `PACKMON_DB_CONNECT_TIMEOUT` deadline and exits on mismatch or connectivity
  failure;
- no automatic schema mutation on normal server startup;
- bounded, idempotent feed-data reconciliation may run after schema-version
  verification, but it must not perform DDL, update schema migration state, or
  bring an outdated schema current;
- server scan-log rows may contain scan ID, optional bounded and
  path-minimized repository name, client IP, package/finding counts, duration,
  decision evidence, correlation ID, a `sha256:` digest of the canonical JSON
  `ScanResult` response, authenticated API-key metadata, and a bounded
  normalized Packmon client version extracted from authenticated scan
  User-Agent values. Remote CLI requests and webhooks send only the repository
  name by default and can omit it with `--no-repo-metadata`,
  `PACKMON_NO_REPO_METADATA=true`, or `send_repo_metadata: false`. New scan-log
  rows do not retain branch, commit, or raw User-Agent values.
  `PACKMON_SCAN_LOG_IDENTITY_MODE` defaults to `full`; `minimal` suppresses
  scan-log client IP and API-key ID/name, and `none` also suppresses repository
  name and normalized client version while still retaining non-identifying
  scan evidence. Admin-audit rows contain action, details, source IP,
  timestamp, previous-row digest, and row digest; new production rows use
  `hmac-sha256:` digests keyed by `PACKMON_ADMIN_AUDIT_HMAC_KEY`, while older
  `sha256:` rows remain legacy-verifiable;
  details should not duplicate the source IP already stored in the typed column.
  Authenticated `/api/v1/sync` export attempts write a `sync_export`
  admin-audit row before data export with safe request scope metadata,
  correlation ID, trusted client IP, and API-key identity when available; raw
  sync cursors and package/finding data are not retained in that audit row.
  The offline `packmon-server privacy export` command verifies schema state,
  exports retained `scan_log` and `admin_audit_log` rows for exact whitelisted
  selectors, and writes a `privacy_export` admin-audit row with selector type,
  selector digest, and row counts before emitting JSON; the raw selector value
  is not retained in the audit details.
  Security-sensitive admin writes require the corresponding audit row; API-key
  lifecycle changes, queue mutations, password changes, and manual advisory
  writes are atomic with audit persistence in PostgreSQL. Password rotation is
  conditional on the stored bcrypt hash still matching the hash verified for
  the submitted current password. Queue clear/purge
  details retain a bounded affected-job sample, redacted bounded error text, and
  delete-count metadata from the same destructive operation. These rows are
  pruned by configurable retention controls
  (`PACKMON_SCAN_LOG_RETENTION`, `PACKMON_ADMIN_AUDIT_LOG_RETENTION`,
  `PACKMON_REFRESH_QUEUE_RETENTION`,
  `PACKMON_PACKAGE_CHECK_STATUS_RETENTION`, `PACKMON_AUDIT_RETENTION_INTERVAL`).
  Defaults are 30 days for scan logs, 30 days for admin audit logs, 30 days
  for terminal refresh-queue jobs, and
  90 days for Socket.dev package-check status rows. Admins can override the
  scan-log and admin-audit metadata retention values from `/admin/settings`;
  setting a dataset retention to `0` disables pruning for that table;
- backups use `pg_dump` and local retention as documented in the runbook.

## Local Mode Security

Local SQLite sync:

- pulls from Packmon server only;
- stores compact finding, reputation, and lifecycle data, not raw feed JSON;
- preserves user-facing source attribution for synced vulnerability and
  malicious findings;
- maps synced malicious-table rows with `supply_chain` or `typosquatting` risk
  types to `supply_chain_risk` scan findings rather than malware findings;
- rejects synced malicious exact-version data unless it is empty, `null`, or a
  JSON array of strings, and fails local lookup on malformed stored malicious
  version constraints instead of treating them as global findings;
- limits ReversingLabs reputation sync to active `malicious` and `removed`
  rows needed for local scan decisions plus non-blocking `risk` rows needed for
  local `LOW` reputation context;
- resolves synced reputation rows through explicit reputation lookup methods,
  not through malicious-package lookup methods;
- refuses to mark the local database fresh from a server `synced_at` timestamp
  that is beyond the allowed future clock-skew tolerance;
- rejects semantically empty full-sync snapshots before clearing local finding
  tables. A full sync response must include a parseable `synced_at` and either
  feed state metadata or synced data that proves the server returned a real
  snapshot;
- warns when data is stale;
- does not block solely because data is stale.

Local DB freshness is a policy input, not a hidden failure mode. When local DB
age exceeds `PACKMON_DB_WARN_AFTER_DAYS` (default `7` days), canonical scan
diagnostics and the local dashboard must surface a visible stale-data warning.
If freshness metadata cannot be read, user-visible diagnostics treat coverage as
stale or unknown instead of silently healthy.

## CI/CD Security

The first-party GitHub Actions workflows and the GitLab CI template were
removed in August 2026. The former hosted gates (release attestations, Trivy
image and filesystem scans, secret scanning, protected release environment)
are replaced by the local verification gate in `CONTRIBUTING.md`; run Trivy image
and filesystem scans locally before shipping images (see
`docs/runbook.md` -> "Container image vulnerability scans").

Consumer CI pipelines that run the Packmon CLI must:

- use `github.com/8linkz-sec/packmon` as the canonical source and Go module
  namespace;
- install or use known Packmon binaries;
- verify checksums where downloads occur;
- keep maintained Dockerfile and Compose image defaults digest-pinned; internal
  registry mirror overrides for builder, runtime, and PostgreSQL images must
  preserve `@sha256` pinning;
- avoid embedding secrets in logs;
- treat `PACKMON_SERVER` and API key values as CI secrets;
- use `PACKMON_REQUIRE_REMOTE=true` for remote CI scans so server failures do
  not silently fall back to stale local data;
- use `PACKMON_NO_REPO_METADATA=true` when CI project names should not be sent
  to the Packmon server as optional scan context;
- use short-lived, named API keys where the CI platform supports routine
  rotation;
- upload SARIF/JUnit/JSON artifacts according to platform conventions;
- inspect artifact diagnostics for degraded feed status, stale local database
  state, and partial parse errors, not only vulnerability result entries;
- keep detailed PR comments opt-in and escape Markdown table/link fields before
  rendering scan result data into forge comments;
- preserve exit codes so blocking findings fail pipelines.

The GitLab template is locally tested for YAML and contract behavior. A real
GitLab runner execution remains an external validation requirement.

## Dependency and Tooling Security

`packmon scan --auto-sbom` is local CLI behavior only; the server remains
unaffected. The CLI invokes fixed-name local tools with argument arrays and no
shell: Go uses the local Go toolchain, while npm, PyPI, and Maven use
CycloneDX generators. `--install-tools` is off by default because it runs
third-party package-manager installs, including any behavior those ecosystems
perform during installation. When enabled, Packmon logs the package, source,
and exact argv before running the pinned install command. Existing PATH tools
for npm and PyPI generators are version-checked against the pinned versions
before use. Auto-SBOM manifest reads, subprocess output capture, and generated
SBOM validation are bounded; cleanup errors after generation or scanning are
reported as operational failures. Generated SBOM files are written with `0600`
permissions in a `0700` temporary directory and deleted after the scan unless
`--keep-sbom` is set. Keep mode writes timestamped snapshot filenames and never
overwrites existing files; if a snapshot filename already exists, Packmon adds a
numeric suffix. Generated Go SBOMs preserve module replacement metadata so
local CLI scans do not silently label replaced dependencies as the unreplaced
source/version.

Scan report outputs (JSON, SARIF, JUnit, scan HTML, list-all HTML, and outdated
HTML) are privacy-sensitive local artifacts. Packmon opens them through a shared
private output-file helper that requests `0600` and also chmods existing targets
back to `0600` after opening, so reusing an old broader-mode artifact path does
not leave the overwritten report group/world-readable on POSIX filesystems.

SwiftPM outdated/list-all lookups must not turn repository-controlled lockfile
or SBOM strings into arbitrary Git egress. Package identities are normalized to
the documented `host/owner/repo` form without URL userinfo, and Git latest-tag
lookups are limited to the built-in public Git host allowlist plus trusted
operator-configured bare hostnames from `PACKMON_SWIFTPM_GIT_ALLOWED_HOSTS` or
`registries.swiftpm_git_allowed_hosts`. Unsupported schemes, full URLs,
SCP-like remotes, local paths, localhost/IP identities, and non-allowlisted
hosts are reported as unknown; SwiftPM remotes are still constructed as
`https://host/path.git` rather than copied from lockfile text.

`packmon scan --list-all-offline` is the privacy-preserving list-all reporting
mode for repositories where package names, SwiftPM identities, GitHub Action
names, or Docker image references must not be disclosed to public registries or
remote Git endpoints. The option is valid only with `--list-all`; it keeps the
normal findings scan and package inventory but suppresses latest-version and
Docker digest lookups, rendering those freshness fields as unknown.

Latest-version checks must honor lockfile source provenance when the ecosystem
records it. Source references are local-only package metadata and are not
serialized into API check payloads. For npm, requirements.txt, Cargo, Bundler,
CocoaPods, Composer, renv, pub, Maven, and Hex inputs, a source outside the
ecosystem's public default registry must make `--outdated` and `--list-all`
freshness checks return `unknown` instead of sending the package name or
coordinate to the public registry unless a trusted operator mirror is
configured. Use `PACKMON_NPM_REGISTRY_BASE_URL` for an npm registry-compatible
mirror, `PACKMON_PYPI_API_BASE_URL` for a PyPI JSON API-compatible mirror,
`PACKMON_RUBYGEMS_API_BASE_URL` for a RubyGems gems API-compatible mirror,
`PACKMON_CARGO_REGISTRY_API_BASE_URL` for a crates.io API-compatible mirror,
`PACKMON_COCOAPODS_TRUNK_API_BASE_URL` for a CocoaPods trunk API-compatible
mirror, `PACKMON_COMPOSER_REPOSITORY_BASE_URL` for a Packagist p2-compatible
mirror, `PACKMON_CRAN_MIRROR_URL` for a CRAN mirror root,
`PACKMON_GO_PROXY_URL` for a single Go module proxy root,
`PACKMON_MAVEN_REPOSITORY_BASE_URL` for a Maven repository root,
`PACKMON_PUB_HOSTED_URL` for a hosted Pub API root, `PACKMON_HEX_API_BASE_URL`
for a Hex API-compatible mirror, and `PACKMON_NUGET_V3_BASE_URL` for a NuGet
v3 flat-container-compatible mirror; HTTPS is required except loopback HTTP
test endpoints. `PACKMON_GO_PROXY_URL=off` disables Go latest-version lookups
without using direct VCS fallback. crates.io requests must use an identifying
Packmon User-Agent and a one-request-per-second throttle.

Required checks:

```bash
PACKAGES="$(go list ./...)"
GOSEC_DIRS="$(go list -f '{{.Dir}}' ./...)"
govulncheck ${PACKAGES}
gosec -nosec-require-rules -nosec-require-justification ${GOSEC_DIRS}
golangci-lint run ./...
```

When suppressing a security linter warning, include a narrow inline rationale.
Prefer fixing the root issue over adding suppressions.

## Security Audit Checklist

For each security review:

- Confirm API auth protects production `/api/v1/*` mutation and import paths.
- Confirm admin write paths require session and CSRF.
- Confirm admin sessions enforce both absolute and idle timeout.
- Confirm no new endpoint mutates state anonymously.
- Confirm trusted proxy handling is not bypassed.
- Confirm metrics exposure remains internal.
- Confirm logs do not expose secrets, full paths, env values, or file contents.
- Confirm feed file reads are scoped to intended roots.
- Confirm subprocess calls do not allow attacker-controlled commands.
- Confirm manual advisory deletion cannot remove feed-sourced data.
- Confirm migrations remain a separate command.
- Confirm scan result schema and blocking semantics stay consistent.
- Confirm stale/degraded feed states are visible to clients.
- Confirm CI templates preserve exit codes and artifacts.
- Confirm PRs include the security checklist and sensitive paths route through
  CODEOWNERS.
- Confirm release publishing remains behind the protected `release`
  environment approval gate.

## Current Open Security-Relevant Validation

The GitLab CI template still needs a real GitLab runner smoke test. Local tests
validate the template contract, but only a real runner can prove GitLab UI
artifact/report behavior end to end.

Fork-local note: GitLab/CI/CD and release-binary distribution hardening are
currently deferred for this fork because those delivery surfaces are not
operated. `docs/deferred-scope.md` records the accepted scope. Re-evaluate the
deferred findings before enabling CI/CD, publishing release binaries for other
users, or using Packmon as a required pipeline security gate.
