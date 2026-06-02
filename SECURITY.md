# Packmon Security Model

This document is the canonical security baseline for Packmon. Use it for
security reviews and audits. If implementation and this document drift, either
fix the code or update this file in the same change with a clear rationale.

## Security Goals

- Prevent unauthorized writes to feed data, admin settings, queue state, API
  keys, and manual advisories.
- Prevent accidental public exposure of internal APIs and metrics.
- Preserve integrity of vulnerability, malicious package, and lifecycle data.
- Avoid leaking secrets, repository paths, file contents, or environment values.
- Provide trustworthy CI outputs for dependency security decisions.
- Keep local developer use safe even when remote services are unavailable.

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
- API key creation/revocation;
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

API keys are stored hashed. Plaintext keys are shown only at creation time.
Keys have labels/names for auditability, record `last_used_at`, may be
revoked, and may have an optional `expires_at` timestamp. Expired keys must be
treated the same as missing or revoked keys by API authentication.

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
- reference keys from `.packmon.yaml` with `api_key_env` rather than plaintext
  `api_key` values;
- use short expirations for CI and automation where rotation is practical;
- review `last_used_at` before revoking stale keys.

## Admin Authentication

Packmon intentionally has one shared admin identity, not per-user accounts.

Admin properties:

- bootstrap password comes from `PACKMON_ADMIN_INITIAL_PASSWORD` only when no
  admin hash exists yet;
- password is stored as a bcrypt hash;
- existing admin hash takes precedence over bootstrap env;
- login form uses standard username/password fields and browser/vault-friendly
  autocomplete attributes;
- sessions use secure cookies with HttpOnly and SameSite behavior;
- admin write forms require CSRF validation;
- failed logins are rate limited and counted in metrics;
- admin actions are written to the audit log where supported.

Admin features must not introduce multi-user assumptions without updating this
document and the design.

## Authorization Rules

Admins may:

- manage API keys;
- manage manual advisories;
- change feed settings;
- mutate queue state;
- update system settings;
- view admin audit data.

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
use with a loopback `PACKMON_SERVER_PUBLIC_HOST` and host-port binding. Do not
enable that override on shared hosts or network-exposed deployments. When this
local-only override is active, admin session cookies intentionally omit the
`Secure` flag so login works over `http://localhost`; all non-override
production deployments must keep `Secure` session cookies.

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
- preserve source identity and freshness;
- preserve malicious-package semantics when an advisory feed exposes them as
  category metadata rather than severity data;
- not delete existing good data on failed sync;
- mark feed status as skipped/error/degraded when data is unavailable;
- handle rate limits and timeouts without corrupting stored data;
- prevent path traversal when reading files from cloned feed repositories;
- avoid shell command injection when invoking `git`;
- avoid trusting raw feed JSON beyond parser validation.

GHSA and malicious package git repositories are external input. Treat changed
file paths from git as untrusted until scoped under the repository root.

ReversingLabs API tokens are sensitive feed API keys and follow the same
handling rules as VulnCheck, NVD, and Socket.dev keys. Packmon stores only
normalized ReversingLabs status and minimal evidence, not full raw reports.
ReversingLabs rate-limit, capacity, and network failures degrade that source
but must not fail scans or delete existing cached blocking data.

endoflife.date lifecycle metadata is external feed input. Packmon fetches it
server-side, validates and normalizes product/release data, and exposes only
normalized lifecycle rows and findings to scan clients. Raw endoflife.date JSON
is not exposed through scan results. The feed requires no API key, and upstream
rate limits, 304 responses, network failures, or schema parse failures must
degrade feed status without deleting existing cached lifecycle data.

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
- manual malicious findings block immediately;
- manual vulnerability findings follow the configured vulnerability threshold;
- admin create/update/delete actions should be audit logged;
- deleting a manual advisory must not delete feed-sourced advisories.

## Scan Result Trust

The canonical scan result is shared by:

- CLI JSON output;
- `POST /api/v1/check` response;
- webhook result object.

Downstream tools should trust `findings_blocking`, exit code, and finding type
semantics only if the result was produced by a verified Packmon binary/server.

Malicious and supply-chain risk findings always block. Vulnerability and
`lifecycle` findings block according to the configured threshold. Exact EOL
matches from lifecycle data are represented as blocking `supply_chain_risk`
findings, while upcoming EOL and security-support-only states remain
severity-gated `lifecycle` findings. Feed-degraded responses must be visible so
CI/N8N can make policy decisions.

## Webhooks

Webhook delivery is best effort.

If a webhook secret is configured:

- sign payloads with `X-Packmon-Signature: sha256=<hmac>`;
- use HMAC-SHA256 over the payload body.

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
- sensitive feed API keys.

Allowed:

- ecosystem names;
- package names and versions;
- advisory IDs;
- scan IDs;
- correlation IDs;
- filenames without full path;
- aggregate counts and durations.

Full local paths may appear only in local debug output where explicitly
intended. Server logs must stay path-minimized.

## Metrics Exposure

Metrics are unauthenticated by design for Prometheus-style scraping, but they
must bind to localhost by default and must not be exposed to untrusted networks.

Production deployments exposing metrics beyond localhost need explicit network
controls such as firewall rules, private service monitors, or trusted internal
scrapers.

Metrics may reveal operational counts and feed health. They must not include
secrets or raw package lists.

## Database and Migrations

Server persistence uses PostgreSQL. Local CLI persistence uses SQLite.

Requirements:

- PostgreSQL credentials come from configuration/secrets;
- migrations run through `packmon-server migrate`;
- normal server startup verifies expected schema version and exits on mismatch;
- no automatic schema mutation on normal server startup;
- backups use `pg_dump` and local retention as documented in the runbook.

## Local Mode Security

Local SQLite sync:

- pulls from Packmon server only;
- stores compact finding, reputation, and lifecycle data, not raw feed JSON;
- warns when data is stale;
- does not block solely because data is stale.

Local DB freshness is a policy input, not a hidden failure mode.

## CI/CD Security

GitHub Actions and GitLab CI templates must:

- install or use known Packmon binaries;
- verify checksums where downloads occur;
- avoid embedding secrets in logs;
- treat `PACKMON_SERVER` and API key values as CI secrets;
- use `PACKMON_REQUIRE_REMOTE=true` for remote CI scans so server failures do
  not silently fall back to stale local data;
- use short-lived, named API keys where the CI platform supports routine
  rotation;
- upload SARIF/JUnit/JSON artifacts according to platform conventions;
- preserve exit codes so blocking findings fail pipelines.

The GitLab template is locally tested for YAML and contract behavior. A real
GitLab runner execution remains an external validation requirement.

## Dependency and Tooling Security

Required checks:

```bash
govulncheck ./...
gosec ./...
golangci-lint run ./...
```

When suppressing a security linter warning, include a narrow inline rationale.
Prefer fixing the root issue over adding suppressions.

## Security Audit Checklist

For each security review:

- Confirm API auth protects production `/api/v1/*` mutation and import paths.
- Confirm admin write paths require session and CSRF.
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

## Current Open Security-Relevant Validation

The GitLab CI template still needs a real GitLab runner smoke test. Local tests
validate the template contract, but only a real runner can prove GitLab UI
artifact/report behavior end to end.
