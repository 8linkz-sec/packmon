# Runbook

## Services

- API and web UI: port `8080`
- metrics: `127.0.0.1:9090`
- PostgreSQL: port `5432`

## Transport security (read before first production start)

In production mode (`PACKMON_SERVER_MODE=production`, the default) the server is
**fail-closed**: it refuses to start unless the client channel is protected by
one of these:

1. In-app TLS: set both `PACKMON_TLS_CERT_FILE` and `PACKMON_TLS_KEY_FILE`
   (optional `PACKMON_TLS_MIN_VERSION`, default `1.2`, accepts `1.2` or `1.3`).
   The certificate's SAN must include every hostname/IP that clients use to
   reach the server -- important when clients sit in separate networks.
2. A TLS-terminating reverse proxy in front: set `PACKMON_TRUSTED_PROXIES` to
   the proxy IPs/CIDRs.
3. Local-only Docker: `PACKMON_ALLOW_INSECURE_LOCAL_HTTP=true` together with a
   loopback `PACKMON_SERVER_PUBLIC_HOST` (e.g. `localhost:8080`). Plain HTTP,
   only safe when the port is bound to `127.0.0.1`.

When none is configured the server exits with:

```text
config: refusing to start in production without transport security: set
PACKMON_TLS_CERT_FILE and PACKMON_TLS_KEY_FILE for in-app TLS, or
PACKMON_TRUSTED_PROXIES when running behind a TLS-terminating reverse proxy
```

The startup log states which transport is active (`https` listener vs `http`).

CLI clients enforce `https://` for `--server` and refuse to send the API key
over plain HTTP unless `--insecure-allow-http` / `PACKMON_INSECURE_ALLOW_HTTP`
is set. Distribute an internal CA bundle to clients via `--cacert` /
`PACKMON_CA_CERT_FILE`; `PACKMON_CA_CERT` remains a legacy alias. Use
`--require-remote` / `PACKMON_REQUIRE_REMOTE` on CI runners so a broken or
unreachable server fails the pipeline instead of silently falling back to the
(possibly stale) local DB.

## Backup

Packmon uses a daily PostgreSQL archive dump with 7-day local retention.
External backup systems are responsible for off-host or longer-term retention.

Recommended target path:

```text
/backups/packmon/
```

Use the deployment scheduler or database host automation to run a daily backup
job that creates the same custom archive format restored by the command below:

```bash
install -d -m 0700 /backups/packmon
pg_dump \
  --format=custom \
  --file "/backups/packmon/packmon-$(date -u +%Y%m%d-%H%M%S).dump" \
  packmon
find /backups/packmon -type f -name 'packmon-*.dump' -mtime +7 -delete
pg_restore --list "$(ls -1t /backups/packmon/packmon-*.dump | head -n 1)" >/dev/null
```

For the repository-provided Compose model, run the same policy as an explicit
operator action:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm packmon-backup
```

For Docker Compose deployments, run the same command from a host or job
container that can reach the PostgreSQL service and receives database
credentials through the deployment secret path. Do not write database passwords
into the command line or into tracked files.

Backups contain personal data and security-relevant metadata such as scan logs,
admin audit logs, API-key history, package names, repository identifiers, and
feed provider status. Keep dump directories at `0700`, encrypt dumps at rest
with age, GPG, or storage-managed encryption, restrict restore access to the
same operator group that can administer production, and replicate only through
approved off-host backup storage.

The `PACKMON_ENCRYPTION_KEY` deployment secret is part of the recovery set when
stored feed API keys exist. Back it up with the same access controls as the
database backup, because changing or losing it prevents Packmon from decrypting
stored provider keys after restore.

## Restore

1. Stop the API server.
2. Ensure PostgreSQL is running.
3. Make sure the selected dump is available on the database host or mounted
   backup volume.
4. Restore into a clean target database. Do not restore a full dump into an
   existing populated Packmon database.

```bash
psql -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'packmon' AND pid <> pg_backend_pid();"
dropdb --if-exists packmon
createdb --owner packmon packmon
pg_restore --single-transaction --no-owner --no-privileges --role packmon -d packmon /backups/packmon/packmon-YYYYMMDD-HHMMSS.dump
```

5. If the restored dump comes from an older Packmon release, run the explicit
   migration command for the version you are starting.
6. Verify the restored deployment has the same `PACKMON_ENCRYPTION_KEY` that
   was active when encrypted feed API keys were saved.
7. Start `packmon-server`.
8. Verify readiness before routing traffic. Do not use `/healthz` alone; it is
   a liveness endpoint and can succeed before the database-backed service is
   ready.

```bash
# Use https:// when in-app TLS is enabled (PACKMON_TLS_CERT_FILE/KEY_FILE).
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/version
curl -fsS http://127.0.0.1:9090/metrics
```

## Upgrade And Rollback

Packmon server startup verifies the schema version and does not run migrations
implicitly. Treat binary rollout and database migration as one operator-owned
change.

1. Capture the target Packmon version and current database schema version from
   `/version`, `packmon_build_info`, and `packmon_db_migration_version`.
2. Take and verify a fresh backup with the command in `Backup`.
3. Stop or drain `packmon-server` so clients do not write during migration.
4. Run the explicit migration step:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml run --build --rm packmon-migrate
   ```
5. Start the new server build:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d packmon-server
   ```
6. Verify `/healthz`, `/readyz`, `/version`, `/metrics`,
   `/api/v1/feeds/status`, and the admin dashboard.
7. Run a remote CLI scan with a non-production test key or a known safe target.

If startup fails before a migration changed the schema, roll back the binary and
start the previous server version. If a migration already changed the schema,
assume rollback requires restoring the pre-upgrade dump into a clean database
before starting the older binary. Do not rely on normal server startup to bring
an older schema forward or a newer schema backward.

For an operator rollback:

1. Stop or drain the new `packmon-server` instance.
2. Redeploy the previous known-good Packmon binary or container image and its
   matching Compose or service definition.
3. If no migration ran, verify the current `packmon_db_migration_version` is
   compatible with the previous binary before starting it.
4. If a migration ran or schema compatibility is uncertain, restore the
   pre-upgrade dump into a clean database before starting the previous binary.
5. Start the previous server and verify `/healthz`, `/readyz`, `/version`, and
   `/metrics`; then run a remote CLI smoke scan with a non-production test key.
6. Record the rollback, release version, schema version, backup used, and
   operator action in the operator change log.

## API Key Rotation

API keys expire no more than 90 days after creation. Rotate one client class at
a time so scans and imports keep working while the old key remains available.

1. In `/admin/keys`, create a replacement key with a clear name such as
   `ci-main-2026-07` and a UTC expiration before the 90-day limit.
2. Update the matching client secret store, CI variable, N8N credential, or
   user environment variable. Prefer `PACKMON_API_KEY` or config `api_key_env`
   over plaintext command-line arguments.
3. Run the affected scan, sync, or feed-import job and verify success.
4. Confirm the replacement key's `last_used_at` moved in `/admin/keys`.
5. Revoke the old key and keep the row for audit history.

For suspected key exposure, revoke the key first, then create a replacement and
check recent scan logs, auth failure metrics, and admin audit entries for
unexpected use.

## Admin Access Control

Packmon uses one shared admin identity. For production environments where
privileged access requires stronger assurance, enforce MFA or SSO in a trusted reverse proxy
or identity provider before requests can reach `/admin`.

- restrict /admin network reachability to the proxy or private management
  network;
- block direct access to the Packmon listener from administrator workstations;
- keep Packmon's own admin password, session timeout, CSRF, lockout, and
  current-password step-up controls enabled behind the proxy;
- record the proxy/identity-provider policy, MFA requirement, allowed groups,
  and break-glass process in the operator change log.

## Encryption Key Backup And Rotation

`PACKMON_ENCRYPTION_KEY` encrypts persisted feed provider API keys in
production. Keep it stable across restarts, upgrades, and restores.

- Store it in the deployment secret manager, not in tracked files.
- Back it up with the same recovery scope and access controls as PostgreSQL
  dumps.
- Verify the key is present before restoring or starting a production server.
- Do not change it in-place while encrypted feed API keys are stored.

For planned rotation, record which feeds show a configured key, deploy the new
secret in a maintenance window, re-enter or clear each provider key through
`/admin/feeds`, trigger manual syncs where supported, verify feed status, and
only then retire the old secret.

## Operational Objectives

These defaults are starting points for internal deployments. Environment owners
should replace them with stricter or looser objectives where their service
model requires it.

| Objective | Default target | Breach response |
|---|---:|---|
| API/web availability | 99.5% monthly | Open an incident, check `/healthz`, `/readyz`, recent deploys, and PostgreSQL. |
| API check latency | p95 below 2 seconds for normal package lists | Inspect DB pool, queue backlog, feed status, and CPU/memory. |
| Feed freshness | No required self-managed feed stale beyond cadence plus 2 hours | Follow `Server reports degraded feed status`. |
| Refresh queue age | Oldest active job below 2 hours by default | Follow `Queue is not draining`; tune workers or provider credentials. |
| Backup RPO | Roughly 24 hours | Verify the latest dump exists and passes `pg_restore --list`. |
| Restore RTO (Recovery Time Objective) | Operator-owned, documented per deployment | Run a restore drill after backup, schema, or storage changes and record the measured restore time. |

## Incident Response

Open an operational incident when Packmon is unavailable, feed status is
degraded past the alert window, a migration fails, a restore is needed, repeated
auth failures suggest misuse, or an API/feed key may be exposed.

1. Assign an incident lead and record the start time, affected surfaces, and
   current Packmon version.
2. Check `/healthz`, `/readyz`, `/version`, `/metrics`, `/api/v1/feeds/status`,
   `/admin/queue`, recent server logs, and recent deployment changes.
3. Classify severity by user impact: outage, degraded scan coverage, delayed
   async enrichment, or administrative-only impact.
4. Communicate status to affected client owners and CI/automation maintainers.
5. Apply the smallest mitigation: rollback binary before migration, restore
   from backup after migration/data loss, rotate keys, disable a failing
   optional feed, or pause/retry queue jobs.
6. After recovery, record timeline, root cause, customer impact, permanent
   follow-up, and any documentation updates.

Classify each incident before closure:

- availability incident: Packmon API, web UI, queue, or feed refresh is
  unavailable beyond the deployment objective;
- security incident: API keys, admin credentials, feed provider secrets,
  release artifacts, or scan integrity may be compromised;
- personal-data breach: scan logs, admin audit logs, package/repository
  identifiers, client IPs, or operator identities may have been exposed or
  altered without authorization;
- NIS2 / regulatory candidate: the operator legal/compliance owner must assess
  whether reporting duties apply, including early warning within 24 hours and
  notification within 72 hours where the deployment is in scope.

Record the notification decision, owner, timestamp, evidence reviewed, and any
external notices or customer communications in the operator incident record.

## Capacity And Scaling

Packmon is single-server by default. Adding multiple `packmon-server` replicas
is not a safe first response without a separate HA design for admin sessions,
background workers, migrations, and queue processing.

When capacity pressure appears:

1. Check HTTP latency, `packmon_degraded_responses_total`, and Go runtime
   resource metrics such as `packmon_go_goroutines` and
   `packmon_go_heap_alloc_bytes`.
2. Check queue size and oldest active job age.
3. Check `packmon_db_pool_connections` for acquired connections approaching
   max.
4. Check feed age, sync duration, sync timeouts, and upstream provider rate
   limits.
5. Check host CPU, memory, and PostgreSQL limits.

Safe first knobs are vertical host/container resources, PostgreSQL capacity,
`PACKMON_DB_MAX_CONNS`, `PACKMON_DB_MIN_CONNS`, rate-limit settings, per-feed
cadence, and whether startup feed sync should run during maintenance. Keep
Compose resource-limit changes in the operator-owned deployment configuration.

## Privacy Metadata Export

Covered operators that need to answer a right-to-know/access request for
Packmon-held server metadata can run an offline export against PostgreSQL:

```bash
packmon-server privacy export --selector client-ip=203.0.113.10 --format json
```

Supported exact selector types are `client-ip`, `repo-name`, `api-key-id`,
`api-key-name`, and `correlation-id`. The export includes matching `scan_log`
rows and matching `admin_audit_log` rows across the retained database window.
Treat the JSON output as sensitive operational metadata and store or transmit it
only through the operator's approved privacy-request process.

The command verifies the schema version before reading, refuses dirty or
unexpected schemas, and writes a `privacy_export` admin-audit row before
emitting JSON. The audit row records selector type, a `sha256:` selector
digest, and exported row counts; it does not store the raw selector value.
Free-form admin-audit detail JSON is matched only through a small whitelist of
known keys, so the export is an operator helper rather than an identity-proofing
or legal-completeness workflow.

## Troubleshooting

### Server refuses to start (transport security)

Symptom: startup exits immediately with `config: refusing to start in
production without transport security: ...`.

Cause: production mode with no TLS, no trusted proxy, and no local override.

Actions: pick one option from the "Transport security" section above:

- enable in-app TLS (`PACKMON_TLS_CERT_FILE` + `PACKMON_TLS_KEY_FILE`), or
- set `PACKMON_TRUSTED_PROXIES` if a TLS-terminating proxy fronts the server, or
- for local Docker only, set `PACKMON_ALLOW_INSECURE_LOCAL_HTTP=true` with a
  loopback `PACKMON_SERVER_PUBLIC_HOST`.

A related variant -- `PACKMON_ALLOW_INSECURE_LOCAL_HTTP requires
PACKMON_SERVER_PUBLIC_HOST to be localhost/127.0.0.1/::1` -- means the insecure
override is set but the public host is not loopback. Either point the public
host at loopback or configure real TLS / a trusted proxy.

### ReversingLabs reputation feed (demand-driven)

ReversingLabs is optional, self-mode only, and disabled by default
(`PACKMON_FEED_REVERSINGLABS_ENABLED=false`). It does NOT do a bulk sync, so it
will not show a normal "last sync" age like OSV/GHSA -- it lazily looks up a
package version (at most once per `PACKMON_REVERSINGLABS_LOOKUP_TTL`, default
24h) only when that package appears in a `/api/v1/check` and no other feed
already covers it.

Operational notes:

- Requires `PACKMON_REVERSINGLABS_API_KEY`. `external` mode is rejected at
  startup (there is no import endpoint).
- Batch size is capped at 5 (free-plan `/find/packages` limit).
- Rate-limit, capacity, or network failures degrade the feed but must NOT fail
  scans or delete cached data. Watch the queue metrics below; the worker shares
  the refresh queue (`source = reversinglabs`).
- A `removed` package maps to a blocking `supply_chain_risk` finding; a
  `malicious` package maps to a blocking malware finding. The first scan of an
  unseen package only schedules the lookup, so it blocks on a later scan.

### CLI warns that the local DB is stale

Expected behavior after `PACKMON_DB_WARN_AFTER_DAYS` days without sync.
The local dashboard must show the same stale-data condition as a visible warning
to all viewers, not only as CLI stderr output.

Actions:

```bash
packmon db info
packmon db sync --server http://packmon-server:8080 --insecure-allow-http
```

Open `packmon dashboard` after the sync. If the CLI reports stale or unknown
freshness while the dashboard and scan artifacts show healthy coverage, treat
that as a product defect rather than an operator-only warning.

Use the plain HTTP form only for local-only Docker or loopback troubleshooting.
For shared deployments, use the HTTPS server URL or a TLS-terminating reverse
proxy instead.

### Server reports degraded feed status

Symptoms:

- `feed_status=degraded` in `/api/v1/check`
- admin feed page shows warning or error
- feed-status UI or API reports rejected import records, validation reason
  classes, or an old last successful import timestamp
- scan history or package/finding totals show a sudden spike in blocking
  findings from one source

Actions:

1. Inspect `/api/v1/feeds/status` with production API headers:
   ```bash
   curl -fsS \
     -H "Authorization: Bearer $PACKMON_API_KEY" \
     -H "User-Agent: packmon-cli/runbook" \
     https://packmon.example.com/api/v1/feeds/status
   ```
2. Check `/metrics` for `packmon_feed_*`
3. Verify upstream credentials and network access
4. Inspect recent sync logs
5. For self-managed feeds that support manual sync, open `/admin/feeds`, verify
   the affected feed is enabled and in `self` mode, then use `Sync now`.
6. Re-check `/api/v1/feeds/status` and the `packmon_feed_*` metrics after the
   manual sync finishes.
7. For external imports, check the feed-status UI/API for bounded rejection
   diagnostics, rejected-record counts, reason classes, correlation ID,
   trusted client IP, API-key ID/name when available, and the last successful
   usable import timestamp.
8. Compare recent finding/blocking totals by feed source before treating a
   spike as real dependency risk. If strict validation rejected the import,
   keep the previous good data and fix the importer payload before retrying.

Avoid launching overlapping manual syncs for the same feed. Manual sync is not
available for disabled feeds, external feeds, or demand-driven queue sources
such as ReversingLabs.

### Feed scheduler controls

Global self-sync scheduling uses:

- `PACKMON_FEED_SYNC_INTERVAL=8h`
- `PACKMON_FEED_SYNC_ON_STARTUP=true`

Per-feed cadence saved from `/admin/feeds` overrides the global interval for
that feed and must be at least `15m`. Disable startup sync only during planned
maintenance or when the deployment platform starts several replacement
containers in quick succession. After changing cadence, check
`packmon_feed_last_sync_timestamp`, `packmon_feed_entries_age_seconds`, and the
admin feed page.

### Queue is not draining

Actions:

1. Check `/admin/queue` for `pending`, `processing`, `paused`, and `error` jobs.
2. Resume paused jobs or retry errored jobs from the admin queue page.
3. Check `/metrics` for `packmon_queue_size`, `packmon_queue_oldest_job_seconds`,
   `packmon_queue_error_total`, and `packmon_queue_jobs_completed_total`.
4. Verify that the relevant async feed worker is enabled and has credentials.

### Database pool saturation

Symptom: `packmon_db_pool_connections{state="acquired"}` approaches
`packmon_db_pool_connections{state="max"}` or API latency rises while
PostgreSQL is healthy.

Actions:

1. Confirm PostgreSQL can accept the larger pool and has headroom for
   maintenance connections.
2. Increase `PACKMON_DB_MAX_CONNS` deliberately and keep
   `PACKMON_DB_MIN_CONNS` below the maximum.
3. Reduce avoidable load by tuning feed cadence, retrying stuck queue jobs, or
   lowering client request bursts.
4. Restart the server only when the deployment change requires it.

### Prometheus metric families to alert on

- `packmon_http_requests_total`
- `packmon_http_request_duration_seconds_count`
- `packmon_http_request_duration_seconds_sum`
- `packmon_build_info`
- `packmon_go_goroutines`
- `packmon_go_heap_alloc_bytes`
- `packmon_go_heap_inuse_bytes`
- `packmon_go_gc_cycles_total`
- `packmon_go_gc_last_pause_seconds`
- `packmon_auth_login_failures_total`
- `packmon_degraded_responses_total`
- `packmon_metrics_store_read_failures_total`
- `packmon_db_migration_version`
- `packmon_db_pool_connections`
- `packmon_packages_total`
- `packmon_packages_scanned_total`
- `packmon_scan_findings_total`
- `packmon_findings_total`
- `packmon_findings_by_severity`
- `packmon_queue_size`
- `packmon_queue_oldest_job_seconds`
- `packmon_queue_error_total`
- `packmon_queue_jobs_completed_total`
- `packmon_queue_stuck_jobs_recovered_total`
- `packmon_feed_last_sync_timestamp`
- `packmon_feed_sync_status`
- `packmon_feed_entries_age_seconds`
- `packmon_feed_sync_timeout_total`
- `packmon_feed_sync_duration_seconds`

The versioned starter Prometheus rule file is
`docs/monitoring/packmon-alerts.yml`. Import it as a baseline and tune
thresholds, routing labels, and Alertmanager receivers for the deployment's
feed cadence, package volume, and service objectives.

Starter alert rules:

| Signal | Example expression | First response |
|---|---|---|
| Metrics scrape down | `up{job=~"packmon.*"} == 0` | Check the metrics listener, node-local scrape path, or tunnel/sidecar configuration. |
| Metrics store read failure | `increase(packmon_metrics_store_read_failures_total[10m]) > 0` | Check PostgreSQL availability and server logs for bounded metrics-store read failures. |
| Degraded scan coverage | `increase(packmon_degraded_responses_total[10m]) > 0` | Check feed status, local DB freshness, and partial parse errors. |
| Feed sync error | `packmon_feed_sync_status{status=~"error|permanent_error|rejected"} == 1` | Check provider credentials, imports, and the feed error detail in the admin feed page. |
| Feed stale | `time() - packmon_feed_last_sync_timestamp > 36000` | Run the degraded feed procedure and check provider credentials. |
| Feed entry age | `packmon_feed_entries_age_seconds > 36000` | Verify upstream sync and import freshness. |
| Feed sync duration spike | `packmon_feed_sync_duration_seconds > 1800` | Check the affected feed logs, provider latency, and database pool pressure. |
| Queue backlog | `packmon_queue_oldest_job_seconds > 7200` | Check queue page, provider credentials, and worker logs. |
| Queue errors | `increase(packmon_queue_error_total[15m]) > 0` | Retry or inspect errored jobs by source. |
| DB pool pressure | `packmon_db_pool_connections{state="acquired"} / packmon_db_pool_connections{state="max"} > 0.8` | Check PostgreSQL limits and pool sizing. |
| Runtime heap growth | `packmon_go_heap_alloc_bytes` rising continuously across several scrapes | Compare with traffic/feed activity and check for stuck sync or queue workers. |
| Runtime goroutine growth | `packmon_go_goroutines` rising continuously across several scrapes | Check recent deploys, feed syncs, queue workers, and shutdown/restart logs. |
| Login failures | `increase(packmon_auth_login_failures_total[10m]) > 5` | Review admin access, trusted proxy configuration, and audit logs. |
| Schema mismatch | `packmon_db_migration_version != 0` with an unexpected version label | Stop rollout and follow `Upgrade And Rollback`. |

Tune thresholds for the deployment's feed cadence, package volume, and service
objectives.

Route firing alerts to the deployment's ticketing or incident channel and page the on-call owner for availability, security, or data-integrity impact. If you use Alertmanager, encode the Packmon service name, environment, severity, and runbook URL in alert labels or annotations before paging.

### Metrics are unreachable remotely

Expected behavior. Metrics are bound to localhost by default.

Use SSH tunneling, node-local Prometheus, or a PodMonitor/sidecar pattern instead of exposing the metrics port publicly.

### Real client IP behind a reverse proxy

By default Packmon ignores forwarded IP headers. Set `PACKMON_TRUSTED_PROXIES`
to a comma-separated list of trusted proxy IPs or CIDRs before using
`X-Forwarded-For` or `X-Real-IP` for rate limiting and audit logs. Setting this
also satisfies the fail-closed transport requirement (it tells the server a
TLS-terminating proxy is in front).

### Admin system settings do not appear to apply

`/admin/settings` can persist the API block threshold and global rate-limit
settings in PostgreSQL. Saved values are applied immediately to the live
runtime and persisted for future server starts. If a saved value does not appear
to apply, check the admin audit log, the settings save response, and the server
logs for validation or store errors before restarting the service.

Environment defaults are:

- `PACKMON_BLOCK_THRESHOLD=CRITICAL`
- `PACKMON_RATE_LIMIT_PER_MINUTE=60`
- `PACKMON_RATE_LIMIT_BURST=60`

### Managing manual advisories

Use `/admin/advisories` for operator-managed findings. Choose `vulnerability`
for non-malicious package advisories and `malicious` for malware,
typosquatting, or supply-chain package findings. Entries use source `manual`
and receive a stable `manual:<uuid>` ID when no ID is provided.
Do not use manual advisories for Docker images; Docker rows in Packmon are
inventory metadata only, not vulnerability-scan coverage.

### Validating the GitLab CI template

The shared GitLab template lives at `ci/gitlab/.packmon-scan.yml`. Local and
GitHub CI validation is covered by:

```bash
mkdir -p .gotmp
GOTMPDIR="$PWD/.gotmp" go test -count=1 ./tests/ci
```

The test parses the YAML template and checks that the job downloads the release
binary at runtime, verifies it against `checksums.txt`, and publishes JSON,
SARIF, and JUnit artifacts. `make test-ci` is available as a wrapper on systems
with `make`. A real GitLab Runner smoke test still requires an available
GitLab project and runner.

### Container image vulnerability scans

GitHub CI and release verification build the Dockerfile `server` and `cli`
targets as local images and run Trivy against OS package vulnerabilities before
release artifacts can be published. The gate blocks on HIGH and CRITICAL OS
package CVEs, uses the repository-pinned Dockerfile base image digests, and does
not publish the built images to a registry.

The same security jobs run a Trivy filesystem dependency scan over repository
lockfiles and block HIGH and CRITICAL library vulnerabilities before release.

On Windows hosts without `make`, build the binaries and point the integration
tests at that directory directly:

```powershell
New-Item -ItemType Directory -Force .gotmp | Out-Null
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
$env:PACKMON_TEST_BIN_DIR = ".build"
go test -count=1 -tags integration .\tests\integration
go test -count=1 -tags e2e .\tests\e2e
```
