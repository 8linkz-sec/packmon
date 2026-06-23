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
`PACKMON_CA_CERT`. Use `--require-remote` / `PACKMON_REQUIRE_REMOTE` on CI
runners so a broken or unreachable server fails the pipeline instead of
silently falling back to the (possibly stale) local DB.

## Backup

Packmon uses a daily `pg_dump` backup job with 7-day local retention.

Recommended target path:

```text
/backups/packmon/
```

Use the deployment scheduler or database host automation to run a daily
`pg_dump` job that:

1. creates a timestamped dump file
2. writes it to the mounted backup volume
3. deletes files older than 7 days

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
createdb packmon
pg_restore --single-transaction --no-owner --no-privileges -d packmon /backups/packmon/packmon-YYYYMMDD-HHMMSS.dump
```

5. If the restored dump comes from an older Packmon release, run the explicit
   migration command for the version you are starting.
6. Start `packmon-server`.
7. Verify:

```bash
# Use https:// when in-app TLS is enabled (PACKMON_TLS_CERT_FILE/KEY_FILE).
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:9090/metrics
```

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

Actions:

```bash
packmon db info
packmon db sync --server http://packmon-server:8080 --insecure-allow-http
```

Use the plain HTTP form only for local-only Docker or loopback troubleshooting.
For shared deployments, use the HTTPS server URL or a TLS-terminating reverse
proxy instead.

### Server reports degraded feed status

Symptoms:

- `feed_status=degraded` in `/api/v1/check`
- admin feed page shows warning or error

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

### Queue is not draining

Actions:

1. Check `/admin/queue` for `pending`, `processing`, `paused`, and `error` jobs.
2. Resume paused jobs or retry errored jobs from the admin queue page.
3. Check `/metrics` for `packmon_queue_size`, `packmon_queue_oldest_job_seconds`, and `packmon_queue_error_total`.
4. Verify that the relevant async feed worker is enabled and has credentials.

### Prometheus metric families to alert on

- `packmon_http_requests_total`
- `packmon_http_request_duration_seconds_count`
- `packmon_http_request_duration_seconds_sum`
- `packmon_auth_login_failures_total`
- `packmon_degraded_responses_total`
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
- `packmon_queue_stuck_jobs_recovered_total`
- `packmon_feed_last_sync_timestamp`
- `packmon_feed_entries_age_seconds`
- `packmon_feed_sync_timeout_total`

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

### Validating the GitLab CI template

The shared GitLab template lives at `ci/gitlab/.packmon-scan.yml`. Local and
GitHub CI validation is covered by:

```bash
mkdir -p .gotmp
GOTMPDIR="$PWD/.gotmp" go test ./tests/ci
```

The test parses the YAML template and checks that the job downloads the release
binary at runtime, verifies it against `checksums.txt`, and publishes JSON,
SARIF, and JUnit artifacts. `make test-ci` is available as a wrapper on systems
with `make`. A real GitLab Runner smoke test still requires an available
GitLab project and runner.

On Windows hosts without `make`, build the binaries and point the integration
tests at that directory directly:

```powershell
New-Item -ItemType Directory -Force .gotmp | Out-Null
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
$env:PACKMON_TEST_BIN_DIR = ".build"
go test -tags integration .\tests\integration
go test -tags e2e .\tests\e2e
```
