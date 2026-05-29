# Runbook

## Services

- API and web UI: port `8080`
- metrics: `127.0.0.1:9090`
- PostgreSQL: port `5432`

## Backup

Packmon uses a daily `pg_dump` backup job with 7-day local retention.

Recommended target path:

```text
/backups/packmon/
```

The Helm chart includes a backup CronJob template that:

1. creates a timestamped dump file
2. writes it to the mounted backup volume
3. deletes files older than 7 days

## Restore

1. Stop the API server.
2. Ensure PostgreSQL is running.
3. Restore the selected backup:

```bash
pg_restore -d packmon /backups/packmon/packmon-YYYYMMDD-HHMMSS.dump
```

4. Start `packmon-server`.
5. Verify:

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:9090/metrics
```

## Troubleshooting

### CLI warns that the local DB is stale

Expected behavior after `PACKMON_DB_WARN_AFTER_DAYS` days without sync.

Actions:

```bash
packmon db info
packmon db sync --server http://packmon-server:8080
```

### Server reports degraded feed status

Symptoms:

- `feed_status=degraded` in `/api/v1/check`
- admin feed page shows warning or error

Actions:

1. Inspect `/api/v1/feeds/status`
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
- `packmon_packages_scanned_total`
- `packmon_scan_findings_total`
- `packmon_findings_total`
- `packmon_findings_by_severity`
- `packmon_queue_size`
- `packmon_db_pool_connections`
- `packmon_feed_entries_age_seconds`

### Metrics are unreachable remotely

Expected behavior. Metrics are bound to localhost by default.

Use SSH tunneling, node-local Prometheus, or a PodMonitor/sidecar pattern instead of exposing the metrics port publicly.

### Real client IP behind a reverse proxy

By default Packmon ignores forwarded IP headers. Set `PACKMON_TRUSTED_PROXIES`
to a comma-separated list of trusted proxy IPs or CIDRs before using
`X-Forwarded-For` or `X-Real-IP` for rate limiting and audit logs.

### Admin system settings do not appear to apply

`/admin/settings` can persist the API block threshold and global rate-limit
settings in PostgreSQL. These values are read during server startup, so restart
`packmon-server` after saving changes.

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
go test ./tests/ci
```

The test parses the YAML template and checks that the job downloads the release
binary at runtime, verifies it against `checksums.txt`, and publishes JSON,
SARIF, and JUnit artifacts. `make test-ci` is available as a wrapper on systems
with `make`. A real GitLab Runner smoke test still requires an available
GitLab project and runner.

On Windows hosts without `make`, build the binaries and point the integration
tests at that directory directly:

```powershell
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
$env:PACKMON_TEST_BIN_DIR = ".build"
go test -tags integration .\tests\integration
go test -tags e2e .\tests\e2e
```
