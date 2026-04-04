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

### Metrics are unreachable remotely

Expected behavior. Metrics are bound to localhost by default.

Use SSH tunneling, node-local Prometheus, or a PodMonitor/sidecar pattern instead of exposing the metrics port publicly.
