# Architecture Decision Records

This index lists the accepted Packmon ADRs that are currently tracked in this
repository. Numbering continues from earlier private design history; missing
numbers before ADR-0028 are intentional and are not required for this source
tree to be complete.

| ADR | Status | Area | Decision |
|---|---|---|---|
| [ADR-0028](ADR-0028-backup-restore.md) | Accepted | Operations | Daily `pg_dump` backups with 7-day local retention. |
| [ADR-0029](ADR-0029-metrics-localhost.md) | Accepted | Operations | Metrics bind to localhost by default. |
| [ADR-0030](ADR-0030-observability-metrics.md) | Accepted | Observability | Packmon exposes feed, queue, DB, auth, HTTP, scan, and finding metrics. |
| [ADR-0031](ADR-0031-stale-data-warnings.md) | Accepted | CLI | Stale local data warns instead of blocking scans. |
| [ADR-0032](ADR-0032-logging-rules.md) | Accepted | Security | Persistent server logs avoid paths, file contents, and secrets. |
| [ADR-0033](ADR-0033-deployment-packaging-boundary.md) | Accepted | Deployment | The maintained deployment surface is Compose, release binaries, CI templates, and N8N assets. |
| [ADR-0034](ADR-0034-persistence-boundaries.md) | Accepted | Persistence | Server data belongs in PostgreSQL; local CLI cache belongs in SQLite synced from Packmon. |
| [ADR-0035](ADR-0035-postgres-refresh-queue.md) | Accepted | Feeds | Async reputation/enrichment work uses a PostgreSQL-backed refresh queue. |
| [ADR-0036](ADR-0036-admin-auth-model.md) | Accepted | Admin auth | Packmon uses one shared admin identity and in-memory admin sessions. |
| [ADR-0037](ADR-0037-web-ui-stack.md) | Accepted | Web UI | The UI uses Go templates, htmx, Tailwind, local assets, and binary embedding. |
