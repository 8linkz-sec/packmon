# PostgreSQL Query Observability

Packmon schema version 48 requires `pg_stat_statements`. The repository
Compose stacks also enable PostgreSQL I/O timing and log statements that take
at least one second by default. These controls provide historical, normalized
query timings without granting the Packmon runtime role elevated privileges.

## Bundled Compose PostgreSQL

The Compose files configure these PostgreSQL settings at process startup:

- `shared_preload_libraries=pg_stat_statements`
- `compute_query_id=on`
- `track_io_timing=on`
- `pg_stat_statements.track=top`
- `pg_stat_statements.track_utility=off`
- `pg_stat_statements.max=5000`
- `log_min_duration_statement=1000`
- `log_parameter_max_length=0`
- `log_parameter_max_length_on_error=0`
- `log_statement=none`

Recreate the PostgreSQL container after updating because preload changes take
effect only when PostgreSQL starts. The named database volume remains intact.
Then run `packmon-server migrate` through the applicable Compose migration
service. Migration 48 creates the extension in the Packmon database.

`PACKMON_POSTGRES_TRACK_IO_TIMING=off` disables I/O timing if measurements on
the target platform show unacceptable timing-call overhead.
`PACKMON_POSTGRES_SLOW_QUERY_MS` changes the slow-query threshold in
milliseconds; `-1` disables slow-query logging.

## External PostgreSQL

An external database administrator or managed-service administrator must do
all of the following before Packmon migration 48 runs:

1. Add `pg_stat_statements` to `shared_preload_libraries` and restart the
   PostgreSQL service.
2. Set `compute_query_id` to `on` or `auto`; it must not be `off`.
3. Enable `track_io_timing` if per-query I/O timings are required.
4. Run `CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA public;`
   while connected to the Packmon database. Packmon requires this extension
   schema so diagnostics do not depend on an operator-specific `search_path`.

Do not make the Packmon application or migration role a superuser. The
migrator accepts an extension pre-created by an administrator. If the
extension is not installed, only the initialization superuser used by the
bundled Compose database may create it during migration.

Verify the setup in the Packmon database:

```sql
SHOW shared_preload_libraries;
SHOW compute_query_id;
SHOW track_io_timing;

SELECT extversion
FROM pg_extension
WHERE extname = 'pg_stat_statements';

SELECT COUNT(*)
FROM public.pg_stat_statements(false);
```

The migration prerequisite runs before Packmon records a migration as dirty.
A missing preload, disabled query ID, unavailable extension, or missing
administrator preparation therefore leaves the previous schema version clean
and retryable.

## Query-ID-First Diagnosis

Start without retrieving statement text. Treat the complete
`(dbid, userid, queryid, toplevel)` tuple as the entry identity:

```sql
SELECT dbid,
       userid,
       queryid,
       toplevel,
       calls,
       total_exec_time,
       mean_exec_time,
       rows,
       shared_blks_hit,
       shared_blks_read,
       temp_blks_read,
       temp_blks_written,
       blk_read_time,
       blk_write_time
FROM public.pg_stat_statements(false)
WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
ORDER BY total_exec_time DESC
LIMIT 20;
```

Check whether entries have been evicted before interpreting a time window:

```sql
SELECT dealloc, stats_reset
FROM public.pg_stat_statements_info;
```

Only after identifying a relevant tuple should an authorized operator retrieve
its `query` from `public.pg_stat_statements(true)`. PostgreSQL restricts other
users' query text and query identifiers to superusers and roles with
`pg_read_all_stats`. Query identifiers are not guaranteed to remain stable
across PostgreSQL major versions, so do not use them as permanent application
identifiers.

## Log Data Boundary

Setting `log_parameter_max_length=0` prevents bind-parameter values from being
included in normal slow-statement log entries. It does not redact SQL text.
Ad hoc SQL that embeds literal values can therefore place those values in the
PostgreSQL log. Restrict Docker log access to operators, keep application SQL
parameterized, and preserve the Compose rotation limit (`10m` times five
files). The statistics view can expose representative query text to privileged
operators. PostgreSQL usually replaces constants for aggregation, but text can
occasionally retain literals, particularly when entries are repeatedly
deallocated. Treat statistics text with the same operator-only sensitivity as
slow-query logs; access to database statistics is an operational privilege.
