# ADR-0031: Stale Data Warnings In The CLI

## Status

Accepted

## Decision

Local scans are never blocked because of stale data. Instead, the CLI surfaces warnings and includes freshness fields in JSON output.

## Rationale

- scanning with stale data is still better than not scanning
- CI and automation can decide how to react to `db_stale=true`

## Consequences

- terminal output warns when the local DB age crosses the configured threshold
- JSON output includes `db_age_days` and `db_stale`
