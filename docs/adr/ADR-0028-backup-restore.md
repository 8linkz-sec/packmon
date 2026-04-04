# ADR-0028: Backup And Restore

## Status

Accepted

## Decision

Packmon uses daily `pg_dump` backups with 7-day local retention.

## Rationale

- simple to operate on small installations
- sufficient for Packmon's data profile
- avoids WAL archiving and point-in-time complexity

## Consequences

- restore is file-based via `pg_restore`
- RPO is roughly 24 hours
- external long-term backup remains the operator's responsibility
