# ADR-0028: Backup And Restore

## Status

Accepted

## Decision

Packmon uses daily `pg_dump --format=custom` archive backups with 7-day local
retention.

## Rationale

- simple to operate on small installations
- sufficient for Packmon's data profile
- avoids WAL archiving and point-in-time complexity

## Consequences

- restore is file-based via `pg_restore` into a clean recreated database
- RPO is roughly 24 hours
- RTO (Recovery Time Objective) is operator-defined per deployment; the
  repository-provided Compose model has no built-in standby or automated
  failover target
- external long-term backup remains the operator's responsibility
