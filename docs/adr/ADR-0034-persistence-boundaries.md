# ADR-0034: Persistence Boundaries

## Status

Accepted

## Decision

Packmon uses PostgreSQL as the canonical server store and SQLite as the local
CLI cache. The CLI syncs local data only from the Packmon server.

## Rationale

- PostgreSQL provides durable server-side storage for feed data, admin state,
  audit rows, queue jobs, scan logs, and migrations.
- SQLite gives the CLI a compact local database for offline and auto-fallback
  scans.
- Routing local sync through Packmon keeps public feed access, normalization,
  enrichment, provenance, and policy on the server side.

## Consequences

- Production server deployments need PostgreSQL backup and restore procedures.
- Local SQLite contains enough synced data for scan decisions, not full server
  feed detail.
- The CLI must not add direct sync paths to OSV, GHSA, OpenSSF, VulnCheck,
  Socket.dev, ReversingLabs, CISA KEV, EPSS, NVD, endoflife.date, or public
  registries.
