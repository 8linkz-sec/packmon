# ADR-0035: PostgreSQL Refresh Queue

## Status

Accepted

## Decision

Packmon uses a PostgreSQL-backed `refresh_queue` table plus in-process workers
for async Socket.dev and ReversingLabs enrichment work.

## Rationale

- The queue needs durable deduplication, retry state, pause/resume controls,
  auditability, and metrics.
- PostgreSQL is already required for the server and keeps the maintained
  deployment model small.
- An external broker would add an operator dependency that is not needed for
  the default single-server design.

## Consequences

- Queue workers run in the server process and must honor graceful shutdown.
- Scaling multiple server replicas requires a separate HA design for worker
  ownership, session behavior, and migration ordering.
- Query performance and retention for queue rows are operational concerns.
