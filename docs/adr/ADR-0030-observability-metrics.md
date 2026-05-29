# ADR-0030: Extended Observability Metrics

## Status

Accepted

## Decision

Packmon exposes metrics for feed freshness, queue health, degraded responses, login failures, HTTP request volume/duration, scan totals, current finding totals, PostgreSQL pool gauges, and schema version.

## Rationale

- feed staleness is an operational risk
- async queue issues must be visible without inspecting the database
- degraded API responses should be measurable over time
- API latency, scan volume, queue size, and database pool pressure are core operational signals

## Consequences

- alerting is expected to happen in Prometheus and Alertmanager, not inside Packmon
- a small set of runtime counters is kept in-process for operational visibility
- store-derived gauges are calculated at scrape time to avoid duplicate state
