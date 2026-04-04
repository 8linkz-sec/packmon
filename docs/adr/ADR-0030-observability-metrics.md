# ADR-0030: Extended Observability Metrics

## Status

Accepted

## Decision

Packmon exposes additional metrics for feed freshness, queue health, degraded responses, login failures, and schema version.

## Rationale

- feed staleness is an operational risk
- async queue issues must be visible without inspecting the database
- degraded API responses should be measurable over time

## Consequences

- alerting is expected to happen in Prometheus and Alertmanager, not inside Packmon
- a small set of runtime counters is kept in-process for operational visibility
