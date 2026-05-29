# Agent Guide -- Telemetry & Metrics

Scope: `internal/telemetry/` -- the hand-rolled Prometheus text exposition,
HTTP metrics middleware, and the `/metrics` handler. Primary owner agent:
**platform-ci-engineer**; coordinate with backend-engineer for store-derived
series.

Read `AGENTS.md` (root) and `docs/adr/ADR-0030-observability-metrics.md` and
`docs/runbook.md` (metric names) first.

## Invariants (do not break)

- The metric names in DESIGN.md sec 3.9 / runbook are a contract (dashboards and
  alerts depend on them). Keep the 17 spec'd series and their label sets stable.
- This is a hand-rolled registry, not `prometheus.MustRegister` -- map writes are
  guarded by a mutex and per-key counters use `atomic`. Keep new series
  thread-safe (RLock fast path, Lock + re-check).
- Metrics bind to localhost by default and must not be exposed to untrusted
  networks. The `/metrics` mux has no auth middleware by design (separate port).
- LABEL CARDINALITY IS A SECURITY CONCERN. Never put unbounded, attacker-
  controlled values (raw request paths, package names, IPs) into a label.

## Current open landmines (see Audit.md)

> Status (2026-05-29): the items in this section were addressed across the
> Audit.md "Fix-Runde" passes. Audit.md is authoritative; project-wide only the
> external GitLab-runner test remains open. Keep the notes below as guardrails
> so the fixes are not regressed.

- **H2:** `HTTPMiddleware` falls back to the raw `r.URL.Path` as the `route`
  label when `r.Pattern` is empty (i.e. on 404s). An unauthenticated scanner can
  create unbounded series and exhaust memory. Bucket unmatched routes to a
  constant (e.g. `"__unmatched__"`). This is the top fix here.
- **L2:** `MetricsHandler` discards every store error (`_`) and has no logger, so
  DB outages are masked. Plumb the logger and log a WARN per failed store call.
- **Design:** `ScanTotals`/`DBPoolStats` are obtained via type assertion on the
  concrete Postgres store, not via the `db.Store` interface -- those series
  silently vanish for any other store. Prefer promoting them to the interface.

## Tests

```bash
go test ./internal/telemetry/...
```
Add a test asserting unmatched routes collapse to one label, plus label-escaping
for values containing quotes/backslashes.
