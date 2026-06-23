# Agent Guide -- Telemetry & Metrics

Scope: `internal/telemetry/` -- the hand-rolled Prometheus text exposition,
HTTP metrics middleware, and the `/metrics` handler. Primary owner agent:
**platform-ci-engineer**; coordinate with backend-engineer for store-derived
series.

Read `AGENTS.md` (root), `DESIGN.md`, and `SECURITY.md` first.

## Invariants (do not break)

- The metric names in DESIGN.md are a contract (dashboards and alerts depend on
  them). Keep the documented series and their label sets stable.
- This is a hand-rolled registry, not `prometheus.MustRegister` -- map writes are
  guarded by a mutex and per-key counters use `atomic`. Keep new series
  thread-safe (RLock fast path, Lock + re-check).
- Metrics bind to localhost by default and must not be exposed to untrusted
  networks. The `/metrics` mux has no auth middleware by design (separate port).
- LABEL CARDINALITY IS A SECURITY CONCERN. Never put unbounded, attacker-
  controlled values (raw request paths, package names, IPs) into a label.

## Current Guardrails

These notes are guardrails for behavior that has regressed before. Keep them in
sync with `DESIGN.md` and `SECURITY.md` when the behavior intentionally changes.

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
