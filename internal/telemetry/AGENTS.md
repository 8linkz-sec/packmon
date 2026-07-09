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

- **H2:** `HTTPMiddleware` must keep unmatched routes bucketed under the
  constant `"__unmatched__"` when `r.Pattern` is empty. Never reintroduce raw
  `r.URL.Path` as a metrics label for 404s.
- **L2:** `MetricsHandler` must keep logging bounded WARN records for failed
  store-derived metric reads. Do not silently discard DB errors during metrics
  scrapes.
- **Design:** `ScanTotals`/`DBPoolStats` are obtained via type assertion on the
  concrete Postgres store, not via the `db.Store` interface -- those series
  silently vanish for any other store. Prefer promoting them to the interface.

## Tests

```bash
go test -count=1 ./internal/telemetry/...
```
Add a test asserting unmatched routes collapse to one label, plus label-escaping
for values containing quotes/backslashes.
