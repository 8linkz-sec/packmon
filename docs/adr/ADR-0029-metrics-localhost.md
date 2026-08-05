# ADR-0029: Metrics Are Localhost Only

## Status

Accepted

## Decision

The metrics listener binds to `127.0.0.1` by default.

## Rationale

- operational metrics should not be internet-facing
- Prometheus can scrape locally on the host or inside the cluster
- avoids accidental exposure of internal state

## Consequences

- operators need local scrape access or Kubernetes-native monitoring
- metrics are not published through the public service or ingress
