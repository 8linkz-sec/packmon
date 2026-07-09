# ADR-0033: Deployment Packaging Boundary

## Status

Accepted

## Decision

Packmon maintains repository-root Docker Compose, binary release artifacts,
GitHub/GitLab CI templates, and N8N automation assets. It does not maintain
first-party orchestrator packaging.

## Rationale

- Packmon is internal tooling, not a public SaaS.
- Compose keeps the supported migration, PostgreSQL, secret, metrics, and
  local HTTP invariants visible in one place.
- Release binaries and CI templates cover the scanner-agent path without
  requiring a maintained container registry.
- Orchestrator deployments vary by organization and need platform-owned
  networking, secrets, probes, and backup controls.

## Consequences

- Operators that deploy on an orchestrator own those manifests.
- Deployment changes must preserve explicit migrations, TLS/proxy handling,
  metrics exposure controls, secret management, backups, and the single-server
  architecture unless a separate HA design is added.
- The release workflow publishes binary artifacts and related provenance, not a
  first-party container image.
