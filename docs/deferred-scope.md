# Deferred Scope

This fork is currently used without GitLab, CI/CD pipelines, or release-binary
distribution workflows. The source-build and local Windows usage path remains
in scope.

The following audit categories are intentionally deferred and are not current
release blockers for this fork:

- GitLab shared CI template hardening;
- real GitLab runner validation;
- CI/CD branch-protection and required-check enforcement;
- GitHub Actions runner-label reproducibility findings that only affect hosted
  CI execution.
- optional account-gated provider integrations that are not enabled in this
  fork, including ReversingLabs, Socket.dev private refresh, VulnCheck
  account-gated flows, NVD API-key rate-limit paths, and N8N feed-import
  workflows.

Core no-key public feed behavior remains in scope. Optional provider findings
must be re-opened before storing provider API keys, enabling provider workers,
or routing feed imports through N8N.

## Local-First Deployment Scope

The current deployment priority is local Windows use through the repository's
Docker Compose helper, with the option to evolve into a server/agent setup
later.

Current local scope:

- `docker compose run --rm init-secrets` followed by `docker compose up` starts
  PostgreSQL, runs migrations automatically, and starts `packmon-server`;
- the admin UI and API are reachable through `http://localhost:8080`;
- metrics are reachable locally through `127.0.0.1:9090`;
- the CLI/agent can scan against the local server with
  `--insecure-allow-http --require-remote`;
- Compose port mappings, Docker healthchecks, local migrations, and local
  metrics reachability remain in scope and should not be deferred.

Deferred until a shared or remote server/agent deployment exists:

- in-app TLS, internal CA distribution, and TLS listener hardening;
- TLS-terminating reverse proxy behavior, `PACKMON_TRUSTED_PROXIES`, and
  `X-Forwarded-*` handling in a real proxy topology;
- Prometheus/Alertmanager rule files, SLO buckets, service identity metrics,
  and production monitoring escalation;
- production backup encryption, restore drills, RTO evidence, and off-host
  retention;
- production rollout/rollback operations beyond the local Compose smoke path;
- capacity/scaling work for long-running shared server deployments;
- production log aggregation fields, Docker log rotation, and shared-host
  metrics exposure hardening.

## Not Deferred

Privacy, legal, and compliance impacts for future colleague use are not deferred
solely because the current deployment is local. Items covering privacy notices,
employee-identifying scan metadata, retention, transparency, or compliance
decision inputs remain reviewable before Packmon is used by colleagues. Shared
server operational controls may still be scheduled for the server/agent rollout,
but the affected people and disclosure requirements are not treated as
irrelevant.

Re-open these items before any of the following becomes true:

- another repository consumes `ci/gitlab/.packmon-scan.yml`;
- Packmon scans are used as a required CI security gate;
- Packmon is exposed to other machines as a shared server;
- agents connect over a real network instead of loopback;
- Prometheus or another monitoring stack scrapes Packmon in an operator
  environment;
- production backups or restore objectives are required.
- any optional provider API key or N8N feed-import workflow is enabled;
- Packmon is rolled out to colleagues or used with employee-identifying scan
  metadata.

Deferred does not mean fixed. It means the risk is accepted for the current
operator workflow because the affected delivery surface is not used. If the
surface is introduced later, the corresponding `Todo.txt` items must be
re-evaluated before rollout.
