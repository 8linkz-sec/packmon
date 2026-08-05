# Packmon Architecture

This file is a concise architecture map. `DESIGN.md` remains the canonical
product and requirements baseline.

Supporting artifacts:

- `docs/architecture/system-context.mmd`: system-boundary diagram.
- `docs/adr/README.md`: accepted architecture decision index.
- `docs/data-classification.md`: data classes, storage locations, and controls.

## Runtime Surfaces

Packmon has two main runtime surfaces:

- `packmon`: the CLI that reads repositories, parses lockfiles and SBOM files,
  produces reports, and checks findings through the server or local SQLite.
- `packmon-server`: the central API/web process that owns feed synchronization,
  PostgreSQL persistence, admin workflows, package checks, sync export, metrics,
  and web pages.

The CLI owns repository filesystem access. The server receives package lists and
metadata, not source files or lockfile contents.

```text
Developer or CI workspace
  -> packmon CLI
     -> parsers / SBOM import / scanner
     -> remote /api/v1/check or local SQLite
     -> terminal output, JSON, SARIF, JUnit, HTML, optional webhook

Feed sources and N8N imports
  -> packmon-server
     -> PostgreSQL normalized feed tables
     -> API checks, SQLite sync export, web UI, metrics
```

The Mermaid diagram in `docs/architecture/system-context.mmd` shows the same
surfaces with actors, stores, external inputs, and trust boundaries.

## Persistence

PostgreSQL is the server persistence layer for normalized advisories, malicious
findings, lifecycle data, package reputation, feed status, refresh queue state,
scan logs, admin auth, API keys, and manual advisories.

SQLite is the local CLI cache for offline and auto-fallback mode. Local data is
synced only from the Packmon server through `/api/v1/sync`; the CLI does not
sync directly from public vulnerability feeds.

## Deployment Model

Packmon is an internal service, not a public SaaS. The maintained deployment
surfaces are:

- `docker-compose.yml` at the repository root for local and internal
  self-hosted container starts;
- `deploy/n8n` for automation workflows that call Packmon APIs;
- GitHub Actions and GitLab CI templates for consumer repository scans;
- binary artifacts from the release workflow.

The repository does not maintain first-party Kubernetes deployment packaging.
Teams that run Packmon on an orchestrator own those manifests or platform
templates. They must preserve the documented operational boundaries:

- database migrations are explicit operator actions;
- production startup requires in-app TLS or a trusted TLS-terminating proxy;
- metrics stay on localhost unless protected by explicit network controls;
- PostgreSQL backup and restore are operator-owned `pg_dump`/`pg_restore`
  procedures;
- platform secrets are supplied by the deployment environment, not by Packmon
  source files;
- multiple server replicas require a separate HA design for sessions,
  background workers, migrations, and queue processing.

## Trust Boundaries

API and admin writes are authenticated in production. Health, readiness,
version, and local metrics endpoints are operational exceptions.

Forwarded headers are trusted only from configured trusted proxies. Repository
content is untrusted input to the CLI parsers and report generation. Feed data
is untrusted input to normalizers and persistence. Logs and metrics must not
retain secrets, full environment values, file contents, or full local paths.

## Extension Points

New package ecosystems should enter through parser, domain, OpenAPI, server,
SQLite sync, and report changes together. New feed sources should normalize into
the existing vulnerability, malicious, reputation, or lifecycle models instead
of creating a separate scan result shape. New deployment integrations should
consume the same authenticated APIs and preserve the server-side feed boundary.
