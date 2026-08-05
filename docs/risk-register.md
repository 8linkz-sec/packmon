# Risk Assessment and Treatment Register

This lightweight register records Packmon's main security and operational risks,
current controls, owner, treatment, residual risk, and Review cadence. Review it
at least quarterly and whenever `DESIGN.md`, `SECURITY.md`, deployment exposure,
or feed-provider behavior changes.

| Risk ID | Scenario | Owner | Current controls | Treatment | Residual risk |
|---|---|---|---|---|---|
| R-001 | shared admin identity is misused or cannot be attributed to one human operator | Operator | Admin access is intended for internal deployments, audit logs record admin actions, and `SECURITY.md` requires a reverse proxy or IdP with MFA/SSO for regulated/shared production. | Mitigate with external MFA/SSO, restricted listener exposure, and periodic audit review. | Medium |
| R-002 | feed-provider compromise or outage causes stale, missing, or misleading findings | Maintainer | Multiple feeds are separated by source, feed health is surfaced, and malicious/supply-chain risk findings fail closed when present. | Mitigate with source attribution, health alerts, supplier review, and operator-visible degraded state. | Medium |
| R-003 | public exposure of internal services, admin routes, or metrics | Operator | Metrics bind localhost by default, production API routes require API keys and User-Agent policy, and trusted proxy handling is explicit. | Mitigate with network policy, reverse proxy configuration review, and deployment hardening checks. | Low |
| R-004 | secret or log disclosure through errors, reports, metrics, or artifacts | Maintainer | Logging rules forbid API keys, env values, file contents, and full paths; tests cover redaction-sensitive paths. | Mitigate with code review, secure-coding checklist, and secret scanning in CI. | Low |
| R-005 | database migration or rollback failure affects availability | Maintainer | Migrations are explicit operational steps, versioned, checksummed, and tested with up/down coverage. | Mitigate with backup/restore runbook, migration review, and production dry-run where practical. | Medium |

## Review cadence

- Quarterly: review open risks, residual risk, and owners.
- Release-facing changes: review entries touched by auth, feed, migration,
  deployment, or logging changes.
- Incident follow-up: add or update a risk entry when a control gap is found.
