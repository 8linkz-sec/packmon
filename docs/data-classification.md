# Data Classification

Packmon stores internal security-scanner data, not arbitrary repository source
code. This map summarizes where data lives and which controls apply.

| Data class | Location | Sensitivity | Controls |
|---|---|---|---|
| Advisory, malicious package, lifecycle, and reputation records | PostgreSQL; synced subset in SQLite | Internal operational data | Normalized at import, source-attributed, backed up with PostgreSQL, compact subset exposed through sync. |
| API key secrets | One-time admin response only | Secret | Never stored plaintext; hashed at rest; shown only at creation; expire within 90 days; revocable and soft-deletable. |
| API key metadata | PostgreSQL admin tables and admin UI | Sensitive audit metadata | Names bounded; lifecycle timestamps retained for audit; protected by admin session. |
| Feed provider API keys | PostgreSQL encrypted fields; deployment secret source | Secret | Encrypted with `PACKMON_ENCRYPTION_KEY`; never rendered after save; audit records configured/not-configured only. |
| `PACKMON_ENCRYPTION_KEY` | Deployment secret manager | Secret | Required in production; backed up with the recovery set; not stored in Packmon source or database. |
| Admin password hash and sessions | PostgreSQL for password hash; process memory for sessions | Secret-derived/auth state | Bcrypt password hash; HttpOnly admin cookie; CSRF on writes; sessions tied to the single-server model. |
| Admin audit log | PostgreSQL | Sensitive audit evidence | Includes action, source IP, details, timestamps, digest chain; retention-controlled. |
| Scan log rollup | PostgreSQL | Internal operational metadata | Stores scan ID, optional path-minimized repo name, package/finding counts, decision evidence, correlation ID, digest, and API-key metadata. |
| Local scan history | SQLite | Local developer metadata | Compact repository name, branch, commit, counts, finding IDs, and timestamps; local retention controls. |
| Refresh queue jobs | PostgreSQL | Internal operational metadata | Package coordinates, source, status, priority, retry/error state; admin mutations are audit logged. |
| Logs | Server stdout/stderr or deployment log sink | Operational metadata | Must not contain secrets, full environment values, file contents, or full local paths. |
| Metrics | Metrics listener | Operational metadata | Unauthenticated by design; localhost by default; no secrets or raw package lists. |
| Web/admin surfaces | Server-rendered pages | Mixed internal/admin data | Public dashboard is internal-view only; admin actions require session and CSRF. |
