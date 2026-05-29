# Agent Guide -- API Handlers (v1 + admin)

Scope: `internal/api/v1/` (public scan/refresh/feeds API) and
`internal/api/admin/` (login-protected admin handlers, forms, runtime config).
Primary owner agent: **backend-engineer**; coordinate with security-engineer for
admin auth and frontend-engineer for the templates these handlers render.

Read `AGENTS.md` (root), `DESIGN.md`, and the OpenAPI spec
`api/openapi/packmon-v1.yaml` first. The OpenAPI contract and the handler must
not drift -- update both in the same change.

## Invariants (do not break)

- `POST /api/v1/check` caps at 5000 packages, uses strict JSON decoding
  (`DisallowUnknownFields`, reject trailing data, `MaxBytesReader`), and returns
  the canonical scan-result shape shared with CLI JSON output and webhooks.
- Malicious findings always block. Vulnerability blocking uses the configured
  severity threshold; `SeverityNone` disables vuln blocking only. Severity
  ordering lives in `internal/domain` (`Rank()`/`Blocks()`) -- reuse it, do not
  re-implement comparisons.
- `POST /api/v1/.../refresh`: body is optional and must be an empty JSON object;
  `version` is not accepted.
- `X-Correlation-ID`: read from request, generate if absent, echo on response,
  thread into logs and the scan-log context.
- Feed name `malicious` is accepted as an alias and normalized to `openssf`.
- Every admin write handler must be: auth-checked (`requireAdmin` +
  `RequireAdminSession`), CSRF-validated, form-size-capped, and audit-logged.

## Current open landmines (see Audit.md)

> Status (2026-05-29): the items in this section were addressed across the
> Audit.md "Fix-Runde" passes. Audit.md is authoritative; project-wide only the
> external GitLab-runner test remains open. Keep the notes below as guardrails
> so the fixes are not regressed.

- **M2:** block threshold and rate limits are captured once at construction;
  saved system settings do NOT take effect until restart. If you make them
  hot-reloadable, do it atomically and update the admin UI message.
- **M4:** advisory create/edit does not validate `severity`/`ecosystem`/
  `finding_type` server-side. Add allow-list validation; an invalid severity
  ranks 0 and silently never blocks.
- **L10:** the handler correlation-ID fallback accepts arbitrary header values
  while the middleware enforces UUIDv4. Prefer the middleware context value.

## Tests

```bash
go test ./internal/api/...
```
Cover negative paths: oversize body, bad severity, missing CSRF, unauthenticated
admin write, refresh-with-version (must 400).
