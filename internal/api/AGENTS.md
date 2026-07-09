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
- Malicious AND `supply_chain_risk` findings always block, regardless of the
  severity threshold (`isBlocking` / scanner `hasBlockingFindings`).
  Vulnerability blocking uses the configured severity threshold; `SeverityNone`
  disables vuln blocking only. Severity ordering lives in `internal/domain`
  (`Rank()`/`Blocks()`) -- reuse it, do not re-implement comparisons.
- `POST /api/v1/.../refresh`: body is optional and must be an empty JSON object;
  `version` is not accepted.
- `X-Correlation-ID`: read from request, generate if absent, echo on response,
  thread into logs and the scan-log context.
- Feed name `malicious` is accepted as an alias and normalized to `openssf`.
- Every admin write handler must be: auth-checked (`requireAdmin` +
  `RequireAdminSession`), CSRF-validated, form-size-capped, and audit-logged.

## Current Guardrails

These notes are guardrails for behavior that has regressed before. Keep them in
sync with `DESIGN.md`, `SECURITY.md`, and the OpenAPI contract when the behavior
intentionally changes.

- **M2:** saved system settings apply immediately through the runtime config for
  block threshold and rate limits, and are persisted for startup reload. Keep
  the in-memory update atomic with the database write, and keep the admin UI
  message aligned with that behavior.
- **M4:** manual advisory create/update must keep server-side allow-list
  validation for `finding_type`, `severity`, `ecosystem`, bounded field lengths,
  and the `manual:` ID namespace. Do not rely on HTML form controls alone.
- **L10:** the handler correlation-ID fallback accepts arbitrary header values
  while the middleware enforces UUIDv4. Prefer the middleware context value.

## Tests

```bash
go test -count=1 ./internal/api/...
```
Cover negative paths: oversize body, bad severity, missing CSRF, unauthenticated
admin write, refresh-with-version (must 400).
