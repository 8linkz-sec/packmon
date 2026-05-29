# Agent Guide -- HTTP Server & Middleware

Scope: `internal/server/` (server.go, routes.go) and `internal/server/middleware/`
(auth, clientip, correlation, csrf via `internal/auth`, logging, ratelimit,
recovery, securityheaders, session, useragent). Primary owner agent:
**security-engineer**; coordinate with backend-engineer for routing.

Read `AGENTS.md` (root) and `SECURITY.md` first. This file only adds
subsystem-specific rules. Do not duplicate the root.

## Middleware order is load-bearing

`clientip` resolves the trusted client IP and must run **outermost** so the rate
limiter, audit logging, and security headers all read the resolved IP from
context (`ClientIP(r)`), not `r.RemoteAddr`. Verify the wrap order in
`server.go` before adding or reordering middleware.

## Invariants (do not break)

- `X-Forwarded-For` / `X-Real-IP` are honored ONLY when the direct peer is in
  `PACKMON_TRUSTED_PROXIES`. XFF selection is rightmost-untrusted. Never trust
  forwarded headers from an untrusted peer (`clientip.go`).
- Production `/api/v1/*` requires a Bearer API key (SHA-256 hashed lookup).
  Health/version/metrics are the only API-namespace exemptions.
- Session cookies: `HttpOnly`, `SameSite=Strict`, `Secure` outside dev mode.
  Session IDs are 256-bit `crypto/rand`. CSRF token on every admin POST,
  compared with `crypto/subtle.ConstantTimeCompare`.
- Never log API keys, tokens, passwords, or full file paths.

## Current open landmines (see Audit.md)

> Status (2026-05-29): the items in this section were addressed across the
> Audit.md "Fix-Runde" passes. Audit.md is authoritative; project-wide only the
> external GitLab-runner test remains open. Keep the notes below as guardrails
> so the fixes are not regressed.

- **H3:** dev mode currently skips auth for ALL `/api/v1/*`, including the
  data-mutating `feeds/import`. If you touch `auth.go`, restore a
  write-endpoint guard rather than widening the bypass.
- **M8:** `GET /admin/login` mints a stored 8h session per visit and mutates the
  `Admin` flag without a lock. Do not copy this pattern; prefer a stateless
  signed CSRF token for pre-auth forms.
- **L3:** Bearer key compare is not constant-time. Use `subtle` for new secret
  comparisons.
- **L4:** `X-Forwarded-Proto` (HTTPS redirect) is not gated by the trusted-proxy
  check. Gate it the same way as XFF if you rework SecurityHeaders.

## Tests

Add a failing-first regression test for any auth/trust change. Negative cases
matter most: malformed/spoofed XFF from an untrusted peer, all-trusted chains,
IPv6, missing port in `RemoteAddr`.

```bash
go test -race ./internal/server/...
```
