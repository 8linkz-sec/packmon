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
- Production `POST /api/v1/feeds/{feed}/import` also requires the dedicated
  `X-Packmon-Feed-Import-Secret` header configured by
  `PACKMON_FEED_IMPORT_SECRET`; a scan/sync API key alone must not mutate feed
  data.
- Transport is fail-closed in production (`Config.ValidateTransportSecurity`,
  called from `cmd/packmon-server/main.go`): the server refuses to start unless
  in-app TLS (`PACKMON_TLS_CERT_FILE` + `PACKMON_TLS_KEY_FILE`),
  `PACKMON_TRUSTED_PROXIES`, or the loopback `PACKMON_ALLOW_INSECURE_LOCAL_HTTP`
  override is set. In-app TLS uses `ListenAndServeTLS` with a configurable
  `MinVersion` (default 1.2); otherwise plain `ListenAndServe`. Do not weaken
  this guard.
- Session cookies: `HttpOnly`, `SameSite=Strict`, `Secure` outside dev mode
  except the explicit local Docker `PACKMON_ALLOW_INSECURE_LOCAL_HTTP` override.
  Session IDs are 256-bit `crypto/rand`. CSRF token on every admin POST,
  compared with `crypto/subtle.ConstantTimeCompare`.
- Never log API keys, tokens, passwords, or full file paths.

## Current Guardrails

These notes are guardrails for behavior that has regressed before. Keep them in
sync with `DESIGN.md` and `SECURITY.md` when the behavior intentionally changes.

- **H3:** dev mode skips most `/api/v1/*` API-key checks for local integration
  tests, but package refresh and feed imports are unauthenticated only from a
  loopback peer; non-loopback callers still need API-key auth, and production
  feed imports also require the feed-import secret. If you touch auth or
  routes, keep `requiresAuthInDev` and its loopback exception intact.
- **M8:** the pre-auth login form may create only the minimum session state
  needed for CSRF. Do not mark a session admin-authenticated until credentials
  have been verified, and keep session mutation concurrency-safe.
- **L3:** API-key authentication uses hashed lookup; any direct secret
  comparison must stay constant-time via `crypto/subtle`.
- **L4:** `X-Forwarded-Proto` HTTPS redirects must remain trusted-proxy-gated in
  the same boundary as XFF/X-Real-IP handling.

## Tests

Add a failing-first regression test for any auth/trust change. Negative cases
matter most: malformed/spoofed XFF from an untrusted peer, all-trusted chains,
IPv6, missing port in `RemoteAddr`.

```bash
go test -race ./internal/server/...
```
