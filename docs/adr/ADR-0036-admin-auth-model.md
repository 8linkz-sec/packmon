# ADR-0036: Shared Admin Auth Model

## Status

Accepted

## Decision

Packmon uses one shared admin identity, bcrypt password storage, CSRF-protected
admin write forms, and in-memory admin sessions.

## Rationale

- Packmon is internal tooling with a small operator group.
- A shared admin account keeps the first production deployment simple.
- The audit log records administrative actions even without per-user accounts.
- In-memory sessions avoid adding another persistent session table to the
  current single-server design.

## Consequences

- Audit attribution is to the shared admin identity plus source IP and action
  details, not to individual user accounts.
- Horizontal server replicas require a separate session design.
- Per-user accounts, OIDC, SAML, or server-backed sessions are future design
  changes that must update `DESIGN.md` and `SECURITY.md`.
