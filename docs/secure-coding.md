# Secure Coding and Security Awareness

This guide is the contributor-facing security baseline for Packmon. Contributors review this guide during onboarding and before making security-sensitive changes.

## When to Treat a Change as Security-Sensitive

A change is security-sensitive when it touches any of these areas:

- authentication, authorization, CSRF, sessions, or API keys;
- feed import, webhook, admin, or manual advisory write paths;
- database migrations, audit logs, scan decisions, or finding normalization;
- logs, metrics, errors, CI artifacts, or report output;
- dependency and feed-provider changes, including registry clients and optional
  third-party tools;
- deployment, TLS, proxy trust, backup, restore, or release packaging behavior.

For these changes, read the relevant threat model in `SECURITY.md`, keep
implementation and canonical documentation in the same change, and add a
regression test for the failure mode being fixed.

## Secure Development Checklist

- Preserve fail-closed behavior for malware and active supply-chain risk
  findings.
- Keep API keys, webhook secrets, passwords, secrets, file contents, full paths, or environment values out of persistent logs, metrics, errors, and generated artifacts.
- Validate untrusted input at the boundary with explicit size, enum, and shape
  checks before database writes or expensive work.
- Use parameterized SQL and existing store helpers; never concatenate user input
  into queries.
- Keep trusted proxy handling explicit. Do not trust `X-Forwarded-*` or
  `X-Real-IP` unless the direct peer is configured as trusted.
- Keep web assets local to the repository or binary. Do not add CDN runtime
  dependencies.
- Update `DESIGN.md` for requirement or data-flow changes and `SECURITY.md` for
  auth, trust-boundary, logging, crypto, dependency, admin, or exposure changes.
- Run the smallest security validation commands that prove the change, and list
  them in the PR.

## Awareness Expectations

Contributors are expected to understand Packmon's threat model before changing
security-sensitive code. At minimum, review:

- `SECURITY.md` for trust boundaries, logging rules, admin controls, and the
  security review checklist;
- `AGENTS.md` and subsystem `AGENTS.md` files for local invariants;
- `CONTRIBUTING.md` for workflow and validation expectations;
- relevant tests in `tests/ci`, `tests/integration`, or package-local test files.

Security validation commands should match the risk of the change. Examples
include focused package tests, `go test -count=1 ./tests/ci`, `go vet ./...`,
`govulncheck`, and `gosec` with the repository's documented flags.
