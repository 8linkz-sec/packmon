# Contributing

Packmon is a dependency security scanner for lock files: a cross-platform CLI
plus a central API/web server. `README.md` explains what it does and how to
build and run it; this file covers how changes to the repository are made and
validated.

## Before You Start

- Packmon is licensed under the Apache License, Version 2.0 (see `LICENSE`).
  Contributions are accepted under the same license.
- External contributions are reviewed at the maintainers' discretion. Open an
  issue describing the change before investing in a pull request, so the
  maintainers can confirm it is wanted and agree on the approach.
- Report security vulnerabilities privately as described in
  `.github/SECURITY.md`, never in a public issue or pull request.
- Read `docs/secure-coding.md` before touching auth, sessions, API keys,
  logging, secrets handling, feed providers, or dependencies.

## Local Setup

Install the pinned toolchain from `requirements/packmon-tools.tsv`; the Go
version there matches `go.mod` and the Docker builder image. Verify it with
`scripts/check-requirements.sh --profile agent` (or the `.ps1` equivalent on
Windows), then build and test as shown in `README.md`, section
`Build From Source`.

## Workflow

- Prefer small, reviewable commits with a descriptive branch name.
- Write everything in English: code, comments, identifiers, commit messages,
  and documentation. Non-English text belongs only in deliberate test fixtures.
- Keep new code and docs ASCII unless a file already uses Unicode.
- Run `make fmt` before committing. It runs `gofumpt -extra` on
  `git ls-files '*.go'` only, so ignored scratch trees such as `.gotmp/` are
  never formatted. Do not run the formatter recursively over the working tree.
- Run `make lint` for `golangci-lint`, the formatter gate, and the non-Go
  linters (shell, Docker, PowerShell, web assets, OpenAPI).
- Add or update tests with every behavior change. Security-sensitive fixes
  need a regression test that fails without the fix.
- Never commit secrets, API keys, `.env` values, or environment dumps. The
  repository is public; anything committed is world-readable.

## Testing Conventions

- Narrow unit tests live next to the package that owns the behavior.
- `tests/ci` holds repository contracts, release hardening, generated asset
  checks, and CI-template behavior.
- `tests/integration` (build tag `integration`) covers the built binaries
  against a real server and database.
- `tests/e2e` (build tag `e2e`) covers complete CLI workflows.
- Use `-count=1` in documented verification commands so results are not
  served from the Go test cache.

## Validation

For a small change, run the tests of the touched packages plus any contract
test in `tests/ci` that covers the area. If you change web templates,
Tailwind classes, or asset inputs, run `npm run build:web` and commit the
regenerated assets in the same change.

For release-facing or cross-cutting changes, run the full local gate:

```bash
make verify
```

`verify` chains `lint`, `vet`, `test` (race detector plus the coverage
threshold), `test-ci`, `test-integration`, `test-e2e`, `security`, and
`security-images`; the individual targets can be run on their own. The
integration and image steps need Docker. On Windows without `make`, run the
recipe lines of those targets from the `Makefile` in PowerShell.

## Documentation

Ship implementation and canonical documentation in the same change:

- `DESIGN.md` for requirements, architecture, data flow, operational model,
  configuration, and non-goals.
- `SECURITY.md` for auth, trust boundaries, logging, crypto, dependency
  handling, admin behavior, and deployment exposure.
- `ARCHITECTURE.md` for runtime surfaces, persistence, deployment boundaries,
  and extension points.
- `docs/runbook.md` for operator procedures: backup/restore, alerting,
  upgrades, rotation, incident response.
- `README.md` only for user-facing quick start and common commands.

Deployment files (Docker, Compose) live at the repository root and n8n
examples in `deploy/n8n`; their operational rules are specified in
`DESIGN.md` and `SECURITY.md`, not here.

## Pull Requests

- Describe the behavior change, its risk, the tests you ran, and which
  canonical documents you updated.
- Include regenerated web assets only when a template or Tailwind source
  change requires them.
- Wait for required CI, and address review comments with follow-up commits
  rather than rewriting unrelated history.
