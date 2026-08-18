# Contributing

## Local Setup

Install the pinned toolchain from `requirements/packmon-tools.tsv`. The current
Go toolchain is Go 1.26.6, matching `go.mod` and the Docker builder image. Run
the requirement check for the profile you need before building.

Windows PowerShell:

```powershell
.\scripts\check-requirements.ps1 -Profile agent
New-Item -ItemType Directory -Force .build | Out-Null
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
go test -count=1 ./...
```

Linux/macOS, or WSL on Windows:

```bash
bash scripts/check-requirements.sh --profile agent
mkdir -p .build
go build -o .build/packmon ./cmd/packmon
go build -o .build/packmon-server ./cmd/packmon-server
go test -count=1 ./...
```

`make` is convenient on systems that have it, but it is not required on
Windows. Use the direct PowerShell commands from `README.md` when `make` is not
available.

## Workflow

- Prefer small, reviewable commits.
- Keep new code ASCII unless a file already uses Unicode.
- Use `make fmt` before committing. It runs `gofumpt -extra` on
  `git ls-files '*.go'`, so ignored scratch trees such as `.gotmp/` are not
  formatted.
- Run `make lint` for `golangci-lint` plus the same tracked-file formatter
  gate.
- Add or update tests for behavior changes.
- Do not commit secrets, API keys, `.env` values, or environment dumps.
- Review `docs/secure-coding.md` during onboarding and before
  security-sensitive changes.

## Testing Conventions

- Put narrow unit tests next to the package that owns the behavior.
- Use `tests/ci` for repository contracts, release hardening, generated asset
  checks, and CI-template behavior.
- Use tagged `tests/integration` tests for Packmon binary plus server/database
  behavior.
- Use tagged `tests/e2e` tests for complete CLI workflows.
- Use `-count=1` in documented verification commands so local results are not
  satisfied from the Go test cache.

## Documentation Updates

Keep implementation and canonical documentation in the same change:

- Update `DESIGN.md` when requirements, architecture, data flow, operational
  model, or non-goals change.
- Update `SECURITY.md` when auth, trust boundaries, logging, crypto,
  dependency handling, admin behavior, or deployment exposure changes.
- Update `ARCHITECTURE.md` when runtime surfaces, persistence, deployment
  boundaries, trust boundaries, or extension points change.
- Update `README.md` only for user-facing quick-start and common commands.
- Update `docs/runbook.md` when operator procedures, backup/restore, alerting,
  upgrade, rotation, or incident response behavior changes.

## Validation Checklist

For a small change, run the narrow package tests plus any touched contract
tests. If you touch web templates, Tailwind classes, or asset inputs, also run
the generated web asset gate used by CI.

On systems with `make`, the existing wrappers for the Go gates are `make test`,
`make test-ci`, `make test-integration`, `make test-e2e`, `make lint`, and
`make security`. For release-facing changes, use the full local gate:

```bash
bash scripts/bootstrap.sh --profile dev
npm ci --ignore-scripts
npm run build:web
git diff --exit-code -- internal/web/static/tailwind.css internal/web/static/htmx.min.js
mkdir -p .gotmp
export GOTMPDIR="$PWD/.gotmp"
PACKAGES="$(go list ./... | grep -v /node_modules/)"
GOSEC_DIRS="$(go list -f '{{.Dir}}' ./... | grep -v node_modules)"
GOFMT_FILES="$(git ls-files '*.go')"
gofumpt -extra -l ${GOFMT_FILES}
go test -count=1 ${PACKAGES}
go test -count=1 -race -coverprofile=coverage.out ${PACKAGES}
go run ./tools/checkcoverage -profile=coverage.out -min=79.5
go vet ${PACKAGES}
golangci-lint run ./...
govulncheck ${PACKAGES}
gosec -nosec-require-rules -nosec-require-justification ${GOSEC_DIRS}
go build -o .build/packmon ./cmd/packmon
go build -o .build/packmon-server ./cmd/packmon-server
PACKMON_TEST_BIN_DIR=.build go test -count=1 -tags integration ./tests/integration
PACKMON_TEST_BIN_DIR=.build go test -count=1 -tags e2e ./tests/e2e
```

Windows PowerShell equivalent:

```powershell
.\scripts\bootstrap.ps1 -Profile dev
npm ci --ignore-scripts
npm run build:web
git diff --exit-code -- internal/web/static/tailwind.css internal/web/static/htmx.min.js
New-Item -ItemType Directory -Force .gotmp | Out-Null
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
$packages = go list ./... | Where-Object { $_ -notmatch 'node_modules' }
$gosecDirs = go list -f '{{.Dir}}' ./... | Where-Object { $_ -notmatch 'node_modules' }
$gofmtFiles = git ls-files '*.go'
gofumpt -extra -l $gofmtFiles
go test -count=1 $packages
go test -count=1 -race '-coverprofile=coverage.out' $packages
go run ./tools/checkcoverage '-profile=coverage.out' '-min=79.5'
go vet ${PACKAGES}
golangci-lint run ./...
govulncheck $packages
gosec -nosec-require-rules -nosec-require-justification $gosecDirs
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
$env:PACKMON_TEST_BIN_DIR = ".build"
go test -count=1 -tags integration .\tests\integration
go test -count=1 -tags e2e .\tests\e2e
```

## Pull Requests

- Use a branch name that describes the change area.
- Keep the PR description focused on behavior, risk, tests run, and required
  documentation updates.
- Include generated web assets only when template or Tailwind source changes
  require them.
- Wait for required CI before merge and address review comments with follow-up
  commits instead of rewriting unrelated history.

## Deployment Files

- Docker and Compose deployment changes belong at the repository root.
- n8n automation examples belong in `deploy/n8n`.

## Operational Rules

- Metrics stay on localhost by default.
- Backup and restore procedures must remain documented in `docs/runbook.md`.
- Avoid logging filesystem paths, secrets, or raw file content in persistent
  server logs.
