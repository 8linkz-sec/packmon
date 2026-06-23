# Contributing

## Local Setup

1. Install Go 1.26 or newer.
2. Build the binaries:

```bash
go build -o packmon ./cmd/packmon
go build -o packmon-server ./cmd/packmon-server
```

3. Run tests:

```bash
go test -count=1 ./...
```

4. Optional integration run:

```bash
make test-integration
```

## Workflow

- Prefer small, reviewable commits.
- Keep new code ASCII unless a file already uses Unicode.
- Use `make fmt` before committing. It runs `gofumpt -extra` on
  `git ls-files '*.go'`, so ignored scratch trees such as `.gotmp/` are not
  formatted.
- Run `make lint` for `golangci-lint` plus the same tracked-file formatter
  gate.
- Add or update tests for behavior changes.
- Do not commit secrets, API keys, or environment dumps.

## Validation Checklist

- `make fmt`
- `make lint`
- `go test -count=1 ./...`
- `make build`
- `make build-server`
- `make test-integration` for server and CLI path changes

## Deployment Files

- Docker and Compose deployment changes belong at the repository root.
- n8n automation examples belong in `deploy/n8n`.

## Operational Rules

- Metrics stay on localhost by default.
- Backup and restore procedures must remain documented in `docs/runbook.md`.
- Avoid logging filesystem paths, secrets, or raw file content in persistent server logs.
