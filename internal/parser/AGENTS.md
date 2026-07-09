# Agent Guide -- Lock-File Parsers

Scope: `internal/parser/` -- one parser per ecosystem (npm, pypi, maven, gradle,
cargo, gomod, gem, nuget, composer, cocoapods, pub, swiftpm, hex, cran, actions)
plus `parser.go`, `helpers.go`, and `fuzz_test.go`. Primary owner agent:
**backend-engineer**.

Read `AGENTS.md` (root) and `DESIGN.md` (supported ecosystems table) first.

## Conventions

- A parser implements `CanParse`, `Parse(io.Reader) ([]Package, error)`, and
  `Ecosystem()`. Decode into typed structs; never assume JSON/YAML/TOML shape
  with unchecked type assertions. Malformed input returns an error, never panics.
- Most parsers match by basename. Path-sensitive parsers are allowed for formats
  where directory placement is part of the contract, such as GitHub Actions
  workflows under `.github/workflows/`.
- Every parser has a sibling `_test.go` and a fuzz target. Coverage target for
  this package is >= 90%. New ecosystems need both.
- `domain.Package` carries a `Dev bool`. A parser MUST set `Dev: true` for
  entries it can identify as dev/test scope (npm `dev`, Pipfile `develop`, Maven
  `scope=test`). The scanner filters dev deps by default and includes them with
  `--include-dev`.

## Current Guardrails

Keep these tracked guardrails in mind:

- Preserve dev/test dependency marking in parser tests when touching npm, pnpm,
  Pipfile, poetry, uv, Maven, Gradle, Composer, or equivalent lock formats.
- Keep the parser-level `dedup` "production wins" merge rule covered by tests.
- `requirements.txt` parsing intentionally skips recursive include files because
  parser instances receive only an `io.Reader`; adding recursive includes needs
  a collector-level design rather than ad hoc filesystem access here.

## Tests

```bash
go test -count=1 ./internal/parser/...
go test -count=1 -run Fuzz -fuzz <Target> -fuzztime 30s ./internal/parser
```
When changing the `Dev` flag, assert the flag value in the parser test (most
existing tests only check name->version).
