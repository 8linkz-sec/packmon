# Agent Guide -- Lock-File Parsers

Scope: `internal/parser/` -- one parser per ecosystem (npm, pypi, maven, gradle,
cargo, gomod, gem, nuget, composer, cocoapods, pub, swiftpm, hex, cran) plus
`parser.go`, `helpers.go`, and `fuzz_test.go`. Primary owner agent:
**backend-engineer**.

Read `AGENTS.md` (root) and `DESIGN.md` (supported ecosystems table) first.

## Conventions

- A parser implements `CanParse`, `Parse(io.Reader) ([]Package, error)`, and
  `Ecosystem()`. Decode into typed structs; never assume JSON/YAML/TOML shape
  with unchecked type assertions. Malformed input returns an error, never panics.
- Every parser has a sibling `_test.go` and a fuzz target. Coverage target for
  this package is >= 90%. New ecosystems need both.
- `domain.Package` carries a `Dev bool`. A parser MUST set `Dev: true` for
  entries it can identify as dev/test scope (npm `dev`, Pipfile `develop`, Maven
  `scope=test`). The scanner filters dev deps by default and includes them with
  `--include-dev`.

## Current open landmines (see Audit.md)

> Status (2026-05-29): the items in this section were addressed across the
> Audit.md "Fix-Runde" passes. Audit.md is authoritative; project-wide only the
> external GitLab-runner test remains open. Keep the notes below as guardrails
> so the fixes are not regressed.

- **H4:** `composer.go` reads `packages-dev` but emits every entry with
  `Dev:false` -- dev deps are wrongly scanned by default. Set `Dev:true` when
  appending `PackagesDev`.
- Other parsers that could but do not yet model dev scope: pnpm (`dev:` per
  package), poetry/uv (groups/category), gradle (test* configurations). Setting
  `Dev` inconsistently across ecosystems is a UX trap -- prefer parity.
- The `dedup` "production wins" merge rule (a name+version seen as both dev and
  prod stays prod) exists in BOTH `parser.go` and `scanner.go` and is currently
  untested. Assert it when you touch either copy; consider consolidating.

## Tests

```bash
go test ./internal/parser/...
go test -run Fuzz -fuzz <Target> -fuzztime 30s ./internal/parser
```
When changing the `Dev` flag, assert the flag value in the parser test (most
existing tests only check name->version).
