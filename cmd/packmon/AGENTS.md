# Agent Guide -- packmon CLI (the client/agent)

Scope: `cmd/packmon/` -- the cross-platform CLI binary: cobra commands (scan,
hook, db, config, version), config loading/precedence, local SQLite history, and
git repo-metadata collection. Primary owner agent: **cli-integrations-engineer**.

Read `AGENTS.md` (root) and `DESIGN.md` (CLI interface, flags, exit codes,
config precedence) first.

## Invariants (do not break)

- Config precedence (DESIGN.md sec 2.7): CLI flags > env (`PACKMON_*`) > project
  `.packmon.yaml` > user `~/.packmon/config/packmon.yaml` > binary defaults.
- The CLI talks only to the Packmon server for sync, never directly to upstream
  feeds. `db sync` advertises only `--source server`.
- Exit codes are a contract (see `internal/scanner` AGENTS.md). The CLI maps
  scanner results to process exit codes; keep the mapping intact.
- Repo metadata (name/branch/commit) is collected via fixed-argv `git -C <dir>`
  calls, must degrade gracefully outside a git repo (omit, do not error), and
  must not leak git stderr to the user terminal.
- Never log API keys, passwords, env values, or file contents. `config show`
  masks secrets.
- Cross-platform: dev/CI runs on Windows too. Use `filepath`, handle `~`/`~\`,
  and `GOEXE`.

## Current open landmines (see Audit.md)

> Status (2026-05-29): the items in this section were addressed across the
> Audit.md "Fix-Runde" passes. Audit.md is authoritative; project-wide only the
> external GitLab-runner test remains open. Keep the notes below as guardrails
> so the fixes are not regressed.

- **M5:** the user-global config layer (`~/.packmon/config/packmon.yaml`) is not
  loaded at all -- only the project file. Implement the missing precedence level.
- `db sync` ignores `db.sync_source` from the config file (only the flag is read).
- `db_test.go` only checks the help string; it does not test `--source osv`
  rejection or case-insensitivity. Deepen it when you touch `db.go`.
- The new git-metadata path (`local_history.go`) has no cmd-layer test; add a
  temp-`git init` table test (with and without a commit).

## Tests

```bash
go test ./cmd/packmon/...
```
