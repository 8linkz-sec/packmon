# Agent Guide -- packmon CLI (the client/agent)

Scope: `cmd/packmon/` -- the cross-platform CLI binary: cobra commands (scan,
hook, db, config, version), config loading/precedence, local SQLite history, and
git repo-metadata collection. Primary owner agent: **cli-integrations-engineer**.

Read `AGENTS.md` (root) and `DESIGN.md` (CLI interface, flags, exit codes,
config precedence) first.

## Invariants (do not break)

- Config precedence (DESIGN.md sec 2.7): CLI flags > env (`PACKMON_*`) >
  project `.packmon.yaml` > user `~/.packmon/config/packmon.yaml` > binary
  defaults for non-sensitive scan policy. Auto-discovered project config is
  untrusted for credential/server/DB routing fields.
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

## Current Guardrails

Keep these tracked guardrails in mind:

- Preserve config precedence for non-sensitive scan policy: flags > environment
  > project config > user-global config > defaults. Keep credential/server/DB
  routing under flags, environment, user-global config, or explicit `--config`.
- `db sync` must keep using the Packmon server as its only source. Config
  `db.sync_source` is read, but values other than `server` must stay rejected.
- The git-metadata path (`local_history.go`) has cmd-layer tests for no-git,
  committed repo, and no-commit repo cases; keep them hermetic when changing
  `GOTMPDIR` or git discovery behavior.

## Tests

```bash
go test ./cmd/packmon/...
```
