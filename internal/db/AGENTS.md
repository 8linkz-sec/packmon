# Agent Guide -- Database Layer

Scope: `internal/db/` (the `Store` interface, `sync.go`), `internal/db/postgres/`
(server persistence), `internal/db/sqlite/` (local CLI sync/history), and
`internal/db/postgres/migrations/`. Primary owner agent: **data-feeds-engineer**;
coordinate with backend-engineer for handler-facing query shapes.

Read `AGENTS.md` (root) and `DESIGN.md` first.

## Invariants (do not break)

- Migrations are a SEPARATE operational step: `packmon-server migrate`. The
  server must not silently migrate on startup -- it reads the schema version and
  refuses to start on mismatch (`cmd/packmon-server/main.go`, migrator
  `ExpectedVersion`). When you add a migration, bump `ExpectedVersion` and ship
  symmetric `*.up.sql` / `*.down.sql`. Treat the migrator's `ExpectedVersion`
  as the current schema version; do not duplicate that number in guidance.
- All SQL is parameterized (`$N`). Never concatenate user input into SQL. For
  dynamic status/IN lists, whitelist values (see `ClearQueue`).
- Nullable JSONB text columns must be `COALESCE`d (e.g. `versions::text`,
  `reference_urls::text`) before scanning into Go strings, and
  `jsonb_array_length` must be guarded with `jsonb_typeof(...) = 'array'`.
- Manual advisories: `vulnerability` type goes into the vulnerability tables with
  `source='manual'` (so it appears in normal lookups); `malicious` type goes into
  `malicious_findings`. IDs without an operator value get `manual:<uuid>` from
  `crypto/rand`.
- `paused` queue jobs must never be dequeued and must remain visible in
  stats/metrics.

## Current Guardrails

These notes are guardrails for behavior that has regressed before. Keep them in
sync with `DESIGN.md` and `SECURITY.md` when the behavior intentionally changes.

- Manual vulnerability advisories are stored with empty
  `version_ranges`/`versions_affected` (`[]`). This is intentional and correct:
  `version.VersionAffected(_, "[]", "[]", _)` returns fail-safe `true`
  (compare.go) so the advisory matches every scanned version. Do NOT "fix" this
  into a non-matching state. Covered by
  `TestVersionAffected_EmptyRangesAndVersions`.
- **M3:** `EnqueueRefresh`'s resurrection UPDATE flips `paused` jobs back to
  `pending`. Exclude `paused` from the resurrection so admin pause is durable.
- **M9:** keep DB-backed regression coverage for `manual_advisories`,
  `system_settings`, and queue management when touching those paths (target
  >= 80% for DB-layer changes).
- **L7:** manual advisory creation must reject feed-owned IDs such as CVE, GHSA,
  and OSV identifiers before insert/upsert so operator input cannot replace
  feed-owned vulnerability data.

## Tests

```bash
go test ./internal/db/...
```
DB-backed tests require Postgres (see `tests/integration`). State explicitly if
Postgres is unavailable locally.
