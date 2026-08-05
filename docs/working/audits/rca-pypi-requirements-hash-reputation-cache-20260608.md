# RCA: PyPI requirements hashes stored as package versions

Date: 2026-06-08
Status: Parser fix landed; database cleanup and production validation remain

## Summary

During the Reporter repository scan, Packmon logged repeated warnings while
scheduling ReversingLabs package reputation checks. PostgreSQL rejected inserts
into `package_reputation_cache` because the unique index key
`(ecosystem, name, version, source)` exceeded the btree row-size limit.

This was not a PostgreSQL capacity issue. The bad data originated earlier:
Packmon's `requirements.txt` parser stored pip `--hash` options as part of the
package `version` field when hashed requirements used backslash line
continuations. The parser now strips per-requirement options before storing the
package coordinate, with regression coverage for both continued and single-line
hashed pins.

## Timeline

- 2026-06-08 17:24:45 Europe/Berlin: Reporter scan completed the remote
  `/api/v1/check` request with HTTP 200.
- Immediately after that request, `packmon-server` logged multiple
  `failed to mark package reputation due` warnings for PyPI packages such as
  `cffi`, `numpy`, `pydantic-core`, `pyyaml`, `sqlalchemy`, `watchfiles`, and
  `websockets`.
- PostgreSQL logged matching `index row size ... exceeds btree ... maximum`
  errors for the `package_reputation_cache_ecosystem_name_version_source_key`
  unique index.
- Both Docker containers remained healthy.

Earlier `/health` 404, `/api/v1/sync` 401, and `context canceled` sync logs were
from separate local checks and are not the same incident.

## Impact

- The Reporter scan itself returned HTTP 200 and produced the HTML report.
- ReversingLabs reputation scheduling failed for PyPI packages whose malformed
  `version` value was too large for the unique index.
- Shorter malformed versions were accepted into `package_reputation_cache` as
  wrong cache keys. The live database currently contains 39 PyPI reputation
  cache rows where `version` contains `--hash=`.
- Before the parser fix, scans that relied only on `requirements.txt` could
  degrade vulnerability and reputation matching because package coordinates
  were no longer canonical. New parses now produce clean versions; existing
  malformed reputation-cache rows still need cleanup.

## Evidence

Docker logs:

- `packmon-server` warned `failed to mark package reputation due`.
- The wrapped error was `postgres: mark package reputation due: ERROR: index row
  size ... exceeds btree version 4 maximum ...`.
- The failing index was
  `package_reputation_cache_ecosystem_name_version_source_key`.

Reproduction without the server:

- Running `packmon scan --list-packages` against the Reporter repository shows
  PyPI lockfile packages with versions such as `2.0.0 --hash=...`.
- The generated CycloneDX SBOM for Reporter has clean PyPI PURLs, for example
  `pkg:pypi/numpy@2.4.6`, so the SBOM importer is not the source of this
  malformed value.
- The generated Reporter list-all HTML contains duplicate PyPI entries: clean
  `sbom` rows and malformed `lockfile` rows where `version` includes hashes.

Code path:

- `internal/parser/pypi.go:208` reads `requirements.txt` as logical lines via
  `readRequirementLogicalLines`.
- `internal/parser/pypi.go:269` folds backslash-continuation lines into a
  single string.
- `internal/parser/pypi.go:240` calls `parseRequirementLine`.
- `internal/parser/pypi.go:357` returns everything after `==` as the version.
- `internal/parser/pypi.go:252` stores that value directly in
  `domain.Package.Version`.
- `internal/api/v1/handler.go:459` copies `pkg.Version` into
  `db.PackageReputation.Version`.
- `internal/db/postgres/reputation.go:156` passes that value into the
  `package_reputation_cache` upsert.

Regression trigger:

- `git blame` shows logical line continuation handling in `requirements.txt`
  parsing was introduced by commit `91f0337` on 2026-06-04. The older
  `parseRequirementLine` implementation was already greedy, but folding hash
  continuation lines made the full hash block part of the parsed version.

## Root Cause

The root cause is missing per-requirement option normalization in
`RequirementsParser`.

Hashed pip requirements commonly look like this:

```text
package==1.2.3 \
    --hash=sha256:<digest> \
    --hash=sha256:<digest>
```

Packmon correctly folded this into one logical requirement line, but then
treated the entire right-hand side of `==` as the package version. The parser
already skipped top-level pip option lines and stripped comments, environment
markers, and extras, but it did not remove per-requirement options such as
`--hash`.

As a result, the package coordinate becomes:

```text
name = package
version = 1.2.3 --hash=sha256:... --hash=sha256:...
```

That malformed coordinate propagated unchanged into scan payloads, list-all
output, reputation scheduling, and the PostgreSQL reputation cache. Current
parser behavior strips the per-requirement option tail first, so the stored
coordinate becomes `name = package`, `version = 1.2.3`.

## Contributing Factors

- Existing parser tests cover line continuations and comments, but not hashed
  pinned requirements generated by `pip-compile --generate-hashes`.
- API request validation requires non-empty `version`, but does not validate
  that versions are canonical enough for package matching or cache indexing.
- ReversingLabs PURL construction accepts any non-empty version string for PyPI,
  including versions containing whitespace and option fragments.
- The DB schema uses `TEXT` plus a btree unique index. That is correct for
  normal package versions, but it surfaces malformed input as an index-size
  exception instead of a domain validation error.

## Remediation Status

Completed parser fix:

- `RequirementsParser` now normalizes pinned requirement lines before package
  extraction.
- For pinned dependencies, only the first token after `==` is treated as the
  version; following per-requirement options such as `--hash` are ignored.
- `internal/parser/pypi_test.go` covers hashed pinned requirements with
  backslash continuations and hashed pinned requirements on one physical line,
  while retaining existing marker/extras/comment behavior.

Defense in depth:

- Add package-coordinate validation before scheduling ReversingLabs reputation
  lookups. For supported ecosystems, skip or mark unsupported versions that
  contain whitespace, `--hash=`, or other obvious requirement-option fragments.
- Keep logging sanitized: log ecosystem, name, and source as today; do not log
  long version strings.

Cleanup for databases that already ingested malformed rows:

```sql
DELETE FROM package_reputation_cache
WHERE ecosystem = 'pypi'
  AND version LIKE '%--hash=%';
```

Then rerun the affected Reporter scan so clean PyPI coordinates repopulate the
reputation cache.

## Verification Plan

Completed:

1. Parser regression tests landed in `internal/parser/pypi_test.go`.
2. Normalization landed in `internal/parser/pypi.go`.
3. `go test -count=1 ./internal/parser` verifies the parser behavior locally.

Remaining environment-specific checks:

1. Run a targeted Reporter list-packages check and verify affected packages
   show versions like `2.4.6`, not `2.4.6 --hash=...`.
2. Run the remote Reporter scan and verify Docker logs no longer contain
   `failed to mark package reputation due` for PyPI hash-stuffed versions.
3. Query `package_reputation_cache` and verify no rows remain with
   `version LIKE '%--hash=%'`.
