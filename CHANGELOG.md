# Changelog

## Unreleased

### Added

- `packmon scan --list-all` inventories Chocolatey packages as a metadata-only
  ecosystem (`chocolatey`): FLARE-VM / VM-Packages style `config.xml` package
  lists (identified by content) and `choco install|upgrade` / `cinst` / `cup`
  lines in `.ps1`, `.psm1`, `.bat`, and `.cmd` scripts. Rows carry latest
  versions from the configured NuGet v2 feeds (`registries.chocolatey_feed_urls`
  / `PACKMON_CHOCOLATEY_FEED_URLS`, default community feed); pinned versions
  are compared under NuGet rules, unpinned entries render as `unpinned`.
  Chocolatey rows are never sent to `/api/v1/check`; migration 047 adds the
  ecosystem to the database CHECK constraints.

### Fixed

- SHA-pinned GitHub Actions are no longer compared as version strings in
  `--list-all` / `--outdated`. The `# vX.Y.Z` comment convention is used as
  the declared version; without it the pin is compared with the dereferenced
  latest tag commit, and unresolvable tags report `unknown` instead of a guess.
- The dashboard severity buckets and the `/metrics` finding-severity totals
  count ReversingLabs `malware_history` (historical risk) reputation rows as
  `LOW`, the severity of the informational finding they produce, instead of the
  stored provider severity (often `HIGH`). Stored reputation data is unchanged.
- PostgreSQL scan totals no longer fail once a retained sum exceeds
  2147483647: the cumulative `/metrics` package/finding totals and the daily
  findings sum on the scans page are read as BIGINT instead of being cast to
  int.
- The GHSA affected-package repair writes canonical package names (PyPI
  separator/case folding, NuGet and GitHub Actions lowercase, trimmed) like
  every feed upsert, so repair-only rows such as PyPI `My.Pkg_Name` or NuGet
  `Newtonsoft.Json` match canonical lookups and no longer sit beside the
  canonical row as duplicates.
- One stored GHSA advisory with `affected: null` (or an object/scalar where an
  array is expected, or range `events` that are null or not an array) no
  longer aborts the GHSA affected-package repair for every advisory.
- PostgreSQL `FindMaliciousBatch` keeps a versionless request for a package
  when the same batch also asks for concrete versions of it, so the empty
  version still returns every active malicious finding of the package, as
  `FindMalicious(..., "")` and a versionless-only batch already did.
- Manual advisory writes and deletes on PostgreSQL use the normalized
  (trimmed) advisory ID throughout. A padded ID such as ` manual:x ` no longer
  leaves both the vulnerability and the malicious record active after a type
  change, and deleting it no longer reports "not found".
- Editing a manual vulnerability advisory replaces its stored state instead of
  going through the feed merge: a `HIGH` -> `LOW` edit is stored as `LOW`, a
  cleared description is cleared, and moving coverage from package A to B no
  longer leaves A affected. Feed severity/details retention is unchanged.

### Security updates

- No security fixes pending disclosure.

### Operator action

- Run `packmon-server migrate` (or the `packmon-migrate` compose service)
  before starting the updated server: this release adds schema migration 047
  (schema version 46 -> 47), which widens the ecosystem CHECK constraints for
  the inventory-only `chocolatey` ecosystem. The server refuses to start on a
  schema version mismatch. Rolling 047 back removes any `chocolatey` rows
  (none are written by the scan path).
