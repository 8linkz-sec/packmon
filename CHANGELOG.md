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

- Local scans no longer report ReversingLabs reputation findings that the
  server's `/api/v1/check` ignores. `GET /api/v1/sync` now exports reputation
  rows only while ReversingLabs is enabled in `self` mode; otherwise it sends
  no rows and the new optional `reputation_disabled: true` response field, and
  `packmon db sync` drops previously synced reputation rows (also on
  incremental syncs). Leftover `malicious` / `removed` rows from an earlier
  enabled period therefore no longer block a local scan while the same
  lockfile passes remotely. When ReversingLabs is enabled again, the next sync
  refetches the whole reputation dataset. The field is omitted while
  reputation is served, so older clients and servers remain compatible.
- `packmon db sync` now rejects timeouts above 9223372036 seconds from
  `--timeout`, config `timeout`, or `PACKMON_TIMEOUT`. Such values used to
  overflow `time.Duration` into a negative deadline, so the sync aborted at
  once with a context deadline error instead of a clear validation error.
- SHA-pinned GitHub Actions are no longer compared as version strings in
  `--list-all` / `--outdated`. The `# vX.Y.Z` comment convention is used as
  the declared version; without it the pin is compared with the dereferenced
  latest tag commit, and unresolvable tags report `unknown` instead of a guess.

### Security updates

- No security fixes pending disclosure.

### Operator action

- Run `packmon-server migrate` (or the `packmon-migrate` compose service)
  before starting the updated server: this release adds schema migration 047
  (schema version 46 -> 47), which widens the ecosystem CHECK constraints for
  the inventory-only `chocolatey` ecosystem. The server refuses to start on a
  schema version mismatch. Rolling 047 back removes any `chocolatey` rows
  (none are written by the scan path).
