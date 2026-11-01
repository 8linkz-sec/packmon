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
- `packmon scan` and `packmon config show` apply the same 9223372036-second
  upper bound to `--timeout`, `PACKMON_TIMEOUT`, config `timeout`, and
  `repos[].timeout` (config files are rejected on load). Larger values used to
  overflow `time.Duration` into a negative or near-zero HTTP, SBOM-generation,
  and per-request registry lookup timeout, so the scan failed or timed out at
  once instead of reporting a validation error.
- A project `.packmon.yaml` `repos:` entry that refers to a user-global repo
  (matched by name, then by path) now inherits that trusted repo's
  `send_repo_metadata: false`, server/API-key routing, and webhook. The
  project's repos still replace the user-global list, and each entry keeps its
  own name, path (the project path wins on a name match), and scan policy.
  Previously a project entry naming a trusted repo silently re-enabled
  repository metadata that repo had disabled.
- `packmon config show` escapes terminal control characters in every config-,
  flag-, and environment-derived value it prints: config file path, server,
  masked API key, API key env name, mode, fail_on, ecosystems, CA cert path,
  webhook URL, masked webhook secret, DB path, repo names and paths, and log
  level. A crafted value,
  including one from an auto-discovered project `.packmon.yaml`, could
  previously inject ANSI escape sequences or forge output lines.
- `packmon hook install` sets the hook file's mode to `0755` explicitly after
  writing it. Updating an existing packmon hook kept its old mode, so a managed
  hook that had lost its execute bit stayed non-executable while install
  reported success and Git skipped the scan. `packmon hook status` now reports
  such a hook as `packmon hook not executable` instead of `installed` (POSIX
  only; Git for Windows does not use mode bits for hooks).
- Latest-version registry base URLs, Docker registry mirrors, and Chocolatey
  feed URLs ending in an empty fragment marker (`https://mirror.example/api#`)
  are now rejected like any other fragment. `net/url` records no fragment for a
  bare `#` and drops it on re-serialization, so the value was previously
  accepted and silently rewritten.
- SHA-pinned GitHub Actions are no longer compared as version strings in
  `--list-all` / `--outdated`. The `# vX.Y.Z` comment convention is used as
  the declared version; without it the pin is compared with the dereferenced
  latest tag commit, and unresolvable tags report `unknown` instead of a guess.
- `docker-compose.server.yml` passes `PACKMON_SERVER_PORT` into the container,
  so a shell override no longer publishes a container port the server does not
  listen on.
- `docker-compose.server.yml` mounts a named `feed-data` volume at
  `/data/feeds` and pins `PACKMON_FEED_DATA_DIR` to it; the git-backed GHSA and
  OpenSSF checkouts survive container recreation instead of living in
  temporary storage.
- `docker-compose.server.yml` enables `restart: unless-stopped` for
  PostgreSQL and the server (previously commented out); the one-shot migrate
  and backup jobs keep `restart: "no"`.
- `docker-compose.yml` defaults `PACKMON_SCAN_LOG_RETENTION` and
  `PACKMON_ADMIN_AUDIT_LOG_RETENTION` to the documented `720h` (30 days)
  instead of `2160h` / `8760h`.
- `.dockerignore` now excludes every git-ignored path, including the local
  working documents (`AGENTS.md` at any depth, `CLAUDE.local.md`,
  `TESTING.md`, `WORKFLOW.md`, `Roadmap.txt`, `docs/superpowers/`) and the
  default `backups/` dump directory, so they no longer enter the build
  context.
- The local `init-secrets` Compose service runs as
  `${PACKMON_UID:-1000}:${PACKMON_GID:-1000}` instead of the image's `packmon`
  system account, and the new `scripts/init-secrets.sh` wrapper passes the
  host UID/GID (or `0:0` under rootless Docker; an explicit `PACKMON_UID` or
  `PACKMON_GID` wins for that variable only), so bootstrapping on native Linux
  no longer fails with `permission denied` on a host-owned checkout or
  `.env`. The production server image still runs as `packmon`.
- `.env.example` seeds `PACKMON_METRICS_HOST=127.0.0.1` instead of `0.0.0.0`,
  which production startup rejects. README, runbook, and deferred-scope notes
  no longer claim the metrics port is reachable from the host; read metrics
  with
  `docker compose exec packmon-server wget -qO- http://127.0.0.1:9090/metrics`.
  An existing `.env` that still says `0.0.0.0` keeps working under Compose
  (both Compose models pin loopback) but should be changed for any other launch
  path.
- `packmon-server init-secrets` copies an existing `PACKMON_DB_PASSWORD` onto
  a blank `POSTGRES_PASSWORD` instead of generating a different value. The
  bundled PostgreSQL was previously initialized with a password the server
  and migrator did not use, so a fresh local stack failed authentication
  although `init-secrets` reported success. When both are set to different
  values it keeps them and prints a one-line warning naming the variables,
  never their values.
- The starter Prometheus alerts `PackmonMetricsStoreReadFailure`,
  `PackmonDegradedResponses`, and `PackmonQueueErrors` in
  `docs/monitoring/packmon-alerts.yml` use `for: 0m`. Their `for` duration
  equalled the `increase()` range, so an isolated event left the range before
  the alert could fire. Re-import the rule file if you deployed it.
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
  `Newtonsoft.Json` match canonical lookups and new repairs no longer add
  a duplicate beside the canonical row.
- One stored GHSA advisory with `affected: null` (or an object/scalar where an
  array is expected, or range `events` that are null or not an array) no
  longer aborts the GHSA affected-package repair for every advisory. A
  package whose reconstructed ranges or versions the schema would reject is
  skipped and keeps its feed-written row.
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
- Rejected admin credentials (a login with a wrong username or password, the
  API-key create step-up, and the password-change current-password check)
  are counted toward the IP and shared-account lockout and
  `packmon_auth_login_failures_total` before the rejection audit row is
  written. A failing audit write previously returned early, so the attempt
  escaped lockout accounting; the request still fails closed.
- The admin login and admin pages render the shared footer's terms link
  (`PACKMON_WEB_TERMS_URL`, default `/terms`) like the public pages; the
  admin renderer previously received only the privacy and legal URLs.
- The 12-character minimum for bootstrap (`PACKMON_ADMIN_INITIAL_PASSWORD`)
  and rotated admin passwords counts Unicode characters instead of bytes, so
  a password of four three-byte characters no longer passes.
- Overlapping `/admin/feeds` saves and resets no longer leave the running
  feed configuration out of step with PostgreSQL. The request that lost the
  revision race used to roll the runtime back to a snapshot taken before the
  winner applied its change; apply, persistence and rollback now run as one
  step ordered against other feed saves and resets.
- `/admin/feeds` save and reset forms carry the stored override's revision
  (`updated_at`) like the system settings form. Submitting a form that was
  rendered before another admin saved or reset the feed is rejected with the
  existing conflict message instead of silently overwriting that change;
  a malformed revision is rejected as invalid. A blank API key still keeps
  the stored key.

### Security updates

- No security fixes pending disclosure.

### Operator action

- Run `packmon-server migrate` (or the `packmon-migrate` compose service)
  before starting the updated server: this release adds schema migration 047
  (schema version 46 -> 47), which widens the ecosystem CHECK constraints for
  the inventory-only `chocolatey` ecosystem. The server refuses to start on a
  schema version mismatch. Rolling 047 back removes any `chocolatey` rows
  (none are written by the scan path).
- `docker-compose.server.yml` deployments: the next `up` creates the new
  `<project>_feed-data` volume, so the first feed sync after the upgrade
  re-clones the GHSA and OpenSSF repositories once. A `PACKMON_FEED_DATA_DIR`
  set in `.env` is now overridden by `/data/feeds`. PostgreSQL and the server
  now restart automatically; stop them with `docker compose -f
  docker-compose.server.yml stop` when they must stay down. Make sure the
  reverse proxy targets the port in `PACKMON_SERVER_PORT`.
- `docker-compose.yml` deployments that relied on the old implicit
  `2160h` / `8760h` scan-log and admin-audit retention: set
  `PACKMON_SCAN_LOG_RETENTION` / `PACKMON_ADMIN_AUDIT_LOG_RETENTION`
  explicitly (or in `/admin/settings`) before upgrading, otherwise the next
  prune deletes rows older than 30 days. Values saved in `/admin/settings`
  take precedence over the environment default.
