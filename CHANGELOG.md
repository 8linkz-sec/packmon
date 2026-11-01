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

- `packmon report` exits `2` (operational error) when writing the report to
  stdout fails. It used to discard every write error outside the history
  table, so a closed pipe or full disk ended the command with exit `0` and no
  (or a truncated) report, and the empty-history message never failed at all.
- `--outdated` / `--list-all` latest-version lookups whose `200` registry
  response exceeds the read limit (512 KiB for most registries) now count as
  refused or failed registry requests, so the stderr warning and the list-all
  HTML hint report them. They used to count as successes without any warning
  while the row silently ended up `unknown`. The registry did answer, so such
  a response does not advance the consecutive-failure breaker.
- `packmon scan --outdated` exits `4` (parser error) when a lockfile or SBOM
  fails to parse. Nonfatal parse errors used to print only a warning and exit
  `0`; the run now reports the packages it could parse (terminal table and
  `--html` report) and then fails with "package inventory is incomplete: N
  parse errors". An inventory where nothing parsed exits `4` instead of
  printing "No packages found.". `--outdated --quiet` without `--html` used to
  return before reading the inventory, so even fatal parse errors exited `0`;
  it still skips the registry lookups but now collects the inventory and keeps
  the discovery (`2`) and parser (`4`) exit codes. CI jobs that relied on
  `--outdated --quiet` always exiting `0` can now see `2` or `4`.
- The `packmon scan --html` report formats its timestamps in the viewer's
  browser locale and time zone again; its inline script had the same
  `dateStyle`/`timeStyle` plus `timeZoneName` combination as the list-all and
  `--outdated` reports below. All three reports now share one Intl option set.
- The list-all and `--outdated` HTML reports format their timestamps in the
  viewer's browser locale and time zone again. The inline script combined
  `dateStyle`/`timeStyle` with `timeZoneName`, which conforming JavaScript
  engines reject with a `TypeError`, so every timestamp kept its UTC fallback
  text.
- The list-all and `--outdated` HTML reports no longer show a full Windows
  drive or UNC source path (`C:\Users\...\go.sum`, `C:/...`, `\\server\...`)
  on a Linux host when the scan root is relative (for example `.`). Such a
  path was treated as "inside" the current directory and rendered in full;
  it now shows only its final segment, like every other path outside the scan
  root.
- The list-all and `--outdated` HTML reports reduce a Windows path
  rooted on the current drive (`\Users\Alice\go.sum`) to its final segment on
  every OS. It was not recognized as absolute, so it rendered in full (as
  `/Users/Alice/go.sum` on Windows) in the report target and source paths.
- `packmon scan --list-all` compares each installed Docker image tag with its
  own local repo digest. Local digests used to be keyed by repository name
  only, so two installed tags of one repository (for example `postgres:17`
  and `postgres:18`) shared one baseline and could be reported as
  `UPDATE yes` while up to date, or `-` while outdated.
- `--outdated` / `--list-all` latest-version lookups whose registry response
  broke off mid-body (connection reset or per-request timeout after the `200`
  status) now count as refused registry requests. They used to count as
  successes, which reset the consecutive-failure breaker and suppressed the
  "registry requests were refused or failed" warning on stderr and in the
  list-all HTML report.
- A panicking latest-version, npm-metadata, or Git tag lookup in
  `--outdated` / `--list-all` no longer hangs the run. The shared in-flight
  lookup is now always completed, so other packages waiting on the same
  registry key get a failed lookup instead of blocking forever.
- `packmon scan --outdated --quiet --html <file>` no longer prints the routine
  "Checking N packages for updates..." line to stderr; `--quiet` now
  suppresses it like the later lookup progress.
- `packmon scan --list-packages` now exits with the parser-failure code `4`
  when a lockfile or SBOM entry could not be parsed, as `packmon scan` does.
  Partially parsed inventories are still listed before the error; a lockfile
  set that could not be parsed at all no longer exits `0` with
  "No packages found.".
- `packmon scan --list-all` now writes the requested `--output-json`,
  `--output-sarif`, and `--output-junit` files when the scan completes but the
  local scan-history write fails, and returns the history error afterwards,
  matching a normal `packmon scan`. Previously the artifacts were silently
  omitted while the HTML report was still written.
- A Socket.dev or ReversingLabs feed setting change no longer leaves the
  refresh-queue workers stopped when the previous queue generation misses the
  restart deadline. The replacement now starts as soon as that generation
  exits, with the settings current at that time; before, both providers'
  queue processing stayed stopped until another effective change or a server
  restart, because saving the same settings again is a no-op.
- The production startup schema check now redacts and bounds the database
  error it logs, like the fatal startup log already did. Driver errors that
  echoed the connection URL, secret assignments, or local filesystem paths were
  logged verbatim. Diagnostic redaction now also strips credentials, paths, and
  query strings from `postgres://` and `postgresql://` URLs. The same
  redact-and-bound step now covers the server's other error logs: the startup
  package-name repair, background startup tasks, queue-worker status
  reads/writes, audit-retention prunes, queue-processor and retention-worker
  exits, feed-syncer registration, invalid persisted feed modes, and the
  plain-stderr fatal message printed before a logger is configured. A quoted
  secret value such as libpq's `password='two words'` (single or double
  quotes, with backslash-escaped quotes) is now redacted as a whole; before,
  only its first word was hidden. The redacted value runs to the next
  unquoted, unescaped whitespace, `;`, or `&`, so text after a closing quote
  (`password="ab"cd`, `password=''secret`) or an escaped space
  (`password=foo\ bar`) no longer leaks, and an unterminated quote redacts the
  rest of the message.
- `PACKMON_SERVER_PUBLIC_HOST` must now be a bare `host[:port]`. Values such
  as `packmon.internal#fragment`, `packmon.internal?x=1`, a host with
  whitespace, control characters, a percent-escape, a non-ASCII name, a
  zone-scoped or bracketed non-IPv6 literal, a signed (`:+443`) or empty port
  were accepted and produced broken redirects such as
  `https://packmon.internal#fragment/admin`; the server now refuses to start
  with a clear configuration error. The HTTPS redirect builder also drops such
  hosts.
- Admin passwords longer than 72 bytes (bcrypt's input limit) are now rejected
  by the password policy with their own error. A password change used to pass
  validation and then fail hashing with the generic "Failed to update
  password", and a too-long `PACKMON_ADMIN_INITIAL_PASSWORD` failed bootstrap
  with a bcrypt hash error. The form now answers "Password must be at most 72
  bytes", and each policy error maps to its own message instead of every one
  being reported as too short. The password form's help text now states both
  bounds ("Use at least 12 characters and at most 72 bytes.").
- Admin login and feed-config hardening: a feed save or reset that has to roll
  the runtime back now does so on a context detached from the request (with a
  30-second timeout), so a client disconnect can no longer cancel the rollback
  and leave the server on an unpersisted feed configuration. A login while no
  admin account exists now counts as a failed attempt (lockout, metrics, and a
  `login_failed` audit row with reason `admin account not configured`), and
  logins with an unknown username or without an admin account run a dummy
  bcrypt comparison at the production cost, so they no longer answer
  measurably faster than a wrong password. The dummy hash is generated at
  server startup before serving; if that fails, an embedded production-cost
  hash is used instead, so the equalization cannot silently disappear.
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
  Clients older than this change ignore the unknown `reputation_disabled`
  field, so their incremental syncs keep previously synced reputation rows
  (and the local/remote mismatch) until the client is upgraded; only a full
  sync (`packmon db sync --full`), which clears every local sync table first,
  removes those rows on an older client.
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
- The managed Git hook no longer writes into the repository. It now runs
  `packmon scan . --hook ...`. For destinations that resolve inside the
  repository work tree or its Git directories, `--hook` skips a config
  `output.file` with a stderr warning (also under `--quiet`) and still runs
  the gated scan, and fails with exit code 2 before scanning for an explicit
  `--output-json`, `--output-sarif`, `--output-junit`, or `--html` path or for
  a used local database directory (`PACKMON_DB_PATH`, `db.path`). The check
  follows symlinks (dangling ones by their target) and compares the deepest
  existing ancestor by file identity, so a different letter case on a
  case-insensitive filesystem does not bypass it. Previously a trusted
  user-global `output.file` with a relative path was resolved against the
  hook's working directory, so every hook run wrote a report file into the
  repository. Destinations outside the repository still work. `--hook` cannot
  be combined with `--list-packages`, `--outdated`, `--list-all`, or
  `--auto-sbom`. `packmon hook status` reports hooks installed by older
  versions as `outdated`; rerun `packmon hook install` to update them.
  Multi-target scans (`--all`), with or without `--hook`, now resolve every
  target's settings before the first scan, so a settings error on a later
  target is reported before any target is scanned.
- A project `.packmon.yaml` `repos:` entry whose name matches one user-global
  repo and whose path matches another now inherits `send_repo_metadata: false`
  from both. Routing (server, API key, webhook) still comes from the name
  match. Previously only the name match was consulted, so reusing an
  unrestricted repo name for an opted-out directory dropped that directory's
  opt-out.
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
- A local database without a recorded sync time (absent or blank
  `last_sync_at` metadata, for example one that was never synced) is now
  reported as stale instead of fresh. Local scans set `db_stale: true` and show
  the "Local database freshness could not be verified" warning, `packmon db
  info` / `db export` report `db_stale: true`, and `packmon dashboard` shows
  the same warning banner.
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
- The vulnerability batch lookup (PostgreSQL and local SQLite) and the local
  SQLite malicious batch lookup apply the same rule: a versionless request
  next to a concrete version of the same package no longer drops the
  all-versions match, so a local scan and `/api/v1/check` return the same
  findings for such a batch. Requested versions are deduplicated per package
  in request order.
- The PostgreSQL startup package-name repair now folds names with the same
  canonical identity as every write and lookup (`packageid.NormalizeName`)
  for all ecosystems instead of only lower-casing NuGet and folding PyPI.
  Legacy mixed-case GitHub Actions rows and names with surrounding whitespace
  (including untrimmed names an earlier repair left behind) are now merged
  into the canonical row, so their advisories and malicious findings match
  again instead of never being found by a lookup.
- An incremental `packmon db sync` now removes packages a vulnerability no
  longer affects. Local rows used to be only upserted (or deleted when the
  advisory was withdrawn), so after a server-side coverage change -- a manual
  advisory edited to another package, or the package-name repair -- a local
  scan kept reporting the old package until a full sync while
  `/api/v1/check` no longer did. A delta `GET /api/v1/sync` now exports each
  changed vulnerability with its complete current affected set (it no longer
  drops affected rows written after the snapshot). A delta with a `since`
  window that fits in a single page carries the new optional
  `vulnerability_affected_complete: true` field, and the client then replaces
  the local affected rows of each delivered vulnerability in that page's
  transaction. Full exports and every page of a multi-page delta omit the
  field, and the client applies the replacement only to a single-page delta
  with a stored `since`, so a vulnerability changed between two pages of a
  larger delta can never delete still-valid local rows; such deltas stay
  upsert-only (whole-advisory paging is a planned follow-up). The package-name
  repair also marks merged vulnerabilities changed so they enter the next
  delta. Older servers omit the field and older clients ignore it, so both
  keep the previous upsert-only behavior.
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
- SwiftPM `Package.resolved` locations only become a `host/owner/repo`
  identity when their host is a valid DNS hostname or IP address (IPv6 only
  in an `http(s)` URL). SCP-like remotes such as `git@.gitserver.example:org/repo`
  were canonicalized without any host check, so a dot-prefixed, empty-label,
  hyphen-edged, or otherwise malformed host (even `git@..:org/repo` ->
  `../org/repo`) became the package name; the same rules now apply to bare
  `host/path` and `http(s)` locations. A location with a slash before its
  first colon is a local path, as in Git, not an SCP-like remote. Rejected
  locations fall back to the pin's identity.
- Chocolatey inventory ignores a malformed or truncated `config.xml` with a
  `<config>` root but no `<packages>` section (for example `<config><envs>`)
  as an unrelated file. It used to be reported as an "invalid config.xml
  package list" parse error; only a file whose `<packages>` section was
  already read reports a decoder error.
- Chocolatey script inventory keeps quoted separator characters as
  arguments. `Write-Host ';' choco install fake` no longer reports `fake`
  (the quoted `;` used to put `choco` back into command position), and
  `choco install a --params ';' b` reports `b` as well as `a` (the quoted
  `;` used to end the package list).
- Chocolatey script inventory no longer treats a backtick at the end of a
  PowerShell comment as a line continuation. ``# note ` `` followed by
  `choco install git` used to join both lines into one comment and drop
  `git`; the same applied to trailing `#` comments and to lines ending inside
  a `<# ... #>` block comment. A continued command that ends after a closed
  block comment (``<# doc #> choco install a ` `` + `b`) now keeps `b`.
- Chocolatey script inventory reads each script with its own language's
  rules. PowerShell files (`.ps1`, `.psm1`) continue lines only with a
  backtick and batch files (`.bat`, `.cmd`) only with a caret; either marker
  in the other language used to join the next line, so `choco install a ^`
  followed by `choco install b` in a `.ps1` reported `choco` and `install` as
  packages. `#` comments, `<# ... #>` block comments, and here-strings apply
  only to PowerShell files (a batch `echo @"` no longer hides the rest of the
  file, and `#` is ordinary text in batch), and `REM` / `::` comment lines
  only to batch files.

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
