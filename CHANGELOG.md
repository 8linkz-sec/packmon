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

- `/api/v1/sync` pages are now bounded by bytes in every dataset, not only in
  the vulnerability dataset. The malicious, reputation, and lifecycle rows of
  a page were bounded only by the row `limit` (up to 10,000 rows each), so
  large rows (long version lists, references, or summaries) could push one
  page past the 32 MiB a client accepts; the client rejected it with
  `response too large` and the sync never advanced. The server now keeps them
  within estimated byte budgets of 8 MiB, 4 MiB, and 4 MiB besides the
  vulnerability rows' 12 MiB (28 MiB in total). A page cut by its budget
  holds fewer rows than the `limit` but still continues after its last row,
  and every dataset with rows left delivers at least one row per page, so a
  sync makes progress as long as a page fits the cap. Because the first row of
  each dataset is always accepted, only pathological rows several MiB larger
  than their budgets (for example one 13 MiB malicious row next to full
  vulnerability, reputation, and lifecycle pages) can still push a page past
  32 MiB and stall the sync. The wire format is unchanged: current and older
  clients already follow `truncated` and `next_cursor`, and a sequence that
  an older server started continues by its keyset cursors or offsets.
- An incremental `packmon db sync` now drops the packages that an advisory too
  large for one sync page no longer lists, instead of keeping them until a
  full sync. The server split such an advisory over several pages without
  `vulnerability_affected_complete`, so the client only upserted them. Every
  page of a split now names the advisory in the new optional
  `vulnerability_split_advisory` field, the page that starts the split also
  sets `vulnerability_split_start`, and the last split page sets
  `vulnerability_split_complete` when the server finds that neither the
  advisory nor any of its affected packages changed after the pinned snapshot
  (an epoch-safe transaction ID check), so the split pages missed no package
  that still exists. The client collects the packages the split pages of one
  sync delivered and, on that page, drops the advisory's other local packages
  in the synced ecosystems in the page's transaction. It does so only when it
  received the start page (marked, and not requested with an advisory row
  cursor) and every later page of the split; a page without the markers, for
  example from an older server during a rolling upgrade, ends the split. A
  split that changed on the server meanwhile, an interrupted sync, or a split
  that an older server started or continued drops nothing, and the next delta
  delivers a changed advisory again. Older clients ignore the fields and older
  servers omit them, so both keep the previous upsert-only behavior.
- `packmon-server migrate` no longer keeps an `INVALID` index left by an
  interrupted `CREATE INDEX CONCURRENTLY` (connection drop, cancel, crash).
  A retry used to skip such an index because the migrations use
  `IF NOT EXISTS`, so the schema reported the new version while the index
  was never used and its queries fell back to sequential scans. The migrator
  now drops an `INVALID` index of the same name before each concurrent build,
  fails the migration (dirty) unless the build left a valid index, and on
  every run, before any pending migration, rebuilds concurrently any
  `INVALID` or missing index of an already applied migration (010, 011, 021
  and 049 build indexes concurrently); a failed repair aborts the run with
  the schema version clean. A database
  left dirty by an interrupted 049 no longer needs a backup restore: migrate
  still refuses it, but its error names the retry path (clear the 49 dirty
  marker, rerun migrate), documented in "Upgrade And Rollback" in
  `docs/runbook.md`. No migration is added.
- The PostgreSQL `version_ranges` CHECK constraints accepted malformed OSV
  ranges: a range without an `events` key (`[{}]`) and events whose boundary
  was `null`, a number, or blank (`{"introduced":null}`), because the check
  only tested that a boundary key exists. Migration 050 replaces
  `packmon_jsonb_version_ranges_valid` with the rule the store already applied
  before writes (nonempty `events` arrays, event objects, at least one
  nonblank string boundary among `introduced` / `fixed` / `last_affected` /
  `limit`, other boundaries a string or `null`); `[]` stays valid. Existing
  rows that fail it are repaired before the constraints are re-validated:
  affected-package ranges become `[]` (as in migration 032); a malicious
  finding keeps its nonempty exact `versions` and loses only the ranges; an
  active malicious finding without exact versions is quarantined (tombstoned
  via `removed_at`, exported to local clients as withdrawn) instead of becoming
  an all-version blocking finding. Each repaired row is recorded with its
  original value in `packmon_m050_version_range_repairs`, and the 050 down
  migration restores the rows unchanged since the repair (rows changed since
  keep their current state). The store's
  own pre-write check now matches keys exactly, as the database does, so a
  case-variant key such as `"Introduced"` is rejected before the write
  instead of failing the CHECK constraint. The feed
  import endpoint applies the same rule to `version_ranges` in vulnerability
  and malicious imports, so such a range gets a `400` naming the failing
  field (for example `version_ranges[0].events[0].fixed must be a string`)
  instead of the generic store-rejection message. The shared rule also
  requires a range `type`, when present, to be a string or `null`, as the
  range matcher reads it.
- Refresh-queue clear, purge and single-job admin audit details omit
  `requested_at` / `processed_at` for a job that has no such timestamp. They
  used to record an empty string (for example `"processed_at":""` for a job
  that was never processed). Existing audit rows are unchanged; readers must
  treat a missing key as "never set".
- The baseline down migration `001_initial.down.sql` can reverse the baseline
  schema on its own: it dropped `api_keys` before `scan_log`, whose
  `scan_log_api_key_id_fkey` references it, so PostgreSQL refused the drop. It
  now drops `scan_log` first and also removes the two JSON helper functions
  the baseline creates. Down migrations are review and verification aids that
  are never applied by `packmon-server migrate` or server startup; the
  documented rollback path remains restoring the pre-upgrade backup.
- `POST /api/v1/packages/{ecosystem}/{name}/refresh` accepts a chunked request
  with an empty body like a request without a body. Only `Content-Length: 0`
  counted as "no body" before, so an empty chunked body (`Content-Length`
  unknown) got `400 empty JSON body`, or `415` without a JSON Content-Type,
  although the body is optional. Bodies that carry bytes keep the strict
  empty-object rules.
- Feed imports answer `400` instead of `500` when the request passes
  validation but the store rejects a value: an EPSS score or percentile too
  small for the stored precision, a NUL character in a text or JSON field, a
  record that fails the store's own version-JSON checks, or a CHECK
  constraint. Only an allowlist of PostgreSQL value errors (SQLSTATE 22001,
  22003, 22007, 22008, 22021, 22P02, 22P05) and CHECK violations (23514) are
  treated this way; other database errors stay `500`. This covers every
  import path (OSV/GHSA, OpenSSF/Socket, VulnCheck, CISA KEV and EPSS,
  buffered and streamed). The response and the
  recorded `rejected` feed status carry the fixed message "feed import
  contains values the store cannot accept"; the detailed store error is only
  logged. Nothing from the rejected import commits.
- The `packmon scan --outdated --html` report now shows the list-all report's
  warning lines at the top. When lockfiles or SBOMs fail to parse, it says
  "Inventory incomplete: N files could not be parsed:" followed by the file
  names (never their directories or full paths). It also shows the registry
  lookup warnings (refused or failed requests, oversized responses, lookups
  skipped after consecutive failures). Like the list-all report, it shows at
  most five lines and counts the rest in one closing line. These diagnostics
  used to go
  only to stderr, so a report from a partially parsed inventory, which exits
  `4`, looked complete. A run without warnings renders the report as before.
- Diagnostic redaction now hides secrets whose key is quoted, as in JSON or
  dict-style error text: `"password":"x"`, `"api_key": "x"`, `'token':'x'`, and
  `\"token\":\"x\"` inside an escaped JSON string, with optional whitespace
  around `:` or `=`. These values used to reach logs and error messages in
  clear text, because the separator had to follow the key name directly. Only
  the secret values are redacted; the other fields of the object stay
  readable. An escaped value of JSON inside a JSON string
  (`\"token\":\"a b\"`) is redacted up to its matching escaped closing quote,
  so the part after its first space no longer leaks. A backslash-escaped
  newline inside a secret value (`password='ab\` followed by a line break)
  also no longer ends the redaction early and leaks the rest of the value.
- Diagnostic redaction now also hides secrets whose key name carries a secret
  word as one component: `"authToken":"x"`, `"db_password":"x"`,
  `"DB_PASSWORD":"x"`, `"client_secret_value":"x"`, `GITHUB_TOKEN=x`,
  `PGPASSWORD=x`, and `x-api-key: x` used to reach logs and error messages in
  clear text, because the key had to be exactly the secret word. The secret
  word must end a component of the name (split at `_`, `-`, `.`, digits, and
  camelCase boundaries), so `tokenizer`, `tokens_count`, `passwordless`, and
  `secretariat` stay readable. The plurals `credentials`, `secrets`,
  `passwords`, and `passwds` are secret words too; `tokens` is not, because
  it usually holds a count. An object or array assigned to a secret key
  (`"token": {"value": "x"}`, `"password": ["a", "b"]`) is now redacted as a
  whole up to its balanced closing bracket; before, everything after its
  first delimiter leaked. JSON embedded in a JSON string more than once
  (`\\\"token\\\":\\\"a b\\\"`) is now redacted too. A value cut off inside
  embedded JSON now ends where the enclosing string closes, so the fields
  after that string stay readable.
- The CLI no longer creates its local SQLite database (and its WAL and
  journal files) in the working directory when the home directory cannot be
  resolved. The default `~/.packmon/db` used to fall back to `./.packmon/db`,
  usually inside whatever repository the CLI ran in. Without a home directory
  and without `PACKMON_DB_PATH` or `db.path`, commands that need the database
  now fail with `the home directory is unknown; set PACKMON_DB_PATH or
  db.path`, auto-mode fallback and scan history warn and skip it, a `--hook`
  scan exits `2`, and `packmon config show` reports `db_path` as unresolved.
- `--outdated` / `--list-all` start the per-request `--timeout` when a
  registry request leaves the shared rate limiter. The deadline used to start
  before the queue wait, so with a small `--timeout` and many packages a
  request could expire before it was sent; the row ended up `unknown` and the
  lookup counted as neither refused nor skipped, so no warning appeared. The
  queue wait is now bounded only by the scan itself, and a queued lookup that
  ends for any reason other than a user cancellation (for example a caller
  deadline) counts as a refused request in the stderr warning and the
  list-all HTML hint, without advancing the consecutive-failure breaker.
- `--outdated` / `--list-all` resolve npm dependency ranges for popular
  packages again. The npm metadata lookup read the full packument through the
  general 512 KiB registry limit, which popular packages exceed, so their
  rows ended up `unknown` with a refused-request warning. The lookup now
  requests npm's abbreviated install document
  (`Accept: application/vnd.npm.install-v1+json`, full packument as fallback)
  under a dedicated 16 MiB limit. Responses discarded for exceeding a size
  limit now get their own warning on stderr and in the list-all HTML hint
  instead of the refused-request advice to rerun or raise `--timeout`, which
  cannot help for them.
- `packmon report` exits `2` (operational error) when writing the report to
  stdout fails. It used to discard every write error outside the history
  table, so a closed pipe or full disk ended the command with exit `0` and no
  (or a truncated) report, and the empty-history message never failed at all.
- `--outdated` / `--list-all` latest-version lookups whose `200` registry
  response exceeds the read limit (512 KiB for most registries) now count as
  failed lookups, so the stderr warning and the list-all HTML hint report
  them. They used to count as successes without any warning
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
  drops affected rows written after the snapshot). A delta now pages the
  vulnerability dataset by whole advisories: every page is one statement,
  ordered by advisory ID behind a versioned advisory cursor, and never splits
  an advisory across pages; an advisory with more affected rows than the
  `limit` is a page of its own, so that page holds more rows than the limit.
  Every such delta page carries the new optional
  `vulnerability_affected_complete: true` field, and the client then replaces
  the local affected rows of each vulnerability delivered on that page in the
  page's transaction -- on a single-page delta and on every page of a larger
  one. An advisory that changes between two pages is delivered whole on a
  later page or by the next delta, or excluded whole, never partially, so no
  page can delete still-valid local rows; a failed sequence does not advance
  the `since` window. Full exports and delta pages that continue a legacy row
  cursor or offset keep row paging and omit the field, and unflagged pages stay
  upsert-only. The server still accepts the legacy row cursor of a sequence an
  older server started, and rejects an advisory cursor without `since`. The
  package-name repair also marks merged vulnerabilities changed so they enter
  the next delta. Older servers omit the field (or set it only on a delta that
  fits in one page) and older clients ignore it, so both keep the previous
  upsert-only behavior on larger deltas.
- An incremental `packmon db sync` now also removes an advisory that lost every
  affected package on the server. Such an advisory had no affected row left,
  so no delta page ever delivered it and a local scan kept reporting it until a
  full sync while `/api/v1/check` no longer did. A flagged delta page
  (`vulnerability_affected_complete`) now lists the IDs of such changed
  advisories in the new optional `vulnerabilities_without_affected` array, and
  the client drops their local rows in that page's transaction. The list is
  scoped to the requested ecosystems: an ecosystem-filtered sync also lists an
  advisory without an affected package in those ecosystems (for example one
  whose coverage moved to another ecosystem) and drops only its rows in those
  ecosystems. Each listed advisory takes one row of the page's `limit`. Older
  clients ignore the field and older servers omit it, so both keep the
  previous behavior.
- An incremental `packmon db sync` no longer fails on every retry when one
  advisory has an unusually large affected set. Whole-advisory paging always
  delivered the first advisory of a page complete, so such an advisory (its
  summary and references repeat on every affected row) could make one page
  larger than the 32 MiB a client accepts; the client rejected it with
  `response too large` and the local database never advanced. The server now
  bounds the vulnerability rows of every sync page by an estimated 12 MiB as
  well as by the row `limit`: a page ends after the last whole advisory that
  fits and stays flagged, and an advisory whose rows alone exceed the budget is
  split over several pages in (ecosystem, name) order behind a new opaque
  advisory row cursor. Those pages omit `vulnerability_affected_complete`, so
  the client only upserts them and packages such an advisory no longer lists
  stay until a full sync (a completed split now drops them, see
  `vulnerability_split_complete` above); the advisories around it are still
  replaced. Full
  exports and legacy delta row pages honor the same budget. An older server
  rejects the new cursor with `400` if it continues a sequence a new server
  started, and the next sync starts over.
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
  in an `http(s)` URL). SCP-like remotes such as
  `git@.gitserver.example:org/repo` were canonicalized without any host
  check, so a dot-prefixed, empty-label, hyphen-edged, or otherwise malformed
  host (even `git@..:org/repo` -> `../org/repo`) became the package name; the
  same rules now apply to bare `host/path` and `http(s)` locations. Hosts with
  non-ASCII (IDN) characters or underscores are no longer canonicalized
  either; write internationalized hosts in their punycode (`xn--`) form. A
  location with a slash before its first colon is a local path, as in Git,
  not an SCP-like remote. Rejected locations fall back to the pin's identity.
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
- Chocolatey script inventory reads batch files (`.bat`, `.cmd`) with cmd.exe
  quoting and escaping instead of the PowerShell rules, so batch `choco
  install` lines are no longer split or joined wrongly. A single quote is
  ordinary text (`echo 'x & choco install b'` reports `b`, and
  `choco install 'a'` no longer reports `a`); a caret inside double quotes is
  literal and no longer continues the line, which used to swallow the next
  command; an unquoted caret escapes the next character, so `^&`, `^|`,
  `^<`, and `^>` are arguments rather than separators or redirects and `^"`
  opens no quote; a line ending in `^^` (a literal caret) or in a caret
  followed by spaces no longer continues and no longer reports the next
  command's `choco` / `install` words as packages. A continued line is joined
  without an inserted space and the first character of the next line is
  escaped, as in cmd.exe. Only the cmd.exe separators `&`, `&&`, `||`, `|`,
  and block parentheses start a new batch command: `;`, `{`, `}`,
  and `=` are ordinary text, so `echo x;choco install a` and
  `set x = choco install a` no longer report `a`, and `choco install a ; b`
  reports `b` as well. A batch `--version='1.0'` keeps its single quotes, as
  cmd.exe passes them to choco.exe, and is reported unpinned instead of as
  version `1.0`. PowerShell parsing is unchanged.
- Chocolatey script inventory removes a redirection together with its target
  instead of treating it as a command separator, in PowerShell and batch
  files alike. `>nul choco install a` used to report nothing and
  `choco install a >nul b` only `a`, although the shell runs choco with both
  packages; a word after a redirection such as `echo x > choco install a` is
  no longer read as a command either. This covers `>`, `>>`, `<`, `2>`,
  `2>>`, `*>`, `2>&1`, `1>&2`, `>nul`, `>$null`, and quoted targets.
- Chocolatey script inventory groups a batch `^"...^"` for choco.exe's
  argument splitting, so `choco install a --params ^"/x y z^"` no longer
  reports `y` and `z` as packages; `&` and `|` after a `^"` still separate
  commands. An empty `""` is an argument in batch files, so
  `--version "" b` no longer reads `b` as the version.
- Chocolatey script inventory recognizes batch `choco` commands after
  `for ... in (...) do`, after an `if` condition (`if exist x`, `if not ...`,
  `if errorlevel 1`, `if defined x`, `if "%1"==""`, `if %x% EQU 1`, with
  `/i`), and after `else`; they used to be missed. The words of a `for` set
  are no longer read as commands. A batch `%ProgramFiles(x86)%` expansion and
  a PowerShell `${env:ProgramFiles(x86)}` variable stay one word, so their
  parentheses no longer split a command (`Write-Host
  ${env:ProgramFiles(x86)} choco install a` no longer reports `a`).
  PowerShell `if` / `foreach` / `try` block bodies were already recognized.
- Chocolatey script inventory reads batch parentheses with the cmd.exe block
  rules instead of splitting a command at every `(` and `)`. A `(` opens a
  block only where a command starts (line start, after `&` / `|` / `(`, after
  an `if` condition, after `else` or `do` that follows a closing parenthesis,
  as a `for` set, and after an `@`), and a `)` closes one only while a block
  is open, which a multi-line block keeps open across lines; any other
  parenthesis is argument text. So `echo Installing (x86) choco install a`
  no longer reports `a`, `choco install a (x86) b` and
  `choco install a >out(1).log b` report `b` as well, a `^"...^"` group such
  as `--params ^"/InstallDir:C:\Program Files (x86)\x^" b` is no longer split
  at its parentheses (so `b` is reported), and an unbalanced `)` outside any
  block no longer starts a command (`) choco install a` reports nothing).
  The attached forms `)else(`, `do(`, and `in(`, which cmd.exe rejects as a
  syntax error, are tolerated and conservatively read as block openers. A
  bare `@` prefix keeps command position, so `@ choco install a` now reports
  `a`. A caret-escaped blank inside an `if` condition stays part of its
  operand, as cmd.exe reads it, so
  `if exist C:\Program^ Files\Git choco install git` now reports `git`.
  PowerShell parsing is unchanged.
- `packmon-server migrate` no longer bounds the migrations themselves by
  `PACKMON_DB_CONNECT_TIMEOUT` (default `10s`). The whole run used to share
  that deadline, so on a large catalog the 049 `CREATE INDEX CONCURRENTLY`
  builds or the single-transaction 050 repair were cancelled, leaving the
  database dirty at that version (049 also with `INVALID` indexes). The
  timeout now bounds connecting, the migration advisory-lock wait and the
  post-migration version read only; the migrations and the rebuild of
  `INVALID` or missing concurrently built indexes run until they finish or
  `SIGINT`/`SIGTERM` cancels the run. A cancelled run asks PostgreSQL to
  cancel the running statement instead of dropping the connection, then
  records the failed attempt (with `finished_at`) in `schema_migration_events`
  and releases the advisory lock on a separate short deadline; the failure
  bookkeeping and the lock release used to run on the already cancelled
  context and could fail. When the bookkeeping or the lock release fails, the
  migrate error now reports that failure together with the migration error.

### Security updates

- No security fixes pending disclosure.

### Operator action

- Run `packmon-server migrate` (or the `packmon-migrate` compose service)
  before starting the updated server: this release adds schema migrations 047
  to 050 (schema version 46 -> 50), applied in one run. The server refuses to
  start on a schema version mismatch. Read "Upgrade And Rollback" in
  `docs/runbook.md` first; a failed migration other than a 048 prerequisite
  failure leaves the database dirty, and the documented recovery is restoring
  the pre-upgrade backup, except for an interrupted 049 (see below). The run
  has no overall time limit (index builds and 050 can take a while on a large
  catalog); `PACKMON_DB_CONNECT_TIMEOUT` does not need raising for it, and
  Ctrl-C or `SIGTERM` cancels it.
  - 047 widens the ecosystem CHECK constraints for the inventory-only
    `chocolatey` ecosystem. Rolling 047 back removes any `chocolatey` rows
    (none are written by the scan path).
  - 048 creates the `pg_stat_statements` extension and needs preparation
    first: `pg_stat_statements` in `shared_preload_libraries` (bundled
    Compose: recreate the `postgres` service), `compute_query_id` on or
    `auto`, and for external PostgreSQL an administrator-created extension in
    schema `public` (see `docs/postgres-query-observability.md`). The check
    runs before anything is marked dirty, so missing preparation leaves schema
    47 clean and retryable. Rolling 048 back keeps the extension.
  - 049 builds two partial indexes over active `malicious_findings` rows with
    `CREATE INDEX CONCURRENTLY`, outside a transaction. It avoids a long
    write lock but can run for a while on large catalogs; check PostgreSQL
    temporary space and volume headroom before starting. If 049 is
    interrupted, clear its dirty marker
    (`DELETE FROM schema_migrations WHERE version = 49 AND dirty;`) and rerun
    migrate; it replaces any `INVALID` index the interrupted run left.
  - 050 tightens the `version_ranges` CHECK constraints and repairs rows that
    fail them. In one transaction it scans `affected_packages` and
    `malicious_findings` to log the failing rows in
    `packmon_m050_version_range_repairs`, rewrites the logged rows, and scans
    both tables again to validate the constraints, holding an exclusive lock
    on both tables from the constraint step until it commits. Repaired
    affected-package rows match every version until the next feed sync
    rewrites them, so finding totals for those packages can
    rise temporarily. Malicious findings without exact versions are
    quarantined: they stop blocking until a feed import that contains them
    resurrects them, and quarantined manual advisories (`manual:` IDs) must
    be re-entered in `/admin/advisories`. The migration reports its counts as
    a PostgreSQL NOTICE; list the repaired rows afterwards with the query in
    "Upgrade And Rollback" in `docs/runbook.md`.
- Databases already past a concurrent index migration (010, 011, 021, 049),
  including those already at schema 49 or 50: the next `packmon-server
  migrate` run rebuilds any `INVALID` or missing index such a migration
  builds (it needs no pending migration). It is a no-op when every index is
  valid; to
  check beforehand, run `SELECT indexrelid::regclass FROM pg_index WHERE NOT
  indisvalid;`. A rebuild takes as long as the original build, so drain the
  server first.
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
