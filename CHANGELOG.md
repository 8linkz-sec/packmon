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
  host UID/GID (or `0:0` under rootless Docker; explicit `PACKMON_UID` /
  `PACKMON_GID` win), so bootstrapping on native Linux no longer fails with
  `permission denied` on a host-owned checkout or `.env`. The production
  server image still runs as `packmon`.
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
