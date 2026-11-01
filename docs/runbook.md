# Runbook

## Services

- API and web UI: port `8080` (`PACKMON_SERVER_PORT`; the Compose files use
  the same value for the in-container listener and both sides of the
  `127.0.0.1` port mapping, so point your reverse proxy at the same port)
- metrics: `127.0.0.1:9090` -- host loopback for bare-metal / non-Compose
  starts; in both Compose deployments it is container loopback, so read it with
  `docker compose exec` (see the note under `Restore`), not a host curl
- PostgreSQL: port `5432`

Persistent Docker volumes (project-scoped, by default `packmon_<name>`):

- `postgres-data`: the PostgreSQL cluster. Covered by the `Backup` section.
- `feed-data`: the server's feed working directory (`/data/feeds`) with the
  git checkouts of the GHSA advisory database and the OpenSSF
  malicious-packages repository. It needs no backup -- after loss the next
  sync re-clones -- but keeping it avoids a full re-clone of roughly 350k files
  on every container recreation.

In `docker-compose.server.yml`, `postgres` and `packmon-server` run with
`restart: unless-stopped`, so they come back after a crash, a Docker daemon
restart, or a host reboot. A container stopped explicitly with
`docker compose -f docker-compose.server.yml stop` (or removed with `down`)
stays down, including across daemon restarts. The one-shot `packmon-migrate`
and `packmon-backup` jobs never restart.

## Transport security (read before first production start)

In production mode (`PACKMON_SERVER_MODE=production`, the default) the server is
**fail-closed**: it refuses to start unless the client channel is protected by
one of these:

1. In-app TLS: set both `PACKMON_TLS_CERT_FILE` and `PACKMON_TLS_KEY_FILE`
   (optional `PACKMON_TLS_MIN_VERSION`, default `1.2`, accepts `1.2` or `1.3`).
   The certificate's SAN must include every hostname/IP that clients use to
   reach the server -- important when clients sit in separate networks.
2. A TLS-terminating reverse proxy in front: set `PACKMON_TRUSTED_PROXIES` to
   the proxy IPs/CIDRs.
3. Local-only Docker: `PACKMON_ALLOW_INSECURE_LOCAL_HTTP=true` together with a
   loopback `PACKMON_SERVER_PUBLIC_HOST` (e.g. `localhost:8080`). Plain HTTP,
   only safe when the port is bound to `127.0.0.1`.

The repository-provided `docker-compose.server.yml` deployment uses option 2:
the server serves plain HTTP in-container, the server port is published only
on `127.0.0.1`, and the operator must terminate TLS at their own reverse proxy
and set `PACKMON_TRUSTED_PROXIES` to the proxy's IP/CIDR:

```bash
# Production server (behind your own TLS reverse proxy):
docker compose -f docker-compose.server.yml run --rm packmon-migrate
docker compose -f docker-compose.server.yml up -d
```

Example nginx front (TLS terminated at the proxy, forwarding to the
loopback-published server):

```nginx
server {
  listen 443 ssl;
  server_name packmon.example.com;
  ssl_certificate     /etc/ssl/packmon/fullchain.pem;
  ssl_certificate_key /etc/ssl/packmon/privkey.pem;
  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

Set `PACKMON_TRUSTED_PROXIES` to the proxy's source address as seen by the
container (e.g. the Docker gateway CIDR).

When none is configured the server exits with:

```text
config: refusing to start in production without transport security: set
PACKMON_TLS_CERT_FILE and PACKMON_TLS_KEY_FILE for in-app TLS, or
PACKMON_TRUSTED_PROXIES when running behind a TLS-terminating reverse proxy
```

The startup log states which transport is active (`https` listener vs `http`).

CLI clients enforce `https://` for `--server` and refuse to send the API key
over plain HTTP unless `--insecure-allow-http` / `PACKMON_INSECURE_ALLOW_HTTP`
is set. Distribute an internal CA bundle to clients via `--cacert` /
`PACKMON_CA_CERT_FILE`; `PACKMON_CA_CERT` remains a legacy alias. Use
`--require-remote` / `PACKMON_REQUIRE_REMOTE` on CI runners so a broken or
unreachable server fails the pipeline instead of silently falling back to the
(possibly stale) local DB.

## Backup

Packmon uses a daily PostgreSQL archive dump with 7-day local retention.
External backup systems are responsible for off-host or longer-term retention.

Recommended target path:

```text
/backups/packmon/
```

Use the deployment scheduler or database host automation to run a daily backup
job that creates the same custom archive format restored by the command below:

```bash
install -d -m 0700 /backups/packmon
pg_dump \
  --format=custom \
  --file "/backups/packmon/packmon-$(date -u +%Y%m%d-%H%M%S).dump" \
  packmon
find /backups/packmon -type f -name 'packmon-*.dump' -mtime +7 -delete
pg_restore --list "$(ls -1t /backups/packmon/packmon-*.dump | head -n 1)" >/dev/null
```

For the repository-provided Compose model, run the same policy as an explicit
operator action:

```bash
docker compose -f docker-compose.server.yml run --rm packmon-backup
```

The backup covers PostgreSQL only. The `feed-data` volume is deliberately not
backed up: it holds re-clonable upstream git checkouts, and a restored server
with an empty feed volume re-clones them on its next feed sync.

For Docker Compose deployments, run the same command from a host or job
container that can reach the PostgreSQL service and receives database
credentials through the deployment secret path. Do not write database passwords
into the command line or into tracked files.

Backups contain personal data and security-relevant metadata such as scan logs,
admin audit logs, API-key history, package names, repository identifiers, and
feed provider status. Keep dump directories at `0700`, encrypt dumps at rest
with age, GPG, or storage-managed encryption, restrict restore access to the
same operator group that can administer production, and replicate only through
approved off-host backup storage.

The `PACKMON_ENCRYPTION_KEY` deployment secret is part of the recovery set when
stored feed API keys exist. Back it up with the same access controls as the
database backup, because changing or losing it prevents Packmon from decrypting
stored provider keys after restore.

## Restore

1. Stop the API server.
2. Ensure PostgreSQL is running.
3. Make sure the selected dump is available on the database host or mounted
   backup volume.
4. Restore into a clean target database. Do not restore a full dump into an
   existing populated Packmon database.

```bash
psql -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'packmon' AND pid <> pg_backend_pid();"
dropdb --if-exists packmon
createdb --owner packmon packmon
pg_restore --single-transaction --no-owner --no-privileges --role packmon -d packmon /backups/packmon/packmon-YYYYMMDD-HHMMSS.dump
```

5. If the restored dump comes from an older Packmon release, run the explicit
   migration command for the version you are starting.
6. Verify the restored deployment has the same `PACKMON_ENCRYPTION_KEY` that
   was active when encrypted feed API keys were saved.
7. Start `packmon-server`.
8. Verify readiness before routing traffic. Do not use `/healthz` alone; it is
   a liveness endpoint and can succeed before the database-backed service is
   ready.

```bash
# Use https:// when in-app TLS is enabled (PACKMON_TLS_CERT_FILE/KEY_FILE).
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/version
# Bare-metal / non-Compose deployments only; under Compose see the note below.
curl -fsS http://127.0.0.1:9090/metrics
```

Note: in both Compose deployments metrics stay on container loopback
(production rejects a non-loopback `PACKMON_METRICS_HOST`), so a host curl
cannot reach them; `docker-compose.server.yml` does not publish the metrics
port at all. Verify metrics with
`docker compose -f docker-compose.server.yml exec packmon-server wget -qO- http://127.0.0.1:9090/metrics`
instead of a host curl.

## Upgrade And Rollback

Packmon server startup verifies the schema version and does not run migrations
implicitly. Treat binary rollout and database migration as one operator-owned
change.

1. Capture the target Packmon version and current database schema version from
   `/version`, `packmon_build_info`, and `packmon_db_migration_version`.
2. Take and verify a fresh backup with the command in `Backup`.
3. Stop or drain `packmon-server` so clients do not write during migration.
4. Apply release-specific database prerequisites before running migrations,
   and plan for the per-migration notes below. `packmon-server migrate`
   applies every pending migration in one run. Apart from the 48 prerequisite
   check, a migration that fails is recorded as dirty at its version, and
   migrate and server startup then refuse that database; recover by restoring
   the pre-upgrade backup (see the rollback steps below).
   - Migration 48 (`048_pg_stat_statements`, schema 47 -> 48) creates the
     `pg_stat_statements` extension in schema `public` for PostgreSQL query
     observability. Follow
     [`postgres-query-observability.md`](postgres-query-observability.md)
     first. For the bundled database, recreate and wait for PostgreSQL so the
     new preload setting is active while preserving its named volume:
     ```bash
     docker compose -f docker-compose.server.yml up -d --force-recreate --wait postgres
     ```
     External PostgreSQL requires the documented administrator preload,
     restart, query-ID setting, and extension creation instead. The migration
     itself is quick; its prerequisites are checked before anything is marked
     dirty, so a missing preload, query-ID setting or extension leaves schema
     47 clean and retryable. Its down migration keeps the extension, which may
     be shared with other users of the database.
   - Migration 49 (`049_malicious_active_search_indexes`, schema 48 -> 49)
     builds two partial covering indexes over active `malicious_findings`
     rows with `CREATE INDEX CONCURRENTLY`, outside a transaction. Before
     starting it, verify PostgreSQL has temporary working space and
     durable-volume headroom for both index builds. The concurrent build
     avoids a long table-write lock but still consumes I/O and CPU and takes
     longer on large catalogs; keep the server drained as required above and
     monitor PostgreSQL logs. An interrupted concurrent build can leave an
     `INVALID` index behind, and a retry would keep it because the statements
     use `IF NOT EXISTS`; restore the backup rather than retrying by hand.
   - Migration 50 (`050_version_range_boundary_values`, schema 49 -> 50)
     tightens the `version_ranges` CHECK constraints on `affected_packages`
     and `malicious_findings` (every range needs a nonempty `events` array and
     every event a nonblank string boundary). Inside one transaction it scans
     both tables once to repair rows that only passed the older check and once
     more to validate the constraints; expect it to take longer on large
     databases. The re-added constraints hold an exclusive lock on both
     tables until the transaction commits, so reads and writes to them wait
     during validation (another reason to keep the server drained). A failure
     rolls back every 50 change but still leaves the version dirty. Repaired
     affected-package rows fall back to `[]` (every version of that package is
     treated as affected) and repaired malicious-finding rows to `NULL`
     ranges, so the affected packages may report more findings until the next
     feed sync rewrites them with valid ranges. Compare finding/blocking
     totals by feed source after the upgrade and run the feed syncs before
     treating a spike as new risk. The repair is one-way: the 050 down
     migration restores only the previous check function, so restore the
     pre-upgrade backup if the original rows are needed.
5. Run the explicit migration step:
   ```bash
   docker compose -f docker-compose.server.yml run --build --rm packmon-migrate
   ```
6. Start the new server build:
   ```bash
   docker compose -f docker-compose.server.yml up --build -d packmon-server
   ```
7. Verify `/healthz`, `/readyz`, `/version`, `/metrics`,
   `/api/v1/feeds/status`, and the admin dashboard.
8. Run a remote CLI scan with a non-production test key or a known safe target.

If startup fails before a migration changed the schema, roll back the binary and
start the previous server version. If a migration already changed the schema,
assume rollback requires restoring the pre-upgrade dump into a clean database
before starting the older binary. Do not rely on normal server startup to bring
an older schema forward or a newer schema backward.

For an operator rollback:

1. Stop or drain the new `packmon-server` instance.
2. Redeploy the previous known-good Packmon binary or container image and its
   matching Compose or service definition.
3. If no migration ran, verify the current `packmon_db_migration_version` is
   compatible with the previous binary before starting it.
4. If a migration ran or schema compatibility is uncertain, restore the
   pre-upgrade dump into a clean database before starting the previous binary.
5. Start the previous server and verify `/healthz`, `/readyz`, `/version`, and
   `/metrics`; then run a remote CLI smoke scan with a non-production test key.
6. Record the rollback, release version, schema version, backup used, and
   operator action in the operator change log.

Known limitation of migration 005 (`005_normalize_unknown_severity`): its up
migration records the malicious-finding IDs it backs up from the affected
entries flagged `malicious`, but inserts findings for every affected entry of
those advisories, numbering them `<advisory id>-<index>` when an advisory has
more than one. The two ID sets can differ, and an index-based ID can coincide
with an unrelated existing finding ID. Its down migration therefore cannot be
trusted to restore `malicious_findings` exactly. Applied migrations are
checksum-verified on every `packmon-server migrate` run, so 005 cannot be
changed for databases that already ran it, and on a fresh install it runs
before any feed data exists, where the defect has no effect. Use the
pre-upgrade backup, never the 005 down migration, to get back to a schema older
than 5.

## API Key Rotation

API keys expire no more than 365 days after creation (legacy keys created
before expiration support have no expiry). Rotate one client class at a time so
scans and imports keep working while the old key remains available.

1. In `/admin/keys`, create a replacement key with a clear name such as
   `ci-main-2026-07` and a lifetime in whole days within the 365-day limit.
2. Update the matching client secret store, CI variable, N8N credential, or
   user environment variable. Prefer `PACKMON_API_KEY` or config `api_key_env`
   over plaintext command-line arguments.
3. Run the affected scan, sync, or feed-import job and verify success.
4. Confirm the replacement key's `last_used_at` moved in `/admin/keys`.
5. Revoke the old key and keep the row for audit history.

For suspected key exposure, revoke the key first, then create a replacement and
check recent scan logs, auth failure metrics, and admin audit entries for
unexpected use.

## Admin Access Control

Packmon uses one shared admin identity. For production environments where
privileged access requires stronger assurance, enforce MFA or SSO in a trusted reverse proxy
or identity provider before requests can reach `/admin`.

- restrict /admin network reachability to the proxy or private management
  network;
- block direct access to the Packmon listener from administrator workstations;
- keep Packmon's own admin password, session timeout, CSRF, lockout, and
  current-password step-up controls enabled behind the proxy;
- record the proxy/identity-provider policy, MFA requirement, allowed groups,
  and break-glass process in the operator change log.

## Encryption Key Backup And Rotation

`PACKMON_ENCRYPTION_KEY` encrypts persisted feed provider API keys in
production. Keep it stable across restarts, upgrades, and restores.

- Store it in the deployment secret manager, not in tracked files.
- Back it up with the same recovery scope and access controls as PostgreSQL
  dumps.
- Verify the key is present before restoring or starting a production server.
- Do not change it in-place while encrypted feed API keys are stored.

For planned rotation, record which feeds show a configured key, deploy the new
secret in a maintenance window, re-enter or clear each provider key through
`/admin/feeds`, trigger manual syncs where supported, verify feed status, and
only then retire the old secret.

## Operational Objectives

These defaults are starting points for internal deployments. Environment owners
should replace them with stricter or looser objectives where their service
model requires it.

| Objective | Default target | Breach response |
|---|---:|---|
| API/web availability | 99.5% monthly | Open an incident, check `/healthz`, `/readyz`, recent deploys, and PostgreSQL. |
| API check latency | p95 below 2 seconds for normal package lists | Inspect DB pool, queue backlog, feed status, and CPU/memory. |
| Feed freshness | No required self-managed feed stale beyond cadence plus 2 hours | Follow `Server reports degraded feed status`. |
| Refresh queue age | Oldest active job below 2 hours by default | Follow `Queue is not draining`; tune workers or provider credentials. |
| Backup RPO | Roughly 24 hours | Verify the latest dump exists and passes `pg_restore --list`. |
| Restore RTO (Recovery Time Objective) | Operator-owned, documented per deployment | Run a restore drill after backup, schema, or storage changes and record the measured restore time. |

## Incident Response

Open an operational incident when Packmon is unavailable, feed status is
degraded past the alert window, a migration fails, a restore is needed, repeated
auth failures suggest misuse, or an API/feed key may be exposed.

1. Assign an incident lead and record the start time, affected surfaces, and
   current Packmon version.
2. Check `/healthz`, `/readyz`, `/version`, `/metrics`, `/api/v1/feeds/status`,
   `/admin/queue`, recent server logs, and recent deployment changes.
3. Classify severity by user impact: outage, degraded scan coverage, delayed
   async enrichment, or administrative-only impact.
4. Communicate status to affected client owners and CI/automation maintainers.
5. Apply the smallest mitigation: rollback binary before migration, restore
   from backup after migration/data loss, rotate keys, disable a failing
   optional feed, or pause/retry queue jobs.
6. After recovery, record timeline, root cause, customer impact, permanent
   follow-up, and any documentation updates.

Classify each incident before closure:

- availability incident: Packmon API, web UI, queue, or feed refresh is
  unavailable beyond the deployment objective;
- security incident: API keys, admin credentials, feed provider secrets,
  release artifacts, or scan integrity may be compromised;
- personal-data breach: scan logs, admin audit logs, package/repository
  identifiers, client IPs, or operator identities may have been exposed or
  altered without authorization;
- NIS2 / regulatory candidate: the operator legal/compliance owner must assess
  whether reporting duties apply, including early warning within 24 hours and
  notification within 72 hours where the deployment is in scope.

Record the notification decision, owner, timestamp, evidence reviewed, and any
external notices or customer communications in the operator incident record.

## Capacity And Scaling

Packmon is single-server by default. Adding multiple `packmon-server` replicas
is not a safe first response without a separate HA design for admin sessions,
background workers, migrations, and queue processing.

When capacity pressure appears:

1. Check HTTP latency, `packmon_degraded_responses_total`, and Go runtime
   resource metrics such as `packmon_go_goroutines` and
   `packmon_go_heap_alloc_bytes`.
2. Check queue size and oldest active job age.
3. Check `packmon_db_pool_connections` for acquired connections approaching
   max.
4. Check feed age, sync duration, sync timeouts, and upstream provider rate
   limits.
5. Check host CPU, memory, and PostgreSQL limits.

Safe first knobs are vertical host/container resources, PostgreSQL capacity,
`PACKMON_DB_MAX_CONNS`, `PACKMON_DB_MIN_CONNS`, rate-limit settings, per-feed
cadence, and whether startup feed sync should run during maintenance. Keep
Compose resource-limit changes in the operator-owned deployment configuration.

## Privacy Metadata Export

Covered operators that need to answer a right-to-know/access request for
Packmon-held server metadata can run an offline export against PostgreSQL:

```bash
packmon-server privacy export --selector client-ip=203.0.113.10 --format json
```

Supported exact selector types are `client-ip`, `repo-name`, `api-key-id`,
`api-key-name`, and `correlation-id`. The export includes matching `scan_log`
rows and matching `admin_audit_log` rows across the retained database window.
Treat the JSON output as sensitive operational metadata and store or transmit it
only through the operator's approved privacy-request process.

The command verifies the schema version before reading, refuses dirty or
unexpected schemas, and writes a `privacy_export` admin-audit row before
emitting JSON. The audit row records selector type, a `sha256:` selector
digest, and exported row counts; it does not store the raw selector value.
Free-form admin-audit detail JSON is matched only through a small whitelist of
known keys, so the export is an operator helper rather than an identity-proofing
or legal-completeness workflow.

## Troubleshooting

### Server refuses to start (transport security)

Symptom: startup exits immediately with `config: refusing to start in
production without transport security: ...`.

Cause: production mode with no TLS, no trusted proxy, and no local override.

Actions: pick one option from the "Transport security" section above:

- enable in-app TLS (`PACKMON_TLS_CERT_FILE` + `PACKMON_TLS_KEY_FILE`), or
- set `PACKMON_TRUSTED_PROXIES` if a TLS-terminating proxy fronts the server, or
- for local Docker only, set `PACKMON_ALLOW_INSECURE_LOCAL_HTTP=true` with a
  loopback `PACKMON_SERVER_PUBLIC_HOST`.

A related variant -- `PACKMON_ALLOW_INSECURE_LOCAL_HTTP requires
PACKMON_SERVER_PUBLIC_HOST to be localhost/127.0.0.1/::1` -- means the insecure
override is set but the public host is not loopback. Either point the public
host at loopback or configure real TLS / a trusted proxy.

`config: invalid PACKMON_SERVER_PUBLIC_HOST (want a bare host[:port] ...)`
means the value is not just a hostname, IPv4 address, or IPv6 literal plus an
optional port 1-65535. Remove any scheme, path, `?query`, `#fragment`,
`user@`, percent-escape, or whitespace (for example `packmon.internal:8443`
or `[2001:db8::1]:8443`).

### ReversingLabs reputation feed (demand-driven)

ReversingLabs is optional, self-mode only, and disabled by default
(`PACKMON_FEED_REVERSINGLABS_ENABLED=false`). It does NOT do a bulk sync, so it
will not show a normal "last sync" age like OSV/GHSA -- it lazily looks up a
package version (at most once per `PACKMON_REVERSINGLABS_LOOKUP_TTL`, default
24h) only when that package appears in a `/api/v1/check` and no other feed
already covers it.

Operational notes:

- Requires `PACKMON_REVERSINGLABS_API_KEY`. `external` mode is rejected at
  startup (there is no import endpoint).
- Batch size is capped at 5 (free-plan `/find/packages` limit).
- Rate-limit, capacity, or network failures degrade the feed but must NOT fail
  scans or delete cached data. Watch the queue metrics below; the worker shares
  the refresh queue (`source = reversinglabs`).
- A `removed` package maps to a blocking `supply_chain_risk` finding; a
  `malicious` package maps to a blocking malware finding. The first scan of an
  unseen package only schedules the lookup, so it blocks on a later scan.

### CLI warns that the local DB is stale

Expected behavior after `PACKMON_DB_WARN_AFTER_DAYS` days without sync.
The local dashboard must show the same stale-data condition as a visible warning
to all viewers, not only as CLI stderr output.

Actions:

```bash
packmon db info
packmon db sync --server http://packmon-server:8080 --insecure-allow-http
```

Open `packmon dashboard` after the sync. If the CLI reports stale or unknown
freshness while the dashboard and scan artifacts show healthy coverage, treat
that as a product defect rather than an operator-only warning.

Use the plain HTTP form only for local-only Docker or loopback troubleshooting.
For shared deployments, use the HTTPS server URL or a TLS-terminating reverse
proxy instead.

### Local scan still reports a package the server no longer lists

The startup package-name repair folds legacy package names into the canonical
identity for every ecosystem (GitHub Actions lowercasing and whitespace
trimming included, not only NuGet and PyPI) and moves `updated_at` of every
advisory it touches, so local clients refetch those advisories with their next
incremental sync. Manual advisory edits that move coverage to another package
are picked up the same way.

Current clients drop de-listed packages of a changed advisory only on an
incremental sync whose delta arrives in a single page (the server then sets
`vulnerability_affected_complete`). Multi-page deltas, older servers, and
older clients stay upsert-only and keep the old package until a later
single-page incremental sync drops it or a full sync, which clears and reloads
the local tables, replaces it:

```bash
packmon db sync --server https://packmon.internal:8080 --full
```

### Git hook fails with "hook scans never write inside the repository"

The packmon Git hook (`packmon scan . --hook`) never writes into the
repository. It exits with code `2` before scanning, which blocks the commit or
push, when the scan was asked to write there and cannot skip the write:

- an explicit `--output-json`, `--output-sarif`, `--output-junit`, or `--html`
  path inside the repository. The managed hook passes none of these; a
  hand-edited hook or a manual `packmon scan --hook` does. Remove the flag or
  point it outside the repository.
- the local database directory is inside the repository. The scan opens it in
  local and auto mode and to record scan history. Typical causes: a relative
  `PACKMON_DB_PATH` (it resolves against the repository for a hook run), a
  `db.path` pointing into the repository, the home directory itself being a
  Git repository (the default database lives in `~/.packmon/db`), or an
  unknown home directory, where the default falls back to `./.packmon/db`.
  Set `PACKMON_DB_PATH` or `db.path` to an absolute directory outside every
  repository, or make `HOME` / `USERPROFILE` resolvable for the hook.

A config `output.file` inside the repository does not fail the hook: it is
skipped with `warning: --hook: skipping output.file <path> (inside the
repository)` on stderr and the scan still runs. To keep that report for hook
runs, set `output.file` to an absolute path outside the repository.

If `packmon hook status` shows `packmon hook outdated`, the hook was written
by an older packmon and runs the scan without `--hook`, so none of these
protections apply. Rerun `packmon hook install` (with the same `--type`) in
the repository to rewrite it.

### Server reports degraded feed status

Symptoms:

- `feed_status=degraded` in `/api/v1/check`
- admin feed page shows warning or error
- feed-status UI or API reports rejected import records, validation reason
  classes, or an old last successful import timestamp
- scan history or package/finding totals show a sudden spike in blocking
  findings from one source

Actions:

1. Inspect `/api/v1/feeds/status` with production API headers:
   ```bash
   curl -fsS \
     -H "Authorization: Bearer $PACKMON_API_KEY" \
     -H "User-Agent: packmon-cli/runbook" \
     https://packmon.example.com/api/v1/feeds/status
   ```
2. Check `/metrics` for `packmon_feed_*`
3. Verify upstream credentials and network access
4. Inspect recent sync logs
5. For self-managed feeds that support manual sync, open `/admin/feeds`, verify
   the affected feed is enabled and in `self` mode, then use `Sync now`.
6. Re-check `/api/v1/feeds/status` and the `packmon_feed_*` metrics after the
   manual sync finishes.
7. For external imports, check the feed-status UI/API for bounded rejection
   diagnostics, rejected-record counts, reason classes, correlation ID,
   trusted client IP, API-key ID/name when available, and the last successful
   usable import timestamp.
8. Compare recent finding/blocking totals by feed source before treating a
   spike as real dependency risk. If strict validation rejected the import,
   keep the previous good data and fix the importer payload before retrying.
   The rejection reason "feed import contains values the store cannot accept"
   means the request passed validation but PostgreSQL refused a value (for
   example an EPSS score below the stored precision or a NUL character); the
   server log line `feed import rejected by store validation` with the same
   correlation ID names the record and field.

Avoid launching overlapping manual syncs for the same feed. Manual sync is not
available for disabled feeds, external feeds, or demand-driven queue sources
such as ReversingLabs.

### NVD enrichment stays in running for a long time

NVD is a phase-2 enrichment feed: it does not import advisories itself, it
raises CVSS/severity for already-imported CVEs that arrived without usable
severity data. Its `Entries` counters show CVEs updated/processed by the last
completed enrichment run, not a vulnerability inventory. NVD is excluded from
the aggregate `feed_status`, so a slow or stalled NVD sync shows up only in its
own row on `/admin/feeds` and in the per-feed `/api/v1/feeds/status` list, not
as a degraded scan result. Two symptoms look alarming but have expected causes:

- `running` with an old last-sync timestamp for hours: `last_sync_at`
  intentionally keeps the timestamp of the last usable data while a sync is
  in progress. Without `PACKMON_NVD_API_KEY` the NVD API allows 5 requests
  per 30 seconds (with a key: 50), so an enrichment pass over a few thousand
  fallback-severity CVEs takes hours, and progress logs appear only once per
  500-CVE discovery page. Request a free key at
  https://nvd.nist.gov/developers/request-an-api-key and set it as
  `PACKMON_NVD_API_KEY` (or save it from `/admin/feeds`) to cut the runtime
  roughly by a factor of ten.
- A `running` row that never finishes after an unclean server stop: the
  interrupted sync could not finalize its status row, so `running` persists
  as a stale heartbeat. The next scheduled or manual sync replaces it.
  Confirm in recent server logs (`starting NVD enrichment sync`,
  `NVD enrichment: processing CVE page`) that a new run is actually active
  before treating the feed as stuck.

A run that NVD rate-limited logs `NVD enrichment sync finished with errors`
at WARN with a separate `failed` count, and is recorded as an error without
the manager's usual immediate retries: retrying seconds after a run that
already exhausted the rate limit would hit the same wall and only add load.
The feed resumes at its next scheduled sync and picks up where it stopped,
because CVEs enriched so far drop out of the discovery query. CVEs for which
NVD returned no CVSS data are recorded in `nvd_cvss_negative_cache` and skipped
for 30 days, or until their advisory changes, so an interrupted run (server
restart, image rebuild) loses at most the CVE in flight. Repeated `failed`
counts are the signal to configure `PACKMON_NVD_API_KEY`.

### Feed scheduler controls

Global self-sync scheduling uses:

- `PACKMON_FEED_SYNC_INTERVAL=8h`
- `PACKMON_FEED_SYNC_ON_STARTUP=true` (Compose/`.env.example` value; the bare
  binary defaults to `false`)

Per-feed cadence saved from `/admin/feeds` overrides the global interval for
that feed and must be at least `15m`. Disable startup sync only during planned
maintenance or when the deployment platform starts several replacement
containers in quick succession. After changing cadence, check
`packmon_feed_last_sync_timestamp`, `packmon_feed_entries_age_seconds`, and the
admin feed page.

### Queue is not draining

Actions:

1. Check `/admin/queue` for `pending`, `processing`, `paused`, and `error` jobs.
2. Resume paused jobs or retry errored jobs from the admin queue page.
3. Check `/metrics` for `packmon_queue_size`, `packmon_queue_oldest_job_seconds`,
   `packmon_queue_error_total`, and `packmon_queue_jobs_completed_total`.
4. Verify that the relevant async feed worker is enabled and has credentials.

### Database pool saturation

Symptom: `packmon_db_pool_connections{state="acquired"}` approaches
`packmon_db_pool_connections{state="max"}` or API latency rises while
PostgreSQL is healthy.

Actions:

1. Confirm PostgreSQL can accept the larger pool and has headroom for
   maintenance connections.
2. Increase `PACKMON_DB_MAX_CONNS` deliberately and keep
   `PACKMON_DB_MIN_CONNS` below the maximum.
3. Reduce avoidable load by tuning feed cadence, retrying stuck queue jobs, or
   lowering client request bursts.
4. Restart the server only when the deployment change requires it.

### Prometheus metric families to alert on

- `packmon_http_requests_total`
- `packmon_http_request_duration_seconds_count`
- `packmon_http_request_duration_seconds_sum`
- `packmon_build_info`
- `packmon_go_goroutines`
- `packmon_go_heap_alloc_bytes`
- `packmon_go_heap_inuse_bytes`
- `packmon_go_gc_cycles_total`
- `packmon_go_gc_last_pause_seconds`
- `packmon_auth_login_failures_total`
- `packmon_degraded_responses_total`
- `packmon_metrics_store_read_failures_total`
- `packmon_db_migration_version`
- `packmon_db_pool_connections`
- `packmon_packages_total`
- `packmon_packages_scanned_total`
- `packmon_scan_findings_total`
- `packmon_findings_total`
- `packmon_findings_by_severity`
- `packmon_queue_size`
- `packmon_queue_oldest_job_seconds`
- `packmon_queue_error_total`
- `packmon_queue_jobs_completed_total`
- `packmon_queue_stuck_jobs_recovered_total`
- `packmon_feed_last_sync_timestamp`
- `packmon_feed_sync_status`
- `packmon_feed_entries_age_seconds`
- `packmon_feed_sync_timeout_total`
- `packmon_feed_sync_duration_seconds`

The versioned starter Prometheus rule file is
`docs/monitoring/packmon-alerts.yml`. Import it as a baseline and tune
thresholds, routing labels, and Alertmanager receivers for the deployment's
feed cadence, package volume, and service objectives.

Starter alert rules:

| Signal | Example expression | First response |
|---|---|---|
| Metrics scrape down | `up{job=~"packmon.*"} == 0` | Check the metrics listener, node-local scrape path, or tunnel/sidecar configuration. |
| Metrics store read failure | `increase(packmon_metrics_store_read_failures_total[10m]) > 0` | Check PostgreSQL availability and server logs for bounded metrics-store read failures. |
| Degraded scan coverage | `increase(packmon_degraded_responses_total[10m]) > 0` | Check feed status, local DB freshness, and partial parse errors. |
| Feed sync error | `packmon_feed_sync_status{status=~"error|permanent_error|rejected"} == 1` | Check provider credentials, imports, and the feed error detail in the admin feed page. |
| Feed stale | `time() - packmon_feed_last_sync_timestamp > 36000` | Run the degraded feed procedure and check provider credentials. |
| Feed entry age | `packmon_feed_entries_age_seconds > 36000` | Verify upstream sync and import freshness. |
| Feed sync duration spike | `packmon_feed_sync_duration_seconds > 1800` | Check the affected feed logs, provider latency, and database pool pressure. |
| Queue backlog | `packmon_queue_oldest_job_seconds > 7200` | Check queue page, provider credentials, and worker logs. |
| Queue errors | `increase(packmon_queue_error_total[15m]) > 0` | Retry or inspect errored jobs by source. |
| DB pool pressure | `packmon_db_pool_connections{state="acquired"} / packmon_db_pool_connections{state="max"} > 0.8` | Check PostgreSQL limits and pool sizing. |
| Runtime heap growth | `packmon_go_heap_alloc_bytes` rising continuously across several scrapes | Compare with traffic/feed activity and check for stuck sync or queue workers. |
| Runtime goroutine growth | `packmon_go_goroutines` rising continuously across several scrapes | Check recent deploys, feed syncs, queue workers, and shutdown/restart logs. |
| Login failures | `increase(packmon_auth_login_failures_total[10m]) > 5` | Review admin access, trusted proxy configuration, and audit logs. |
| Schema mismatch | `packmon_db_migration_version != 0` with an unexpected version label | Stop rollout and follow `Upgrade And Rollback`. |

Tune thresholds for the deployment's feed cadence, package volume, and service
objectives. The event-counter rules (`increase(...[R]) > 0`) fire without a
pending period (`for: 0m`): a single event keeps the expression true for at
most `R`, so a `for` of `R` or longer would never fire for an isolated event.
Lengthen the range rather than the `for` duration to smooth them.

Route firing alerts to the deployment's ticketing or incident channel and page the on-call owner for availability, security, or data-integrity impact. If you use Alertmanager, encode the Packmon service name, environment, severity, and runbook URL in alert labels or annotations before paging.

### Metrics are unreachable remotely

Expected behavior. Metrics are bound to localhost by default.

Use SSH tunneling, node-local Prometheus, or a PodMonitor/sidecar pattern instead of exposing the metrics port publicly.

### Real client IP behind a reverse proxy

By default Packmon ignores forwarded IP headers. Set `PACKMON_TRUSTED_PROXIES`
to a comma-separated list of trusted proxy IPs or CIDRs before using
`X-Forwarded-For` or `X-Real-IP` for rate limiting and audit logs. Setting this
also satisfies the fail-closed transport requirement (it tells the server a
TLS-terminating proxy is in front).

### Admin system settings do not appear to apply

`/admin/settings` can persist the API block threshold and global rate-limit
settings in PostgreSQL. Saved values are applied immediately to the live
runtime and persisted for future server starts. If a saved value does not appear
to apply, check the admin audit log, the settings save response, and the server
logs for validation or store errors before restarting the service.

Environment defaults are:

- `PACKMON_BLOCK_THRESHOLD=CRITICAL`
- `PACKMON_RATE_LIMIT_PER_MINUTE=60`
- `PACKMON_RATE_LIMIT_BURST=60`

### Managing manual advisories

Use `/admin/advisories` for operator-managed findings. Choose `vulnerability`
for non-malicious package advisories and `malicious` for malware,
typosquatting, or supply-chain package findings. Entries use source `manual`
and receive a stable `manual:<uuid>` ID when no ID is provided.
Do not use manual advisories for Docker images; Docker rows in Packmon are
inventory metadata only, not vulnerability-scan coverage.

### Admin password forgotten / reset

The admin password is stored only as a bcrypt hash; it cannot be read back
from the database. To reset it:

1. Delete the stored admin credentials:

   ```bash
   docker compose exec postgres psql -U packmon -d packmon \
     -c "DELETE FROM admin_auth WHERE id = 1;"
   ```

2. Ensure `PACKMON_ADMIN_INITIAL_PASSWORD` (at least 12 characters, at most
   72 bytes) is set in the server environment.
3. Restart the server: `docker compose restart packmon-server`. Startup
   re-creates the admin account from the bootstrap password because no admin
   hash exists anymore.
4. Log in and change the password immediately: sessions authenticated with the
   bootstrap password may only rotate that password; all other admin writes
   stay blocked until `password_is_bootstrap` is cleared by the change.

API keys, feeds, and scan data are unaffected by the reset.

### Postgres logs FATAL "terminating background worker" / "connection to client lost"

Benign when it correlates with dashboard traffic. The public dashboard runs
its aggregate statistics query on the HTTP request context; when a browser
aborts or reloads mid-load (auto-refresh, navigation), the context
cancellation kills the in-flight query and Postgres logs the terminated
parallel workers and the lost client connection. No data is lost and the
server keeps serving (the dashboard renders with a stats-load error instead).
Investigate only if the messages appear without any correlated client
activity or the dashboard aggregate becomes slow enough to hit them on every
page load.

### Container image vulnerability scans

The hosted CI gates were removed with the GitHub workflows; run the scans
locally before shipping images:

```bash
docker build --target server -t packmon-server:local .
docker build --target cli -t packmon-cli:local .
trivy image --severity HIGH,CRITICAL packmon-server:local
trivy image --severity HIGH,CRITICAL packmon-cli:local
trivy fs --severity HIGH,CRITICAL .
```

The image scans block on HIGH and CRITICAL OS package CVEs against the
repository-pinned base image digests; the filesystem scan covers repository
lockfiles for library vulnerabilities.

On Windows hosts without `make`, build the binaries and point the integration
tests at that directory directly:

```powershell
New-Item -ItemType Directory -Force .gotmp | Out-Null
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
$env:PACKMON_TEST_BIN_DIR = ".build"
go test -count=1 -tags integration .\tests\integration
go test -count=1 -tags e2e .\tests\e2e
```
