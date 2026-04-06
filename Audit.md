# Packmon Full Audit Report

**Datum:** 2026-04-05
**Scope:** Gesamte Codebasis (`cmd/`, `internal/`, `deploy/`, `.github/`, `tests/`)
**Build:** `go build ./...` erfolgreich, `go test ./... -race` alle PASS, 0 Data Races

---

## Zusammenfassung

| Severity | Anzahl | Beschreibung |
|----------|--------|--------------|
| CRITICAL | 7 | Unauthentifizierte Write-API, Plaintext-Keys in DB, Test-Coverage-Luecken |
| HIGH | 16 | IP-Spoofing, fehlende Security-Headers, N+1 Queries, fehlende ETag-Deltas |
| MEDIUM | 22 | Goroutine-Leaks, Config-Abweichungen, fehlende Features, Batch-Performance |
| LOW | 18 | Code-Duplication, minor Spec-Abweichungen, Precision-Drift |
| INFO | 8 | Positive Findings (SQL-Injection-sicher, XSS-sicher, gute Session-Entropy) |

**Gesamtbewertung:** Die Codebasis ist funktional, gut strukturiert und fuer Phase 3 solide. Kritische Sicherheitsluecken im Server (unauthentifizierte Feed-Import-API, IP-Spoofing bei Rate-Limiting) muessen vor Production-Deployment behoben werden. Die Testabdeckung liegt weit unter dem 80%-Ziel aus CLAUDE.md.

---

## Inhaltsverzeichnis

1. [Security](#1-security)
2. [Performance & Skalierung](#2-performance--skalierung)
3. [Architektur & Code-Qualitaet](#3-architektur--code-qualitaet)
4. [Data Feeds & Parser](#4-data-feeds--parser)
5. [Test-Qualitaet & QA](#5-test-qualitaet--qa)
6. [Infrastruktur & CI/CD](#6-infrastruktur--cicd)
7. [Feature-Vollstaendigkeit](#7-feature-vollstaendigkeit)
8. [Positive Findings](#8-positive-findings)
9. [Priorisierter Massnahmenplan](#9-priorisierter-massnahmenplan)

---

## 1. Security

### CRITICAL

#### SEC-C1: Feed-Import-Endpoint komplett unauthentifiziert

- **Datei:** `internal/server/routes.go:29`, `internal/api/v1/handler.go:402-483`
- **Problem:** `POST /api/v1/feeds/{feed}/import` akzeptiert bis zu 100 MB Daten und schreibt Vulnerabilities, Malicious Findings, EPSS Scores und CISA KEV Flags direkt in die Produktionsdatenbank -- ohne jegliche Authentifizierung.
- **Im devMode (`PACKMON_SERVER_MODE=development`) wird Auth komplett uebersprungen** (`middleware/auth.go:49`).
- **Impact:** Ein Angreifer mit Netzwerkzugriff kann falsche Vulnerabilities injizieren (False Positives in CI/CD), echte Vulnerabilities loeschen (False Negatives), oder EPSS/KEV-Scores manipulieren.
- **Fix:** Mandatory Admin-Auth oder dedizierter Import-API-Key, der nie uebersprungen werden kann.

#### SEC-C2: Feed-API-Keys als Plaintext in der Datenbank

- **Datei:** `internal/db/postgres/migrations/002_feed_configs.up.sql:6`, `internal/db/postgres/feed_config.go:57-84`
- **Problem:** VulnCheck- und Socket.dev-API-Keys werden als `TEXT` gespeichert. Bei DB-Kompromittierung (Backup-Leak, unauthorisierter Zugriff) sind die Keys sofort nutzbar.
- **Kontrast:** User-facing API-Keys in `api_keys` nutzen korrekt SHA-256 Hashes.
- **Fix:** Application-level Encryption (Envelope Encryption) fuer Feed-API-Keys.

#### SEC-C3: CSRF-Token-Vergleich anfaellig fuer Timing-Attack

- **Datei:** `internal/auth/csrf.go:49`
- **Problem:** `formToken == sess.csrfToken` nutzt direkten String-Vergleich statt `crypto/subtle.ConstantTimeCompare`.
- **Fix:** `subtle.ConstantTimeCompare([]byte(formToken), []byte(sess.csrfToken)) == 1`

### HIGH

#### SEC-H1: X-Forwarded-For IP-Spoofing umgeht Rate-Limiting und Login-Lockout

- **Datei:** `internal/server/middleware/ratelimit.go:116-134`, `internal/api/admin/handler.go:433-449`
- **Problem:** `clientIP()` vertraut blind dem ersten `X-Forwarded-For`-Eintrag. Angreifer koennen Rate-Limits und den 5-Versuch Login-Lockout komplett umgehen, indem sie den Header rotieren.
- **Fix:** Trusted-Proxy-Konfiguration implementieren. Ohne trusted Proxies immer `r.RemoteAddr` verwenden.

#### SEC-H2: Keine Security-Headers (HSTS, CSP, X-Frame-Options)

- **Datei:** `internal/server/server.go`
- **Problem:** Kein `Strict-Transport-Security`, kein `Content-Security-Policy`, kein `X-Content-Type-Options: nosniff`, kein `X-Frame-Options: DENY`. CLAUDE.md fordert explizit "HTTPS erzwingen (Redirect HTTP -> HTTPS)" -- nicht implementiert.
- **Fix:** Security-Headers-Middleware, HTTP->HTTPS-Redirect im Production-Mode.

#### SEC-H3: Kein HTTPS-Enforcement / HTTP-to-HTTPS-Redirect

- **Datei:** `internal/server/server.go:116-118`
- **Problem:** Server nutzt immer `ListenAndServe()` (plain HTTP), nie `ListenAndServeTLS()`. Keine TLS-Konfiguration, kein Redirect, kein HSTS.
- **Fix:** Middleware die `X-Forwarded-Proto` prueft und auf HTTPS redirected. HSTS-Header setzen.

#### SEC-H4: Bootstrap-Passwort bleibt unbegrenzt gueltig

- **Datei:** `internal/auth/auth.go:43-82`, `cmd/packmon-server/main.go:149`
- **Problem:** `PACKMON_ADMIN_INITIAL_PASSWORD` setzt das initiale Passwort. Es gibt keinen Mechanismus fuer Passwort-Aenderungszwang, Warnung, oder Erkennung ob das Bootstrap-Passwort noch aktiv ist.
- **Fix:** Flag in `admin_auth` ob Passwort via Bootstrap gesetzt. Warnung im Admin-UI.

#### SEC-H5: Neuer API-Key wird im URL-Query-Parameter exponiert

- **Datei:** `internal/api/admin/pages.go:246`
- **Problem:** `http.Redirect(w, r, "/admin/keys?newkey="+plaintext, ...)` -- der 64-Zeichen API-Key erscheint in Browser-History, Referer-Headers, Server-Logs, Proxy-Logs.
- **Fix:** Flash-Session-Value statt URL-Parameter.

#### SEC-H6: Logout-Endpoint ohne CSRF-Schutz

- **Datei:** `internal/api/admin/handler.go:219-232`
- **Problem:** `POST /admin/logout` validiert keinen CSRF-Token. Alle anderen Admin-POST-Endpoints tun dies.
- **Fix:** CSRF-Validierung wie bei allen anderen Admin-POSTs.

### MEDIUM

#### SEC-M1: Development-Mode deaktiviert Auth komplett

- **Datei:** `internal/server/middleware/auth.go:49`, `internal/server/middleware/useragent.go:32`
- **Problem:** `PACKMON_SERVER_MODE=development` ueberspringt API-Key-Auth und User-Agent-Validierung vollstaendig.
- **Fix:** WARN-Log bei Start im Dev-Mode. Auth-Bypass nie fuer Write-Endpoints.

#### SEC-M2: Fire-and-Forget Goroutine mit Request-Context

- **Datei:** `internal/server/middleware/auth.go:84-86`
- **Problem:** Goroutine nutzt `r.Context()` der nach Handler-Return cancelled wird. `TouchAPIKeyLastUsed` schlaegt dann fehl -- `last_used_at` Timestamps koennen unzuverlaessig sein.
- **Fix:** `context.WithoutCancel(r.Context())` oder `context.Background()` mit Timeout.

#### SEC-M3: Metrics-Endpoint ohne Auth exponiert Betriebsdaten

- **Datei:** `internal/telemetry/telemetry.go:128-228`
- **Problem:** Login-Failure-Counts, Feed-Sync-Timestamps, Queue-Error-Rates ohne Auth sichtbar. `PACKMON_METRICS_HOST` kann auf `0.0.0.0` gesetzt werden.
- **Fix:** Warnung wenn Metrics-Host nicht auf localhost gebunden.

#### SEC-M4: Keine Passwort-Komplexitaetsanforderungen

- **Datei:** `internal/api/admin/pages.go:590`
- **Problem:** Nur `len(newPassword) < 8`. Kein Uppercase, Lowercase, Digits, Sonderzeichen.
- **Fix:** Minimum 12 Zeichen oder zxcvbn-basierte Staerke-Pruefung.

#### SEC-M5: Unbegrenzte Memory-Allokation in collectFindings

- **Datei:** `internal/api/v1/handler.go:213-237`
- **Problem:** Bis zu 5000 Packages * viele Findings pro Package ohne Gesamtlimit.
- **Fix:** Findings-Cap (z.B. 50.000) mit Truncation-Indicator.

#### SEC-M6: Sync-Export-Endpoint ohne Pagination oder Groessenlimit

- **Datei:** `internal/api/v1/handler.go:648-718`
- **Problem:** `GET /api/v1/sync` exportiert die gesamte DB ohne Pagination, ohne Auth.
- **Fix:** Pagination (offset/limit), maximale Response-Groesse, optional API-Key.

#### SEC-M7: Default-Credentials in .env.example

- **Datei:** `.env:8,14,21`, `.env.example:8,22,30`
- **Problem:** `PACKMON_ADMIN_INITIAL_PASSWORD=admin`, `POSTGRES_PASSWORD=changeme` in `.env.example` -- wird von Nutzern kopiert.
- **Fix:** Leere Werte in `.env.example` mit Kommentar. Startup-Check der `changeme`/`admin` in Production ablehnt.

---

## 2. Performance & Skalierung

### HIGH

#### PERF-H1: N+1 Query-Pattern in /api/v1/check (Hot Path)

- **Datei:** `internal/api/v1/handler.go:213-236`
- **Problem:** Pro Package 2 separate DB-Queries (`FindVulnerabilities` + `FindMalicious`). Bei max. 5000 Packages = 10.000 Round-Trips zu PostgreSQL pro API-Call.
- **Impact:** Das ist der primaere Hot-Path -- jeder CI-Scan trifft diesen Endpoint.
- **Fix:** Batch-Query mit `WHERE (ecosystem, name) IN (VALUES ...)` -- reduziert auf 2 Queries total.

#### PERF-H2: OSV-Syncer ohne ETag-basierte Delta-Updates

- **Datei:** `internal/feed/osv/syncer.go:95-147`
- **Problem:** CLAUDE.md spezifiziert "ETag-basiertes Delta-Update von GCS Bucket". Die Implementierung laedt ALLE Ecosystem-ZIPs bei jedem Sync neu herunter (~300-500 MB), parst jedes JSON und upserted alles. Die `last_etag`-Spalte in `feed_sync_status` wird nie befuellt.
- **Fix:** ETag aus Response-Header speichern, `If-None-Match` senden, bei 304 ueberspringen.

#### PERF-H3: Keine Resource-Limits in docker-compose.yml

- **Datei:** `docker-compose.yml`
- **Problem:** Weder `postgres` noch `packmon-server` haben `deploy.resources.limits` oder `mem_limit`. Ein OSV-Sync (500 MB ZIPs in Memory) kann den Host-Speicher erschoepfen.
- **Fix:** Memory- und CPU-Limits setzen.

#### PERF-H4: Docker-Release nur Single-Arch (kein ARM64)

- **Datei:** `.github/workflows/release.yml:69`
- **Problem:** `docker/build-push-action@v7` ohne `platforms`-Parameter. ARM64-Deployments (z.B. Rancher mit ARM-Nodes) funktionieren nicht.
- **Fix:** `platforms: linux/amd64,linux/arm64` + QEMU/buildx Setup.

### MEDIUM

#### PERF-M1: OSV-Syncer laedt komplette ZIPs in Memory

- **Datei:** `internal/feed/osv/syncer.go:154-158`
- **Problem:** `io.ReadAll(io.LimitReader(resp.Body, maxZIPSize))` liest bis zu 500 MB pro Ecosystem-ZIP in Memory. 13+ ZIPs sequentiell, Peak-Memory kann 100+ MB erreichen.
- **Fix:** ZIP in Temp-File streamen, `zip.OpenReader` statt `bytes.NewReader`.

#### PERF-M2: EPSS Batch-Processing mit N+1 UPDATE-Pattern

- **Datei:** `internal/db/postgres/vulnerabilities.go:468-499`
- **Problem:** ~230.000 EPSS-Eintraege, je 5000 pro Transaktion, jedes ein einzelnes UPDATE mit CTE+UNION Subquery.
- **Fix:** `UPDATE ... FROM unnest(...)` oder Temporary Table.

#### PERF-M3: VulnCheck-Enrichment gleiches N+1-Pattern

- **Datei:** `internal/db/postgres/vulnerabilities.go:501-562`
- **Fix:** Wie PERF-M2.

#### PERF-M4: GHSA-Syncer verarbeitet alle ~65.000 Files bei jeder Aenderung

- **Datei:** `internal/feed/ghsa/syncer.go:95-128`
- **Problem:** Bei geaendertem Commit-Hash wird jede Advisory-Datei neu geparsed. Kein `git diff --name-only` fuer inkrementelle Updates.
- **Fix:** Delta via `git diff --name-only <old-hash>..<new-hash>`.

#### PERF-M5: Connection Pool nicht konfigurierbar

- **Datei:** `internal/db/postgres/store.go:25`
- **Problem:** `pgxpool.New(ctx, dsn)` mit Defaults. Waehrend Feed-Sync + API + Queue koennte Contention auftreten.
- **Fix:** Env-Vars `PACKMON_DB_MAX_CONNS`, `PACKMON_DB_MIN_CONNS`.

#### PERF-M6: Correlated Subqueries in FindVulnerabilities

- **Datei:** `internal/db/postgres/vulnerabilities.go:16-40`
- **Problem:** Zwei korrelierte Scalar-Subqueries pro Zeile (`ref_url`, `source`). Bei grossen Result-Sets ineffizient.
- **Fix:** JOIN-basierter Ansatz oder Lateral Join.

### LOW

#### PERF-L1: Keine Response-Body-Size-Limit auf CLI-Scanner

- **Datei:** `internal/scanner/scanner.go:268-269`
- **Problem:** `io.ReadAll(resp.Body)` ohne Limit. Boeswilliger Server kann beliebig grosse Response senden.
- **Fix:** `io.LimitReader` hinzufuegen.

#### PERF-L2: Insertion Sort statt stdlib

- **Datei:** `internal/db/postgres/store.go:102-112`
- **Problem:** Manueller Insertion Sort statt `slices.Sort`.
- **Fix:** `slices.Sort` oder `sort.Strings` verwenden.

#### PERF-L3: OSV per-Entry LimitReader nutzt 500 MB Limit

- **Datei:** `internal/feed/osv/syncer.go:186`
- **Problem:** `LimitReader(rc, maxZIPSize)` fuer einzelne JSON-Eintraege (typisch 1-10 KB). Limit sollte 10 MB sein.

---

## 3. Architektur & Code-Qualitaet

### HIGH

#### ARCH-H1: Version-Matching ignoriert OSV-Range `type` Feld

- **Datei:** `internal/db/postgres/versioning.go:20`
- **Problem:** OSV unterscheidet `SEMVER`, `ECOSYSTEM` und `GIT` Range-Types. Die Implementierung ignoriert das Feld komplett und nutzt immer die gleiche `compareVersions`-Logik.
  - `ECOSYSTEM`: Python PEP 440 (`1.0a1 < 1.0b1 < 1.0rc1 < 1.0`), Maven-eigene Ordnung -- generischer SemVer-Vergleich liefert falsche Ergebnisse.
  - `GIT`: Commit-Hashes koennen nicht numerisch verglichen werden.
- **Impact:** False Negatives bei Python-, Maven- und Git-basierten Vulnerabilities. Das ist der gravierendste Correctness-Bug.
- **Fix:** Range-Type auswerten, Ecosystem-spezifische Versionsvergleiche implementieren (mindestens PEP 440 fuer Python).

#### ARCH-H2: Pre-Release-Handling fehlerhaft fuer Python-Versionen

- **Datei:** `internal/db/postgres/versioning.go:175-179`
- **Problem:** `splitPrerelease` spaltet nur am Hyphen. Python nutzt `1.0a1`, `1.0b2`, `1.0rc1` (ohne Hyphen). `1.0a1` wird als `1.0a1` ohne Pre-Release behandelt. `parseVersionSegment("a1")` gibt `0` zurueck -- `1.0a1` wird als gleich zu `1.0.0` bewertet statt kleiner.
- **Fix:** Alpha/Beta/RC-Suffixe ohne Hyphen erkennen.

#### ARCH-H3: Alias-Konflikt kann Vulnerabilities von CVE-Aliases trennen

- **Datei:** `internal/db/postgres/vulnerabilities.go:224-230`
- **Problem:** `ON CONFLICT (alias_id) DO UPDATE SET vulnerability_id = EXCLUDED.vulnerability_id` verschiebt Aliases. Wenn OSV `PYSEC-2021-1234` mit Alias `CVE-2021-23337` anlegt und GHSA dann `GHSA-xxxx` mit dem gleichen Alias, verliert die PYSEC-Vulnerability ihre CVE-Verbindung.
- **Fix:** Many-to-Many Relationship oder Composite Key `(vulnerability_id, alias_id)`.

#### ARCH-H4: Duplizierte Version-Comparison zwischen PostgreSQL und SQLite

- **Datei:** `internal/db/postgres/versioning.go`, `internal/db/sqlite/store.go:250-299`
- **Problem:** Identische (aber separat gepflegte) Versionsvergleichs-Logik. Bugs muessen manuell in beiden Kopien behoben werden.
- **Fix:** Shared Package `internal/version/`.

#### ARCH-H5: Local-Sync verliert Version-Range-Fidelity

- **Datei:** `internal/db/postgres/sync.go:44`, `internal/db/sqlite/store.go:271`
- **Problem:** Server exportiert volles OSV-Range-Format (nested Events mit `last_affected`, `limit`). SQLite-Client erwartet flaches `{introduced, fixed}` Format. Lokale Offline-Scans haben inkorrektes Version-Matching.
- **Fix:** Export-Format anpassen oder SQLite-Parser fuer volles OSV-Format erweitern.

### MEDIUM

#### ARCH-M1: Goroutine-Leaks bei 3 Cleanup-Routinen

- **Dateien:**
  - `internal/api/admin/handler.go:397-410` (`cleanupAttempts`)
  - `internal/auth/session.go:155-167` (`SessionManager.cleanup`)
  - `internal/server/middleware/ratelimit.go:74-87` (`rateLimiter.cleanup`)
- **Problem:** Endlos-Ticker ohne Context-Parameter, kein Shutdown-Mechanismus.
- **Fix:** Context akzeptieren, bei Cancellation terminieren.

#### ARCH-M2: 5x dupliziertes `closeSilently`

- **Dateien:** `cmd/packmon/closers.go`, `internal/db/postgres/closers.go`, `internal/db/postgres/migrations/closers.go`, `internal/db/sqlite/closers.go`, `internal/scanner/closers.go`
- **Fix:** Shared Package `internal/ioutils/`.

#### ARCH-M3: 3x dupliziertes `clientIP` mit unterschiedlichen Implementierungen

- **Dateien:** `internal/api/v1/handler.go:1031`, `internal/api/admin/handler.go:433`, `internal/server/middleware/ratelimit.go:116`
- **Problem:** Admin-Version iteriert Bytes manuell, API-v1 nutzt `strings.IndexByte`, Middleware iteriert auch manuell. Inkonsistenz und Wartungsrisiko.
- **Fix:** Eine Funktion in `internal/server/` oder `internal/httputil/`.

#### ARCH-M4: `db.Store` ist ein God-Interface mit 36 Methoden

- **Datei:** `internal/db/db.go:17-203`
- **Problem:** Noop-Store in `cmd/packmon-server/noop.go` ist 789 Zeilen. Schwer testbar.
- **Fix:** Aufteilen in `VulnStore`, `FeedStore`, `AdminStore`, `QueueStore` -- Composition.

#### ARCH-M5: Webhook nutzt `log.Printf` statt `slog`

- **Datei:** `internal/scanner/webhook.go:60,70,93,102,104`
- **Problem:** Einzige Datei die den unstrukturierten `log` Package nutzt. Umgeht die slog-Pipeline.
- **Fix:** slog-Logger injizieren oder globalen slog-Default nutzen.

#### ARCH-M6: Fehlende Interfaces aus CLAUDE.md

- **Problem:** `Checker`, `Reporter`, `FileWalker` Interfaces aus CLAUDE.md Section 8.2 sind nicht implementiert. Scanner ruft HTTP/LocalChecker direkt auf -- nicht testbar mit Mocks.
- **Fix:** Interfaces einziehen, Dependency Injection.

### LOW -- Dead Code

| Datei | Dead Code | Grund |
|---|---|---|
| `internal/parser/parser.go:118-135` | `dedup()` | Identische Kopie in `scanner/scanner.go:367` wird genutzt |
| `internal/parser/helpers.go:7-9` | `baseFilename()` | Wraps `filepath.Base()`, kein Caller |
| `internal/parser/parser.go:139-148` | `joinErrors()` | Kein Caller |
| `internal/scanner/json.go` | `JSONWriter` Typ | `cmd/packmon/scan.go:497` nutzt `json.MarshalIndent` direkt |
| `internal/config/config.go:255-259` | `defaultMetricsHost()` | Beide Branches returnen `"127.0.0.1"` |
| `internal/api/admin/handler.go:302` | `adminFeedRow.LastSyncStatus` | Deklariert aber nie zugewiesen |

---

## 4. Data Feeds & Parser

### Parser-Abdeckung: Alle 14 Oekosysteme implementiert

19 Parser fuer 14 Ecosystems mit Fuzz-Targets -- vollstaendig.

### MEDIUM

#### FEED-M1: Composer-Parser strippt "v"-Prefix, potentielles Mismatch

- **Datei:** `internal/parser/composer.go:72-74`
- **Problem:** `strings.TrimPrefix(version, "v")`. Advisories fuer Packagist referenzieren Versionen oft MIT "v"-Prefix. Parser sendet "2.3.1", DB hat "v2.3.1" -- False Negative.

#### FEED-M2: NuGet case-sensitive Matching

- **Datei:** `internal/parser/nuget.go:75-82`
- **Problem:** Dedup nutzt `strings.ToLower(name)`, aber emittierter `Package.Name` behaelt Original-Casing. `FindVulnerabilities` nutzt `ap.name = $2` (case-sensitive). Mismatch moeglich.
- **Fix:** Case-insensitive Lookup oder Name-Normalisierung.

#### FEED-M3: Token-Bucket Refill hat Floating-Point Precision Drift

- **Datei:** `internal/feed/socket/worker.go:447-465`
- **Problem:** `int(elapsed.Seconds() * float64(w.maxTokens) / 3600.0)` -- `int()` Truncation. Bei 10s Poll-Interval werden ~360 statt 500 Tokens/Stunde refilled.
- **Fix:** Fractional Tokens tracken oder Nanosekunden-Basis.

#### FEED-M4: OpenSSF Malicious Syncer indiziert nur erstes Affected-Ecosystem

- **Datei:** `internal/feed/malicious/syncer.go:325`
- **Problem:** `aff := entry.Affected[0]` -- wenn ein boeswilliges Package in mehreren Ecosystems publiziert ist, wird nur das erste indiziert.

### LOW

#### FEED-L1: Yarn Berry (v2+) Format liefert still leere Ergebnisse

- **Datei:** `internal/parser/npm.go:121-122`
- **Problem:** `yarnHeaderRe` erkennt nur Yarn v1. Berry-Format liefert 0 Packages ohne Warnung.
- **Fix:** Mindestens Warning-Log wenn Format nicht erkannt.

#### FEED-L2: EPSS-Syncer nimmt immer gzip an

- **Datei:** `internal/feed/epss/syncer.go:149-153`
- **Problem:** `gzip.NewReader` ohne Check von `Content-Encoding`. Proxy/CDN koennte gzip strippen.

#### FEED-L3: Mehrere Parser lesen Files komplett in Memory

- **Dateien:** `internal/parser/npm.go:209` (pnpm), sowie Cargo, NuGet, Composer, Poetry, UV, CRAN, Swift PM, Pub
- **Problem:** `io.ReadAll(r)` -- bei sehr grossen Monorepo Lock-Files (100+ MB) potentielles OOM.

### CLAUDE.md Dokumentations-Abweichungen

| CLAUDE.md sagt | Realitaet |
|---|---|
| `build.gradle` als supported File | Nur `gradle.lockfile` wird geparsed |
| `*.csproj` als supported File | Nur `packages.lock.json` wird geparsed |
| Tabelle `malicious_packages` | Tatsaechlicher Name: `malicious_findings` |
| OSV mit ETag Delta-Updates | Full-Sync ohne ETag |
| DB-Schema Section 3.4 | Tatsaechliches Schema ist besser (Aliases, Multi-Source, References) |

---

## 5. Test-Qualitaet & QA

### CRITICAL

#### TEST-C1: API-Handler Coverage bei 3.8% (Ziel: 85%)

- **Datei:** `internal/api/v1/handler.go` (1044 Zeilen)
- **Problem:** Nur `overallFeedStatus()` und `feedHealthStatus()` getestet. `HandleCheck`, `HandleFeedImport`, `HandleFeedStatus`, `HandlePackageDetail`, `HandleRefresh`, `HandleSync` -- alles ungetestet.
- **Fehlend:** Request-Size-Limit, 5000-Package-Limit, `DisallowUnknownFields`, Trailing-JSON-Rejection.

#### TEST-C2: Scanner-Core bei 7.7% Coverage

- **Datei:** `internal/scanner/scanner.go` (392 Zeilen)
- **Problem:** `Scanner.Run()` (Orchestrierung: Walk, Parse, Check, Mode-Fallback, Exit-Code) ist ungetestet. `hasBlockingFindings()`, `resolveMode()`, Auto-Mode-Fallback -- alles ungetestet.

#### TEST-C3: 0% Coverage fuer 6 von 7 Feed-Syncern (2.405 LOC)

| Syncer | LOC | Coverage |
|---|---|---|
| `internal/feed/osv/syncer.go` | 458 | 0% |
| `internal/feed/ghsa/syncer.go` | 411 | 0% |
| `internal/feed/malicious/syncer.go` | 424 | 0% |
| `internal/feed/cisakev/syncer.go` | 173 | 0% |
| `internal/feed/epss/syncer.go` | 225 | 0% |
| `internal/feed/socket/worker.go` | 483 | 0% |

#### TEST-C4: Admin-Panel bei 0% (1.918 LOC)

- **Dateien:** `internal/api/admin/handler.go`, `pages.go`, `feed_forms.go`, `runtime_config.go`
- **Problem:** Login-Flow, Session-Enforcement, CSRF-Validierung, Rate-Limiting fuer Admin komplett ungetestet.

#### TEST-C5: Integration Tests laufen nicht in CI

- **Datei:** `.github/workflows/ci.yml`
- **Problem:** `go test -race ./...` ohne `-tags integration`. Die guten Integration Tests in `tests/integration/` werden nie in CI ausgefuehrt.

#### TEST-C6: E2E-Tests sind nur Placeholder

- **Datei:** `.github/workflows/nightly.yml`
- **Problem:** `echo "E2E tests placeholder -- will be implemented in Phase 5"`

### HIGH

#### TEST-H1: Keine Golden-Tests fuer Output-Formate

- **Dateien:** `internal/scanner/json.go`, `sarif.go`, `junit.go`
- **Problem:** JSON, SARIF, JUnit Writer haben 0% Coverage. Kein `testdata/`-Verzeichnis. CLAUDE.md fordert "Golden-Tests fuer Outputs und Exit-Codes".

#### TEST-H2: Webhook-Delivery ungetestet

- **Datei:** `internal/scanner/webhook.go` (115 Zeilen)
- **Problem:** HMAC-SHA256 Signatur, Envelope-Struktur, Timeout, Error-Resilience -- alles ungetestet.

#### TEST-H3: Walker (File Discovery) ungetestet

- **Datei:** `internal/scanner/walker.go` (123 Zeilen)
- **Problem:** Directory-Traversal, Depth-Limiting, Hidden-Dir-Skipping, node_modules/vendor-Exclusion, Ecosystem-Filter.

#### TEST-H4: PostgreSQL Store bei 15.3% (Ziel: 80%)

- **Datei:** `internal/db/postgres/vulnerabilities.go`, `feeds_queue.go`, etc.
- **Problem:** Nur Versionsvergleich getestet. `FindVulnerabilities`, `FindMalicious`, `UpsertVulnerability`, `EnqueueRefresh`, alle Feed-Status-Methoden ungetestet.

#### TEST-H5: Migrations nicht getestet

- **Datei:** `internal/db/postgres/migrations/migrator.go` (94 Zeilen, 0%)
- **Problem:** Kein Test ob 001/002 SQL korrekt applied und rolled back werden kann.

#### TEST-H6: Config-Priority-Chain nicht End-to-End getestet

- **Problem:** CLAUDE.md Section 2.7 definiert Flags > Env > Config > Default. Kein Test verifiziert dass ein Flag eine Env-Var ueberschreibt.

### Coverage-Uebersicht vs. Ziele

| Bereich | Ist | Soll (CLAUDE.md 8.3) | Status |
|---|---|---|---|
| Gesamt | ~35-40% | >= 80% | WEIT UNTER ZIEL |
| Parser | 90.1% | >= 90% | ERFUELLT |
| API-Handler | 3.8% | >= 85% | WEIT UNTER ZIEL |
| DB-Layer (Postgres) | 15.3% | >= 80% | WEIT UNTER ZIEL |
| DB-Layer (SQLite) | 28.6% | >= 80% | WEIT UNTER ZIEL |

---

## 6. Infrastruktur & CI/CD

### HIGH

#### INFRA-H1: Helm PostgreSQL-Passwort im Klartext

- **Dateien:** `deploy/helm/packmon/templates/postgres-statefulset.yaml:33`, `deploy/helm/packmon/templates/cronjob-backup.yaml:23`
- **Problem:** `POSTGRES_PASSWORD` als `value:` statt `secretKeyRef`. Sichtbar fuer jeden mit `kubectl get pod -o yaml`.
- **Fix:** `secretKeyRef` auf den Secret-Resourcen nutzen.

#### INFRA-H2: Default-Passwort "packmon" in Helm values.yaml

- **Datei:** `deploy/helm/packmon/values.yaml:72`
- **Problem:** PostgreSQL-Passwort defaulted auf "packmon". In Kombination mit INFRA-H1 hat jede Default-Installation ein bekanntes, lesbares DB-Passwort.

### MEDIUM

#### INFRA-M1: PostgreSQL-Port exposed to Host

- **Datei:** `docker-compose.yml:9` (`"5432:5432"`)
- **Problem:** In Production sollte der Port nicht nach aussen exponiert werden.

#### INFRA-M2: Kein Restart-Policy fuer Migrate-Service

- **Datei:** `docker-compose.yml:19-28`
- **Problem:** Bei transientem Migration-Fehler bleibt der Stack kaputt.
- **Fix:** `restart: on-failure` mit Max-Retries.

#### INFRA-M3: Readiness-Check verifiziert Feed-Status nicht

- **Datei:** `internal/health/checker.go:40-55`
- **Problem:** CLAUDE.md: "DB erreichbar + mindestens ein Feed synchronisiert?" Implementierung prueft nur DB. Kubernetes routet Traffic zu Server mit leerer DB -- Scans liefern 0 Findings (false sense of security).
- **Fix:** Feed-Sync-Status in Readiness einbeziehen.

#### INFRA-M4: Shutdown-Timeout Default 5s statt Spec 15s

- **Datei:** `internal/config/config.go:169`
- **Problem:** Code: `5*time.Second`, CLAUDE.md: `15s`. Non-Helm Deployments bekommen kuerzeren Timeout.

#### INFRA-M5: DB Close-Timeout unwirksam

- **Datei:** `cmd/packmon-server/main.go:199-201`
- **Problem:** 2s-Timeout-Context erstellt, aber `pool.Close()` akzeptiert keinen Context. Timeout wird ignoriert.

#### INFRA-M6: GHCR Login nutzt custom PAT statt GITHUB_TOKEN

- **Datei:** `.github/workflows/release.yml:68`
- **Problem:** `secrets.GHCR_TOKEN` statt `secrets.GITHUB_TOKEN`. Unnoetige Secret-Verwaltung.

#### INFRA-M7: /readyz meldet nicht 503 waehrend Shutdown

- **Problem:** CLAUDE.md Section 3.8 Step 2: "/readyz -> 503". ReadyHandler trackt nicht ob der Server shutting down ist.

### LOW

#### INFRA-L1: Kein HEALTHCHECK im Dockerfile

#### INFRA-L2: Security-Tools nicht version-pinned in CI

- **Datei:** `.github/workflows/ci.yml:71,76`
- **Problem:** `govulncheck@latest`, `gosec@latest` -- nicht reproduzierbar.

#### INFRA-L3: Helm Metrics-Host Default 127.0.0.1

- **Datei:** `deploy/helm/packmon/values.yaml:12`
- **Problem:** In Kubernetes mit Sidecar-Prometheus unreachable von aussen.

#### INFRA-L4: Kein PodDisruptionBudget in Helm

#### INFRA-L5: Kein Multi-Arch Docker Build

#### INFRA-L6: Fuzz-Failures in Nightly silently ignoriert (`|| true`)

---

## 7. Feature-Vollstaendigkeit

### Fehlend oder nur teilweise implementiert

| Feature (CLAUDE.md) | Status | Severity |
|---|---|---|
| Exit Code 3 (Warnings unter Schwellwert) | Nicht implementiert | HIGH |
| `--output FORMAT` Flag (stdout-Format wechseln) | Nicht implementiert | HIGH |
| `--ignore PACKAGE` / `--ignore-file` Flags | Config-Support existiert, aber nicht in Scan-Pipeline verdrahtet | HIGH |
| `--output-file PATH` Flag | Nicht implementiert | MEDIUM |
| `--log-format` / `--log-file` fuer CLI | Flags definiert aber nie genutzt | MEDIUM |
| `packmon db sync --source osv` | Nur `server` als Source implementiert | MEDIUM |
| OSV ETag-basierte Delta-Updates | Full-Sync statt Delta | MEDIUM |
| Prometheus-Metriken (HTTP requests, scan totals, etc.) | Stark vereinfacht vs. Spec | MEDIUM |
| `/.well-known/change-password` Redirect | Redirect existiert, zeigt auf `/admin/settings` | LOW |
| Per-Feed Interval Env-Vars | Config-Struct vorhanden, Env-Loading fehlt | LOW |
| `Checker`/`Reporter`/`FileWalker` Interfaces | Nicht als Interfaces implementiert | LOW |
| Zerolog (CLAUDE.md) vs. slog (Implementierung) | Pragmatische Abweichung, slog ist besser | INFO |

---

## 8. Positive Findings

### SQL Injection: Sicher

Alle DB-Queries nutzen parametrisierte Queries mit `$1`, `$2`, etc. via pgx. Kein String-Concatenation von User-Input in SQL. Auch dynamische Query-Konstruktion (`exportSyncVulnerabilities`) nutzt `fmt.Sprintf` nur fuer Parameter-Positionen.

### XSS: Sicher

Alle HTML-Rendering nutzt Go's `html/template` mit Auto-Escaping. Kein `template.HTML`, `template.JS` oder `template.URL` Bypass gefunden. `html.EscapeString()` fuer manuell konstruiertes HTML.

### Session-Entropy: Ausreichend

32 Bytes (256 Bit) aus `crypto/rand`, hex-encoded zu 64 Zeichen. CSRF-Tokens gleiche Entropy. Kryptographisch sicher.

### Cookie-Security: Korrekt

`HttpOnly: true`, `SameSite: http.SameSiteStrictMode`, `Secure: !devMode`. Korrekt an Production-Mode gekoppelt.

### Webhook HMAC: Korrekt implementiert

`hmac.New(sha256.New, secret)` mit `sha256=<hex>` Konvention.

### Command Injection: Kontrolliert

Git-Operationen via `exec.CommandContext` mit internen Werten, nicht User-Input.

### Fuzz Testing: Vorbildlich

20 Fuzz-Targets fuer alle 19 Parser. Nightly CI laeuft 5 Minuten pro Target.

### Race Detector: Sauber

`go test ./... -race` -- alle Tests PASS, 0 Data Races.

---

## 9. Priorisierter Massnahmenplan

### P0 -- Vor Production-Deployment (Blocker)

| # | Finding | Aufwand |
|---|---|---|
| 1 | SEC-C1: Feed-Import-Endpoint mit Auth schuetzen | Klein |
| 2 | SEC-H1: X-Forwarded-For Trust-Model fixen | Mittel |
| 3 | SEC-H2/H3: Security-Headers + HTTPS-Enforcement | Mittel |
| 4 | SEC-C2: Feed-API-Keys verschluesseln | Mittel |
| 5 | SEC-H5: API-Key aus URL entfernen (Flash-Session) | Klein |
| 6 | SEC-C3: Constant-Time CSRF-Vergleich | Klein |
| 7 | INFRA-H1/H2: Helm Passwort-Handling fixen | Klein |
| 8 | ARCH-H1: Version-Matching OSV Range Type beachten | Gross |

### P1 -- Zeitnah (naechste 2-4 Wochen)

| # | Finding | Aufwand |
|---|---|---|
| 9 | PERF-H1: N+1 Query in /api/v1/check eliminieren | Mittel |
| 10 | PERF-H2: OSV ETag-basierte Delta-Updates | Mittel |
| 11 | ARCH-H2: Pre-Release-Handling fuer Python | Mittel |
| 12 | ARCH-H3: Alias-Konflikt Many-to-Many | Mittel |
| 13 | ARCH-H4/H5: Version-Comparison deduplizieren + Sync-Format fixen | Mittel |
| 14 | TEST-C5: Integration Tests in CI aktivieren | Klein |
| 15 | SEC-H4: Bootstrap-Passwort Warnung/Ablauf | Klein |
| 16 | SEC-H6: CSRF auf Logout | Klein |
| 17 | Exit Code 3, --output FORMAT, --ignore implementieren | Mittel |
| 18 | ARCH-M1: Goroutine-Leaks fixen (Context) | Klein |

### P2 -- Mittel-/Langfristig

| # | Finding | Aufwand |
|---|---|---|
| 19 | Test-Coverage auf 80% Ziel bringen | Gross |
| 20 | Feed-Syncer Tests (httptest-basiert) | Gross |
| 21 | Admin-Panel Tests | Gross |
| 22 | Golden Tests fuer Output-Formate | Mittel |
| 23 | PERF-M1: OSV ZIP Streaming statt Memory | Mittel |
| 24 | PERF-M2/M3: EPSS/VulnCheck Batch-Optimization | Mittel |
| 25 | PERF-M4: GHSA inkrementelles Delta | Mittel |
| 26 | Code-Duplication bereinigen (closeSilently, clientIP, splitCSV) | Klein |
| 27 | Dead Code entfernen | Klein |
| 28 | God-Interface db.Store aufteilen | Mittel |
| 29 | Docker Multi-Arch Build | Klein |
| 30 | E2E Tests implementieren | Gross |
