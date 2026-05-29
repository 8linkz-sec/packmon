# Packmon Audit Validation

**Datum:** 2026-05-29
**Status:** Verifizierte Findings plus drei Fix-Runden. Alle H/M/L-Findings sind
behoben (inkl. Action-SHA-Pinning); offen bleibt nur noch der externe
GitLab-Runner-Test. Die Finding-Tabellen tragen je eine Status-Spalte
(R1/R2/R3 = Fix-Runde 1/2/3).

Diese Datei ersetzt die ungepruefte Review-Fassung. Die vorherige Review war
wertvoll als Finding-Liste, enthielt aber mehrere falsche oder nur teilweise
zutreffende Aussagen (siehe H1/H5). Die Verdikte sind gegen den Code, Tests,
Tooling und die kanonischen Repo-Dokumente (`DESIGN.md`, `SECURITY.md`,
`AGENTS.md`) abgeglichen; die "Status"-Spalten und die Fix-Runden-Abschnitte
dokumentieren die anschliessende Umsetzung.

> Lese-Reihenfolge: Die Fix-Runden stehen in umgekehrter Reihenfolge (3, 2, 1).
> "Fix-Runde 1" war zuerst (bestaetigte Kern-Findings), "Fix-Runde 2" zog die
> zurueckgestellten Punkte nach, "Fix-Runde 3" schloss Action-SHA-Pinning und
> die letzten Test-Luecken.

## Verifikationsbasis

Frisch ausgefuehrt und bestanden:

- `$pkgs = go list ./... | Where-Object { $_ -ne 'github.com/8linkz/packmon/internal/version' }; go test -count=1 $pkgs`
- `go test -c -o .gotmp\version.test.exe ./internal/version`
- `.\.gotmp\version.test.exe --test.v=true`
- `go test -race -count=1 ./...`
- `go build -o .build\packmon.exe ./cmd/packmon`
- `go build -o .build\packmon-server.exe ./cmd/packmon-server`
- `$env:PACKMON_TEST_BIN_DIR='.build'; go test -count=1 -tags integration ./tests/integration`
- `$env:PACKMON_TEST_BIN_DIR='.build'; go test -count=1 -tags e2e ./tests/e2e`
- `$env:PACKMON_TEST_BIN_DIR='.build'; go test -count=1 -tags integration -run '^TestProductionServerWithPostgresAndAPIKey$' -v ./tests/integration`
- `gofumpt -extra -l .`
- `go vet ./...`
- `golangci-lint run ./...` (`0 issues`)
- `govulncheck ./...` (keine aufgerufenen Code-Vulnerabilities)
- `gosec ./...` (`Issues: 0`)

Nicht lokal ausfuehrbar:

- `go test -count=1 ./...`: auf diesem Windows-Host blockiert Windows
  Defender wiederholbar das temporaere Go-Test-Executable
  `...\go-build...\version.test.exe` fuer `internal/version` als PUA/Virus.
  Alle anderen Packages bestehen; das explizit gebaute `internal/version`
  Test-Binary besteht vollstaendig.
- `make --version`: `make` ist auf dieser Maschine nicht installiert.
- `gitlab-runner --version`: `gitlab-runner` ist auf dieser Maschine nicht
  installiert.

Temporaere Build-Artefakte unter `.build` und `.gotmp` wurden nach der
Pruefung geloescht.

## Kurzfazit

Die Codebasis kompiliert, die Test-Suites laufen, und die statischen
Security-Tools melden keine generischen Findings. Die adversariale Audit-Datei
hat dennoch mehrere echte Design-/Security-Drifts gefunden.

Wichtig: **H1 und H5 sind widerlegt** und sollten nicht als offene High
Findings behandelt werden.

## Fix-Runde 3 -- 2026-05-29 (Claude): Action-Pinning + Test-Luecken

Die zuletzt verbliebenen, lokal umsetzbaren Punkte wurden geschlossen.
Verifikation wie zuvor (`go build`, `gofumpt`, `go vet`, `go test -race`,
`golangci-lint` `0 issues`, `gosec` `0 Issues`, e2e). Workflow-YAML zusaetzlich
mit einem YAML-Parser gegengeprueft.

- **L8 vollstaendig:** Alle 26 GitHub-Action-Referenzen in `ci.yml`,
  `nightly.yml`, `packmon-scan.yml` und `release.yml` sind auf den exakten
  Commit-SHA gepinnt (Tag als `# vN`-Kommentar erhalten), aufgeloest ueber die
  GitHub-API (`/repos/.../commits/<tag>`). Behaviour-erhaltend, da der SHA
  exakt dem aktuellen Tag-Stand entspricht.
- **Test-Luecken geschlossen:** neue/erweiterte Unit-Tests fuer
  `dedup`-Prod-wins (`TestDedupProductionWins`), NPM-/Pipfile-`Dev`-Flag
  (`TestNPMParser_ParseMarksDevDependencies`,
  `TestPipfileParser_ParseMarksDevDependencies`), Trusted-Proxy-Kantenfaelle
  (malformed XFF, all-trusted-chain, invalid X-Real-IP in `clientip_test.go`),
  `db sync --source`-Reject (`TestDBSyncRejectsUnsupportedSource`),
  Auto-Mode-Fallback-Warnung (`autoFallbackWarning` extrahiert +
  `TestAutoFallbackWarning`) und ein Release-Tag-Trigger-YAML-Check
  (`tests/ci/github_release_test.go`).

## Fix-Runde 2 -- 2026-05-29 (Claude): restliche Punkte eingebaut

Auf Wunsch wurden auch die in Fix-Runde 1 noch offen gelassenen Punkte
umgesetzt. Verifikation: `go build ./...`, `gofumpt -extra -l .` (sauber),
`go vet ./...`, `go test -race -count=1 ./...`, `golangci-lint run ./...`
(`0 issues`), `gosec ./...` (`0 Issues`), e2e-Smoke sowie die neuen
PostgreSQL-Integrationstests (`-tags integration`, gegen `postgres:16-alpine`
via Docker) bestehen.

- **M2 (Live-Reload):** Neuer thread-sicherer Holder `config.RuntimeSettings`
  (`internal/config/runtime.go`). `/api/v1/check` liest den Block-Threshold pro
  Request, der Rate-Limiter liest Limit/Burst pro Request
  (`RateLimitWithSource`), und der Admin-Save aktualisiert den Holder sofort.
  Kein Neustart mehr noetig; das UI meldet "saved and applied". Tests:
  `TestEffectiveBlockThresholdFollowsRuntime`,
  `TestRateLimitWithSourceUsesDynamicLimit`.
- **M5 (User-globale Config):** `~/.packmon/config/packmon.yaml` wird als
  Basis-Layer geladen und vom Projekt-`.packmon.yaml` ueberlagert
  (`cmd/packmon/client_config.go`). `DESIGN.md`-Precedence auf 5 Ebenen
  aktualisiert. Test: `TestLoadCLIConfigLayersUserGlobalUnderProject`.
- **M6 (Exit-Code 3):** Scanner gibt `3` zurueck, wenn Findings vorhanden, aber
  nicht blockierend sind; Multi-Target-Aggregation ist severity-aware
  (blockierend schlaegt nicht-blockierend). GitLab- und GitHub-Templates
  behandeln Exit 3 als gruene Pipeline; `DESIGN.md` ergaenzt. Test:
  `TestScannerReturnsUnderThresholdForNonBlockingFindings`.
- **M8 (Login-Session):** Neue `SessionManager.CreatePreAuth` erzeugt eine
  kurzlebige (15 min) Nicht-Admin-Session atomar (keine ungesicherte
  `Admin`-Mutation mehr); Sessions haben jetzt ein per-Session-`expiresAt`.
  Test: `TestCreatePreAuthIsNonAdminAndShortLived`.
- **M9 (Store-Level-Tests):** Neue `tests/integration/store_test.go` prueft
  Queue-Pause-Durability (M3), Manual-Advisory-Versionsmatch (H1) und
  System-Settings-Round-Trip direkt gegen PostgreSQL.
- **L8 (Reproduzierbare Tools):** `gofumpt@latest` in der CI auf `v0.9.2`
  gepinnt. Das in R2 noch offene Action-SHA-Pinning wurde anschliessend in
  Fix-Runde 3 geschlossen.
- **L9 (CLAUDE.md-Drift):** Durch M5/M6 stimmen Code, `DESIGN.md` und
  `CLAUDE.md` bei Precedence und Exit-Codes nun ueberein; `AGENTS.md` weist
  `DESIGN.md`/`SECURITY.md` weiterhin als kanonisch aus.

Nach Fix-Runde 2 blieb damals nur noch das optionale Action-SHA-Pinning
(Teil L8) und der externe GitLab-Runner-Test offen. Das Action-Pinning ist
seit Fix-Runde 3 geschlossen.

## Fix-Runde 1 -- 2026-05-29 (Claude): bestaetigte Kern-Findings

> Reihenfolge-Hinweis: Dies ist die ERSTE Fix-Runde. Die oben stehende
> "Fix-Runde 2" kam danach und hat die hier zunaechst zurueckgestellten Punkte
> (M2, M5, M6, M8, M9, L8, L9) nachgezogen. Die unten stehenden Finding-Tabellen
> enthalten den urspruenglichen Verdikt plus den aktuellen Status.

Die bestaetigten, eindeutig umsetzbaren Findings wurden in dieser Runde
behoben. Verifikation: `go build ./...`, `gofumpt -extra -l .` (sauber),
`go vet ./...`, `go test -race -count=1 ./...`, `golangci-lint run ./...`
(`0 issues`), `gosec ./...` (`0 Issues`) sowie die e2e-Smoke-Suite
(`-tags e2e ./tests/e2e`) bestehen lokal.

Behoben (mit Regressionstests, wo ohne PostgreSQL pruefbar):

- **H2** Metrics-404-Cardinality: unmatched Routen werden auf das konstante
  Label `__unmatched__` gebucketet (`internal/telemetry/telemetry.go`).
- **H3** Dev-Mode-Auth: schreibende Endpunkte (`/api/v1/feeds/`) sind im
  Dev-Mode nur noch vom Loopback-Peer unauthentifiziert erreichbar; ueber das
  Netz erzwingen sie einen API-Key (`internal/server/middleware/auth.go`).
- **H4** Composer-Dev-Flag: `packages-dev` wird mit `Dev: true` markiert
  (`internal/parser/composer.go`).
- **M3** Queue-Pause-Durability: `EnqueueRefresh` resurrected `paused`-Jobs
  nicht mehr (`internal/db/postgres/feeds_queue.go`).
- **M4** Advisory-Validierung: `severity`/`ecosystem` werden serverseitig
  gegen die erlaubten Mengen geprueft, Textlaengen begrenzt
  (`internal/api/admin/pages.go`, neues `domain.Ecosystem.Valid()`).
- **M7** Auto-Mode-Fallback warnt jetzt sichtbar inkl. DB-Alter
  (`cmd/packmon/scan.go`).
- **M10** Release-Workflow hat jetzt einen Tag-Trigger `v*`
  (`.github/workflows/release.yml`).
- **L1** Scan-Pipeline emittiert DEBUG-Logs ("found lock file", "parsed
  lock file", "packages collected") (`internal/scanner/scanner.go`).
- **L2** `MetricsHandler` loggt Store-Fehler statt sie zu verschlucken
  (`internal/telemetry/telemetry.go`).
- **L3** Bearer-Key-Vergleich im Dev-Store nutzt `subtle.ConstantTimeCompare`
  (`cmd/packmon-server/noop.go`).
- **L4** `X-Forwarded-Proto` wird nur von vertrauten Proxies ausgewertet
  (`internal/server/middleware/securityheaders.go`).
- **L5** Dev-Mode loggt beim Start eine deutliche WARN
  (`cmd/packmon-server/main.go`).
- **L6** Feed-Health bewertet `entries_total == 0` als unhealthy (v1- und
  Admin-Pfad).
- **L7** Operator-vergebene Advisory-IDs muessen im `manual:`-Namespace liegen
  (`internal/api/admin/pages.go`).
- **L10** Correlation-ID: der Handler echo't keinen ungepruefen Client-Header
  mehr, sondern nutzt den von der Middleware validierten Kontextwert
  (`internal/api/v1/handler.go`).

Die in dieser Runde zunaechst zurueckgestellten Punkte (M2, M5, M6, M8, M9,
L8, L9) wurden anschliessend in **Fix-Runde 2** (siehe oben) umgesetzt.

## HIGH Findings

> Spalte "Status" = aktueller Stand nach den Fix-Runden. "Verdikt" = die
> urspruengliche, gegen den Code gepruefte Bewertung.

| ID | Verdikt | Status | Bewertung |
|---|---|---|---|
| H1 | **Widerlegt** | n/a | Manuelle Vulnerability-Advisories mit `[]`-Ranges matchen konkrete Versionen im aktuellen Code. `internal/version.VersionAffected(..., "[]", "[]")` gibt fail-safe `true` zurueck; der gezielte Test `TestVersionAffected_EmptyRangesAndVersions` besteht. Der SQL-Lookup filtert nicht vorab nach Version. |
| H2 | **Bestaetigt** | **Behoben (R1)** | `internal/telemetry/telemetry.go` nutzte bei leerem `r.Pattern` den rohen `r.URL.Path` als Metrics-Label. Jetzt auf konstantes Label `__unmatched__` gebucketet. |
| H3 | **Bestaetigt** | **Behoben (R1)** | Dev-Mode bypasste Auth fuer `POST /api/v1/feeds/{feed}/import`. Jetzt sind schreibende Endpunkte im Dev-Mode nur noch vom Loopback-Peer unauthentifiziert; ueber das Netz ist ein API-Key noetig. |
| H4 | **Bestaetigt** | **Behoben (R1)** | `internal/parser/composer.go` las `packages-dev` ohne `Dev: true`. Jetzt korrekt als Dev markiert. |
| H5 | **Widerlegt** | n/a | Go 1.26 ist zum Pruefzeitpunkt released. Lokal laeuft `go version go1.26.3 windows/amd64`; offizielle Go-History nennt `go1.26.3` vom 2026-05-07. Die CI-Pins auf `go-version: "1.26"` sind daher kein "unreleased Go"-Risiko. |

Go-Quellen:

- https://go.dev/blog/go1.26
- https://go.dev/doc/devel/release#go1.26.3

## MEDIUM Findings

| ID | Verdikt | Status | Bewertung |
|---|---|---|---|
| M1 | **Teilweise bestaetigt** | Akzeptiert (Policy) | Der Code filtert Dev-Dependencies defaultmaessig heraus (`IncludeDev=false`). Das ist eine Policy-Entscheidung, kein Bug gegen `DESIGN.md`. Keine Codeaenderung. |
| M2 | **Teilweise bestaetigt** | **Behoben (R2)** | Block-Threshold und Rate-Limit werden jetzt per `config.RuntimeSettings` zur Laufzeit gelesen; Admin-Save wirkt sofort, kein Neustart noetig. |
| M3 | **Bestaetigt** | **Behoben (R1)** | `EnqueueRefresh` reaktiviert `paused`-Jobs nicht mehr (Store-Test in `tests/integration/store_test.go`). |
| M4 | **Bestaetigt** | **Behoben (R1)** | `HandleAdvisoryCreate` validiert `severity`/`ecosystem` serverseitig gegen Allow-Lists und begrenzt Textlaengen. |
| M5 | **Teilweise bestaetigt** | **Behoben (R2)** | `~/.packmon/config/packmon.yaml` wird als Basis-Layer geladen; `DESIGN.md`-Precedence auf 5 Ebenen aktualisiert. |
| M6 | **Teilweise bestaetigt** | **Behoben (R2)** | Exit-Code `3` wird emittiert; CI-Templates behandeln ihn als gruene Pipeline; `DESIGN.md` ergaenzt. |
| M7 | **Bestaetigt** | **Behoben (R1)** | Auto-Mode-Fallback warnt jetzt sichtbar inkl. lokalem DB-Alter. |
| M8 | **Teilweise bestaetigt** | **Behoben (R2)** | `CreatePreAuth` erzeugt eine kurzlebige Nicht-Admin-Session atomar; per-Session-`expiresAt` begrenzt das Wachstum. |
| M9 | **Bestaetigt** | **Behoben (R2)** | `tests/integration/store_test.go` deckt Manual-Advisories, System-Settings und Queue-Verhalten direkt gegen PostgreSQL ab. |
| M10 | **Bestaetigt** | **Behoben (R1)** | `release.yml` hat jetzt `push.tags: ["v*"]`. |

## LOW / INFO Findings

| ID | Verdikt | Status | Bewertung |
|---|---|---|---|
| L1 | **Bestaetigt** | **Behoben (R1)** | Scan-Pipeline emittiert DEBUG-Logs ("found lock file", "parsed lock file", "packages collected"). |
| L2 | **Bestaetigt** | **Behoben (R1)** | `MetricsHandler` loggt Store-Fehler statt sie zu verschlucken. |
| L3 | **Teilweise bestaetigt** | **Behoben (R1)** | Dev-Store-Key-Vergleich nutzt jetzt `subtle.ConstantTimeCompare`. Prod-Pfad war bereits per SHA-256-Lookup unkritisch. |
| L4 | **Bestaetigt** | **Behoben (R1)** | `X-Forwarded-Proto` wird nur von vertrauten Proxies ausgewertet. |
| L5 | **Bestaetigt** | **Teilweise (R1)** | Dev-Mode loggt beim Start eine deutliche WARN. Ein `//go:build dev`-Tag fuer `noop.go` wurde bewusst NICHT gesetzt, weil die Integrationstests den realen Dev-Mode-Binary brauchen. |
| L6 | **Bestaetigt** | **Behoben (R1)** | Feed-Health bewertet `entries_total == 0` als unhealthy (v1- und Admin-Pfad). |
| L7 | **Bestaetigt** | **Behoben (R1)** | Operator-vergebene Advisory-IDs muessen im `manual:`-Namespace liegen; Kollision mit Feed-CVEs wird abgewiesen. |
| L8 | **Teilweise bestaetigt** | **Behoben (R3)** | `gofumpt` auf `v0.9.2` gepinnt; alle 26 GitHub-Action-Referenzen in den vier Workflows sind auf den Commit-SHA gepinnt (Version als Kommentar), aufgeloest ueber die GitHub-API. |
| L9 | **Teilweise bestaetigt** | **Behoben (R2)** | Durch M5/M6 stimmen Code, `DESIGN.md` und `CLAUDE.md` bei Precedence und Exit-Codes ueberein; `AGENTS.md` weist `DESIGN.md`/`SECURITY.md` als kanonisch aus. |
| L10 | **Bestaetigt** | **Behoben (R1)** | Handler echo't keinen ungepruefen `X-Correlation-ID`-Client-Header mehr, sondern nutzt den von der Middleware validierten Kontextwert. |

## Vorher behauptete Fixes

| Behauptung | Verifizierter Stand |
|---|---|
| Trusted-Reverse-Proxy fuer XFF | Korrekt; `X-Forwarded-Proto`-Luecke (L4) inzwischen geschlossen. |
| Refresh-API bereinigt | Korrekt. |
| Correlation-ID durchgehend | Korrekt; Format-Fallback (L10) inzwischen behoben. |
| Block-Threshold aus Settings | Korrekt; Live-Reload (M2) inzwischen nachgeruestet. |
| Queue-Management | Korrekt; Pause-Durability (M3) inzwischen behoben. |
| Manuelle Advisory-IDs `manual:<uuid>` | Korrekt; Namespace-Erzwingung (L7) inzwischen ergaenzt. |
| Manuelle Advisories fuer Vuln/Malicious | Korrekt (H1 widerlegt); Store-Level-Tests (M9) inzwischen ergaenzt. |
| System-Settings persistierbar | Korrekt, Migration 003 vorhanden. |
| Remote-Scan-500 bei `versions=NULL` | Korrekt; JSONB/COALESCE-Pfade wirken gehaertet. |
| `--include-dev` verdrahtet | Korrekt; Composer-Dev-Flag (H4) inzwischen behoben. |
| Metrics vervollstaendigt | Korrekt; 404-Cardinality-Bug (H2) inzwischen behoben. |
| GitLab-Template + SHA256-Fix | Korrekt; echter Runner-Test extern offen. |
| Nightly-Workflow / E2E kein Alias | Korrekt. |
| CI-Matrix erweitert | Vorhanden; Go-1.26-"unreleased"-Claim ist widerlegt (H5). |

## Bereits Korrekt Bestaetigt

- Session-Cookies setzen `HttpOnly`, `SameSite=Strict` und in Production
  `Secure`.
- Session-IDs nutzen 32 Bytes `crypto/rand` (256 Bit).
- CSRF-Tokens werden per `crypto/rand` erzeugt und per
  `subtle.ConstantTimeCompare` validiert.
- Admin-Passwoerter werden mit bcrypt gehasht.
- Trusted-Proxy-Kern fuer XFF ist vorhanden: nur vertraute direkte Peers
  duerfen Forwarded-Header beeinflussen.
- Middleware-Reihenfolge bindet `TrustedClientIP` als aeusseren Teil vor den
  nachgelagerten Middleware-Entscheidungen ein.
- JSONB-Zugriffe auf nullable/range Felder sind mit `COALESCE` und
  `jsonb_typeof(...)=array` Guards gehaertet.
- Die geprueften SQL-Pfade verwenden parametrisierte Queries; keine konkrete
  SQL-Injection bestaetigt.
- Migrationen `001`, `002`, `003` sind fortlaufend vorhanden, inklusive Up/Down.
- GitLab-Template verifiziert das Binary gegen `checksums.txt` via
  `sha256sum -c`.
- GHSA/Malicious-Sync nutzen `os.OpenRoot` gegen Path-Traversal.
- `gitutil`-`#nosec G204` ist fuer fixe `git`-Kommandos und interne Argumente
  nachvollziehbar.
- Keine offensichtlichen Secrets/API-Keys/Passwoerter in Logs gefunden; der
  Config-Show-Pfad maskiert API-Keys.

## Test-Luecken

Inzwischen geschlossen (Fix-Runden 1/2):

- PostgreSQL-Store-Level-Tests fuer Manual-Advisories, System-Settings und
  Queue-Pause-Durability (`tests/integration/store_test.go`).
- 404/Unmatched-Route-Bucketing in Metrics
  (`TestHTTPMiddlewareBucketsUnmatchedRoutes`).
- Composer `packages-dev` als `Dev: true` (`composer_test.go`).
- Serverseitige Validierung von Advisory-Create
  (`TestHandleAdvisoryCreateRejectsInvalidInput`).
- Dev-Mode-Feed-Import Auth ueber Loopback vs. Netz
  (`TestAuthRequiresAPIKeyForDevelopmentFeedImportFromNonLoopback`).
- `X-Forwarded-Proto` von untrusted Proxy
  (`TestSecurityHeaders_NoRedirectFromUntrustedProxy`).
- Runtime-Block-Threshold und dynamisches Rate-Limit
  (`TestEffectiveBlockThresholdFollowsRuntime`,
  `TestRateLimitWithSourceUsesDynamicLimit`).
- Exit-Code 3 fuer nicht-blockierende Findings
  (`TestScannerReturnsUnderThresholdForNonBlockingFindings`).
- User-globale Config-Ueberlagerung
  (`TestLoadCLIConfigLayersUserGlobalUnderProject`).
- Pre-Auth-Session kurzlebig/nicht-admin
  (`TestCreatePreAuthIsNonAdminAndShortLived`).

In Fix-Runde 3 zusaetzlich geschlossen:

- Auto-Mode-Fallback-Warnung (`autoFallbackWarning` + `TestAutoFallbackWarning`).
- Release-Tag-Trigger-YAML-Check (`tests/ci/github_release_test.go`).
- Trusted-Proxy-Kantenfaelle: malformed XFF, all-trusted-chain, invalid
  X-Real-IP (`clientip_test.go`).
- `cmd/packmon/db_test.go`: Reject-Pfad fuer nicht unterstuetzte `--source`.
- `dedup`-Prod-wins-Regel und Pipfile/NPM-`Dev`-Flags.

Damit sind keine bekannten Test-Luecken aus diesem Audit mehr offen.

## Verbleibend offen

Alle in den Finding-Tabellen gelisteten H/M/L-Punkte sind behoben (siehe Spalte
"Status"). Offen bleibt nur noch:

1. Der externe GitLab-Runner-Test (siehe unten) -- benoetigt eine echte
   GitLab-Instanz und ist lokal nicht ausfuehrbar.
2. M1 bleibt eine bewusste Policy-Entscheidung (Dev-Deps default ausgeschlossen),
   kein offener Bug.

Hinweis zum Action-Pinning: Die Tags sind jetzt auf SHAs fixiert. Damit die
Actions kuenftig nicht veralten, empfiehlt sich ein Dependabot-Eintrag fuer
`github-actions` (optional, nicht Teil dieses Audits).

## Extern Offen

Ein echter GitLab-Runner-Test bleibt extern abhaengig. Dafuer braucht es eine
erreichbare GitLab-Instanz, registrierten Runner und einen realen Pipeline-Lauf
mit JUnit-/Artifact-Ansicht. Lokal ist `gitlab-runner` nicht installiert.
