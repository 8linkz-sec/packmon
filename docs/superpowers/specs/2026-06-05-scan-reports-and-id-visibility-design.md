# Design: Nachträgliche Scan-Reports, Scan-ID-Sichtbarkeit & Suche

**Datum:** 2026-06-05
**Status:** Approved (Design), Implementierungsplan folgt

## 1. Problem & Scope

Unter `http://localhost:8080/scans` werden vergangene Scans gelistet, aber:

1. Es gibt keine Möglichkeit, den Report eines vergangenen Scans nachträglich
   anzusehen.
2. Die Scan-ID ist für den User nirgends ersichtlich (Terminal zeigt sie gar
   nicht, HTML nur klein in der Fußzeile, `/scans` schneidet sie auf 12 Zeichen
   ab) — die angezeigte ID ist damit nutzlos.
3. Es gibt keine Suche, um einen bestimmten Scan wiederzufinden.

Drei zusammenhängende Änderungen:

- **A** „Show Report"-Button unter `/scans` → rendert den gespeicherten
  HTML-Report (Äquivalent zu `--html`).
- **B** Scan-ID prominent in Terminal **und** HTML ausgeben.
- **C** Suche unter `/scans` nach (Teil-)Scan-ID **und** Repo-Name.

### Zentrale Erkenntnis (Ist-Zustand)

`scan_log` (Insert in `internal/api/v1/handler.go:635` `logScan`) speichert nur
eine **Zusammenfassung**: `scan_id`, `repo_name`, `branch`, `commit`,
`packages_count`, `findings_count`, `duration_ms`, `client_ip`, `user_agent`.
Die eigentlichen Findings/Pakete werden **nicht** persistiert. Der HTML-Renderer
(`internal/scanner/html.go`, `HTMLWriter.Write`) braucht aber das vollständige
`domain.ScanResult`. Ein Re-Scan wäre nicht originalgetreu (Lockfile
serverseitig nicht vorhanden, Vuln-DB hat sich seitdem verändert).

→ „Show Report" nachträglich erfordert, beim Scan zusätzlich etwas
Wiederherstellbares zu persistieren.

## 2. Gewählter Ansatz (Design-Entscheidungen)

- **Persistenz:** Der Server rendert beim Scan **einmal das fertige HTML** und
  legt es als Blob ab; „Show Report" liefert es 1:1 aus.
- **Aufbewahrung:** **altersbasiert**, Default 90 Tage, konfigurierbar; nur das
  HTML wird gelöscht, die `scan_log`-Summary bleibt erhalten.
- **Geltung:** Nur server-seitige Scans (rein lokale Offline-Scans erzeugen
  keinen `scan_log`). Nur neue Scans ab Einführung; Alt-Scans haben kein
  gespeichertes HTML.
- **Suche:** matcht (Teil-)Scan-ID **und** Repo-Name.

## 3. Datenmodell & Persistenz

Neue Migration `009_scan_reports.up.sql` / `.down.sql`:

```sql
CREATE TABLE scan_reports (
    scan_id     TEXT        PRIMARY KEY,
    report_html TEXT        NOT NULL,
    scanned_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_scan_reports_scanned_at ON scan_reports(scanned_at);
```

- Separate Tabelle (nicht Spalte auf `scan_log`), damit die großen Blobs die
  häufig gelesene Summary-Tabelle nicht aufblähen.
- `expected_version` der Migration → **9**.
- Store-Methoden (in `internal/db` Interface + `internal/db/postgres`,
  plus `noopStore` in `cmd/packmon-server`):
  - `InsertScanReport(ctx, scanID string, html string, scannedAt time.Time) error`
  - `GetScanReport(ctx, scanID string) (html string, ok bool, err error)`
  - `PruneScanReports(ctx, olderThan time.Time) (int64, error)`

## 4. Server: HTML beim Scan rendern & speichern

- In `Handler.logScan` (`internal/api/v1/handler.go:635`, läuft bereits **nach**
  der Response → nicht auf dem kritischen Pfad): mit dem vorhandenen
  `scanner.HTMLWriter` aus `result` rendern (Titel = Repo-Name, `failOn` aus dem
  Request) und via `InsertScanReport` ablegen.
- Kein Import-Zyklus: `scanner` hängt nur an `domain`; `internal/api/v1` darf
  `internal/scanner` importieren.
- Fehler beim Rendern/Speichern werden nur geloggt und beeinflussen die
  Scan-Response nicht (analog zum bestehenden `InsertScanLog`-Verhalten).

## 5. „Show Report"-Endpoint

- Neue Route in `internal/web/routes.go`:
  `GET /scans/{scan_id}/report`.
- Handler lädt HTML via `GetScanReport`; liefert
  `Content-Type: text/html; charset=utf-8`.
- Fehlender/geprunter Report → `404` mit freundlicher
  „kein Report verfügbar"-Seite.
- `scan_id` wird vor der Query strikt gegen das erwartete ID-Format validiert.

## 6. Scan-ID sichtbar machen

- **Terminal** (`internal/scanner/table.go`): neue Zeile in der Zusammenfassung,
  z. B. `Scan ID: <voll>`. Aktuell fehlt sie komplett.
- **HTML** (`internal/scanner/html.go`): Scan-ID aus der Fußzeile zusätzlich in
  den Kopf-/Meta-Block hochziehen, monospace + gut kopierbar. Fußzeile bleibt
  erhalten (minimale Teständerung).

## 7. `/scans`-Layout (Recent Scans)

In `internal/web/templates/scans.html` und `internal/web/scans.go`:

- **Volle, kopierbare Scan-ID** statt `truncate 12`: monospace-Zelle, volle ID
  im `title`/per Copy-Button erreichbar.
- Neue Spalte **Report** mit Button „Show Report" → `/scans/{id}/report`
  (öffnet im neuen Tab). Kein Report vorhanden (alte Scans) → ausgegrauter „—".
- **Suchfeld** oben (HTMX, wie restliche UI): server-seitiger Filter über
  `ListRecentScans` per Query-Param `q`, matcht
  `scan_id ILIKE %q%` ODER `repo_name ILIKE %q%`. Leeres `q` = Standardliste.

## 8. Retention-Job

- Konfig: `PACKMON_SCAN_REPORT_RETENTION_DAYS` (Default 90; `0` = unbegrenzt).
- Periodischer Goroutine-Ticker im Server (Muster wie die Feed-Sync-Loops),
  ruft `PruneScanReports(now - retention)`. Löscht nur `scan_reports`-Zeilen,
  `scan_log`-Summary bleibt.

## 9. Security

- Report-Endpoint folgt dem **bestehenden Dashboard-Zugriffsmodell**: `/scans`,
  `/search`, `/feeds`, `/package` sind heute schon als „Public pages" ohne
  Extra-Auth registriert (`internal/web/routes.go:14`); nur `/admin*` ist
  session-geschützt.
- Die zufällige, nicht erratbare `scan_id` (`generateID()`) wirkt als
  Capability.
- Der Report enthält die volle Paket-/Findings-Liste — etwas sensibler als die
  heutige Übersicht. Als Punkt für den Security-Review vermerkt; Scope wird
  **nicht** um eine neue Auth-Schicht erweitert (außer auf ausdrücklichen
  Wunsch).
- `scan_id`-Validierung verhindert Injection in die Lookup-Query.

## 10. Testing

- Store-Integrationstests: `InsertScanReport` / `GetScanReport` /
  `PruneScanReports`.
- Handler-Test: erfolgreicher Scan erzeugt einen `scan_reports`-Eintrag.
- Web-Test: Report-Endpoint (200 mit HTML / 404 ohne), Such-Filter,
  `scan_id`-Validierung.
- Scanner-Tests: Scan-ID erscheint in Terminal- und HTML-Ausgabe.

## 11. Non-Goals (YAGNI)

- Kein Re-Scan.
- Kein JSON-Export-Endpoint.
- Keine Reports für reine Offline-Scans.
- Kein Backfill von Reports für Alt-Scans.
- Keine neue Auth-Schicht.
