# Scan-Reports, Scan-ID-Sichtbarkeit & Suche — Implementierungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Vergangene Scans unter `/scans` als HTML-Report nachträglich anzeigbar machen, die Scan-ID in Terminal + HTML sichtbar machen und eine Suche nach Scan-ID/Repo bereitstellen.

**Architecture:** Der Server rendert beim Scan einmalig das HTML (vorhandener `scanner.HTMLWriter`) und legt es in einer neuen Tabelle `scan_reports` ab. Ein neuer Web-Endpoint liefert es 1:1 aus. Remote-CLI-Scans übernehmen die vom Server erzeugte Scan-ID, damit Terminal-Ausgabe, `/scans`-Liste und Report-URL dieselbe ID verwenden. Ein altersbasierter Prune-Job (Default 90 Tage, konfigurierbar) begrenzt das Wachstum. Die `/scans`-Seite zeigt volle IDs, einen „Show Report"-Button und ein Suchfeld.

**Tech Stack:** Go, PostgreSQL (pgx), `net/http` ServeMux (Go 1.22 Pattern-Routing), Go `html/template`, HTMX, Tailwind.

**Referenz-Spec:** `docs/superpowers/specs/2026-06-05-scan-reports-and-id-visibility-design.md`

**Hinweis:** Die Plan-/Spec-Markdown-Dateien werden **nicht** committet (Projekt-Konvention). Die `git commit`-Schritte unten betreffen ausschließlich Code-/Test-Änderungen.

**Verifikations-Gate (am Ende jedes Tasks beachten):** Build, Tests und Lint laufen gemäß `AGENTS.md` → „Common Commands". Auf Windows ist `GOTMPDIR` gesetzt zu beachten. Die Postgres-Integrationstests (`store_docker_test.go`) brauchen einen laufenden Docker-Postgres.

---

## Dateiübersicht

**Neu:**
- `internal/db/postgres/migrations/009_scan_reports.up.sql` — Tabelle `scan_reports`
- `internal/db/postgres/migrations/009_scan_reports.down.sql` — Rollback
- `internal/db/postgres/scan_reports.go` — Postgres-Implementierung der Report-Store-Methoden
- `internal/web/scan_report.go` — Handler `GET /scans/{scan_id}/report`

**Geändert:**
- `internal/db/postgres/migrations/migrator.go` — `ExpectedVersion` 8 → 9
- `internal/db/postgres/migrations/migrator_test.go` — hartkodierte Version-Assertion anpassen
- `internal/db/db.go` — `db.Store`-Interface (`InsertScanReport`, `PruneScanReports`) + `ScanLogEntry.HasReport`
- `internal/web/store.go` — `web.Store`-Interface (`GetScanReport`, `SearchRecentScans`)
- `internal/db/sqlite/web.go` — `GetScanReport`, `SearchRecentScans` (lokale No-Report-Variante)
- `cmd/packmon-server/noop.go` — Stubs für alle neuen Methoden
- `internal/api/v1/handler.go` — `HandleCheck` startet async HTML-Report-Persistenz nach der JSON-Antwort
- `internal/config/config.go` — `PACKMON_SCAN_REPORT_RETENTION_DAYS`
- `cmd/packmon-server/background.go` — Prune-Loop
- `internal/scanner/scanner.go` — Remote-Scan-ID aus Serverantwort übernehmen
- `internal/scanner/table.go` — `Scan ID:`-Zeile
- `internal/scanner/html.go` — Scan-ID im Kopf-/Meta-Block
- `internal/web/scans.go` — Such-Param `q`, Report-Route registrieren, View-Model
- `internal/web/routes.go` — Route `GET /scans/{scan_id}/report`
- `internal/web/templates/scans.html` — volle ID, Suchfeld, „Show Report"-Spalte
- Test-Doubles: `internal/web/web_test.go`, `internal/web/render_helpers_test.go`
- Dokumentation: `DESIGN.md`, `SECURITY.md`, `README.md`, `Audit.md`

---

## Task 1: Migration `009_scan_reports`

**Files:**
- Create: `internal/db/postgres/migrations/009_scan_reports.up.sql`
- Create: `internal/db/postgres/migrations/009_scan_reports.down.sql`
- Modify: `internal/db/postgres/migrations/migrator.go:24`
- Test: `internal/db/postgres/migrations/migrator_test.go:60-77`

- [ ] **Step 1: Up-Migration schreiben**

`internal/db/postgres/migrations/009_scan_reports.up.sql`:
```sql
-- 009_scan_reports.up.sql
-- Stores the rendered HTML report per scan so it can be viewed retroactively
-- from the /scans dashboard. The scan_log summary row is the source of truth
-- for listing; this table only holds the heavy HTML blob and is pruned by age.
CREATE TABLE scan_reports (
    scan_id     TEXT        PRIMARY KEY,
    report_html TEXT        NOT NULL,
    scanned_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_reports_scanned_at ON scan_reports(scanned_at);
```

- [ ] **Step 2: Down-Migration schreiben**

`internal/db/postgres/migrations/009_scan_reports.down.sql`:
```sql
-- 009_scan_reports.down.sql
DROP TABLE IF EXISTS scan_reports;
```

- [ ] **Step 3: `ExpectedVersion` erhöhen**

In `internal/db/postgres/migrations/migrator.go:24` ändern:
```go
const ExpectedVersion = 9
```

- [ ] **Step 4: Hartkodierte Version-Tests anpassen**

In `internal/db/postgres/migrations/migrator_test.go`: Der Test `TestExpectedVersionIncludesMaliciousTombstoneMigration` (ca. Zeile 60) prüft `ExpectedVersion != 8`. Diese Assertion gehört zu Migration 8 und bleibt inhaltlich korrekt als „mindestens 8". Ändere die Gleichheits- in eine Mindest-Prüfung, damit sie bei künftigen Migrationen stabil ist:
```go
	if ExpectedVersion < 8 {
		t.Fatalf("ExpectedVersion = %d, want >= 8 for malicious tombstone schema", ExpectedVersion)
	}
```
Der separate Test `TestExpectedVersionMatchesHighestEmbeddedMigration` (ca. Zeile 12) und der Count-Check (`len(migrations) != ExpectedVersion`, ca. Zeile 75) brauchen **keine** Änderung — sie leiten den Wert dynamisch ab und gelten mit der neuen `.up.sql` automatisch für 9.

- [ ] **Step 5: Migrations-Tests ausführen**

Run: `go test ./internal/db/postgres/migrations/...`
Expected: PASS (höchste Migration = 9 = ExpectedVersion, Count = 9).

- [ ] **Step 6: Commit**

```bash
git add internal/db/postgres/migrations/
git commit -m "feat(db): add scan_reports migration (009)"
```

---

## Task 2: Store-Interfaces & Typen erweitern

**Files:**
- Modify: `internal/db/db.go` (Store-Interface + `ScanLogEntry`)
- Modify: `internal/web/store.go` (web.Store-Interface)

- [ ] **Step 1: `ScanLogEntry` um `HasReport` ergänzen**

In `internal/db/db.go` im `ScanLogEntry`-Struct (ca. Zeile 518) nach `UserAgent` ergänzen:
```go
	UserAgent     string
	// HasReport is true when a rendered HTML report exists for this scan.
	// Populated by SearchRecentScans; zero (false) elsewhere.
	HasReport     bool
```

- [ ] **Step 2: `db.Store` um server-seitige Report-Methoden ergänzen**

In `internal/db/db.go` im `Store`-Interface, im Abschnitt `-- Scan log` (nach `CountScansByDay`, ca. Zeile 206), ergänzen:
```go
	// -- Scan reports -----------------------------------------------------------

	// InsertScanReport stores the rendered HTML report for a scan. Overwrites
	// any existing report for the same scan_id.
	InsertScanReport(ctx context.Context, scanID, html string, scannedAt time.Time) error

	// PruneScanReports deletes stored reports older than the given cutoff and
	// returns the number of rows removed. The scan_log summary is untouched.
	PruneScanReports(ctx context.Context, olderThan time.Time) (int64, error)
```

- [ ] **Step 3: `web.Store` um Lese-/Such-Methoden ergänzen**

In `internal/web/store.go` im `Store`-Interface ergänzen:
```go
	// GetScanReport returns the stored HTML report for a scan, or ok=false
	// when no report exists (old scan, pruned, or local-only store).
	GetScanReport(ctx context.Context, scanID string) (html string, ok bool, err error)

	// SearchRecentScans returns recent scans filtered by a query that matches
	// the scan_id or repo_name (case-insensitive substring). An empty query
	// returns the most recent scans unfiltered. Each entry's HasReport flag
	// indicates whether a stored HTML report is available.
	SearchRecentScans(ctx context.Context, query string, limit int) ([]db.ScanLogEntry, error)
```

- [ ] **Step 4: Build prüfen (erwartet: Compile-Fehler in Implementierern)**

Run: `go build ./...`
Expected: FAIL — `*postgres.Store`, `*noopStore`, `*sqlite.Store` erfüllen die Interfaces noch nicht. Das ist erwartet und wird in Task 3–4 behoben.

- [ ] **Step 5: Commit**

```bash
git add internal/db/db.go internal/web/store.go
git commit -m "feat(db): declare scan report store methods and HasReport flag"
```

---

## Task 3: Postgres-Implementierung

**Files:**
- Create: `internal/db/postgres/scan_reports.go`
- Modify: `internal/db/postgres/admin_stats.go` (neue `SearchRecentScans`-Methode anhängen — gleiche Datei wie `ListRecentScans`)
- Test: `internal/db/postgres/store_docker_test.go`

- [ ] **Step 1: Report-Store-Methoden implementieren**

`internal/db/postgres/scan_reports.go`:
```go
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// InsertScanReport stores (or replaces) the rendered HTML report for a scan.
func (s *Store) InsertScanReport(ctx context.Context, scanID, html string, scannedAt time.Time) error {
	const query = `
		INSERT INTO scan_reports (scan_id, report_html, scanned_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (scan_id) DO UPDATE
		SET report_html = EXCLUDED.report_html, scanned_at = EXCLUDED.scanned_at`

	if _, err := s.pool.Exec(ctx, query, scanID, html, scannedAt); err != nil {
		return fmt.Errorf("postgres: insert scan report: %w", err)
	}
	return nil
}

// GetScanReport returns the stored HTML report for a scan.
func (s *Store) GetScanReport(ctx context.Context, scanID string) (string, bool, error) {
	const query = `SELECT report_html FROM scan_reports WHERE scan_id = $1`

	var html string
	err := s.pool.QueryRow(ctx, query, scanID).Scan(&html)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("postgres: get scan report: %w", err)
	}
	return html, true, nil
}

// PruneScanReports deletes reports older than the cutoff.
func (s *Store) PruneScanReports(ctx context.Context, olderThan time.Time) (int64, error) {
	const query = `DELETE FROM scan_reports WHERE scanned_at < $1`

	tag, err := s.pool.Exec(ctx, query, olderThan)
	if err != nil {
		return 0, fmt.Errorf("postgres: prune scan reports: %w", err)
	}
	return tag.RowsAffected(), nil
}
```

- [ ] **Step 2: `SearchRecentScans` implementieren**

Ans Ende von `internal/db/postgres/admin_stats.go` anhängen (nutzt vorhandene Helfer `clampLimit`, `closeSilently`):
```go
// SearchRecentScans returns recent scans filtered by scan_id or repo_name.
// An empty query returns the most recent scans. HasReport reflects whether a
// stored HTML report exists for each scan.
func (s *Store) SearchRecentScans(ctx context.Context, query string, limit int) ([]db.ScanLogEntry, error) {
	limit = clampLimit(limit, 15, 100)
	like := scanSearchLike(query)

	rows, err := s.pool.Query(ctx, `
		SELECT sl.scan_id, COALESCE(sl.repo_name, ''), COALESCE(sl.branch, ''),
		       COALESCE(sl.commit, ''), sl.scanned_at, sl.packages_count,
		       sl.findings_count, sl.duration_ms,
		       COALESCE(sl.client_ip::text, ''), COALESCE(sl.user_agent, ''),
		       EXISTS (SELECT 1 FROM scan_reports sr WHERE sr.scan_id = sl.scan_id) AS has_report
		FROM scan_log sl
		WHERE $1 = '' OR sl.scan_id ILIKE $1 ESCAPE '\' OR sl.repo_name ILIKE $1 ESCAPE '\'
		ORDER BY sl.scanned_at DESC, sl.id DESC
		LIMIT $2`, like, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: search recent scans: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.ScanLogEntry, 0)
	for rows.Next() {
		var entry db.ScanLogEntry
		if err := rows.Scan(
			&entry.ScanID, &entry.RepoName, &entry.Branch, &entry.Commit,
			&entry.ScannedAt, &entry.PackagesCount, &entry.FindingsCount,
			&entry.DurationMs, &entry.ClientIP, &entry.UserAgent, &entry.HasReport,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan search row: %w", err)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate search rows: %w", err)
	}
	return out, nil
}

func scanSearchLike(query string) string {
	q := strings.TrimSpace(query)
	if q == "" {
		return ""
	}
	q = strings.ReplaceAll(q, `\`, `\\`)
	q = strings.ReplaceAll(q, `%`, `\%`)
	q = strings.ReplaceAll(q, `_`, `\_`)
	return "%" + q + "%"
}
```

- [ ] **Step 3: Integrationstest schreiben (Docker-Postgres)**

In `internal/db/postgres/store_docker_test.go` eine neue Testfunktion ergänzen (Muster wie die bestehende `InsertScanLog`/`ListRecentScans`-Sektion bei Zeile 651). Verwende den vorhandenen Test-Store-Setup-Helper dieser Datei (siehe Dateianfang, gleiche Konstruktion wie andere `Test...` Funktionen):
```go
func TestScanReportsStore(t *testing.T) {
	store, cleanup := newDockerStore(t) // vorhandenen Setup-Helper dieser Datei verwenden
	defer cleanup()
	ctx := context.Background()

	now := time.Now().UTC()
	// scan_log-Eintrag, auf den der Report sich bezieht.
	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{ScanID: "rep-1", RepoName: "acme/api", ScannedAt: now, PackagesCount: 3, FindingsCount: 1}); err != nil {
		t.Fatalf("InsertScanLog: %v", err)
	}

	// Kein Report -> ok=false.
	if _, ok, err := store.GetScanReport(ctx, "rep-1"); err != nil || ok {
		t.Fatalf("GetScanReport(empty) = ok %v err %v, want ok=false", ok, err)
	}

	if err := store.InsertScanReport(ctx, "rep-1", "<html>report</html>", now); err != nil {
		t.Fatalf("InsertScanReport: %v", err)
	}
	html, ok, err := store.GetScanReport(ctx, "rep-1")
	if err != nil || !ok || html != "<html>report</html>" {
		t.Fatalf("GetScanReport = (%q,%v,%v)", html, ok, err)
	}

	// SearchRecentScans matcht Repo-Name und setzt HasReport.
	res, err := store.SearchRecentScans(ctx, "acme", 10)
	if err != nil || len(res) != 1 || res[0].ScanID != "rep-1" || !res[0].HasReport {
		t.Fatalf("SearchRecentScans(repo) = %+v err %v", res, err)
	}
	// Suche per ID-Fragment.
	if res, _ := store.SearchRecentScans(ctx, "rep-", 10); len(res) != 1 {
		t.Fatalf("SearchRecentScans(id) len = %d, want 1", len(res))
	}
	// Nicht-Treffer.
	if res, _ := store.SearchRecentScans(ctx, "zzz", 10); len(res) != 0 {
		t.Fatalf("SearchRecentScans(miss) len = %d, want 0", len(res))
	}
	// LIKE-Wildcards werden literal behandelt, nicht als "match all".
	if res, _ := store.SearchRecentScans(ctx, "%", 10); len(res) != 0 {
		t.Fatalf("SearchRecentScans(wildcard literal) len = %d, want 0", len(res))
	}

	// Prune mit Zukunfts-Cutoff entfernt den Report, lässt scan_log stehen.
	n, err := store.PruneScanReports(ctx, now.Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("PruneScanReports = (%d,%v), want (1,nil)", n, err)
	}
	if _, ok, _ := store.GetScanReport(ctx, "rep-1"); ok {
		t.Fatalf("report should be pruned")
	}
	if res, _ := store.SearchRecentScans(ctx, "acme", 10); len(res) != 1 || res[0].HasReport {
		t.Fatalf("scan_log row must survive prune with HasReport=false, got %+v", res)
	}
}
```
> Hinweis: Falls der Setup-Helper in dieser Datei anders heißt als `newDockerStore`, den tatsächlichen Namen aus den umliegenden `Test...`-Funktionen übernehmen.

- [ ] **Step 4: Tests ausführen**

Run: `go test ./internal/db/postgres/... -run TestScanReportsStore -v`
Expected: PASS (bei laufendem Docker-Postgres). Ohne Docker wird der Test übersprungen — dann mindestens `go build ./internal/db/postgres/...` grün.

- [ ] **Step 5: Commit**

```bash
git add internal/db/postgres/
git commit -m "feat(db): implement scan report storage and search in postgres"
```

---

## Task 4: Übrige Store-Implementierer (noop, sqlite, Test-Doubles)

**Files:**
- Modify: `cmd/packmon-server/noop.go`
- Modify: `internal/db/sqlite/web.go`
- Modify: `internal/web/web_test.go` (`mockStore`)
- Modify: `internal/web/render_helpers_test.go` (`scansStore`)

- [ ] **Step 1: `noopStore`-Stubs ergänzen**

In `cmd/packmon-server/noop.go` nach `InsertScanLog`/`ListRecentScans` (ca. Zeile 811) ergänzen:
```go
func (s *noopStore) InsertScanReport(_ context.Context, _ string, _ string, _ time.Time) error {
	return nil
}

func (s *noopStore) GetScanReport(_ context.Context, _ string) (string, bool, error) {
	return "", false, nil
}

func (s *noopStore) PruneScanReports(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (s *noopStore) SearchRecentScans(ctx context.Context, _ string, limit int) ([]db.ScanLogEntry, error) {
	return s.ListRecentScans(ctx, limit)
}
```

- [ ] **Step 2: SQLite-Implementierung (lokaler Cache speichert keine Reports)**

In `internal/db/sqlite/web.go` ergänzen. SQLite hat keine `scan_reports`-Tabelle; `GetScanReport` liefert „nicht vorhanden", `SearchRecentScans` filtert die vorhandenen lokalen Scans in-memory und lässt `HasReport=false`:
```go
// GetScanReport always reports no stored report: the local SQLite cache never
// persists rendered HTML (reports live only on the server).
func (s *Store) GetScanReport(_ context.Context, _ string) (string, bool, error) {
	return "", false, nil
}

// SearchRecentScans filters the most recent local scans by scan_id or repo_name.
func (s *Store) SearchRecentScans(ctx context.Context, query string, limit int) ([]db.ScanLogEntry, error) {
	entries, err := s.ListRecentScans(ctx, limit)
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return entries, nil
	}
	out := make([]db.ScanLogEntry, 0, len(entries))
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.ScanID), q) ||
			strings.Contains(strings.ToLower(e.RepoName), q) {
			out = append(out, e)
		}
	}
	return out, nil
}
```
> Falls `strings` in `internal/db/sqlite/web.go` noch nicht importiert ist, den Import ergänzen.

- [ ] **Step 3: Web-Test-Doubles ergänzen**

In `internal/web/web_test.go` zum `mockStore` ergänzen:
```go
func (m *mockStore) GetScanReport(_ context.Context, _ string) (string, bool, error) {
	return "", false, nil
}

func (m *mockStore) SearchRecentScans(_ context.Context, _ string, _ int) ([]db.ScanLogEntry, error) {
	return []db.ScanLogEntry{}, nil
}
```

In `internal/web/render_helpers_test.go` zum `scansStore` (ca. Zeile 145, neben dessen `ListRecentScans`) ergänzen:
```go
func (s scansStore) GetScanReport(_ context.Context, scanID string) (string, bool, error) {
	if html, ok := s.reports[scanID]; ok {
		return html, true, nil
	}
	return "", false, nil
}

func (s scansStore) SearchRecentScans(_ context.Context, query string, limit int) ([]db.ScanLogEntry, error) {
	return s.ListRecentScans(context.Background(), limit)
}
```
Dazu im `scansStore`-Struct (ca. Zeile 135) ein optionales Feld ergänzen, damit Report-Tests Daten einspeisen können:
```go
	reports map[string]string
```
> `context` ist in dieser Testdatei vermutlich bereits importiert; sonst ergänzen.

- [ ] **Step 4: Build + Vollbuild prüfen**

Run: `go build ./...`
Expected: PASS — alle Interfaces erfüllt.

Run: `go vet ./cmd/packmon-server/... ./internal/db/... ./internal/web/...`
Expected: keine Fehler.

- [ ] **Step 5: Commit**

```bash
git add cmd/packmon-server/noop.go internal/db/sqlite/web.go internal/web/web_test.go internal/web/render_helpers_test.go
git commit -m "feat(db): satisfy scan report store methods across noop, sqlite, mocks"
```

---

## Task 5: Server rendert & speichert HTML beim Scan

**Files:**
- Modify: `internal/api/v1/handler.go` (`HandleCheck`, neue Helper-Methode, Imports)
- Test: `internal/api/v1/handler_test.go`

- [ ] **Step 1: Failing-Test — Scan erzeugt Report**

Der vorhandene `stubStore` (handler_test.go:51) sammelt `InsertScanLog`-Aufrufe. Ergänze analoge, threadsichere Erfassung für Reports. Im `stubStore`-Struct Felder hinzufügen:
```go
	scanReports       map[string]string
	scanReportStarted chan struct{}
	scanReportBlock   <-chan struct{}
```
Und die Stub-Methoden ergänzen:
```go
func (s *stubStore) InsertScanReport(_ context.Context, scanID, html string, _ time.Time) error {
	if s.scanReportStarted != nil {
		select {
		case s.scanReportStarted <- struct{}{}:
		default:
		}
	}
	if s.scanReportBlock != nil {
		<-s.scanReportBlock
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scanReports == nil {
		s.scanReports = map[string]string{}
	}
	s.scanReports[scanID] = html
	return nil
}

func (s *stubStore) PruneScanReports(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (s *stubStore) scanReportSnapshot() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.scanReports))
	for k, v := range s.scanReports {
		out[k] = v
	}
	return out
}

func waitForScanReports(t *testing.T, store *stubStore, want int) map[string]string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		reports := store.scanReportSnapshot()
		if len(reports) == want {
			return reports
		}
		time.Sleep(10 * time.Millisecond)
	}
	return store.scanReportSnapshot()
}
```
> `GetScanReport`/`SearchRecentScans` muss der `stubStore` nur implementieren, falls er `db.Store` erfüllen muss. `InsertScanReport`/`PruneScanReports` gehören zu `db.Store` und sind daher Pflicht. Falls der Compiler weitere fordert, die No-op-Varianten aus Task 4 übernehmen.

Neuer Test mit direktem `httptest`-Request (zu handler_test.go hinzufügen):
```go
func TestCheckPersistsHTMLReport(t *testing.T) {
	store := &stubStore{
		feedStatuses: []db.FeedSyncStatus{{
			FeedName:       "osv",
			LastSyncStatus: "success",
			LastSyncAt:     ptrFeedTime(time.Now().UTC()),
		}},
	}
	h := newTestHandler(store)
	body := `{"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}],"repo":{"name":"acme/api"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleCheck(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}

	reports := waitForScanReports(t, store, 1)
	if len(reports) != 1 {
		t.Fatalf("expected exactly one stored report, got %d", len(reports))
	}
	for scanID, html := range reports {
		if scanID == "" {
			t.Fatalf("stored report has empty scan id")
		}
		if !strings.Contains(html, "<html") || !strings.Contains(html, "acme/api") {
			t.Fatalf("stored report html missing expected content: %q", html)
		}
	}
}
```
> `ptrFeedTime` verwenden, falls er in dieser Testdatei existiert; sonst lokal `func ptrFeedTime(t time.Time) *time.Time { return &t }` ergänzen.

- [ ] **Step 2: Failing-Test — Report-Persistenz blockiert API-Antwort nicht**

Zusätzlicher Test, der den `InsertScanReport`-Stub absichtlich blockieren lässt. Der API-Handler muss trotzdem mit `200` zurückkehren:
```go
func TestCheckReportPersistenceDoesNotBlockResponse(t *testing.T) {
	block := make(chan struct{})
	started := make(chan struct{}, 1)
	defer close(block)

	store := &stubStore{
		scanReportStarted: started,
		scanReportBlock:   block,
		feedStatuses: []db.FeedSyncStatus{{
			FeedName:       "osv",
			LastSyncStatus: "success",
			LastSyncAt:     ptrFeedTime(time.Now().UTC()),
		}},
	}
	h := newTestHandler(store)
	body := `{"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		h.HandleCheck(rec, req)
		close(done)
	}()

	select {
	case <-done:
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("HandleCheck blocked on report persistence")
	}
}
```
Expected before implementation: FAIL — if the report insert runs synchronously, the handler blocks.

- [ ] **Step 3: Tests ausführen — fehlschlagen sehen**

Run: `go test ./internal/api/v1/ -run 'TestCheckPersistsHTMLReport|TestCheckReportPersistenceDoesNotBlockResponse' -v`
Expected: FAIL — entweder kein Report-Insert oder blockierende Persistenz.

- [ ] **Step 4: `HandleCheck` mit Threshold-Snapshot und Async-Report-Persistenz erweitern**

In `internal/api/v1/handler.go` den Import-Block um `bytes` (falls noch nicht vorhanden) und das scanner-Paket ergänzen:
```go
	"bytes"

	"github.com/8linkz/packmon/internal/scanner"
```
In `HandleCheck` den Blocker-Threshold einmalig vor der Blocking-Berechnung erfassen:
```go
	threshold := h.effectiveBlockThreshold()
	blocking := isBlocking(findings, threshold)
```
Die `logScan`-Persistenz für `scan_log` bleibt best-effort vor der Antwort. Die HTML-Report-Persistenz kommt nach `writeJSON`, startet aber nur eine Goroutine:
```go
	h.logScan(ctx, &result, r, &req, correlationID)

	w.Header().Set("X-Correlation-ID", correlationID)
	w.Header().Set("X-Scan-Duration-Ms", fmt.Sprintf("%d", durationMs))
	writeJSON(w, http.StatusOK, result)

	h.persistScanReportAsync(context.WithoutCancel(ctx), &result, &req, threshold, correlationID)
```
Neue Helper-Methode neben `logScan` ergänzen:
```go
func (h *Handler) persistScanReportAsync(ctx context.Context, result *domain.ScanResult, req *domain.ScanRequest, threshold domain.Severity, correlationID string) {
	if h == nil || h.store == nil || result == nil || result.ScanID == "" {
		return
	}
	report := *result
	title := "Scan " + report.ScanID
	if req != nil && req.Repo != nil {
		if repoName := strings.TrimSpace(req.Repo.Name); repoName != "" {
			title = repoName
		}
	}

	go func() {
		reportCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		var buf bytes.Buffer
		writer := scanner.NewHTMLWriter("")
		if err := writer.Write(&buf, title, threshold, &report); err != nil {
			h.logger.Warn("failed to render scan report", "error", err, "correlation_id", correlationID)
			return
		}
		if err := h.store.InsertScanReport(reportCtx, report.ScanID, buf.String(), report.ScannedAt); err != nil {
			h.logger.Warn("failed to store scan report", "error", err, "correlation_id", correlationID)
		}
	}()
}
```
> Wichtig: Nicht in `logScan` rendern. `HandleCheck` ruft `h.logScan` heute vor `writeJSON`; HTML-Rendern/DB-Blob-Insert an dieser Stelle würde die API-Antwort verzögern. Der `threshold`-Snapshot verhindert außerdem, dass eine spätere Konfigurationsänderung den gespeicherten Report anders klassifiziert als die JSON-Antwort.

- [ ] **Step 5: Tests ausführen — bestehen sehen**

Run: `go test ./internal/api/v1/ -run 'TestCheckPersistsHTMLReport|TestCheckReportPersistenceDoesNotBlockResponse' -v`
Expected: PASS.

- [ ] **Step 6: Gesamte api/v1-Tests**

Run: `go test ./internal/api/v1/...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/api/v1/
git commit -m "feat(server): render and persist HTML report on each scan"
```

---

## Task 6: Konfiguration `PACKMON_SCAN_REPORT_RETENTION_DAYS`

**Files:**
- Modify: `internal/config/config.go` (`Load`, Config-Struct)
- Test: `internal/config/config_test.go`
- Modify: `DESIGN.md` (Konfiguration)
- Modify: `README.md` (Server-Konfiguration)

- [ ] **Step 1: Failing-Test**

In `internal/config/config_test.go` ergänzen:
```go
func TestScanReportRetentionDays(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ScanReportRetentionDays != 90 {
			t.Fatalf("default = %d, want 90", cfg.ScanReportRetentionDays)
		}
	})
	t.Run("override", func(t *testing.T) {
		t.Setenv("PACKMON_SCAN_REPORT_RETENTION_DAYS", "30")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ScanReportRetentionDays != 30 {
			t.Fatalf("override = %d, want 30", cfg.ScanReportRetentionDays)
		}
	})
}
```
> Falls `Load()` zwingend weitere Env-Variablen (z. B. Transport-Security) braucht, dieselbe Test-Vorbereitung wie bestehende `config_test.go`-Tests übernehmen.

- [ ] **Step 2: Test ausführen — fehlschlagen sehen**

Run: `go test ./internal/config/ -run TestScanReportRetentionDays -v`
Expected: FAIL — Feld `ScanReportRetentionDays` existiert nicht.

- [ ] **Step 3: Config-Feld + Parsing ergänzen**

Im Config-Struct (passender Abschnitt, z. B. neben anderen Server-/Feed-Settings) ergänzen:
```go
	// ScanReportRetentionDays controls how long rendered HTML scan reports are
	// kept before pruning. 0 disables pruning (keep forever).
	ScanReportRetentionDays int
```
In `Load()` (Muster wie `envIntOrDefault` bei Zeile 204) ergänzen:
```go
	scanReportRetentionDays, err := envIntOrDefault("PACKMON_SCAN_REPORT_RETENTION_DAYS", 90)
	if err != nil {
		return nil, err
	}
	if scanReportRetentionDays < 0 {
		return nil, fmt.Errorf("PACKMON_SCAN_REPORT_RETENTION_DAYS must be >= 0, got %d", scanReportRetentionDays)
	}
```
Und beim Zusammenbauen des `Config`-Werts das Feld setzen:
```go
		ScanReportRetentionDays: scanReportRetentionDays,
```

- [ ] **Step 4: Test ausführen — bestehen sehen**

Run: `go test ./internal/config/ -run TestScanReportRetentionDays -v`
Expected: PASS.

- [ ] **Step 5: Doku-Hinweis**

In `DESIGN.md` im Abschnitt der Umgebungsvariablen (Konfiguration) eine Zeile für `PACKMON_SCAN_REPORT_RETENTION_DAYS` (Default `90`, `0` = unbegrenzt) ergänzen, damit die Env-Var dokumentiert ist.
In `README.md` im Server-/Docker-Konfigurationsabschnitt dieselbe Env-Var knapp ergänzen:
```text
PACKMON_SCAN_REPORT_RETENTION_DAYS=90  # 0 disables pruning of stored HTML reports
```

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go DESIGN.md README.md
git commit -m "feat(config): add PACKMON_SCAN_REPORT_RETENTION_DAYS"
```

---

## Task 7: Prune-Loop im Server

**Files:**
- Modify: `cmd/packmon-server/background.go` (neue Methode + Start-Aufruf)
- Test: `cmd/packmon-server/` (vorhandene Hintergrund-Test-Muster)

- [ ] **Step 1: Prune-Loop-Methode ergänzen**

In `cmd/packmon-server/background.go` ergänzen (nutzt vorhandene Felder `rootCtx`, `cfg`, `store`, `logger`):
```go
// startScanReportPruneLoop periodically deletes scan reports older than the
// configured retention. A retention of 0 disables pruning entirely.
func (b *backgroundServices) startScanReportPruneLoop() {
	if b == nil || b.cfg == nil || b.rootCtx == nil {
		return
	}
	days := b.cfg.ScanReportRetentionDays
	if days <= 0 {
		if b.logger != nil {
			b.logger.Info("scan report pruning disabled", "component", "scan_report_pruner")
		}
		return
	}
	retention := time.Duration(days) * 24 * time.Hour
	const interval = 6 * time.Hour

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// Run once shortly after start, then on each tick.
		b.pruneScanReportsOnce(retention)
		for {
			select {
			case <-b.rootCtx.Done():
				return
			case <-ticker.C:
				b.pruneScanReportsOnce(retention)
			}
		}
	}()
}

func (b *backgroundServices) pruneScanReportsOnce(retention time.Duration) {
	cutoff := time.Now().Add(-retention).UTC()
	n, err := b.store.PruneScanReports(b.rootCtx, cutoff)
	if err != nil {
		if b.logger != nil {
			b.logger.Warn("scan report prune failed", "component", "scan_report_pruner", "error", err)
		}
		return
	}
	if n > 0 && b.logger != nil {
		b.logger.Info("pruned scan reports", "component", "scan_report_pruner", "removed", n, "cutoff", cutoff)
	}
}
```
> `time` ist in `background.go` bereits importiert.

- [ ] **Step 2: Loop beim Start aufrufen**

In der Funktion, die die Hintergrunddienste startet (dort wo `startQueueProcessorLocked` bzw. der Feed-Manager gestartet werden — gleicher Lebenszyklus wie `rootCtx`), ergänzen:
```go
	b.startScanReportPruneLoop()
```
> Den exakten Start-Punkt anhand der vorhandenen Start-/`Run`-Methode in `background.go` wählen (analog zur Queue-/Feed-Initialisierung), damit `rootCtx` gesetzt ist.

- [ ] **Step 3: Verhaltenstest (Retention deaktiviert)**

Test ergänzen (Muster der vorhandenen `noop_*_test.go`/Hintergrund-Tests), der prüft, dass bei `ScanReportRetentionDays = 0` kein Prune passiert. Der Stub zählt Aufrufe von `PruneScanReports`:
```go
type countingPruneStore struct {
	noopStore
	calls   int
	removed int64
}

func (s *countingPruneStore) PruneScanReports(_ context.Context, _ time.Time) (int64, error) {
	s.calls++
	return s.removed, nil
}

func TestStartScanReportPruneLoopDisabledDoesNotPrune(t *testing.T) {
	store := &countingPruneStore{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &backgroundServices{
		rootCtx: ctx,
		cfg:     &config.Config{ScanReportRetentionDays: 0},
		store:   store,
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	b.startScanReportPruneLoop()
	time.Sleep(50 * time.Millisecond)

	if store.calls != 0 {
		t.Fatalf("PruneScanReports calls = %d, want 0 when retention disabled", store.calls)
	}
}
```

Separater Smoke-/Regressionsschutz für den eigentlichen Prune-Aufruf:
```go
func TestPruneScanReportsOnce(t *testing.T) {
	store := &countingPruneStore{removed: 3}
	b := &backgroundServices{
		rootCtx: context.Background(),
		store:   store,
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	b.pruneScanReportsOnce(24 * time.Hour) // darf nicht panicen
	if store.calls != 1 {
		t.Fatalf("PruneScanReports calls = %d, want 1", store.calls)
	}
}
```
> Wenn `noopStore` nicht direkt eingebettet werden kann, stattdessen den kleinsten vorhandenen Test-Store aus `cmd/packmon-server` erweitern. Wichtig ist die Zähl-Assertion; der Test darf sich nicht nur auf „kein Panic" beschränken.

- [ ] **Step 4: Tests ausführen**

Run: `go test ./cmd/packmon-server/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/packmon-server/background.go cmd/packmon-server/*_test.go
git commit -m "feat(server): periodically prune aged scan reports"
```

---

## Task 8: „Show Report"-Endpoint

**Files:**
- Create: `internal/web/scan_report.go`
- Modify: `internal/web/routes.go` (Route registrieren)
- Test: `internal/web/scan_report_test.go`

- [ ] **Step 1: Failing-Test**

`internal/web/scan_report_test.go`:
```go
package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleScanReport(t *testing.T) {
	store := scansStore{reports: map[string]string{
		"a1b2c3d4e5f60718": "<html><body>report</body></html>",
	}}
	h := HandleScanReport(store, discardLogger())

	t.Run("existing report", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/scans/a1b2c3d4e5f60718/report", nil)
		req.SetPathValue("scan_id", "a1b2c3d4e5f60718")
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("content-type = %q", ct)
		}
		if !strings.Contains(rec.Body.String(), "report") {
			t.Fatalf("body missing report html")
		}
	})

	t.Run("missing report -> 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/scans/00000000deadbeef/report", nil)
		req.SetPathValue("scan_id", "00000000deadbeef")
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("invalid id -> 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/scans/..%2Fetc/report", nil)
		req.SetPathValue("scan_id", "../etc")
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}
```

- [ ] **Step 2: Test ausführen — fehlschlagen sehen**

Run: `go test ./internal/web/ -run TestHandleScanReport -v`
Expected: FAIL — `HandleScanReport` existiert nicht.

- [ ] **Step 3: Handler implementieren**

`internal/web/scan_report.go`:
```go
package web

import (
	"log/slog"
	"net/http"
	"regexp"
)

// scanIDPattern matches the hex IDs produced by the server's generateID
// (16 hex chars) plus the timestamp fallback. Validation prevents any
// untrusted input from reaching the store lookup.
var scanIDPattern = regexp.MustCompile(`^[a-f0-9]{8,32}$`)

// HandleScanReport serves GET /scans/{scan_id}/report.
func HandleScanReport(store Store, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID := r.PathValue("scan_id")
		if !scanIDPattern.MatchString(scanID) {
			http.Error(w, "invalid scan id", http.StatusBadRequest)
			return
		}

		html, ok, err := store.GetScanReport(r.Context(), scanID)
		if err != nil {
			logger.Error("scan report: store lookup failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !ok {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><body style="font-family:sans-serif;padding:2rem">` +
				`<h1>No report available</h1>` +
				`<p>This scan predates report storage or its report was pruned by retention policy.</p>` +
				`<p><a href="/scans">&larr; Back to scans</a></p></body></html>`))
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(html))
	}
}
```
> Der Handler nutzt direkt `store Store`; keine zusätzliche Hilfsschnittstelle anlegen.

- [ ] **Step 4: Route registrieren**

In `internal/web/routes.go` in `RegisterRoutes` nach der `/scans`-Zeile ergänzen:
```go
	mux.HandleFunc("GET /scans/{scan_id}/report", HandleScanReport(store, logger))
```

- [ ] **Step 5: Tests ausführen — bestehen sehen**

Run: `go test ./internal/web/ -run TestHandleScanReport -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/web/scan_report.go internal/web/routes.go internal/web/scan_report_test.go
git commit -m "feat(web): serve stored HTML report at /scans/{id}/report"
```

---

## Task 9: Remote-Scan-ID in CLI-Result übernehmen

**Files:**
- Modify: `internal/scanner/scanner.go` (`Run`, `checkRemote`)
- Test: `internal/scanner/scanner_test.go`

- [ ] **Step 1: Failing-Test — Remote-Scan verwendet Server-ID**

In `internal/scanner/scanner_test.go` ergänzen:
```go
func TestScannerRunUsesRemoteScanID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/lodash": {"version":"4.17.15"}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(domain.ScanResult{
			ScanID:          "a1b2c3d4e5f60718",
			Mode:            "remote",
			ScannedAt:       time.Now().UTC(),
			PackagesScanned: 1,
			Summary:         domain.ScanSummary{BySeverity: map[string]int{}, ByType: map[string]int{}, BySource: map[string]int{}},
			Findings:        []domain.Finding{},
			FeedVersions:    map[string]string{},
		})
	}))
	defer closeSilently(server)

	sc := New(parser.NewRegistry(), Config{
		Path:              dir,
		Mode:              ModeRemote,
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		FailOn:            domain.SeverityCritical,
		Timeout:           time.Second,
	})

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOK {
		t.Fatalf("exit = %d, result=%+v", exitCode, result)
	}
	if result.ScanID != "a1b2c3d4e5f60718" {
		t.Fatalf("ScanID = %q, want server scan id", result.ScanID)
	}
}
```
> Dieser Test pinnt die UX-/Datenbank-Konsistenz: Terminal-Ausgabe, `/scans`-Liste und `/scans/{id}/report` müssen dieselbe vom Server erzeugte ID verwenden.

- [ ] **Step 2: Test ausführen — fehlschlagen sehen**

Run: `go test ./internal/scanner/ -run TestScannerRunUsesRemoteScanID -v`
Expected: FAIL — `Run` setzt noch die lokal generierte ID.

- [ ] **Step 3: `checkRemote` gibt Server-ID zurück**

In `internal/scanner/scanner.go` die Signatur erweitern:
```go
func (s *Scanner) checkRemote(ctx context.Context, pkgs []domain.Package) (string, []domain.Finding, map[string]string, string, bool, error) {
```
Alle Fehler-Returns entsprechend mit leerer ID anpassen:
```go
return "", nil, nil, "", false, fmt.Errorf("no server URL configured (set --server or PACKMON_SERVER)")
```
Am Ende die Server-ID aus der Antwort zurückgeben:
```go
	return result.ScanID, result.Findings, result.FeedVersions, result.FeedStatus, result.FindingsBlocking, nil
```
Direkte `checkRemote`-Tests an die neue Rückgabemenge anpassen, z. B.:
```go
if _, _, _, _, _, err := sc.checkRemote(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "no server URL") {
	t.Fatalf("checkRemote(no URL) error = %v", err)
}
```

- [ ] **Step 4: `Run` übernimmt Server-ID bei erfolgreichem Remote-Pfad**

In `Run` eine Variable für die Remote-ID hinzufügen:
```go
	var remoteScanID string
```
Die Remote-Aufrufe anpassen:
```go
case ModeRemote:
	remoteScanID, findings, feedVersions, feedStatus, remoteBlocking, checkErr = s.checkRemote(ctx, allPackages)
```
und im Auto-Remote-Pfad:
```go
		remoteScanID, findings, feedVersions, feedStatus, remoteBlocking, checkErr = s.checkRemote(ctx, allPackages)
```
Nach dem `switch`, aber vor dem Result-Build:
```go
	if hasRemoteBlocking && remoteScanID != "" {
		scanID = remoteScanID
	}
```
> `hasRemoteBlocking` ist hier ein Proxy für „Remote erfolgreich genutzt". Bei Auto-Fallback auf local bleibt es `false`; dann behält der lokale Scan seine lokal erzeugte ID.

- [ ] **Step 5: Tests ausführen**

Run: `go test ./internal/scanner/ -run 'TestScannerRunUsesRemoteScanID|TestScannerRunHonorsRemoteBlockingDecision|TestCheckRemote' -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/scanner.go internal/scanner/scanner_test.go
git commit -m "fix(cli): preserve server scan id for remote scans"
```

---

## Task 10: Scan-ID im Terminal

**Files:**
- Modify: `internal/scanner/table.go` (Summary-Block, ca. Zeile 201-205)
- Test: `internal/scanner/table_test.go`

- [ ] **Step 1: Failing-Test**

In `internal/scanner/table_test.go` ergänzen:
```go
func TestTableWriterShowsScanID(t *testing.T) {
	var buf bytes.Buffer
	tw := NewTableWriter(true)
	result := &domain.ScanResult{
		ScanID:          "a1b2c3d4e5f60718",
		PackagesScanned: 2,
		FindingsCount:   0,
	}
	if err := tw.Write(&buf, result); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(buf.String(), "Scan ID: a1b2c3d4e5f60718") {
		t.Fatalf("output missing scan id:\n%s", buf.String())
	}
}
```

- [ ] **Step 2: Test ausführen — fehlschlagen sehen**

Run: `go test ./internal/scanner/ -run TestTableWriterShowsScanID -v`
Expected: FAIL — keine `Scan ID:`-Zeile.

- [ ] **Step 3: Summary-Block ergänzen**

In `internal/scanner/table.go` direkt vor der finalen Summary-Zeile (`Found %d finding(s) ...`, ca. Zeile 202) und auch im Früh-Return-Pfad „No findings" (Zeile 67-70) die Scan-ID ausgeben. Am robustesten: eine kleine Helper-Ausgabe am Ende beider Pfade. Konkret die `No findings`-Zweige und den Schlussblock so anpassen, dass nach der jeweiligen Zusammenfassung folgt:
```go
	if result.ScanID != "" {
		if _, err := fmt.Fprintf(w, "Scan ID: %s\n", result.ScanID); err != nil {
			return err
		}
	}
```
Konkrete Stellen:
- Im „No findings"-Zweig (Zeile 67-70): nach `fmt.Fprintf(w, "\nNo findings in %d packages.\n", ...)` den ScanID-Block einfügen und dann `return nil` statt direktem `return err` — d. h. erst den Fprintf-Fehler prüfen, dann ScanID schreiben:
```go
	if len(result.Findings) == 0 {
		if _, err := fmt.Fprintf(w, "\nNo findings in %d packages.\n", result.PackagesScanned); err != nil {
			return err
		}
		return writeScanID(w, result.ScanID)
	}
```
- Am Ende der `Write`-Methode (Zeile 202-205) ebenso:
```go
	blocking := tw.countBlocking(result)
	if _, err := fmt.Fprintf(w, "\nFound %d finding(s) (%d blocking) in %d packages\n",
		result.FindingsCount, blocking, result.PackagesScanned); err != nil {
		return err
	}
	return writeScanID(w, result.ScanID)
```
Und den Helper am Dateiende ergänzen:
```go
func writeScanID(w io.Writer, scanID string) error {
	if scanID == "" {
		return nil
	}
	_, err := fmt.Fprintf(w, "Scan ID: %s\n", scanID)
	return err
}
```
> Den „operational status"-Früh-Return (Zeile 62-65) unverändert lassen — dort gibt es keinen abgeschlossenen Scan/keine sinnvolle ID-Anzeige nötig; optional ebenfalls `writeScanID` anhängen, wenn gewünscht.

- [ ] **Step 4: Tests ausführen**

Run: `go test ./internal/scanner/ -run TestTableWriter -v`
Expected: PASS. Falls bestehende Table-Golden-Tests die exakte Ausgabe prüfen, deren Erwartung um die `Scan ID:`-Zeile ergänzen.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/table.go internal/scanner/table_test.go
git commit -m "feat(cli): print Scan ID in terminal table output"
```

---

## Task 11: Scan-ID prominent im HTML-Report

**Files:**
- Modify: `internal/scanner/html.go` (`htmlReport`-Struct + Template-Kopf)
- Test: `internal/scanner/html_test.go`

- [ ] **Step 1: Failing-Test**

In `internal/scanner/html_test.go` ergänzen (die ID steht heute nur in der Fußzeile; neu: auch im Kopf-/Meta-Block, monospace/kopierbar):
```go
func TestHTMLReportShowsScanIDInHeader(t *testing.T) {
	var buf bytes.Buffer
	hw := NewHTMLWriter("dev")
	result := &domain.ScanResult{
		ScanID:          "a1b2c3d4e5f60718",
		PackagesScanned: 1,
	}
	if err := hw.Write(&buf, "acme/api", domain.SeverityCritical, result); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	// Im Kopfbereich als eigenes, klar erkennbares Element (data-Attribut macht
	// die Assertion robust gegen Layout-Änderungen).
	if !strings.Contains(out, `data-scan-id="a1b2c3d4e5f60718"`) {
		t.Fatalf("scan id not rendered in header:\n%s", out)
	}
}
```

- [ ] **Step 2: Test ausführen — fehlschlagen sehen**

Run: `go test ./internal/scanner/ -run TestHTMLReportShowsScanIDInHeader -v`
Expected: FAIL.

- [ ] **Step 3: `htmlReport` um `ScanID` ergänzen (falls nicht vorhanden) und Template-Kopf anpassen**

In `internal/scanner/html.go`: Prüfen, ob `htmlReport` (Struct ab Zeile 55) bereits ein `ScanID`-Feld hat. Falls nicht, ergänzen:
```go
	ScanID        string
```
In `buildReport` (die Funktion, die `htmlReport` füllt) `rep.ScanID = result.ScanID` setzen.

Im `htmlTemplate` (ab Zeile 330) im Kopfbereich (nahe Titel/Meta, vor der Findings-Tabelle) ein Element ergänzen, das die ID prominent und kopierbar zeigt — nur wenn gesetzt:
```html
{{if .ScanID}}
<p class="meta scan-id" data-scan-id="{{.ScanID}}">
  Scan ID: <code style="font-family:monospace;user-select:all">{{.ScanID}}</code>
</p>
{{end}}
```
> Falls das Template bereits inline-CSS-Klassen nutzt, an den vorhandenen Stil anpassen. Die bestehende Fußzeilen-Ausgabe der ID (über `metaParts`, Zeile 320-323) bleibt unverändert.

- [ ] **Step 4: Tests ausführen**

Run: `go test ./internal/scanner/ -run TestHTML -v`
Expected: PASS. Falls Golden-/Snapshot-Tests die Kopfausgabe prüfen, Erwartung ergänzen.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/html.go internal/scanner/html_test.go
git commit -m "feat(report): surface Scan ID prominently in HTML report header"
```

---

## Task 12: `/scans`-Layout — volle ID, „Show Report", Suche

**Files:**
- Modify: `internal/web/scans.go` (Such-Param `q`, View-Model)
- Modify: `internal/web/templates/scans.html`
- Test: `internal/web/render_helpers_test.go` bzw. `internal/web/scans_test.go`

- [ ] **Step 1: Failing-Test — Such-Param wird angewandt**

Test ergänzen (in `internal/web/scans_test.go`, ggf. neu anlegen), der prüft, dass `HandleScans` den Query-Param `q` an den Store weiterreicht. Da `scansStore.SearchRecentScans` in Task 4 auf `ListRecentScans` mappt, hier mit einem zählenden Store arbeiten oder den Aufruf verifizieren:
```go
type recordingScansStore struct {
	scansStore
	lastQuery string
}

func (s *recordingScansStore) SearchRecentScans(_ context.Context, query string, limit int) ([]db.ScanLogEntry, error) {
	if limit != 50 {
		panic("unexpected limit")
	}
	s.lastQuery = query
	return []db.ScanLogEntry{{
		ScanID:        "a1b2c3d4e5f60718",
		RepoName:      "acme/api",
		ScannedAt:     time.Now().UTC(),
		PackagesCount: 1,
		HasReport:     true,
	}}, nil
}

func TestHandleScansPassesSearchQuery(t *testing.T) {
	store := &recordingScansStore{
		scansStore: scansStore{
			mockStore: &mockStore{},
			daily:     []db.DailyScanStats{},
		},
	}
	h := HandleScans(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/scans?q=acme", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if store.lastQuery != "acme" {
		t.Fatalf("query = %q, want acme", store.lastQuery)
	}
}
```

- [ ] **Step 2: Test ausführen — fehlschlagen sehen**

Run: `go test ./internal/web/ -run TestHandleScansPassesSearchQuery -v`
Expected: FAIL — `HandleScans` liest `q` noch nicht / nutzt `SearchRecentScans` noch nicht.

- [ ] **Step 3: `scans.go` — Such-Param + View-Model**

In `internal/web/scans.go`:
- `ScansData` um die Suchanfrage ergänzen:
```go
type ScansData struct {
	ActiveNav    string
	DailyStats   []DailyStatRow
	TotalScans7d int
	RecentScans  []db.ScanLogEntry
	Query        string
}
```
- In `HandleScans` den Param lesen und `SearchRecentScans` statt `ListRecentScans` verwenden:
```go
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	scans, err := store.SearchRecentScans(ctx, query, 50)
	if err != nil {
		logger.Error("scans: failed to load recent scans", "error", err)
	}

	data := ScansData{
		ActiveNav:    "scans",
		DailyStats:   rows,
		TotalScans7d: totalScans,
		RecentScans:  scans,
		Query:        query,
	}
```
> `strings` zum Import ergänzen, falls nötig.

- [ ] **Step 4: Test ausführen — bestehen sehen**

Run: `go test ./internal/web/ -run TestHandleScansPassesSearchQuery -v`
Expected: PASS.

- [ ] **Step 5: Template — Suchfeld, volle ID, Report-Button**

In `internal/web/templates/scans.html`:

(a) Die „Recent Scans"-Karte muss immer rendern, auch wenn `RecentScans` leer ist. Nur die Tabelle vs. Empty-State darf unter `{{if .RecentScans}}` stehen. Dadurch bleiben Suchfeld und „Clear" bei Null-Treffer-Suchen sichtbar:
```html
<div class="bg-white rounded-lg shadow p-5 border border-gray-200">
  <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between mb-3">
    <h2 class="text-lg font-semibold text-gray-900">Recent Scans</h2>
    <form method="GET" action="/scans" class="flex flex-col gap-2 sm:flex-row sm:items-center">
      <input type="text" name="q" value="{{.Query}}" placeholder="Search by Scan ID or repo"
             class="border border-gray-300 rounded px-3 py-1 text-sm w-full sm:w-72" />
      <button type="submit" class="bg-gray-800 text-white text-sm px-3 py-1 rounded">Search</button>
      {{if .Query}}<a href="/scans" class="text-sm text-gray-500 px-2 py-1">Clear</a>{{end}}
    </form>
  </div>

  {{if .RecentScans}}
  <div class="overflow-x-auto">
    <!-- existing table lives here -->
  </div>
  {{else}}
  <div class="text-center text-gray-400 py-10">
    {{if .Query}}No scans match "{{.Query}}".{{else}}No scans recorded yet. Run <code class="bg-gray-100 px-1 rounded">packmon scan</code> to get started.{{end}}
  </div>
  {{end}}
</div>
```

(b) Innerhalb der bestehenden Tabelle den Tabellenkopf um eine `Report`-Spalte ergänzen (nach der `Duration`-Spalte, Zeile 60):
```html
            <th class="pb-2 pr-4">Report</th>
```

(c) Die Scan-ID-Zelle (Zeile 66) von `truncate` auf volle, kopierbare ID umstellen, und eine Report-Zelle anhängen (Zeile 71 danach):
```html
            <td class="py-2 pr-4 font-mono text-xs">
              <span class="select-all" title="{{.ScanID}}">{{.ScanID}}</span>
            </td>
```
```html
            <td class="py-2 pr-4">
              {{if .HasReport}}
              <a href="/scans/{{.ScanID}}/report" target="_blank" rel="noopener"
                 class="text-blue-600 hover:underline text-sm">Show Report</a>
              {{else}}
              <span class="text-gray-300 text-sm" title="No stored report">—</span>
              {{end}}
            </td>
```

(d) Falls das vorhandene Template aktuell die gesamte Karte in `{{if .RecentScans}} ... {{else}} ... {{end}}` einbettet, diese Struktur auflösen: Die Karte mit Header/Suchformular bleibt außen, nur Tabelleninhalt und Empty-State wechseln.

- [ ] **Step 6: Render-Test (Template kompiliert + zeigt Button/Suchfeld)**

Den vorhandenen Scans-Render-Test (`render_helpers_test.go`, `scansStore` mit Beispielzeilen) erweitern: eine Zeile mit `HasReport: true` und eine mit `false` einspeisen und prüfen, dass das gerenderte HTML „Show Report", einen `/scans/<id>/report`-Link und das `name="q"`-Suchfeld enthält:
```go
	if !strings.Contains(html, `name="q"`) {
		t.Fatalf("scans page missing search field")
	}
	if !strings.Contains(html, "Show Report") {
		t.Fatalf("scans page missing report button")
	}
```
Zusätzlich einen Render-Test für leere Suchtreffer ergänzen. Erwartet: Suchfeld bleibt sichtbar, „Clear" bleibt sichtbar, und die Empty-State-Meldung nennt die Query:
```go
func TestHandleScansEmptySearchKeepsSearchControls(t *testing.T) {
	store := scansStore{
		mockStore: &mockStore{},
		daily:     []db.DailyScanStats{},
		scans:     nil,
	}
	handler := HandleScans(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/scans?q=missing", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleScans status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="q"`) || !strings.Contains(body, `href="/scans"`) {
		t.Fatalf("empty search state must keep search and clear controls:\n%s", body)
	}
	if !strings.Contains(body, `No scans match "missing"`) {
		t.Fatalf("empty search state missing query-specific message:\n%s", body)
	}
}
```

- [ ] **Step 7: Tests ausführen**

Run: `go test ./internal/web/...`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/web/scans.go internal/web/templates/scans.html internal/web/*_test.go
git commit -m "feat(web): full scan IDs, report button, and search on /scans"
```

---

## Task 13: End-to-End-Verifikation & Gate

**Files:** keine (Verifikation)

- [ ] **Step 1: Vollständiger Build + Tests + Vet**

Run: `go build ./...`
Run: `go test ./...`
Run: `go vet ./...`
Expected: alle grün. (Postgres-Integrationstests benötigen Docker-Postgres; sonst werden sie übersprungen.)

- [ ] **Step 2: Lint / Security gemäß AGENTS.md**

Die in `AGENTS.md` → „Verification Gate" gelisteten Lint-/Security-Kommandos ausführen (z. B. `golangci-lint`, `gosec`). Erwartet: keine neuen Findings.

- [ ] **Step 3: Manuelle Smoke-Verifikation (Docker-Stack)**

1. Stack neu bauen/starten (`docker compose up -d --build`), Migration läuft auf `schema_version=9`.
2. Einen Scan über die CLI/`/api/v1/check` ausführen → Terminal zeigt `Scan ID: <id>`.
3. `http://localhost:8080/scans` öffnen → Zeile zeigt dieselbe volle ID + „Show Report".
4. „Show Report" klickt → HTML-Report öffnet im neuen Tab (entspricht `--html`).
5. Suchfeld mit ID-Fragment / Repo-Name testen → gefilterte Liste.
6. Bestehende Alt-Scans zeigen in der Report-Spalte „—".

- [ ] **Step 4: Kanonische Doku + Audit-Notiz**

Gemäß `AGENTS.md` diese Dateien in derselben Änderung aktualisieren:

`DESIGN.md`:
- Im Server-/Web-UI-Abschnitt dokumentieren: `POST /api/v1/check` erzeugt weiter den kanonischen JSON-Scan-Result und speichert zusätzlich best-effort ein gerendertes HTML-Report-Artefakt in `scan_reports`.
- `/scans` listet volle Scan-IDs und verlinkt vorhandene Reports unter `/scans/{scan_id}/report`; alte oder geprunte Scans bleiben in `scan_log` sichtbar, zeigen aber keinen Report-Link.
- Retention: `PACKMON_SCAN_REPORT_RETENTION_DAYS` Default `90`, `0` deaktiviert Pruning; Pruning löscht nur `scan_reports`, nie `scan_log`.
- Remote CLI Scans übernehmen die Server-`ScanID`; lokale/offline Scans erzeugen weiterhin lokale IDs.

`SECURITY.md`:
- Public-pages-/Dashboard-Abschnitt um `GET /scans/{scan_id}/report` ergänzen.
- Explizit festhalten: Der Report enthält Paketnamen/-versionen, Findings und Repo-Metadaten; der `scan_id` wirkt als Capability für den direkten Report-Link.
- Deployment-Grenze wiederholen: Packmon bleibt internal-only; diese Seite darf nicht ins öffentliche Internet exponiert werden, außer es gibt davor eine geeignete Auth-/Proxy-Schicht.
- Keine API-Key-Requirement für diesen Web-Endpunkt in diesem Scope, konsistent mit dem bestehenden Web-UI-Zugriffsmodell.

`README.md`:
- `PACKMON_SCAN_REPORT_RETENTION_DAYS` im Server-/Docker-Konfigurationsbeispiel aufführen, falls nicht bereits in Task 6 erledigt.
- Kurzer Bedienhinweis: `/scans` zeigt volle IDs, Suche und „Show Report" für neue Scans.

`Audit.md`:
- Eintrag zu den abgeschlossenen Validierungen ergänzen: Report-Persistenz, Remote-ID-Konsistenz, `/scans`-Suche/Report-Link.
- Offenen Review-Hinweis aufnehmen: Report-Endpoint folgt dem bestehenden Public-pages-Modell; `scan_id` ist eine Capability und sollte im nächsten Security-Review erneut bewertet werden.

- [ ] **Step 5: Commit**

```bash
git add DESIGN.md SECURITY.md README.md Audit.md
git commit -m "docs: document stored scan reports and report links"
```

---

## Self-Review (durchgeführt)

- **Spec-Abdeckung:** Persistenz (Task 1,3,5), Retention (Task 1,6,7), Report-Endpoint (Task 8), Remote-Scan-ID-Konsistenz (Task 9), Scan-ID Terminal (Task 10) + HTML (Task 11), `/scans` Layout + Suche (Task 12), kanonische Doku + Security-Notiz (Task 13) — alle Spec-Abschnitte abgedeckt.
- **Typen-Konsistenz:** `InsertScanReport(ctx, scanID, html string, scannedAt time.Time)`, `GetScanReport(ctx, scanID) (string, bool, error)`, `PruneScanReports(ctx, olderThan) (int64, error)`, `SearchRecentScans(ctx, query string, limit int)` — über alle Implementierer (postgres, sqlite, noop, Mocks) und Aufrufer identisch verwendet. `ScanLogEntry.HasReport bool` durchgängig.
- **Platzhalter:** Keine offenen Platzhalter; die geänderten Test-Schritte zeigen konkrete Stubs, Requests und Assertions.
- **Handler-Reihenfolge:** Task 5 speichert `scan_log` wie bisher best-effort, schreibt die JSON-Antwort und startet erst danach async die HTML-Report-Persistenz mit Threshold-Snapshot.
