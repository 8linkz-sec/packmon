package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const f223ScanHistoryTable = `CREATE TABLE scan_history (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	repo_name          TEXT,
	branch             TEXT,
	"commit"           TEXT,
	scanned_at         TEXT NOT NULL,
	packages_count     INTEGER,
	findings_count     INTEGER,
	finding_ids        TEXT,
	finding_severities TEXT
)`

func TestInsertScanPersistsCanonicalValuesAndReportsExecFailure(t *testing.T) {
	t.Run("canonical values", func(t *testing.T) {
		store := newSQLiteTestStore(t)
		ctx := context.Background()
		scannedAt := time.Date(2026, 5, 4, 12, 30, 45, 0, time.FixedZone("test", 2*60*60))

		if err := store.InsertScan(ctx, ScanEntry{
			RepoName:      "example/repo",
			Branch:        "main",
			Commit:        "abc123",
			ScannedAt:     scannedAt,
			PackagesCount: 7,
			FindingsCount: 0,
		}); err != nil {
			t.Fatalf("InsertScan() error = %v", err)
		}

		var storedAt, idsJSON, severitiesJSON string
		if err := store.db.QueryRowContext(ctx, `
			SELECT scanned_at, finding_ids, finding_severities
			FROM scan_history`).Scan(&storedAt, &idsJSON, &severitiesJSON); err != nil {
			t.Fatalf("query stored scan: %v", err)
		}
		if want := scannedAt.UTC().Format(time.RFC3339); storedAt != want {
			t.Errorf("stored scanned_at = %q, want %q", storedAt, want)
		}
		if idsJSON != "null" || severitiesJSON != "null" {
			t.Errorf("stored nil finding slices = (%q, %q), want (null, null)", idsJSON, severitiesJSON)
		}

		got, err := store.GetRecentScans(ctx, "", 1)
		if err != nil {
			t.Fatalf("GetRecentScans() error = %v", err)
		}
		if len(got) != 1 || !got[0].ScannedAt.Equal(scannedAt) || got[0].FindingIDs != nil || got[0].FindingSeverities != nil {
			t.Fatalf("GetRecentScans() = %+v, want the canonical persisted values", got)
		}
	})

	t.Run("exec failure", func(t *testing.T) {
		database, rule := openFaultyDB(t, "INSERT INTO scan_history", 0)
		f223CreateScanHistoryTable(t, database)
		store := &Store{db: database}

		err := store.InsertScan(context.Background(), ScanEntry{
			ScannedAt: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC),
		})
		if err == nil || !errors.Is(err, errInjectedFault) || !strings.Contains(err.Error(), "sqlite: insert scan history") {
			t.Fatalf("InsertScan() error = %v, want wrapped injected exec fault", err)
		}
		if !rule.didFire() {
			t.Fatal("the injected InsertScan fault did not fire")
		}
		var count int
		if err := database.QueryRow(`SELECT COUNT(*) FROM scan_history`).Scan(&count); err != nil {
			t.Fatalf("count scan history: %v", err)
		}
		if count != 0 {
			t.Fatalf("scan history row count = %d after failed insert, want 0", count)
		}
	})
}

func TestClearHistoryFilterCombinations(t *testing.T) {
	cutoff := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		before    *time.Time
		repo      string
		wantCount int
		wantRows  []string
	}{
		{name: "before and repository", before: &cutoff, repo: "repo-a", wantCount: 1, wantRows: []string{"repo-a:2", "repo-b:3", "repo-b:4"}},
		{name: "before only", before: &cutoff, wantCount: 2, wantRows: []string{"repo-a:2", "repo-b:4"}},
		{name: "repository only", repo: "repo-a", wantCount: 2, wantRows: []string{"repo-b:3", "repo-b:4"}},
		{name: "no filters", wantCount: 4},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newSQLiteTestStore(t)
			ctx := context.Background()
			for _, entry := range []ScanEntry{
				{RepoName: "repo-a", ScannedAt: cutoff.Add(-time.Hour), PackagesCount: 1},
				{RepoName: "repo-a", ScannedAt: cutoff, PackagesCount: 2},
				{RepoName: "repo-b", ScannedAt: cutoff.Add(-time.Hour), PackagesCount: 3},
				{RepoName: "repo-b", ScannedAt: cutoff, PackagesCount: 4},
			} {
				if err := store.InsertScan(ctx, entry); err != nil {
					t.Fatalf("seed InsertScan() error = %v", err)
				}
			}

			gotCount, err := store.ClearHistory(ctx, tc.before, tc.repo)
			if err != nil {
				t.Fatalf("ClearHistory() error = %v", err)
			}
			if gotCount != tc.wantCount {
				t.Errorf("ClearHistory() count = %d, want %d", gotCount, tc.wantCount)
			}

			rows, err := store.db.Query(`SELECT repo_name, packages_count FROM scan_history ORDER BY id`)
			if err != nil {
				t.Fatalf("query remaining history: %v", err)
			}
			var gotRows []string
			for rows.Next() {
				var repo string
				var packages int
				if err := rows.Scan(&repo, &packages); err != nil {
					_ = rows.Close()
					t.Fatalf("scan remaining history: %v", err)
				}
				gotRows = append(gotRows, fmt.Sprintf("%s:%d", repo, packages))
			}
			if err := rows.Err(); err != nil {
				_ = rows.Close()
				t.Fatalf("iterate remaining history: %v", err)
			}
			if err := rows.Close(); err != nil {
				t.Fatalf("close remaining history rows: %v", err)
			}
			if !reflect.DeepEqual(gotRows, tc.wantRows) {
				t.Errorf("remaining rows = %v, want %v", gotRows, tc.wantRows)
			}
		})
	}
}

func TestClearHistoryExecFailureLeavesRowsUntouched(t *testing.T) {
	database, rule := openFaultyDB(t, "DELETE FROM scan_history", 0)
	f223CreateScanHistoryTable(t, database)
	if _, err := database.Exec(`INSERT INTO scan_history (scanned_at) VALUES ('2026-05-04T12:00:00Z')`); err != nil {
		t.Fatalf("seed scan history: %v", err)
	}
	store := &Store{db: database}

	count, err := store.ClearHistory(context.Background(), nil, "")
	if count != 0 || err == nil || !errors.Is(err, errInjectedFault) || !strings.Contains(err.Error(), "sqlite: clear history") {
		t.Fatalf("ClearHistory() = (%d, %v), want zero and wrapped injected exec fault", count, err)
	}
	if !rule.didFire() {
		t.Fatal("the injected ClearHistory fault did not fire")
	}
	var remaining int
	if err := database.QueryRow(`SELECT COUNT(*) FROM scan_history`).Scan(&remaining); err != nil {
		t.Fatalf("count remaining history: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("remaining row count = %d after failed clear, want 1", remaining)
	}
}

func TestGetRecentScansPageBoundariesAndNullableValues(t *testing.T) {
	store := newSQLiteTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 55; i++ {
		if err := store.InsertScan(ctx, ScanEntry{
			RepoName:      fmt.Sprintf("repo-%d", i%2),
			Branch:        "main",
			Commit:        fmt.Sprintf("commit-%02d", i),
			ScannedAt:     base.Add(time.Duration(i) * time.Minute),
			PackagesCount: i,
		}); err != nil {
			t.Fatalf("seed InsertScan(%d) error = %v", i, err)
		}
	}

	defaultPage, err := store.getRecentScansPage(ctx, "", 0, 0)
	if err != nil {
		t.Fatalf("getRecentScansPage(default limit) error = %v", err)
	}
	if len(defaultPage) != 50 {
		t.Fatalf("default page length = %d, want 50", len(defaultPage))
	}
	if defaultPage[0].Commit != "commit-54" || defaultPage[49].Commit != "commit-05" {
		t.Fatalf("default page boundaries = first %q, last %q; want commit-54, commit-05", defaultPage[0].Commit, defaultPage[49].Commit)
	}

	page, err := store.getRecentScansPage(ctx, "", 2, 1)
	if err != nil {
		t.Fatalf("getRecentScansPage(offset) error = %v", err)
	}
	if len(page) != 2 || page[0].Commit != "commit-53" || page[1].Commit != "commit-52" {
		t.Fatalf("offset page = %+v, want commits 53 and 52", page)
	}

	clamped, err := store.getRecentScansPage(ctx, "repo-0", 1, -9)
	if err != nil {
		t.Fatalf("getRecentScansPage(negative offset) error = %v", err)
	}
	if len(clamped) != 1 || clamped[0].Commit != "commit-54" {
		t.Fatalf("negative-offset page = %+v, want newest repo-0 row", clamped)
	}

	unlimited, err := store.getRecentScansPage(ctx, "repo-1", -1, 0)
	if err != nil {
		t.Fatalf("getRecentScansPage(unlimited) error = %v", err)
	}
	if len(unlimited) != 27 {
		t.Fatalf("unlimited repo page length = %d, want 27", len(unlimited))
	}
	if unlimited[0].Commit != "commit-53" || unlimited[26].Commit != "commit-01" {
		t.Fatalf("unlimited repo page boundaries = first %q, last %q; want commit-53, commit-01", unlimited[0].Commit, unlimited[26].Commit)
	}

	if _, err := store.db.Exec(`INSERT INTO scan_history
		(repo_name, branch, "commit", scanned_at, packages_count, findings_count, finding_ids, finding_severities)
		VALUES (NULL, NULL, NULL, ?, 3, 2, NULL, NULL),
		       ('', '', '', ?, 4, 1, '', '')`,
		base.Add(2*time.Hour).Format(time.RFC3339), base.Add(3*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatalf("seed nullable history rows: %v", err)
	}
	nullable, err := store.getRecentScansPage(ctx, "", 2, 0)
	if err != nil {
		t.Fatalf("getRecentScansPage(nullable rows) error = %v", err)
	}
	for i, entry := range nullable {
		if entry.RepoName != "" || entry.Branch != "" || entry.Commit != "" || entry.FindingIDs != nil || entry.FindingSeverities != nil {
			t.Errorf("nullable row %d = %+v, want zero-valued optional fields", i, entry)
		}
	}
}

func TestGetRecentScansPageReturnsNilOnRowFailures(t *testing.T) {
	tests := []struct {
		name       string
		corruptSQL string
		want       string
	}{
		{name: "scan", corruptSQL: `UPDATE scan_history SET packages_count = 'not-an-integer' WHERE id = 2`, want: "sqlite: scan history row"},
		{name: "scanned at", corruptSQL: `UPDATE scan_history SET scanned_at = '2025-invalid' WHERE id = 2`, want: "sqlite: decode scan history row 2 scanned_at"},
		{name: "finding ids", corruptSQL: `UPDATE scan_history SET finding_ids = '{' WHERE id = 2`, want: "sqlite: decode scan history row 2 finding_ids"},
		{name: "finding severities", corruptSQL: `UPDATE scan_history SET finding_severities = '{' WHERE id = 2`, want: "sqlite: decode scan history row 2 finding_severities"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newSQLiteTestStore(t)
			ctx := context.Background()
			for _, entry := range []ScanEntry{
				{ScannedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), FindingIDs: []string{"good"}, FindingSeverities: []string{"LOW"}},
				{ScannedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), FindingIDs: []string{"bad"}, FindingSeverities: []string{"HIGH"}},
			} {
				if err := store.InsertScan(ctx, entry); err != nil {
					t.Fatalf("seed InsertScan() error = %v", err)
				}
			}
			if _, err := store.db.Exec(tc.corruptSQL); err != nil {
				t.Fatalf("corrupt scan history: %v", err)
			}

			got, err := store.getRecentScansPage(ctx, "", 10, 0)
			if got != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("getRecentScansPage() = (%+v, %v), want nil and error containing %q", got, err, tc.want)
			}
		})
	}
}

func TestGetRecentScansPageReportsQueryAndIterationFailuresWithoutPartialResults(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		database, rule := openFaultyDB(t, "SELECT id, repo_name", 0)
		store := &Store{db: database}

		got, err := store.getRecentScansPage(context.Background(), "", 10, 0)
		if got != nil || err == nil || !errors.Is(err, errInjectedFault) || !strings.Contains(err.Error(), "sqlite: query scan history") {
			t.Fatalf("getRecentScansPage() = (%+v, %v), want nil and wrapped query fault", got, err)
		}
		if !rule.didFire() {
			t.Fatal("the injected history query fault did not fire")
		}
	})

	t.Run("iteration", func(t *testing.T) {
		database, fired := f223OpenIterationFaultDB(t)
		f223CreateScanHistoryTable(t, database)
		if _, err := database.Exec(`INSERT INTO scan_history
			(scanned_at, packages_count, findings_count, finding_ids, finding_severities)
			VALUES ('2026-01-02T00:00:00Z', 1, 0, '[]', '[]'),
			       ('2026-01-01T00:00:00Z', 2, 0, '[]', '[]')`); err != nil {
			t.Fatalf("seed scan history: %v", err)
		}
		store := &Store{db: database}

		got, err := store.getRecentScansPage(context.Background(), "", 10, 0)
		if got != nil || err == nil || !errors.Is(err, errInjectedFault) || !strings.Contains(err.Error(), "sqlite: iterate scan history") {
			t.Fatalf("getRecentScansPage() = (%+v, %v), want nil and wrapped iteration fault", got, err)
		}
		if !fired.Load() {
			t.Fatal("the injected history iteration fault did not fire")
		}
	})
}

func f223CreateScanHistoryTable(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(f223ScanHistoryTable); err != nil {
		t.Fatalf("create scan_history: %v", err)
	}
}

type f223IterationFaultDriver struct {
	inner driver.Driver
	fired *atomic.Bool
}

func (d *f223IterationFaultDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &f223IterationFaultConn{Conn: conn, fired: d.fired}, nil
}

type f223IterationFaultConn struct {
	driver.Conn
	fired *atomic.Bool
}

func (c *f223IterationFaultConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return execer.ExecContext(ctx, query, args)
}

func (c *f223IterationFaultConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	rows, err := queryer.QueryContext(ctx, query, args)
	if err != nil || !strings.Contains(strings.ToUpper(query), "SELECT ID, REPO_NAME") {
		return rows, err
	}
	return &f223IterationFaultRows{Rows: rows, fired: c.fired}, nil
}

type f223IterationFaultRows struct {
	driver.Rows
	fired    *atomic.Bool
	returned bool
}

func (r *f223IterationFaultRows) Next(dest []driver.Value) error {
	if r.returned {
		r.fired.Store(true)
		return errInjectedFault
	}
	err := r.Rows.Next(dest)
	if err == nil {
		r.returned = true
	}
	return err
}

var f223IterationFaultDriverSequence atomic.Uint64

func f223OpenIterationFaultDB(t *testing.T) (*sql.DB, *atomic.Bool) {
	t.Helper()

	probe, err := sql.Open(realDriverName, ":memory:")
	if err != nil {
		t.Fatalf("open SQLite driver probe: %v", err)
	}
	inner := probe.Driver()
	if err := probe.Close(); err != nil {
		t.Fatalf("close SQLite driver probe: %v", err)
	}

	fired := &atomic.Bool{}
	driverName := fmt.Sprintf("sqlite-f223-iteration-%d", f223IterationFaultDriverSequence.Add(1))
	sql.Register(driverName, &f223IterationFaultDriver{inner: inner, fired: fired})
	database, err := sql.Open(driverName, filepath.Join(t.TempDir(), "iteration.db"))
	if err != nil {
		t.Fatalf("open iteration-fault database: %v", err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	return database, fired
}

var (
	_ driver.ExecerContext  = (*f223IterationFaultConn)(nil)
	_ driver.QueryerContext = (*f223IterationFaultConn)(nil)
	_ driver.Rows           = (*f223IterationFaultRows)(nil)
)
