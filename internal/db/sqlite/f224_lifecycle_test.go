package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	lifecyclepolicy "github.com/8linkz-sec/packmon/internal/lifecycle"
)

func TestF224LifecycleHelpersNormalizeContextAndDates(t *testing.T) {
	t.Parallel()

	if got := localPackageChunkContext(localPackagePredicateChunk{}); got != "requested packages" {
		t.Fatalf("localPackageChunkContext(empty) = %q", got)
	}
	if got := localPackageChunkContext(localPackagePredicateChunk{args: []any{7, false}}); got != "requested packages" {
		t.Fatalf("localPackageChunkContext(non-string args) = %q", got)
	}
	chunk := localPackagePredicateChunk{args: []any{
		"npm", "alpha",
		"pypi", "beta",
		"nuget", "gamma",
		"go", "delta",
		"cargo", "epsilon",
	}}
	if got, want := localPackageChunkContext(chunk), "npm/alpha, pypi/beta, nuget/gamma, +2 more"; got != want {
		t.Fatalf("localPackageChunkContext(truncated) = %q, want %q", got, want)
	}

	for _, tc := range []struct {
		name string
		in   db.PackageQuery
		want db.PackageQuery
		ok   bool
	}{
		{name: "empty ecosystem", in: db.PackageQuery{Name: "django"}},
		{name: "empty name", in: db.PackageQuery{Ecosystem: "pypi", Name: "  "}},
		{
			name: "normalized",
			in:   db.PackageQuery{Ecosystem: " PyPI ", Name: " Django_Core ", Version: " 4.2.11 "},
			want: db.PackageQuery{Ecosystem: "PyPI", Name: "django-core", Version: "4.2.11"},
			ok:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := normalizeLifecyclePackageQuery(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("normalizeLifecyclePackageQuery(%+v) = (%+v, %v), want (%+v, %v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}

	dateOnly := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	rfc3339 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("f224", 2*60*60))
	for _, tc := range []struct {
		name  string
		value sql.NullString
		want  *time.Time
	}{
		{name: "null"},
		{name: "blank", value: sql.NullString{Valid: true, String: "  "}},
		{name: "invalid", value: sql.NullString{Valid: true, String: "2026-02-31"}},
		{name: "date", value: sql.NullString{Valid: true, String: " 2026-01-02 "}, want: &dateOnly},
		{name: "RFC3339", value: sql.NullString{Valid: true, String: "2026-01-02T03:04:05+02:00"}, want: &rfc3339},
	} {
		t.Run("date "+tc.name, func(t *testing.T) {
			got := parseSQLiteDate(tc.value)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("parseSQLiteDate(%+v) = %v, want nil", tc.value, got)
				}
				return
			}
			if got == nil || !got.Equal(*tc.want) {
				t.Fatalf("parseSQLiteDate(%+v) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestF224CollectLifecycleReleaseRowsConvertsNullableValues(t *testing.T) {
	store := newSQLiteTestStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `
		INSERT INTO lifecycle_releases_local (
			id, ecosystem, name, product_slug, product_label, cycle, latest,
			release_date, is_lts, lts_from, is_eoas, eoas_from, is_eol, eol_from,
			is_discontinued, discontinued_from, is_eoes, eoes_from, is_maintained
		) VALUES
			('f224-null', 'npm', 'f224-package', 'f224-product', 'F224 Product', '1', '1.2.3',
			 ' 2026-01-02 ', 2, '2026-01-03T04:05:06+02:00', -1, '', 0, 'invalid-date',
			 1, '2026-02-03', NULL, '2026-03-04T05:06:07Z', 2),
			('f224-false', 'npm', 'f224-package', 'f224-product-two', '', '2', '',
			 NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0)`); err != nil {
		t.Fatalf("seed lifecycle conversion rows: %v", err)
	}

	chunks := localPackagePredicateChunks([]db.PackageQuery{{Ecosystem: "npm", Name: "f224-package"}}, 1)
	if len(chunks) != 1 {
		t.Fatalf("localPackagePredicateChunks() count = %d, want 1", len(chunks))
	}
	rowsByPackage := make(map[localPackageKey][]lifecyclepolicy.ReleaseRow)
	if err := store.collectLifecycleReleaseRows(ctx, chunks[0], rowsByPackage); err != nil {
		t.Fatalf("collectLifecycleReleaseRows() error = %v", err)
	}
	rows := rowsByPackage[localPackageKey{ecosystem: "npm", name: "f224-package"}]
	if len(rows) != 2 {
		t.Fatalf("converted lifecycle rows = %+v, want 2", rows)
	}
	byID := make(map[string]lifecyclepolicy.ReleaseRow, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	nullable := byID["f224-null"]
	if nullable.ID == "" || nullable.ProductName != "F224 Product" || nullable.Release.Cycle != "1" || nullable.Release.Latest != "1.2.3" {
		t.Fatalf("converted lifecycle identity = %+v", nullable)
	}
	wantReleaseDate := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	wantLTSFrom := time.Date(2026, 1, 3, 4, 5, 6, 0, time.FixedZone("f224-lts", 2*60*60))
	wantDiscontinued := time.Date(2026, 2, 3, 0, 0, 0, 0, time.UTC)
	wantEOESFrom := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if nullable.Release.ReleaseDate == nil || !nullable.Release.ReleaseDate.Equal(wantReleaseDate) ||
		!nullable.Release.IsLTS || nullable.Release.LTSFrom == nil || !nullable.Release.LTSFrom.Equal(wantLTSFrom) ||
		!nullable.Release.IsEOAS || nullable.Release.EOASFrom != nil || nullable.Release.IsEOL || nullable.Release.EOLFrom != nil ||
		!nullable.Release.IsDiscontinued || nullable.Release.DiscontinuedFrom == nil || !nullable.Release.DiscontinuedFrom.Equal(wantDiscontinued) ||
		nullable.Release.IsEOES != nil || nullable.Release.EOESFrom == nil || !nullable.Release.EOESFrom.Equal(wantEOESFrom) ||
		!nullable.Release.IsMaintained {
		t.Fatalf("converted nullable lifecycle release = %+v", nullable.Release)
	}
	falseEOES := byID["f224-false"]
	if falseEOES.ID == "" || falseEOES.Release.IsEOES == nil || *falseEOES.Release.IsEOES ||
		falseEOES.Release.ReleaseDate != nil || falseEOES.Release.IsLTS || falseEOES.Release.IsEOAS || falseEOES.Release.IsEOL ||
		falseEOES.Release.IsDiscontinued || falseEOES.Release.EOESFrom != nil || falseEOES.Release.IsMaintained {
		t.Fatalf("converted false/NULL lifecycle release = %+v", falseEOES.Release)
	}
}

func TestF224FindLifecycleFindingsBatchEmptyNormalizedAndZeroNow(t *testing.T) {
	store := newSQLiteTestStore(t)
	ctx := context.Background()

	if got, err := store.FindLifecycleFindingsBatch(ctx, nil, time.Time{}); err != nil || got != nil {
		t.Fatalf("FindLifecycleFindingsBatch(empty) = (%+v, %v), want nil nil", got, err)
	}
	invalid := []db.PackageQuery{{Name: "missing-ecosystem"}, {Ecosystem: "npm", Name: "  "}}
	if got, err := store.FindLifecycleFindingsBatch(ctx, invalid, time.Time{}); err != nil || got != nil {
		t.Fatalf("FindLifecycleFindingsBatch(invalid packages) = (%+v, %v), want nil nil", got, err)
	}

	if _, err := store.db.ExecContext(ctx, `
		INSERT INTO lifecycle_releases_local
			(id, ecosystem, name, product_slug, product_label, cycle, latest, eol_from)
		VALUES
			('f224-zero-now', 'npm', 'f224-zero-now', 'f224-zero-now', 'F224 Zero Now', '1', '1.2.3', '2000-01-01')`); err != nil {
		t.Fatalf("seed zero-now lifecycle row: %v", err)
	}
	query := []db.PackageQuery{{Ecosystem: " npm ", Name: " f224-zero-now ", Version: " 1.2.0 "}}
	beforeEOL, err := store.FindLifecycleFindingsBatch(ctx, query, time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || len(beforeEOL) != 0 {
		t.Fatalf("FindLifecycleFindingsBatch(before EOL) = (%+v, %v), want no finding", beforeEOL, err)
	}
	withDefaultNow, err := store.FindLifecycleFindingsBatch(ctx, query, time.Time{})
	if err != nil || len(withDefaultNow) != 1 || withDefaultNow[0].RiskType != "eol" ||
		withDefaultNow[0].Ecosystem != "npm" || withDefaultNow[0].Name != "f224-zero-now" || withDefaultNow[0].Version != "1.2.0" {
		t.Fatalf("FindLifecycleFindingsBatch(zero now) = (%+v, %v), want normalized EOL finding", withDefaultNow, err)
	}
}

func TestF224FindLifecycleFindingsBatchFailuresReturnNoPartialResults(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	t.Run("query", func(t *testing.T) {
		database, rule := openFaultyDB(t, "FROM lifecycle_releases_local AS l", 0)
		f224CreateSQLiteSchema(t, database)
		store := &Store{db: database}

		got, err := store.FindLifecycleFindingsBatch(context.Background(), []db.PackageQuery{{Ecosystem: "npm", Name: "query-fault", Version: "1.0.0"}}, now)
		if got != nil || err == nil || !errors.Is(err, errInjectedFault) || !strings.Contains(err.Error(), "sqlite: query lifecycle releases batch") {
			t.Fatalf("FindLifecycleFindingsBatch(query fault) = (%+v, %v), want nil wrapped query error", got, err)
		}
		if !rule.didFire() {
			t.Fatal("lifecycle query fault did not fire")
		}
	})

	t.Run("scan after a valid row", func(t *testing.T) {
		store := newSQLiteTestStore(t)
		ctx := context.Background()
		if _, err := store.db.ExecContext(ctx, `
			INSERT INTO lifecycle_releases_local
				(id, ecosystem, name, product_slug, product_label, cycle, latest, is_eol, is_lts)
			VALUES
				('f224-scan-good', 'npm', 'scan-fault', 'a-product', 'Good', '1', '1.0.0', 1, 0),
				('f224-scan-bad', 'npm', 'scan-fault', 'b-product', 'Bad', '1', '1.0.0', 1, 'not-an-integer')`); err != nil {
			t.Fatalf("seed lifecycle scan rows: %v", err)
		}

		got, err := store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "scan-fault", Version: "1.0.0"}}, now)
		if got != nil || err == nil || !strings.Contains(err.Error(), "sqlite: scan lifecycle release batch row") {
			t.Fatalf("FindLifecycleFindingsBatch(scan fault) = (%+v, %v), want nil scan error", got, err)
		}
	})

	t.Run("iteration after a valid row", func(t *testing.T) {
		database, fired := f224OpenIterationFaultDB(t)
		f224CreateSQLiteSchema(t, database)
		if _, err := database.Exec(`
			INSERT INTO lifecycle_releases_local
				(id, ecosystem, name, product_slug, product_label, cycle, latest, is_eol)
			VALUES
				('f224-iterate-first', 'npm', 'iterate-fault', 'a-product', 'First', '1', '1.0.0', 1),
				('f224-iterate-second', 'npm', 'iterate-fault', 'b-product', 'Second', '1', '1.0.0', 1)`); err != nil {
			t.Fatalf("seed lifecycle iteration rows: %v", err)
		}
		store := &Store{db: database}

		got, err := store.FindLifecycleFindingsBatch(context.Background(), []db.PackageQuery{{Ecosystem: "npm", Name: "iterate-fault", Version: "1.0.0"}}, now)
		if got != nil || err == nil || !errors.Is(err, errInjectedFault) || !strings.Contains(err.Error(), "sqlite: iterate lifecycle release batch rows") {
			t.Fatalf("FindLifecycleFindingsBatch(iteration fault) = (%+v, %v), want nil wrapped iteration error", got, err)
		}
		if !fired.Load() {
			t.Fatal("lifecycle iteration fault did not fire")
		}
	})
}

func TestF224FindLifecycleFindingsBatchMultiChunkErrorNamesFailingChunk(t *testing.T) {
	database, rule := openFaultyDB(t, "FROM lifecycle_releases_local AS l", 1)
	f224CreateSQLiteSchema(t, database)
	if _, err := database.Exec(`
		INSERT INTO lifecycle_releases_local
			(id, ecosystem, name, product_slug, product_label, cycle, latest, is_eol)
		VALUES ('f224-first-chunk', 'npm', 'pkg-000', 'f224-product', 'F224', '1', '1.0.0', 1)`); err != nil {
		t.Fatalf("seed first lifecycle chunk: %v", err)
	}
	store := &Store{db: database}
	packages := make([]db.PackageQuery, 401)
	for i := range packages {
		packages[i] = db.PackageQuery{Ecosystem: "npm", Name: fmt.Sprintf("pkg-%03d", i), Version: "1.0.0"}
	}

	got, err := store.FindLifecycleFindingsBatch(context.Background(), packages, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if got != nil || err == nil || !errors.Is(err, errInjectedFault) || !strings.Contains(err.Error(), "lifecycle releases for npm/pkg-400") {
		t.Fatalf("FindLifecycleFindingsBatch(second chunk fault) = (%+v, %v), want nil error naming pkg-400", got, err)
	}
	if !rule.didFire() {
		t.Fatal("second lifecycle chunk fault did not fire")
	}
}

func f224CreateSQLiteSchema(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(schemaSQL); err != nil {
		t.Fatalf("create SQLite schema: %v", err)
	}
}

type f224IterationFaultDriver struct {
	inner driver.Driver
	fired *atomic.Bool
}

func (d *f224IterationFaultDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &f224IterationFaultConn{Conn: conn, fired: d.fired}, nil
}

type f224IterationFaultConn struct {
	driver.Conn
	fired *atomic.Bool
}

func (c *f224IterationFaultConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return execer.ExecContext(ctx, query, args)
}

func (c *f224IterationFaultConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	rows, err := queryer.QueryContext(ctx, query, args)
	if err != nil || !strings.Contains(strings.ToUpper(query), "FROM LIFECYCLE_RELEASES_LOCAL AS L") {
		return rows, err
	}
	return &f224IterationFaultRows{Rows: rows, fired: c.fired}, nil
}

type f224IterationFaultRows struct {
	driver.Rows
	fired    *atomic.Bool
	returned bool
}

func (r *f224IterationFaultRows) Next(dest []driver.Value) error {
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

var f224IterationFaultDriverSequence atomic.Uint64

func f224OpenIterationFaultDB(t *testing.T) (*sql.DB, *atomic.Bool) {
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
	driverName := fmt.Sprintf("sqlite-f224-iteration-%d", f224IterationFaultDriverSequence.Add(1))
	sql.Register(driverName, &f224IterationFaultDriver{inner: inner, fired: fired})
	database, err := sql.Open(driverName, filepath.Join(t.TempDir(), "iteration.db"))
	if err != nil {
		t.Fatalf("open lifecycle iteration-fault database: %v", err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	return database, fired
}

var (
	_ driver.ExecerContext  = (*f224IterationFaultConn)(nil)
	_ driver.QueryerContext = (*f224IterationFaultConn)(nil)
	_ driver.Rows           = (*f224IterationFaultRows)(nil)
)
