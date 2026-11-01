//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/synccontract"
)

// testSyncAffectedCompleteOnlyOnSinglePageDeltas pins where the export offers
// vulnerability_affected_complete: on a delta that fits in one page, never on
// a full export and never on any page of a paginated delta.
func testSyncAffectedCompleteOnlyOnSinglePageDeltas(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	since := syncDeltaBoundary(ctx, t, store)
	now := time.Now().UTC()
	for _, name := range []string{"flag-page-a", "flag-page-b"} {
		if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
			ID: "GHSA-flag-" + name, Summary: "flag fixture", Severity: "HIGH", Published: now, Modified: now,
			Sources: []db.VulnerabilitySource{{Source: "ghsa", SourceID: "GHSA-flag-" + name}},
			AffectedPackages: []db.AffectedPackage{{
				Ecosystem: "npm", Name: name, VersionRanges: []byte(`[]`), VersionsAffected: []byte(`[]`),
			}},
		}); err != nil {
			t.Fatalf("UpsertVulnerability(%s) error = %v", name, err)
		}
	}

	full, err := store.ExportSync(ctx, db.SyncExportOptions{})
	if err != nil {
		t.Fatalf("ExportSync(full) error = %v", err)
	}
	if full.VulnerabilityAffectedComplete {
		t.Fatal("ExportSync(full).VulnerabilityAffectedComplete = true, want false")
	}
	single, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &since})
	if err != nil {
		t.Fatalf("ExportSync(single-page delta) error = %v", err)
	}
	if single.Truncated || !single.VulnerabilityAffectedComplete {
		t.Fatalf("ExportSync(single-page delta) truncated=%v complete=%v, want an untruncated complete page", single.Truncated, single.VulnerabilityAffectedComplete)
	}

	opts := db.SyncExportOptions{Since: &since, Limit: 1}
	for pages := 1; ; pages++ {
		page, err := store.ExportSync(ctx, opts)
		if err != nil {
			t.Fatalf("ExportSync(paginated delta page %d) error = %v", pages, err)
		}
		if page.VulnerabilityAffectedComplete {
			t.Fatalf("ExportSync(paginated delta page %d).VulnerabilityAffectedComplete = true, want false", pages)
		}
		if !page.Truncated {
			if pages < 2 {
				t.Fatalf("paginated delta finished after %d page, want at least 2", pages)
			}
			break
		}
		opts.SnapshotAt, opts.SnapshotXID, opts.Cursor = page.SyncedAt, page.SyncedXID, *page.NextCursor
	}
}

// newLoopbackSyncServer serves GET /api/v1/sync from the PostgreSQL store with
// one row per dataset and page, so every delta with more than one row is
// split. beforePage runs before the export of each page (1-based).
func newLoopbackSyncServer(t *testing.T, store *Store, beforePage func(page int)) *httptest.Server {
	t.Helper()
	var pages atomic.Int32
	parseTime := func(raw string) time.Time {
		if raw == "" {
			return time.Time{}
		}
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			t.Errorf("parse sync time %q: %v", raw, err)
		}
		return parsed
	}
	parseUint := func(raw string) uint64 {
		if raw == "" {
			return 0
		}
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			t.Errorf("parse sync xid %q: %v", raw, err)
		}
		return parsed
	}
	parseInt := func(raw string) int {
		parsed, _ := strconv.Atoi(raw)
		return parsed
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		beforePage(int(pages.Add(1)))
		opts := db.SyncExportOptions{
			SinceXID:    parseUint(q.Get("since_xid")),
			SnapshotAt:  parseTime(q.Get("snapshot")),
			SnapshotXID: parseUint(q.Get("snapshot_xid")),
			Limit:       1,
			Cursor: db.SyncCursor{
				Vulnerabilities:       parseInt(q.Get("vulnerabilities_offset")),
				Malicious:             parseInt(q.Get("malicious_offset")),
				Reputation:            parseInt(q.Get("reputation_offset")),
				Lifecycle:             parseInt(q.Get("lifecycle_offset")),
				VulnerabilitiesCursor: q.Get("vulnerabilities_cursor"),
				MaliciousCursor:       q.Get("malicious_cursor"),
				ReputationCursor:      q.Get("reputation_cursor"),
				LifecycleCursor:       q.Get("lifecycle_cursor"),
				VulnerabilitiesDone:   q.Get("vulnerabilities_done") == "true",
				MaliciousDone:         q.Get("malicious_done") == "true",
				ReputationDone:        q.Get("reputation_done") == "true",
				LifecycleDone:         q.Get("lifecycle_done") == "true",
			},
		}
		if since := parseTime(q.Get("since")); !since.IsZero() {
			opts.Since = &since
		}
		exported, err := store.ExportSync(r.Context(), opts)
		if err != nil {
			t.Errorf("ExportSync() error = %v", err)
			http.Error(w, "export failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(synccontract.ResponseFromExport(exported, "healthy", nil)); err != nil {
			t.Errorf("encode sync page: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// testSplitDeltaKeepsRowsOfVulnerabilityChangedBetweenPages runs the real
// SQLite client against real PostgreSQL exports. The delta for an advisory with
// two affected packages is split over two pages, and the advisory changes
// again between them, so the second page (a separate statement) no longer
// selects it. No local row of the advisory may be deleted: both packages are
// still affected on the server.
func testSplitDeltaKeepsRowsOfVulnerabilityChangedBetweenPages(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const id = "GHSA-split-delta-change"
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified)
		VALUES ('GHSA-split-delta-change', 'split delta', 'HIGH', NOW(), NOW());
		INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected)
		VALUES
			('GHSA-split-delta-change', 'npm', 'split-delta-a', '[]'::jsonb, '[]'::jsonb),
			('GHSA-split-delta-change', 'npm', 'split-delta-b', '[]'::jsonb, '[]'::jsonb);
	`); err != nil {
		t.Fatalf("insert split delta fixture: %v", err)
	}
	since := syncDeltaBoundary(ctx, t, store)
	if _, err := store.pool.Exec(ctx, `UPDATE vulnerabilities SET summary = 'split delta changed', updated_at = NOW() WHERE id = $1`, id); err != nil {
		t.Fatalf("change advisory before the delta: %v", err)
	}

	local, err := sqlite.New(filepath.Join(t.TempDir(), "packmon.db"))
	if err != nil {
		t.Fatalf("sqlite.New() error = %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(local) })
	if _, err := local.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, versions_affected, severity)
		VALUES
			('GHSA-split-delta-change|npm|split-delta-a', 'GHSA-split-delta-change', 'npm', 'split-delta-a', '[]', '[]', 'HIGH'),
			('GHSA-split-delta-change|npm|split-delta-b', 'GHSA-split-delta-change', 'npm', 'split-delta-b', '[]', '[]', 'HIGH')`); err != nil {
		t.Fatalf("seed local rows: %v", err)
	}
	if err := local.SetSyncMeta(ctx, "last_sync_at", since.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed local last sync: %v", err)
	}

	server := newLoopbackSyncServer(t, store, func(page int) {
		if page != 2 {
			return
		}
		if _, err := store.pool.Exec(ctx, `
			UPDATE vulnerabilities SET summary = 'split delta changed again', updated_at = NOW() WHERE id = 'GHSA-split-delta-change';
			UPDATE affected_packages SET updated_at = NOW() WHERE vulnerability_id = 'GHSA-split-delta-change';
		`); err != nil {
			t.Errorf("change advisory between pages: %v", err)
		}
	})
	if err := sqlite.Sync(ctx, local, sqlite.SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("sqlite.Sync(split delta) error = %v", err)
	}

	rows, err := local.DB().QueryContext(ctx, `SELECT name FROM vulnerabilities_local WHERE id = ? ORDER BY name`, id)
	if err != nil {
		t.Fatalf("query local rows: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan local row: %v", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate local rows: %v", err)
	}
	if want := []string{"split-delta-a", "split-delta-b"}; !slices.Equal(names, want) {
		t.Fatalf("local affected packages of %s after split delta = %q, want %q (no still-affected row deleted)", id, names, want)
	}
}

// syncDeltaBoundary returns a database timestamp after every committed write
// so far, usable as the since bound of the next delta export.
func syncDeltaBoundary(ctx context.Context, t *testing.T, store *Store) time.Time {
	t.Helper()
	var boundary time.Time
	if err := store.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&boundary); err != nil {
		t.Fatalf("read delta boundary: %v", err)
	}
	return boundary.UTC()
}

// deltaAffectedPackages exports a delta since the boundary and returns the
// ecosystem/name pairs it sends for one vulnerability.
func deltaAffectedPackages(ctx context.Context, t *testing.T, store *Store, since time.Time, id string) []string {
	t.Helper()
	exported, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &since})
	if err != nil {
		t.Fatalf("ExportSync(delta) error = %v", err)
	}
	if !exported.VulnerabilityAffectedComplete {
		t.Fatal("ExportSync(delta).VulnerabilityAffectedComplete = false, want the complete-affected-set guarantee")
	}
	var packages []string
	for _, row := range exported.Vulnerabilities {
		if row.ID == id {
			packages = append(packages, row.Ecosystem+"/"+row.Name)
		}
	}
	slices.Sort(packages)
	return packages
}

// testManualEditDeltaSendsCompleteAffectedSet moves a manual advisory from one
// package to another. The next delta must include the advisory with exactly
// its current package, so a client replacing the advisory's local affected
// rows drops the old package.
func testManualEditDeltaSendsCompleteAffectedSet(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const id = "manual:delta-coverage-move"
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID: id, FindingType: "vulnerability", Ecosystem: "npm", Name: "delta-move-a",
		Severity: "HIGH", Summary: "coverage move",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(create) error = %v", err)
	}
	current, err := store.GetManualAdvisory(ctx, id)
	if err != nil || current == nil {
		t.Fatalf("GetManualAdvisory(create) = %+v, %v; want advisory", current, err)
	}
	since := syncDeltaBoundary(ctx, t, store)

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID: id, FindingType: "vulnerability", Ecosystem: "npm", Name: "delta-move-b",
		Severity: "HIGH", Summary: "coverage move", UpdatedAt: current.UpdatedAt,
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(edit) error = %v", err)
	}

	if got, want := deltaAffectedPackages(ctx, t, store, since, id), []string{"npm/delta-move-b"}; !slices.Equal(got, want) {
		t.Fatalf("delta affected packages for %s = %q, want %q", id, got, want)
	}
}

// testPackageNameRepairDeltaIncludesMergedVulnerability seeds an advisory
// whose legacy non-canonical row duplicates its canonical row. The repair only
// deletes the legacy row, so it must still mark the advisory changed: otherwise
// no delta would ever send it again and clients would keep the legacy row.
func testPackageNameRepairDeltaIncludesMergedVulnerability(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const id = "GHSA-name-repair-delta"
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified)
		VALUES ('GHSA-name-repair-delta', 'repair delta', 'HIGH', NOW(), NOW());
		INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected)
		VALUES
			('GHSA-name-repair-delta', 'actions', 'Repair-Delta/Action', '[]'::jsonb, '["1.0.0"]'::jsonb),
			('GHSA-name-repair-delta', 'actions', 'repair-delta/action', '[]'::jsonb, '["1.0.0"]'::jsonb);
	`); err != nil {
		t.Fatalf("insert legacy duplicate rows: %v", err)
	}
	since := syncDeltaBoundary(ctx, t, store)

	if _, err := store.RepairCaseInsensitivePackageNames(ctx); err != nil {
		t.Fatalf("RepairCaseInsensitivePackageNames() error = %v", err)
	}

	if got, want := deltaAffectedPackages(ctx, t, store, since, id), []string{"actions/repair-delta/action"}; !slices.Equal(got, want) {
		t.Fatalf("delta affected packages for %s = %q, want %q", id, got, want)
	}
}
