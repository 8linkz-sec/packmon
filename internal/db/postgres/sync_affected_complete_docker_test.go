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

// insertSyncPagingAdvisory inserts one vulnerability with the given npm
// affected packages through plain SQL, so updated_at is the statement time.
func insertSyncPagingAdvisory(ctx context.Context, t *testing.T, store *Store, id string, names ...string) {
	t.Helper()
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified)
		VALUES ($1, 'paging fixture', 'HIGH', NOW(), NOW())`, id); err != nil {
		t.Fatalf("insert vulnerability %s: %v", id, err)
	}
	for _, name := range names {
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected)
			VALUES ($1, 'npm', $2, '[]'::jsonb, '[]'::jsonb)`, id, name); err != nil {
			t.Fatalf("insert affected package %s/%s: %v", id, name, err)
		}
	}
}

// syncExportRowsByID groups exported vulnerability rows by advisory ID.
func syncExportRowsByID(rows []db.SyncVulnerability) map[string][]string {
	out := make(map[string][]string)
	for _, row := range rows {
		out[row.ID] = append(out[row.ID], row.Name)
	}
	for id := range out {
		slices.Sort(out[id])
	}
	return out
}

// testSyncAffectedCompleteOnDeltaPages pins where the export offers
// vulnerability_affected_complete: on every page of a delta paged by whole
// advisories, never on a full export and never on the legacy row-cursor or
// offset pages of a delta.
func testSyncAffectedCompleteOnDeltaPages(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	since := syncDeltaBoundary(ctx, t, store)
	insertSyncPagingAdvisory(ctx, t, store, "GHSA-flag-page-a", "flag-page-a")
	insertSyncPagingAdvisory(ctx, t, store, "GHSA-flag-page-b", "flag-page-b")

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
		if !page.VulnerabilityAffectedComplete {
			t.Fatalf("ExportSync(paginated delta page %d).VulnerabilityAffectedComplete = false, want every advisory page flagged", pages)
		}
		if !page.Truncated {
			if pages < 2 {
				t.Fatalf("paginated delta finished after %d page, want at least 2", pages)
			}
			break
		}
		opts.SnapshotAt, opts.SnapshotXID, opts.Cursor = page.SyncedAt, page.SyncedXID, *page.NextCursor
	}

	for name, legacy := range map[string]db.SyncExportOptions{
		"legacy row cursor": {Since: &since, Limit: 1, Cursor: db.SyncCursor{VulnerabilitiesCursor: encodeSyncCursorKey("", "", "")}},
		"legacy offset":     {Since: &since, Limit: 1, Offset: 1},
	} {
		page, err := store.ExportSync(ctx, legacy)
		if err != nil {
			t.Fatalf("ExportSync(%s delta page) error = %v", name, err)
		}
		if page.VulnerabilityAffectedComplete {
			t.Fatalf("ExportSync(%s delta page).VulnerabilityAffectedComplete = true, want false", name)
		}
	}
}

// testDeltaPagesKeepEachAdvisoryWhole pages a delta whose first advisory has
// more affected rows than the page limit. That advisory is a page of its own
// instead of being split, the next page continues after it with an advisory
// cursor and fills up to the limit, and no advisory appears on two pages. A
// delta continuing a legacy row cursor (an older server started the sequence)
// and a legacy offset delta still deliver every row, unflagged.
func testDeltaPagesKeepEachAdvisoryWhole(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	since := syncDeltaBoundary(ctx, t, store)
	insertSyncPagingAdvisory(ctx, t, store, "GHSA-whole-page-a", "whole-a1", "whole-a2", "whole-a3")
	insertSyncPagingAdvisory(ctx, t, store, "GHSA-whole-page-b", "whole-b1")
	insertSyncPagingAdvisory(ctx, t, store, "GHSA-whole-page-c", "whole-c1")
	want := map[string][]string{
		"GHSA-whole-page-a": {"whole-a1", "whole-a2", "whole-a3"},
		"GHSA-whole-page-b": {"whole-b1"},
		"GHSA-whole-page-c": {"whole-c1"},
	}

	first, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &since, Limit: 2})
	if err != nil {
		t.Fatalf("ExportSync(first page) error = %v", err)
	}
	if got := syncExportRowsByID(first.Vulnerabilities); len(got) != 1 || !slices.Equal(got["GHSA-whole-page-a"], want["GHSA-whole-page-a"]) {
		t.Fatalf("first page = %v, want only GHSA-whole-page-a with all three rows", got)
	}
	if !first.Truncated || first.NextCursor == nil || !first.VulnerabilityAffectedComplete {
		t.Fatalf("first page truncated=%v cursor=%+v complete=%v, want a flagged page with a next cursor", first.Truncated, first.NextCursor, first.VulnerabilityAffectedComplete)
	}
	if id, ok := db.DecodeSyncAdvisoryCursor(first.NextCursor.VulnerabilitiesCursor); !ok || id != "GHSA-whole-page-a" {
		t.Fatalf("first page vulnerabilities_cursor decodes to %q, %v; want an advisory cursor after GHSA-whole-page-a", id, ok)
	}

	second, err := store.ExportSync(ctx, db.SyncExportOptions{
		Since: &since, Limit: 2, SnapshotAt: first.SyncedAt, SnapshotXID: first.SyncedXID, Cursor: *first.NextCursor,
	})
	if err != nil {
		t.Fatalf("ExportSync(second page) error = %v", err)
	}
	if got := syncExportRowsByID(second.Vulnerabilities); len(got) != 2 ||
		!slices.Equal(got["GHSA-whole-page-b"], want["GHSA-whole-page-b"]) || !slices.Equal(got["GHSA-whole-page-c"], want["GHSA-whole-page-c"]) {
		t.Fatalf("second page = %v, want GHSA-whole-page-b and GHSA-whole-page-c", got)
	}
	if second.Truncated || !second.VulnerabilityAffectedComplete {
		t.Fatalf("second page truncated=%v complete=%v, want the final flagged page", second.Truncated, second.VulnerabilityAffectedComplete)
	}

	// A legacy offset continues in advisory row order: offset 3 starts right
	// after the three rows of the first advisory.
	offsetPage, err := store.ExportSync(ctx, db.SyncExportOptions{
		Since: &since, Limit: 2, SnapshotAt: first.SyncedAt, SnapshotXID: first.SyncedXID, Cursor: db.SyncCursor{Vulnerabilities: 3},
	})
	if err != nil {
		t.Fatalf("ExportSync(legacy offset page) error = %v", err)
	}
	if got := syncExportRowsByID(offsetPage.Vulnerabilities); len(got) != 2 || offsetPage.VulnerabilityAffectedComplete {
		t.Fatalf("legacy offset page = %v complete=%v, want GHSA-whole-page-b and GHSA-whole-page-c unflagged", got, offsetPage.VulnerabilityAffectedComplete)
	}

	// A sequence continuing a legacy row cursor stays on legacy row paging
	// and still delivers every row.
	opts := db.SyncExportOptions{
		Since: &since, Limit: 1, SnapshotAt: first.SyncedAt, SnapshotXID: first.SyncedXID,
		Cursor: db.SyncCursor{VulnerabilitiesCursor: encodeSyncCursorKey("", "", ""), MaliciousDone: true, ReputationDone: true, LifecycleDone: true},
	}
	var legacyRows []db.SyncVulnerability
	for pages := 1; ; pages++ {
		page, err := store.ExportSync(ctx, opts)
		if err != nil {
			t.Fatalf("ExportSync(legacy cursor page %d) error = %v", pages, err)
		}
		if page.VulnerabilityAffectedComplete || len(page.Vulnerabilities) > 1 {
			t.Fatalf("legacy cursor page %d rows=%d complete=%v, want one unflagged row", pages, len(page.Vulnerabilities), page.VulnerabilityAffectedComplete)
		}
		legacyRows = append(legacyRows, page.Vulnerabilities...)
		if !page.Truncated {
			break
		}
		if page.NextCursor.VulnerabilitiesCursor != "" {
			if _, err := decodeSyncCursorKey(page.NextCursor.VulnerabilitiesCursor, 3); err != nil {
				t.Fatalf("legacy cursor page %d next cursor is not a legacy row cursor: %v", pages, err)
			}
		}
		opts.Cursor = *page.NextCursor
	}
	got := syncExportRowsByID(legacyRows)
	for id, names := range want {
		if !slices.Equal(got[id], names) {
			t.Fatalf("legacy cursor sequence delivered %v, want %v", got, want)
		}
	}
}

// newLoopbackSyncServer serves GET /api/v1/sync from the PostgreSQL store with
// limit rows per dataset and page. beforePage runs before the export of each
// page (1-based).
func newLoopbackSyncServer(t *testing.T, store *Store, limit int, beforePage func(page int)) *httptest.Server {
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
			Limit:       limit,
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

// localSyncPagingRows returns the local affected packages of the given
// advisories, keyed by advisory ID.
func localSyncPagingRows(ctx context.Context, t *testing.T, local *sqlite.Store, ids ...string) map[string][]string {
	t.Helper()
	out := make(map[string][]string, len(ids))
	for _, id := range ids {
		rows, err := local.DB().QueryContext(ctx, `SELECT name FROM vulnerabilities_local WHERE id = ? ORDER BY name`, id)
		if err != nil {
			t.Fatalf("query local rows of %s: %v", id, err)
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				ioutils.CloseSilently(rows)
				t.Fatalf("scan local row of %s: %v", id, err)
			}
			out[id] = append(out[id], name)
		}
		if err := rows.Err(); err != nil {
			ioutils.CloseSilently(rows)
			t.Fatalf("iterate local rows of %s: %v", id, err)
		}
		ioutils.CloseSilently(rows)
	}
	return out
}

// testMultiPageDeltaReplacesWholeAdvisoriesChangedBetweenPages runs the real
// SQLite client against real PostgreSQL exports of a delta that spans two
// pages. Each flagged page replaces the local affected rows of its advisories.
// Between the pages the server changes every advisory again: the advisory the
// first page already delivered keeps the state that page saw, an advisory
// whose vulnerability row changed after the snapshot is excluded whole from
// the second page and keeps every local row, and an advisory whose affected
// rows alone changed is delivered whole with its current set. No local row
// that is still affected on the server is deleted, and the next delta
// converges every advisory to the server state.
func testMultiPageDeltaReplacesWholeAdvisoriesChangedBetweenPages(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const (
		idA = "GHSA-page-change-a"
		idB = "GHSA-page-change-b"
		idC = "GHSA-page-change-c"
	)
	insertSyncPagingAdvisory(ctx, t, store, idA, "a1", "a2", "a3", "a-old")
	insertSyncPagingAdvisory(ctx, t, store, idB, "b1", "b-old")
	insertSyncPagingAdvisory(ctx, t, store, idC, "c1", "c-old")

	local, err := sqlite.New(filepath.Join(t.TempDir(), "packmon.db"))
	if err != nil {
		t.Fatalf("sqlite.New() error = %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(local) })
	for id, names := range map[string][]string{idA: {"a1", "a2", "a3", "a-old"}, idB: {"b1", "b-old"}, idC: {"c1", "c-old"}} {
		for _, name := range names {
			if _, err := local.DB().ExecContext(ctx, `
				INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, versions_affected, severity)
				VALUES (?, ?, 'npm', ?, '[]', '[]', 'HIGH')`, id+"|npm|"+name, id, name); err != nil {
				t.Fatalf("seed local row %s/%s: %v", id, name, err)
			}
		}
	}
	since := syncDeltaBoundary(ctx, t, store)
	if err := local.SetSyncMeta(ctx, "last_sync_at", since.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed local last sync: %v", err)
	}

	// The delta: every advisory drops its old package.
	for _, stmt := range []string{
		`DELETE FROM affected_packages WHERE vulnerability_id = ANY($1) AND name LIKE '%-old'`,
		`UPDATE vulnerabilities SET updated_at = NOW() WHERE id = ANY($1)`,
	} {
		if _, err := store.pool.Exec(ctx, stmt, []string{idA, idB, idC}); err != nil {
			t.Fatalf("drop old packages before the delta: %v", err)
		}
	}

	// Three rows per page: the first page holds only A (three rows), the
	// second B and C.
	server := newLoopbackSyncServer(t, store, 3, func(page int) {
		if page != 2 {
			return
		}
		for _, stmt := range []string{
			`DELETE FROM affected_packages WHERE vulnerability_id = 'GHSA-page-change-a' AND name = 'a3'`,
			`INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected) VALUES ('GHSA-page-change-a', 'npm', 'a4', '[]'::jsonb, '[]'::jsonb)`,
			`UPDATE vulnerabilities SET updated_at = NOW() WHERE id = 'GHSA-page-change-a'`,
			`INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected) VALUES ('GHSA-page-change-b', 'npm', 'b2', '[]'::jsonb, '[]'::jsonb)`,
			`UPDATE vulnerabilities SET updated_at = NOW() WHERE id = 'GHSA-page-change-b'`,
			`INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected) VALUES ('GHSA-page-change-c', 'npm', 'c2', '[]'::jsonb, '[]'::jsonb)`,
		} {
			if _, err := store.pool.Exec(ctx, stmt); err != nil {
				t.Errorf("change advisories between pages: %v", err)
			}
		}
	})
	syncConfig := sqlite.SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true}
	if err := sqlite.Sync(ctx, local, syncConfig); err != nil {
		t.Fatalf("sqlite.Sync(multi-page delta) error = %v", err)
	}
	afterFirst := localSyncPagingRows(ctx, t, local, idA, idB, idC)
	for id, want := range map[string][]string{
		idA: {"a1", "a2", "a3"}, // the state page 1 delivered; a-old dropped
		idB: {"b-old", "b1"},    // excluded whole from page 2; nothing dropped
		idC: {"c1", "c2"},       // delivered whole on page 2; c-old dropped
	} {
		if !slices.Equal(afterFirst[id], want) {
			t.Fatalf("local affected packages of %s after the multi-page delta = %q, want %q (all local rows: %v)", id, afterFirst[id], want, afterFirst)
		}
	}

	if err := sqlite.Sync(ctx, local, syncConfig); err != nil {
		t.Fatalf("sqlite.Sync(next delta) error = %v", err)
	}
	afterNext := localSyncPagingRows(ctx, t, local, idA, idB, idC)
	for id, want := range map[string][]string{
		idA: {"a1", "a2", "a4"},
		idB: {"b1", "b2"},
		idC: {"c1", "c2"},
	} {
		if !slices.Equal(afterNext[id], want) {
			t.Fatalf("local affected packages of %s after the next delta = %q, want %q (all local rows: %v)", id, afterNext[id], want, afterNext)
		}
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
