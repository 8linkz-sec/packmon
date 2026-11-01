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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/domain"
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
		if raw := q.Get("ecosystem"); raw != "" {
			opts.Ecosystems = strings.Split(raw, ",")
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

// seedLocalSyncRows stores npm-style local affected rows of one advisory in
// the given ecosystem, matching what an earlier sync would have written.
func seedLocalSyncRows(ctx context.Context, t *testing.T, local *sqlite.Store, id, ecosystem string, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := local.DB().ExecContext(ctx, `
			INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, versions_affected, severity)
			VALUES (?, ?, ?, ?, '[]', '[]', 'HIGH')`, id+"|"+ecosystem+"|"+name, id, ecosystem, name); err != nil {
			t.Fatalf("seed local row %s/%s/%s: %v", id, ecosystem, name, err)
		}
	}
}

// localAndRemoteAdvisories returns the advisories among ids that a remote
// check (the PostgreSQL lookup behind /api/v1/check) and a local scan (the
// synced SQLite lookup) report for one package version.
func localAndRemoteAdvisories(ctx context.Context, t *testing.T, store *Store, local *sqlite.Store, ecosystem, name string, ids ...string) (remote, localIDs []string) {
	t.Helper()
	pick := func(findings []domain.Finding) []string {
		var out []string
		for _, finding := range findings {
			if slices.Contains(ids, finding.AdvisoryID) && !slices.Contains(out, finding.AdvisoryID) {
				out = append(out, finding.AdvisoryID)
			}
		}
		slices.Sort(out)
		return out
	}
	remoteFindings, err := store.FindVulnerabilities(ctx, ecosystem, name, "1.0.0")
	if err != nil {
		t.Fatalf("remote FindVulnerabilities(%s/%s) error = %v", ecosystem, name, err)
	}
	localFindings, err := local.FindVulnerabilities(ctx, ecosystem, name, "1.0.0")
	if err != nil {
		t.Fatalf("local FindVulnerabilities(%s/%s) error = %v", ecosystem, name, err)
	}
	return pick(remoteFindings), pick(localFindings)
}

// testDeltaDeliversAdvisoriesWithoutAffectedPackages covers advisories that
// lose every affected package on the server (within the requested
// ecosystems): one loses all of its packages, one moves from npm to pypi. Such
// an advisory has no row to deliver, so a flagged delta page lists it in
// VulnerabilitiesWithoutAffected -- also when it is the only advisory on a
// page -- and the real SQLite client drops its local rows in the requested
// ecosystems. Afterwards a local scan reports exactly what a remote check
// reports, and a filtered sync keeps rows of other ecosystems.
func testDeltaDeliversAdvisoriesWithoutAffectedPackages(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const (
		idGone  = "GHSA-no-affected-gone"
		idMoved = "GHSA-no-affected-moved"
		idKept  = "GHSA-no-affected-kept"
	)
	insertSyncPagingAdvisory(ctx, t, store, idGone, "gone-a", "gone-b")
	insertSyncPagingAdvisory(ctx, t, store, idMoved, "moved-a")
	insertSyncPagingAdvisory(ctx, t, store, idKept, "kept-a")

	newLocal := func(withOtherEcosystem bool) *sqlite.Store {
		local, err := sqlite.New(filepath.Join(t.TempDir(), "packmon.db"))
		if err != nil {
			t.Fatalf("sqlite.New() error = %v", err)
		}
		t.Cleanup(func() { ioutils.CloseSilently(local) })
		seedLocalSyncRows(ctx, t, local, idGone, "npm", "gone-a", "gone-b")
		seedLocalSyncRows(ctx, t, local, idMoved, "npm", "moved-a")
		seedLocalSyncRows(ctx, t, local, idKept, "npm", "kept-a")
		if withOtherEcosystem {
			seedLocalSyncRows(ctx, t, local, idGone, "pypi", "gone-py")
		}
		return local
	}
	unfiltered, filtered := newLocal(false), newLocal(true)
	since := syncDeltaBoundary(ctx, t, store)
	for _, local := range []*sqlite.Store{unfiltered, filtered} {
		if err := local.SetSyncMeta(ctx, "last_sync_at", since.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("seed local last sync: %v", err)
		}
	}

	for _, stmt := range []string{
		`DELETE FROM affected_packages WHERE vulnerability_id = 'GHSA-no-affected-gone'`,
		`DELETE FROM affected_packages WHERE vulnerability_id = 'GHSA-no-affected-moved'`,
		`INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected) VALUES ('GHSA-no-affected-moved', 'pypi', 'moved-a', '[]'::jsonb, '[]'::jsonb)`,
		`UPDATE vulnerabilities SET updated_at = NOW() WHERE id IN ('GHSA-no-affected-gone', 'GHSA-no-affected-moved')`,
	} {
		if _, err := store.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("drop affected packages before the delta: %v", err)
		}
	}

	unfilteredExport, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &since})
	if err != nil {
		t.Fatalf("ExportSync(unfiltered delta) error = %v", err)
	}
	if !unfilteredExport.VulnerabilityAffectedComplete || !slices.Equal(unfilteredExport.VulnerabilitiesWithoutAffected, []string{idGone}) {
		t.Fatalf("unfiltered delta complete=%v without-affected=%q, want a flagged page listing only %s", unfilteredExport.VulnerabilityAffectedComplete, unfilteredExport.VulnerabilitiesWithoutAffected, idGone)
	}
	if got := syncExportRowsByID(unfilteredExport.Vulnerabilities); len(got) != 1 || !slices.Equal(got[idMoved], []string{"moved-a"}) {
		t.Fatalf("unfiltered delta rows = %v, want only the pypi row of %s", got, idMoved)
	}

	// One advisory per page: each page holds only a marker and still
	// continues after it.
	opts := db.SyncExportOptions{Since: &since, Ecosystems: []string{"npm"}, Limit: 1}
	var listed []string
	for pages := 1; ; pages++ {
		page, err := store.ExportSync(ctx, opts)
		if err != nil {
			t.Fatalf("ExportSync(filtered delta page %d) error = %v", pages, err)
		}
		if len(page.Vulnerabilities) != 0 || !page.VulnerabilityAffectedComplete {
			t.Fatalf("filtered delta page %d rows=%d complete=%v, want a flagged page without npm rows", pages, len(page.Vulnerabilities), page.VulnerabilityAffectedComplete)
		}
		listed = append(listed, page.VulnerabilitiesWithoutAffected...)
		if !page.Truncated {
			break
		}
		if pages > 3 {
			t.Fatalf("filtered delta did not finish after %d pages", pages)
		}
		opts.SnapshotAt, opts.SnapshotXID, opts.Cursor = page.SyncedAt, page.SyncedXID, *page.NextCursor
	}
	if !slices.Equal(listed, []string{idGone, idMoved}) {
		t.Fatalf("filtered delta listed %q without affected npm packages, want %s and %s", listed, idGone, idMoved)
	}

	server := newLoopbackSyncServer(t, store, 1, func(int) {})
	if err := sqlite.Sync(ctx, unfiltered, sqlite.SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("sqlite.Sync(unfiltered delta) error = %v", err)
	}
	if err := sqlite.Sync(ctx, filtered, sqlite.SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true, Ecosystems: []string{"npm"}}); err != nil {
		t.Fatalf("sqlite.Sync(filtered delta) error = %v", err)
	}

	ids := []string{idGone, idMoved, idKept}
	for _, pkg := range []struct{ ecosystem, name string }{
		{"npm", "gone-a"}, {"npm", "gone-b"}, {"npm", "moved-a"}, {"pypi", "moved-a"}, {"npm", "kept-a"},
	} {
		remote, local := localAndRemoteAdvisories(ctx, t, store, unfiltered, pkg.ecosystem, pkg.name, ids...)
		if !slices.Equal(local, remote) {
			t.Fatalf("%s/%s after the delta: local scan reports %q, remote check reports %q", pkg.ecosystem, pkg.name, local, remote)
		}
	}
	if got := localSyncPagingRows(ctx, t, filtered, idGone, idMoved, idKept); len(got) != 2 ||
		!slices.Equal(got[idGone], []string{"gone-py"}) || !slices.Equal(got[idKept], []string{"kept-a"}) {
		t.Fatalf("filtered local rows after the npm delta = %v, want only the pypi row of %s and %s/kept-a", got, idGone, idKept)
	}
}

// testDeltaSplitsAnAdvisoryLargerThanThePageBudget syncs a delta whose middle
// advisory has 12,000 affected packages with a 3,000-byte summary, about 40 MB
// of JSON -- more than the 32 MiB a client accepts in one response. The pages
// stay below that cap: the whole-advisory page before it ends at the advisory
// boundary and stays flagged, the oversized advisory is split over several
// unflagged pages with a row cursor that all name it in
// VulnerabilitySplitAdvisory, the first of them is marked as the start, the
// last of them reports the split complete
// (nothing of the advisory changed after the snapshot), and the advisory
// after it is paged whole and flagged again. The real SQLite client completes
// the sync, every row arrives exactly once, flagged pages drop their stale
// rows, and the completed split drops the stale row of the split advisory.
func testDeltaSplitsAnAdvisoryLargerThanThePageBudget(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const (
		idBefore = "GHSA-budget-a-before"
		idBig    = "GHSA-budget-b-giant"
		idAfter  = "GHSA-budget-c-after"
		bigRows  = 12000
	)
	insertSyncPagingAdvisory(ctx, t, store, idBefore, "budget-a1", "budget-a-stale")
	insertSyncPagingAdvisory(ctx, t, store, idAfter, "budget-c1", "budget-c-stale")
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified)
		VALUES ($1, repeat('x', 3000), 'HIGH', NOW(), NOW())`, idBig); err != nil {
		t.Fatalf("insert oversized vulnerability: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected)
		SELECT $1, 'npm', 'budget-big-' || lpad(g::text, 5, '0'), '[]'::jsonb, '[]'::jsonb
		FROM generate_series(1, $2::int) g
		UNION ALL
		SELECT $1, 'npm', 'budget-big-stale', '[]'::jsonb, '[]'::jsonb`, idBig, bigRows); err != nil {
		t.Fatalf("insert oversized affected packages: %v", err)
	}

	local, err := sqlite.New(filepath.Join(t.TempDir(), "packmon.db"))
	if err != nil {
		t.Fatalf("sqlite.New() error = %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(local) })
	seedLocalSyncRows(ctx, t, local, idBefore, "npm", "budget-a1", "budget-a-stale")
	seedLocalSyncRows(ctx, t, local, idBig, "npm", "budget-big-stale")
	seedLocalSyncRows(ctx, t, local, idAfter, "npm", "budget-c1", "budget-c-stale")
	since := syncDeltaBoundary(ctx, t, store)
	if err := local.SetSyncMeta(ctx, "last_sync_at", since.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed local last sync: %v", err)
	}
	for _, stmt := range []string{
		`DELETE FROM affected_packages WHERE vulnerability_id = ANY($1) AND name LIKE '%-stale'`,
		`UPDATE vulnerabilities SET updated_at = NOW() WHERE id = ANY($1)`,
	} {
		if _, err := store.pool.Exec(ctx, stmt, []string{idBefore, idBig, idAfter}); err != nil {
			t.Fatalf("drop stale packages before the delta: %v", err)
		}
	}

	type pageFacts struct {
		ids           []string
		complete      bool
		splitAdvisory string
		splitStart    bool
		splitComplete bool
	}
	var (
		pages   []pageFacts
		bigSeen = make(map[string]struct{}, bigRows)
	)
	opts := db.SyncExportOptions{Since: &since, Limit: synccontract.MaxLimit}
	for {
		page, err := store.ExportSync(ctx, opts)
		if err != nil {
			t.Fatalf("ExportSync(delta page %d) error = %v", len(pages)+1, err)
		}
		encoded, err := json.Marshal(synccontract.ResponseFromExport(page, "healthy", nil))
		if err != nil {
			t.Fatalf("encode delta page %d: %v", len(pages)+1, err)
		}
		if len(encoded) > synccontract.MaxResponseBytes {
			t.Fatalf("delta page %d encodes to %d bytes, more than the %d-byte client cap", len(pages)+1, len(encoded), synccontract.MaxResponseBytes)
		}
		facts := pageFacts{complete: page.VulnerabilityAffectedComplete, splitAdvisory: page.VulnerabilitySplitAdvisory, splitStart: page.VulnerabilitySplitStart, splitComplete: page.VulnerabilitySplitComplete}
		for id := range syncExportRowsByID(page.Vulnerabilities) {
			facts.ids = append(facts.ids, id)
		}
		slices.Sort(facts.ids)
		for _, row := range page.Vulnerabilities {
			if row.ID != idBig {
				continue
			}
			if _, dup := bigSeen[row.Name]; dup {
				t.Fatalf("delta page %d repeats %s/%s", len(pages)+1, idBig, row.Name)
			}
			bigSeen[row.Name] = struct{}{}
		}
		pages = append(pages, facts)
		if !page.Truncated {
			break
		}
		if len(pages) > 20 {
			t.Fatalf("delta did not finish after %d pages", len(pages))
		}
		opts.SnapshotAt, opts.SnapshotXID, opts.Cursor = page.SyncedAt, page.SyncedXID, *page.NextCursor
	}
	if len(bigSeen) != bigRows {
		t.Fatalf("delta delivered %d rows of %s, want %d", len(bigSeen), idBig, bigRows)
	}
	var splitPages, firstSplitPage, lastSplitPage, startPages, completePages int
	for i, page := range pages {
		if page.splitComplete {
			completePages++
		}
		if page.splitStart {
			startPages++
		}
		switch {
		case slices.Equal(page.ids, []string{idBefore}) || slices.Equal(page.ids, []string{idAfter}):
			if !page.complete || page.splitAdvisory != "" {
				t.Fatalf("delta page %d with %q is unflagged or names split advisory %q, want whole advisories flagged (pages %+v)", i+1, page.ids, page.splitAdvisory, pages)
			}
		case slices.Equal(page.ids, []string{idBig}) || (len(page.ids) == 0 && page.splitAdvisory != ""):
			if page.complete || page.splitAdvisory != idBig {
				t.Fatalf("delta page %d of the split advisory is flagged or names %q (pages %+v)", i+1, page.splitAdvisory, pages)
			}
			if splitPages == 0 {
				firstSplitPage = i
			}
			splitPages++
			lastSplitPage = i
		case len(page.ids) == 0:
		default:
			t.Fatalf("delta page %d mixes advisories %q (pages %+v)", i+1, page.ids, pages)
		}
	}
	if splitPages < 2 {
		t.Fatalf("oversized advisory spans %d page(s), want it split (pages %+v)", splitPages, pages)
	}
	if startPages != 1 || !pages[firstSplitPage].splitStart {
		t.Fatalf("split start on %d page(s), want only the first split page (pages %+v)", startPages, pages)
	}
	if completePages != 1 || !pages[lastSplitPage].splitComplete {
		t.Fatalf("split complete on %d page(s), want only the last split page (pages %+v)", completePages, pages)
	}

	server := newLoopbackSyncServer(t, store, synccontract.MaxLimit, func(int) {})
	if err := sqlite.Sync(ctx, local, sqlite.SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("sqlite.Sync(delta with an oversized advisory) error = %v", err)
	}
	got := localSyncPagingRows(ctx, t, local, idBefore, idBig, idAfter)
	if !slices.Equal(got[idBefore], []string{"budget-a1"}) || !slices.Equal(got[idAfter], []string{"budget-c1"}) {
		t.Fatalf("local rows of the whole advisories = %q / %q, want their stale rows dropped", got[idBefore], got[idAfter])
	}
	if len(got[idBig]) != bigRows || slices.Contains(got[idBig], "budget-big-stale") {
		t.Fatalf("local rows of the split advisory = %d (stale kept %v), want all %d rows and the stale row dropped by the completed split", len(got[idBig]), slices.Contains(got[idBig], "budget-big-stale"), bigRows)
	}
}

// testSplitAdvisoryChangedMidSplitStaysUpsertOnly splits an oversized advisory
// like testDeltaSplitsAnAdvisoryLargerThanThePageBudget, but one of its
// affected rows changes on the server while the client pages through the
// split. The split pages may then have missed a row, so the last split page
// does not report the split complete and the client keeps the advisory's
// stale local row. The change enters the next delta, which splits the
// advisory again without interference, completes it, and drops the stale row.
func testSplitAdvisoryChangedMidSplitStaysUpsertOnly(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const (
		idBig   = "GHSA-midsplit-giant"
		bigRows = 12000
	)
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified)
		VALUES ($1, repeat('x', 3000), 'HIGH', NOW(), NOW())`, idBig); err != nil {
		t.Fatalf("insert oversized vulnerability: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected)
		SELECT $1, 'npm', 'midsplit-big-' || lpad(g::text, 5, '0'), '[]'::jsonb, '[]'::jsonb
		FROM generate_series(1, $2::int) g`, idBig, bigRows); err != nil {
		t.Fatalf("insert oversized affected packages: %v", err)
	}

	local, err := sqlite.New(filepath.Join(t.TempDir(), "packmon.db"))
	if err != nil {
		t.Fatalf("sqlite.New() error = %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(local) })
	seedLocalSyncRows(ctx, t, local, idBig, "npm", "midsplit-big-stale")
	since := syncDeltaBoundary(ctx, t, store)
	if err := local.SetSyncMeta(ctx, "last_sync_at", since.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed local last sync: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE vulnerabilities SET updated_at = NOW() WHERE id = $1`, idBig); err != nil {
		t.Fatalf("mark the oversized advisory changed: %v", err)
	}

	var changeMidSplit atomic.Bool
	changeMidSplit.Store(true)
	server := newLoopbackSyncServer(t, store, synccontract.MaxLimit, func(page int) {
		// Page 1 starts the split; change an affected row before page 2
		// continues it.
		if page == 2 && changeMidSplit.Load() {
			if _, err := store.pool.Exec(ctx, `
				UPDATE affected_packages SET updated_at = NOW()
				WHERE vulnerability_id = $1 AND name = 'midsplit-big-00001'`, idBig); err != nil {
				t.Errorf("change an affected row mid-split: %v", err)
			}
		}
	})
	if err := sqlite.Sync(ctx, local, sqlite.SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("sqlite.Sync(delta changed mid-split) error = %v", err)
	}
	got := localSyncPagingRows(ctx, t, local, idBig)
	if len(got[idBig]) != bigRows+1 || !slices.Contains(got[idBig], "midsplit-big-stale") {
		t.Fatalf("local rows after a split changed mid-split = %d (stale kept %v), want all %d rows plus the stale row", len(got[idBig]), slices.Contains(got[idBig], "midsplit-big-stale"), bigRows)
	}

	changeMidSplit.Store(false)
	if err := sqlite.Sync(ctx, local, sqlite.SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("sqlite.Sync(next delta) error = %v", err)
	}
	got = localSyncPagingRows(ctx, t, local, idBig)
	if len(got[idBig]) != bigRows || slices.Contains(got[idBig], "midsplit-big-stale") {
		t.Fatalf("local rows after the next delta = %d (stale kept %v), want all %d rows and the stale row dropped", len(got[idBig]), slices.Contains(got[idBig], "midsplit-big-stale"), bigRows)
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
