package postgres

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// TestSyncVulnerabilityPagingModes pins which requests page the vulnerability
// dataset by whole advisories: a delta (since window) that starts fresh or
// echoes an advisory cursor. A full export and a delta that continues a legacy
// row cursor keep (ecosystem, name, id) row paging, and a legacy offset delta
// pages rows in advisory order so an offset-only client stays consistent with
// the advisory-ordered first page.
func TestSyncVulnerabilityPagingModes(t *testing.T) {
	t.Parallel()

	since := time.Unix(1700000000, 0).UTC()
	legacy := encodeSyncCursorKey("npm", "left-pad", "GHSA-1")
	advisory := db.EncodeSyncAdvisoryCursor("GHSA-1")
	tests := []struct {
		name string
		opts db.SyncExportOptions
		want syncVulnerabilityPaging
	}{
		{name: "full export", opts: db.SyncExportOptions{}, want: syncVulnerabilityRowKeyset},
		{name: "full export page", opts: db.SyncExportOptions{Cursor: db.SyncCursor{VulnerabilitiesCursor: legacy}}, want: syncVulnerabilityRowKeyset},
		{name: "full export offset", opts: db.SyncExportOptions{Offset: 5}, want: syncVulnerabilityRowKeyset},
		{name: "first delta page", opts: db.SyncExportOptions{Since: &since}, want: syncVulnerabilityAdvisoryPages},
		{name: "advisory cursor delta page", opts: db.SyncExportOptions{Since: &since, Cursor: db.SyncCursor{VulnerabilitiesCursor: advisory}}, want: syncVulnerabilityAdvisoryPages},
		{name: "advisory cursor wins over an echoed offset", opts: db.SyncExportOptions{Since: &since, Offset: 3, Cursor: db.SyncCursor{VulnerabilitiesCursor: advisory}}, want: syncVulnerabilityAdvisoryPages},
		{name: "legacy cursor delta page", opts: db.SyncExportOptions{Since: &since, Cursor: db.SyncCursor{VulnerabilitiesCursor: legacy}}, want: syncVulnerabilityRowKeyset},
		{name: "legacy offset delta page", opts: db.SyncExportOptions{Since: &since, Offset: 3}, want: syncVulnerabilityDeltaRowOffset},
	}
	for _, tt := range tests {
		if got := syncVulnerabilityPagingFor(tt.opts); got != tt.want {
			t.Fatalf("%s: syncVulnerabilityPagingFor() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestSyncVulnerabilityAffectedCompleteOnAdvisoryPagedDeltas pins where the
// export offers vulnerability_affected_complete: on every page of a delta paged
// by whole advisories, because each page is one statement that carries every
// advisory on it with its complete current affected set. A full export bounds
// affected rows by the snapshot, and the legacy row-cursor and offset pages of
// a delta can split an advisory, so they never carry it.
func TestSyncVulnerabilityAffectedCompleteOnAdvisoryPagedDeltas(t *testing.T) {
	t.Parallel()

	since := time.Unix(1700000000, 0).UTC()
	advisory := db.EncodeSyncAdvisoryCursor("GHSA-1")
	tests := []struct {
		name string
		opts db.SyncExportOptions
		want bool
	}{
		{name: "single-page delta", opts: db.SyncExportOptions{Since: &since}, want: true},
		{name: "first page of a multi-page delta", opts: db.SyncExportOptions{Since: &since, Limit: 1}, want: true},
		{name: "later page of an advisory-paged delta", opts: db.SyncExportOptions{Since: &since, Limit: 1, Cursor: db.SyncCursor{VulnerabilitiesCursor: advisory}}, want: true},
		{name: "page after another dataset finished", opts: db.SyncExportOptions{Since: &since, Cursor: db.SyncCursor{MaliciousDone: true}}, want: true},
		{name: "single-page delta without reputation", opts: db.SyncExportOptions{Since: &since, ExcludeReputation: true}, want: true},
		{name: "full export", opts: db.SyncExportOptions{}},
		{name: "full export page", opts: db.SyncExportOptions{Limit: 1, Cursor: db.SyncCursor{VulnerabilitiesCursor: encodeSyncCursorKey("npm", "a", "GHSA-1")}}},
		{name: "legacy row-cursor delta page", opts: db.SyncExportOptions{Since: &since, Cursor: db.SyncCursor{VulnerabilitiesCursor: encodeSyncCursorKey("npm", "a", "GHSA-1")}}},
		{name: "legacy offset delta page", opts: db.SyncExportOptions{Since: &since, Offset: 10}},
		{name: "legacy dataset offset delta page", opts: db.SyncExportOptions{Since: &since, Cursor: db.SyncCursor{Vulnerabilities: 10}}},
		{name: "delta page after the vulnerability dataset finished", opts: db.SyncExportOptions{Since: &since, Cursor: db.SyncCursor{VulnerabilitiesDone: true}}},
	}
	for _, tt := range tests {
		if got := syncVulnerabilityAffectedComplete(tt.opts, tt.opts.EffectiveCursor()); got != tt.want {
			t.Fatalf("%s: syncVulnerabilityAffectedComplete() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestBuildAdvisoryPageQueryNeverSplitsAnAdvisory pins the delta page query:
// it selects whole advisories after the cursor in ID order, keeps adding them
// while the page stays within the row limit (the first advisory always fits,
// however many rows it has), and exports every in-scope affected row of each
// selected advisory in one statement.
func TestBuildAdvisoryPageQueryNeverSplitsAnAdvisory(t *testing.T) {
	t.Parallel()

	since := time.Unix(1700000000, 0).UTC()
	opts := db.SyncExportOptions{
		Since:      &since,
		SinceXID:   7,
		Ecosystems: []string{"npm"},
		Limit:      2,
		Cursor:     db.SyncCursor{VulnerabilitiesCursor: db.EncodeSyncAdvisoryCursor("GHSA-b")},
	}
	query, args, err := buildExportSyncVulnerabilitiesQuery(opts, since.Add(time.Hour), 42)
	if err != nil {
		t.Fatalf("build advisory page query: %v", err)
	}
	normalized := strings.Join(strings.Fields(query), " ")
	for _, want := range []string{
		"WITH changed_vulnerability_ids AS",
		"page_candidates AS (",
		"INNER JOIN changed_vulnerability_ids changed ON changed.id = v.id",
		"SUM(COUNT(*)) OVER (ORDER BY v.id)",
		"ROW_NUMBER() OVER (ORDER BY v.id)",
		"GROUP BY v.id ORDER BY v.id",
		"page_vulnerabilities AS (",
		"INNER JOIN page_vulnerabilities page ON page.id = v.id",
		"ORDER BY v.id ASC, ap.ecosystem ASC, ap.name ASC",
		"AS has_more",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("advisory page query missing %q in:\n%s", want, query)
		}
	}
	for _, forbidden := range []string{"(ap.ecosystem, ap.name, v.id) >", "OFFSET"} {
		if strings.Contains(normalized, forbidden) {
			t.Fatalf("advisory page query must not page rows with %q in:\n%s", forbidden, query)
		}
	}
	cursorArg := slices.Index(args, any("GHSA-b")) + 1
	if cursorArg == 0 {
		t.Fatalf("advisory page query args %v miss the cursor advisory ID", args)
	}
	limitArg := slices.Index(args, any(2)) + 1
	if limitArg == 0 {
		t.Fatalf("advisory page query args %v miss the row limit", args)
	}
	for _, want := range []string{
		"v.id > $" + strconv.Itoa(cursorArg),
		"position = 1 OR cumulative_rows <= $" + strconv.Itoa(limitArg) + "::bigint",
		"LIMIT $" + strconv.Itoa(limitArg) + "::bigint + 1",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("advisory page query missing %q in:\n%s", want, query)
		}
	}
	// The ecosystem filter applies when counting the page and when exporting
	// its rows, so a page is complete within the requested ecosystems.
	if got := strings.Count(normalized, "ap.ecosystem = ANY($"); got != 2 {
		t.Fatalf("advisory page query applies the ecosystem filter %d times, want 2:\n%s", got, query)
	}
	// Like every delta, only the vulnerability row is bounded by the snapshot
	// after the changed-ID CTE; affected rows are exported complete.
	outer := normalized[strings.Index(normalized, "page_candidates AS ("):]
	for _, forbidden := range []string{"ap.updated_at <= $1", "ap.xmin"} {
		if strings.Contains(outer, forbidden) {
			t.Fatalf("advisory page query bounds affected rows with %q:\n%s", forbidden, query)
		}
	}
	snapshotXIDArg := slices.Index(args, any("42")) + 1
	if snapshotXIDArg == 0 {
		t.Fatalf("advisory page query args %v miss the snapshot xid", args)
	}
	for _, want := range []string{"v.updated_at <= $1", syncXIDBeforeSQL("v.xmin", "$"+strconv.Itoa(snapshotXIDArg))} {
		if !strings.Contains(outer, want) {
			t.Fatalf("advisory page query lost vulnerability snapshot bound %q:\n%s", want, query)
		}
	}

	unlimited, _, err := buildExportSyncVulnerabilitiesQuery(db.SyncExportOptions{Since: &since}, since.Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("build unlimited advisory page query: %v", err)
	}
	if strings.Contains(unlimited, "::bigint + 1") || strings.Contains(unlimited, "cumulative_rows <=") {
		t.Fatalf("unlimited advisory page query must not limit the page:\n%s", unlimited)
	}
}

// TestBuildAdvisoryPageQueryKeepsAdvisoriesWithoutAffectedRows pins how a
// delta page reaches a changed advisory that has no affected row left within
// the requested ecosystems: the page candidates and the exported rows LEFT JOIN
// the in-scope affected packages, so such an advisory takes one slot of the
// page and comes back as one marker row (without_affected) instead of
// vanishing from every delta.
func TestBuildAdvisoryPageQueryKeepsAdvisoriesWithoutAffectedRows(t *testing.T) {
	t.Parallel()

	since := time.Unix(1700000000, 0).UTC()
	for _, tt := range []struct {
		name       string
		ecosystems []string
		join       string
	}{
		{name: "unfiltered", join: "LEFT JOIN affected_packages ap ON ap.vulnerability_id = v.id LEFT JOIN LATERAL"},
		{name: "filtered", ecosystems: []string{"npm"}, join: "LEFT JOIN affected_packages ap ON ap.vulnerability_id = v.id AND ap.ecosystem = ANY($"},
	} {
		query, _, err := buildExportSyncVulnerabilitiesQuery(db.SyncExportOptions{Since: &since, Ecosystems: tt.ecosystems, Limit: 2}, since.Add(time.Hour), 42)
		if err != nil {
			t.Fatalf("%s: build advisory page query: %v", tt.name, err)
		}
		normalized := strings.Join(strings.Fields(query), " ")
		pageQuery := normalized[strings.Index(normalized, "page_candidates AS ("):]
		if strings.Contains(pageQuery, "INNER JOIN affected_packages") {
			t.Fatalf("%s: advisory page query inner-joins affected packages, dropping advisories without rows:\n%s", tt.name, query)
		}
		for _, want := range []string{
			"SUM(COUNT(*)) OVER (ORDER BY v.id)",
			"(ap.vulnerability_id IS NULL) AS without_affected",
			"COALESCE(ap.ecosystem, '')",
			"COALESCE(ap.version_ranges::text, '[]')",
		} {
			if !strings.Contains(pageQuery, want) {
				t.Fatalf("%s: advisory page query missing %q in:\n%s", tt.name, want, query)
			}
		}
		joins := strings.Count(pageQuery, "LEFT JOIN affected_packages ap ON ap.vulnerability_id = v.id")
		if joins != 2 {
			t.Fatalf("%s: advisory page query LEFT JOINs affected packages %d times, want 2:\n%s", tt.name, joins, query)
		}
		if tt.ecosystems != nil && strings.Count(pageQuery, tt.join) != 2 {
			t.Fatalf("%s: advisory page query must scope both affected joins with %q:\n%s", tt.name, tt.join, query)
		}
		if strings.Contains(pageQuery, "WHERE TRUE AND ap.ecosystem") {
			t.Fatalf("%s: advisory page query filters ecosystems in WHERE, dropping advisories without in-scope rows:\n%s", tt.name, query)
		}
	}
}

// TestSyncAdvisoryPageCollectsAdvisoriesWithoutAffectedRows feeds marker rows
// of an advisory page into the page: they never become package rows, they
// list the advisory ID once, and they still advance the advisory cursor, so a
// page that ends with (or only holds) such advisories continues after them.
func TestSyncAdvisoryPageCollectsAdvisoriesWithoutAffectedRows(t *testing.T) {
	t.Parallel()

	page := newSyncAdvisoryPage()
	page.add(db.SyncVulnerability{ID: "GHSA-a", Ecosystem: "npm", Name: "left-pad"}, false)
	page.add(db.SyncVulnerability{ID: "GHSA-b"}, true)
	page.add(db.SyncVulnerability{ID: "GHSA-c", Withdrawn: true}, true)
	if len(page.rows) != 1 || page.rows[0].ID != "GHSA-a" {
		t.Fatalf("advisory page rows = %+v, want only the GHSA-a package row", page.rows)
	}
	if !slices.Equal(page.withoutAffected, []string{"GHSA-b", "GHSA-c"}) {
		t.Fatalf("advisory page without-affected IDs = %q, want GHSA-b and GHSA-c", page.withoutAffected)
	}
	if page.lastAdvisoryID != "GHSA-c" {
		t.Fatalf("advisory page last advisory = %q, want GHSA-c", page.lastAdvisoryID)
	}

	for _, tt := range []struct {
		name string
		page syncVulnerabilityPage
		want string
	}{
		{name: "page ending with an advisory without rows", page: page, want: "GHSA-c"},
		{name: "page holding only advisories without rows", page: syncVulnerabilityPage{withoutAffected: []string{"GHSA-d"}, lastAdvisoryID: "GHSA-d"}, want: "GHSA-d"},
	} {
		truncated, next := nextSyncExportCursor(db.SyncCursor{}, syncVulnerabilityAdvisoryPages, syncDatasets{
			vulnerabilities:               tt.page.rows,
			vulnerabilitiesHaveMore:       true,
			vulnerabilitiesLastAdvisoryID: tt.page.lastAdvisoryID,
		}, 2)
		if !truncated || next == nil {
			t.Fatalf("%s: truncated %v next %+v, want more data", tt.name, truncated, next)
		}
		if id, ok := db.DecodeSyncAdvisoryCursor(next.VulnerabilitiesCursor); !ok || id != tt.want {
			t.Fatalf("%s: vulnerabilities_cursor decodes to %q, %v; want an advisory cursor after %s", tt.name, id, ok, tt.want)
		}
	}
}

// TestBuildLegacyVulnerabilityQueriesKeepRowPaging keeps full exports and
// delta pages that continue a legacy row cursor on (ecosystem, name, id) row
// paging, and pages a legacy offset delta in advisory row order.
func TestBuildLegacyVulnerabilityQueriesKeepRowPaging(t *testing.T) {
	t.Parallel()

	since := time.Unix(1700000000, 0).UTC()
	snapshot := since.Add(time.Hour)
	legacy := db.SyncCursor{VulnerabilitiesCursor: encodeSyncCursorKey("npm", "left-pad", "GHSA-1")}
	tests := []struct {
		name   string
		opts   db.SyncExportOptions
		want   []string
		reject []string
	}{
		{
			name:   "full export",
			opts:   db.SyncExportOptions{Limit: 2, Cursor: legacy},
			want:   []string{"(ap.ecosystem, ap.name, v.id) > ($", "ORDER BY ap.ecosystem ASC, ap.name ASC, v.id ASC"},
			reject: []string{"page_candidates", "changed_vulnerability_ids"},
		},
		{
			name:   "delta continuing a legacy row cursor",
			opts:   db.SyncExportOptions{Since: &since, Limit: 2, Cursor: legacy},
			want:   []string{"changed_vulnerability_ids", "(ap.ecosystem, ap.name, v.id) > ($", "ORDER BY ap.ecosystem ASC, ap.name ASC, v.id ASC"},
			reject: []string{"page_candidates"},
		},
		{
			name:   "legacy offset delta",
			opts:   db.SyncExportOptions{Since: &since, Limit: 2, Offset: 4},
			want:   []string{"changed_vulnerability_ids", "ORDER BY v.id ASC, ap.ecosystem ASC, ap.name ASC", "OFFSET $"},
			reject: []string{"page_candidates", "(ap.ecosystem, ap.name, v.id) >"},
		},
	}
	for _, tt := range tests {
		query, _, err := buildExportSyncVulnerabilitiesQuery(tt.opts, snapshot, 0)
		if err != nil {
			t.Fatalf("%s: build query: %v", tt.name, err)
		}
		normalized := strings.Join(strings.Fields(query), " ")
		for _, want := range tt.want {
			if !strings.Contains(normalized, want) {
				t.Fatalf("%s: query missing %q in:\n%s", tt.name, want, query)
			}
		}
		for _, reject := range tt.reject {
			if strings.Contains(normalized, reject) {
				t.Fatalf("%s: query must not contain %q in:\n%s", tt.name, reject, query)
			}
		}
	}

	// An advisory cursor belongs to a delta; a full export cannot continue it.
	if _, _, err := buildExportSyncVulnerabilitiesQuery(db.SyncExportOptions{
		Limit: 2, Cursor: db.SyncCursor{VulnerabilitiesCursor: db.EncodeSyncAdvisoryCursor("GHSA-1")},
	}, snapshot, 0); err == nil {
		t.Fatal("full export with an advisory cursor error = nil, want invalid cursor")
	}
}

// TestNextSyncExportCursorPagesWholeAdvisories pins the pagination state
// around the vulnerability dataset: an advisory page reports more data only
// when the query found an advisory it left for the next page, even when the
// page overshoots the row limit for its only advisory, and continues with an
// advisory cursor. Legacy pages keep the full-page heuristic and their cursor
// kinds.
func TestNextSyncExportCursorPagesWholeAdvisories(t *testing.T) {
	t.Parallel()

	rows := func(ids ...string) []db.SyncVulnerability {
		out := make([]db.SyncVulnerability, 0, len(ids))
		for i, id := range ids {
			out = append(out, db.SyncVulnerability{ID: id, Ecosystem: "npm", Name: "pkg-" + strconv.Itoa(i)})
		}
		return out
	}

	// One advisory with three rows exceeds the limit of two and is the whole
	// page; another advisory follows.
	truncated, next := nextSyncExportCursor(db.SyncCursor{}, syncVulnerabilityAdvisoryPages, syncDatasets{
		vulnerabilities: rows("GHSA-a", "GHSA-a", "GHSA-a"), vulnerabilitiesHaveMore: true,
	}, 2)
	if !truncated || next == nil {
		t.Fatalf("overshooting advisory page = truncated %v next %+v, want more data", truncated, next)
	}
	if id, ok := db.DecodeSyncAdvisoryCursor(next.VulnerabilitiesCursor); !ok || id != "GHSA-a" || next.VulnerabilitiesDone {
		t.Fatalf("overshooting advisory page cursor = %+v (decoded %q, %v), want an advisory cursor after GHSA-a", next, id, ok)
	}
	if next.Vulnerabilities != 3 || !next.MaliciousDone || !next.ReputationDone || !next.LifecycleDone {
		t.Fatalf("overshooting advisory page cursor = %+v, want offset 3 and the empty datasets done", next)
	}

	// The same overshooting page without a following advisory is the last one.
	if truncated, next := nextSyncExportCursor(db.SyncCursor{}, syncVulnerabilityAdvisoryPages, syncDatasets{
		vulnerabilities: rows("GHSA-a", "GHSA-a", "GHSA-a"),
	}, 2); truncated || next != nil {
		t.Fatalf("last overshooting advisory page = truncated %v next %+v, want the final page", truncated, next)
	}

	// A short advisory page while another dataset continues marks the
	// vulnerability dataset done.
	truncated, next = nextSyncExportCursor(db.SyncCursor{VulnerabilitiesCursor: db.EncodeSyncAdvisoryCursor("GHSA-0")}, syncVulnerabilityAdvisoryPages, syncDatasets{
		vulnerabilities:   rows("GHSA-b"),
		malicious:         []db.SyncMalicious{{ID: "MAL-1"}, {ID: "MAL-2"}},
		maliciousHaveMore: true,
	}, 2)
	if !truncated || next == nil || !next.VulnerabilitiesDone || next.VulnerabilitiesCursor != "" || next.MaliciousCursor == "" {
		t.Fatalf("finished advisory dataset cursor = truncated %v next %+v, want vulnerabilities done and malicious continued", truncated, next)
	}

	// Legacy offset delta pages advance only the offset, so an offset client
	// keeps paging rows in the same order.
	truncated, next = nextSyncExportCursor(db.SyncCursor{Vulnerabilities: 4}, syncVulnerabilityDeltaRowOffset, syncDatasets{
		vulnerabilities: rows("GHSA-a", "GHSA-b"), vulnerabilitiesHaveMore: true,
	}, 2)
	if !truncated || next == nil || next.Vulnerabilities != 6 || next.VulnerabilitiesCursor != "" || next.VulnerabilitiesDone {
		t.Fatalf("legacy offset delta cursor = truncated %v next %+v, want offset 6 without a keyset cursor", truncated, next)
	}

	// Full exports and legacy row-cursor deltas keep the legacy row cursor.
	truncated, next = nextSyncExportCursor(db.SyncCursor{}, syncVulnerabilityRowKeyset, syncDatasets{
		vulnerabilities: rows("GHSA-a", "GHSA-b"), vulnerabilitiesHaveMore: true,
	}, 2)
	if !truncated || next == nil {
		t.Fatalf("row keyset page = truncated %v next %+v, want more data", truncated, next)
	}
	parts, err := decodeSyncCursorKey(next.VulnerabilitiesCursor, 3)
	if err != nil || !slices.Equal(parts, []string{"npm", "pkg-1", "GHSA-b"}) {
		t.Fatalf("row keyset cursor = %v, %v; want the last (ecosystem, name, id) row", parts, err)
	}
}
