package postgres

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/synccontract"
)

// budgetRow returns an npm package row of the given advisory whose estimated
// wire size is exactly size bytes.
func budgetRow(t *testing.T, id, name string, size int) db.SyncVulnerability {
	t.Helper()
	row := db.SyncVulnerability{ID: id, Ecosystem: "npm", Name: name}
	pad := size - syncVulnerabilityWireBytes(row)
	if pad < 0 {
		t.Fatalf("budget row %s/%s needs at least %d bytes, want %d", id, name, size-pad, size)
	}
	row.Summary = strings.Repeat("s", pad)
	return row
}

// TestSyncVulnerabilityWireBytesBoundsTheEncodedRow keeps the byte estimate
// of a vulnerability row an upper bound of its JSON encoding in a sync
// response (including the separating comma), for values that expand when
// escaped, and of a listed advisory ID.
func TestSyncVulnerabilityWireBytesBoundsTheEncodedRow(t *testing.T) {
	t.Parallel()

	maxFloat := -math.MaxFloat64
	tricky := "\"quoted\" \\ <script>&amp;    \x01\x1f\t\n\r \xff\xfe ü 漢字 \U0001F600"
	for _, row := range []db.SyncVulnerability{
		{},
		{ID: "GHSA-1", Ecosystem: "npm", Name: "left-pad", VersionRanges: `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`, VersionsAffected: `["1.0.0"]`, References: `[{"type":"WEB","url":"https://example.test/?a=1&b=<2>"}]`, Severity: "HIGH", Summary: "summary", Source: "ghsa"},
		{ID: tricky, Ecosystem: tricky, Name: tricky, VersionRanges: tricky, VersionsAffected: tricky, References: tricky, Severity: tricky, Summary: tricky, Source: tricky, CVSSScore: &maxFloat, EPSSScore: &maxFloat, EPSSPercentile: &maxFloat, CISAKEV: true, Withdrawn: true},
	} {
		encoded, err := json.Marshal(synccontract.ResponseFromExport(&db.SyncExport{Vulnerabilities: []db.SyncVulnerability{row}}, "", nil).Vulnerabilities[0])
		if err != nil {
			t.Fatalf("marshal wire row: %v", err)
		}
		if got, want := syncVulnerabilityWireBytes(row), len(encoded)+1; got < want {
			t.Fatalf("syncVulnerabilityWireBytes(%+v) = %d, want at least %d (encoded %s)", row, got, want, encoded)
		}
	}
	for _, id := range []string{"GHSA-1", tricky} {
		encoded, _ := json.Marshal(id)
		if got, want := syncAdvisoryIDWireBytes(id), len(encoded)+1; got < want {
			t.Fatalf("syncAdvisoryIDWireBytes(%q) = %d, want at least %d", id, got, want)
		}
	}
}

// TestSyncAdvisoryPageBuilderCutsAtAdvisoryBoundaries bounds an advisory page
// by bytes as well as rows: when the next advisory no longer fits, the page
// ends after the last whole advisory, stays flagged, and continues with an
// advisory cursor after it; the deferred advisory starts the next page.
// Listed advisories without rows count toward the budget too.
func TestSyncAdvisoryPageBuilderCutsAtAdvisoryBoundaries(t *testing.T) {
	t.Parallel()

	b := newSyncVulnerabilityPageBuilder(syncVulnerabilityAdvisoryPages, 10, "", 10000)
	for _, step := range []struct {
		row     db.SyncVulnerability
		without bool
		want    bool
	}{
		{row: budgetRow(t, "GHSA-a", "a1", 3000), want: true},
		{row: budgetRow(t, "GHSA-a", "a2", 3000), want: true},
		{row: db.SyncVulnerability{ID: "GHSA-b"}, without: true, want: true},
		{row: budgetRow(t, "GHSA-c", "c1", 2000), want: true},
		{row: budgetRow(t, "GHSA-c", "c2", 3000), want: false},
	} {
		if got := b.add(step.row, step.without, false); got != step.want {
			t.Fatalf("add(%s/%s) = %v, want %v", step.row.ID, step.row.Name, got, step.want)
		}
	}
	page := b.finish()
	if got := syncExportRowsByAdvisory(page.rows); len(got) != 1 || !slices.Equal(got["GHSA-a"], []string{"a1", "a2"}) {
		t.Fatalf("budget-cut page rows = %v, want only GHSA-a with both rows", got)
	}
	if !slices.Equal(page.withoutAffected, []string{"GHSA-b"}) || page.lastAdvisoryID != "GHSA-b" {
		t.Fatalf("budget-cut page without-affected %q last %q, want GHSA-b kept as the last whole advisory", page.withoutAffected, page.lastAdvisoryID)
	}
	if !page.hasMore || page.split {
		t.Fatalf("budget-cut page hasMore %v split %v, want more data on a flagged page", page.hasMore, page.split)
	}
	if id, ok := db.DecodeSyncAdvisoryCursor(page.nextCursor); !ok || id != "GHSA-b" {
		t.Fatalf("budget-cut page next cursor decodes to %q, %v; want an advisory cursor after GHSA-b", id, ok)
	}

	// A page that fits keeps the query's verdict on whether advisories follow.
	b = newSyncVulnerabilityPageBuilder(syncVulnerabilityAdvisoryPages, 10, "", 10000)
	b.add(budgetRow(t, "GHSA-a", "a1", 3000), false, false)
	if page := b.finish(); page.hasMore || page.split || page.nextCursor != "" {
		t.Fatalf("fitting final page = hasMore %v split %v next %q, want the final page", page.hasMore, page.split, page.nextCursor)
	}
}

// TestSyncAdvisoryPageBuilderSplitsAnOversizedFirstAdvisory covers an
// advisory whose rows alone exceed the byte budget. It is the first advisory
// of its page, so the page carries as many of its rows as fit (always at
// least one, so the sync makes progress), is marked split -- it must not
// promise vulnerability_affected_complete -- and continues inside the
// advisory with a row cursor after the last delivered row.
func TestSyncAdvisoryPageBuilderSplitsAnOversizedFirstAdvisory(t *testing.T) {
	t.Parallel()

	b := newSyncVulnerabilityPageBuilder(syncVulnerabilityAdvisoryPages, 10, "", 10000)
	for i, want := range []bool{true, true, true, false} {
		if got := b.add(budgetRow(t, "GHSA-big", "big"+strconv.Itoa(i), 3000), false, false); got != want {
			t.Fatalf("add(big%d) = %v, want %v", i, got, want)
		}
	}
	page := b.finish()
	if len(page.rows) != 3 || !page.split || !page.hasMore {
		t.Fatalf("oversized first advisory page rows=%d split=%v hasMore=%v, want three rows on a split page with more data", len(page.rows), page.split, page.hasMore)
	}
	if id, ecosystem, name, ok := db.DecodeSyncAdvisoryRowCursor(page.nextCursor); !ok || id != "GHSA-big" || ecosystem != "npm" || name != "big2" {
		t.Fatalf("oversized first advisory next cursor = %q %q %q %v, want a row cursor after GHSA-big npm/big2", id, ecosystem, name, ok)
	}

	// A single row larger than the budget is still delivered.
	b = newSyncVulnerabilityPageBuilder(syncVulnerabilityAdvisoryPages, 10, "", 10000)
	if !b.add(budgetRow(t, "GHSA-huge", "h0", 50000), false, true) {
		t.Fatal("add(first oversized row) = false, want the first row always accepted")
	}
	if b.add(budgetRow(t, "GHSA-huge", "h1", 4000), false, true) {
		t.Fatal("add(row after an oversized first row) = true, want the page split")
	}
	if page := b.finish(); len(page.rows) != 1 || !page.split {
		t.Fatalf("oversized single-row page rows=%d split=%v, want one row on a split page", len(page.rows), page.split)
	}
}

// TestSyncSplitPageBuilderContinuesAndFinishesTheAdvisory pages the rest of a
// split advisory: by row limit and byte budget with a row cursor while rows
// remain, and with an advisory cursor after the split advisory once its rows
// are exhausted -- also when none remain, for example because the advisory
// changed after the pinned snapshot. Split pages never promise completeness
// and always continue.
func TestSyncSplitPageBuilderContinuesAndFinishesTheAdvisory(t *testing.T) {
	t.Parallel()

	rowsCursor := func(page syncVulnerabilityPage) string {
		id, ecosystem, name, ok := db.DecodeSyncAdvisoryRowCursor(page.nextCursor)
		if !ok {
			return ""
		}
		return id + "|" + ecosystem + "|" + name
	}

	// The query returns Limit+1 rows when more follow.
	b := newSyncVulnerabilityPageBuilder(syncVulnerabilityAdvisorySplit, 2, "GHSA-big", 100000)
	for i, want := range []bool{true, true, false} {
		if got := b.add(budgetRow(t, "GHSA-big", "big"+strconv.Itoa(i), 3000), false, false); got != want {
			t.Fatalf("add(big%d) = %v, want %v", i, got, want)
		}
	}
	if page := b.finish(); len(page.rows) != 2 || !page.split || !page.hasMore || rowsCursor(page) != "GHSA-big|npm|big1" {
		t.Fatalf("row-limited split page rows=%d split=%v hasMore=%v cursor=%q, want two rows and a row cursor after big1", len(page.rows), page.split, page.hasMore, rowsCursor(page))
	}

	b = newSyncVulnerabilityPageBuilder(syncVulnerabilityAdvisorySplit, 10, "GHSA-big", 10000)
	for i, want := range []bool{true, true, true, false} {
		if got := b.add(budgetRow(t, "GHSA-big", "big"+strconv.Itoa(i), 3000), false, false); got != want {
			t.Fatalf("add(budget big%d) = %v, want %v", i, got, want)
		}
	}
	if page := b.finish(); len(page.rows) != 3 || rowsCursor(page) != "GHSA-big|npm|big2" {
		t.Fatalf("budget-limited split page rows=%d cursor=%q, want three rows and a row cursor after big2", len(page.rows), rowsCursor(page))
	}

	for _, rows := range [][]db.SyncVulnerability{{budgetRow(t, "GHSA-big", "last", 3000)}, nil} {
		b = newSyncVulnerabilityPageBuilder(syncVulnerabilityAdvisorySplit, 10, "GHSA-big", 10000)
		for _, row := range rows {
			b.add(row, false, false)
		}
		page := b.finish()
		if id, ok := db.DecodeSyncAdvisoryCursor(page.nextCursor); !ok || id != "GHSA-big" || !page.split || !page.hasMore || len(page.rows) != len(rows) {
			t.Fatalf("finished split page rows=%d split=%v hasMore=%v cursor=%q (%v), want an advisory cursor after GHSA-big", len(page.rows), page.split, page.hasMore, id, ok)
		}
	}
}

// TestSyncRowPageBuilderHonorsTheByteBudget bounds full-export and legacy
// delta row pages by bytes too: the page ends before the row that no longer
// fits (never before the first row) and reports more data, so the row cursor
// or offset continues after the last delivered row.
func TestSyncRowPageBuilderHonorsTheByteBudget(t *testing.T) {
	t.Parallel()

	for _, paging := range []syncVulnerabilityPaging{syncVulnerabilityRowKeyset, syncVulnerabilityDeltaRowOffset} {
		b := newSyncVulnerabilityPageBuilder(paging, 10, "", 10000)
		for i, want := range []bool{true, true, true, false} {
			if got := b.add(budgetRow(t, "GHSA-"+strconv.Itoa(i), "pkg", 3000), false, false); got != want {
				t.Fatalf("paging %v add(row %d) = %v, want %v", paging, i, got, want)
			}
		}
		if page := b.finish(); len(page.rows) != 3 || !page.hasMore || page.split || page.nextCursor != "" {
			t.Fatalf("paging %v budget-cut page rows=%d hasMore=%v split=%v next=%q, want three rows and more data", paging, len(page.rows), page.hasMore, page.split, page.nextCursor)
		}

		b = newSyncVulnerabilityPageBuilder(paging, 2, "", 10000)
		b.add(budgetRow(t, "GHSA-a", "pkg", 3000), false, false)
		b.add(budgetRow(t, "GHSA-b", "pkg", 3000), false, false)
		if page := b.finish(); !page.hasMore {
			t.Fatalf("paging %v full row page hasMore = false, want the full-page heuristic", paging)
		}
		b = newSyncVulnerabilityPageBuilder(paging, 3, "", 10000)
		b.add(budgetRow(t, "GHSA-a", "pkg", 3000), false, false)
		if page := b.finish(); page.hasMore {
			t.Fatalf("paging %v short row page hasMore = true, want the last page", paging)
		}
	}

	// An export without a limit has no next page, so it is never cut.
	for _, paging := range []syncVulnerabilityPaging{syncVulnerabilityRowKeyset, syncVulnerabilityAdvisoryPages} {
		b := newSyncVulnerabilityPageBuilder(paging, 0, "", 10000)
		for i := range 5 {
			if !b.add(budgetRow(t, "GHSA-big", "pkg"+strconv.Itoa(i), 3000), false, false) {
				t.Fatalf("paging %v unlimited export rejected row %d, want every row", paging, i)
			}
		}
		if page := b.finish(); len(page.rows) != 5 || page.hasMore || page.split {
			t.Fatalf("paging %v unlimited export rows=%d hasMore=%v split=%v, want one complete page", paging, len(page.rows), page.hasMore, page.split)
		}
	}
}

// TestSyncSplitAdvisoryPaging pins the paging mode, flag, and cursor of the
// pages that continue a split advisory: they continue a row cursor of a
// delta, never promise vulnerability_affected_complete, and pass on the
// cursor the page computed. A page that starts a split is unflagged as well.
func TestSyncSplitAdvisoryPaging(t *testing.T) {
	t.Parallel()

	since := time.Unix(1700000000, 0).UTC()
	rowCursor := db.SyncCursor{VulnerabilitiesCursor: db.EncodeSyncAdvisoryRowCursor("GHSA-big", "npm", "big2")}
	delta := db.SyncExportOptions{Since: &since, Cursor: rowCursor}
	if got := syncVulnerabilityPagingFor(delta); got != syncVulnerabilityAdvisorySplit {
		t.Fatalf("paging of a delta with a row cursor = %v, want split advisory paging", got)
	}
	if got := syncVulnerabilityPagingFor(db.SyncExportOptions{Cursor: rowCursor}); got == syncVulnerabilityAdvisorySplit {
		t.Fatal("paging of a full export with a row cursor = split, want it rejected as a legacy row cursor")
	}
	if syncVulnerabilityAffectedComplete(delta, delta.EffectiveCursor()) {
		t.Fatal("split continuation page promises vulnerability_affected_complete")
	}
	advisoryDelta := db.SyncExportOptions{Since: &since}
	if !syncPageVulnerabilityAffectedComplete(advisoryDelta, advisoryDelta.EffectiveCursor(), syncDatasets{}) {
		t.Fatal("whole-advisory page lost vulnerability_affected_complete")
	}
	if syncPageVulnerabilityAffectedComplete(advisoryDelta, advisoryDelta.EffectiveCursor(), syncDatasets{vulnerabilitiesSplit: true}) {
		t.Fatal("page that starts a split promises vulnerability_affected_complete")
	}

	next := db.EncodeSyncAdvisoryRowCursor("GHSA-big", "npm", "big5")
	truncated, cursor := nextSyncExportCursor(rowCursor, syncVulnerabilityAdvisorySplit, syncDatasets{
		vulnerabilitiesHaveMore:   true,
		vulnerabilitiesNextCursor: next,
	}, 2)
	if !truncated || cursor == nil || cursor.VulnerabilitiesCursor != next || cursor.VulnerabilitiesDone {
		t.Fatalf("split page cursor = truncated %v cursor %+v, want the page's row cursor", truncated, cursor)
	}
}

// TestBuildSplitAdvisoryRowsQuery pins the query that continues a split
// advisory: the rows of that one advisory after the row cursor in (ecosystem,
// name) order, bounded by the vulnerability snapshot and the requested
// ecosystems, with one extra row that tells whether more follow.
func TestBuildSplitAdvisoryRowsQuery(t *testing.T) {
	t.Parallel()

	since := time.Unix(1700000000, 0).UTC()
	opts := db.SyncExportOptions{
		Since:      &since,
		Ecosystems: []string{"npm"},
		Limit:      7,
		Cursor:     db.SyncCursor{VulnerabilitiesCursor: db.EncodeSyncAdvisoryRowCursor("GHSA-big", "npm", "big2")},
	}
	query, args, err := buildExportSyncVulnerabilitiesQuery(opts, since.Add(time.Hour), 42)
	if err != nil {
		t.Fatalf("build split advisory query: %v", err)
	}
	normalized := strings.Join(strings.Fields(query), " ")
	arg := func(value any) string {
		index := slices.Index(args, value)
		if index < 0 {
			t.Fatalf("split advisory query args %v miss %v", args, value)
		}
		return "$" + strconv.Itoa(index+1)
	}
	for _, want := range []string{
		"INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id",
		"WHERE v.id = " + arg("GHSA-big"),
		"(ap.ecosystem, ap.name) > (" + arg("npm") + ", " + arg("big2") + ")",
		"v.updated_at <= $1",
		syncXIDBeforeSQL("v.xmin", arg("42")),
		"ap.ecosystem = ANY(",
		"ORDER BY ap.ecosystem ASC, ap.name ASC",
		"LIMIT " + arg(7) + "::bigint + 1",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("split advisory query missing %q in:\n%s", want, query)
		}
	}
	for _, forbidden := range []string{"page_candidates", "changed_vulnerability_ids", "OFFSET"} {
		if strings.Contains(normalized, forbidden) {
			t.Fatalf("split advisory query must not contain %q in:\n%s", forbidden, query)
		}
	}
}

func syncExportRowsByAdvisory(rows []db.SyncVulnerability) map[string][]string {
	out := make(map[string][]string)
	for _, row := range rows {
		out[row.ID] = append(out[row.ID], row.Name)
	}
	return out
}
