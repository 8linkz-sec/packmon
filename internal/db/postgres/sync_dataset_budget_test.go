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

// syncPageEnvelopeHeadroom is the part of the client response cap that the
// dataset byte budgets leave free for the envelope and for a first row that
// alone exceeds its budget.
const syncPageEnvelopeHeadroom = 4 << 20

// budgetMalicious, budgetReputation, and budgetLifecycle return a row of their
// dataset whose estimated wire size is exactly size bytes, padded with an
// escape-heavy value so the JSON encoding expands it.
func budgetMalicious(t *testing.T, i, size int) db.SyncMalicious {
	t.Helper()
	row := db.SyncMalicious{ID: "MAL-" + strconv.Itoa(i), Ecosystem: "npm", Name: "pkg-" + strconv.Itoa(i)}
	row.Summary = budgetPadding(t, size-syncMaliciousWireBytes(row))
	return row
}

func budgetReputation(t *testing.T, i, size int) db.SyncReputationFinding {
	t.Helper()
	row := db.SyncReputationFinding{ID: "reputation:npm:pkg-" + strconv.Itoa(i) + ":1.0.0", Ecosystem: "npm", Name: "pkg-" + strconv.Itoa(i), Version: "1.0.0"}
	row.Summary = budgetPadding(t, size-syncReputationWireBytes(row))
	return row
}

func budgetLifecycle(t *testing.T, i, size int) db.SyncLifecycleRelease {
	t.Helper()
	row := db.SyncLifecycleRelease{ID: "endoflife:npm:pkg:pkg:" + strconv.Itoa(i), Ecosystem: "npm", Name: "pkg", ProductSlug: "pkg", Cycle: strconv.Itoa(i)}
	row.ProductLabel = budgetPadding(t, size-syncLifecycleWireBytes(row))
	return row
}

// budgetPadding returns a value that adds exactly pad estimated wire bytes to
// a row: '<' takes six bytes escaped, so most of the padding expands.
func budgetPadding(t *testing.T, pad int) string {
	t.Helper()
	if pad < 0 {
		t.Fatalf("budget row needs %d more bytes", -pad)
	}
	return strings.Repeat("<", pad/6) + strings.Repeat("s", pad%6)
}

// TestSyncDatasetWireBytesBoundTheEncodedRows keeps the byte estimates of the
// malicious, reputation, and lifecycle rows upper bounds of their JSON
// encoding in a sync response (including the separating comma), for values
// that expand when escaped and for dates outside four-digit years.
func TestSyncDatasetWireBytesBoundTheEncodedRows(t *testing.T) {
	t.Parallel()

	tricky := "\"quoted\" \\ <script>&amp;    \x01\x1f\t\n\r \xff\xfe ü 漢字 \U0001F600"
	farFuture := time.Date(5874897, 12, 31, 0, 0, 0, 0, time.UTC)
	farPast := time.Date(-4713, 11, 24, 0, 0, 0, 0, time.UTC)
	yes := true
	export := &db.SyncExport{
		Malicious: []db.SyncMalicious{
			{},
			{ID: tricky, Ecosystem: tricky, Name: tricky, VersionRanges: tricky, Versions: tricky, ReferenceURLs: tricky, RiskType: tricky, Severity: tricky, Summary: tricky, Source: tricky, Withdrawn: true},
		},
		Reputation: []db.SyncReputationFinding{
			{},
			{ID: tricky, Ecosystem: tricky, Name: tricky, Version: tricky, Type: tricky, RiskType: tricky, Severity: tricky, Summary: tricky, Withdrawn: true},
		},
		Lifecycle: []db.SyncLifecycleRelease{
			{},
			{
				ID: tricky, Ecosystem: tricky, Name: tricky, ProductSlug: tricky, ProductLabel: tricky, Cycle: tricky, Latest: tricky,
				ReleaseDate: &farFuture, IsLTS: true, LTSFrom: &farPast, IsEOAS: true, EOASFrom: &farFuture, IsEOL: true, EOLFrom: &farPast,
				IsDiscontinued: true, DiscontinuedFrom: &farFuture, IsEOES: &yes, EOESFrom: &farPast, IsMaintained: true, Withdrawn: true,
			},
		},
	}
	resp := synccontract.ResponseFromExport(export, "", nil)
	bound := func(name string, wire any, estimate int) {
		t.Helper()
		encoded, err := json.Marshal(wire)
		if err != nil {
			t.Fatalf("marshal %s wire row: %v", name, err)
		}
		if want := len(encoded) + 1; estimate < want {
			t.Fatalf("%s wire bytes = %d, want at least %d (encoded %s)", name, estimate, want, encoded)
		}
	}
	for i, row := range export.Malicious {
		bound("malicious", resp.Malicious[i], syncMaliciousWireBytes(row))
	}
	for i, row := range export.Reputation {
		bound("reputation", resp.Reputation[i], syncReputationWireBytes(row))
	}
	for i, row := range export.Lifecycle {
		bound("lifecycle", resp.Lifecycle[i], syncLifecycleWireBytes(row))
	}
}

// TestSyncRowPageBuilderBoundsTheOtherDatasetsByBytes bounds the malicious,
// reputation, and lifecycle pages by bytes as well as rows: a page ends before
// the row that no longer fits its budget, never before the first row (so a
// single row larger than the budget still makes progress), and reports more
// data so the dataset continues after its last delivered row. The row limit
// keeps the full-page heuristic, and an export without a limit is never cut.
func TestSyncRowPageBuilderBoundsTheOtherDatasetsByBytes(t *testing.T) {
	t.Parallel()

	b := newSyncRowPageBuilder(10, 10000, syncMaliciousWireBytes)
	for i, want := range []bool{true, true, true, false} {
		if got := b.add(budgetMalicious(t, i, 3000)); got != want {
			t.Fatalf("add(malicious %d) = %v, want %v", i, got, want)
		}
	}
	if b.add(budgetMalicious(t, 9, 300)) {
		t.Fatal("add after the page was cut = true, want every later row on a later page")
	}
	if page := b.finish(); len(page.rows) != 3 || !page.hasMore {
		t.Fatalf("budget-cut malicious page rows=%d hasMore=%v, want three rows and more data", len(page.rows), page.hasMore)
	}

	reputation := newSyncRowPageBuilder(10, 10000, syncReputationWireBytes)
	if !reputation.add(budgetReputation(t, 0, 50000)) {
		t.Fatal("add(first oversized reputation row) = false, want the first row always accepted")
	}
	if reputation.add(budgetReputation(t, 1, 300)) {
		t.Fatal("add(row after an oversized first row) = true, want the page cut")
	}
	if page := reputation.finish(); len(page.rows) != 1 || !page.hasMore {
		t.Fatalf("oversized reputation page rows=%d hasMore=%v, want one row and more data", len(page.rows), page.hasMore)
	}

	lifecycle := newSyncRowPageBuilder(2, 100000, syncLifecycleWireBytes)
	lifecycle.add(budgetLifecycle(t, 0, 3000))
	lifecycle.add(budgetLifecycle(t, 1, 3000))
	if page := lifecycle.finish(); !page.hasMore {
		t.Fatal("full lifecycle page hasMore = false, want the full-page heuristic")
	}
	lifecycle = newSyncRowPageBuilder(3, 100000, syncLifecycleWireBytes)
	lifecycle.add(budgetLifecycle(t, 0, 3000))
	if page := lifecycle.finish(); page.hasMore || len(page.rows) != 1 {
		t.Fatalf("short lifecycle page rows=%d hasMore=%v, want the last page", len(page.rows), page.hasMore)
	}
	if page := newSyncRowPageBuilder(3, 100000, syncLifecycleWireBytes).finish(); page.rows == nil || page.hasMore {
		t.Fatalf("empty lifecycle page rows=%v hasMore=%v, want an empty, final page", page.rows, page.hasMore)
	}

	unlimited := newSyncRowPageBuilder(0, 10000, syncMaliciousWireBytes)
	for i := range 5 {
		if !unlimited.add(budgetMalicious(t, i, 3000)) {
			t.Fatalf("unlimited export rejected malicious row %d, want every row", i)
		}
	}
	if page := unlimited.finish(); len(page.rows) != 5 || page.hasMore {
		t.Fatalf("unlimited malicious export rows=%d hasMore=%v, want one complete page", len(page.rows), page.hasMore)
	}
}

// TestNextSyncExportCursorContinuesByteCutDatasets keeps a malicious,
// reputation, or lifecycle dataset going when its page was cut by bytes with
// fewer rows than the limit: the dataset continues after its last delivered
// row by keyset cursor and offset instead of being marked done, while a short
// page that was not cut still finishes its dataset.
func TestNextSyncExportCursorContinuesByteCutDatasets(t *testing.T) {
	t.Parallel()

	start := db.SyncCursor{VulnerabilitiesDone: true, Malicious: 10, Reputation: 20, Lifecycle: 30}
	truncated, next := nextSyncExportCursor(start, syncVulnerabilityRowKeyset, syncDatasets{
		malicious:          []db.SyncMalicious{{ID: "MAL-1", Ecosystem: "npm", Name: "a"}, {ID: "MAL-2", Ecosystem: "npm", Name: "b"}},
		maliciousHaveMore:  true,
		reputation:         []db.SyncReputationFinding{{Ecosystem: "pypi", Name: "c", Version: "1.0"}},
		reputationHaveMore: true,
		lifecycle:          []db.SyncLifecycleRelease{{Ecosystem: "npm", Name: "d", ProductSlug: "d", Cycle: "1"}},
		lifecycleHaveMore:  true,
	}, 100)
	if !truncated || next == nil {
		t.Fatalf("byte-cut datasets = truncated %v next %+v, want more data", truncated, next)
	}
	if next.MaliciousDone || next.ReputationDone || next.LifecycleDone || !next.VulnerabilitiesDone {
		t.Fatalf("byte-cut datasets cursor = %+v, want only vulnerabilities done", next)
	}
	if next.Malicious != 12 || next.Reputation != 21 || next.Lifecycle != 31 {
		t.Fatalf("byte-cut datasets offsets = %d/%d/%d, want 12/21/31", next.Malicious, next.Reputation, next.Lifecycle)
	}
	for _, check := range []struct {
		name  string
		raw   string
		parts int
		want  []string
	}{
		{name: "malicious", raw: next.MaliciousCursor, parts: 3, want: []string{"npm", "b", "MAL-2"}},
		{name: "reputation", raw: next.ReputationCursor, parts: 3, want: []string{"pypi", "c", "1.0"}},
		{name: "lifecycle", raw: next.LifecycleCursor, parts: 4, want: []string{"npm", "d", "d", "1"}},
	} {
		if parts, err := decodeSyncCursorKey(check.raw, check.parts); err != nil || !slices.Equal(parts, check.want) {
			t.Fatalf("%s cursor = %v, %v; want %v", check.name, parts, err, check.want)
		}
	}

	// Only the byte-cut malicious dataset continues; the short reputation and
	// lifecycle pages finish their datasets.
	truncated, next = nextSyncExportCursor(start, syncVulnerabilityRowKeyset, syncDatasets{
		malicious:         []db.SyncMalicious{{ID: "MAL-1", Ecosystem: "npm", Name: "a"}},
		maliciousHaveMore: true,
		reputation:        []db.SyncReputationFinding{{Ecosystem: "pypi", Name: "c", Version: "1.0"}},
	}, 100)
	if !truncated || next == nil || next.MaliciousDone || !next.ReputationDone || !next.LifecycleDone || next.ReputationCursor != "" {
		t.Fatalf("mixed datasets = truncated %v next %+v, want malicious continued and the rest done", truncated, next)
	}

	// No dataset continues: the sequence ends.
	if truncated, next := nextSyncExportCursor(start, syncVulnerabilityRowKeyset, syncDatasets{
		malicious: []db.SyncMalicious{{ID: "MAL-1", Ecosystem: "npm", Name: "a"}},
	}, 100); truncated || next != nil {
		t.Fatalf("finished datasets = truncated %v next %+v, want the final page", truncated, next)
	}
}

// TestSyncPageOfOversizedRowsStaysBelowTheClientCap fills every dataset of one
// page with oversized, escape-heavy synthetic rows up to the row limit and
// checks that the byte budgets cut each dataset, that each still delivers at
// least one row and continues, and that the encoded response stays below the
// response size the client accepts with room to spare.
func TestSyncPageOfOversizedRowsStaysBelowTheClientCap(t *testing.T) {
	t.Parallel()

	const rowSize = 700 << 10
	limit := synccontract.MaxLimit

	vulns := newSyncVulnerabilityPageBuilder(syncVulnerabilityRowKeyset, limit, "", db.SyncVulnerabilityPageByteBudget)
	for i := 0; i < limit; i++ {
		row := db.SyncVulnerability{ID: "GHSA-" + strconv.Itoa(i), Ecosystem: "npm", Name: "pkg"}
		row.Summary = budgetPadding(t, rowSize-syncVulnerabilityWireBytes(row))
		if !vulns.add(row, false, false) {
			break
		}
	}
	malicious := newSyncRowPageBuilder(limit, db.SyncMaliciousPageByteBudget, syncMaliciousWireBytes)
	for i := 0; i < limit && malicious.add(budgetMalicious(t, i, rowSize)); i++ {
	}
	reputation := newSyncRowPageBuilder(limit, db.SyncReputationPageByteBudget, syncReputationWireBytes)
	for i := 0; i < limit && reputation.add(budgetReputation(t, i, rowSize)); i++ {
	}
	lifecycle := newSyncRowPageBuilder(limit, db.SyncLifecyclePageByteBudget, syncLifecycleWireBytes)
	for i := 0; i < limit && lifecycle.add(budgetLifecycle(t, i, rowSize)); i++ {
	}

	vulnPage, malPage, repPage, lifePage := vulns.finish(), malicious.finish(), reputation.finish(), lifecycle.finish()
	for name, rows := range map[string]int{"vulnerabilities": len(vulnPage.rows), "malicious": len(malPage.rows), "reputation": len(repPage.rows), "lifecycle": len(lifePage.rows)} {
		if rows < 1 || rows >= limit {
			t.Fatalf("%s page holds %d rows, want the byte budget to cut it after at least one row", name, rows)
		}
	}
	datasets := syncDatasets{
		vulnerabilities: vulnPage.rows, vulnerabilitiesHaveMore: vulnPage.hasMore,
		malicious: malPage.rows, maliciousHaveMore: malPage.hasMore,
		reputation: repPage.rows, reputationHaveMore: repPage.hasMore,
		lifecycle: lifePage.rows, lifecycleHaveMore: lifePage.hasMore,
	}
	truncated, next := nextSyncExportCursor(db.SyncCursor{}, syncVulnerabilityRowKeyset, datasets, limit)
	if !truncated || next == nil || next.VulnerabilitiesDone || next.MaliciousDone || next.ReputationDone || next.LifecycleDone {
		t.Fatalf("oversized page = truncated %v next %+v, want every dataset to continue", truncated, next)
	}

	resp := synccontract.ResponseFromExport(&db.SyncExport{
		SyncedAt:        time.Unix(1700000000, 0).UTC(),
		SyncedXID:       math.MaxInt64,
		Vulnerabilities: datasets.vulnerabilities,
		Malicious:       datasets.malicious,
		Reputation:      datasets.reputation,
		Lifecycle:       datasets.lifecycle,
		Truncated:       truncated,
		NextCursor:      next,
	}, "healthy", map[string]string{"osv": "2026-11-01T00:00:00Z"})
	var body countingWriter
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(resp); err != nil {
		t.Fatalf("encode oversized page: %v", err)
	}
	if limit := synccontract.MaxResponseBytes - syncPageEnvelopeHeadroom; body.n > limit {
		t.Fatalf("oversized page encodes to %d bytes, want at most %d (client cap %d)", body.n, limit, synccontract.MaxResponseBytes)
	}
}

type countingWriter struct{ n int }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += len(p)
	return len(p), nil
}
