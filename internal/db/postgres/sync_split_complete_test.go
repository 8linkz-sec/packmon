package postgres

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// TestSyncSplitPagesNameTheirAdvisoryAndItsLastPage pins the split markers:
// the page that starts splitting an oversized advisory and every page that
// continues it name that advisory, only the page that starts it is marked as
// the start, only the page that exhausts its rows is the last page of the
// split (the one that may report the split complete), and whole-advisory and
// legacy row pages never name a split advisory.
func TestSyncSplitPagesNameTheirAdvisoryAndItsLastPage(t *testing.T) {
	t.Parallel()

	b := newSyncVulnerabilityPageBuilder(syncVulnerabilityAdvisoryPages, 10, "", 10000)
	for i := range 4 {
		b.add(budgetRow(t, "GHSA-big", "big"+strconv.Itoa(i), 3000), false, false)
	}
	if page := b.finish(); page.splitAdvisoryID != "GHSA-big" || !page.splitStart || page.splitLast {
		t.Fatalf("split start page names %q (start %v, last %v), want the start of GHSA-big with more split pages", page.splitAdvisoryID, page.splitStart, page.splitLast)
	}

	b = newSyncVulnerabilityPageBuilder(syncVulnerabilityAdvisorySplit, 10, "GHSA-big", 10000)
	for i := range 4 {
		b.add(budgetRow(t, "GHSA-big", "big"+strconv.Itoa(i), 3000), false, false)
	}
	if page := b.finish(); page.splitAdvisoryID != "GHSA-big" || page.splitStart || page.splitLast {
		t.Fatalf("cut split page names %q (start %v, last %v), want a continuation of GHSA-big with more split pages", page.splitAdvisoryID, page.splitStart, page.splitLast)
	}
	for _, rows := range [][]db.SyncVulnerability{{budgetRow(t, "GHSA-big", "last", 3000)}, nil} {
		b = newSyncVulnerabilityPageBuilder(syncVulnerabilityAdvisorySplit, 10, "GHSA-big", 10000)
		for _, row := range rows {
			b.add(row, false, false)
		}
		if page := b.finish(); page.splitAdvisoryID != "GHSA-big" || page.splitStart || !page.splitLast {
			t.Fatalf("finished split page with %d rows names %q (start %v, last %v), want the last page of GHSA-big", len(rows), page.splitAdvisoryID, page.splitStart, page.splitLast)
		}
	}

	b = newSyncVulnerabilityPageBuilder(syncVulnerabilityAdvisoryPages, 10, "", 10000)
	b.add(budgetRow(t, "GHSA-a", "a1", 3000), false, true)
	b.add(budgetRow(t, "GHSA-b", "b1", 3000), false, true)
	b.add(budgetRow(t, "GHSA-c", "c1", 6000), false, true)
	if page := b.finish(); page.splitAdvisoryID != "" || page.splitStart || page.splitLast {
		t.Fatalf("whole-advisory page names split advisory %q (start %v, last %v), want none", page.splitAdvisoryID, page.splitStart, page.splitLast)
	}
	for _, paging := range []syncVulnerabilityPaging{syncVulnerabilityRowKeyset, syncVulnerabilityDeltaRowOffset} {
		b = newSyncVulnerabilityPageBuilder(paging, 10, "", 10000)
		for i := range 4 {
			b.add(budgetRow(t, "GHSA-big", "big"+strconv.Itoa(i), 3000), false, false)
		}
		if page := b.finish(); page.splitAdvisoryID != "" || page.splitStart || page.splitLast {
			t.Fatalf("paging %v row page names split advisory %q (start %v, last %v), want none", paging, page.splitAdvisoryID, page.splitStart, page.splitLast)
		}
	}
}

// TestSyncSplitAdvisoryUnchangedQuery pins the check behind
// vulnerability_split_complete: the split advisory's vulnerability row and
// every affected row of it (in any ecosystem) still carry versions from
// before the pinned snapshot, by timestamp and by transaction ID. The 32-bit
// xmin is compared with the 64-bit, epoch-extended snapshot ID modulo 2^32
// (syncXIDAtOrAfterSQL), which counts every row as changed once the snapshot
// is more than 2^31 transactions old, so the vulnerability row must provably
// predate the snapshot (NOT at or after it, never the fail-open
// syncXIDBeforeSQL). Without a snapshot transaction ID the check cannot prove
// anything, so the split is never reported complete.
func TestSyncSplitAdvisoryUnchangedQuery(t *testing.T) {
	t.Parallel()

	snapshot := time.Unix(1700000000, 0).UTC()
	const epochXID = uint64(5)<<32 | 42
	query, args, ok := buildSyncSplitAdvisoryUnchangedQuery("GHSA-big", snapshot, epochXID)
	if !ok {
		t.Fatal("split advisory check with a snapshot xid is disabled, want it built")
	}
	if !slices.Equal(args, []any{snapshot, "GHSA-big", strconv.FormatUint(epochXID, 10)}) {
		t.Fatalf("split advisory check args = %v, want snapshot, id, and the 64-bit snapshot xid as text", args)
	}
	normalized := strings.Join(strings.Fields(query), " ")
	for _, want := range []string{
		"SELECT EXISTS ( SELECT 1 FROM vulnerabilities v WHERE v.id = $2 AND v.updated_at <= $1 AND NOT " + syncXIDAtOrAfterSQL("v.xmin", "$3") + " )",
		"AND NOT EXISTS ( SELECT 1 FROM affected_packages ap WHERE ap.vulnerability_id = $2 AND (ap.updated_at > $1 OR " + syncXIDAtOrAfterSQL("ap.xmin", "$3") + ") )",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("split advisory check missing %q in:\n%s", want, query)
		}
	}
	if strings.Contains(normalized, "ecosystem") {
		t.Fatalf("split advisory check must cover affected rows of every ecosystem:\n%s", query)
	}

	if _, _, ok := buildSyncSplitAdvisoryUnchangedQuery("GHSA-big", snapshot, 0); ok {
		t.Fatal("split advisory check without a snapshot xid is enabled, want the split never reported complete")
	}
}

// TestNewSyncExportCarriesTheSplitMarkers passes the split markers of the
// vulnerability page to the export: the split advisory on every page of a
// split, and the start and completeness markers only together with it.
func TestNewSyncExportCarriesTheSplitMarkers(t *testing.T) {
	t.Parallel()

	since := time.Unix(1700000000, 0).UTC()
	opts := db.SyncExportOptions{
		Since: &since,
		Limit: 10,
		Cursor: db.SyncCursor{
			VulnerabilitiesCursor: db.EncodeSyncAdvisoryRowCursor("GHSA-big", "npm", "big2"),
			MaliciousDone:         true, ReputationDone: true, LifecycleDone: true,
		},
	}
	datasets := syncDatasets{
		vulnerabilities:              []db.SyncVulnerability{{ID: "GHSA-big", Ecosystem: "npm", Name: "big3"}},
		vulnerabilitiesHaveMore:      true,
		vulnerabilitiesNextCursor:    db.EncodeSyncAdvisoryCursor("GHSA-big"),
		vulnerabilitiesSplit:         true,
		vulnerabilitiesSplitAdvisory: "GHSA-big",
		vulnerabilitiesSplitComplete: true,
	}
	export := newSyncExport(opts, opts.EffectiveCursor(), since.Add(time.Hour), 42, datasets)
	if export.VulnerabilitySplitAdvisory != "GHSA-big" || !export.VulnerabilitySplitComplete {
		t.Fatalf("export split markers = %q / %v, want GHSA-big complete", export.VulnerabilitySplitAdvisory, export.VulnerabilitySplitComplete)
	}
	if export.VulnerabilityAffectedComplete || !export.Truncated || export.NextCursor == nil || export.VulnerabilitySplitStart {
		t.Fatalf("last split page export = complete %v truncated %v next %+v start %v, want an unflagged continuation page that continues", export.VulnerabilityAffectedComplete, export.Truncated, export.NextCursor, export.VulnerabilitySplitStart)
	}
	datasets.vulnerabilitiesSplitStart, datasets.vulnerabilitiesSplitComplete = true, false
	if export := newSyncExport(opts, opts.EffectiveCursor(), since.Add(time.Hour), 42, datasets); !export.VulnerabilitySplitStart || export.VulnerabilitySplitComplete {
		t.Fatalf("split start export = start %v complete %v, want the start marker only", export.VulnerabilitySplitStart, export.VulnerabilitySplitComplete)
	}

	datasets.vulnerabilitiesSplitAdvisory, datasets.vulnerabilitiesSplitComplete = "", true
	if export := newSyncExport(opts, opts.EffectiveCursor(), since.Add(time.Hour), 42, datasets); export.VulnerabilitySplitAdvisory != "" || export.VulnerabilitySplitStart || export.VulnerabilitySplitComplete {
		t.Fatalf("export without a split advisory = %q / %v / %v, want no split markers", export.VulnerabilitySplitAdvisory, export.VulnerabilitySplitStart, export.VulnerabilitySplitComplete)
	}
}
