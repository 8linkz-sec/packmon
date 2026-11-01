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
// xmin is compared with the low 32 bits of the 64-bit, epoch-extended
// snapshot ID modulo 2^32, and only while the snapshot is at most 2^31
// transactions old. Without a snapshot transaction ID the check cannot prove
// anything, so the split is never reported complete.
func TestSyncSplitAdvisoryUnchangedQuery(t *testing.T) {
	t.Parallel()

	snapshot := time.Unix(1700000000, 0).UTC()
	const epochXID = uint64(5)<<32 | 42
	query, args, ok := buildSyncSplitAdvisoryUnchangedQuery("GHSA-big", snapshot, epochXID)
	if !ok {
		t.Fatal("split advisory check with a snapshot xid is disabled, want it built")
	}
	if !slices.Equal(args, []any{snapshot, "GHSA-big", "42", strconv.FormatUint(epochXID, 10)}) {
		t.Fatalf("split advisory check args = %v, want snapshot, id, the 32-bit snapshot xid 42, and the 64-bit snapshot xid", args)
	}
	normalized := strings.Join(strings.Fields(query), " ")
	notBefore := func(column string) string {
		return "(((" + column + "::text)::bigint - $3::bigint + 4294967296) % 4294967296) < 2147483648"
	}
	for _, want := range []string{
		"SELECT txid_snapshot_xmax(txid_current_snapshot()) - $4::bigint BETWEEN 0 AND 2147483647",
		"AND EXISTS ( SELECT 1 FROM vulnerabilities v WHERE v.id = $2 AND v.updated_at <= $1 AND NOT " + notBefore("v.xmin") + " )",
		"AND NOT EXISTS ( SELECT 1 FROM affected_packages ap WHERE ap.vulnerability_id = $2 AND (ap.updated_at > $1 OR " + notBefore("ap.xmin") + ") )",
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

// TestSyncXIDNotBeforeSnapshotComparesModulo2To32 evaluates the condition of
// syncXIDNotBeforeSnapshotSQL, with PostgreSQL's integer semantics, across the
// 32-bit wraparound: an xmin at or up to 2^31 - 1 after the snapshot ID counts
// as not before the snapshot (a change the check must see), also when the
// transaction ID counter wrapped between them, and an xmin up to 2^31 before
// it counts as older.
func TestSyncXIDNotBeforeSnapshotComparesModulo2To32(t *testing.T) {
	t.Parallel()

	if got, want := syncXIDNotBeforeSnapshotSQL("ap.xmin", "$3"), "(((ap.xmin::text)::bigint - $3::bigint + 4294967296) % 4294967296) < 2147483648"; got != want {
		t.Fatalf("syncXIDNotBeforeSnapshotSQL = %q, want %q", got, want)
	}
	notBefore := func(xmin, snapshot int64) bool {
		return (xmin-snapshot+4294967296)%4294967296 < 2147483648
	}
	for _, tt := range []struct {
		name           string
		xmin, snapshot int64
		want           bool
	}{
		{name: "snapshot xmin itself", xmin: 1000, snapshot: 1000, want: true},
		{name: "after the snapshot", xmin: 1001, snapshot: 1000, want: true},
		{name: "before the snapshot", xmin: 999, snapshot: 1000, want: false},
		{name: "after the snapshot across the wraparound", xmin: 5, snapshot: 4294967290, want: true},
		{name: "before the snapshot across the wraparound", xmin: 4294967290, snapshot: 5, want: false},
		{name: "furthest change after the snapshot", xmin: 1000 + 2147483647, snapshot: 1000, want: true},
		{name: "furthest version before the snapshot", xmin: 4294967296 + 1000 - 2147483648, snapshot: 1000, want: false},
	} {
		if got := notBefore(tt.xmin, tt.snapshot); got != tt.want {
			t.Fatalf("%s: not before(xmin %d, snapshot %d) = %v, want %v", tt.name, tt.xmin, tt.snapshot, got, tt.want)
		}
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
