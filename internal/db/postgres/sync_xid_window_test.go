package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// syncTestEpoch5 is the first 64-bit transaction ID of transaction ID epoch 5,
// a database that passed the 32-bit wraparound five times.
const syncTestEpoch5 = int64(5) << 32

// syncTestXIDDistance mirrors syncXIDDistanceSQL with PostgreSQL's bigint
// semantics (% truncates toward zero, like Go's).
func syncTestXIDDistance(xmin uint32, watermark int64) int64 {
	return ((int64(xmin)-watermark)%4294967296 + 4294967296) % 4294967296
}

// syncTestXIDWindowWidth mirrors syncXIDWindowWidthSQL for the statement's
// next transaction ID next.
func syncTestXIDWindowWidth(watermark, next, outOfRange int64) int64 {
	if width := next - watermark; width >= 0 && width <= 2147483647 {
		return width
	}
	return outOfRange
}

// syncTestXIDAtOrAfter and syncTestXIDBefore mirror syncXIDAtOrAfterSQL and
// syncXIDBeforeSQL.
func syncTestXIDAtOrAfter(xmin uint32, watermark, next int64) bool {
	return syncTestXIDDistance(xmin, watermark) < syncTestXIDWindowWidth(watermark, next, 4294967296)
}

func syncTestXIDBefore(xmin uint32, watermark, next int64) bool {
	return syncTestXIDDistance(xmin, watermark) >= syncTestXIDWindowWidth(watermark, next, 0)
}

// TestSyncXIDWindowSQL pins the SQL that the evaluators of this file mirror:
// the distance modulo 2^32 from the watermark's low 32 bits to the 32-bit
// xmin, compared with the width of the window from the watermark to the
// statement's next transaction ID, which an out-of-range window replaces with
// a width that makes the condition true for every row.
func TestSyncXIDWindowSQL(t *testing.T) {
	t.Parallel()

	const (
		distance = "((((ap.xmin::text)::bigint - $3::bigint) % 4294967296 + 4294967296) % 4294967296)"
		width    = "(SELECT CASE WHEN xid_window.width BETWEEN 0 AND 2147483647 THEN xid_window.width ELSE %s END FROM (SELECT txid_snapshot_xmax(txid_current_snapshot()) - $3::bigint AS width) xid_window)"
	)
	if got := syncXIDDistanceSQL("ap.xmin", "$3"); got != distance {
		t.Fatalf("syncXIDDistanceSQL = %q, want %q", got, distance)
	}
	if got, want := syncXIDAtOrAfterSQL("ap.xmin", "$3"), distance+" < "+strings.Replace(width, "%s", "4294967296", 1); got != want {
		t.Fatalf("syncXIDAtOrAfterSQL = %q, want %q", got, want)
	}
	if got, want := syncXIDBeforeSQL("ap.xmin", "$3"), distance+" >= "+strings.Replace(width, "%s", "0", 1); got != want {
		t.Fatalf("syncXIDBeforeSQL = %q, want %q", got, want)
	}
}

// TestSyncXIDAtOrAfterComparesModulo2To32 evaluates the "changed since" leg
// of a delta past the first transaction ID epoch, where a raw comparison of
// the 32-bit xmin with the 64-bit since_xid never held: every row version a
// transaction from since_xid up to the statement's next transaction ID wrote
// counts as changed, also across the 32-bit wraparound, while older versions
// do not. A frozen or special xmin counts as changed only when it aliases into
// that window. An out-of-range window (since_xid more than 2^31 transactions
// old, or from the future) counts every row as changed.
func TestSyncXIDAtOrAfterComparesModulo2To32(t *testing.T) {
	t.Parallel()

	const (
		since = syncTestEpoch5 + 1000
		next  = syncTestEpoch5 + 2000
		// wrapSince lies 6 IDs before the 32-bit wraparound into epoch 6.
		wrapSince = syncTestEpoch5 + 4294967290
		wrapNext  = syncTestEpoch5 + 4294967296 + 20
	)
	for _, tt := range []struct {
		name              string
		xmin              uint32
		watermark, nextID int64
		want              bool
	}{
		{name: "row written after since_xid in epoch 5", xmin: 1500, watermark: since, nextID: next, want: true},
		{name: "since_xid itself", xmin: 1000, watermark: since, nextID: next, want: true},
		{name: "last transaction before the next ID", xmin: 1999, watermark: since, nextID: next, want: true},
		{name: "row written before since_xid", xmin: 999, watermark: since, nextID: next, want: false},
		{name: "oldest unfrozen row before since_xid", xmin: 4294967296 + 1000 - 2147483647, watermark: since, nextID: next, want: false},
		{name: "change after the wraparound", xmin: 5, watermark: wrapSince, nextID: wrapNext, want: true},
		{name: "change before the wraparound", xmin: 4294967295, watermark: wrapSince, nextID: wrapNext, want: true},
		{name: "row before since_xid across the wraparound", xmin: 4294967289, watermark: wrapSince, nextID: wrapNext, want: false},
		{name: "frozen xmin outside the window", xmin: 1000000, watermark: since, nextID: next, want: false},
		{name: "frozen xmin 2 outside the window", xmin: 2, watermark: since, nextID: next, want: false},
		{name: "frozen xmin 2 aliasing into a window across the wraparound", xmin: 2, watermark: wrapSince, nextID: wrapNext, want: true},
		{name: "empty window", xmin: 1000, watermark: since, nextID: since, want: false},
		{name: "widest window", xmin: 1000 + 2147483646, watermark: since, nextID: since + 2147483647, want: true},
		{name: "since_xid 2^31 transactions old", xmin: 999, watermark: since, nextID: since + 2147483648, want: true},
		{name: "since_xid from the future", xmin: 999, watermark: next + 1, nextID: next, want: true},
		{name: "epoch 0 change", xmin: 1500, watermark: 1000, nextID: 2000, want: true},
		{name: "epoch 0 older row", xmin: 500, watermark: 1000, nextID: 2000, want: false},
	} {
		if got := syncTestXIDAtOrAfter(tt.xmin, tt.watermark, tt.nextID); got != tt.want {
			t.Errorf("%s: at or after(xmin %d, watermark %d, next %d) = %v, want %v", tt.name, tt.xmin, tt.watermark, tt.nextID, got, tt.want)
		}
	}
}

// TestSyncXIDBeforeComparesModulo2To32 evaluates the snapshot upper bound past
// the first transaction ID epoch, where a raw comparison never excluded a
// row: only row versions a transaction from the snapshot ID up to the
// statement's next transaction ID wrote are excluded, also across the 32-bit
// wraparound. A frozen or special xmin outside that window stays included,
// and an out-of-range window (snapshot more than 2^31 transactions old, or
// from the future) excludes nothing, so a full export never loses an old row.
func TestSyncXIDBeforeComparesModulo2To32(t *testing.T) {
	t.Parallel()

	const (
		snapshot     = syncTestEpoch5 + 1000
		next         = syncTestEpoch5 + 2000
		wrapSnapshot = syncTestEpoch5 + 4294967290
		wrapNext     = syncTestEpoch5 + 4294967296 + 20
	)
	for _, tt := range []struct {
		name              string
		xmin              uint32
		watermark, nextID int64
		want              bool
	}{
		{name: "row written before the snapshot", xmin: 999, watermark: snapshot, nextID: next, want: true},
		{name: "snapshot xid itself", xmin: 1000, watermark: snapshot, nextID: next, want: false},
		{name: "row written after the snapshot in epoch 5", xmin: 1500, watermark: snapshot, nextID: next, want: false},
		{name: "row after the snapshot across the wraparound", xmin: 5, watermark: wrapSnapshot, nextID: wrapNext, want: false},
		{name: "row before the snapshot across the wraparound", xmin: 4294967289, watermark: wrapSnapshot, nextID: wrapNext, want: true},
		{name: "frozen ancient xmin", xmin: 3000000000, watermark: snapshot, nextID: next, want: true},
		{name: "frozen xmin 2", xmin: 2, watermark: snapshot, nextID: next, want: true},
		{name: "empty window", xmin: 1000, watermark: snapshot, nextID: snapshot, want: true},
		{name: "snapshot 2^31 transactions old", xmin: 1500, watermark: snapshot, nextID: snapshot + 2147483648, want: true},
		{name: "snapshot from the future", xmin: 1500, watermark: next + 1, nextID: next, want: true},
		{name: "epoch 0 row after the snapshot", xmin: 1500, watermark: 1000, nextID: 2000, want: false},
	} {
		if got := syncTestXIDBefore(tt.xmin, tt.watermark, tt.nextID); got != tt.want {
			t.Errorf("%s: before(xmin %d, watermark %d, next %d) = %v, want %v", tt.name, tt.xmin, tt.watermark, tt.nextID, got, tt.want)
		}
	}
}

// TestSyncXIDWindowsLeaveNoGap checks the hand-over between two syncs: a row
// version the snapshot bound of one sync excludes is matched as changed by the
// next delta, whose since_xid is that snapshot ID, however far its next
// transaction ID moved on (including past 2^31, where every row counts as
// changed). Within one in-range window the two conditions are exact
// complements.
func TestSyncXIDWindowsLeaveNoGap(t *testing.T) {
	t.Parallel()

	const snapshot = syncTestEpoch5 + 4294967000
	next := snapshot + 600 // crosses the 32-bit wraparound
	for _, xmin := range []uint32{0, 1, 2, 3, 4294966999, 4294967000, 4294967001, 4294967295, 100, 303, 304, 1 << 31} {
		if syncTestXIDBefore(xmin, snapshot, next) == syncTestXIDAtOrAfter(xmin, snapshot, next) {
			t.Errorf("xmin %d: before and at or after the snapshot agree within one window", xmin)
		}
		if syncTestXIDBefore(xmin, snapshot, next) {
			continue
		}
		for _, later := range []int64{next, next + 1, next + 1000000, snapshot + 2147483647, snapshot + 2147483648, snapshot + 1<<40} {
			if !syncTestXIDAtOrAfter(xmin, snapshot, later) {
				t.Errorf("xmin %d excluded by the snapshot bound (next %d) is not changed for the next delta (next %d)", xmin, next, later)
			}
		}
	}
}

// TestSyncWindowFiltersCompareXIDsEpochSafe pins the transaction ID filters of
// the row-paged datasets (malicious, reputation) and of the lifecycle
// dataset: the snapshot bound and the delta's since_xid leg use the epoch-safe
// conditions on the bare xmin column with the 64-bit watermarks bound as text.
func TestSyncWindowFiltersCompareXIDsEpochSafe(t *testing.T) {
	t.Parallel()

	since := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	opts := db.SyncExportOptions{Since: &since, SinceXID: 5<<32 | 7}

	query := "WHERE true"
	args := []any{since.Add(time.Hour)}
	addSyncWindowFilters(&query, &args, opts, 5<<32|42, "updated_at", "mf.xmin")
	if want := "WHERE true AND " + syncXIDBeforeSQL("mf.xmin", "$2") + " AND (updated_at >= $3 OR " + syncXIDAtOrAfterSQL("mf.xmin", "$4") + ")"; query != want {
		t.Fatalf("window filters = %q, want %q", query, want)
	}
	if len(args) != 4 || args[1] != "21474836522" || args[3] != "21474836487" {
		t.Fatalf("window filter args = %#v, want the 64-bit snapshot and since xids as text", args)
	}

	lifecycle := newSyncLifecycleQueryArgs(opts, since.Add(time.Hour), 5<<32|42)
	if lifecycle.args[1] != "21474836522" || lifecycle.args[3] != "21474836487" {
		t.Fatalf("lifecycle args = %#v, want the 64-bit snapshot xid as $2 and since xid as $4", lifecycle.args)
	}
	active := strings.Join(lifecycle.activeFilters, "\n")
	tombstones := strings.Join(lifecycle.tombstoneFilters, "\n")
	for _, alias := range []string{"m", "p", "r"} {
		for _, want := range []string{syncXIDBeforeSQL(alias+".xmin", "$2"), syncXIDAtOrAfterSQL(alias+".xmin", "$4")} {
			if !strings.Contains(active, want) {
				t.Fatalf("lifecycle active filters miss %q in:\n%s", want, active)
			}
		}
	}
	for _, want := range []string{syncXIDBeforeSQL("t.xmin", "$2"), syncXIDAtOrAfterSQL("t.xmin", "$4")} {
		if !strings.Contains(tombstones, want) {
			t.Fatalf("lifecycle tombstone filters miss %q in:\n%s", want, tombstones)
		}
	}
	for _, filters := range []string{active, tombstones} {
		for _, forbidden := range []string{"::bigint >= $", "::bigint < $"} {
			if strings.Contains(filters, forbidden) {
				t.Fatalf("lifecycle filters compare a raw xmin with %q:\n%s", forbidden, filters)
			}
		}
	}

	for name, column := range map[string]string{"exportSyncMalicious": "`mf.xmin`,", "exportSyncReputation": "`prc.xmin`,"} {
		source := postgresFunctionSource(t, "sync.go", name)
		if !strings.Contains(source, column) || strings.Contains(source, "xmin::text") {
			t.Fatalf("%s must pass the bare xmin column %s to addSyncWindowFilters:\n%s", name, column, source)
		}
	}
}
