package postgres

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// TestNewSyncLifecycleQueryArgsAlwaysBoundsTheSnapshot covers the base filters.
// Every lifecycle sync query is bounded by the snapshot timestamp so a row
// written mid-export cannot appear in one page but not the next.
func TestNewSyncLifecycleQueryArgsAlwaysBoundsTheSnapshot(t *testing.T) {
	t.Parallel()

	snapshot := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	args := newSyncLifecycleQueryArgs(db.SyncExportOptions{}, snapshot, 0)

	if len(args.args) != 1 || args.args[0] != snapshot {
		t.Fatalf("args = %v, want the snapshot as the only bind value", args.args)
	}
	if len(args.activeFilters) != 3 {
		t.Fatalf("active filters = %q, want the three snapshot bounds", args.activeFilters)
	}
	for _, filter := range args.activeFilters {
		if !strings.Contains(filter, "$1") {
			t.Errorf("filter %q does not bind the snapshot", filter)
		}
	}
	if len(args.tombstoneFilters) != 1 {
		t.Fatalf("tombstone filters = %q, want one snapshot bound", args.tombstoneFilters)
	}
}

// TestSyncLifecycleQueryArgsAddsTheSnapshotXID covers the transaction-ID bound
// that complements the timestamp. Timestamps alone cannot exclude a transaction
// that committed late with an earlier updated_at, which would let a client miss
// a row permanently.
func TestSyncLifecycleQueryArgsAddsTheSnapshotXID(t *testing.T) {
	t.Parallel()

	snapshot := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

	without := newSyncLifecycleQueryArgs(db.SyncExportOptions{}, snapshot, 0)
	with := newSyncLifecycleQueryArgs(db.SyncExportOptions{}, snapshot, 4242)

	if len(with.args) <= len(without.args) {
		t.Fatalf("a snapshot XID added no bind value: %v", with.args)
	}
	if len(with.tombstoneFilters) <= len(without.tombstoneFilters) {
		t.Fatalf("a snapshot XID added no tombstone bound: %q", with.tombstoneFilters)
	}
	// The XID is bound as a string so it survives values above int64 range.
	found := false
	for _, arg := range with.args {
		if text, ok := arg.(string); ok && text == strconv.FormatUint(4242, 10) {
			found = true
		}
	}
	if !found {
		t.Fatalf("args = %v, want the snapshot XID bound as text", with.args)
	}
}

// TestSyncLifecycleQueryArgsAddsADeltaWindow covers the incremental sync path.
// Without the Since bound every sync would be a full export, and with a wrong
// one a client would silently skip rows changed in between.
func TestSyncLifecycleQueryArgsAddsADeltaWindow(t *testing.T) {
	t.Parallel()

	snapshot := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	since := snapshot.Add(-24 * time.Hour)

	base := newSyncLifecycleQueryArgs(db.SyncExportOptions{}, snapshot, 0)
	delta := newSyncLifecycleQueryArgs(db.SyncExportOptions{Since: &since}, snapshot, 0)

	if len(delta.args) <= len(base.args) {
		t.Fatalf("the delta window added no bind value: %v", delta.args)
	}
	if len(delta.activeFilters) <= len(base.activeFilters) {
		t.Fatalf("the delta window added no active filter: %q", delta.activeFilters)
	}
	// Since is normalised to UTC before binding, so a client in another zone
	// cannot shift the window.
	found := false
	for _, arg := range delta.args {
		if stamp, ok := arg.(time.Time); ok && stamp.Equal(since) && stamp.Location() == time.UTC {
			found = true
		}
	}
	if !found {
		t.Fatalf("args = %v, want the Since bound in UTC", delta.args)
	}
}

// TestSyncLifecycleQueryArgsCombinesTheDeltaWindowWithItsXID covers the paired
// form used by a resuming client: both the timestamp and the transaction ID
// widen the window, because either alone can miss a late-committing row.
func TestSyncLifecycleQueryArgsCombinesTheDeltaWindowWithItsXID(t *testing.T) {
	t.Parallel()

	snapshot := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	since := snapshot.Add(-time.Hour)

	timeOnly := newSyncLifecycleQueryArgs(db.SyncExportOptions{Since: &since}, snapshot, 0)
	withXID := newSyncLifecycleQueryArgs(
		db.SyncExportOptions{Since: &since, SinceXID: 99}, snapshot, 0,
	)

	if len(withXID.args) <= len(timeOnly.args) {
		t.Fatalf("SinceXID added no bind value: %v", withXID.args)
	}

	joined := strings.Join(withXID.activeFilters, "\n")
	if !strings.Contains(joined, "xmin") {
		t.Fatalf("active filters do not consider xmin:\n%s", joined)
	}
	// The delta filter is a disjunction: a row qualifies by timestamp OR by xid.
	// An AND here would drop rows that only one half matches.
	if !strings.Contains(joined, "OR") {
		t.Fatalf("the delta filter is not a disjunction:\n%s", joined)
	}
}

// TestSyncLifecycleQueryArgsAppendArgReturnsOneBasedPositions pins the numbering
// the filter strings interpolate. An off-by-one here would bind a filter to the
// wrong value, which PostgreSQL would accept whenever the types happen to match.
func TestSyncLifecycleQueryArgsAppendArgReturnsOneBasedPositions(t *testing.T) {
	t.Parallel()

	var args syncLifecycleQueryArgs
	if got := args.appendArg("first"); got != 1 {
		t.Fatalf("first appendArg = %d, want 1", got)
	}
	if got := args.appendArg("second"); got != 2 {
		t.Fatalf("second appendArg = %d, want 2", got)
	}
	if len(args.args) != 2 || args.args[0] != "first" || args.args[1] != "second" {
		t.Fatalf("args = %v, want both values in order", args.args)
	}
}

// TestNormalizeUnknownSeverityCVEIDPageLimitBoundsThePage covers the cap on the
// severity-backfill page size. An unbounded limit would let one request pull the
// whole table into memory.
func TestNormalizeUnknownSeverityCVEIDPageLimitBoundsThePage(t *testing.T) {
	t.Parallel()

	for limit, want := range map[int]int{
		0:                                    0,
		-1:                                   0,
		1:                                    1,
		500:                                  500,
		maxUnknownSeverityCVEIDPageLimit:     maxUnknownSeverityCVEIDPageLimit,
		maxUnknownSeverityCVEIDPageLimit + 1: maxUnknownSeverityCVEIDPageLimit,
		1 << 30:                              maxUnknownSeverityCVEIDPageLimit,
	} {
		if got := normalizeUnknownSeverityCVEIDPageLimit(limit); got != want {
			t.Errorf("normalizeUnknownSeverityCVEIDPageLimit(%d) = %d, want %d", limit, got, want)
		}
	}
}

// TestExpectedSystemSettingsUpdatedAtPicksTheOptimisticLockValue covers the
// source of the revision check for system settings. Reading the wrong field
// would either skip the concurrency check entirely or reject every valid save.
func TestExpectedSystemSettingsUpdatedAtPicksTheOptimisticLockValue(t *testing.T) {
	t.Parallel()

	if _, ok := expectedSystemSettingsUpdatedAt(nil); ok {
		t.Error("nil settings produced an expected revision")
	}
	if _, ok := expectedSystemSettingsUpdatedAt(&db.SystemSettings{}); ok {
		t.Error("settings without any timestamp produced an expected revision")
	}

	updatedAt := time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)
	got, ok := expectedSystemSettingsUpdatedAt(&db.SystemSettings{UpdatedAt: updatedAt})
	if !ok || !got.Equal(updatedAt) {
		t.Fatalf("UpdatedAt fallback = %v, %v; want %v, true", got, ok, updatedAt)
	}

	// An explicit ExpectedUpdatedAt wins, including the zero value, which is how
	// a form says "this row must not exist yet".
	expected := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	got, ok = expectedSystemSettingsUpdatedAt(&db.SystemSettings{
		UpdatedAt:         updatedAt,
		ExpectedUpdatedAt: &expected,
	})
	if !ok || !got.Equal(expected) {
		t.Fatalf("ExpectedUpdatedAt = %v, %v; want %v, true", got, ok, expected)
	}

	var zero time.Time
	got, ok = expectedSystemSettingsUpdatedAt(&db.SystemSettings{
		UpdatedAt:         updatedAt,
		ExpectedUpdatedAt: &zero,
	})
	if !ok {
		t.Fatal("an explicit zero ExpectedUpdatedAt was ignored")
	}
	if !got.IsZero() {
		t.Fatalf("expected revision = %v, want the zero time preserved", got)
	}
}
