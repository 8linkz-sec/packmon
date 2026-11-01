package db

import (
	"testing"
	"time"
)

func TestSyncCursorZeroAndEffectiveCursor(t *testing.T) {
	t.Parallel()

	if !(SyncCursor{}).IsZero() {
		t.Fatal("empty cursor should be zero")
	}
	if (SyncCursor{Malicious: 1}).IsZero() {
		t.Fatal("cursor with offset should not be zero")
	}

	explicit := SyncCursor{Vulnerabilities: 1, Malicious: 2, Reputation: 3, Lifecycle: 4}
	if got := (SyncExportOptions{Cursor: explicit, Offset: 99}).EffectiveCursor(); got != explicit {
		t.Fatalf("EffectiveCursor(explicit) = %+v, want %+v", got, explicit)
	}
	if got := (SyncExportOptions{Offset: 25}).EffectiveCursor(); got != (SyncCursor{Vulnerabilities: 25, Malicious: 25, Reputation: 25, Lifecycle: 25}) {
		t.Fatalf("EffectiveCursor(offset) = %+v", got)
	}
	if got := (SyncExportOptions{Offset: 0, SnapshotAt: time.Now()}).EffectiveCursor(); !got.IsZero() {
		t.Fatalf("EffectiveCursor(no offset) = %+v, want zero", got)
	}
}

func TestEffectiveCursorMarksReputationDoneWhenExcluded(t *testing.T) {
	t.Parallel()

	// Legacy offset-only clients keep their offset expansion; the reputation
	// dataset is reported as exhausted so it is never queried or paginated.
	if got := (SyncExportOptions{Offset: 25, ExcludeReputation: true}).EffectiveCursor(); got != (SyncCursor{
		Vulnerabilities: 25, Malicious: 25, Reputation: 25, Lifecycle: 25, ReputationDone: true,
	}) {
		t.Fatalf("EffectiveCursor(offset, excluded) = %+v", got)
	}
	explicit := SyncCursor{VulnerabilitiesCursor: "v", ReputationCursor: "r"}
	if got := (SyncExportOptions{Cursor: explicit, ExcludeReputation: true}).EffectiveCursor(); got != (SyncCursor{
		VulnerabilitiesCursor: "v", ReputationDone: true,
	}) {
		t.Fatalf("EffectiveCursor(explicit, excluded) = %+v, want reputation cursor dropped and done", got)
	}
	if got := (SyncExportOptions{ExcludeReputation: true}).EffectiveCursor(); got != (SyncCursor{ReputationDone: true}) {
		t.Fatalf("EffectiveCursor(first page, excluded) = %+v, want only reputation done", got)
	}
}
