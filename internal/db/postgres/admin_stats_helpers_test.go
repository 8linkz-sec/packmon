package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestNormalizeQueueStatusesFiltersDeduplicatesAndPreservesOrder(t *testing.T) {
	t.Parallel()

	got := normalizeQueueStatuses([]string{
		" pending ",
		"PAUSED",
		"bogus",
		"done",
		"pending",
		"error",
		"",
	})
	want := []string{"pending", "paused", "done", "error"}
	if len(got) != len(want) {
		t.Fatalf("len(normalizeQueueStatuses) = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalizeQueueStatuses[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCountScansByDayQueryUsesScannedAtRange(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("admin_stats.go")
	if err != nil {
		t.Fatalf("read admin_stats.go: %v", err)
	}
	text := string(source)
	if strings.Contains(text, "timezone('UTC', scan_log.scanned_at)::date = days.day") {
		t.Fatal("CountScansByDay must not wrap scan_log.scanned_at in a date expression; keep the scanned_at index usable")
	}
	for _, want := range []string{
		"scan_log.scanned_at >= days.day",
		"scan_log.scanned_at < days.day + INTERVAL '1 day'",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("CountScansByDay query missing sargable range marker %q", want)
		}
	}
}

func TestExportSyncLifecycleUsesIndexableTimestampFilters(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("sync.go")
	if err != nil {
		t.Fatalf("read sync.go: %v", err)
	}
	text := string(source)
	if strings.Contains(text, "GREATEST(m.updated_at, p.updated_at, r.updated_at)") {
		t.Fatal("exportSyncLifecycle must not filter lifecycle deltas through a cross-table GREATEST timestamp expression")
	}
	for _, want := range []string{
		"m.updated_at <= $1",
		"p.updated_at <= $1",
		"r.updated_at <= $1",
		"m.updated_at >= $",
		"p.updated_at >= $",
		"r.updated_at >= $",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("exportSyncLifecycle query missing indexable lifecycle timestamp marker %q", want)
		}
	}
}
