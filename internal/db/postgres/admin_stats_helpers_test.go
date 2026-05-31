package postgres

import "testing"

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
