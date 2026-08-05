package db

import "testing"

func TestRefreshStatusConstantsAndGroups(t *testing.T) {
	t.Parallel()

	if got := RefreshStatuses(); !sameStrings(got, []string{
		RefreshStatusPending,
		RefreshStatusProcessing,
		RefreshStatusPaused,
		RefreshStatusDone,
		RefreshStatusError,
	}) {
		t.Fatalf("RefreshStatuses() = %#v", got)
	}
	if got := ActiveRefreshStatuses(); !sameStrings(got, []string{RefreshStatusPending, RefreshStatusProcessing, RefreshStatusPaused}) {
		t.Fatalf("ActiveRefreshStatuses() = %#v", got)
	}
	if got := DrainableRefreshStatuses(); !sameStrings(got, []string{RefreshStatusPending, RefreshStatusProcessing}) {
		t.Fatalf("DrainableRefreshStatuses() = %#v", got)
	}
	if got := TerminalRefreshStatuses(); !sameStrings(got, []string{RefreshStatusDone, RefreshStatusError}) {
		t.Fatalf("TerminalRefreshStatuses() = %#v", got)
	}
	if got := ClearableRefreshStatuses(); !sameStrings(got, []string{RefreshStatusPending, RefreshStatusPaused, RefreshStatusDone, RefreshStatusError}) {
		t.Fatalf("ClearableRefreshStatuses() = %#v", got)
	}
	if got := RetryableRefreshStatuses(); !sameStrings(got, []string{RefreshStatusDone, RefreshStatusError, RefreshStatusPaused}) {
		t.Fatalf("RetryableRefreshStatuses() = %#v", got)
	}
}

func TestRefreshStatusNormalizationAndPredicates(t *testing.T) {
	t.Parallel()

	normalized, ok := NormalizeRefreshStatus(" PENDING ")
	if !ok || normalized != RefreshStatusPending {
		t.Fatalf("NormalizeRefreshStatus(PENDING) = %q, %v", normalized, ok)
	}
	if normalized, ok := NormalizeRefreshStatus("failed"); ok || normalized != "" {
		t.Fatalf("NormalizeRefreshStatus(failed) = %q, %v; want invalid", normalized, ok)
	}

	if !IsActiveRefreshStatus(RefreshStatusPending) || !IsActiveRefreshStatus(RefreshStatusProcessing) {
		t.Fatal("pending and processing must be active refresh statuses")
	}
	if !IsActiveRefreshStatus(RefreshStatusPaused) {
		t.Fatal("paused must remain active for deduplication")
	}
	if IsActiveRefreshStatus(RefreshStatusDone) || IsActiveRefreshStatus(RefreshStatusError) {
		t.Fatal("terminal statuses must not be active refresh statuses")
	}
	if !IsDrainableRefreshStatus(RefreshStatusPending) || !IsDrainableRefreshStatus(RefreshStatusProcessing) {
		t.Fatal("pending and processing must be drainable refresh statuses")
	}
	if IsDrainableRefreshStatus(RefreshStatusPaused) || IsDrainableRefreshStatus(RefreshStatusDone) || IsDrainableRefreshStatus(RefreshStatusError) {
		t.Fatal("paused and terminal statuses must not be drainable refresh statuses")
	}
	if !IsTerminalRefreshStatus(RefreshStatusDone) || !IsTerminalRefreshStatus(RefreshStatusError) {
		t.Fatal("done and error must be terminal refresh statuses")
	}
	if IsTerminalRefreshStatus(RefreshStatusPending) || IsTerminalRefreshStatus(RefreshStatusProcessing) || IsTerminalRefreshStatus(RefreshStatusPaused) {
		t.Fatal("pending, processing, and paused must not be terminal refresh statuses")
	}
	if CanClearRefreshStatus(RefreshStatusProcessing) {
		t.Fatal("processing queue jobs must not be clearable")
	}
	if !CanClearRefreshStatus(RefreshStatusPending) || !CanClearRefreshStatus(RefreshStatusPaused) ||
		!CanClearRefreshStatus(RefreshStatusDone) || !CanClearRefreshStatus(RefreshStatusError) {
		t.Fatal("pending, paused, done, and error queue jobs must be clearable")
	}
}

func TestNormalizeClearableRefreshStatusesFiltersDeduplicatesAndPreservesOrder(t *testing.T) {
	t.Parallel()

	got := NormalizeClearableRefreshStatuses([]string{
		" pending ",
		"PROCESSING",
		"PAUSED",
		"bogus",
		"done",
		"pending",
		"error",
		"",
	})
	want := []string{RefreshStatusPending, RefreshStatusPaused, RefreshStatusDone, RefreshStatusError}
	if !sameStrings(got, want) {
		t.Fatalf("NormalizeClearableRefreshStatuses() = %#v, want %#v", got, want)
	}
}

func TestDrainableRefreshStatusPredicateSQL(t *testing.T) {
	t.Parallel()

	if got, want := DrainableRefreshStatusPredicateSQL(), "status IN ('pending', 'processing')"; got != want {
		t.Fatalf("DrainableRefreshStatusPredicateSQL() = %q, want %q", got, want)
	}
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
