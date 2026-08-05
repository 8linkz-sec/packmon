package sqlite

import (
	"strings"
	"testing"
	"time"
)

// TestLocalSearchCollectorLimitCoversPagination pins the collector budget used
// by local package search. Each collector has to fetch limit+offset rows so the
// merged, re-sorted result set can still serve the requested page; returning
// only `limit` would silently drop matches on every page after the first.
func TestLocalSearchCollectorLimitCoversPagination(t *testing.T) {
	t.Parallel()

	if got := localSearchCollectorLimit(50, 0); got != 50 {
		t.Errorf("localSearchCollectorLimit(50, 0) = %d, want 50", got)
	}
	if got := localSearchCollectorLimit(50, -5); got != 50 {
		t.Errorf("localSearchCollectorLimit(50, -5) = %d, want 50 for a negative offset", got)
	}
	if got := localSearchCollectorLimit(50, 100); got != 150 {
		t.Errorf("localSearchCollectorLimit(50, 100) = %d, want 150", got)
	}
}

// TestLocalSearchCollectorLimitSaturatesInsteadOfOverflowing is the reason the
// function exists at all: limit+offset must not wrap to a negative number, which
// would turn the SQL LIMIT into an error or an empty result.
func TestLocalSearchCollectorLimitSaturatesInsteadOfOverflowing(t *testing.T) {
	t.Parallel()

	maxInt := int(^uint(0) >> 1)

	if got := localSearchCollectorLimit(maxInt, 1); got != maxInt {
		t.Errorf("localSearchCollectorLimit(maxInt, 1) = %d, want saturation at maxInt", got)
	}
	if got := localSearchCollectorLimit(maxInt-1, 10); got != maxInt {
		t.Errorf("localSearchCollectorLimit(maxInt-1, 10) = %d, want saturation at maxInt", got)
	}
	if got := localSearchCollectorLimit(maxInt, maxInt); got != maxInt {
		t.Errorf("localSearchCollectorLimit(maxInt, maxInt) = %d, want saturation at maxInt", got)
	}
	if got := localSearchCollectorLimit(10, 20); got < 0 {
		t.Errorf("localSearchCollectorLimit produced a negative budget %d", got)
	}
}

// TestSyncDateValueNormalisesEveryAcceptedShape covers the date coercion used
// when importing lifecycle rows from the server. The column stores a plain date,
// so an RFC3339 timestamp has to be reduced to one -- storing the raw string
// would make later date comparisons silently wrong.
func TestSyncDateValueNormalisesEveryAcceptedShape(t *testing.T) {
	t.Parallel()

	dateOnly := "2026-08-04"
	if got, err := syncDateValue("eol", &dateOnly); err != nil || got != "2026-08-04" {
		t.Fatalf("syncDateValue(date-only) = %v, %v; want 2026-08-04", got, err)
	}

	timestamp := "2026-08-04T22:15:30.5Z"
	got, err := syncDateValue("eol", &timestamp)
	if err != nil {
		t.Fatalf("syncDateValue(RFC3339) error = %v", err)
	}
	if got != "2026-08-04" {
		t.Fatalf("syncDateValue(RFC3339) = %v, want the date part only", got)
	}

	// A timestamp late in the day in a positive offset still belongs to the UTC
	// date, not the local one.
	offset := "2026-08-05T01:30:00+05:00"
	if got, err := syncDateValue("eol", &offset); err != nil || got != "2026-08-04" {
		t.Fatalf("syncDateValue(offset) = %v, %v; want the UTC date 2026-08-04", got, err)
	}
}

// TestSyncDateValueTreatsAbsentValuesAsNull keeps an omitted or blank date out
// of the column instead of writing an empty string that would not parse later.
func TestSyncDateValueTreatsAbsentValuesAsNull(t *testing.T) {
	t.Parallel()

	if got, err := syncDateValue("eol", nil); err != nil || got != nil {
		t.Fatalf("syncDateValue(nil) = %v, %v; want nil, nil", got, err)
	}
	for _, blank := range []string{"", "   ", "\t"} {
		value := blank
		if got, err := syncDateValue("eol", &value); err != nil || got != nil {
			t.Fatalf("syncDateValue(%q) = %v, %v; want nil, nil", blank, got, err)
		}
	}
}

// TestSyncDateValueRejectsUnparseableInput makes sure a malformed date from the
// server surfaces as an error naming the field, rather than being stored raw.
func TestSyncDateValueRejectsUnparseableInput(t *testing.T) {
	t.Parallel()

	bad := "not-a-date"
	got, err := syncDateValue("lifecycle_eol", &bad)
	if err == nil {
		t.Fatalf("syncDateValue(malformed) = %v, want an error", got)
	}
	if !strings.Contains(err.Error(), "lifecycle_eol") {
		t.Fatalf("syncDateValue error = %v, want the field name for diagnosis", err)
	}
}

// TestSyncDateValueAcceptsTheDateFormatItEmits closes the round trip: whatever
// syncDateValue produces must be accepted by syncDateValue again, so a re-sync
// of already-normalised data cannot fail.
func TestSyncDateValueAcceptsTheDateFormatItEmits(t *testing.T) {
	t.Parallel()

	source := time.Now().UTC().Format(time.RFC3339Nano)
	first, err := syncDateValue("eol", &source)
	if err != nil {
		t.Fatalf("first pass error = %v", err)
	}
	normalised, ok := first.(string)
	if !ok {
		t.Fatalf("first pass returned %T, want a string", first)
	}
	second, err := syncDateValue("eol", &normalised)
	if err != nil {
		t.Fatalf("second pass error = %v", err)
	}
	if second != normalised {
		t.Fatalf("second pass = %v, want the stable value %q", second, normalised)
	}
}
