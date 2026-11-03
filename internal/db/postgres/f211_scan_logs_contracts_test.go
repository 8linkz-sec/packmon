package postgres

import (
	"context"
	"testing"
	"time"
)

func TestF211ScanLogNoopBoundariesAvoidDatabaseAccess(t *testing.T) {
	t.Parallel()

	store := &Store{}
	for _, key := range []string{"", " \t\r\n "} {
		got, err := store.GetScanLogByIdempotencyKey(context.Background(), key)
		if err != nil || got != nil {
			t.Fatalf("GetScanLogByIdempotencyKey(%q) = %#v, %v; want nil, nil", key, got, err)
		}
	}

	for _, retention := range []time.Duration{0, -time.Nanosecond, -24 * time.Hour} {
		got, err := store.PruneScanLogs(context.Background(), retention)
		if err != nil || got != 0 {
			t.Fatalf("PruneScanLogs(%s) = %d, %v; want 0, nil", retention, got, err)
		}
	}
}
