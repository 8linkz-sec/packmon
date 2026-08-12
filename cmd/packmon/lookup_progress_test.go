package main

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncWriter is a race-safe buffer for output written from the progress
// reporter goroutine.
type syncWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// TestLookupProgressReportsCompletedCounts proves the lookup phase emits
// periodic "done/total" progress lines while lookups complete.
func TestLookupProgressReportsCompletedCounts(t *testing.T) {
	t.Parallel()

	out := &syncWriter{}
	progress := startLookupProgress(out, 569, false, 5*time.Millisecond)
	if progress == nil {
		t.Fatal("startLookupProgress returned nil for a non-quiet run")
	}
	defer progress.stop()

	for range 123 {
		progress.increment()
	}

	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(out.String(), "123/569") {
		if time.Now().After(deadline) {
			t.Fatalf("progress output = %q, want a 123/569 progress line", out.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestLookupProgressQuietAndNilAreSilent proves quiet mode starts no reporter
// and that the nil reporter tolerates increment/stop calls.
func TestLookupProgressQuietAndNilAreSilent(t *testing.T) {
	t.Parallel()

	out := &syncWriter{}
	progress := startLookupProgress(out, 10, true, time.Millisecond)
	if progress != nil {
		t.Fatal("startLookupProgress should return nil in quiet mode")
	}
	progress.increment()
	progress.stop()
	if got := out.String(); got != "" {
		t.Fatalf("quiet progress wrote %q, want no output", got)
	}

	if p := startLookupProgress(out, 0, false, time.Millisecond); p != nil {
		t.Fatal("startLookupProgress should return nil for zero packages")
	}
}

// TestAnnounceLookupPhaseUsesCratesIORateForCargo proves the upfront estimate
// accounts for the one-request-per-second crates.io throttle instead of the
// generic 50ms interval: 569 cargo packages take ~9.5 minutes, not "under a
// minute".
func TestAnnounceLookupPhaseUsesCratesIORateForCargo(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	announceLookupPhase(&buf, 569, 569, false)
	got := buf.String()
	if !strings.Contains(got, "569 packages") || !strings.Contains(got, "about 9 minutes") {
		t.Fatalf("cargo-only announcement = %q, want 569 packages and about 9 minutes", got)
	}

	// Mixed workload: the slower of the two rates dominates the estimate.
	buf.Reset()
	announceLookupPhase(&buf, 600, 100, false)
	got = buf.String()
	if !strings.Contains(got, "600 packages") || !strings.Contains(got, "about 2 minutes") {
		t.Fatalf("mixed announcement = %q, want 600 packages and about 2 minutes", got)
	}

	// No cargo packages: the generic estimate stays unchanged.
	buf.Reset()
	announceLookupPhase(&buf, 100, 0, false)
	got = buf.String()
	if !strings.Contains(got, "under a minute") {
		t.Fatalf("non-cargo announcement = %q, want under a minute", got)
	}
}
