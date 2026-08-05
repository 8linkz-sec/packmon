package telemetry

import "testing"

// TestDefaultReturnsTheProcessWideRegistry covers the accessor every call site
// uses to record metrics. It must hand out the same initialised registry each
// time -- a fresh one per call would silently discard every counter.
func TestDefaultReturnsTheProcessWideRegistry(t *testing.T) {
	t.Parallel()

	registry := Default()
	if registry == nil {
		t.Fatal("Default() = nil, want the process-wide registry")
	}
	if Default() != registry {
		t.Fatal("Default() returns a different registry on each call")
	}

	// The registry must be usable, not just non-nil.
	before := registry.Snapshot()
	registry.IncAuthLoginFailures()
	after := registry.Snapshot()
	if after.AuthLoginFailures <= before.AuthLoginFailures {
		t.Fatalf("AuthLoginFailures went %d -> %d, want the counter to advance",
			before.AuthLoginFailures, after.AuthLoginFailures)
	}
}
