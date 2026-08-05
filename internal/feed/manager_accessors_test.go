package feed

import (
	"log/slog"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/devstore"
)

// TestManagerSyncOnStartupRoundTripsThePolicy covers the startup-sync switch.
// It decides whether a server syncs immediately or waits for the first interval
// tick, which on a fresh deployment is the difference between usable advisory
// data now and hours from now.
func TestManagerSyncOnStartupRoundTripsThePolicy(t *testing.T) {
	t.Parallel()

	manager := NewManager(devstore.NewStore(), slog.New(slog.DiscardHandler), time.Hour)

	initial := manager.SyncOnStartup()

	manager.SetSyncOnStartup(!initial)
	if manager.SyncOnStartup() == initial {
		t.Fatal("SetSyncOnStartup did not change the policy")
	}
	manager.SetSyncOnStartup(initial)
	if manager.SyncOnStartup() != initial {
		t.Fatal("the policy did not round-trip back")
	}
}

// TestManagerSetMetricsRecorderNeverStoresNil covers the metrics injection point.
// Sync loops record unconditionally, so a nil recorder reaching one would panic
// mid-sync; the setter has to substitute the no-op instead.
func TestManagerSetMetricsRecorderNeverStoresNil(t *testing.T) {
	t.Parallel()

	manager := NewManager(devstore.NewStore(), slog.New(slog.DiscardHandler), time.Hour)

	manager.SetMetricsRecorder(nil)
	manager.mu.Lock()
	recorder := manager.metrics
	manager.mu.Unlock()

	if recorder == nil {
		t.Fatal("SetMetricsRecorder(nil) stored a nil recorder")
	}
	// The stored no-op must tolerate every call.
	recorder.AddQueueStuckRecovered(1)
	recorder.IncFeedSyncTimeout("osv")
	recorder.IncQueueError("osv")
	recorder.IncQueueJobCompleted("osv", "done")

	custom := &countingMetricsRecorder{}
	manager.SetMetricsRecorder(custom)
	manager.mu.Lock()
	stored := manager.metrics
	manager.mu.Unlock()
	if stored != custom {
		t.Fatal("SetMetricsRecorder did not store the supplied recorder")
	}
}

// TestNoopMetricsRecorderAcceptsEveryCall pins the no-op implementation. It is
// the fallback everywhere a recorder is optional, so each method must exist and
// do nothing rather than panic.
func TestNoopMetricsRecorderAcceptsEveryCall(t *testing.T) {
	t.Parallel()

	recorder := NoopMetricsRecorder()
	if recorder == nil {
		t.Fatal("NoopMetricsRecorder() = nil")
	}
	recorder.AddQueueStuckRecovered(0)
	recorder.AddQueueStuckRecovered(7)
	recorder.IncFeedSyncTimeout("")
	recorder.IncFeedSyncTimeout("osv")
	recorder.IncQueueError("")
	recorder.IncQueueError("scan")
	recorder.IncQueueJobCompleted("", "")
	recorder.IncQueueJobCompleted("scan", "done")
}

// TestWithMetricsRecorderCarriesTheRecorder covers the option constructor used
// by components that accept feed options.
func TestWithMetricsRecorderCarriesTheRecorder(t *testing.T) {
	t.Parallel()

	custom := &countingMetricsRecorder{}
	option := WithMetricsRecorder(custom)
	if option.recorder != custom {
		t.Fatalf("option.recorder = %v, want the supplied recorder", option.recorder)
	}
}

type countingMetricsRecorder struct {
	stuckRecovered int
	timeouts       int
	queueErrors    int
	completed      int
}

func (r *countingMetricsRecorder) AddQueueStuckRecovered(n int)        { r.stuckRecovered += n }
func (r *countingMetricsRecorder) IncFeedSyncTimeout(string)           { r.timeouts++ }
func (r *countingMetricsRecorder) IncQueueError(string)                { r.queueErrors++ }
func (r *countingMetricsRecorder) IncQueueJobCompleted(string, string) { r.completed++ }
