package feed

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingMetricsRecorder struct {
	feedSyncTimeouts map[string]int
	queueErrors      map[string]int
	stuckRecovered   int
	jobsCompleted    map[string]int
}

func newRecordingMetricsRecorder() *recordingMetricsRecorder {
	return &recordingMetricsRecorder{
		feedSyncTimeouts: make(map[string]int),
		queueErrors:      make(map[string]int),
		jobsCompleted:    make(map[string]int),
	}
}

func (r *recordingMetricsRecorder) IncFeedSyncTimeout(feed string) {
	r.feedSyncTimeouts[feed]++
}

func (r *recordingMetricsRecorder) IncQueueError(source string) {
	r.queueErrors[source]++
}

func (r *recordingMetricsRecorder) AddQueueStuckRecovered(count int) {
	r.stuckRecovered += count
}

func (r *recordingMetricsRecorder) IncQueueJobCompleted(source, result string) {
	r.jobsCompleted[source+":"+result]++
}

func TestFeedRuntimeFilesDoNotUseGlobalTelemetry(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{
		"manager.go",
		"queue.go",
		filepath.Join("socket", "worker.go"),
		filepath.Join("reversinglabs", "worker.go"),
	} {
		t.Run(rel, func(t *testing.T) {
			t.Parallel()
			src, err := os.ReadFile(rel)
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			if strings.Contains(string(src), "telemetry.Default()") {
				t.Fatalf("%s calls telemetry.Default(); use the feed MetricsRecorder port", rel)
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, rel, src, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s imports: %v", rel, err)
			}
			for _, spec := range file.Imports {
				path := strings.Trim(spec.Path.Value, `"`)
				if path == "github.com/8linkz-sec/packmon/internal/telemetry" {
					t.Fatalf("%s imports internal/telemetry directly", rel)
				}
			}
		})
	}
}

func TestQueueProcessorRecordsMetricsThroughInjectedRecorder(t *testing.T) {
	recorder := newRecordingMetricsRecorder()
	store := &queueStoreStub{
		resetCount:       3,
		resetPanicSource: "socket",
		resetPanicValue:  "reset boom",
	}
	workers := []AsyncWorker{
		&queueWorkerStub{name: "socket"},
		&queueWorkerStub{name: "reversinglabs"},
	}
	q := NewQueueProcessor(store, nil, workers, WithMetricsRecorder(recorder))

	q.resetAllStuckJobs(t.Context())

	if got := recorder.queueErrors["socket"]; got != 1 {
		t.Fatalf("queue error metrics for socket = %d, want 1", got)
	}
	if got := recorder.stuckRecovered; got != 3 {
		t.Fatalf("stuck recovered metrics = %d, want 3", got)
	}
}

func TestManagerRecordsTimeoutMetricsThroughInjectedRecorder(t *testing.T) {
	saved := backoffSchedule
	backoffSchedule = [3]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { backoffSchedule = saved }()

	recorder := newRecordingMetricsRecorder()
	store := &managerStoreStub{}
	manager := NewManager(store, nil, time.Hour, WithMetricsRecorder(recorder))
	rf := &registeredFeed{
		config: FeedConfig{Syncer: &failingSyncerStub{name: "osv", err: errors.New("dial tcp: i/o timeout")}},
		syncMu: &sync.Mutex{},
	}

	_, err := manager.syncWithRetry(t.Context(), rf, true)
	if err == nil {
		t.Fatal("syncWithRetry() error = nil, want timeout failure")
	}
	if got := recorder.feedSyncTimeouts["osv"]; got != len(backoffSchedule)+1 {
		t.Fatalf("feed sync timeout metrics = %d, want %d", got, len(backoffSchedule)+1)
	}
}
