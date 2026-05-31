package feed

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

type queueStoreStub struct {
	db.Store
	mu             sync.Mutex
	resetCalls     []string
	resetThreshold time.Duration
	resetCount     int
	resetErr       error
}

func (s *queueStoreStub) ResetStuckJobs(_ context.Context, source string, threshold time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resetCalls = append(s.resetCalls, source)
	s.resetThreshold = threshold
	if s.resetErr != nil {
		return 0, s.resetErr
	}
	return s.resetCount, nil
}

type queueWorkerStub struct {
	name    string
	run     func(context.Context) error
	started chan struct{}
}

func (w *queueWorkerStub) Name() string { return w.name }

func (w *queueWorkerStub) Run(ctx context.Context) error {
	if w.started != nil {
		select {
		case w.started <- struct{}{}:
		default:
		}
	}
	if w.run != nil {
		return w.run(ctx)
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestNewQueueProcessorDefaultsAndOptions(t *testing.T) {
	t.Parallel()

	store := &queueStoreStub{}
	worker := &queueWorkerStub{name: "socket"}
	q := NewQueueProcessor(store, nil, []AsyncWorker{worker},
		WithQueuePollInterval(25*time.Millisecond),
		WithQueueStuckThreshold(2*time.Minute),
	)

	if q.logger == nil {
		t.Fatal("logger is nil")
	}
	if q.pollInterval != 25*time.Millisecond {
		t.Fatalf("pollInterval = %v, want 25ms", q.pollInterval)
	}
	if q.stuckThreshold != 2*time.Minute {
		t.Fatalf("stuckThreshold = %v, want 2m", q.stuckThreshold)
	}
	if got := q.findWorker("socket"); got != worker {
		t.Fatalf("findWorker(socket) = %+v, want registered worker", got)
	}
	if got := q.findWorker("missing"); got != nil {
		t.Fatalf("findWorker(missing) = %+v, want nil", got)
	}
}

func TestQueueProcessorRunWithNoWorkersWaitsForCancellation(t *testing.T) {
	t.Parallel()

	q := NewQueueProcessor(&queueStoreStub{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not exit after context cancellation")
	}
}

func TestQueueProcessorStartsWorkersAndResetsStuckJobs(t *testing.T) {
	t.Parallel()

	store := &queueStoreStub{resetCount: 2}
	started := make(chan struct{}, 1)
	worker := &queueWorkerStub{name: "reversinglabs", started: started}
	q := NewQueueProcessor(store, slog.New(slog.NewTextHandler(io.Discard, nil)), []AsyncWorker{worker},
		WithQueuePollInterval(10*time.Millisecond),
		WithQueueStuckThreshold(time.Minute),
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx) }()

	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("worker was not started")
	}

	store.mu.Lock()
	resetCalls := append([]string(nil), store.resetCalls...)
	threshold := store.resetThreshold
	store.mu.Unlock()
	if len(resetCalls) == 0 || resetCalls[0] != "reversinglabs" {
		cancel()
		t.Fatalf("reset calls = %#v, want initial reversinglabs reset", resetCalls)
	}
	if threshold != time.Minute {
		cancel()
		t.Fatalf("reset threshold = %v, want 1m", threshold)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not exit after cancellation")
	}
}

func TestQueueProcessorHandlesResetErrors(t *testing.T) {
	t.Parallel()

	store := &queueStoreStub{resetErr: errors.New("db down")}
	worker := &queueWorkerStub{name: "socket"}
	q := NewQueueProcessor(store, slog.New(slog.NewTextHandler(io.Discard, nil)), []AsyncWorker{worker})

	q.resetAllStuckJobs(context.Background())
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.resetCalls) != 1 || store.resetCalls[0] != "socket" {
		t.Fatalf("reset calls = %#v, want socket despite error", store.resetCalls)
	}
}

func TestQueueProcessorRestartsCrashedWorkerUntilLimit(t *testing.T) {
	// Not parallel: mutates package-level workerBackoffs.
	saved := workerBackoffs
	workerBackoffs = [maxWorkerRestarts]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { workerBackoffs = saved }()

	var runCount int32
	worker := &queueWorkerStub{
		name: "socket",
		run: func(context.Context) error {
			atomic.AddInt32(&runCount, 1)
			return errors.New("worker crashed")
		},
	}
	q := NewQueueProcessor(&queueStoreStub{}, slog.New(slog.NewTextHandler(io.Discard, nil)), []AsyncWorker{worker},
		WithQueuePollInterval(time.Hour),
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx) }()

	deadline := time.After(time.Second)
	for atomic.LoadInt32(&runCount) < int32(maxWorkerRestarts+1) {
		select {
		case <-deadline:
			cancel()
			t.Fatalf("worker run count = %d, want %d", atomic.LoadInt32(&runCount), maxWorkerRestarts+1)
		default:
			time.Sleep(time.Millisecond)
		}
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not exit after cancellation")
	}
}

func TestQueueProcessorHandlesCleanWorkerExit(t *testing.T) {
	t.Parallel()

	worker := &queueWorkerStub{
		name: "socket",
		run:  func(context.Context) error { return nil },
	}
	q := NewQueueProcessor(&queueStoreStub{}, slog.New(slog.NewTextHandler(io.Discard, nil)), []AsyncWorker{worker},
		WithQueuePollInterval(time.Hour),
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx) }()

	time.Sleep(25 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not exit after clean worker exit and cancellation")
	}
}
