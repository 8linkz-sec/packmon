package feed

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type queueStoreStub struct {
	mu               sync.Mutex
	resetCalls       []string
	resetThreshold   time.Duration
	resetCount       int
	resetErr         error
	resetBlock       chan struct{}
	resetCtxErr      error
	resetCtxDeadline bool
	resetPanicSource string
	resetPanicValue  any
}

func (s *queueStoreStub) ResetStuckJobs(ctx context.Context, source string, threshold time.Duration) (int, error) {
	s.mu.Lock()
	s.resetCalls = append(s.resetCalls, source)
	s.resetThreshold = threshold
	_, s.resetCtxDeadline = ctx.Deadline()
	s.mu.Unlock()

	if source == s.resetPanicSource {
		if s.resetPanicValue != nil {
			panic(s.resetPanicValue)
		}
		panic("reset panic")
	}

	if s.resetBlock != nil {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.resetCtxErr = ctx.Err()
			s.mu.Unlock()
			return 0, ctx.Err()
		case <-s.resetBlock:
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
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

func TestQueueProcessorBoundsStuckJobReset(t *testing.T) {
	saved := resetStuckJobsTimeout
	resetStuckJobsTimeout = 10 * time.Millisecond
	defer func() { resetStuckJobsTimeout = saved }()

	store := &queueStoreStub{resetBlock: make(chan struct{})}
	worker := &queueWorkerStub{name: "socket"}
	q := NewQueueProcessor(store, slog.New(slog.NewTextHandler(io.Discard, nil)), []AsyncWorker{worker})

	q.resetAllStuckJobs(context.Background())

	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.resetCtxDeadline {
		t.Fatal("reset context had no deadline")
	}
	if !errors.Is(store.resetCtxErr, context.DeadlineExceeded) {
		t.Fatalf("reset context error = %v, want deadline exceeded", store.resetCtxErr)
	}
}

func TestQueueProcessorContainsResetPanicPerSource(t *testing.T) {
	store := &queueStoreStub{
		resetCount:       1,
		resetPanicSource: "socket",
		resetPanicValue:  "reset boom",
	}
	workers := []AsyncWorker{
		&queueWorkerStub{name: "socket"},
		&queueWorkerStub{name: "reversinglabs"},
	}
	var logs strings.Builder
	recorder := newRecordingMetricsRecorder()
	q := NewQueueProcessor(store, slog.New(slog.NewJSONHandler(&logs, nil)), workers, WithMetricsRecorder(recorder))

	q.resetAllStuckJobs(context.Background())

	store.mu.Lock()
	resetCalls := append([]string(nil), store.resetCalls...)
	store.mu.Unlock()
	if len(resetCalls) != 2 || resetCalls[0] != "socket" || resetCalls[1] != "reversinglabs" {
		t.Fatalf("reset calls = %#v, want panic source followed by next source", resetCalls)
	}
	logLine := logs.String()
	for _, want := range []string{"stuck job reset panic recovered", "socket", "reset boom"} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("logs missing %q in %s", want, logLine)
		}
	}
	if got := recorder.queueErrors["socket"]; got != 1 {
		t.Fatalf("queue errors for socket = %d, want 1", got)
	}
}

func TestQueueProcessorRunKeepsRestartFlowInHelpers(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("queue.go")
	if err != nil {
		t.Fatalf("read queue.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "queue.go", src, 0)
	if err != nil {
		t.Fatalf("parse queue.go: %v", err)
	}

	runBody := queueProcessorMethodBody(t, fset, file, src, "Run")
	for _, marker := range []string{
		"restartCounts",
		"workerBackoffs",
		"worker crashed, scheduling restart",
		"worker permanently failed after max restarts",
		"time.After",
	} {
		if strings.Contains(runBody, marker) {
			t.Fatalf("QueueProcessor.Run contains restart-flow marker %q; keep this flow in named helpers", marker)
		}
	}
	for _, helper := range []string{
		"newWorkerLifecycleState",
		"startWorkers",
		"handleWorkerResult",
		"drainWorkersOnShutdown",
	} {
		if !strings.Contains(runBody, helper) {
			t.Fatalf("QueueProcessor.Run does not call helper %q", helper)
		}
	}
	for _, helper := range []string{"startWorker", "restartWorkerAfterBackoff"} {
		body := queueProcessorMethodBody(t, fset, file, src, helper)
		if strings.Contains(body, "recover()") {
			t.Fatalf("QueueProcessor worker helper %s must not recover worker panics; this refactor must preserve prior worker behavior", helper)
		}
	}
}

func queueProcessorMethodBody(t *testing.T, fset *token.FileSet, file *ast.File, src []byte, name string) string {
	t.Helper()

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil {
			continue
		}
		if exprString(fn.Recv.List[0].Type) != "*QueueProcessor" {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		return string(src[start:end])
	}
	t.Fatalf("QueueProcessor.%s not found", name)
	return ""
}

func exprString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return "*" + exprString(e.X)
	default:
		return ""
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

func TestQueueProcessorRestartsUnexpectedNilWorkerExit(t *testing.T) {
	// Not parallel: mutates package-level workerBackoffs.
	saved := workerBackoffs
	workerBackoffs = [maxWorkerRestarts]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { workerBackoffs = saved }()

	var runCount int32
	worker := &queueWorkerStub{
		name: "socket",
		run: func(context.Context) error {
			atomic.AddInt32(&runCount, 1)
			return nil
		},
	}
	q := NewQueueProcessor(&queueStoreStub{}, slog.New(slog.NewTextHandler(io.Discard, nil)), []AsyncWorker{worker},
		WithQueuePollInterval(time.Hour),
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx) }()

	deadline := time.After(time.Second)
	for atomic.LoadInt32(&runCount) < 2 {
		select {
		case <-deadline:
			cancel()
			t.Fatalf("worker run count = %d, want restart after nil exit", atomic.LoadInt32(&runCount))
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
