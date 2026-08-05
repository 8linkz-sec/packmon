// Package feed contains the core feed syncer interface, the feed manager,
// and the priority queue processor.
//
// This file implements the priority queue processor that reads jobs from
// the refresh_queue table and dispatches them to registered async workers.
// Priority levels (see DESIGN.md refresh queue behavior):
//
//	0: Manual trigger (user clicks "check now")
//	1: Unknown packages (never checked before)
//	2: Packages with known findings (re-check more often)
//	3: Oldest updated_at (longest time since last check)
//
// The queue table uses a partial unique index (DE-16) to prevent duplicate
// pending/processing jobs for the same (ecosystem, name, source) tuple.
package feed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

const (
	// defaultPollInterval is how often the queue processor checks for work.
	defaultPollInterval = 10 * time.Second

	// defaultStuckThreshold is the time after which a 'processing' job is
	// considered stuck and eligible for reset.
	defaultStuckThreshold = 5 * time.Minute

	// maxWorkerRestarts is the maximum number of restart attempts per worker
	// before giving up.
	maxWorkerRestarts = 3
)

var resetStuckJobsTimeout = 2 * time.Second

// workerBackoffs defines the exponential backoff delays for worker restarts.
// Index maps to restart attempt (0-based).
var workerBackoffs = [maxWorkerRestarts]time.Duration{
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
}

// AsyncWorker is the interface that async feed workers (e.g. Socket.dev)
// must implement to be dispatched by the QueueProcessor. Each worker owns
// one source name and processes jobs for that source.
type AsyncWorker interface {
	// Name returns the source identifier (e.g. "socket"). This must match
	// the refresh_queue.source column value.
	Name() string

	// Run starts the worker's event loop. It blocks until ctx is cancelled.
	Run(ctx context.Context) error
}

// QueueMaintenanceStore is the narrow persistence contract used by the
// QueueProcessor itself. Async workers keep their own store dependencies for
// dequeue and source-specific writes.
type QueueMaintenanceStore interface {
	ResetStuckJobs(ctx context.Context, source string, stuckThreshold time.Duration) (int, error)
}

// QueueProcessor polls the refresh_queue table and dispatches jobs to the
// appropriate async workers. It handles stuck-job detection and graceful
// shutdown. Each registered worker runs in its own goroutine via Run.
//
// The QueueProcessor itself does not call worker APIs directly. Instead,
// it starts each worker's Run loop and relies on the workers to dequeue
// their own jobs from the store. The processor provides a supervisory
// layer: starting workers, resetting stuck jobs, and coordinating shutdown.
type QueueProcessor struct {
	store          QueueMaintenanceStore
	logger         *slog.Logger
	workers        []AsyncWorker
	pollInterval   time.Duration
	stuckThreshold time.Duration
	metrics        MetricsRecorder
}

// QueueOption configures a QueueProcessor.
type QueueOption interface {
	applyQueueOption(*QueueProcessor)
}

type queueOptionFunc func(*QueueProcessor)

func (f queueOptionFunc) applyQueueOption(q *QueueProcessor) {
	f(q)
}

// WithQueuePollInterval overrides the default poll interval.
func WithQueuePollInterval(d time.Duration) QueueOption {
	return queueOptionFunc(func(q *QueueProcessor) { q.pollInterval = d })
}

// WithQueueStuckThreshold overrides the default stuck-job threshold.
func WithQueueStuckThreshold(d time.Duration) QueueOption {
	return queueOptionFunc(func(q *QueueProcessor) { q.stuckThreshold = d })
}

// NewQueueProcessor creates a queue processor that supervises the given
// async workers.
func NewQueueProcessor(store QueueMaintenanceStore, logger *slog.Logger, workers []AsyncWorker, opts ...QueueOption) *QueueProcessor {
	if logger == nil {
		logger = slog.Default()
	}
	q := &QueueProcessor{
		store:          store,
		logger:         logger.With("component", "queue_processor"),
		workers:        workers,
		pollInterval:   defaultPollInterval,
		stuckThreshold: defaultStuckThreshold,
		metrics:        NoopMetricsRecorder(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt.applyQueueOption(q)
		}
	}
	return q
}

// Run starts all registered async workers and a periodic stuck-job
// scanner. It blocks until the context is cancelled.
//
// If a worker exits with a non-nil error (and the context is not cancelled),
// it will be restarted with exponential backoff (5s, 30s, 5min). After 3
// failed restart attempts the worker is considered dead and its jobs will
// accumulate in the queue until the processor is restarted.
func (q *QueueProcessor) Run(ctx context.Context) error {
	if len(q.workers) == 0 {
		q.logger.Info("no async workers registered, queue processor idle")
		<-ctx.Done()
		return ctx.Err()
	}

	q.logger.Info("starting queue processor",
		"worker_count", len(q.workers),
		"poll_interval", q.pollInterval,
		"stuck_threshold", q.stuckThreshold,
	)

	// Reset any stuck jobs left from a previous crash before starting workers.
	q.resetAllStuckJobs(ctx)

	lifecycle := newWorkerLifecycleState(len(q.workers))
	done := make(chan workerResult, len(q.workers))
	q.startWorkers(ctx, done)

	// Periodic stuck-job scanner runs alongside the workers.
	stuckTicker := time.NewTicker(q.pollInterval)
	defer stuckTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			q.logger.Info("queue processor shutting down, waiting for workers")
			q.drainWorkersOnShutdown(done, lifecycle.exited)
			q.logger.Info("all workers stopped")
			return ctx.Err()

		case result := <-done:
			q.handleWorkerResult(ctx, result, done, lifecycle)

			// If all workers have permanently exited, wait for context cancellation.
			if lifecycle.allWorkersExited() {
				q.logger.Info("all workers have exited, waiting for shutdown signal")
				<-ctx.Done()
				return ctx.Err()
			}

		case <-stuckTicker.C:
			q.resetAllStuckJobs(ctx)
		}
	}
}

// startWorkers starts each registered worker in its own goroutine.
func (q *QueueProcessor) startWorkers(ctx context.Context, done chan<- workerResult) {
	for _, w := range q.workers {
		q.startWorker(ctx, w, done)
		q.logger.Info("started async worker", "worker", w.Name())
	}
}

func (q *QueueProcessor) startWorker(ctx context.Context, worker AsyncWorker, done chan<- workerResult) {
	go func() {
		err := worker.Run(ctx)
		done <- workerResult{name: worker.Name(), err: err}
	}()
}

// drainWorkersOnShutdown waits for active workers or pending restarts to report
// their final result after the processor context has been cancelled.
func (q *QueueProcessor) drainWorkersOnShutdown(done <-chan workerResult, exited int) {
	for exited < len(q.workers) {
		result := <-done
		exited++
		if result.err != nil && !errors.Is(result.err, context.Canceled) {
			q.logger.Warn("worker exited with error during shutdown",
				"worker", result.name,
				"error", result.err,
			)
		}
	}
}

func (q *QueueProcessor) handleWorkerResult(ctx context.Context, result workerResult, done chan<- workerResult, lifecycle *workerLifecycleState) {
	if result.isCanceled(ctx) {
		lifecycle.markExited()
		q.logger.Info("worker exited", "worker", result.name)
		return
	}

	if result.err == nil {
		result.err = errors.New("worker exited unexpectedly without error")
	}
	if q.restartWorker(ctx, result, done, lifecycle) {
		return
	}
	lifecycle.markExited()
}

func (q *QueueProcessor) restartWorker(ctx context.Context, result workerResult, done chan<- workerResult, lifecycle *workerLifecycleState) bool {
	restart, ok := lifecycle.claimRestart(result.name)
	if !ok {
		q.logger.Error("worker permanently failed after max restarts",
			"worker", result.name,
			"error", result.err,
			"restarts_attempted", restart.attempts,
		)
		return false
	}

	q.logger.Warn("worker crashed, scheduling restart",
		"worker", result.name,
		"error", result.err,
		"restart_attempt", restart.attempts,
		"max_restarts", maxWorkerRestarts,
		"backoff", restart.backoff,
	)

	w := q.findWorker(result.name)
	if w == nil {
		q.logger.Error("cannot restart worker: not found in registry",
			"worker", result.name,
		)
		return false
	}

	q.restartWorkerAfterBackoff(ctx, w, restart, done)
	return true
}

func (q *QueueProcessor) restartWorkerAfterBackoff(ctx context.Context, worker AsyncWorker, restart workerRestart, done chan<- workerResult) {
	go func() {
		select {
		case <-ctx.Done():
			done <- workerResult{name: worker.Name(), err: ctx.Err()}
			return
		case <-time.After(restart.backoff):
		}
		q.logger.Info("restarting worker after backoff",
			"worker", worker.Name(),
			"restart_attempt", restart.attempts,
		)
		err := worker.Run(ctx)
		done <- workerResult{name: worker.Name(), err: err}
	}()
}

// findWorker returns the registered AsyncWorker with the given name, or nil.
func (q *QueueProcessor) findWorker(name string) AsyncWorker {
	for _, w := range q.workers {
		if w.Name() == name {
			return w
		}
	}
	return nil
}

// resetAllStuckJobs resets stuck jobs for every registered worker source.
func (q *QueueProcessor) resetAllStuckJobs(ctx context.Context) {
	for _, w := range q.workers {
		q.resetStuckJobsForSource(ctx, w.Name())
	}
}

func (q *QueueProcessor) resetStuckJobsForSource(ctx context.Context, source string) {
	resetCtx, cancel := context.WithTimeout(ctx, resetStuckJobsTimeout)
	defer cancel()
	defer func() {
		if recovered := recover(); recovered != nil {
			q.metrics.IncQueueError(source)
			q.logger.Error("stuck job reset panic recovered",
				"source", source,
				"panic", SafeDiagnosticMessage(fmt.Sprint(recovered)),
			)
		}
	}()

	count, err := q.store.ResetStuckJobs(resetCtx, source, q.stuckThreshold)
	if err != nil {
		q.logger.Warn("failed to reset stuck jobs",
			"source", source,
			"error", err,
		)
		return
	}
	if count > 0 {
		q.metrics.AddQueueStuckRecovered(count)
		q.logger.Info("reset stuck jobs",
			"source", source,
			"count", count,
		)
	}
}

// workerResult pairs a worker name with its exit error.
type workerResult struct {
	name string
	err  error
}

func (r workerResult) isCanceled(ctx context.Context) bool {
	return errors.Is(r.err, context.Canceled) || ctx.Err() != nil
}

type workerLifecycleState struct {
	restartCounts map[string]int
	exited        int
	total         int
}

func newWorkerLifecycleState(workerCount int) *workerLifecycleState {
	return &workerLifecycleState{
		restartCounts: make(map[string]int, workerCount),
		total:         workerCount,
	}
}

func (s *workerLifecycleState) markExited() {
	s.exited++
}

func (s *workerLifecycleState) allWorkersExited() bool {
	return s.exited >= s.total
}

func (s *workerLifecycleState) claimRestart(workerName string) (workerRestart, bool) {
	attempts := s.restartCounts[workerName]
	if attempts >= maxWorkerRestarts {
		return workerRestart{attempts: attempts}, false
	}
	s.restartCounts[workerName] = attempts + 1
	return workerRestart{
		attempts: attempts + 1,
		backoff:  workerBackoffs[attempts],
	}, true
}

type workerRestart struct {
	attempts int
	backoff  time.Duration
}
