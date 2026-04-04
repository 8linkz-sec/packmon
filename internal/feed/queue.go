// Package feed contains the core feed syncer interface, the feed manager,
// and the priority queue processor.
//
// This file implements the priority queue processor that reads jobs from
// the refresh_queue table and dispatches them to registered async workers.
// Priority levels (from CLAUDE.md):
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
	"log/slog"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

const (
	// defaultPollInterval is how often the queue processor checks for work.
	defaultPollInterval = 10 * time.Second

	// defaultStuckThreshold is the time after which a 'processing' job is
	// considered stuck and eligible for reset.
	defaultStuckThreshold = 5 * time.Minute
)

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

// QueueProcessor polls the refresh_queue table and dispatches jobs to the
// appropriate async workers. It handles stuck-job detection and graceful
// shutdown. Each registered worker runs in its own goroutine via Run.
//
// The QueueProcessor itself does not call worker APIs directly. Instead,
// it starts each worker's Run loop and relies on the workers to dequeue
// their own jobs from the store. The processor provides a supervisory
// layer: starting workers, resetting stuck jobs, and coordinating shutdown.
type QueueProcessor struct {
	store          db.Store
	logger         *slog.Logger
	workers        []AsyncWorker
	pollInterval   time.Duration
	stuckThreshold time.Duration
}

// QueueOption configures a QueueProcessor.
type QueueOption func(*QueueProcessor)

// WithQueuePollInterval overrides the default poll interval.
func WithQueuePollInterval(d time.Duration) QueueOption {
	return func(q *QueueProcessor) { q.pollInterval = d }
}

// WithQueueStuckThreshold overrides the default stuck-job threshold.
func WithQueueStuckThreshold(d time.Duration) QueueOption {
	return func(q *QueueProcessor) { q.stuckThreshold = d }
}

// NewQueueProcessor creates a queue processor that supervises the given
// async workers.
func NewQueueProcessor(store db.Store, logger *slog.Logger, workers []AsyncWorker, opts ...QueueOption) *QueueProcessor {
	if logger == nil {
		logger = slog.Default()
	}
	q := &QueueProcessor{
		store:          store,
		logger:         logger.With("component", "queue_processor"),
		workers:        workers,
		pollInterval:   defaultPollInterval,
		stuckThreshold: defaultStuckThreshold,
	}
	for _, opt := range opts {
		opt(q)
	}
	return q
}

// Run starts all registered async workers and a periodic stuck-job
// scanner. It blocks until the context is cancelled. Worker failures
// are logged but do not bring down the processor; the worker goroutine
// simply exits and its jobs accumulate in the queue.
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

	// Start each worker in its own goroutine.
	done := make(chan workerResult, len(q.workers))
	for _, w := range q.workers {
		w := w // capture loop variable
		go func() {
			err := w.Run(ctx)
			done <- workerResult{name: w.Name(), err: err}
		}()
		q.logger.Info("started async worker", "worker", w.Name())
	}

	// Periodic stuck-job scanner runs alongside the workers.
	stuckTicker := time.NewTicker(q.pollInterval)
	defer stuckTicker.Stop()

	exited := 0
	for {
		select {
		case <-ctx.Done():
			q.logger.Info("queue processor shutting down, waiting for workers")
			// Workers will observe the cancelled context and exit.
			// Drain remaining results.
			for exited < len(q.workers) {
				result := <-done
				exited++
				if result.err != nil && result.err != context.Canceled {
					q.logger.Warn("worker exited with error",
						"worker", result.name,
						"error", result.err,
					)
				}
			}
			q.logger.Info("all workers stopped")
			return ctx.Err()

		case result := <-done:
			exited++
			if result.err != nil && result.err != context.Canceled {
				q.logger.Error("worker exited unexpectedly",
					"worker", result.name,
					"error", result.err,
				)
			} else {
				q.logger.Info("worker exited", "worker", result.name)
			}
			// If all workers have exited, wait for context cancellation.
			if exited >= len(q.workers) {
				q.logger.Info("all workers have exited, waiting for shutdown signal")
				<-ctx.Done()
				return ctx.Err()
			}

		case <-stuckTicker.C:
			q.resetAllStuckJobs(ctx)
		}
	}
}

// resetAllStuckJobs resets stuck jobs for every registered worker source.
func (q *QueueProcessor) resetAllStuckJobs(ctx context.Context) {
	for _, w := range q.workers {
		count, err := q.store.ResetStuckJobs(ctx, w.Name(), q.stuckThreshold)
		if err != nil {
			q.logger.Warn("failed to reset stuck jobs",
				"source", w.Name(),
				"error", err,
			)
			continue
		}
		if count > 0 {
			q.logger.Info("reset stuck jobs",
				"source", w.Name(),
				"count", count,
			)
		}
	}
}

// workerResult pairs a worker name with its exit error.
type workerResult struct {
	name string
	err  error
}
