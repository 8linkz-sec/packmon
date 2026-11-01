package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
)

func newDelayedQueueRestartServices(rootCtx context.Context, oldCancel context.CancelFunc, oldDone chan error) *backgroundServices {
	return &backgroundServices{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg: &config.Config{
			Server: config.ServerConfig{Mode: config.ModeProduction},
			Feeds: config.FeedsConfig{
				SocketEnabled: true,
				SocketMode:    config.FeedModeSelf,
				SocketAPIKey:  "socket-secret",
			},
		},
		store:        newNoopStore(),
		rootCtx:      rootCtx,
		shutdownWait: time.Second,
		queueCancel:  oldCancel,
		queueDone:    oldDone,
		queueDones:   []chan error{oldDone},
	}
}

func (b *backgroundServices) trackedQueueGenerations() (chan error, int) {
	b.queueMu.Lock()
	defer b.queueMu.Unlock()
	return b.queueDone, len(b.queueDones)
}

// TestRestartQueueProcessorStartsReplacementAfterDelayedOldGenerationExit
// covers a queue generation that misses the restart deadline. The settings are
// already applied to the config at that point, and saving them again is a
// no-op, so the replacement must start once the old generation exits instead
// of leaving the async workers stopped until the next effective change.
func TestRestartQueueProcessorStartsReplacementAfterDelayedOldGenerationExit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rootCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		oldCtx, oldCancel := context.WithCancel(context.Background())
		defer oldCancel()
		oldDone := make(chan error, 1)
		services := newDelayedQueueRestartServices(rootCtx, oldCancel, oldDone)

		if err := services.restartQueueProcessor(); err != nil {
			t.Fatalf("restartQueueProcessor() error = %v", err)
		}
		if oldCtx.Err() == nil {
			t.Fatal("old queue context was not cancelled")
		}
		synctest.Wait()
		pending, tracked := services.trackedQueueGenerations()
		if pending == nil || tracked != 1 {
			t.Fatalf("tracked generations = (%v, %d), want only the still-running old generation", pending, tracked)
		}

		// The old generation finally exits after the restart deadline.
		oldDone <- context.Canceled
		synctest.Wait()

		replacement, tracked := services.trackedQueueGenerations()
		if replacement == nil || replacement == pending || replacement == oldDone {
			t.Fatal("no replacement queue generation started after the old generation exited")
		}
		if tracked != 1 {
			t.Fatalf("tracked generations = %d, want only the replacement", tracked)
		}

		cancel()
		if !services.Wait() {
			t.Fatal("Wait() = false, want the replacement to stop on root cancellation")
		}
	})
}

// TestRestartQueueProcessorDelayedExitDoesNotStartAfterShutdown keeps the
// continuation from starting a replacement once shutdown has taken over.
func TestRestartQueueProcessorDelayedExitDoesNotStartAfterShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rootCtx, cancel := context.WithCancel(context.Background())
		_, oldCancel := context.WithCancel(context.Background())
		defer oldCancel()
		oldDone := make(chan error, 1)
		services := newDelayedQueueRestartServices(rootCtx, oldCancel, oldDone)

		if err := services.restartQueueProcessor(); err != nil {
			t.Fatalf("restartQueueProcessor() error = %v", err)
		}
		cancel()
		waited := make(chan bool, 1)
		go func() { waited <- services.Wait() }()
		synctest.Wait()

		oldDone <- context.Canceled
		if !<-waited {
			t.Fatal("Wait() = false, want shutdown to observe the delayed generation exit")
		}
		synctest.Wait()
		if done, _ := services.trackedQueueGenerations(); done != nil {
			t.Fatal("a replacement queue generation started after shutdown began")
		}
	})
}

// TestRestartQueueProcessorSecondRestartTakesOverDelayedGeneration covers a
// second effective change while the first replacement is still deferred: it
// waits on the same generation, and exactly one replacement starts.
func TestRestartQueueProcessorSecondRestartTakesOverDelayedGeneration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rootCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, oldCancel := context.WithCancel(context.Background())
		defer oldCancel()
		oldDone := make(chan error, 1)
		services := newDelayedQueueRestartServices(rootCtx, oldCancel, oldDone)

		if err := services.restartQueueProcessor(); err != nil {
			t.Fatalf("first restartQueueProcessor() error = %v", err)
		}
		pending, _ := services.trackedQueueGenerations()

		second := make(chan error, 1)
		go func() { second <- services.restartQueueProcessor() }()
		synctest.Wait()
		oldDone <- context.Canceled
		if err := <-second; err != nil {
			t.Fatalf("second restartQueueProcessor() error = %v", err)
		}
		synctest.Wait()

		replacement, tracked := services.trackedQueueGenerations()
		if replacement == nil || replacement == pending || tracked != 1 {
			t.Fatalf("tracked generations = (%v, %d), want exactly one replacement", replacement, tracked)
		}

		cancel()
		if !services.Wait() {
			t.Fatal("Wait() = false, want the replacement to stop on root cancellation")
		}
	})
}
