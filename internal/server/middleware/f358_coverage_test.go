package middleware

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"
)

func f358DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestF358LastUsedUpdaterNormalizesAndRejectsInvalidWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updater := newAPIKeyLastUsedUpdater(ctx, nil, &authStoreStub{}, 0, 0, 0)
	if cap(updater.queue) != 1 || updater.logger == nil {
		t.Fatalf("normalized updater = %+v, want queue capacity 1 and logger", updater)
	}
	if updater.Enqueue(0) {
		t.Fatal("Enqueue(0) = true")
	}
	var nilUpdater *APIKeyLastUsedUpdater
	if nilUpdater.Enqueue(1) {
		t.Fatal("nil updater Enqueue() = true")
	}
	if (&APIKeyLastUsedUpdater{}).Enqueue(1) {
		t.Fatal("updater without store Enqueue() = true")
	}
}

func TestF358LastUsedUpdaterBoundsAndInitializesPendingState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	updater := &APIKeyLastUsedUpdater{
		logger:       f358DiscardLogger(),
		store:        &authStoreStub{},
		queue:        make(chan int, 1),
		pending:      map[int]*apiKeyLastUsedPending{1: {}},
		pendingLimit: 1,
		now:          func() time.Time { return now },
	}
	if updater.Enqueue(2) {
		t.Fatal("Enqueue() retained work beyond pending limit")
	}

	empty := &APIKeyLastUsedUpdater{}
	empty.ensureStateLocked()
	if empty.queue == nil || empty.lastQueued == nil || empty.pending == nil {
		t.Fatalf("ensureStateLocked() left nil state: %+v", empty)
	}
	if empty.retryBackoff <= 0 || empty.pendingLimit <= 0 {
		t.Fatalf("ensureStateLocked() left invalid limits: %+v", empty)
	}
	if empty.currentTime().IsZero() {
		t.Fatal("currentTime() with nil clock returned zero")
	}
	if empty.markDequeued(404) {
		t.Fatal("markDequeued() accepted missing pending key")
	}
}

func TestF358LastUsedUpdaterPendingAndRetryBoundaries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	updater := &APIKeyLastUsedUpdater{
		logger:       f358DiscardLogger(),
		store:        &authStoreStub{},
		queue:        make(chan int, 1),
		pending:      make(map[int]*apiKeyLastUsedPending),
		lastQueued:   make(map[int]time.Time),
		retryBackoff: time.Hour,
		pendingLimit: 1,
		now:          func() time.Time { return now },
	}
	if !updater.schedulePendingLocked(1, nil, now) {
		t.Fatal("schedulePendingLocked(nil) = false, want already handled")
	}
	pending := &apiKeyLastUsedPending{retryAfter: now.Add(time.Minute)}
	if updater.schedulePendingLocked(1, pending, now) {
		t.Fatal("schedulePendingLocked() queued before retry deadline")
	}
	updater.scheduleRetryLocked(context.Background(), 1, nil, 0)
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	updater.scheduleRetryLocked(canceledCtx, 1, &apiKeyLastUsedPending{}, -time.Second)

	updater.pending[1] = &apiKeyLastUsedPending{}
	updater.markFailed(context.Background(), 2, errors.New("store unavailable"))
	if _, ok := updater.pending[2]; ok {
		t.Fatal("markFailed() retained retry beyond pending limit")
	}

	updater.pending = make(map[int]*apiKeyLastUsedPending)
	updater.pendingLimit = 2
	updater.markFailed(context.Background(), 3, errors.New("transient failure"))
	if got := updater.pending[3]; got == nil || got.retryAfter.IsZero() || !got.retryScheduled {
		t.Fatalf("markFailed() pending = %+v, want scheduled retry", got)
	}

	if requiresAuthInDev(http.MethodPost, "/api/v1/packages/npm/lodash") {
		t.Fatal("package detail without refresh suffix requires dev auth")
	}
}
