package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRegistryLookupPhaseBreakerTripsAtThreshold(t *testing.T) {
	t.Parallel()
	_, phase := withRegistryLookupPhase(context.Background(), 0)
	for i := 0; i < registryBreakerThreshold-1; i++ {
		phase.recordRefusal()
	}
	if phase.breakerOpen() {
		t.Fatalf("breaker open after %d refusals, want closed", registryBreakerThreshold-1)
	}
	phase.recordRefusal()
	if !phase.breakerOpen() {
		t.Fatalf("breaker closed after %d refusals, want open", registryBreakerThreshold)
	}
	if got := phase.refusedCount(); got != registryBreakerThreshold {
		t.Fatalf("refusedCount() = %d, want %d", got, registryBreakerThreshold)
	}
}

func TestRegistryLookupPhaseSuccessKeepsLatchedBreakerAndCumulativeRefusals(t *testing.T) {
	t.Parallel()
	_, phase := withRegistryLookupPhase(context.Background(), 0)
	for i := 0; i < registryBreakerThreshold; i++ {
		phase.recordRefusal()
	}
	if !phase.breakerOpen() {
		t.Fatal("breaker closed at refusal threshold")
	}

	phase.recordSuccess()
	if got := phase.consecutive.Load(); got != 0 {
		t.Fatalf("consecutive refusals after success = %d, want 0", got)
	}
	if got := phase.refusedCount(); got != registryBreakerThreshold {
		t.Fatalf("refusedCount() after success = %d, want %d", got, registryBreakerThreshold)
	}
	if !phase.breakerOpen() {
		t.Fatal("breaker closed after success, want latched open")
	}

	phase.recordRefusal()
	if got := phase.refusedCount(); got != registryBreakerThreshold+1 {
		t.Fatalf("refusedCount() after additional refusal = %d, want %d", got, registryBreakerThreshold+1)
	}
	if !phase.breakerOpen() {
		t.Fatal("breaker closed after additional refusal, want latched open")
	}
}

func TestRegistryLookupPhaseSuccessResetsStreak(t *testing.T) {
	t.Parallel()
	_, phase := withRegistryLookupPhase(context.Background(), 0)
	for i := 0; i < registryBreakerThreshold-1; i++ {
		phase.recordRefusal()
	}
	phase.recordSuccess()
	phase.recordRefusal()
	if phase.breakerOpen() {
		t.Fatal("breaker open although a success reset the streak")
	}
}

func TestRegistryLookupPhaseSkippedCounter(t *testing.T) {
	t.Parallel()
	_, phase := withRegistryLookupPhase(context.Background(), 0)
	phase.recordSkipped()
	phase.recordSkipped()
	if got := phase.skippedCount(); got != 2 {
		t.Fatalf("skippedCount() = %d, want 2", got)
	}
}

func TestRegistryLookupPhasePerRequestTimeout(t *testing.T) {
	t.Parallel()
	_, phase := withRegistryLookupPhase(context.Background(), 90)
	if got := phase.perRequestTimeout(); got != 90*time.Second {
		t.Fatalf("perRequestTimeout() = %v, want 90s", got)
	}
	_, def := withRegistryLookupPhase(context.Background(), 0)
	if got := def.perRequestTimeout(); got != defaultPerRequestLookupTimeout {
		t.Fatalf("default perRequestTimeout() = %v, want %v", got, defaultPerRequestLookupTimeout)
	}
}

func TestRegistryLookupPhaseNilSafety(t *testing.T) {
	t.Parallel()
	var phase *registryLookupPhase
	phase.recordRefusal()
	phase.recordSuccess()
	phase.recordSkipped()
	if phase.breakerOpen() || phase.refusedCount() != 0 || phase.skippedCount() != 0 {
		t.Fatal("nil phase must be inert")
	}
	if got := phase.perRequestTimeout(); got != defaultPerRequestLookupTimeout {
		t.Fatalf("nil phase perRequestTimeout() = %v, want default", got)
	}
	if got := registryLookupPhaseFrom(context.Background()); got != nil {
		t.Fatalf("registryLookupPhaseFrom(no phase) = %v, want nil", got)
	}
	if got := registryLookupPhaseFrom(nil); got != nil {
		t.Fatalf("registryLookupPhaseFrom(nil) = %v, want nil", got)
	}
}

func TestRegistryLookupPhaseSetsNoDeadline(t *testing.T) {
	t.Parallel()
	ctx, _ := withRegistryLookupPhase(context.Background(), 30)
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("phase context has a deadline; the phase must be unbounded")
	}
}

func TestRegistryLookupPhaseContextsKeepIndependentState(t *testing.T) {
	t.Parallel()
	firstCtx, first := withRegistryLookupPhase(context.Background(), 10)
	secondCtx, second := withRegistryLookupPhase(context.Background(), 20)

	if got := registryLookupPhaseFrom(firstCtx); got != first {
		t.Fatalf("first phase from context = %p, want %p", got, first)
	}
	if got := registryLookupPhaseFrom(secondCtx); got != second {
		t.Fatalf("second phase from context = %p, want %p", got, second)
	}

	first.recordRefusal()
	first.recordSkipped()
	if got := second.refusedCount(); got != 0 {
		t.Fatalf("second refused count = %d, want 0", got)
	}
	if got := second.skippedCount(); got != 0 {
		t.Fatalf("second skipped count = %d, want 0", got)
	}
	if got := first.perRequestTimeout(); got != 10*time.Second {
		t.Fatalf("first timeout = %v, want 10s", got)
	}
	if got := second.perRequestTimeout(); got != 20*time.Second {
		t.Fatalf("second timeout = %v, want 20s", got)
	}
}

func TestRegistryLookupPhaseInheritsParentCancellationAndDeadline(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithCancel(context.Background())
	ctx, _ := withRegistryLookupPhase(parent, 0)
	cancel()
	if err := ctx.Err(); err != context.Canceled {
		t.Fatalf("phase context error after parent cancellation = %v, want %v", err, context.Canceled)
	}

	deadline := time.Now().Add(time.Minute)
	deadlineParent, deadlineCancel := context.WithDeadline(context.Background(), deadline)
	defer deadlineCancel()
	deadlineCtx, _ := withRegistryLookupPhase(deadlineParent, 0)
	got, ok := deadlineCtx.Deadline()
	if !ok {
		t.Fatal("phase context did not inherit parent deadline")
	}
	if !got.Equal(deadline) {
		t.Fatalf("phase deadline = %v, want %v", got, deadline)
	}

	nilParentCtx, nilParentPhase := withRegistryLookupPhase(nil, 0)
	if got := registryLookupPhaseFrom(nilParentCtx); got != nilParentPhase {
		t.Fatalf("nil-parent phase from context = %p, want %p", got, nilParentPhase)
	}
	if _, ok := nilParentCtx.Deadline(); ok {
		t.Fatal("nil-parent phase context has a deadline")
	}
	if err := nilParentCtx.Err(); err != nil {
		t.Fatalf("nil-parent phase context error = %v, want nil", err)
	}
}

func TestRegistryLookupPhaseConcurrentCountersTripBreakerWithoutLostIncrements(t *testing.T) {
	t.Parallel()
	_, phase := withRegistryLookupPhase(context.Background(), 0)
	const workers = registryBreakerThreshold * 4

	ready := sync.WaitGroup{}
	ready.Add(workers)
	start := make(chan struct{})
	var done sync.WaitGroup
	done.Add(workers)
	for range workers {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			phase.recordRefusal()
			phase.recordSkipped()
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()

	if got := phase.refusedCount(); got != workers {
		t.Fatalf("concurrent refused count = %d, want %d", got, workers)
	}
	if got := phase.skippedCount(); got != workers {
		t.Fatalf("concurrent skipped count = %d, want %d", got, workers)
	}
	if !phase.breakerOpen() {
		t.Fatalf("breaker closed after %d concurrent refusals, want open", workers)
	}
}
