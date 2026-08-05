package main

import (
	"context"
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
}

func TestRegistryLookupPhaseSetsNoDeadline(t *testing.T) {
	t.Parallel()
	ctx, _ := withRegistryLookupPhase(context.Background(), 30)
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("phase context has a deadline; the phase must be unbounded")
	}
}
