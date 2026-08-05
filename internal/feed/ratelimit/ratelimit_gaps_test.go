package ratelimit

import (
	"testing"
	"time"
)

func TestNewFallsBackForInvalidLimits(t *testing.T) {
	t.Parallel()

	if got := New(0, 25).Limit(); got != 25 {
		t.Fatalf("New(0, 25).Limit() = %d, want default 25", got)
	}
	if got := New(-3, 0).Limit(); got != 1 {
		t.Fatalf("New(-3, 0).Limit() = %d, want minimum 1", got)
	}
	if got := New(10, 25).Limit(); got != 10 {
		t.Fatalf("New(10, 25).Limit() = %d, want configured 10", got)
	}
}

func TestNilBucketMethodsAreSafe(t *testing.T) {
	t.Parallel()

	var b *Bucket
	b.SetLimit(10)
	b.Return()
	b.Drain()
	if b.Limit() != 0 {
		t.Fatalf("nil bucket Limit() = %d, want 0", b.Limit())
	}
	if b.Acquire() {
		t.Fatal("nil bucket Acquire() = true, want false")
	}
	if state := b.Snapshot(); state.Limit != 0 || state.Tokens != 0 {
		t.Fatalf("nil bucket Snapshot() = %+v, want zero state", state)
	}
}

func TestSetLimitPreservesPartialConsumption(t *testing.T) {
	t.Parallel()

	full := New(4, 0)
	full.SetLimit(6)
	if state := full.Snapshot(); state.Limit != 6 || state.Tokens != 6 {
		t.Fatalf("SetLimit(full bucket) state = %+v, want refill to new limit", state)
	}

	partial := New(4, 0)
	if !partial.Acquire() {
		t.Fatal("Acquire() = false, want token from fresh bucket")
	}
	partial.SetLimit(10)
	if state := partial.Snapshot(); state.Limit != 10 || state.Tokens != 3 {
		t.Fatalf("SetLimit(partial bucket) state = %+v, want tokens kept at 3", state)
	}

	overCapacity := New(8, 0)
	overCapacity.Return()
	if !overCapacity.Acquire() {
		t.Fatal("Acquire() = false, want token")
	}
	overCapacity.SetLimit(2)
	if state := overCapacity.Snapshot(); state.Limit != 2 || state.Tokens > 2 {
		t.Fatalf("SetLimit(shrink) state = %+v, want tokens clamped to new limit", state)
	}

	overCapacity.SetLimit(0)
	if state := overCapacity.Snapshot(); state.Limit != 2 {
		t.Fatalf("SetLimit(0) state = %+v, want limit unchanged", state)
	}
}

func TestAcquireReturnAndDrainLifecycle(t *testing.T) {
	t.Parallel()

	b := New(2, 0)
	for i := range 2 {
		if !b.Acquire() {
			t.Fatalf("Acquire() call %d = false, want token from fresh bucket", i+1)
		}
	}
	if b.Acquire() {
		t.Fatal("Acquire() on empty bucket = true, want false")
	}

	b.Return()
	if state := b.Snapshot(); state.Tokens != 1 {
		t.Fatalf("Snapshot() after Return = %+v, want one token", state)
	}
	b.Return()
	b.Return()
	if state := b.Snapshot(); state.Tokens != 2 {
		t.Fatalf("Snapshot() after over-Return = %+v, want tokens capped at limit", state)
	}

	b.Drain()
	if state := b.Snapshot(); state.Tokens != 0 || state.FractionalTokens != 0 {
		t.Fatalf("Snapshot() after Drain = %+v, want empty bucket", state)
	}
	if b.Acquire() {
		t.Fatal("Acquire() right after Drain = true, want false")
	}
}

func TestAcquireRefillsProportionallyOverTime(t *testing.T) {
	t.Parallel()

	b := New(3600, 0) // one token per second keeps the test fast and deterministic
	b.Drain()

	b.mu.Lock()
	b.lastRefill = time.Now().Add(-2 * time.Second)
	b.mu.Unlock()

	if !b.Acquire() {
		t.Fatal("Acquire() after elapsed refill window = false, want refilled token")
	}
}
