package ratelimit

import (
	"testing"
	"time"
)

func TestBucketConsumesReturnsAndDrainsTokens(t *testing.T) {
	t.Parallel()

	bucket := New(2, 500)
	first := bucket
	second := bucket

	if !first.Acquire() {
		t.Fatal("first Acquire() = false, want first shared token")
	}
	if !second.Acquire() {
		t.Fatal("second Acquire() = false, want second shared token")
	}
	if second.Acquire() {
		t.Fatal("third Acquire() = true, want exhausted shared bucket")
	}

	first.Return()
	first.Return()
	first.Return()
	state := bucket.Snapshot()
	if state.Tokens != 2 || state.Limit != 2 {
		t.Fatalf("after capped returns tokens/limit = %d/%d, want 2/2", state.Tokens, state.Limit)
	}

	bucket.fractionalTokens = 0.75
	bucket.Drain()
	state = bucket.Snapshot()
	if state.Tokens != 0 || state.FractionalTokens != 0 {
		t.Fatalf("after drain tokens/fractional = %d/%.2f, want 0/0", state.Tokens, state.FractionalTokens)
	}
}

func TestBucketRefillsUsingAccumulatedFractionalTokens(t *testing.T) {
	t.Parallel()

	bucket := New(60, 500)
	bucket.tokens = 0
	bucket.fractionalTokens = 0.75
	bucket.lastRefill = time.Now().Add(-15 * time.Second)

	if !bucket.Acquire() {
		t.Fatal("Acquire() = false, want true after fractional refill reaches one token")
	}
	state := bucket.Snapshot()
	if state.Tokens != 0 {
		t.Fatalf("tokens after acquire = %d, want 0", state.Tokens)
	}
}

func TestSetLimitKeepsFullBucketsFullAndCapsOverLimitBuckets(t *testing.T) {
	t.Parallel()

	full := New(10, 500)
	full.SetLimit(7)
	state := full.Snapshot()
	if state.Tokens != 7 || state.Limit != 7 {
		t.Fatalf("full bucket after SetLimit = %d/%d, want 7/7", state.Tokens, state.Limit)
	}

	partiallyUsed := New(10, 500)
	if !partiallyUsed.Acquire() || !partiallyUsed.Acquire() || !partiallyUsed.Acquire() {
		t.Fatal("failed to consume setup tokens")
	}
	partiallyUsed.SetLimit(12)
	state = partiallyUsed.Snapshot()
	if state.Tokens != 7 || state.Limit != 12 {
		t.Fatalf("partially used bucket after raise = %d/%d, want 7/12", state.Tokens, state.Limit)
	}

	partiallyUsed.SetLimit(5)
	state = partiallyUsed.Snapshot()
	if state.Tokens != 5 || state.Limit != 5 {
		t.Fatalf("over-limit bucket after lower = %d/%d, want 5/5", state.Tokens, state.Limit)
	}
}

func TestNewUsesDefaultLimitForInvalidConfiguredLimit(t *testing.T) {
	t.Parallel()

	bucket := New(0, 300)
	state := bucket.Snapshot()
	if state.Tokens != 300 || state.Limit != 300 {
		t.Fatalf("tokens/limit = %d/%d, want default 300/300", state.Tokens, state.Limit)
	}
}
