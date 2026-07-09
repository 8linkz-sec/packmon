// Package ratelimit provides a small token-bucket limiter for feed workers.
package ratelimit

import (
	"sync"
	"time"
)

// Bucket holds token-bucket state. It can be shared by successive workers so
// runtime reconfiguration does not reset upstream capacity.
type Bucket struct {
	mu               sync.Mutex
	tokens           int
	limit            int
	lastRefill       time.Time
	fractionalTokens float64
}

// State is a point-in-time copy of a bucket's current state.
type State struct {
	Tokens           int
	Limit            int
	LastRefill       time.Time
	FractionalTokens float64
}

// New creates a token bucket with a calls-per-hour limit. If callsPerHour is
// invalid, defaultCallsPerHour is used.
func New(callsPerHour, defaultCallsPerHour int) *Bucket {
	if callsPerHour <= 0 {
		callsPerHour = defaultCallsPerHour
	}
	if callsPerHour <= 0 {
		callsPerHour = 1
	}
	return &Bucket{
		tokens:     callsPerHour,
		limit:      callsPerHour,
		lastRefill: time.Now(),
	}
}

// SetLimit updates the calls-per-hour limit without granting fresh capacity to
// partially used buckets. Buckets that were full remain full at the new limit.
func (b *Bucket) SetLimit(callsPerHour int) {
	if b == nil || callsPerHour <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	wasFull := b.tokens >= b.limit
	b.limit = callsPerHour
	switch {
	case wasFull:
		b.tokens = callsPerHour
	case b.tokens > callsPerHour:
		b.tokens = callsPerHour
	}
}

// Limit returns the current calls-per-hour limit.
func (b *Bucket) Limit() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.limit
}

// Snapshot returns the current bucket state without refilling.
func (b *Bucket) Snapshot() State {
	if b == nil {
		return State{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return State{
		Tokens:           b.tokens,
		Limit:            b.limit,
		LastRefill:       b.lastRefill,
		FractionalTokens: b.fractionalTokens,
	}
}

// Acquire attempts to take one token from the bucket. Tokens refill
// proportionally based on elapsed time since the last refill.
func (b *Bucket) Acquire() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refillLocked(time.Now())
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// Return puts one token back, up to the configured limit.
func (b *Bucket) Return() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tokens < b.limit {
		b.tokens++
	}
}

// Drain clears all available and fractional tokens.
func (b *Bucket) Drain() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens = 0
	b.fractionalTokens = 0
	b.lastRefill = time.Now()
}

func (b *Bucket) refillLocked(now time.Time) {
	elapsed := now.Sub(b.lastRefill)
	if elapsed <= 0 {
		return
	}

	raw := elapsed.Seconds() * float64(b.limit) / 3600.0
	b.fractionalTokens += raw
	whole := int(b.fractionalTokens)
	b.fractionalTokens -= float64(whole)
	b.lastRefill = now
	if whole <= 0 {
		return
	}

	b.tokens += whole
	if b.tokens > b.limit {
		b.tokens = b.limit
	}
}
