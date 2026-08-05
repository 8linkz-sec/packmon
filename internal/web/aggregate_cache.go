package web

import (
	"context"
	"sync"
	"time"
)

const webAggregateCacheTTL = 5 * time.Second

// AggregateCache memoizes one expensive aggregate value for a short TTL so
// page handlers do not recompute it on every request. Shared by the public web
// and admin handlers.
type AggregateCache[T any] struct {
	mu      sync.RWMutex
	ttl     time.Duration
	value   T
	expires time.Time
	ok      bool
}

// NewAggregateCache returns an AggregateCache with the given TTL; a TTL <= 0
// disables caching.
func NewAggregateCache[T any](ttl time.Duration) *AggregateCache[T] {
	return &AggregateCache[T]{ttl: ttl}
}

// Get returns the cached value or loads and stores a fresh one.
func (c *AggregateCache[T]) Get(ctx context.Context, load func(context.Context) (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if c.ttl <= 0 {
		return load(ctx)
	}

	now := time.Now()
	c.mu.RLock()
	if c.ok && now.Before(c.expires) {
		value := c.value
		c.mu.RUnlock()
		return value, nil
	}
	c.mu.RUnlock()

	value, err := load(ctx)
	if err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	c.mu.Lock()
	c.value = value
	c.expires = time.Now().Add(c.ttl)
	c.ok = true
	c.mu.Unlock()

	return value, nil
}
