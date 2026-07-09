package web

import (
	"context"
	"sync"
	"time"
)

const webAggregateCacheTTL = 5 * time.Second

type webAggregateCache[T any] struct {
	mu      sync.RWMutex
	ttl     time.Duration
	value   T
	expires time.Time
	ok      bool
}

func newWebAggregateCache[T any](ttl time.Duration) *webAggregateCache[T] {
	return &webAggregateCache[T]{ttl: ttl}
}

func (c *webAggregateCache[T]) get(ctx context.Context, load func(context.Context) (T, error)) (T, error) {
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
