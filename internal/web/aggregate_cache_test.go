package web

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAggregateCacheGetPropagatesCanceledContextWithoutLoading(t *testing.T) {
	cache := NewAggregateCache[string](time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	loaded := false
	value, err := cache.Get(ctx, func(context.Context) (string, error) {
		loaded = true
		return "unexpected", nil
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Get error = %v, want context.Canceled", err)
	}
	if value != "" {
		t.Fatalf("Get value = %q, want zero value", value)
	}
	if loaded {
		t.Fatal("Get called loader for an already canceled context")
	}
}

func TestAggregateCacheGetDoesNotCacheLoaderError(t *testing.T) {
	cache := NewAggregateCache[string](time.Minute)
	wantErr := errors.New("load failed")
	calls := 0
	load := func(context.Context) (string, error) {
		calls++
		return "", wantErr
	}

	for range 2 {
		value, err := cache.Get(context.Background(), load)
		if !errors.Is(err, wantErr) {
			t.Fatalf("Get error = %v, want %v", err, wantErr)
		}
		if value != "" {
			t.Fatalf("Get value = %q, want zero value", value)
		}
	}

	if calls != 2 {
		t.Fatalf("loader calls = %d, want 2; failed loads must not be cached", calls)
	}
}

func TestAggregateCacheGetWithDisabledCacheLoadsEveryTime(t *testing.T) {
	cache := NewAggregateCache[string](0)
	calls := 0
	load := func(context.Context) (string, error) {
		calls++
		return "value", nil
	}

	for range 2 {
		value, err := cache.Get(context.Background(), load)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if value != "value" {
			t.Fatalf("Get value = %q, want value", value)
		}
	}

	if calls != 2 {
		t.Fatalf("loader calls = %d, want 2 when caching is disabled", calls)
	}
}

func TestAggregateCacheGetDoesNotStoreValueAfterLoaderCancelsContext(t *testing.T) {
	cache := NewAggregateCache[string](time.Minute)
	ctx, cancel := context.WithCancel(context.Background())

	value, err := cache.Get(ctx, func(context.Context) (string, error) {
		cancel()
		return "stale", nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Get error = %v, want context.Canceled", err)
	}
	if value != "" {
		t.Fatalf("Get value = %q, want zero value", value)
	}

	calls := 0
	value, err = cache.Get(context.Background(), func(context.Context) (string, error) {
		calls++
		return "fresh", nil
	})
	if err != nil {
		t.Fatalf("Get fresh value: %v", err)
	}
	if value != "fresh" {
		t.Fatalf("Get value = %q, want fresh", value)
	}
	if calls != 1 {
		t.Fatalf("fresh loader calls = %d, want 1; canceled result must not be cached", calls)
	}
}
