package v1

import (
	"net/http"
	"testing"
	"time"
)

func TestCheckResponseCacheExpiresEntries(t *testing.T) {
	t.Parallel()

	cache := newCheckResponseCache(time.Nanosecond, 2)
	cache.Set("key", cachedCheckResponse{
		statusCode: http.StatusOK,
		durationMs: 7,
		body:       []byte(`{"ok":true}`),
	})

	time.Sleep(time.Millisecond)

	if _, ok := cache.Get("key"); ok {
		t.Fatal("expired cache entry was returned")
	}
}

func TestCheckResponseCacheEvictsOldestEntry(t *testing.T) {
	t.Parallel()

	cache := newCheckResponseCache(time.Minute, 2)
	cache.Set("oldest", cachedCheckResponse{statusCode: http.StatusOK, body: []byte(`{"n":1}`)})
	time.Sleep(time.Millisecond)
	cache.Set("middle", cachedCheckResponse{statusCode: http.StatusOK, body: []byte(`{"n":2}`)})
	time.Sleep(time.Millisecond)
	cache.Set("newest", cachedCheckResponse{statusCode: http.StatusOK, body: []byte(`{"n":3}`)})

	if _, ok := cache.Get("oldest"); ok {
		t.Fatal("oldest cache entry was not evicted")
	}
	if _, ok := cache.Get("middle"); !ok {
		t.Fatal("middle cache entry was evicted")
	}
	if _, ok := cache.Get("newest"); !ok {
		t.Fatal("newest cache entry was evicted")
	}
}

func TestCheckResponseCacheCopiesResponseBody(t *testing.T) {
	t.Parallel()

	cache := newCheckResponseCache(time.Minute, 1)
	body := []byte(`{"ok":true}`)
	cache.Set("key", cachedCheckResponse{
		statusCode: http.StatusOK,
		durationMs: 7,
		body:       body,
	})
	body[1] = 'X'

	cached, ok := cache.Get("key")
	if !ok {
		t.Fatal("cache entry missing")
	}
	if string(cached.body) != `{"ok":true}` {
		t.Fatalf("cached body = %q, want original body", cached.body)
	}

	cached.body[1] = 'Y'
	cachedAgain, ok := cache.Get("key")
	if !ok {
		t.Fatal("cache entry missing after returned-body mutation")
	}
	if string(cachedAgain.body) != `{"ok":true}` {
		t.Fatalf("cached body after mutation = %q, want original body", cachedAgain.body)
	}
}

func TestCheckResponseCacheIgnoresUnsuccessfulResponses(t *testing.T) {
	t.Parallel()

	cache := newCheckResponseCache(time.Minute, 1)
	cache.Set("key", cachedCheckResponse{
		statusCode: http.StatusInternalServerError,
		body:       []byte(`{"error":"failed"}`),
	})

	if _, ok := cache.Get("key"); ok {
		t.Fatal("unsuccessful response was cached")
	}
}
