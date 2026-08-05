package v1

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestNewCheckResponseCacheRefusesUselessConfigurations covers the disabled
// form. A cache with no TTL would replay a scan result forever and one with no
// capacity would evict on every write, so the constructor returns nil instead --
// and the handler calls the cache unconditionally, so nil must stay usable.
func TestNewCheckResponseCacheRefusesUselessConfigurations(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		ttl        time.Duration
		maxEntries int
	}{
		{ttl: 0, maxEntries: 10},
		{ttl: -time.Second, maxEntries: 10},
		{ttl: time.Minute, maxEntries: 0},
		{ttl: time.Minute, maxEntries: -1},
	} {
		if cache := newCheckResponseCache(tc.ttl, tc.maxEntries); cache != nil {
			t.Errorf("newCheckResponseCache(%v, %d) is non-nil, want a disabled cache", tc.ttl, tc.maxEntries)
		}
	}

	var cache *checkResponseCache
	if _, ok := cache.Get("key"); ok {
		t.Error("a disabled cache reported a hit")
	}
	// Must not panic.
	cache.Set("key", cachedCheckResponse{statusCode: http.StatusOK, body: []byte("{}")})
}

// TestCheckResponseCacheRejectsEmptyKeys covers the guard on both accessors. An
// empty key means the request carried no idempotency key, and storing under it
// would let unrelated requests share one cached answer.
func TestCheckResponseCacheRejectsEmptyKeys(t *testing.T) {
	t.Parallel()

	cache := newCheckResponseCache(time.Minute, 4)
	cache.Set("", cachedCheckResponse{statusCode: http.StatusOK, body: []byte("{}")})

	if _, ok := cache.Get(""); ok {
		t.Fatal("an empty key produced a cache hit")
	}
}

// TestCheckResponseCacheDropsExpiredEntriesOnWrite covers the sweep that runs
// before each store. Without it an expired entry would still occupy capacity and
// could evict a live one.
//
// The expired state is planted directly rather than waited for: a sleep-based
// version is only reliable when the machine is idle, and this suite runs
// packages in parallel.
func TestCheckResponseCacheDropsExpiredEntriesOnWrite(t *testing.T) {
	t.Parallel()

	cache := newCheckResponseCache(time.Minute, 8)
	response := cachedCheckResponse{statusCode: http.StatusOK, body: []byte("{}")}
	past := time.Now().Add(-time.Hour)

	cache.mu.Lock()
	for _, key := range []string{"a", "b", "c"} {
		cache.entries[key] = checkResponseCacheEntry{response: response, expires: past, stored: past}
	}
	cache.mu.Unlock()

	// This write sweeps the three expired entries before storing its own.
	cache.Set("fresh", response)

	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()
	if size != 1 {
		t.Fatalf("cache holds %d entries, want only the fresh one", size)
	}
	if _, ok := cache.Get("fresh"); !ok {
		t.Fatal("the fresh entry was swept away with the expired ones")
	}
}

// TestCheckResponseCacheKeyRequiresBothHalves covers the key builder. The cache
// replays a stored answer verbatim, so a key built from only one half would let
// a different request body reuse another request's result.
func TestCheckResponseCacheKeyRequiresBothHalves(t *testing.T) {
	t.Parallel()

	if got := checkResponseCacheKey("", "digest"); got != "" {
		t.Errorf("key without an idempotency key = %q, want empty", got)
	}
	if got := checkResponseCacheKey("idem", ""); got != "" {
		t.Errorf("key without a request digest = %q, want empty", got)
	}

	key := checkResponseCacheKey("idem", "digest")
	if key == "" {
		t.Fatal("a complete pair produced no cache key")
	}
	if !strings.Contains(key, "\x00") {
		t.Errorf("key = %q, want an unambiguous separator between the halves", key)
	}
	if checkResponseCacheKey("idem", "digest") != key {
		t.Error("the key builder is not deterministic")
	}
	if checkResponseCacheKey("idem2", "digest") == key {
		t.Error("different idempotency keys produced the same cache key")
	}
	if checkResponseCacheKey("idem", "digest2") == key {
		t.Error("different request digests produced the same cache key")
	}
}

// TestFeedImportDecodeErrorStaysTransparent covers the decode wrapper. It lets
// the handler name the offending body while callers can still inspect the
// underlying decode failure.
func TestFeedImportDecodeErrorStaysTransparent(t *testing.T) {
	t.Parallel()

	inner := errors.New("unexpected EOF")
	wrapped := &feedImportDecodeError{bodyName: "vulnerabilities", err: inner}

	if wrapped.Error() != inner.Error() {
		t.Errorf("Error() = %q, want the inner message", wrapped.Error())
	}
	if !errors.Is(wrapped, inner) {
		t.Error("errors.Is could not see through feedImportDecodeError")
	}

	// The nil forms are reachable from error-handling paths and must not panic.
	var nilErr *feedImportDecodeError
	if got := nilErr.Error(); got != "" {
		t.Errorf("(*feedImportDecodeError)(nil).Error() = %q, want empty", got)
	}
	if got := nilErr.Unwrap(); got != nil {
		t.Errorf("(*feedImportDecodeError)(nil).Unwrap() = %v, want nil", got)
	}
	if got := (&feedImportDecodeError{bodyName: "vulnerabilities"}).Error(); got != "" {
		t.Errorf("Error() without an inner error = %q, want empty", got)
	}
}

// TestContextualizeFeedImportErrorKeepsTheValidationClassification is the part
// that decides the HTTP status. A validation error must stay one after the
// record context is prepended, or a client's bad payload gets reported as a
// server fault and the importer looks broken.
func TestContextualizeFeedImportErrorKeepsTheValidationClassification(t *testing.T) {
	t.Parallel()

	if got := contextualizeFeedImportError("vulnerabilities[0]", nil); got != nil {
		t.Fatalf("contextualizeFeedImportError(nil) = %v, want nil", got)
	}

	validation := feedImportValidationErrorf("severity %q is not supported", "URGENT")
	contextual := contextualizeFeedImportError("vulnerabilities[3] (id=GHSA-1)", validation)

	var target *feedImportValidationError
	if !errors.As(contextual, &target) {
		t.Fatalf("contextualized error %v lost its validation classification", contextual)
	}
	if !strings.Contains(contextual.Error(), "vulnerabilities[3] (id=GHSA-1)") {
		t.Errorf("error = %v, want the record context prepended", contextual)
	}
	if !strings.Contains(contextual.Error(), "URGENT") {
		t.Errorf("error = %v, want the original detail retained", contextual)
	}
}

// TestContextualizeFeedImportErrorWrapsOtherFailures covers the other branch: an
// infrastructure failure keeps its identity for errors.Is while still naming the
// record that triggered it.
func TestContextualizeFeedImportErrorWrapsOtherFailures(t *testing.T) {
	t.Parallel()

	inner := errors.New("connection reset")
	contextual := contextualizeFeedImportError("malicious[7]", inner)

	if !errors.Is(contextual, inner) {
		t.Fatalf("error %v no longer matches the underlying failure", contextual)
	}
	var validation *feedImportValidationError
	if errors.As(contextual, &validation) {
		t.Fatal("an infrastructure error was classified as a validation error")
	}
	if !strings.Contains(contextual.Error(), "malicious[7]") {
		t.Errorf("error = %v, want the record context prepended", contextual)
	}
}
