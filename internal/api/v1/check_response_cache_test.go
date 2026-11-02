package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestCheckResponseCacheExpiresEntries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := newCheckResponseCache(time.Second, 2)
		cache.Set("key", cachedCheckResponse{
			statusCode: http.StatusOK,
			durationMs: 7,
			body:       []byte(`{"ok":true}`),
		})

		time.Sleep(time.Second)

		if _, ok := cache.Get("key"); ok {
			t.Fatal("expired cache entry was returned")
		}
	})
}

func TestCheckResponseCacheEvictsOldestEntry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := newCheckResponseCache(time.Minute, 2)
		cache.Set("oldest", cachedCheckResponse{statusCode: http.StatusOK, body: []byte(`{"n":1}`)})
		time.Sleep(time.Second)
		cache.Set("middle", cachedCheckResponse{statusCode: http.StatusOK, body: []byte(`{"n":2}`)})
		time.Sleep(time.Second)
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
	})
}

func TestCheckResponseCacheOverwriteAtCapacityDoesNotEvict(t *testing.T) {
	t.Parallel()

	cache := newCheckResponseCache(time.Minute, 2)
	cache.Set("older", cachedCheckResponse{statusCode: http.StatusOK, body: []byte(`{"n":1}`)})
	cache.Set("newer", cachedCheckResponse{statusCode: http.StatusOK, body: []byte(`{"n":2}`)})
	// Make the insertion order explicit instead of relying on clock ticks.
	cache.mu.Lock()
	older := cache.entries["older"]
	older.stored = older.stored.Add(-time.Second)
	cache.entries["older"] = older
	cache.mu.Unlock()

	// A duplicate completion re-stores an existing key while the cache is full.
	cache.Set("newer", cachedCheckResponse{statusCode: http.StatusOK, body: []byte(`{"n":3}`)})

	if _, ok := cache.Get("older"); !ok {
		t.Fatal("overwriting an existing key evicted an unrelated live entry")
	}
	cached, ok := cache.Get("newer")
	if !ok {
		t.Fatal("overwritten cache entry missing")
	}
	if string(cached.body) != `{"n":3}` {
		t.Fatalf("overwritten cache body = %q, want latest body", cached.body)
	}
	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()
	if size != 2 {
		t.Fatalf("cache size after overwrite = %d, want exactly 2", size)
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

func TestCheckResponseCacheAdmissionBoundariesPreserveExistingEntries(t *testing.T) {
	t.Parallel()

	cache := newCheckResponseCache(time.Minute, 3)
	existing := cachedCheckResponse{statusCode: http.StatusAccepted, durationMs: 11, body: []byte(`{"stable":true}`)}
	cache.Set("existing", existing)
	cache.Set("ok", cachedCheckResponse{statusCode: http.StatusOK, durationMs: 20, body: []byte(`{"status":200}`)})
	cache.Set("last-success", cachedCheckResponse{statusCode: 299, durationMs: 29, body: []byte(`{"status":299}`)})

	for _, response := range []cachedCheckResponse{
		{statusCode: 199, durationMs: 99, body: []byte(`{"invalid":199}`)},
		{statusCode: 300, durationMs: 99, body: []byte(`{"invalid":300}`)},
		{statusCode: http.StatusOK, durationMs: 99, body: nil},
		{statusCode: http.StatusOK, durationMs: 99, body: []byte{}},
	} {
		cache.Set("existing", response)
	}
	cache.Set("new-199", cachedCheckResponse{statusCode: 199, body: []byte(`{"invalid":199}`)})
	cache.Set("new-300", cachedCheckResponse{statusCode: 300, body: []byte(`{"invalid":300}`)})
	cache.Set("new-nil", cachedCheckResponse{statusCode: http.StatusOK})
	cache.Set("new-empty", cachedCheckResponse{statusCode: http.StatusOK, body: []byte{}})

	assertCachedResponse(t, cache, "existing", existing)
	assertCachedResponse(t, cache, "ok", cachedCheckResponse{statusCode: http.StatusOK, durationMs: 20, body: []byte(`{"status":200}`)})
	assertCachedResponse(t, cache, "last-success", cachedCheckResponse{statusCode: 299, durationMs: 29, body: []byte(`{"status":299}`)})

	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()
	if size != 3 {
		t.Fatalf("cache size after invalid admissions = %d, want exactly 3", size)
	}
}

func TestCheckResponseCacheConcurrentAccessPreservesCapacityAndResponses(t *testing.T) {
	t.Parallel()

	const (
		capacity = 7
		writers  = 48
	)
	cache := newCheckResponseCache(time.Minute, capacity)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range writers {
		i := i
		wg.Go(func() {
			<-start
			key := "key-" + strconv.Itoa(i)
			body := []byte(`{"value":` + strconv.Itoa(i) + `}`)
			cache.Set(key, cachedCheckResponse{statusCode: http.StatusOK, durationMs: int64(i), body: body})
			body[0] = 'X'
			_, _ = cache.Get(key)
		})
	}
	close(start)
	wg.Wait()

	cache.mu.Lock()
	if len(cache.entries) != capacity {
		size := len(cache.entries)
		cache.mu.Unlock()
		t.Fatalf("cache size after contention = %d, want exactly %d", size, capacity)
	}
	retained := make(map[string]cachedCheckResponse, len(cache.entries))
	for key, entry := range cache.entries {
		retained[key] = cloneCachedCheckResponse(entry.response)
	}
	cache.mu.Unlock()

	for key, want := range retained {
		got, ok := cache.Get(key)
		if !ok {
			t.Fatalf("retained cache entry %q disappeared", key)
		}
		index, err := strconv.Atoi(strings.TrimPrefix(key, "key-"))
		if err != nil {
			t.Fatalf("retained cache key %q has no writer index: %v", key, err)
		}
		exactWant := cachedCheckResponse{
			statusCode: http.StatusOK,
			durationMs: int64(index),
			body:       []byte(`{"value":` + strconv.Itoa(index) + `}`),
		}
		if got.statusCode != exactWant.statusCode || got.durationMs != exactWant.durationMs || string(got.body) != string(exactWant.body) {
			t.Fatalf("retained cache entry %q = %+v, want exact writer response %+v", key, got, exactWant)
		}
		got.body[0] = 'Y'
		again, ok := cache.Get(key)
		if !ok || string(again.body) != string(exactWant.body) || string(want.body) != string(exactWant.body) {
			t.Fatalf("retained cache entry %q changed through returned clone: got %q stored %q want %q", key, again.body, want.body, exactWant.body)
		}
	}
}

type cacheReplayCountingStore struct {
	*stubStore
	mu           sync.Mutex
	durableReads int
}

func (s *cacheReplayCountingStore) GetScanLogByIdempotencyKey(ctx context.Context, key string) (*db.ScanLogEntry, error) {
	s.mu.Lock()
	s.durableReads++
	s.mu.Unlock()
	return s.stubStore.GetScanLogByIdempotencyKey(ctx, key)
}

func (s *cacheReplayCountingStore) durableReadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.durableReads
}

type checkReplayCounters struct {
	durableReads  int
	logs          int
	inserts       int
	vulnerability int
	malicious     int
	reputation    int
	lifecycle     int
	feedStatus    int
}

func snapshotCheckReplayCounters(store *cacheReplayCountingStore) checkReplayCounters {
	durableReads := store.durableReadCount()
	store.stubStore.mu.Lock()
	defer store.stubStore.mu.Unlock()
	return checkReplayCounters{
		durableReads:  durableReads,
		logs:          len(store.scanLogEntries),
		inserts:       store.scanLogInsertCalls,
		vulnerability: len(store.vulnerabilityQueries),
		malicious:     len(store.maliciousQueries),
		reputation:    len(store.reputationQueries),
		lifecycle:     len(store.lifecycleQueries),
		feedStatus:    store.feedStatusListCalls,
	}
}

func TestHandleCheck_IdempotencyReplayRebuildsAfterCacheExpiryOrEviction(t *testing.T) {
	for _, mode := range []string{"expired", "evicted"} {
		t.Run(mode, func(t *testing.T) {
			store := &cacheReplayCountingStore{stubStore: &stubStore{
				vulnBatchFindings: []domain.Finding{{
					Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM,
					Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh,
					AdvisoryID: "GHSA-cache-rebuild", Source: "osv",
				}},
			}}
			h := newTestHandler(store)
			h.ConfigureReversingLabs(config.FeedsConfig{
				ReversingLabsEnabled: true,
				ReversingLabsMode:    config.FeedModeSelf,
			})
			h.checkResponseCache = newCheckResponseCache(time.Minute, 1)
			body := `{"packages":[{"name":"left-pad","version":"1.3.0","ecosystem":"npm"}]}`
			key := "cache-rebuild-" + mode

			first := performIdempotentCheck(t, h, body, key)
			var firstResult domain.ScanResult
			if err := json.Unmarshal(first.Body.Bytes(), &firstResult); err != nil {
				t.Fatalf("decode first response: %v", err)
			}
			if firstResult.ScanID == "" {
				t.Fatal("first scan ID is empty")
			}
			afterFirst := snapshotCheckReplayCounters(store)
			if afterFirst.durableReads == 0 || afterFirst.logs != 1 || afterFirst.inserts != 1 {
				t.Fatalf("idempotency state after seed = %+v, want durable reads and exactly one log/insert", afterFirst)
			}

			switch mode {
			case "expired":
				h.checkResponseCache.mu.Lock()
				for cacheKey, entry := range h.checkResponseCache.entries {
					entry.expires = time.Now().Add(-time.Second)
					h.checkResponseCache.entries[cacheKey] = entry
				}
				h.checkResponseCache.mu.Unlock()
			case "evicted":
				h.checkResponseCache.mu.Lock()
				for cacheKey, entry := range h.checkResponseCache.entries {
					entry.stored = entry.stored.Add(-time.Minute)
					h.checkResponseCache.entries[cacheKey] = entry
				}
				h.checkResponseCache.mu.Unlock()
				h.checkResponseCache.Set("unrelated", cachedCheckResponse{statusCode: http.StatusOK, body: []byte(`{"other":true}`)})
			}

			second := performIdempotentCheck(t, h, body, key)
			var secondResult domain.ScanResult
			if err := json.Unmarshal(second.Body.Bytes(), &secondResult); err != nil {
				t.Fatalf("decode rebuilt response: %v", err)
			}
			afterSecond := snapshotCheckReplayCounters(store)
			if afterSecond.durableReads <= afterFirst.durableReads {
				t.Fatalf("durable reads after cache miss = %d, want more than %d", afterSecond.durableReads, afterFirst.durableReads)
			}
			if afterSecond.logs != 1 || afterSecond.inserts != 1 {
				t.Fatalf("scan-log state after rebuild = %d logs/%d inserts, want 1/1", afterSecond.logs, afterSecond.inserts)
			}
			if afterSecond.vulnerability <= afterFirst.vulnerability ||
				afterSecond.malicious <= afterFirst.malicious ||
				afterSecond.reputation <= afterFirst.reputation ||
				afterSecond.lifecycle <= afterFirst.lifecycle ||
				afterSecond.feedStatus <= afterFirst.feedStatus {
				t.Fatalf("lookup counters did not all advance on rebuild: first=%+v second=%+v", afterFirst, afterSecond)
			}
			if secondResult.ScanID != firstResult.ScanID {
				t.Fatalf("rebuilt scan ID = %q, want original %q", secondResult.ScanID, firstResult.ScanID)
			}

			third := performIdempotentCheck(t, h, body, key)
			afterThird := snapshotCheckReplayCounters(store)
			if afterThird.durableReads <= afterSecond.durableReads {
				t.Fatalf("durable reads after cache hit = %d, want more than %d", afterThird.durableReads, afterSecond.durableReads)
			}
			if afterThird.logs != 1 || afterThird.inserts != 1 ||
				afterThird.vulnerability != afterSecond.vulnerability ||
				afterThird.malicious != afterSecond.malicious ||
				afterThird.reputation != afterSecond.reputation ||
				afterThird.lifecycle != afterSecond.lifecycle ||
				afterThird.feedStatus != afterSecond.feedStatus {
				t.Fatalf("cache hit changed durable insert or lookup counters: second=%+v third=%+v", afterSecond, afterThird)
			}
			if third.Body.String() != second.Body.String() {
				t.Fatalf("cache-hit body differs from rebuilt body:\nsecond: %s\nthird:  %s", second.Body.String(), third.Body.String())
			}
			if third.Header().Get("X-Scan-Duration-Ms") != second.Header().Get("X-Scan-Duration-Ms") {
				t.Fatalf("cache-hit duration = %q, want rebuilt %q", third.Header().Get("X-Scan-Duration-Ms"), second.Header().Get("X-Scan-Duration-Ms"))
			}
			if second.Header().Get(idempotencyKeyHeader) != key || third.Header().Get(idempotencyKeyHeader) != key {
				t.Fatalf("idempotency headers = %q/%q, want %q", second.Header().Get(idempotencyKeyHeader), third.Header().Get(idempotencyKeyHeader), key)
			}
		})
	}
}

func assertCachedResponse(t *testing.T, cache *checkResponseCache, key string, want cachedCheckResponse) {
	t.Helper()
	got, ok := cache.Get(key)
	if !ok {
		t.Fatalf("cache entry %q missing", key)
	}
	if got.statusCode != want.statusCode || got.durationMs != want.durationMs || string(got.body) != string(want.body) {
		t.Fatalf("cache entry %q = %+v, want %+v", key, got, want)
	}
}

func performIdempotentCheck(t *testing.T, h *Handler, body, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(idempotencyKeyHeader, key)
	rec := httptest.NewRecorder()
	h.HandleCheck(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("check status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	return rec
}
