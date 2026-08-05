package v1

import (
	"sync"
	"time"
)

const (
	defaultCheckResponseCacheTTL        = 10 * time.Minute
	defaultCheckResponseCacheMaxEntries = 256
)

type cachedCheckResponse struct {
	statusCode int
	durationMs int64
	body       []byte
}

type checkResponseCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	entries    map[string]checkResponseCacheEntry
}

type checkResponseCacheEntry struct {
	response cachedCheckResponse
	expires  time.Time
	stored   time.Time
}

func newCheckResponseCache(ttl time.Duration, maxEntries int) *checkResponseCache {
	if ttl <= 0 || maxEntries <= 0 {
		return nil
	}
	return &checkResponseCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    make(map[string]checkResponseCacheEntry),
	}
}

func (c *checkResponseCache) Get(key string) (cachedCheckResponse, bool) {
	if c == nil || key == "" {
		return cachedCheckResponse{}, false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return cachedCheckResponse{}, false
	}
	if !entry.expires.After(now) {
		delete(c.entries, key)
		return cachedCheckResponse{}, false
	}
	return cloneCachedCheckResponse(entry.response), true
}

func (c *checkResponseCache) Set(key string, response cachedCheckResponse) {
	if c == nil || key == "" || response.statusCode < 200 || response.statusCode >= 300 || len(response.body) == 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleteExpiredLocked(now)
	if len(c.entries) >= c.maxEntries {
		c.deleteOldestLocked()
	}
	c.entries[key] = checkResponseCacheEntry{
		response: cloneCachedCheckResponse(response),
		expires:  now.Add(c.ttl),
		stored:   now,
	}
}

func (c *checkResponseCache) deleteExpiredLocked(now time.Time) {
	for key, entry := range c.entries {
		if !entry.expires.After(now) {
			delete(c.entries, key)
		}
	}
}

func (c *checkResponseCache) deleteOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	for key, entry := range c.entries {
		if oldestKey == "" || entry.stored.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.stored
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

func cloneCachedCheckResponse(response cachedCheckResponse) cachedCheckResponse {
	response.body = append([]byte(nil), response.body...)
	return response
}

func checkResponseCacheKey(storedIdempotencyKey, requestDigest string) string {
	if storedIdempotencyKey == "" || requestDigest == "" {
		return ""
	}
	return storedIdempotencyKey + "\x00" + requestDigest
}
