package config

import "sync"

// RuntimeSettings holds the subset of server settings that an administrator can
// change at runtime via the admin UI and that must take effect without a
// restart: the API block threshold and the global HTTP rate limit.
//
// All access is synchronized so the live HTTP handlers (block-threshold
// decision) and the rate-limiter middleware can read the current values on
// every request while the admin save handler updates them concurrently.
type RuntimeSettings struct {
	mu                 sync.RWMutex
	blockThreshold     string
	rateLimitPerMinute int
	rateLimitBurst     int
}

// NewRuntimeSettings creates a holder seeded with the given values.
func NewRuntimeSettings(blockThreshold string, perMinute, burst int) *RuntimeSettings {
	return &RuntimeSettings{
		blockThreshold:     blockThreshold,
		rateLimitPerMinute: perMinute,
		rateLimitBurst:     burst,
	}
}

// BlockThreshold returns the current API block threshold.
func (r *RuntimeSettings) BlockThreshold() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.blockThreshold
}

// RateLimit returns the current per-minute rate and burst for the global HTTP
// rate limiter.
func (r *RuntimeSettings) RateLimit() (perMinute, burst int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.rateLimitPerMinute, r.rateLimitBurst
}

// Update replaces the live values. Empty/non-positive arguments are ignored so
// callers can update a single setting without clobbering the others.
func (r *RuntimeSettings) Update(blockThreshold string, perMinute, burst int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if blockThreshold != "" {
		r.blockThreshold = blockThreshold
	}
	if perMinute > 0 {
		r.rateLimitPerMinute = perMinute
	}
	if burst > 0 {
		r.rateLimitBurst = burst
	}
}
