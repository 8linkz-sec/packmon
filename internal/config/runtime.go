package config

import (
	"sync"
	"time"
)

// RuntimeSettings holds the subset of server settings that an administrator can
// change at runtime via the admin UI and that must take effect without a
// restart: the API block threshold and the global HTTP rate limit.
//
// All access is synchronized so the live HTTP handlers (block-threshold
// decision) and the rate-limiter middleware can read the current values on
// every request while the admin save handler updates them concurrently.
type RuntimeSettings struct {
	mu                  sync.RWMutex
	blockThreshold      string
	rateLimitPerMinute  int
	rateLimitBurst      int
	scanLogRetention    time.Duration
	adminAuditRetention time.Duration
}

// NewRuntimeSettings creates a holder seeded with the given values.
func NewRuntimeSettings(blockThreshold string, perMinute, burst int) *RuntimeSettings {
	return &RuntimeSettings{
		blockThreshold:      blockThreshold,
		rateLimitPerMinute:  perMinute,
		rateLimitBurst:      burst,
		scanLogRetention:    30 * 24 * time.Hour,
		adminAuditRetention: 30 * 24 * time.Hour,
	}
}

// NewRuntimeSettingsFromConfig creates a runtime settings holder seeded from
// the effective startup config, including admin-managed retention values.
func NewRuntimeSettingsFromConfig(cfg *Config) *RuntimeSettings {
	blockThreshold := "CRITICAL"
	perMinute := 60
	burst := 60
	var scanLogRetention time.Duration
	var adminAuditRetention time.Duration
	if cfg != nil {
		if cfg.Server.BlockThreshold != "" {
			blockThreshold = cfg.Server.BlockThreshold
		}
		if cfg.Server.RateLimitPerMinute > 0 {
			perMinute = cfg.Server.RateLimitPerMinute
		}
		if cfg.Server.RateLimitBurst > 0 {
			burst = cfg.Server.RateLimitBurst
		}
		scanLogRetention = cfg.Retention.ScanLog
		adminAuditRetention = cfg.Retention.AdminAuditLog
	}
	runtime := NewRuntimeSettings(blockThreshold, perMinute, burst)
	runtime.UpdateRetention(scanLogRetention, adminAuditRetention)
	return runtime
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

// Retention returns the current admin-managed metadata retention settings.
func (r *RuntimeSettings) Retention() RetentionConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return RetentionConfig{
		ScanLog:       r.scanLogRetention,
		AdminAuditLog: r.adminAuditRetention,
	}
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

// UpdateRetention replaces admin-managed retention durations. Zero is valid
// and disables pruning for that dataset; negative values are ignored.
func (r *RuntimeSettings) UpdateRetention(scanLog, adminAuditLog time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if scanLog >= 0 {
		r.scanLogRetention = scanLog
	}
	if adminAuditLog >= 0 {
		r.adminAuditRetention = adminAuditLog
	}
}
