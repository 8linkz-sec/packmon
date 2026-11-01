package config

import (
	"context"
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

	// commitSlot orders CommitAndPublish calls. It is a one-element channel
	// rather than a mutex so a waiting save can give up when its context ends.
	commitSlotOnce sync.Once
	commitSlot     chan struct{}
}

// SystemSettingsValues is one admin system-settings save as published to the
// live runtime: policy (block threshold, rate limit) and metadata retention
// travel together so overlapping saves cannot leave a mix of both.
type SystemSettingsValues struct {
	BlockThreshold      string
	RateLimitPerMinute  int
	RateLimitBurst      int
	ScanLogRetention    time.Duration
	AdminAuditRetention time.Duration
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
	r.updateLocked(blockThreshold, perMinute, burst)
}

// UpdateRetention replaces admin-managed retention durations. Zero is valid
// and disables pruning for that dataset; negative values are ignored.
func (r *RuntimeSettings) UpdateRetention(scanLog, adminAuditLog time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updateRetentionLocked(scanLog, adminAuditLog)
}

// CommitAndPublish runs commit (the database write of a system-settings save)
// and, when it succeeds, publishes values as one unit before any other
// CommitAndPublish call can start its commit. Holding that order across the
// publication keeps the live settings equal to the last committed row even
// when admin saves overlap; publishing outside it would let an earlier commit
// publish after a later one. Readers are not blocked during commit. When ctx
// ends while waiting for an in-flight save, nothing is committed and ctx's
// error is returned.
func (r *RuntimeSettings) CommitAndPublish(ctx context.Context, values SystemSettingsValues, commit func() error) error {
	r.commitSlotOnce.Do(func() { r.commitSlot = make(chan struct{}, 1) })
	select {
	case r.commitSlot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-r.commitSlot }()

	if err := commit(); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.updateLocked(values.BlockThreshold, values.RateLimitPerMinute, values.RateLimitBurst)
	r.updateRetentionLocked(values.ScanLogRetention, values.AdminAuditRetention)
	return nil
}

func (r *RuntimeSettings) updateLocked(blockThreshold string, perMinute, burst int) {
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

func (r *RuntimeSettings) updateRetentionLocked(scanLog, adminAuditLog time.Duration) {
	if scanLog >= 0 {
		r.scanLogRetention = scanLog
	}
	if adminAuditLog >= 0 {
		r.adminAuditRetention = adminAuditLog
	}
}
