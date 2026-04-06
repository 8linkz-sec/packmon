package feed

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/telemetry"
)

// backoffSchedule defines the delays between retry attempts.
// Three attempts: 5s, 30s, 5min.
var backoffSchedule = [3]time.Duration{
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
}

// Manager orchestrates all registered feed syncers. It runs background
// goroutines that invoke each syncer on a configurable interval, records
// sync status in the database, and shuts down gracefully when the
// context is cancelled.
//
// Per DE-19 there is NO blocking sync on startup. The manager starts its
// loops immediately in the background and the caller returns right away.
type Manager struct {
	feeds    map[string]*registeredFeed
	store    db.Store
	logger   *slog.Logger
	interval time.Duration // default interval; per-feed override possible
	wg       sync.WaitGroup
}

// registeredFeed pairs a FeedConfig with optional per-feed overrides.
type registeredFeed struct {
	config   FeedConfig
	interval time.Duration // 0 = use manager default
	mu       sync.Mutex    // prevents concurrent syncs of the same feed
}

// NewManager creates a Manager. The default sync interval applies to
// every feed that does not specify its own interval. Pass 0 to use the
// hard-coded default of 8 hours.
func NewManager(store db.Store, logger *slog.Logger, defaultInterval time.Duration) *Manager {
	if defaultInterval <= 0 {
		defaultInterval = 8 * time.Hour
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		feeds:    make(map[string]*registeredFeed),
		store:    store,
		logger:   logger,
		interval: defaultInterval,
	}
}

// Register adds a feed to the manager. If the feed is disabled or in
// external mode, the manager will not schedule syncs for it but will
// still record its existence. Register must be called before Start.
func (m *Manager) Register(cfg FeedConfig) {
	if cfg.Syncer == nil {
		return
	}
	m.feeds[cfg.Syncer.Name()] = &registeredFeed{
		config: cfg,
	}
}

// RegisterWithInterval is like Register but sets a feed-specific sync
// interval that overrides the manager default.
func (m *Manager) RegisterWithInterval(cfg FeedConfig, interval time.Duration) {
	if cfg.Syncer == nil {
		return
	}
	m.feeds[cfg.Syncer.Name()] = &registeredFeed{
		config:   cfg,
		interval: interval,
	}
}

// Start launches background goroutines for every registered feed whose
// mode is "self" and whose enabled flag is true. It returns immediately
// (DE-19: no blocking sync on startup). The goroutines run until ctx is
// cancelled; after that, call Wait to block until all goroutines finish.
//
// Feeds run in phases: Phase 1 (vulnerability data: OSV, GHSA, OpenSSF)
// starts immediately. Phase 2 (enrichment: EPSS, CISA KEV, VulnCheck)
// waits for all Phase 1 feeds to complete their initial sync. This
// ensures enrichment feeds find vulnerability data to enrich.
func (m *Manager) Start(ctx context.Context) {
	// Collect Phase 1 initial-done signals so Phase 2 can wait for them.
	var phase1Signals []<-chan struct{}

	for name, rf := range m.feeds {
		if !rf.config.Enabled {
			m.logger.Info("feed disabled, skipping", slog.String("feed", name))
			continue
		}
		if rf.config.Mode == FeedModeExternal {
			m.logger.Info("feed in external mode, skipping self-sync", slog.String("feed", name))
			continue
		}

		interval := rf.interval
		if interval <= 0 {
			interval = m.interval
		}

		phase := rf.config.Phase
		if phase == 0 {
			phase = FeedPhaseVulnerability
		}

		if phase == FeedPhaseVulnerability {
			done := make(chan struct{}, 1)
			phase1Signals = append(phase1Signals, done)
			m.wg.Add(1)
			go m.loop(ctx, rf, interval, done)
		}
	}

	// phase1Done is closed once ALL Phase 1 feeds finish their initial sync.
	phase1Done := make(chan struct{})
	go func() {
		for _, ch := range phase1Signals {
			<-ch
		}

		// Propagate severity from known entries to UNKNOWN aliases.
		// E.g. GO-2026-4856 (UNKNOWN) shares alias CVE-2026-33726 with
		// GHSA-hxv8-4j4r-cqgv (MEDIUM) -- copy MEDIUM to GO-2026-4856.
		if updated, err := m.store.PropagateSeverityViaAliases(ctx); err != nil {
			m.logger.Warn("failed to propagate severity via aliases", "error", err)
		} else if updated > 0 {
			m.logger.Info("propagated severity via aliases", slog.Int("updated", updated))
		}

		close(phase1Done)
	}()

	// Start Phase 2 (enrichment) feeds after Phase 1 completes.
	for name, rf := range m.feeds {
		if !rf.config.Enabled || rf.config.Mode == FeedModeExternal {
			continue
		}
		if rf.config.Phase != FeedPhaseEnrichment {
			continue
		}

		interval := rf.interval
		if interval <= 0 {
			interval = m.interval
		}

		m.wg.Add(1)
		go func(rf *registeredFeed, interval time.Duration, name string) {
			select {
			case <-phase1Done:
				m.logger.Info("phase 1 complete, starting enrichment feed", slog.String("feed", name))
			case <-ctx.Done():
				m.wg.Done()
				return
			}
			m.loop(ctx, rf, interval, nil)
		}(rf, interval, name)
	}
}

// Wait blocks until all background sync goroutines have returned.
// Call this after the context passed to Start has been cancelled.
func (m *Manager) Wait() {
	m.wg.Wait()
}

// SyncOne runs a single feed synchronisation for the named feed,
// regardless of its mode. This is useful for on-demand triggers
// (e.g. admin panel, tests). It returns an error if the feed is
// unknown or the sync itself fails after all retries.
func (m *Manager) SyncOne(ctx context.Context, feedName string) error {
	rf, ok := m.feeds[feedName]
	if !ok {
		return fmt.Errorf("feed %q is not registered", feedName)
	}
	_, err := m.syncWithRetry(ctx, rf)
	return err
}

// loop runs the sync-sleep cycle for a single feed until the context
// is cancelled. If initialDone is non-nil, it is closed after the
// initial sync attempt (success or skip) to signal Phase 2 feeds.
func (m *Manager) loop(ctx context.Context, rf *registeredFeed, interval time.Duration, initialDone chan<- struct{}) {
	defer m.wg.Done()

	name := rf.config.Syncer.Name()
	log := m.logger.With(slog.String("feed", name))

	log.Info("starting feed sync loop",
		slog.String("interval", interval.String()),
	)

	// Check whether the last successful sync is still fresh. If it is,
	// skip the immediate sync and just wait for the next tick. This
	// prevents hammering upstream APIs on every container restart.
	if m.lastSyncFresh(ctx, name, interval) {
		log.Info("last sync still within interval, skipping initial sync")
	} else {
		m.runSync(ctx, rf, log)
	}

	// Signal that the initial sync is done (used by phase-based scheduling).
	if initialDone != nil {
		initialDone <- struct{}{}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("feed sync loop shutting down")
			return
		case <-ticker.C:
			m.runSync(ctx, rf, log)
		}
	}
}

// runSync executes a sync with retries and records the result.
func (m *Manager) runSync(ctx context.Context, rf *registeredFeed, log *slog.Logger) {
	// Bail out early if context is already done.
	if ctx.Err() != nil {
		return
	}

	result, err := m.syncWithRetry(ctx, rf)
	if err != nil {
		if IsPermanentError(err) {
			log.Warn("feed sync skipped (permanent error)",
				slog.String("error", err.Error()),
			)
			// Record the permanent failure so it surfaces in /admin/feeds
			// and /readyz instead of being hidden in logs only (C-3).
			m.recordStatus(ctx, rf.config.Syncer.Name(), "permanent_error", err.Error(), 0, nil)
			return
		}
		log.Error("feed sync failed after all retries",
			slog.String("error", err.Error()),
		)
	} else {
		log.Info("feed sync completed",
			slog.Int("entries_synced", result.EntriesSynced),
			slog.Int("entries_total", result.EntriesTotal),
		)
	}
}

// syncWithRetry runs the syncer up to len(backoffSchedule)+1 times.
// On the first call there is no delay; subsequent retries use the
// exponential backoff schedule. It records the outcome in feed_sync_status.
func (m *Manager) syncWithRetry(ctx context.Context, rf *registeredFeed) (*SyncResult, error) {
	// Prevent concurrent syncs of the same feed (e.g. manual trigger
	// via admin panel while the background loop is already syncing).
	rf.mu.Lock()
	defer rf.mu.Unlock()

	name := rf.config.Syncer.Name()
	log := m.logger.With(slog.String("feed", name))

	maxAttempts := len(backoffSchedule) + 1
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// Wait before retry (skip for the first attempt).
		if attempt > 0 {
			delay := backoffSchedule[attempt-1]
			log.Warn("retrying feed sync",
				slog.Int("attempt", attempt+1),
				slog.String("delay", delay.String()),
				slog.String("last_error", lastErr.Error()),
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		start := time.Now()
		result, err := rf.config.Syncer.Sync(ctx, m.store)
		duration := time.Since(start)

		if err == nil {
			// Success -- record in DB and return.
			m.recordStatus(ctx, name, "success", "", duration, result)
			return result, nil
		}

		lastErr = err
		if IsPermanentError(err) {
			m.recordStatus(ctx, name, "skipped", err.Error(), duration, nil)
			return nil, err
		}
		if isTimeoutError(err) {
			telemetry.Default().IncFeedSyncTimeout(name)
		}
		log.Warn("feed sync attempt failed",
			slog.Int("attempt", attempt+1),
			slog.String("duration", duration.String()),
			slog.String("error", err.Error()),
		)
	}

	// All retries exhausted. Record failure.
	m.recordStatus(ctx, name, "error", lastErr.Error(), 0, nil)
	return nil, fmt.Errorf("feed %s: all %d attempts failed: %w", name, maxAttempts, lastErr)
}

// recordStatus persists the feed_sync_status row. This is the manager's
// own status tracking. Individual syncers may also write their own
// status records with additional details (commit hashes, etc.).
func (m *Manager) recordStatus(ctx context.Context, feedName, status, errMsg string, duration time.Duration, result *SyncResult) {
	// Use a separate timeout so a slow/stuck DB doesn't block the sync loop.
	recordCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = ctx // original context is only used for logging context, not for the DB call

	now := time.Now().UTC()
	fss := &db.FeedSyncStatus{
		FeedName:       feedName,
		LastSyncAt:     &now,
		LastSyncStatus: status,
		LastError:      errMsg,
	}

	if duration > 0 {
		fss.LastSyncDuration = &duration
	}

	if result != nil {
		fss.EntriesSynced = result.EntriesSynced
		fss.EntriesTotal = result.EntriesTotal
	}

	if err := m.store.UpsertFeedSyncStatus(recordCtx, fss); err != nil {
		m.logger.Error("failed to record feed sync status",
			slog.String("feed", feedName),
			slog.String("error", err.Error()),
		)
	}
}

// lastSyncFresh returns true if the named feed was successfully synced
// within the given interval. On any error (e.g. first run, DB
// unreachable) it returns false so the sync proceeds.
func (m *Manager) lastSyncFresh(ctx context.Context, feedName string, interval time.Duration) bool {
	status, err := m.store.GetFeedSyncStatus(ctx, feedName)
	if err != nil || status == nil || status.LastSyncAt == nil {
		return false
	}
	if status.LastSyncStatus != "success" {
		return false
	}
	return time.Since(*status.LastSyncAt) < interval
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded")
}
