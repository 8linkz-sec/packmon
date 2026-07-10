package feed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// backoffSchedule defines the delays between retry attempts.
// Three attempts: 5s, 30s, 5min.
var backoffSchedule = [3]time.Duration{
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
}

const interruptedFeedSyncError = "previous feed sync was interrupted before completion"

// AliasSeverityPropagationStatusName is the feed_sync_status name recorded by
// the post-sync severity-propagation step. It is a pipeline maintenance task,
// not an upstream feed, so it is persisted for observability but excluded from
// user-facing feed listings (see IsSyntheticStatus).
const AliasSeverityPropagationStatusName = "alias-severity-propagation"

// IsSyntheticStatus reports whether a feed_sync_status row is a synthetic
// pipeline/maintenance entry rather than a real upstream feed. Such rows are
// recorded for observability but must not appear in the feed list, where they
// would read as a feed that only ever "synced" a single entry.
func IsSyntheticStatus(name string) bool {
	return name == AliasSeverityPropagationStatusName
}

// ErrSyncAlreadyRunning is returned by manual sync triggers when the same feed
// is already syncing. Background loops still serialize normally.
var ErrSyncAlreadyRunning = errors.New("feed sync already running")

// ErrManagerStarted is returned when a feed is registered after Start. Runtime
// reconfiguration must use ApplyConfig so running feed loops are updated.
var ErrManagerStarted = errors.New("feed manager already started")

// Manager orchestrates all registered feed syncers. It runs background
// goroutines that invoke each syncer on a configurable interval, records
// sync status in the database, and shuts down gracefully when the
// context is cancelled.
//
// Per DE-19 there is NO blocking sync on startup. The manager starts its
// loops immediately in the background and the caller returns right away.
type Manager struct {
	feeds      map[string]*registeredFeed
	feedLocks  map[string]*sync.Mutex
	store      db.Store
	logger     *slog.Logger
	interval   time.Duration // default interval; per-feed override possible
	mu         sync.Mutex
	ctx        context.Context
	started    bool
	phase1Done chan struct{}
	wg         sync.WaitGroup
	// feedStatusReadTimeout bounds pre-sync freshness reads so a slow store
	// cannot stall feed-loop startup behind the long-lived manager context.
	feedStatusReadTimeout time.Duration
	// syncOnStartup controls only loops launched by Start. Runtime ApplyConfig
	// starts keep their immediate first sync so admin changes take effect.
	syncOnStartup bool
	metrics       MetricsRecorder
}

// registeredFeed pairs a FeedConfig with optional per-feed overrides.
type registeredFeed struct {
	config     FeedConfig
	interval   time.Duration // 0 = use manager default
	cancel     context.CancelFunc
	done       chan struct{}
	startAfter <-chan struct{}
	mu         sync.Mutex  // fallback for tests that construct registeredFeed directly
	syncMu     *sync.Mutex // shared by feed name across runtime reconfiguration
}

type feedStartOptions struct {
	waitForPhase1 bool
	syncOnStartup bool
}

// ManagerOption configures a Manager.
type ManagerOption interface {
	applyManagerOption(*Manager)
}

type managerOptionFunc func(*Manager)

func (f managerOptionFunc) applyManagerOption(m *Manager) {
	f(m)
}

// NewManager creates a Manager. The default sync interval applies to
// every feed that does not specify its own interval. Pass 0 to use the
// hard-coded default of 8 hours.
func NewManager(store db.Store, logger *slog.Logger, defaultInterval time.Duration, opts ...ManagerOption) *Manager {
	if defaultInterval <= 0 {
		defaultInterval = 8 * time.Hour
	}
	if logger == nil {
		logger = slog.Default()
	}
	manager := &Manager{
		feeds:                 make(map[string]*registeredFeed),
		feedLocks:             make(map[string]*sync.Mutex),
		store:                 store,
		logger:                logger,
		interval:              defaultInterval,
		feedStatusReadTimeout: FeedStatusReadTimeout,
		syncOnStartup:         true,
		metrics:               NoopMetricsRecorder(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt.applyManagerOption(manager)
		}
	}
	return manager
}

// SetMetricsRecorder replaces the metrics recorder used by future manager
// sync attempts.
func (m *Manager) SetMetricsRecorder(recorder MetricsRecorder) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = MetricsRecorderOrNoop(recorder)
}

// SetSyncOnStartup controls whether Start performs an immediate sync before
// waiting for the first interval tick. It should be configured before Start.
func (m *Manager) SetSyncOnStartup(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncOnStartup = enabled
}

// SyncOnStartup reports the manager's startup-sync policy.
func (m *Manager) SyncOnStartup() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncOnStartup
}

// Register adds a feed to the manager. If the feed is disabled or in external
// mode, the manager will not schedule syncs for it but will still record its
// existence. Register must be called before Start; use ApplyConfig for runtime
// changes after the manager is running.
func (m *Manager) Register(cfg FeedConfig) error {
	if cfg.Syncer == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return ErrManagerStarted
	}
	name := cfg.Syncer.Name()
	m.feeds[cfg.Syncer.Name()] = &registeredFeed{
		config: cfg,
		syncMu: m.feedLockForNameLocked(name),
	}
	return nil
}

// RegisterWithInterval is like Register but sets a feed-specific sync
// interval that overrides the manager default.
func (m *Manager) RegisterWithInterval(cfg FeedConfig, interval time.Duration) error {
	if cfg.Syncer == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return ErrManagerStarted
	}
	name := cfg.Syncer.Name()
	m.feeds[cfg.Syncer.Name()] = &registeredFeed{
		config:   cfg,
		interval: interval,
		syncMu:   m.feedLockForNameLocked(name),
	}
	return nil
}

// Start launches background goroutines for every registered feed whose
// mode is "self" and whose enabled flag is true. It returns immediately
// (DE-19: no blocking sync on startup). The goroutines run until ctx is
// cancelled; after that, call Wait to block until all goroutines finish.
//
// Feeds run in phases: Phase 1 (base vulnerability/malicious-package data:
// OSV, GHSA, OpenSSF) starts immediately. Phase 2 post-base feeds wait for
// all Phase 1 feeds to complete their initial sync. Phase 2 includes
// vulnerability enrichers (NVD, EPSS, CISA KEV, VulnCheck) and lifecycle
// metadata feeds (endoflife.date).
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.ctx = ctx
	m.phase1Done = make(chan struct{})
	phase1Done := m.phase1Done
	syncOnStartup := m.syncOnStartup

	// Collect Phase 1 initial-done signals so Phase 2 can wait for them.
	var phase1Signals []<-chan bool
	type skippedStatus struct {
		name   string
		status string
	}
	var skippedStatuses []skippedStatus

	for name, rf := range m.feeds {
		if !managerFeedShouldRun(rf) {
			if !rf.config.Enabled {
				m.logger.Info("feed disabled, skipping", slog.String("feed", name))
				skippedStatuses = append(skippedStatuses, skippedStatus{name: name, status: db.FeedSyncStatusDisabled})
			} else if rf.config.Mode == FeedModeExternal {
				m.logger.Info("feed in external mode, skipping self-sync", slog.String("feed", name))
				skippedStatuses = append(skippedStatuses, skippedStatus{name: name, status: db.FeedSyncStatusExternal})
			}
			continue
		}

		interval := m.effectiveInterval(rf)
		phase := feedPhase(rf.config)

		if phase == FeedPhaseVulnerability {
			done := make(chan bool, 1)
			phase1Signals = append(phase1Signals, done)
			m.startFeedLocked(rf, interval, done, feedStartOptions{
				waitForPhase1: false,
				syncOnStartup: syncOnStartup,
			})
		}
	}
	m.mu.Unlock()

	for _, skipped := range skippedStatuses {
		_ = m.recordStatus(ctx, skipped.name, skipped.status, "", 0, nil)
	}

	// phase1Done is closed once ALL Phase 1 feeds finish their initial sync.
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer close(phase1Done)
		defer func() {
			if recovered := recover(); recovered != nil {
				err := fmt.Errorf("alias severity propagation panic: %v", recovered)
				m.logger.Error("alias severity propagation panic", "error", SafeDiagnosticError(err))
				if ctx.Err() == nil {
					_ = m.recordStatus(ctx, AliasSeverityPropagationStatusName, db.FeedSyncStatusError, SafeDiagnosticError(err), 0, nil)
				}
			}
		}()

		phaseOneAttemptedSync := false
		for _, ch := range phase1Signals {
			if <-ch {
				phaseOneAttemptedSync = true
			}
		}

		if !phaseOneAttemptedSync {
			m.logger.Debug("skipping alias severity propagation; no phase 1 startup sync attempted")
			return
		}

		// Propagate severity from known entries to UNKNOWN aliases.
		// E.g. GO-2026-4856 (UNKNOWN) shares alias CVE-2026-33726 with
		// GHSA-hxv8-4j4r-cqgv (MEDIUM) -- copy MEDIUM to GO-2026-4856.
		if updated, err := m.store.PropagateSeverityViaAliases(ctx); err != nil {
			m.logger.Warn("failed to propagate severity via aliases", "error", SafeDiagnosticError(err))
			if ctx.Err() == nil {
				_ = m.recordStatus(ctx, AliasSeverityPropagationStatusName, db.FeedSyncStatusError, SafeDiagnosticError(err), 0, nil)
			}
		} else if updated > 0 {
			_ = m.recordStatus(ctx, AliasSeverityPropagationStatusName, db.FeedSyncStatusSuccess, "", 0, &SyncResult{EntriesSynced: 1, EntriesTotal: 1})
			m.logger.Info("propagated severity via aliases", slog.Int("updated", updated))
		} else {
			_ = m.recordStatus(ctx, AliasSeverityPropagationStatusName, db.FeedSyncStatusSuccess, "", 0, &SyncResult{EntriesSynced: 1, EntriesTotal: 1})
		}
	}()

	// Start Phase 2 post-base feeds after Phase 1 completes.
	m.mu.Lock()
	for name, rf := range m.feeds {
		if !managerFeedShouldRun(rf) {
			continue
		}
		if feedPhase(rf.config) != FeedPhaseEnrichment {
			continue
		}

		m.startFeedLocked(rf, m.effectiveInterval(rf), nil, feedStartOptions{
			waitForPhase1: true,
			syncOnStartup: syncOnStartup,
		})
		m.logger.Debug("enrichment feed queued behind phase 1", slog.String("feed", name))
	}
	m.mu.Unlock()
}

// ApplyConfig replaces one registered feed's runtime configuration. If the
// manager has already started, the affected feed loop is stopped or started
// immediately so admin feed changes take effect without a process restart.
func (m *Manager) ApplyConfig(ctx context.Context, cfg FeedConfig, interval time.Duration) {
	if cfg.Syncer == nil {
		return
	}
	name := cfg.Syncer.Name()

	m.mu.Lock()
	rf := &registeredFeed{config: cfg, interval: interval, syncMu: m.feedLockForNameLocked(name)}
	var previousDone <-chan struct{}
	if old, ok := m.feeds[name]; ok {
		if old.cancel != nil {
			old.cancel()
			previousDone = old.done
		} else {
			previousDone = old.startAfter
		}
	}
	rf.startAfter = previousDone
	m.feeds[name] = rf
	if m.started && managerFeedShouldRun(rf) && m.ctx != nil && m.ctx.Err() == nil {
		interval := m.effectiveInterval(rf)
		opts := feedStartOptions{
			waitForPhase1: feedPhase(rf.config) == FeedPhaseEnrichment,
			syncOnStartup: true,
		}
		if previousDone != nil {
			m.startFeedAfterPreviousStopsLocked(name, previousDone, rf, interval, opts)
		} else {
			m.startFeedLocked(rf, interval, nil, opts)
		}
	}
	m.mu.Unlock()

	switch {
	case !cfg.Enabled:
		_ = m.recordStatus(ctx, name, db.FeedSyncStatusDisabled, "", 0, nil)
	case cfg.Mode == FeedModeExternal:
		_ = m.recordStatus(ctx, name, db.FeedSyncStatusExternal, "", 0, nil)
	}
}

func (m *Manager) feedLockForNameLocked(name string) *sync.Mutex {
	if m.feedLocks == nil {
		m.feedLocks = make(map[string]*sync.Mutex)
	}
	if lock := m.feedLocks[name]; lock != nil {
		return lock
	}
	lock := &sync.Mutex{}
	m.feedLocks[name] = lock
	return lock
}

func (m *Manager) startFeedLocked(rf *registeredFeed, interval time.Duration, initialDone chan<- bool, opts feedStartOptions) {
	if rf.cancel != nil || m.ctx == nil || m.ctx.Err() != nil {
		return
	}

	// #nosec G118 -- cancel is stored on the registered feed and called by ApplyConfig/Stop.
	feedCtx, cancel := context.WithCancel(m.ctx)
	rf.cancel = cancel
	rf.done = make(chan struct{})
	name := rf.config.Syncer.Name()

	if opts.waitForPhase1 {
		phaseDone := m.phase1Done
		m.wg.Add(1)
		go func() {
			m.recoverInterruptedRunningStatus(name)
			select {
			case <-phaseDone:
				m.logger.Info("phase 1 complete, starting enrichment feed", slog.String("feed", name))
			case <-feedCtx.Done():
				m.finishFeedLoop(rf)
				return
			}
			m.loop(feedCtx, rf, interval, nil, opts.syncOnStartup)
		}()
		return
	}

	m.wg.Add(1)
	go m.loop(feedCtx, rf, interval, initialDone, opts.syncOnStartup)
}

func (m *Manager) startFeedAfterPreviousStopsLocked(name string, previousDone <-chan struct{}, rf *registeredFeed, interval time.Duration, opts feedStartOptions) {
	managerCtx := m.ctx
	if managerCtx == nil || managerCtx.Err() != nil {
		return
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()

		select {
		case <-previousDone:
		case <-managerCtx.Done():
			return
		}

		m.mu.Lock()
		defer m.mu.Unlock()

		current, ok := m.feeds[name]
		if !ok || current != rf || !managerFeedShouldRun(rf) {
			return
		}
		rf.startAfter = nil
		m.startFeedLocked(rf, interval, nil, opts)
	}()
}

func (m *Manager) finishFeedLoop(rf *registeredFeed) {
	m.markFeedStopped(rf)
	if rf.done != nil {
		close(rf.done)
	}
	m.wg.Done()
}

func (m *Manager) markFeedStopped(rf *registeredFeed) {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := rf.config.Syncer.Name()
	if current, ok := m.feeds[name]; ok && current == rf {
		rf.cancel = nil
	}
}

func (m *Manager) effectiveInterval(rf *registeredFeed) time.Duration {
	if rf.interval > 0 {
		return rf.interval
	}
	return m.interval
}

func managerFeedShouldRun(rf *registeredFeed) bool {
	return rf != nil && rf.config.Enabled && rf.config.Mode != FeedModeExternal
}

func feedPhase(cfg FeedConfig) FeedPhase {
	if cfg.Phase == 0 {
		return FeedPhaseVulnerability
	}
	return cfg.Phase
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
	m.mu.Lock()
	rf, ok := m.feeds[feedName]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("feed %q is not registered", feedName)
	}
	_, err := m.syncWithRetry(ctx, rf, false)
	return err
}

// loop runs the sync-sleep cycle for a single feed until the context
// is cancelled. If initialDone is non-nil, it is closed after the
// initial sync attempt (success or skip) to signal Phase 2 feeds.
func (m *Manager) loop(ctx context.Context, rf *registeredFeed, interval time.Duration, initialDone chan<- bool, syncOnLoopStart bool) {
	defer func() {
		m.finishFeedLoop(rf)
	}()

	name := rf.config.Syncer.Name()
	log := m.logger.With(slog.String("feed", name))

	m.recoverInterruptedRunningStatus(name)

	log.Info("starting feed sync loop",
		slog.Duration("interval", interval),
	)

	// Check whether the last successful sync is still fresh. If it is,
	// skip the immediate sync and just wait for the next tick. This
	// prevents hammering upstream APIs on every container restart.
	attemptedInitialSync := false
	if !syncOnLoopStart {
		log.Info("startup feed sync disabled, waiting for next interval")
		m.recordPendingStatusIfMissing(ctx, name)
	} else if m.lastSyncFresh(ctx, name, interval) {
		log.Info("last sync still within interval, skipping initial sync")
	} else {
		attemptedInitialSync = true
		_ = m.runSync(ctx, rf, log)
	}

	// Signal that the initial sync is done (used by phase-based scheduling).
	if initialDone != nil {
		initialDone <- attemptedInitialSync
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("feed sync loop shutting down")
			return
		case <-ticker.C:
			_ = m.runSync(ctx, rf, log)
		}
	}
}

// runSync executes a sync with retries and records the result.
func (m *Manager) runSync(ctx context.Context, rf *registeredFeed, log *slog.Logger) error {
	// Bail out early if context is already done.
	if ctx.Err() != nil {
		return nil
	}

	result, err := m.syncWithRetry(ctx, rf, true)
	if err != nil {
		if IsPermanentError(err) {
			log.Warn("feed sync skipped (permanent error)",
				slog.String("error", SafeDiagnosticError(err)),
			)
			// Record the permanent failure so it surfaces in /admin/feeds
			// and /readyz instead of being hidden in logs only (C-3).
			if statusErr := m.recordStatusForFeed(ctx, rf, db.FeedSyncStatusPermanentError, SafeDiagnosticError(err), 0, nil); statusErr != nil {
				return errors.Join(err, statusErr)
			}
			return err
		}
		log.Error("feed sync failed after all retries",
			slog.String("error", SafeDiagnosticError(err)),
		)
		return err
	} else {
		log.Info("feed sync completed",
			slog.Int("entries_synced", result.EntriesSynced),
			slog.Int("entries_total", result.EntriesTotal),
		)
	}
	return nil
}

// syncWithRetry runs the syncer up to len(backoffSchedule)+1 times.
// On the first call there is no delay; subsequent retries use the
// exponential backoff schedule. It records the outcome in feed_sync_status.
func (m *Manager) syncWithRetry(ctx context.Context, rf *registeredFeed, waitForLock bool) (*SyncResult, error) {
	// Prevent concurrent syncs of the same feed (e.g. manual trigger
	// via admin panel while the background loop is already syncing).
	syncMu := rf.syncMu
	if syncMu == nil {
		syncMu = &rf.mu
	}
	name := rf.config.Syncer.Name()
	locked, lockErr := acquireSyncLock(ctx, syncMu, waitForLock)
	if lockErr != nil {
		return nil, lockErr
	}
	if !locked {
		return nil, fmt.Errorf("feed %s: %w", name, ErrSyncAlreadyRunning)
	}
	defer syncMu.Unlock()

	log := m.logger.With(slog.String("feed", name))

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := m.recordRunningStatusForFeed(ctx, rf); err != nil {
		return nil, fmt.Errorf("feed %s: record running status: %w", name, err)
	}
	started := time.Now()

	maxAttempts := len(backoffSchedule) + 1
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			err := ctx.Err()
			if statusErr := m.recordStatusForFeed(ctx, rf, db.FeedSyncStatusError, SafeDiagnosticError(err), time.Since(started), nil); statusErr != nil {
				return nil, errors.Join(err, statusErr)
			}
			return nil, err
		}

		// Wait before retry (skip for the first attempt).
		if attempt > 0 {
			delay := backoffSchedule[attempt-1]
			log.Warn("retrying feed sync",
				slog.Int("attempt", attempt+1),
				slog.Duration("delay", delay),
				slog.String("last_error", SafeDiagnosticError(lastErr)),
			)
			select {
			case <-ctx.Done():
				err := ctx.Err()
				if statusErr := m.recordStatusForFeed(ctx, rf, db.FeedSyncStatusError, SafeDiagnosticError(err), time.Since(started), nil); statusErr != nil {
					return nil, errors.Join(err, statusErr)
				}
				return nil, err
			case <-time.After(delay):
			}
		}

		start := time.Now()
		result, err := m.syncFeed(ctx, rf.config.Syncer)
		duration := time.Since(start)

		if err == nil {
			// Success -- record in DB and return.
			if statusErr := m.recordStatusForFeed(ctx, rf, db.FeedSyncStatusSuccess, "", duration, result); statusErr != nil {
				return nil, fmt.Errorf("feed %s: record success status: %w", name, statusErr)
			}
			return result, nil
		}

		if ctx.Err() != nil {
			err = ctx.Err()
			if statusErr := m.recordStatusForFeed(ctx, rf, db.FeedSyncStatusError, SafeDiagnosticError(err), time.Since(started), nil); statusErr != nil {
				return nil, errors.Join(err, statusErr)
			}
			return nil, err
		}

		lastErr = err
		if IsPermanentError(err) {
			if statusErr := m.recordStatusForFeed(ctx, rf, db.FeedSyncStatusSkipped, SafeDiagnosticError(err), duration, nil); statusErr != nil {
				return nil, errors.Join(err, statusErr)
			}
			return nil, err
		}
		if IsNonRetryableError(err) {
			if statusErr := m.recordStatusForFeed(ctx, rf, db.FeedSyncStatusError, SafeDiagnosticError(err), duration, nil); statusErr != nil {
				return nil, errors.Join(err, statusErr)
			}
			return nil, err
		}
		if isTimeoutError(err) {
			m.metrics.IncFeedSyncTimeout(name)
		}
		log.Warn("feed sync attempt failed",
			slog.Int("attempt", attempt+1),
			slog.Duration("duration", duration),
			slog.String("error", SafeDiagnosticError(err)),
		)
	}

	// All retries exhausted. Record failure.
	err := fmt.Errorf("feed %s: all %d attempts failed: %w", name, maxAttempts, lastErr)
	if statusErr := m.recordStatusForFeed(ctx, rf, db.FeedSyncStatusError, SafeDiagnosticError(lastErr), 0, nil); statusErr != nil {
		return nil, errors.Join(err, statusErr)
	}
	return nil, err
}

func (m *Manager) syncFeed(ctx context.Context, syncer FeedSyncer) (result *SyncResult, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("syncer panic: %v", recovered)
			result = nil
		}
	}()

	return syncer.Sync(ctx, m.store)
}

func acquireSyncLock(ctx context.Context, syncMu *sync.Mutex, waitForLock bool) (bool, error) {
	if !waitForLock {
		return syncMu.TryLock(), nil
	}
	if syncMu.TryLock() {
		return true, nil
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
			if syncMu.TryLock() {
				return true, nil
			}
		}
	}
}

// recordStatus persists the feed_sync_status row. This is the manager's
// own status tracking. Individual syncers may also write their own
// status records with additional details (commit hashes, etc.).
func (m *Manager) recordStatus(ctx context.Context, feedName, status, errMsg string, duration time.Duration, result *SyncResult) error {
	// Use a separate timeout so a slow/stuck DB doesn't block the sync loop.
	recordCtx, cancel := context.WithTimeout(context.Background(), FeedStatusWriteTimeout)
	defer cancel()
	_ = ctx // original context is only used for logging context, not for the DB call

	now := time.Now().UTC()
	fss := &db.FeedSyncStatus{
		FeedName:       feedName,
		LastSyncStatus: status,
		LastError:      errMsg,
		UpdatedAt:      now,
	}

	if result == nil && status != db.FeedSyncStatusSuccess {
		current, err := m.store.GetFeedSyncStatus(recordCtx, feedName)
		if err != nil {
			m.logger.Warn("failed to load current feed sync status for data preservation",
				slog.String("feed", feedName),
				slog.String("error", SafeDiagnosticError(err)),
			)
			return fmt.Errorf("load current feed sync status for %s: %w", feedName, err)
		} else {
			PreserveFeedStatusData(fss, current)
		}
	}

	if status == db.FeedSyncStatusSuccess {
		fss.LastSyncAt = &now
	}
	if duration > 0 {
		fss.LastSyncDuration = &duration
	}

	if result != nil {
		fss.EntriesSynced = result.EntriesSynced
		fss.EntriesTotal = result.EntriesTotal
		if len(result.Metadata) > 0 {
			fss.Metadata = append([]byte(nil), result.Metadata...)
		}
	}

	if err := m.store.UpsertFeedSyncStatus(recordCtx, fss); err != nil {
		m.logger.Error("failed to record feed sync status",
			slog.String("feed", feedName),
			slog.String("error", SafeDiagnosticError(err)),
		)
		return fmt.Errorf("record feed sync status for %s: %w", feedName, err)
	}
	return nil
}

func (m *Manager) recordStatusForFeed(ctx context.Context, rf *registeredFeed, status, errMsg string, duration time.Duration, result *SyncResult) error {
	if rf == nil || rf.config.Syncer == nil {
		return nil
	}
	feedName := rf.config.Syncer.Name()
	if !m.isCurrentRegisteredFeed(rf) {
		m.logger.Debug("skipping stale feed sync status",
			slog.String("feed", feedName),
			slog.String("status", status),
		)
		return nil
	}
	return m.recordStatus(ctx, feedName, status, errMsg, duration, result)
}

func (m *Manager) recordPendingStatusIfMissing(ctx context.Context, feedName string) {
	recordCtx, cancel := context.WithTimeout(context.Background(), FeedStatusWriteTimeout)
	defer cancel()
	_ = ctx

	current, err := m.store.GetFeedSyncStatus(recordCtx, feedName)
	if err != nil {
		m.logger.Warn("failed to load current feed sync status before pending marker",
			slog.String("feed", feedName),
			slog.String("error", SafeDiagnosticError(err)),
		)
		return
	}
	if current != nil {
		return
	}
	_ = m.recordStatus(ctx, feedName, db.FeedSyncStatusPending, "", 0, nil)
}

func (m *Manager) recoverInterruptedRunningStatus(feedName string) {
	recordCtx, cancel := context.WithTimeout(context.Background(), FeedStatusWriteTimeout)
	defer cancel()

	status, err := m.store.GetFeedSyncStatus(recordCtx, feedName)
	if err != nil {
		m.logger.Warn("failed to load feed sync status for interrupted sync recovery",
			slog.String("feed", feedName),
			slog.String("error", SafeDiagnosticError(err)),
		)
		return
	}
	if status == nil || status.LastSyncStatus != db.FeedSyncStatusRunning {
		return
	}

	status.LastSyncStatus = db.FeedSyncStatusError
	status.LastError = interruptedFeedSyncError
	startedAt := status.UpdatedAt
	if startedAt.IsZero() && status.LastSyncAt != nil {
		startedAt = *status.LastSyncAt
	}
	if !startedAt.IsZero() {
		duration := time.Since(startedAt)
		if duration < 0 {
			duration = 0
		}
		status.LastSyncDuration = &duration
	}

	if err := m.store.UpsertFeedSyncStatus(recordCtx, status); err != nil {
		m.logger.Warn("failed to recover interrupted feed sync status",
			slog.String("feed", feedName),
			slog.String("error", SafeDiagnosticError(err)),
		)
		return
	}

	m.logger.Warn("recovered interrupted feed sync status",
		slog.String("feed", feedName),
	)
}

func (m *Manager) recordRunningStatus(ctx context.Context, feedName string) error {
	recordCtx, cancel := context.WithTimeout(context.Background(), FeedStatusWriteTimeout)
	defer cancel()
	_ = ctx

	now := time.Now().UTC()
	status := &db.FeedSyncStatus{
		FeedName:       feedName,
		LastSyncStatus: db.FeedSyncStatusRunning,
		UpdatedAt:      now,
	}

	current, err := m.store.GetFeedSyncStatus(recordCtx, feedName)
	if err != nil {
		m.logger.Warn("failed to load current feed sync status",
			slog.String("feed", feedName),
			slog.String("error", SafeDiagnosticError(err)),
		)
		return fmt.Errorf("load current feed sync status for %s: %w", feedName, err)
	} else if current != nil {
		PreserveFeedStatusData(status, current)
	}

	if err := m.store.UpsertFeedSyncStatus(recordCtx, status); err != nil {
		m.logger.Error("failed to record feed sync running status",
			slog.String("feed", feedName),
			slog.String("error", SafeDiagnosticError(err)),
		)
		return fmt.Errorf("record feed sync running status for %s: %w", feedName, err)
	}
	return nil
}

func (m *Manager) recordRunningStatusForFeed(ctx context.Context, rf *registeredFeed) error {
	if rf == nil || rf.config.Syncer == nil {
		return nil
	}
	feedName := rf.config.Syncer.Name()
	if !m.isCurrentRegisteredFeed(rf) {
		m.logger.Debug("skipping stale feed running status",
			slog.String("feed", feedName),
		)
		return nil
	}
	return m.recordRunningStatus(ctx, feedName)
}

func (m *Manager) isCurrentRegisteredFeed(rf *registeredFeed) bool {
	if rf == nil || rf.config.Syncer == nil {
		return true
	}
	feedName := rf.config.Syncer.Name()

	m.mu.Lock()
	defer m.mu.Unlock()

	current, ok := m.feeds[feedName]
	return !ok || current == rf
}

// lastSyncFresh returns true if the named feed was successfully synced
// within the given interval. On any error (e.g. first run, DB
// unreachable) it returns false so the sync proceeds.
func (m *Manager) lastSyncFresh(ctx context.Context, feedName string, interval time.Duration) bool {
	timeout := m.feedStatusReadTimeout
	if timeout <= 0 {
		timeout = FeedStatusReadTimeout
	}
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	status, err := m.store.GetFeedSyncStatus(readCtx, feedName)
	if err != nil || status == nil || status.LastSyncAt == nil {
		if err != nil {
			m.logger.Warn("failed to read feed sync freshness status",
				slog.String("feed", feedName),
				slog.String("operation", "last_sync_fresh"),
				slog.String("error", SafeDiagnosticError(err)),
			)
		}
		return false
	}
	if status.LastSyncStatus != db.FeedSyncStatusSuccess {
		return false
	}
	if status.EntriesTotal <= 0 {
		return false
	}
	lastSyncAt := status.LastSyncAt.UTC()
	now := time.Now().UTC()
	if lastSyncAt.After(now) {
		return false
	}
	return now.Sub(lastSyncAt) < interval
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded")
}
