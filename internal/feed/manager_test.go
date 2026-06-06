package feed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

type managerStoreStub struct {
	db.Store
	mu              sync.Mutex
	statuses        []db.FeedSyncStatus
	status          *db.FeedSyncStatus
	getErr          error
	upsertErr       error
	propagated      int
	propagateErr    error
	propagateCalled atomic.Bool
}

func (s *managerStoreStub) PropagateSeverityViaAliases(context.Context) (int, error) {
	s.propagateCalled.Store(true)
	return s.propagated, s.propagateErr
}

func (s *managerStoreStub) GetFeedSyncStatus(_ context.Context, _ string) (*db.FeedSyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.status == nil {
		return nil, nil
	}
	copyValue := *s.status
	return &copyValue, nil
}

func (s *managerStoreStub) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.upsertErr != nil {
		return s.upsertErr
	}
	copyValue := *status
	s.statuses = append(s.statuses, copyValue)
	s.status = &copyValue
	return nil
}

type permanentSyncerStub struct {
	name  string
	calls int
}

func (s *permanentSyncerStub) Name() string { return s.name }

func (s *permanentSyncerStub) Sync(context.Context, db.Store) (*SyncResult, error) {
	s.calls++
	return nil, PermanentError(errors.New("missing api key"))
}

type notifySyncerStub struct {
	name   string
	called chan struct{}
}

type blockingSyncerStub struct {
	name    string
	entered chan struct{}
	release chan struct{}
}

func (s *blockingSyncerStub) Name() string { return s.name }

func (s *blockingSyncerStub) Sync(context.Context, db.Store) (*SyncResult, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	return &SyncResult{EntriesSynced: 1, EntriesTotal: 1}, nil
}

func (s *notifySyncerStub) Name() string { return s.name }

func (s *notifySyncerStub) Sync(context.Context, db.Store) (*SyncResult, error) {
	select {
	case s.called <- struct{}{}:
	default:
	}
	return &SyncResult{EntriesSynced: 1, EntriesTotal: 1}, nil
}

func TestManagerSyncOneRecordsSkippedWithoutRetry(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(store, logger, time.Hour)
	syncer := &permanentSyncerStub{name: "vulncheck"}
	manager.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	err := manager.SyncOne(context.Background(), "vulncheck")
	if err == nil {
		t.Fatal("SyncOne() error = nil, want permanent error")
	}
	if syncer.calls != 1 {
		t.Fatalf("syncer calls = %d, want 1", syncer.calls)
	}
	if store.status == nil {
		t.Fatal("UpsertFeedSyncStatus() was not called")
	}
	if store.status.LastSyncStatus != "skipped" {
		t.Fatalf("LastSyncStatus = %q, want skipped", store.status.LastSyncStatus)
	}
	if store.status.LastError != "missing api key" {
		t.Fatalf("LastError = %q, want %q", store.status.LastError, "missing api key")
	}
}

func TestManagerApplyConfigStartsPreviouslyDisabledFeed(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(store, logger, time.Hour)
	disabledSyncer := &notifySyncerStub{name: "vulncheck", called: make(chan struct{}, 1)}
	manager.Register(FeedConfig{
		Syncer:  disabledSyncer,
		Mode:    FeedModeSelf,
		Enabled: false,
	})
	manager.Start(ctx)

	enabledSyncer := &notifySyncerStub{name: "vulncheck", called: make(chan struct{}, 1)}
	manager.ApplyConfig(context.Background(), FeedConfig{
		Syncer:  enabledSyncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	}, time.Hour)

	select {
	case <-enabledSyncer.called:
	case <-time.After(time.Second):
		t.Fatal("enabled feed did not start after ApplyConfig")
	}
}

func TestManagerApplyConfigSerializesOldAndNewSyncForSameFeed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(store, logger, time.Hour)
	oldSyncer := &blockingSyncerStub{name: "osv", entered: make(chan struct{}, 1), release: make(chan struct{})}
	manager.Register(FeedConfig{
		Syncer:  oldSyncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})
	manager.Start(ctx)

	select {
	case <-oldSyncer.entered:
	case <-time.After(time.Second):
		t.Fatal("old feed sync did not start")
	}

	newSyncer := &blockingSyncerStub{name: "osv", entered: make(chan struct{}, 1), release: make(chan struct{})}
	manager.ApplyConfig(context.Background(), FeedConfig{
		Syncer:  newSyncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	}, time.Hour)

	select {
	case <-newSyncer.entered:
		t.Fatal("new feed sync overlapped old sync for the same feed")
	case <-time.After(100 * time.Millisecond):
	}

	close(oldSyncer.release)

	select {
	case <-newSyncer.entered:
	case <-time.After(time.Second):
		t.Fatal("new feed sync did not start after old sync released")
	}

	close(newSyncer.release)
	cancel()
	manager.Wait()
}

func TestManagerApplyConfigRecordsDisabledAndExternalStatus(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	syncer := &successSyncerStub{name: "osv"}

	manager.ApplyConfig(context.Background(), FeedConfig{Syncer: syncer, Enabled: false, Mode: FeedModeSelf}, 0)
	manager.ApplyConfig(context.Background(), FeedConfig{Syncer: syncer, Enabled: true, Mode: FeedModeExternal}, 0)
	manager.ApplyConfig(context.Background(), FeedConfig{}, 0)

	if len(store.statuses) != 2 {
		t.Fatalf("statuses = %d, want disabled and external", len(store.statuses))
	}
	if store.statuses[0].LastSyncStatus != "disabled" {
		t.Fatalf("first status = %q, want disabled", store.statuses[0].LastSyncStatus)
	}
	if store.statuses[1].LastSyncStatus != "external" {
		t.Fatalf("second status = %q, want external", store.statuses[1].LastSyncStatus)
	}
}

func TestManagerHelpersAndLastSyncFresh(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	syncer := &successSyncerStub{name: "osv"}
	rf := &registeredFeed{config: FeedConfig{Syncer: syncer, Enabled: true, Mode: FeedModeSelf}}

	if !managerFeedShouldRun(rf) {
		t.Fatal("enabled self feed should run")
	}
	if managerFeedShouldRun(nil) {
		t.Fatal("nil registered feed should not run")
	}
	rf.config.Enabled = false
	if managerFeedShouldRun(rf) {
		t.Fatal("disabled feed should not run")
	}
	rf.config.Enabled = true
	rf.config.Mode = FeedModeExternal
	if managerFeedShouldRun(rf) {
		t.Fatal("external feed should not run")
	}
	rf.config.Mode = FeedModeSelf
	if got := feedPhase(rf.config); got != FeedPhaseVulnerability {
		t.Fatalf("default feed phase = %d, want vulnerability", got)
	}
	rf.config.Phase = FeedPhaseEnrichment
	if got := feedPhase(rf.config); got != FeedPhaseEnrichment {
		t.Fatalf("explicit feed phase = %d, want enrichment", got)
	}
	if got := manager.effectiveInterval(rf); got != time.Hour {
		t.Fatalf("effective default interval = %v, want 1h", got)
	}
	rf.interval = time.Minute
	if got := manager.effectiveInterval(rf); got != time.Minute {
		t.Fatalf("effective feed interval = %v, want 1m", got)
	}

	now := time.Now().UTC()
	store.status = &db.FeedSyncStatus{LastSyncStatus: "success", LastSyncAt: &now}
	if !manager.lastSyncFresh(context.Background(), "osv", time.Hour) {
		t.Fatal("fresh success should be fresh")
	}
	old := now.Add(-2 * time.Hour)
	store.status.LastSyncAt = &old
	if manager.lastSyncFresh(context.Background(), "osv", time.Hour) {
		t.Fatal("old sync should not be fresh")
	}
	store.status.LastSyncStatus = "error"
	store.status.LastSyncAt = &now
	if manager.lastSyncFresh(context.Background(), "osv", time.Hour) {
		t.Fatal("error sync should not be fresh")
	}
	store.status = nil
	if manager.lastSyncFresh(context.Background(), "osv", time.Hour) {
		t.Fatal("missing status should not be fresh")
	}
	store.getErr = errors.New("db down")
	if manager.lastSyncFresh(context.Background(), "osv", time.Hour) {
		t.Fatal("status error should not be fresh")
	}
}

func TestManagerStartIsIdempotentAndPropagatesAfterPhaseOne(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{propagated: 2}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	syncer := &successSyncerStub{name: "osv", result: SyncResult{EntriesSynced: 1, EntriesTotal: 1}}
	manager.Register(FeedConfig{Syncer: syncer, Enabled: true, Mode: FeedModeSelf})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Start(ctx)
	manager.Start(ctx)

	deadline := time.After(time.Second)
	for !store.propagateCalled.Load() {
		select {
		case <-deadline:
			t.Fatal("PropagateSeverityViaAliases was not called after phase one")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	manager.Wait()
	if syncer.calls != 1 {
		t.Fatalf("syncer calls = %d, want one initial call despite double Start", syncer.calls)
	}
}

func TestManagerStartMarksInterruptedRunningStatusBeforeRestartingFeed(t *testing.T) {
	t.Parallel()

	started := time.Now().UTC().Add(-3 * time.Hour)
	store := &managerStoreStub{
		status: &db.FeedSyncStatus{
			FeedName:       "nvd",
			LastSyncStatus: "running",
			LastSyncAt:     &started,
			EntriesSynced:  70,
			EntriesTotal:   96,
			LastEtag:       "etag-old",
			LastCommitHash: "commit-old",
			Metadata:       []byte(`{"cursor":"old"}`),
		},
	}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	syncer := &blockingSyncerStub{name: "nvd", entered: make(chan struct{}, 1), release: make(chan struct{})}
	manager.Register(FeedConfig{Syncer: syncer, Enabled: true, Mode: FeedModeSelf})

	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)

	select {
	case <-syncer.entered:
	case <-time.After(time.Second):
		t.Fatal("feed sync did not start")
	}
	close(syncer.release)
	cancel()
	manager.Wait()

	if len(store.statuses) == 0 {
		t.Fatal("no feed status was recorded")
	}
	recovered := store.statuses[0]
	if recovered.LastSyncStatus != "error" {
		t.Fatalf("first recorded status = %q, want error for interrupted running sync", recovered.LastSyncStatus)
	}
	if recovered.LastError != "previous feed sync was interrupted before completion" {
		t.Fatalf("LastError = %q, want interrupted sync message", recovered.LastError)
	}
	if recovered.LastSyncAt == nil || !recovered.LastSyncAt.Equal(started) {
		t.Fatalf("LastSyncAt = %v, want original start time %v", recovered.LastSyncAt, started)
	}
	if recovered.LastSyncDuration == nil || *recovered.LastSyncDuration < 3*time.Hour {
		t.Fatalf("LastSyncDuration = %v, want elapsed interrupted duration", recovered.LastSyncDuration)
	}
	if recovered.EntriesSynced != 70 || recovered.EntriesTotal != 96 {
		t.Fatalf("entries = %d/%d, want preserved 70/96", recovered.EntriesSynced, recovered.EntriesTotal)
	}
	if recovered.LastEtag != "etag-old" || recovered.LastCommitHash != "commit-old" || string(recovered.Metadata) != `{"cursor":"old"}` {
		t.Fatalf("sync metadata was not preserved: %+v", recovered)
	}
}

func TestManagerRunSyncBranches(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cancelledStore := &managerStoreStub{}
	cancelledManager := NewManager(cancelledStore, logger, time.Hour)
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelledManager.runSync(cancelledCtx, &registeredFeed{
		config: FeedConfig{Syncer: &successSyncerStub{name: "cancelled"}, Enabled: true, Mode: FeedModeSelf},
	}, logger)
	if len(cancelledStore.statuses) != 0 {
		t.Fatalf("cancelled runSync recorded %d statuses, want 0", len(cancelledStore.statuses))
	}

	permanentStore := &managerStoreStub{}
	permanentManager := NewManager(permanentStore, logger, time.Hour)
	permanentManager.runSync(context.Background(), &registeredFeed{
		config: FeedConfig{Syncer: &permanentSyncerStub{name: "vulncheck"}, Enabled: true, Mode: FeedModeSelf},
	}, logger)
	if permanentStore.status == nil || permanentStore.status.LastSyncStatus != "permanent_error" {
		t.Fatalf("permanent runSync status = %+v, want permanent_error", permanentStore.status)
	}

	upsertFailStore := &managerStoreStub{upsertErr: errors.New("db down")}
	upsertFailManager := NewManager(upsertFailStore, logger, time.Hour)
	upsertFailManager.recordStatus(context.Background(), "osv", "success", "", time.Millisecond, &SyncResult{EntriesSynced: 1, EntriesTotal: 1})
	upsertFailManager.recordRunningStatus(context.Background(), "osv")
}

func TestRecordRunningStatusPreservesExistingMetadata(t *testing.T) {
	t.Parallel()

	metadata := []byte(`{"etag":"old"}`)
	store := &managerStoreStub{
		status: &db.FeedSyncStatus{
			FeedName:       "osv",
			LastSyncStatus: "success",
			EntriesSynced:  7,
			EntriesTotal:   9,
			LastEtag:       "etag-old",
			LastCommitHash: "commit-old",
			Metadata:       metadata,
		},
	}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)

	manager.recordRunningStatus(context.Background(), "osv")
	metadata[0] = '['

	if store.status == nil || store.status.LastSyncStatus != "running" {
		t.Fatalf("recorded status = %+v, want running", store.status)
	}
	if store.status.EntriesSynced != 7 || store.status.EntriesTotal != 9 {
		t.Fatalf("recorded entries = %d/%d, want 7/9", store.status.EntriesSynced, store.status.EntriesTotal)
	}
	if store.status.LastEtag != "etag-old" || store.status.LastCommitHash != "commit-old" {
		t.Fatalf("recorded status lost sync metadata: %+v", store.status)
	}
	if string(store.status.Metadata) != `{"etag":"old"}` {
		t.Fatalf("metadata = %s, want copied old metadata", string(store.status.Metadata))
	}
}

func TestManagerStartFeedLockedWaitForPhaseCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	manager := NewManager(&managerStoreStub{}, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	manager.ctx = ctx
	manager.phase1Done = make(chan struct{})
	rf := &registeredFeed{
		config: FeedConfig{Syncer: &successSyncerStub{name: "epss"}, Enabled: true, Mode: FeedModeSelf, Phase: FeedPhaseEnrichment},
	}
	manager.feeds["epss"] = rf

	manager.startFeedLocked(rf, time.Hour, nil, true)
	cancel()
	manager.Wait()

	if rf.cancel != nil {
		t.Fatal("rf.cancel was not cleared after phase-wait cancellation")
	}
}

// ---------------------------------------------------------------------------
// PermanentError wrapping / unwrapping
// ---------------------------------------------------------------------------

func TestPermanentErrorNilReturnsNil(t *testing.T) {
	t.Parallel()
	if got := PermanentError(nil); got != nil {
		t.Fatalf("PermanentError(nil) = %v, want nil", got)
	}
}

func TestPermanentErrorWrapsAndPreservesMessage(t *testing.T) {
	t.Parallel()
	inner := errors.New("bad config")
	wrapped := PermanentError(inner)
	if wrapped.Error() != "bad config" {
		t.Fatalf("PermanentError message = %q, want %q", wrapped.Error(), "bad config")
	}
}

func TestPermanentErrorUnwrapsToOriginal(t *testing.T) {
	t.Parallel()
	inner := errors.New("original cause")
	wrapped := PermanentError(inner)
	if !errors.Is(wrapped, inner) {
		t.Fatal("errors.Is(wrapped, inner) = false, want true")
	}
}

func TestPermanentErrorPreservesWrappedChain(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("sentinel")
	wrapped := fmt.Errorf("layer: %w", sentinel)
	perm := PermanentError(wrapped)

	if !errors.Is(perm, sentinel) {
		t.Fatal("errors.Is(PermanentError(wrapping(sentinel)), sentinel) = false, want true")
	}
}

// ---------------------------------------------------------------------------
// IsPermanentError detection
// ---------------------------------------------------------------------------

func TestIsPermanentError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil is not permanent",
			err:  nil,
			want: false,
		},
		{
			name: "plain error is not permanent",
			err:  errors.New("transient failure"),
			want: false,
		},
		{
			name: "PermanentError is permanent",
			err:  PermanentError(errors.New("missing key")),
			want: true,
		},
		{
			name: "wrapped PermanentError is permanent",
			err:  fmt.Errorf("sync failed: %w", PermanentError(errors.New("no key"))),
			want: true,
		},
		{
			name: "context.Canceled is not permanent",
			err:  context.Canceled,
			want: false,
		},
		{
			name: "context.DeadlineExceeded is not permanent",
			err:  context.DeadlineExceeded,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsPermanentError(tt.err); got != tt.want {
				t.Fatalf("IsPermanentError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isTimeoutError detection
// ---------------------------------------------------------------------------

func TestIsTimeoutError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil is not timeout",
			err:  nil,
			want: false,
		},
		{
			name: "plain error is not timeout",
			err:  errors.New("connection refused"),
			want: false,
		},
		{
			name: "error containing timeout",
			err:  errors.New("dial tcp: i/o timeout"),
			want: true,
		},
		{
			name: "error containing Timeout (mixed case)",
			err:  errors.New("HTTP Timeout reached"),
			want: true,
		},
		{
			name: "error containing deadline exceeded",
			err:  errors.New("context deadline exceeded"),
			want: true,
		},
		{
			name: "error containing Deadline Exceeded (mixed case)",
			err:  errors.New("Deadline Exceeded while connecting"),
			want: true,
		},
		{
			name: "context.DeadlineExceeded sentinel",
			err:  context.DeadlineExceeded,
			want: true,
		},
		{
			name: "wrapped timeout error",
			err:  fmt.Errorf("feed osv: %w", errors.New("read timeout")),
			want: true,
		},
		{
			name: "error with timeout substring in longer message",
			err:  errors.New("TLS handshake timeout after 30s"),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isTimeoutError(tt.err); got != tt.want {
				t.Fatalf("isTimeoutError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Manager construction and registration
// ---------------------------------------------------------------------------

func TestNewManagerDefaults(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	m := NewManager(store, nil, 0)

	if m.interval != 8*time.Hour {
		t.Fatalf("default interval = %v, want 8h", m.interval)
	}
	if m.logger == nil {
		t.Fatal("logger is nil, want non-nil default")
	}
	if m.feeds == nil {
		t.Fatal("feeds map is nil")
	}
}

func TestNewManagerCustomInterval(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	m := NewManager(store, nil, 30*time.Minute)

	if m.interval != 30*time.Minute {
		t.Fatalf("interval = %v, want 30m", m.interval)
	}
}

func TestRegisterNilSyncerIsIgnored(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	m := NewManager(store, nil, time.Hour)
	m.Register(FeedConfig{Syncer: nil, Enabled: true})

	if len(m.feeds) != 0 {
		t.Fatalf("feeds count = %d, want 0 (nil syncer should be ignored)", len(m.feeds))
	}
}

func TestRegisterWithIntervalOverridesDefault(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	m := NewManager(store, nil, time.Hour)
	m.RegisterWithInterval(FeedConfig{}, time.Minute)
	if len(m.feeds) != 0 {
		t.Fatalf("feeds count = %d, want 0 after nil RegisterWithInterval", len(m.feeds))
	}

	syncer := &permanentSyncerStub{name: "fast-feed"}
	m.RegisterWithInterval(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	}, 5*time.Minute)

	rf, ok := m.feeds["fast-feed"]
	if !ok {
		t.Fatal("feed not registered")
	}
	if rf.interval != 5*time.Minute {
		t.Fatalf("feed interval = %v, want 5m", rf.interval)
	}
}

func TestSyncOneUnknownFeedReturnsError(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	m := NewManager(store, nil, time.Hour)

	err := m.SyncOne(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("SyncOne(nonexistent) = nil, want error")
	}
}

// ---------------------------------------------------------------------------
// syncWithRetry: success on first attempt
// ---------------------------------------------------------------------------

type successSyncerStub struct {
	name   string
	calls  int
	result SyncResult
}

func (s *successSyncerStub) Name() string { return s.name }

func (s *successSyncerStub) Sync(_ context.Context, _ db.Store) (*SyncResult, error) {
	s.calls++
	return &s.result, nil
}

type observingSyncerStub struct {
	name     string
	observed *db.FeedSyncStatus
	store    *managerStoreStub
}

func (s *observingSyncerStub) Name() string { return s.name }

func (s *observingSyncerStub) Sync(context.Context, db.Store) (*SyncResult, error) {
	if s.store.status != nil {
		copyValue := *s.store.status
		s.observed = &copyValue
	}
	return &SyncResult{EntriesSynced: 7, EntriesTotal: 9}, nil
}

func TestSyncOneRecordsRunningBeforeSyncerStarts(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(store, logger, time.Hour)
	syncer := &observingSyncerStub{name: "osv", store: store}
	m.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	err := m.SyncOne(context.Background(), "osv")
	if err != nil {
		t.Fatalf("SyncOne() unexpected error: %v", err)
	}
	if syncer.observed == nil {
		t.Fatal("syncer started before any feed status was recorded")
	}
	if syncer.observed.LastSyncStatus != "running" {
		t.Fatalf("status observed by syncer = %q, want running", syncer.observed.LastSyncStatus)
	}
	if len(store.statuses) < 2 {
		t.Fatalf("recorded statuses = %d, want running and final success", len(store.statuses))
	}
	if store.statuses[0].LastSyncStatus != "running" {
		t.Fatalf("first recorded status = %q, want running", store.statuses[0].LastSyncStatus)
	}
	if store.statuses[len(store.statuses)-1].LastSyncStatus != "success" {
		t.Fatalf("final recorded status = %q, want success", store.statuses[len(store.statuses)-1].LastSyncStatus)
	}
}

func TestSyncOneSuccessRecordsStatus(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(store, logger, time.Hour)

	syncer := &successSyncerStub{
		name:   "osv",
		result: SyncResult{EntriesSynced: 42, EntriesTotal: 100},
	}
	m.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	err := m.SyncOne(context.Background(), "osv")
	if err != nil {
		t.Fatalf("SyncOne() unexpected error: %v", err)
	}
	if syncer.calls != 1 {
		t.Fatalf("syncer calls = %d, want 1", syncer.calls)
	}
	if store.status == nil {
		t.Fatal("UpsertFeedSyncStatus was not called")
	}
	if store.status.LastSyncStatus != "success" {
		t.Fatalf("LastSyncStatus = %q, want success", store.status.LastSyncStatus)
	}
	if store.status.EntriesSynced != 42 {
		t.Fatalf("EntriesSynced = %d, want 42", store.status.EntriesSynced)
	}
	if store.status.EntriesTotal != 100 {
		t.Fatalf("EntriesTotal = %d, want 100", store.status.EntriesTotal)
	}
}

// ---------------------------------------------------------------------------
// syncWithRetry: transient failures exhaust retries
// ---------------------------------------------------------------------------

type failingSyncerStub struct {
	name  string
	calls int
	err   error
}

func (s *failingSyncerStub) Name() string { return s.name }

func (s *failingSyncerStub) Sync(_ context.Context, _ db.Store) (*SyncResult, error) {
	s.calls++
	return nil, s.err
}

func TestSyncOneTransientErrorRetriesAndFails(t *testing.T) {
	// Not parallel: mutates package-level backoffSchedule.
	saved := backoffSchedule
	backoffSchedule = [3]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { backoffSchedule = saved }()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(store, logger, time.Hour)

	syncer := &failingSyncerStub{name: "ghsa", err: errors.New("network error")}
	m.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	err := m.SyncOne(context.Background(), "ghsa")
	if err == nil {
		t.Fatal("SyncOne() = nil, want error after retries exhausted")
	}

	// 1 initial attempt + 3 retries = 4 total
	wantCalls := len(backoffSchedule) + 1
	if syncer.calls != wantCalls {
		t.Fatalf("syncer calls = %d, want %d", syncer.calls, wantCalls)
	}
	if store.status == nil {
		t.Fatal("UpsertFeedSyncStatus was not called")
	}
	if store.status.LastSyncStatus != "error" {
		t.Fatalf("LastSyncStatus = %q, want error", store.status.LastSyncStatus)
	}
}

// ---------------------------------------------------------------------------
// syncWithRetry: succeeds on retry
// ---------------------------------------------------------------------------

type eventualSuccessSyncerStub struct {
	name      string
	calls     int
	failUntil int
	transErr  error
	result    SyncResult
}

func (s *eventualSuccessSyncerStub) Name() string { return s.name }

func (s *eventualSuccessSyncerStub) Sync(_ context.Context, _ db.Store) (*SyncResult, error) {
	s.calls++
	if s.calls <= s.failUntil {
		return nil, s.transErr
	}
	return &s.result, nil
}

func TestSyncOneSucceedsOnRetry(t *testing.T) {
	// Not parallel: mutates package-level backoffSchedule.
	saved := backoffSchedule
	backoffSchedule = [3]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { backoffSchedule = saved }()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(store, logger, time.Hour)

	syncer := &eventualSuccessSyncerStub{
		name:      "epss",
		failUntil: 2,
		transErr:  errors.New("transient"),
		result:    SyncResult{EntriesSynced: 10, EntriesTotal: 10},
	}
	m.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	err := m.SyncOne(context.Background(), "epss")
	if err != nil {
		t.Fatalf("SyncOne() unexpected error: %v", err)
	}
	// Should have failed twice, then succeeded on 3rd attempt.
	if syncer.calls != 3 {
		t.Fatalf("syncer calls = %d, want 3", syncer.calls)
	}
	if store.status.LastSyncStatus != "success" {
		t.Fatalf("LastSyncStatus = %q, want success", store.status.LastSyncStatus)
	}
}

// ---------------------------------------------------------------------------
// syncWithRetry: context cancellation aborts retries
// ---------------------------------------------------------------------------

func TestSyncOneCancelledContextAbortsRetries(t *testing.T) {
	// Not parallel: mutates package-level backoffSchedule.
	saved := backoffSchedule
	backoffSchedule = [3]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { backoffSchedule = saved }()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(store, logger, time.Hour)

	syncer := &failingSyncerStub{name: "osv", err: errors.New("fail")}
	m.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := m.SyncOne(ctx, "osv")
	if err == nil {
		t.Fatal("SyncOne() = nil, want context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	// Syncer should not be called since context is already cancelled.
	if syncer.calls != 0 {
		t.Fatalf("syncer calls = %d, want 0 (cancelled before first attempt)", syncer.calls)
	}
}

// ---------------------------------------------------------------------------
// Start: disabled and external feeds are not started
// ---------------------------------------------------------------------------

func TestStartSkipsDisabledAndExternalFeeds(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(store, logger, time.Hour)

	disabledSyncer := &successSyncerStub{name: "disabled-feed"}
	externalSyncer := &successSyncerStub{name: "external-feed"}

	m.Register(FeedConfig{Syncer: disabledSyncer, Mode: FeedModeSelf, Enabled: false})
	m.Register(FeedConfig{Syncer: externalSyncer, Mode: FeedModeExternal, Enabled: true})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so loop exits right away

	m.Start(ctx)
	m.Wait()

	// Neither syncer should have been called since both are skipped.
	if disabledSyncer.calls != 0 {
		t.Fatalf("disabled syncer calls = %d, want 0", disabledSyncer.calls)
	}
	if externalSyncer.calls != 0 {
		t.Fatalf("external syncer calls = %d, want 0", externalSyncer.calls)
	}
}
