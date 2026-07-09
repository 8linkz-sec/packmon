package feed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type managerStoreStub struct {
	db.Store
	mu               sync.Mutex
	statuses         []db.FeedSyncStatus
	status           *db.FeedSyncStatus
	getErr           error
	getWaitForCtx    bool
	getEntered       chan struct{}
	getCtxErr        error
	upsertErr        error
	upsertErrOnCall  int
	upsertCalls      int
	propagated       int
	propagateErr     error
	propagatePanic   any
	propagateCalled  atomic.Bool
	propagateEntered chan struct{}
	propagateRelease chan struct{}
}

type managerLogEvent struct {
	message string
	feed    string
}

type managerLogSink struct {
	mu     sync.Mutex
	events []managerLogEvent
	ch     chan managerLogEvent
}

type managerLogHandler struct {
	sink  *managerLogSink
	attrs []slog.Attr
}

func newManagerLogHandler() (*managerLogHandler, *managerLogSink) {
	sink := &managerLogSink{ch: make(chan managerLogEvent, 32)}
	return &managerLogHandler{sink: sink}, sink
}

func (h *managerLogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *managerLogHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := append([]slog.Attr(nil), h.attrs...)
	record.Attrs(func(attr slog.Attr) bool {
		attrs = append(attrs, attr)
		return true
	})
	event := managerLogEvent{message: record.Message}
	for _, attr := range attrs {
		if attr.Key == "feed" {
			event.feed = attr.Value.String()
		}
	}

	h.sink.mu.Lock()
	h.sink.events = append(h.sink.events, event)
	h.sink.mu.Unlock()

	select {
	case h.sink.ch <- event:
	default:
	}
	return nil
}

func (h *managerLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &managerLogHandler{
		sink:  h.sink,
		attrs: append([]slog.Attr(nil), h.attrs...),
	}
	next.attrs = append(next.attrs, attrs...)
	return next
}

func (h *managerLogHandler) WithGroup(string) slog.Handler {
	return h
}

func (s *managerLogSink) count(message, feed string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, event := range s.events {
		if event.message == message && event.feed == feed {
			count++
		}
	}
	return count
}

func (s *managerLogSink) indexOf(message, feed string, occurrence int) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	seen := 0
	for i, event := range s.events {
		if event.message != message || event.feed != feed {
			continue
		}
		seen++
		if seen == occurrence {
			return i
		}
	}
	return -1
}

func (s *managerStoreStub) PropagateSeverityViaAliases(context.Context) (int, error) {
	s.propagateCalled.Store(true)
	if s.propagatePanic != nil {
		panic(s.propagatePanic)
	}
	if s.propagateEntered != nil {
		select {
		case s.propagateEntered <- struct{}{}:
		default:
		}
	}
	if s.propagateRelease != nil {
		<-s.propagateRelease
	}
	return s.propagated, s.propagateErr
}

func (s *managerStoreStub) GetFeedSyncStatus(ctx context.Context, feedName string) (*db.FeedSyncStatus, error) {
	if s.getWaitForCtx {
		if s.getEntered != nil {
			select {
			case s.getEntered <- struct{}{}:
			default:
			}
		}
		<-ctx.Done()
		err := ctx.Err()
		s.mu.Lock()
		s.getCtxErr = err
		s.mu.Unlock()
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.getErr != nil {
		return nil, s.getErr
	}
	for i := len(s.statuses) - 1; i >= 0; i-- {
		if s.statuses[i].FeedName == feedName {
			copyValue := s.statuses[i]
			return &copyValue, nil
		}
	}
	if s.status == nil {
		return nil, nil
	}
	if s.status.FeedName != "" && s.status.FeedName != feedName {
		return nil, nil
	}
	copyValue := *s.status
	return &copyValue, nil
}

func (s *managerStoreStub) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.upsertCalls++
	if s.upsertErr != nil && (s.upsertErrOnCall == 0 || s.upsertCalls == s.upsertErrOnCall) {
		return s.upsertErr
	}
	copyValue := *status
	s.statuses = append(s.statuses, copyValue)
	s.status = &copyValue
	return nil
}

func managerStatusByName(store *managerStoreStub, name string) (db.FeedSyncStatus, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()

	for i := len(store.statuses) - 1; i >= 0; i-- {
		if store.statuses[i].FeedName == name {
			return store.statuses[i], true
		}
	}
	return db.FeedSyncStatus{}, false
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

type contextBlockingSyncerStub struct {
	name    string
	entered chan struct{}
}

func (s *contextBlockingSyncerStub) Name() string { return s.name }

func (s *contextBlockingSyncerStub) Sync(ctx context.Context, _ db.Store) (*SyncResult, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
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

func TestManagerSyncOneFailsClosedWhenRunningStatusCannotBeRecorded(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{upsertErr: errors.New("db down")}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(store, logger, time.Hour)
	syncer := &successSyncerStub{name: "osv", result: SyncResult{EntriesSynced: 1, EntriesTotal: 1}}
	manager.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	err := manager.SyncOne(context.Background(), "osv")
	if err == nil {
		t.Fatal("SyncOne() error = nil, want status persistence error")
	}
	if !strings.Contains(err.Error(), "record running status") {
		t.Fatalf("SyncOne() error = %v, want running-status persistence failure", err)
	}
	if syncer.calls != 0 {
		t.Fatalf("syncer calls = %d, want 0 when running status cannot be recorded", syncer.calls)
	}
}

func TestManagerSyncOneFailsClosedWhenFinalStatusCannotBeRecorded(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{
		upsertErr:       errors.New("db down"),
		upsertErrOnCall: 2,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(store, logger, time.Hour)
	syncer := &successSyncerStub{name: "ghsa", result: SyncResult{EntriesSynced: 3, EntriesTotal: 3}}
	manager.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	err := manager.SyncOne(context.Background(), "ghsa")
	if err == nil {
		t.Fatal("SyncOne() error = nil, want final status persistence error")
	}
	if !strings.Contains(err.Error(), "record success status") {
		t.Fatalf("SyncOne() error = %v, want success-status persistence failure", err)
	}
	if syncer.calls != 1 {
		t.Fatalf("syncer calls = %d, want feed sync to run before final status failure", syncer.calls)
	}
	if store.upsertCalls != 2 {
		t.Fatalf("UpsertFeedSyncStatus calls = %d, want running and final status writes", store.upsertCalls)
	}
	if store.status == nil || store.status.LastSyncStatus != "running" {
		t.Fatalf("persisted status = %+v, want running preserved after final write failure", store.status)
	}
}

func TestManagerSyncOneRejectsOverlappingManualSync(t *testing.T) {
	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(store, logger, time.Hour)
	syncer := &successSyncerStub{name: "osv", result: SyncResult{EntriesSynced: 1, EntriesTotal: 1}}
	manager.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})
	manager.mu.Lock()
	syncMu := manager.feedLocks["osv"]
	manager.mu.Unlock()
	syncMu.Lock()
	defer syncMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := manager.SyncOne(ctx, "osv")
	if !errors.Is(err, ErrSyncAlreadyRunning) {
		t.Fatalf("overlapping SyncOne error = %v, want ErrSyncAlreadyRunning", err)
	}
	if syncer.calls != 0 {
		t.Fatalf("syncer calls = %d, want overlapping manual sync rejected before running", syncer.calls)
	}
	if store.upsertCalls != 0 {
		t.Fatalf("status writes = %d, want none for rejected overlapping manual sync", store.upsertCalls)
	}
}

func TestManagerBackgroundLockWaitHonorsContextCancellation(t *testing.T) {
	store := &managerStoreStub{}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	syncer := &successSyncerStub{name: "osv", result: SyncResult{EntriesSynced: 1, EntriesTotal: 1}}
	syncMu := &sync.Mutex{}
	syncMu.Lock()
	rf := &registeredFeed{
		config: FeedConfig{Syncer: syncer, Mode: FeedModeSelf, Enabled: true},
		syncMu: syncMu,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := manager.syncWithRetry(ctx, rf, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("syncWithRetry() error = %v, want context cancellation while waiting for feed lock", err)
	}
	if syncer.calls != 0 {
		t.Fatalf("syncer calls = %d, want 0 when context ends before lock acquisition", syncer.calls)
	}
	syncMu.Unlock()
}

func TestManagerSyncOneRecordsErrorWhenContextEndsAfterRunningStatus(t *testing.T) {
	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(store, logger, time.Hour)
	syncer := &contextBlockingSyncerStub{name: "ghsa", entered: make(chan struct{}, 1)}
	manager.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	err := manager.SyncOne(ctx, "ghsa")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SyncOne error = %v, want context deadline exceeded", err)
	}
	if store.status == nil {
		t.Fatal("feed status was not recorded")
	}
	if store.status.LastSyncStatus != "error" {
		t.Fatalf("LastSyncStatus = %q, want error after context ended", store.status.LastSyncStatus)
	}
	if !strings.Contains(store.status.LastError, "deadline") {
		t.Fatalf("LastError = %q, want deadline context", store.status.LastError)
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

func TestManagerApplyConfigStartsReplacementLoopAfterOldLoopStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &managerStoreStub{}
	logHandler, logSink := newManagerLogHandler()
	manager := NewManager(store, slog.New(logHandler), time.Hour)
	oldSyncer := &blockingSyncerStub{name: "osv", entered: make(chan struct{}, 1), release: make(chan struct{})}
	newRelease := make(chan struct{})
	latestRelease := make(chan struct{})
	releaseOld := sync.Once{}
	releaseNew := sync.Once{}
	releaseLatest := sync.Once{}
	t.Cleanup(func() {
		releaseOld.Do(func() { close(oldSyncer.release) })
		cancel()
		releaseNew.Do(func() { close(newRelease) })
		releaseLatest.Do(func() { close(latestRelease) })
		manager.Wait()
	})

	if err := manager.Register(FeedConfig{
		Syncer:  oldSyncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	manager.Start(ctx)

	select {
	case <-oldSyncer.entered:
	case <-time.After(time.Second):
		t.Fatal("old feed sync did not start")
	}

	newSyncer := &blockingSyncerStub{name: "osv", entered: make(chan struct{}, 1), release: newRelease}
	manager.ApplyConfig(context.Background(), FeedConfig{
		Syncer:  newSyncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	}, time.Hour)

	latestSyncer := &blockingSyncerStub{name: "osv", entered: make(chan struct{}, 1), release: latestRelease}
	manager.ApplyConfig(context.Background(), FeedConfig{
		Syncer:  latestSyncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	}, time.Hour)

	deadline := time.After(250 * time.Millisecond)
	for logSink.count("starting feed sync loop", "osv") < 2 {
		select {
		case <-logSink.ch:
		case <-deadline:
			releaseOld.Do(func() { close(oldSyncer.release) })
			goto oldReleased
		}
	}
	t.Fatal("replacement feed loop logged its opener before the old loop reached its terminal log")

oldReleased:
	select {
	case <-newSyncer.entered:
		t.Fatal("stale queued replacement started after a newer config replaced it")
	case <-latestSyncer.entered:
	case <-time.After(time.Second):
		t.Fatal("latest feed sync did not start after old loop stopped")
	}

	releaseLatest.Do(func() { close(latestRelease) })
	cancel()
	manager.Wait()

	oldShutdown := logSink.indexOf("feed sync loop shutting down", "osv", 1)
	secondStart := logSink.indexOf("starting feed sync loop", "osv", 2)
	if oldShutdown < 0 || secondStart < 0 {
		t.Fatalf("missing lifecycle logs: oldShutdown=%d secondStart=%d", oldShutdown, secondStart)
	}
	if secondStart < oldShutdown {
		t.Fatalf("replacement opener log index %d before old shutdown log index %d", secondStart, oldShutdown)
	}
}

func TestManagerApplyConfigPreventsStaleSyncStatusOverwrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &managerStoreStub{}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
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

	manager.ApplyConfig(context.Background(), FeedConfig{
		Syncer:  &successSyncerStub{name: "osv"},
		Mode:    FeedModeSelf,
		Enabled: false,
	}, time.Hour)

	disabled, ok := managerStatusByName(store, "osv")
	if !ok || disabled.LastSyncStatus != "disabled" {
		t.Fatalf("status after disabling = %+v ok=%v, want disabled", disabled, ok)
	}

	close(oldSyncer.release)
	manager.Wait()

	final, ok := managerStatusByName(store, "osv")
	if !ok || final.LastSyncStatus != "disabled" {
		t.Fatalf("final status = %+v ok=%v, want stale old sync not to overwrite disabled", final, ok)
	}
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
	store.status = &db.FeedSyncStatus{LastSyncStatus: "success", LastSyncAt: &now, EntriesTotal: 1}
	if !manager.lastSyncFresh(context.Background(), "osv", time.Hour) {
		t.Fatal("fresh success should be fresh")
	}
	store.status.EntriesTotal = 0
	if manager.lastSyncFresh(context.Background(), "osv", time.Hour) {
		t.Fatal("zero-entry success should not be fresh")
	}
	store.status.EntriesTotal = 1
	old := now.Add(-2 * time.Hour)
	store.status.LastSyncAt = &old
	if manager.lastSyncFresh(context.Background(), "osv", time.Hour) {
		t.Fatal("old sync should not be fresh")
	}
	future := now.Add(time.Hour)
	store.status.LastSyncAt = &future
	if manager.lastSyncFresh(context.Background(), "osv", time.Hour) {
		t.Fatal("future sync should not be fresh")
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

func TestLastSyncFreshUsesBoundedStatusRead(t *testing.T) {
	store := &managerStoreStub{
		getWaitForCtx: true,
	}
	var logs bytes.Buffer
	manager := NewManager(store, slog.New(slog.NewJSONHandler(&logs, nil)), time.Hour)
	manager.feedStatusReadTimeout = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if manager.lastSyncFresh(ctx, "osv", time.Hour) {
		t.Fatal("blocked status read should not be treated as fresh")
	}

	store.mu.Lock()
	getCtxErr := store.getCtxErr
	store.mu.Unlock()
	if !errors.Is(getCtxErr, context.DeadlineExceeded) {
		t.Fatalf("GetFeedSyncStatus context error = %v, want local deadline exceeded", getCtxErr)
	}
	if ctx.Err() != nil {
		t.Fatalf("parent context error = %v, want local read timeout before parent context", ctx.Err())
	}

	logLine := logs.String()
	for _, want := range []string{`"feed":"osv"`, `"operation":"last_sync_fresh"`, "context deadline"} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("freshness-read warning missing %q: %s", want, logLine)
		}
	}
}

func TestManagerStartHonorsDisabledStartupSync(t *testing.T) {
	store := &managerStoreStub{}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	manager.SetSyncOnStartup(false)
	syncer := &notifySyncerStub{name: "osv", called: make(chan struct{}, 1)}
	manager.Register(FeedConfig{Syncer: syncer, Enabled: true, Mode: FeedModeSelf})

	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)

	select {
	case <-syncer.called:
		t.Fatal("feed synced immediately even though startup sync is disabled")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	manager.Wait()

	status, ok := managerStatusByName(store, "osv")
	if !ok || status.LastSyncStatus != "pending" {
		t.Fatalf("osv status = %+v ok=%v, want pending row while startup sync is disabled", status, ok)
	}
}

func TestManagerStartupWiringDoesNotUseRawBooleanHelperArgs(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "manager.go", nil, 0)
	if err != nil {
		t.Fatalf("ParseFile(manager.go) error = %v", err)
	}

	guardedHelpers := map[string]struct{}{
		"startFeedLocked":                {},
		"startFeedLockedWithInitialSync": {},
	}
	var failures []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if _, ok := guardedHelpers[selector.Sel.Name]; !ok {
			return true
		}
		for _, arg := range call.Args {
			ident, ok := arg.(*ast.Ident)
			if !ok || (ident.Name != "true" && ident.Name != "false") {
				continue
			}
			pos := fset.Position(ident.Pos())
			failures = append(failures, fmt.Sprintf("%s:%d passes raw boolean %s to %s", pos.Filename, pos.Line, ident.Name, selector.Sel.Name))
		}
		return true
	})

	if len(failures) > 0 {
		t.Fatalf("manager startup helper calls must use named options instead of positional booleans:\n%s", strings.Join(failures, "\n"))
	}
}

func TestManagerWaitTracksPhaseOneCoordinator(t *testing.T) {
	store := &managerStoreStub{
		propagateEntered: make(chan struct{}, 1),
		propagateRelease: make(chan struct{}),
	}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	manager.Register(FeedConfig{
		Syncer:  &successSyncerStub{name: "osv", result: SyncResult{EntriesSynced: 1, EntriesTotal: 1}},
		Enabled: true,
		Mode:    FeedModeSelf,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	manager.Start(ctx)

	select {
	case <-store.propagateEntered:
	case <-time.After(time.Second):
		t.Fatal("phase-one coordinator did not enter alias propagation")
	}

	cancel()

	waitDone := make(chan struct{})
	go func() {
		manager.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		t.Fatal("Manager.Wait returned while phase-one coordinator was still running")
	case <-time.After(50 * time.Millisecond):
	}

	close(store.propagateRelease)
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("Manager.Wait did not return after phase-one coordinator completed")
	}
}

func TestManagerStartSkipsAliasPropagationWhenPhaseOneFeedsAreFresh(t *testing.T) {
	now := time.Now().UTC()
	store := &managerStoreStub{
		status: &db.FeedSyncStatus{
			FeedName:       "osv",
			LastSyncStatus: "success",
			LastSyncAt:     &now,
			EntriesTotal:   1,
		},
	}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	syncer := &notifySyncerStub{name: "osv", called: make(chan struct{}, 1)}
	manager.Register(FeedConfig{Syncer: syncer, Enabled: true, Mode: FeedModeSelf})
	ctx, cancel := context.WithCancel(context.Background())

	manager.Start(ctx)

	select {
	case <-syncer.called:
		t.Fatal("fresh feed unexpectedly performed startup sync")
	case <-time.After(100 * time.Millisecond):
	}
	if store.propagateCalled.Load() {
		t.Fatal("alias propagation ran even though no phase-one feed synced")
	}

	cancel()
	manager.Wait()
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

func TestManagerStartRecordsStatusWhenAliasPropagationFails(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{propagateErr: errors.New("alias propagation failed")}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	syncer := &successSyncerStub{name: "osv", result: SyncResult{EntriesSynced: 1, EntriesTotal: 1}}
	manager.Register(FeedConfig{Syncer: syncer, Enabled: true, Mode: FeedModeSelf})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Start(ctx)

	deadline := time.After(time.Second)
	for {
		if status, ok := managerStatusByName(store, "alias-severity-propagation"); ok {
			if status.LastSyncStatus != "error" {
				t.Fatalf("alias propagation status = %+v, want error", status)
			}
			if !strings.Contains(status.LastError, "alias propagation failed") {
				t.Fatalf("alias propagation LastError = %q, want propagation error", status.LastError)
			}
			cancel()
			manager.Wait()
			return
		}
		select {
		case <-deadline:
			t.Fatal("alias propagation failure status was not recorded")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestManagerStartRecordsStatusWhenAliasPropagationPanics(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	store := &managerStoreStub{propagatePanic: "alias propagation panic"}
	manager := NewManager(store, slog.New(slog.NewJSONHandler(&logs, nil)), time.Hour)
	syncer := &successSyncerStub{name: "osv", result: SyncResult{EntriesSynced: 1, EntriesTotal: 1}}
	manager.Register(FeedConfig{Syncer: syncer, Enabled: true, Mode: FeedModeSelf})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Start(ctx)

	deadline := time.After(time.Second)
	for {
		if status, ok := managerStatusByName(store, aliasSeverityPropagationStatusName); ok {
			if status.LastSyncStatus != db.FeedSyncStatusError {
				t.Fatalf("alias propagation status = %+v, want error", status)
			}
			if !strings.Contains(status.LastError, "alias propagation panic") {
				t.Fatalf("alias propagation LastError = %q, want recovered panic diagnostic", status.LastError)
			}
			if logLine := logs.String(); !strings.Contains(logLine, "alias severity propagation panic") {
				t.Fatalf("logs missing recovered panic diagnostic: %s", logLine)
			}
			cancel()
			manager.Wait()
			return
		}
		select {
		case <-deadline:
			t.Fatal("alias propagation panic status was not recorded")
		default:
			time.Sleep(10 * time.Millisecond)
		}
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
			LastETag:       "etag-old",
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
	if recovered.LastETag != "etag-old" || recovered.LastCommitHash != "commit-old" || string(recovered.Metadata) != `{"cursor":"old"}` {
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
	if err := cancelledManager.runSync(cancelledCtx, &registeredFeed{
		config: FeedConfig{Syncer: &successSyncerStub{name: "cancelled"}, Enabled: true, Mode: FeedModeSelf},
	}, logger); err != nil {
		t.Fatalf("cancelled runSync error = %v, want nil before any sync starts", err)
	}
	if len(cancelledStore.statuses) != 0 {
		t.Fatalf("cancelled runSync recorded %d statuses, want 0", len(cancelledStore.statuses))
	}

	permanentStore := &managerStoreStub{}
	permanentManager := NewManager(permanentStore, logger, time.Hour)
	if err := permanentManager.runSync(context.Background(), &registeredFeed{
		config: FeedConfig{Syncer: &permanentSyncerStub{name: "vulncheck"}, Enabled: true, Mode: FeedModeSelf},
	}, logger); err == nil {
		t.Fatal("permanent runSync error = nil, want permanent feed error")
	}
	if permanentStore.status == nil || permanentStore.status.LastSyncStatus != "permanent_error" {
		t.Fatalf("permanent runSync status = %+v, want permanent_error", permanentStore.status)
	}

	upsertFailStore := &managerStoreStub{upsertErr: errors.New("db down")}
	upsertFailManager := NewManager(upsertFailStore, logger, time.Hour)
	if err := upsertFailManager.recordStatus(context.Background(), "osv", "success", "", time.Millisecond, &SyncResult{EntriesSynced: 1, EntriesTotal: 1}); err == nil {
		t.Fatal("recordStatus() error = nil, want upsert failure")
	}
	if err := upsertFailManager.recordRunningStatus(context.Background(), "osv"); err == nil {
		t.Fatal("recordRunningStatus() error = nil, want upsert failure")
	}
}

func TestRecordRunningStatusPreservesExistingMetadata(t *testing.T) {
	t.Parallel()

	emptyStore := &managerStoreStub{}
	emptyManager := NewManager(emptyStore, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	if err := emptyManager.recordRunningStatus(context.Background(), "osv"); err != nil {
		t.Fatalf("initial recordRunningStatus() error = %v", err)
	}
	if emptyStore.status == nil || emptyStore.status.LastSyncStatus != "running" {
		t.Fatalf("initial recorded status = %+v, want running", emptyStore.status)
	}
	if emptyStore.status.LastSyncAt != nil {
		t.Fatalf("initial LastSyncAt = %v, want nil before usable feed data exists", emptyStore.status.LastSyncAt)
	}
	if emptyStore.status.UpdatedAt.IsZero() {
		t.Fatal("initial UpdatedAt is zero, want running attempt heartbeat")
	}

	lastSuccessfulSync := time.Now().UTC().Add(-72 * time.Hour)
	metadata := []byte(`{"etag":"old"}`)
	store := &managerStoreStub{
		status: &db.FeedSyncStatus{
			FeedName:       "osv",
			LastSyncStatus: "success",
			LastSyncAt:     &lastSuccessfulSync,
			EntriesSynced:  7,
			EntriesTotal:   9,
			LastETag:       "etag-old",
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
	if store.status.LastSyncAt == nil || !store.status.LastSyncAt.Equal(lastSuccessfulSync) {
		t.Fatalf("LastSyncAt = %v, want preserved successful sync time %v", store.status.LastSyncAt, lastSuccessfulSync)
	}
	if store.status.UpdatedAt.IsZero() || time.Since(store.status.UpdatedAt) > time.Minute {
		t.Fatalf("UpdatedAt = %v, want current running attempt heartbeat", store.status.UpdatedAt)
	}
	if store.status.EntriesSynced != 7 || store.status.EntriesTotal != 9 {
		t.Fatalf("recorded entries = %d/%d, want 7/9", store.status.EntriesSynced, store.status.EntriesTotal)
	}
	if store.status.LastETag != "etag-old" || store.status.LastCommitHash != "commit-old" {
		t.Fatalf("recorded status lost sync metadata: %+v", store.status)
	}
	if string(store.status.Metadata) != `{"etag":"old"}` {
		t.Fatalf("metadata = %s, want copied old metadata", string(store.status.Metadata))
	}
}

func TestRecordStatusPreservesExistingDataForNonSuccessStatuses(t *testing.T) {
	t.Parallel()

	lastSuccessfulSync := time.Now().UTC().Add(-12 * time.Hour)
	metadata := []byte(`{"cursor":"old"}`)
	store := &managerStoreStub{
		status: &db.FeedSyncStatus{
			FeedName:       "ghsa",
			LastSyncStatus: "success",
			LastSyncAt:     &lastSuccessfulSync,
			EntriesSynced:  7,
			EntriesTotal:   9,
			LastETag:       "etag-old",
			LastCommitHash: "commit-old",
			Metadata:       metadata,
		},
	}
	manager := NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)

	manager.recordStatus(context.Background(), "ghsa", "external", "", 0, nil)
	metadata[0] = '['

	if store.status == nil || store.status.LastSyncStatus != "external" {
		t.Fatalf("recorded status = %+v, want external", store.status)
	}
	if store.status.LastSyncAt == nil || !store.status.LastSyncAt.Equal(lastSuccessfulSync) {
		t.Fatalf("LastSyncAt = %v, want preserved successful sync time %v", store.status.LastSyncAt, lastSuccessfulSync)
	}
	if store.status.EntriesSynced != 7 || store.status.EntriesTotal != 9 {
		t.Fatalf("recorded entries = %d/%d, want 7/9", store.status.EntriesSynced, store.status.EntriesTotal)
	}
	if store.status.LastETag != "etag-old" || store.status.LastCommitHash != "commit-old" {
		t.Fatalf("recorded status lost sync metadata: %+v", store.status)
	}
	if string(store.status.Metadata) != `{"cursor":"old"}` {
		t.Fatalf("metadata = %s, want copied old metadata", string(store.status.Metadata))
	}
	if store.status.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt is zero, want configuration heartbeat")
	}

	manager.recordStatus(context.Background(), "ghsa", "error", "upstream failed", time.Second, nil)
	if store.status.LastSyncStatus != "error" || store.status.LastError != "upstream failed" {
		t.Fatalf("recorded status = %+v, want error with diagnostic", store.status)
	}
	if store.status.LastSyncAt == nil || !store.status.LastSyncAt.Equal(lastSuccessfulSync) {
		t.Fatalf("error LastSyncAt = %v, want preserved successful sync time %v", store.status.LastSyncAt, lastSuccessfulSync)
	}
	if store.status.EntriesSynced != 7 || store.status.EntriesTotal != 9 {
		t.Fatalf("error entries = %d/%d, want preserved 7/9", store.status.EntriesSynced, store.status.EntriesTotal)
	}
	if store.status.LastSyncDuration == nil || *store.status.LastSyncDuration != time.Second {
		t.Fatalf("LastSyncDuration = %v, want 1s", store.status.LastSyncDuration)
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

	manager.startFeedLocked(rf, time.Hour, nil, feedStartOptions{
		waitForPhase1: true,
		syncOnStartup: true,
	})
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

func TestNonRetryableErrorNilReturnsNil(t *testing.T) {
	t.Parallel()
	if got := NonRetryableError(nil); got != nil {
		t.Fatalf("NonRetryableError(nil) = %v, want nil", got)
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

func TestNonRetryableErrorWrapsAndPreservesMessage(t *testing.T) {
	t.Parallel()
	inner := errors.New("bad payload")
	wrapped := NonRetryableError(inner)
	if wrapped.Error() != "bad payload" {
		t.Fatalf("NonRetryableError message = %q, want %q", wrapped.Error(), "bad payload")
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

func TestNonRetryableErrorUnwrapsToOriginal(t *testing.T) {
	t.Parallel()
	inner := errors.New("original cause")
	wrapped := NonRetryableError(inner)
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

func TestNonRetryableErrorPreservesWrappedChain(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("sentinel")
	wrapped := fmt.Errorf("layer: %w", sentinel)
	nonRetryable := NonRetryableError(wrapped)

	if !errors.Is(nonRetryable, sentinel) {
		t.Fatal("errors.Is(NonRetryableError(wrapping(sentinel)), sentinel) = false, want true")
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

func TestIsNonRetryableError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil is retryable by default",
			err:  nil,
			want: false,
		},
		{
			name: "plain error is retryable",
			err:  errors.New("network failure"),
			want: false,
		},
		{
			name: "NonRetryableError is non-retryable",
			err:  NonRetryableError(errors.New("bad payload")),
			want: true,
		},
		{
			name: "wrapped NonRetryableError is non-retryable",
			err:  fmt.Errorf("sync failed: %w", NonRetryableError(errors.New("bad payload"))),
			want: true,
		},
		{
			name: "PermanentError is not this marker",
			err:  PermanentError(errors.New("missing key")),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsNonRetryableError(tt.err); got != tt.want {
				t.Fatalf("IsNonRetryableError(%v) = %v, want %v", tt.err, got, tt.want)
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

func TestRegisterAfterStartReturnsError(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	m := NewManager(store, nil, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	syncer := &permanentSyncerStub{name: "late-feed"}
	if err := m.Register(FeedConfig{Syncer: syncer, Mode: FeedModeSelf, Enabled: true}); !errors.Is(err, ErrManagerStarted) {
		t.Fatalf("Register(after Start) error = %v, want ErrManagerStarted", err)
	}
	if err := m.RegisterWithInterval(FeedConfig{Syncer: syncer, Mode: FeedModeSelf, Enabled: true}, time.Minute); !errors.Is(err, ErrManagerStarted) {
		t.Fatalf("RegisterWithInterval(after Start) error = %v, want ErrManagerStarted", err)
	}
	if _, ok := m.feeds["late-feed"]; ok {
		t.Fatal("late-feed was registered after Start")
	}
	cancel()
	m.Wait()
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

func TestSyncOneSuccessRecordsResultMetadata(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(store, logger, time.Hour)

	syncer := &successSyncerStub{
		name: "epss",
		result: SyncResult{
			EntriesSynced: 3,
			EntriesTotal:  3,
			Metadata:      []byte(`{"model_version":"v2024.01.01","score_date":"2026-04-03"}`),
		},
	}
	m.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	if err := m.SyncOne(context.Background(), "epss"); err != nil {
		t.Fatalf("SyncOne() unexpected error: %v", err)
	}
	if store.status == nil {
		t.Fatal("UpsertFeedSyncStatus was not called")
	}
	if string(store.status.Metadata) != `{"model_version":"v2024.01.01","score_date":"2026-04-03"}` {
		t.Fatalf("metadata = %s, want EPSS provenance metadata", store.status.Metadata)
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

type panicSyncerStub struct {
	name  string
	calls int
}

func (s *panicSyncerStub) Name() string { return s.name }

func (s *panicSyncerStub) Sync(context.Context, db.Store) (*SyncResult, error) {
	s.calls++
	panic("syncer boom")
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

func TestSyncOneNonRetryableErrorRecordsErrorWithoutRetries(t *testing.T) {
	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(store, logger, time.Hour)

	syncer := &failingSyncerStub{name: "epss", err: NonRetryableError(errors.New("invalid feed payload"))}
	m.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	err := m.SyncOne(context.Background(), "epss")
	if err == nil {
		t.Fatal("SyncOne() = nil, want non-retryable error")
	}
	if !IsNonRetryableError(err) {
		t.Fatalf("SyncOne() error = %v, want NonRetryableError marker", err)
	}
	if syncer.calls != 1 {
		t.Fatalf("syncer calls = %d, want 1", syncer.calls)
	}
	if store.status == nil {
		t.Fatal("UpsertFeedSyncStatus was not called")
	}
	if store.status.LastSyncStatus != db.FeedSyncStatusError {
		t.Fatalf("LastSyncStatus = %q, want error", store.status.LastSyncStatus)
	}
	if !strings.Contains(store.status.LastError, "invalid feed payload") {
		t.Fatalf("LastError = %q, want payload diagnostic", store.status.LastError)
	}
}

func TestSyncOnePanicIsRecordedAsSyncError(t *testing.T) {
	// Not parallel: mutates package-level backoffSchedule.
	saved := backoffSchedule
	backoffSchedule = [3]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { backoffSchedule = saved }()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(store, logger, time.Hour)

	syncer := &panicSyncerStub{name: "osv"}
	m.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	err := m.SyncOne(context.Background(), "osv")
	if err == nil {
		t.Fatal("SyncOne() = nil, want recovered panic error")
	}
	if !strings.Contains(err.Error(), "syncer panic") {
		t.Fatalf("SyncOne() error = %v, want syncer panic diagnostic", err)
	}

	wantCalls := len(backoffSchedule) + 1
	if syncer.calls != wantCalls {
		t.Fatalf("syncer calls = %d, want %d", syncer.calls, wantCalls)
	}
	if store.status == nil {
		t.Fatal("UpsertFeedSyncStatus was not called")
	}
	if store.status.LastSyncStatus != db.FeedSyncStatusError {
		t.Fatalf("LastSyncStatus = %q, want error", store.status.LastSyncStatus)
	}
	if !strings.Contains(store.status.LastError, "syncer panic") {
		t.Fatalf("LastError = %q, want syncer panic diagnostic", store.status.LastError)
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
	disabledStatus, ok := managerStatusByName(store, "disabled-feed")
	if !ok || disabledStatus.LastSyncStatus != "disabled" {
		t.Fatalf("disabled-feed status = %+v ok=%v, want disabled row", disabledStatus, ok)
	}
	externalStatus, ok := managerStatusByName(store, "external-feed")
	if !ok || externalStatus.LastSyncStatus != "external" {
		t.Fatalf("external-feed status = %+v ok=%v, want external row", externalStatus, ok)
	}
}
