package feed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

type managerStoreStub struct {
	db.Store
	status *db.FeedSyncStatus
}

func (s *managerStoreStub) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	copyValue := *status
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

	if m.interval != 6*time.Hour {
		t.Fatalf("default interval = %v, want 6h", m.interval)
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
	t.Parallel()

	// Use a cancelled context with a generous timeout so backoff sleeps are
	// short-circuited. We use a real context but set the backoff to be
	// tested indirectly: the syncer is called maxAttempts times.
	//
	// NOTE: with the real backoffSchedule (5s, 30s, 5min) this test would
	// be too slow. We shorten the schedule for this test only.
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
	name       string
	calls      int
	failUntil  int
	transErr   error
	result     SyncResult
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
	t.Parallel()

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
	t.Parallel()

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
