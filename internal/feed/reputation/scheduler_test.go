package reputation

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

type schedulerStore struct {
	marked        []db.PackageReputation
	upserts       []db.PackageReputation
	jobs          []db.RefreshJob
	markCalled    chan struct{}
	markCalls     int
	enqueueCalls  int
	markQueued    bool
	markQueuedSet bool
	markErr       error
	markErrs      []error
	markPanic     any
	upsertErr     error
	enqueueErr    error
	enqueueErrs   []error
}

type positionlessSchedulerStore struct {
	schedulerStore
	noPositionCalls int
}

func (s *schedulerStore) MarkPackageReputationDue(_ context.Context, rep *db.PackageReputation) (bool, error) {
	s.markCalls++
	if s.markCalled != nil {
		select {
		case s.markCalled <- struct{}{}:
		default:
		}
	}
	if len(s.markErrs) > 0 {
		err := s.markErrs[0]
		s.markErrs = s.markErrs[1:]
		if err != nil {
			return false, err
		}
	}
	if s.markPanic != nil {
		panic(s.markPanic)
	}
	if s.markErr != nil {
		return false, s.markErr
	}
	s.marked = append(s.marked, *rep)
	if s.markQueuedSet {
		return s.markQueued, nil
	}
	return true, nil
}

func (s *schedulerStore) UpsertPackageReputation(_ context.Context, rep *db.PackageReputation) error {
	if s.upsertErr != nil {
		return s.upsertErr
	}
	s.upserts = append(s.upserts, *rep)
	return nil
}

func (s *schedulerStore) EnqueueRefresh(_ context.Context, job *db.RefreshJob) (bool, int, error) {
	s.enqueueCalls++
	if len(s.enqueueErrs) > 0 {
		err := s.enqueueErrs[0]
		s.enqueueErrs = s.enqueueErrs[1:]
		if err != nil {
			return false, 0, err
		}
	}
	if s.enqueueErr != nil {
		return false, 0, s.enqueueErr
	}
	s.jobs = append(s.jobs, *job)
	return true, len(s.jobs), nil
}

func (s *positionlessSchedulerStore) EnqueueRefreshNoPosition(_ context.Context, job *db.RefreshJob) (bool, error) {
	s.noPositionCalls++
	s.jobs = append(s.jobs, *job)
	return true, nil
}

func TestSchedulerDeduplicatesAndCapsReversingLabsWork(t *testing.T) {
	t.Parallel()

	store := &schedulerStore{}
	scheduler := NewScheduler(store, slog.Default(), Config{
		ReversingLabsActive:              true,
		ReversingLabsMaxSchedulePerCheck: 2,
	})

	scheduler.ScheduleReversingLabs(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
		{Name: "lodash", Version: "4.17.21", Ecosystem: domain.EcosystemNPM},
		{Name: "express", Version: "4.18.2", Ecosystem: domain.EcosystemNPM},
	}, nil)

	if got := len(store.marked); got != 2 {
		t.Fatalf("marked reputations = %d, want budget-capped 2", got)
	}
	if got := len(store.jobs); got != 2 {
		t.Fatalf("jobs = %d, want budget-capped 2", got)
	}
	if store.jobs[0].Name != "left-pad" || store.jobs[1].Name != "lodash" {
		t.Fatalf("jobs = %+v, want deterministic first two unique packages", store.jobs)
	}
}

func TestSchedulerUsesPositionlessEnqueueWhenStoreSupportsIt(t *testing.T) {
	t.Parallel()

	store := &positionlessSchedulerStore{}
	scheduler := NewScheduler(store, slog.Default(), Config{
		ReversingLabsActive:              true,
		ReversingLabsMaxSchedulePerCheck: 10,
	})

	scheduler.ScheduleReversingLabs(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
	}, nil)

	if store.noPositionCalls != 1 {
		t.Fatalf("positionless enqueue calls = %d, want 1", store.noPositionCalls)
	}
	if store.enqueueCalls != 0 {
		t.Fatalf("position-counting enqueue calls = %d, want 0", store.enqueueCalls)
	}
	if got := len(store.jobs); got != 1 {
		t.Fatalf("jobs = %d, want one queued refresh", got)
	}
}

func TestSchedulerCapsUnsupportedReversingLabsWrites(t *testing.T) {
	t.Parallel()

	store := &schedulerStore{}
	scheduler := NewScheduler(store, slog.Default(), Config{
		ReversingLabsActive:              true,
		ReversingLabsMaxSchedulePerCheck: 2,
	})

	scheduler.ScheduleReversingLabs(context.Background(), []domain.Package{
		{Name: "github.com/acme/one", Version: "v1.0.0", Ecosystem: domain.EcosystemGo},
		{Name: "github.com/acme/two", Version: "v1.0.0", Ecosystem: domain.EcosystemGo},
		{Name: "phoenix", Version: "1.7.0", Ecosystem: domain.EcosystemHex},
		{Name: "ecto", Version: "3.11.0", Ecosystem: domain.EcosystemHex},
		{Name: "github.com/acme/five", Version: "v1.0.0", Ecosystem: domain.EcosystemGo},
	}, nil)

	if got := len(store.upserts); got != 2 {
		t.Fatalf("unsupported upserts = %d, want budget-capped 2: %+v", got, store.upserts)
	}
	if len(store.marked) != 0 || len(store.jobs) != 0 {
		t.Fatalf("unsupported packages scheduled worker work: marked=%+v jobs=%+v", store.marked, store.jobs)
	}
	for _, rep := range store.upserts {
		if rep.Status != "unsupported" {
			t.Fatalf("unsupported upsert status = %q, want unsupported", rep.Status)
		}
	}
}

func TestSchedulerSkipsCoveredUnsupportedAndExcludedPackages(t *testing.T) {
	t.Parallel()

	store := &schedulerStore{}
	scheduler := NewScheduler(store, slog.Default(), Config{
		ReversingLabsActive:              true,
		ReversingLabsMaxSchedulePerCheck: 10,
		ReversingLabsExcludedNamespaces:  []string{"npm/@school/", "maven/edu.school:"},
	})

	scheduler.ScheduleReversingLabs(context.Background(), []domain.Package{
		{Name: "@school/internal", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "edu.school:lab", Version: "1.0.0", Ecosystem: domain.EcosystemMaven},
		{Name: "github.com/acme/lib", Version: "1.0.0", Ecosystem: domain.EcosystemGo},
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
		{Name: "lodash", Version: "4.17.21", Ecosystem: domain.EcosystemNPM},
	}, []domain.Finding{
		{Name: "lodash", Version: "4.17.21", Ecosystem: domain.EcosystemNPM, Source: "osv"},
	})

	if got := len(store.marked); got != 1 {
		t.Fatalf("marked reputations = %d, want only public uncovered supported package", got)
	}
	if store.marked[0].Name != "left-pad" {
		t.Fatalf("marked = %+v, want left-pad", store.marked)
	}
	if got := len(store.jobs); got != 1 {
		t.Fatalf("jobs = %d, want 1", got)
	}
	if got := len(store.upserts); got != 1 || store.upserts[0].Status != "unsupported" || store.upserts[0].Ecosystem != "go" {
		t.Fatalf("unsupported rows = %+v, want Go unsupported row only", store.upserts)
	}
}

func TestSchedulerMarksOversizedReversingLabsCoordinatesUnsupportedWithoutQueueing(t *testing.T) {
	t.Parallel()

	store := &schedulerStore{}
	scheduler := NewScheduler(store, slog.Default(), Config{
		ReversingLabsActive:              true,
		ReversingLabsMaxSchedulePerCheck: 10,
	})

	scheduler.ScheduleReversingLabs(context.Background(), []domain.Package{
		{Name: "left-pad", Version: strings.Repeat("1", 257), Ecosystem: domain.EcosystemNPM},
	}, nil)

	if len(store.marked) != 0 || len(store.jobs) != 0 {
		t.Fatalf("oversized coordinate queued work: marked=%+v jobs=%+v", store.marked, store.jobs)
	}
	if got := len(store.upserts); got != 1 || store.upserts[0].Status != "unsupported" {
		t.Fatalf("unsupported rows = %+v, want one terminal unsupported row", store.upserts)
	}
}

func TestSchedulerDoesNothingWithoutActiveWorker(t *testing.T) {
	t.Parallel()

	store := &schedulerStore{}
	scheduler := NewScheduler(store, slog.Default(), Config{
		ReversingLabsActive:              false,
		ReversingLabsMaxSchedulePerCheck: 10,
	})

	scheduler.ScheduleReversingLabs(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
	}, nil)

	if len(store.marked) != 0 || len(store.upserts) != 0 || len(store.jobs) != 0 {
		t.Fatalf("scheduler wrote work without active worker: marked=%+v upserts=%+v jobs=%+v", store.marked, store.upserts, store.jobs)
	}
}

func TestSchedulerAsyncDoesNotRunAfterBackgroundContextCanceled(t *testing.T) {
	t.Parallel()

	store := &schedulerStore{markCalled: make(chan struct{}, 1)}
	scheduler := NewScheduler(store, slog.Default(), Config{
		ReversingLabsActive:              true,
		ReversingLabsMaxSchedulePerCheck: 10,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scheduler.ScheduleReversingLabsAsync(ctx, []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
	}, nil)

	select {
	case <-store.markCalled:
		t.Fatal("async scheduler started work after background context was canceled")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSchedulerConfigureDefaultsAndCoverageHelpers(t *testing.T) {
	t.Parallel()

	var nilScheduler *Scheduler
	nilScheduler.Configure(Config{})

	scheduler := NewScheduler(&schedulerStore{}, nil, Config{
		ReversingLabsActive:             true,
		ReversingLabsExcludedNamespaces: []string{" NPM/@Scope/ ", "npm/@scope/", "", "Maven/Com.Acme:"},
	})
	cfg := scheduler.snapshot()
	if !cfg.ReversingLabsActive || cfg.ReversingLabsMaxSchedulePerCheck != DefaultReversingLabsMaxSchedulePerCheck {
		t.Fatalf("snapshot config = %+v, want active default budget", cfg)
	}
	if strings.Join(cfg.ReversingLabsExcludedNamespaces, ",") != "npm/@scope/,maven/com.acme:" {
		t.Fatalf("excluded namespaces = %+v", cfg.ReversingLabsExcludedNamespaces)
	}

	key := packageCoverageKey(" NuGet ", "Newtonsoft.Json", " 13.0.3 ")
	if key.ecosystem != "nuget" || key.name != "newtonsoft.json" || key.version != "13.0.3" {
		t.Fatalf("packageCoverageKey(nuget) = %+v", key)
	}
	coverage := nonReversingLabsCoverage([]domain.Finding{
		{Ecosystem: domain.EcosystemNPM, Name: "left-pad", Version: "1.3.0", Source: "osv"},
		{Ecosystem: domain.EcosystemNPM, Name: "left-pad", Version: "1.3.0", Source: db.ReputationSourceReversingLabs},
	})
	if !coverage[packageCoverageKey("npm", "left-pad", "1.3.0")] {
		t.Fatalf("coverage = %+v, want non-ReversingLabs finding covered", coverage)
	}
}

func TestSchedulerAsyncRunsWhenActive(t *testing.T) {
	t.Parallel()

	store := &schedulerStore{markCalled: make(chan struct{}, 1)}
	scheduler := NewScheduler(store, slog.Default(), Config{
		ReversingLabsActive:              true,
		ReversingLabsMaxSchedulePerCheck: 10,
	})

	scheduler.ScheduleReversingLabsAsync(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
	}, nil)

	select {
	case <-store.markCalled:
	case <-time.After(time.Second):
		t.Fatal("async scheduler did not start work")
	}
}

func TestSchedulerAsyncSchedulesSynchronouslyWhenSaturated(t *testing.T) {
	t.Parallel()

	store := &schedulerStore{}
	scheduler := NewScheduler(store, slog.Default(), Config{
		ReversingLabsActive:              true,
		ReversingLabsMaxSchedulePerCheck: 10,
	})
	for i := 0; i < cap(scheduler.slots); i++ {
		scheduler.slots <- struct{}{}
	}

	scheduler.ScheduleReversingLabsAsync(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
	}, nil)

	if got := len(store.marked); got != 1 {
		t.Fatalf("marked reputations = %d, want saturated async scheduler to durably mark work before returning", got)
	}
	if got := len(store.jobs); got != 1 {
		t.Fatalf("jobs = %d, want saturated async scheduler to enqueue work before returning", got)
	}
}

// syncLogBuffer is a race-safe log sink for output written from the async
// scheduler goroutine.
type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestSchedulerAsyncRecoversPanicsAndReleasesSlot(t *testing.T) {
	t.Parallel()

	var logs syncLogBuffer
	panicValue := "mark panic " + strings.Repeat("x", 512) + " tail-marker"
	store := &schedulerStore{
		markCalled: make(chan struct{}, 1),
		markPanic:  panicValue,
	}
	scheduler := NewScheduler(store, slog.New(slog.NewJSONHandler(&logs, nil)), Config{
		ReversingLabsActive:              true,
		ReversingLabsMaxSchedulePerCheck: 10,
	})

	scheduler.ScheduleReversingLabsAsync(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
	}, nil)

	select {
	case <-store.markCalled:
	case <-time.After(time.Second):
		t.Fatal("async scheduler did not start work")
	}

	deadline := time.After(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for len(scheduler.slots) != 0 {
		select {
		case <-deadline:
			t.Fatalf("scheduler slot count = %d, want panic path to release slot", len(scheduler.slots))
		case <-ticker.C:
		}
	}

	logText := logs.String()
	if !strings.Contains(logText, "reversinglabs scheduler panic recovered") {
		t.Fatalf("logs = %q, want bounded panic diagnostic", logText)
	}
	if !strings.Contains(logText, `"panic":"mark panic`) {
		t.Fatalf("logs = %q, want panic value recorded", logText)
	}
	if strings.Contains(logText, "tail-marker") {
		t.Fatalf("logs = %q, want panic value bounded", logText)
	}
}

func TestSchedulerRetriesTransientStoreBackpressure(t *testing.T) {
	t.Parallel()

	store := &schedulerStore{
		markErrs:    []error{errors.New("mark backpressure")},
		enqueueErrs: []error{errors.New("enqueue backpressure")},
	}
	scheduler := NewScheduler(store, slog.Default(), Config{
		ReversingLabsActive:              true,
		ReversingLabsMaxSchedulePerCheck: 10,
	})

	scheduler.ScheduleReversingLabs(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
	}, nil)

	if store.markCalls != 2 {
		t.Fatalf("mark attempts = %d, want retry after transient backpressure", store.markCalls)
	}
	if got := len(store.marked); got != 1 {
		t.Fatalf("marked reputations = %d, want transient mark retry to preserve work", got)
	}
	if store.enqueueCalls != 2 {
		t.Fatalf("enqueue attempts = %d, want retry after transient backpressure", store.enqueueCalls)
	}
	if got := len(store.jobs); got != 1 {
		t.Fatalf("jobs = %d, want transient enqueue retry to preserve worker job", got)
	}
}

func TestSchedulerHandlesStoreErrorsAndUnqueuedReputations(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		store *schedulerStore
	}{
		{name: "mark error", store: &schedulerStore{markErr: errors.New("mark failed")}},
		{name: "not queued", store: &schedulerStore{markQueuedSet: true, markQueued: false}},
		{name: "enqueue error", store: &schedulerStore{enqueueErr: errors.New("enqueue failed")}},
		{name: "unsupported upsert error", store: &schedulerStore{upsertErr: errors.New("upsert failed")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			scheduler := NewScheduler(tt.store, slog.Default(), Config{
				ReversingLabsActive:              true,
				ReversingLabsMaxSchedulePerCheck: 10,
			})
			packages := []domain.Package{{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM}}
			if strings.Contains(tt.name, "unsupported") {
				packages = []domain.Package{{Name: "github.com/acme/lib", Version: "1.0.0", Ecosystem: domain.EcosystemGo}}
			}

			scheduler.ScheduleReversingLabs(context.Background(), packages, nil)
		})
	}
}
