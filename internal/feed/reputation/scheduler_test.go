package reputation

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

type schedulerStore struct {
	marked     []db.PackageReputation
	upserts    []db.PackageReputation
	jobs       []db.RefreshJob
	markCalled chan struct{}
}

func (s *schedulerStore) MarkPackageReputationDue(_ context.Context, rep *db.PackageReputation) (bool, error) {
	if s.markCalled != nil {
		select {
		case s.markCalled <- struct{}{}:
		default:
		}
	}
	s.marked = append(s.marked, *rep)
	return true, nil
}

func (s *schedulerStore) UpsertPackageReputation(_ context.Context, rep *db.PackageReputation) error {
	s.upserts = append(s.upserts, *rep)
	return nil
}

func (s *schedulerStore) EnqueueRefresh(_ context.Context, job *db.RefreshJob) (bool, int, error) {
	s.jobs = append(s.jobs, *job)
	return true, len(s.jobs), nil
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
