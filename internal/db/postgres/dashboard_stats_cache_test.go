package postgres

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type dashboardStatsObservedContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *dashboardStatsObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func TestDashboardStatsMemoCachesAndDeepClones(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	memo := dashboardStatsMemo{now: func() time.Time { return now }}
	var calls int
	load := func(context.Context) (*db.DashboardStatsResult, time.Time, error) {
		calls++
		return &db.DashboardStatsResult{
			TotalPackages: 7,
			BySeverity:    map[string]int{"HIGH": 3},
		}, now.Add(time.Hour), nil
	}

	first, err := memo.get(context.Background(), load)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	first.TotalPackages = 99
	first.BySeverity["HIGH"] = 99

	second, err := memo.get(context.Background(), load)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if calls != 1 {
		t.Fatalf("loader calls = %d, want 1", calls)
	}
	if second.TotalPackages != 7 || second.BySeverity["HIGH"] != 3 {
		t.Fatalf("cached value was mutated by caller: %+v", second)
	}
}

func TestDashboardStatsMemoDoesNotCacheErrors(t *testing.T) {
	memo := dashboardStatsMemo{}
	wantErr := errors.New("load failed")
	calls := 0
	load := func(context.Context) (*db.DashboardStatsResult, time.Time, error) {
		calls++
		if calls == 1 {
			return nil, time.Time{}, wantErr
		}
		return &db.DashboardStatsResult{TotalPackages: 9}, time.Now().Add(time.Hour), nil
	}

	if _, err := memo.get(context.Background(), load); !errors.Is(err, wantErr) {
		t.Fatalf("first error = %v, want %v", err, wantErr)
	}
	stats, err := memo.get(context.Background(), load)
	if err != nil || stats == nil || stats.TotalPackages != 9 {
		t.Fatalf("retry = %+v, %v", stats, err)
	}
	if calls != 2 {
		t.Fatalf("loader calls = %d, want 2", calls)
	}
}

func TestDashboardStatsMemoSharesOrdinaryLoadErrorWithCurrentWaiters(t *testing.T) {
	memo := dashboardStatsMemo{}
	wantErr := errors.New("load failed")
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	load := func(context.Context) (*db.DashboardStatsResult, time.Time, error) {
		calls.Add(1)
		close(started)
		<-release
		return nil, time.Time{}, wantErr
	}

	const waiters = 8
	errCh := make(chan error, waiters+1)
	go func() {
		_, err := memo.get(context.Background(), load)
		errCh <- err
	}()
	<-started

	for range waiters {
		ctx := &dashboardStatsObservedContext{
			Context:  context.Background(),
			observed: make(chan struct{}),
		}
		go func() {
			_, err := memo.get(ctx, load)
			errCh <- err
		}()
		<-ctx.observed
	}
	close(release)

	for range waiters + 1 {
		if err := <-errCh; !errors.Is(err, wantErr) {
			t.Fatalf("shared load error = %v, want %v", err, wantErr)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("loader calls = %d, want 1", got)
	}
}

func TestDashboardStatsMemoCoalescesConcurrentMisses(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	memo := dashboardStatsMemo{}
	load := func(context.Context) (*db.DashboardStatsResult, time.Time, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return &db.DashboardStatsResult{TotalPackages: 11}, time.Now().Add(time.Hour), nil
	}

	const callers = 12
	errCh := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats, err := memo.get(context.Background(), load)
			if err == nil && (stats == nil || stats.TotalPackages != 11) {
				err = errors.New("unexpected dashboard stats")
			}
			errCh <- err
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("loader calls = %d, want 1", got)
	}
}

func TestDashboardStatsMemoRetriesAfterCanceledLeader(t *testing.T) {
	memo := dashboardStatsMemo{}
	leaderStarted := make(chan struct{})
	var calls atomic.Int32
	load := func(ctx context.Context) (*db.DashboardStatsResult, time.Time, error) {
		if calls.Add(1) == 1 {
			close(leaderStarted)
			<-ctx.Done()
			return nil, time.Time{}, ctx.Err()
		}
		return &db.DashboardStatsResult{TotalPackages: 13}, time.Now().Add(time.Hour), nil
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := memo.get(leaderCtx, load)
		leaderErr <- err
	}()
	<-leaderStarted

	waiterResult := make(chan *db.DashboardStatsResult, 1)
	waiterErr := make(chan error, 1)
	go func() {
		stats, err := memo.get(context.Background(), load)
		waiterResult <- stats
		waiterErr <- err
	}()
	cancelLeader()

	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context canceled", err)
	}
	if err := <-waiterErr; err != nil {
		t.Fatalf("waiter error: %v", err)
	}
	if stats := <-waiterResult; stats == nil || stats.TotalPackages != 13 {
		t.Fatalf("waiter stats = %+v, want fresh retry", stats)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("loader calls = %d, want 2", got)
	}
}

func TestDashboardStatsMemoRetriesWhenGenerationChangesDuringLoad(t *testing.T) {
	memo := dashboardStatsMemo{}
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32
	load := func(context.Context) (*db.DashboardStatsResult, time.Time, error) {
		call := calls.Add(1)
		if call == 1 {
			close(firstStarted)
			<-releaseFirst
			return &db.DashboardStatsResult{TotalPackages: 1}, time.Now().Add(time.Hour), nil
		}
		return &db.DashboardStatsResult{TotalPackages: 2}, time.Now().Add(time.Hour), nil
	}

	result := make(chan *db.DashboardStatsResult, 1)
	go func() {
		stats, _ := memo.get(context.Background(), load)
		result <- stats
	}()
	<-firstStarted
	memo.invalidate()
	close(releaseFirst)

	stats := <-result
	if stats == nil || stats.TotalPackages != 2 {
		t.Fatalf("stats = %+v, want post-invalidation reload", stats)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("loader calls = %d, want 2", got)
	}
}

func TestDashboardStatsMemoExpiresAtDatabaseMidnightAndFallback(t *testing.T) {
	now := time.Date(2026, 10, 30, 23, 58, 0, 0, time.UTC)
	memo := dashboardStatsMemo{now: func() time.Time { return now }}
	calls := 0
	load := func(context.Context) (*db.DashboardStatsResult, time.Time, error) {
		calls++
		return &db.DashboardStatsResult{TotalPackages: calls}, now.Add(2 * time.Minute), nil
	}

	if _, err := memo.get(context.Background(), load); err != nil {
		t.Fatal(err)
	}
	now = now.Add(3 * time.Minute)
	if stats, err := memo.get(context.Background(), load); err != nil || stats.TotalPackages != 2 {
		t.Fatalf("midnight reload = %+v, %v", stats, err)
	}

	memo.invalidate()
	load = func(context.Context) (*db.DashboardStatsResult, time.Time, error) {
		calls++
		return &db.DashboardStatsResult{TotalPackages: calls}, now.Add(time.Hour), nil
	}
	if _, err := memo.get(context.Background(), load); err != nil {
		t.Fatal(err)
	}
	now = now.Add(dashboardStatsFallbackTTL + time.Second)
	if stats, err := memo.get(context.Background(), load); err != nil || stats.TotalPackages != 4 {
		t.Fatalf("fallback reload = %+v, %v", stats, err)
	}
}

func TestDashboardStatsMemoReloadsWhenLoadCrossesDatabaseMidnight(t *testing.T) {
	beforeMidnight := time.Date(2026, 10, 30, 23, 59, 59, 0, time.UTC)
	afterMidnight := beforeMidnight.Add(2 * time.Second)
	now := beforeMidnight
	memo := dashboardStatsMemo{now: func() time.Time { return now }}
	calls := 0
	load := func(context.Context) (*db.DashboardStatsResult, time.Time, error) {
		calls++
		if calls == 1 {
			now = afterMidnight
			return &db.DashboardStatsResult{TotalPackages: 1}, afterMidnight.Truncate(24 * time.Hour), nil
		}
		return &db.DashboardStatsResult{TotalPackages: 2}, afterMidnight.Truncate(24 * time.Hour).Add(24 * time.Hour), nil
	}

	stats, err := memo.get(context.Background(), load)
	if err != nil {
		t.Fatalf("get across database midnight: %v", err)
	}
	if stats == nil || stats.TotalPackages != 2 {
		t.Fatalf("stats across database midnight = %+v, want reloaded snapshot", stats)
	}
	if calls != 2 {
		t.Fatalf("loader calls = %d, want 2", calls)
	}

	cached, err := memo.get(context.Background(), load)
	if err != nil || cached == nil || cached.TotalPackages != 2 {
		t.Fatalf("cached reloaded stats = %+v, %v", cached, err)
	}
	if calls != 2 {
		t.Fatalf("loader calls after cached get = %d, want 2", calls)
	}
}
