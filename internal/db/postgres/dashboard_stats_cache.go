package postgres

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

const dashboardStatsFallbackTTL = 5 * time.Minute

type dashboardStatsLoadFunc func(context.Context) (*db.DashboardStatsResult, time.Time, error)

type dashboardStatsFlight struct {
	done chan struct{}
	err  error
}

// dashboardStatsMemo is the single dashboard aggregate cache for one Store.
// Supported writes invalidate it after commit. The bounded fallback also
// observes changes made by another process, while the database-derived
// midnight prevents CURRENT_DATE lifecycle classifications from going stale.
type dashboardStatsMemo struct {
	mu         sync.Mutex
	generation uint64
	value      *db.DashboardStatsResult
	validUntil time.Time
	loading    *dashboardStatsFlight
	now        func() time.Time
}

func (m *dashboardStatsMemo) get(ctx context.Context, load dashboardStatsLoadFunc) (*db.DashboardStatsResult, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		now := m.currentTime()
		m.mu.Lock()
		if m.value != nil && now.Before(m.validUntil) {
			value := cloneDashboardStatsResult(m.value)
			m.mu.Unlock()
			return value, nil
		}
		if loading := m.loading; loading != nil {
			m.mu.Unlock()
			select {
			case <-loading.done:
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if loading.err != nil && !dashboardStatsLoadContextError(loading.err) {
					return nil, loading.err
				}
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		generation := m.generation
		loading := &dashboardStatsFlight{done: make(chan struct{})}
		m.loading = loading
		m.mu.Unlock()

		value, databaseMidnight, err := load(ctx)
		loadedAt := m.currentTime()

		m.mu.Lock()
		generationChanged := generation != m.generation
		databaseDayChanged := err == nil && !databaseMidnight.After(loadedAt)
		if err == nil && !generationChanged && !databaseDayChanged {
			validUntil := loadedAt.Add(dashboardStatsFallbackTTL)
			if databaseMidnight.Before(validUntil) {
				validUntil = databaseMidnight
			}
			m.value = cloneDashboardStatsResult(value)
			m.validUntil = validUntil
		}
		loading.err = err
		m.loading = nil
		close(loading.done)
		m.mu.Unlock()

		if err != nil {
			return nil, err
		}
		if generationChanged || databaseDayChanged {
			continue
		}
		return cloneDashboardStatsResult(value), nil
	}
}

func dashboardStatsLoadContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (m *dashboardStatsMemo) currentTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *dashboardStatsMemo) invalidate() {
	m.mu.Lock()
	m.generation++
	m.value = nil
	m.validUntil = time.Time{}
	m.mu.Unlock()
}

func cloneDashboardStatsResult(stats *db.DashboardStatsResult) *db.DashboardStatsResult {
	if stats == nil {
		return nil
	}
	clone := *stats
	if stats.BySeverity != nil {
		clone.BySeverity = make(map[string]int, len(stats.BySeverity))
		for severity, count := range stats.BySeverity {
			clone.BySeverity[severity] = count
		}
	}
	return &clone
}
