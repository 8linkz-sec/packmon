package web

import (
	"context"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

// Store is the subset of persistence required by the public web UI.
// The server-side PostgreSQL store and the local SQLite store can both
// satisfy this interface.
type Store interface {
	DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error)
	CountScansByDay(ctx context.Context, days int) ([]db.DailyScanStats, error)
	ListRecentScans(ctx context.Context, limit int) ([]db.ScanLogEntry, error)
	SearchPackages(ctx context.Context, params db.PackageSearchParams) ([]db.PackageSearchResult, error)
	FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error)
	ListRecentVulnerabilities(ctx context.Context, days, limit int) ([]db.RecentVulnerability, error)
}
