package web

import (
	"context"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// Store is the subset of persistence required by the public web UI.
// The server-side PostgreSQL store and the local SQLite store can both
// satisfy this interface.
type Store interface {
	DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error)
	CountScansByDay(ctx context.Context, days int) ([]db.DailyScanStats, error)
	ListRecentScans(ctx context.Context, limit, offset int) ([]db.ScanLogEntry, error)
	SearchPackages(ctx context.Context, params PackageSearchParams) ([]PackageSearchResult, error)
	FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindReputationFindings(ctx context.Context, ecosystem, name, source string) ([]domain.Finding, error)
	FindReputationFindingsBatch(ctx context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error)
	FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error)
	ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error)
	ListRecentVulnerabilities(ctx context.Context, days, limit int) ([]db.RecentVulnerability, error)
}

// PackageSearchParams describes the web search filters accepted by the public
// package search page.
type PackageSearchParams struct {
	Query       string
	Severity    string
	FindingType string
	Limit       int
	Offset      int
}

// PackageSearchResult is the web-owned package search result model rendered by
// the public search template.
type PackageSearchResult struct {
	Ecosystem          string
	Name               string
	Version            string
	FindingsCount      int
	VulnerabilityCount int
	VulnerabilityIDs   string
	FindingTypes       string
	Sources            string
}
