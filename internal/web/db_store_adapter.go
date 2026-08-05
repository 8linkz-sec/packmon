package web

import (
	"context"
	"errors"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

var (
	errMissingReputationLookup      = errors.New("web DB adapter store missing reputation lookup capability")
	errMissingReputationBatchLookup = errors.New("web DB adapter store missing reputation batch lookup capability")
	errMissingLifecycleBatchLookup  = errors.New("web DB adapter store missing lifecycle batch lookup capability")
)

// DBStore is the database-shaped persistence boundary adapted into the
// web-owned Store contract.
type DBStore interface {
	DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error)
	CountScansByDay(ctx context.Context, days int) ([]db.DailyScanStats, error)
	ListRecentScans(ctx context.Context, limit, offset int) ([]db.ScanLogEntry, error)
	SearchPackages(ctx context.Context, params db.PackageSearchParams) ([]db.PackageSearchResult, error)
	FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error)
	ListRecentVulnerabilities(ctx context.Context, days, limit int) ([]db.RecentVulnerability, error)
}

// NewDBStoreAdapter maps database-owned DTOs into the web-owned public UI
// boundary.
func NewDBStoreAdapter(store DBStore) Store {
	if store == nil {
		return nil
	}
	return dbStoreAdapter{store: store}
}

type dbStoreAdapter struct {
	store DBStore
}

func (a dbStoreAdapter) DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error) {
	return a.store.DashboardStats(ctx)
}

func (a dbStoreAdapter) CountScansByDay(ctx context.Context, days int) ([]db.DailyScanStats, error) {
	return a.store.CountScansByDay(ctx, days)
}

func (a dbStoreAdapter) ListRecentScans(ctx context.Context, limit, offset int) ([]db.ScanLogEntry, error) {
	return a.store.ListRecentScans(ctx, limit, offset)
}

func (a dbStoreAdapter) SearchPackages(ctx context.Context, params PackageSearchParams) ([]PackageSearchResult, error) {
	results, err := a.store.SearchPackages(ctx, dbSearchParams(params))
	if err != nil {
		return nil, err
	}
	return packageSearchResultsFromDB(results), nil
}

func (a dbStoreAdapter) FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	return a.store.FindVulnerabilities(ctx, ecosystem, name, version)
}

func (a dbStoreAdapter) FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	return a.store.FindMalicious(ctx, ecosystem, name, version)
}

func (a dbStoreAdapter) ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error) {
	return a.store.ListFeedSyncStatuses(ctx)
}

func (a dbStoreAdapter) ListRecentVulnerabilities(ctx context.Context, days, limit int) ([]db.RecentVulnerability, error) {
	return a.store.ListRecentVulnerabilities(ctx, days, limit)
}

func (a dbStoreAdapter) FindReputationFindings(ctx context.Context, ecosystem, name, source string) ([]domain.Finding, error) {
	store, ok := a.store.(interface {
		FindReputationFindings(context.Context, string, string, string) ([]domain.Finding, error)
	})
	if !ok {
		return nil, errMissingReputationLookup
	}
	return store.FindReputationFindings(ctx, ecosystem, name, source)
}

func (a dbStoreAdapter) FindReputationFindingsBatch(ctx context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error) {
	store, ok := a.store.(interface {
		FindReputationFindingsBatch(context.Context, []db.PackageQuery, string) ([]domain.Finding, error)
	})
	if !ok {
		return nil, errMissingReputationBatchLookup
	}
	return store.FindReputationFindingsBatch(ctx, packages, source)
}

func (a dbStoreAdapter) FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error) {
	store, ok := a.store.(interface {
		FindLifecycleFindingsBatch(context.Context, []db.PackageQuery, time.Time) ([]domain.Finding, error)
	})
	if !ok {
		return nil, errMissingLifecycleBatchLookup
	}
	return store.FindLifecycleFindingsBatch(ctx, packages, now)
}

func dbSearchParams(params PackageSearchParams) db.PackageSearchParams {
	return db.PackageSearchParams{
		Query:       params.Query,
		Severity:    params.Severity,
		FindingType: params.FindingType,
		Limit:       params.Limit,
		Offset:      params.Offset,
	}
}

func packageSearchResultsFromDB(results []db.PackageSearchResult) []PackageSearchResult {
	if len(results) == 0 {
		return nil
	}
	out := make([]PackageSearchResult, len(results))
	for i, result := range results {
		out[i] = PackageSearchResult{
			Ecosystem:          result.Ecosystem,
			Name:               result.Name,
			Version:            result.Version,
			FindingsCount:      result.FindingsCount,
			VulnerabilityCount: result.VulnerabilityCount,
			VulnerabilityIDs:   result.VulnerabilityIDs,
			FindingTypes:       result.FindingTypes,
			Sources:            result.Sources,
		}
	}
	return out
}
