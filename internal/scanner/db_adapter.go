package scanner

import (
	"context"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

type dbLocalChecker interface {
	FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindVulnerabilitiesBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error)
	FindMaliciousBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error)
	FindReputationFindingsBatch(ctx context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error)
	FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error)
}

// DBLocalCheckerAdapter adapts database-backed local checkers to scanner-owned
// lookup ports.
type DBLocalCheckerAdapter struct {
	checker dbLocalChecker
}

var _ LocalChecker = (*DBLocalCheckerAdapter)(nil)

// NewDBLocalCheckerAdapter wraps a database-backed local checker for scanner
// local mode.
func NewDBLocalCheckerAdapter(checker dbLocalChecker) *DBLocalCheckerAdapter {
	return &DBLocalCheckerAdapter{checker: checker}
}

func (a *DBLocalCheckerAdapter) FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	return a.checker.FindVulnerabilities(ctx, ecosystem, name, version)
}

func (a *DBLocalCheckerAdapter) FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	return a.checker.FindMalicious(ctx, ecosystem, name, version)
}

func (a *DBLocalCheckerAdapter) FindVulnerabilitiesBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	return a.checker.FindVulnerabilitiesBatch(ctx, packageLookupsToDB(packages))
}

func (a *DBLocalCheckerAdapter) FindMaliciousBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	return a.checker.FindMaliciousBatch(ctx, packageLookupsToDB(packages))
}

func (a *DBLocalCheckerAdapter) FindReputationFindingsBatch(ctx context.Context, packages []PackageLookup, source string) ([]domain.Finding, error) {
	return a.checker.FindReputationFindingsBatch(ctx, packageLookupsToDB(packages), source)
}

func (a *DBLocalCheckerAdapter) FindLifecycleFindingsBatch(ctx context.Context, packages []PackageLookup, now time.Time) ([]domain.Finding, error) {
	return a.checker.FindLifecycleFindingsBatch(ctx, packageLookupsToDB(packages), now)
}

func packageLookupsToDB(packages []PackageLookup) []db.PackageQuery {
	queries := make([]db.PackageQuery, 0, len(packages))
	for _, pkg := range packages {
		queries = append(queries, db.PackageQuery{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Version:   pkg.Version,
		})
	}
	return queries
}
