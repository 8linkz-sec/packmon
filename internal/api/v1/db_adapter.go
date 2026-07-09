package v1

import (
	"context"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// DBStoreAdapter adapts the broad database Store to the API-owned Store port.
type DBStoreAdapter struct {
	store db.Store
}

// NewDBStoreAdapter wraps a database store for use by API v1 handlers.
func NewDBStoreAdapter(store db.Store) *DBStoreAdapter {
	if store == nil {
		return nil
	}
	return &DBStoreAdapter{store: store}
}

func (a *DBStoreAdapter) FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	return a.store.FindVulnerabilities(ctx, ecosystem, name, version)
}

func (a *DBStoreAdapter) FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	return a.store.FindMalicious(ctx, ecosystem, name, version)
}

func (a *DBStoreAdapter) FindVulnerabilitiesBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	return a.store.FindVulnerabilitiesBatch(ctx, packageLookupsToDB(packages))
}

func (a *DBStoreAdapter) FindMaliciousBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	return a.store.FindMaliciousBatch(ctx, packageLookupsToDB(packages))
}

func (a *DBStoreAdapter) FindReputationFindingsBatch(ctx context.Context, packages []PackageLookup, source string) ([]domain.Finding, error) {
	return a.store.FindReputationFindingsBatch(ctx, packageLookupsToDB(packages), source)
}

func (a *DBStoreAdapter) FindLifecycleFindingsBatch(ctx context.Context, packages []PackageLookup, now time.Time) ([]domain.Finding, error) {
	return a.store.FindLifecycleFindingsBatch(ctx, packageLookupsToDB(packages), now)
}

func (a *DBStoreAdapter) ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error) {
	return a.store.ListFeedSyncStatuses(ctx)
}

func (a *DBStoreAdapter) EnqueueRefresh(ctx context.Context, job *db.RefreshJob) (bool, int, error) {
	return a.store.EnqueueRefresh(ctx, job)
}

func (a *DBStoreAdapter) EnqueueRefreshWithAudit(ctx context.Context, job *db.RefreshJob, audit func(created bool, position int) *db.AdminAuditEntry) (bool, int, error) {
	return a.store.EnqueueRefreshWithAudit(ctx, job, audit)
}

func (a *DBStoreAdapter) InsertScanLog(ctx context.Context, entry *db.ScanLogEntry) error {
	return a.store.InsertScanLog(ctx, entry)
}

func (a *DBStoreAdapter) UpsertVulnerability(ctx context.Context, vuln *db.Vulnerability) error {
	return a.store.UpsertVulnerability(ctx, vuln)
}

func (a *DBStoreAdapter) DeleteVulnerability(ctx context.Context, id string) error {
	return a.store.DeleteVulnerability(ctx, id)
}

func (a *DBStoreAdapter) DeleteVulnerabilityForSource(ctx context.Context, id, source string) error {
	if scoped, ok := any(a.store).(db.SourceVulnerabilityDeleter); ok {
		return scoped.DeleteVulnerabilityForSource(ctx, id, source)
	}
	return a.store.DeleteVulnerability(ctx, id)
}

func (a *DBStoreAdapter) UpsertMaliciousFinding(ctx context.Context, finding *db.MaliciousFinding) error {
	return a.store.UpsertMaliciousFinding(ctx, finding)
}

func (a *DBStoreAdapter) DeleteMaliciousFinding(ctx context.Context, id string) error {
	return a.store.DeleteMaliciousFinding(ctx, id)
}

func (a *DBStoreAdapter) DeleteMaliciousFindingForSource(ctx context.Context, id, source string) error {
	if scoped, ok := any(a.store).(db.SourceMaliciousFindingDeleter); ok {
		return scoped.DeleteMaliciousFindingForSource(ctx, id, source)
	}
	return a.store.DeleteMaliciousFinding(ctx, id)
}

func (a *DBStoreAdapter) ImportVulnerabilityFeedWithAudit(ctx context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (int, int, error) {
	return a.store.ImportVulnerabilityFeedWithAudit(ctx, feed, items, deleteIDs, status, audit)
}

func (a *DBStoreAdapter) ImportMaliciousFeedWithAudit(ctx context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (int, int, error) {
	return a.store.ImportMaliciousFeedWithAudit(ctx, feed, items, deleteIDs, status, audit)
}

func (a *DBStoreAdapter) ImportVulnCheckWithAudit(ctx context.Context, feed string, entries []db.VulnCheckEntry, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (int, error) {
	return a.store.ImportVulnCheckWithAudit(ctx, feed, entries, status, audit)
}

func (a *DBStoreAdapter) ImportCISAKEVWithAudit(ctx context.Context, feed string, cveIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (int, error) {
	return a.store.ImportCISAKEVWithAudit(ctx, feed, cveIDs, status, audit)
}

func (a *DBStoreAdapter) ReplaceCISAKEVWithAudit(ctx context.Context, feed string, cveIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (int, int, error) {
	return a.store.ReplaceCISAKEVWithAudit(ctx, feed, cveIDs, status, audit)
}

func (a *DBStoreAdapter) ImportEPSSWithAudit(ctx context.Context, feed string, entries []db.EPSSEntry, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (int, int, error) {
	return a.store.ImportEPSSWithAudit(ctx, feed, entries, status, audit)
}

func (a *DBStoreAdapter) EnrichVulnCheck(ctx context.Context, entries []db.VulnCheckEntry) (int, error) {
	return a.store.EnrichVulnCheck(ctx, entries)
}

func (a *DBStoreAdapter) SetCISAKEV(ctx context.Context, cveIDs []string) (int, error) {
	return a.store.SetCISAKEV(ctx, cveIDs)
}

func (a *DBStoreAdapter) ClearCISAKEV(ctx context.Context, cveIDs []string) (int, error) {
	return a.store.ClearCISAKEV(ctx, cveIDs)
}

func (a *DBStoreAdapter) ReplaceCISAKEV(ctx context.Context, cveIDs []string) (int, int, error) {
	return a.store.ReplaceCISAKEV(ctx, cveIDs)
}

func (a *DBStoreAdapter) ReplaceEPSSScores(ctx context.Context, entries []db.EPSSEntry) (int, int, error) {
	return a.store.ReplaceEPSSScores(ctx, entries)
}

func (a *DBStoreAdapter) UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error {
	return a.store.UpsertFeedSyncStatus(ctx, status)
}

func (a *DBStoreAdapter) InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error {
	return a.store.InsertAdminAuditLog(ctx, entry)
}

func (a *DBStoreAdapter) ExportSync(ctx context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	return a.store.ExportSync(ctx, opts)
}

func (a *DBStoreAdapter) FindReputationFindings(ctx context.Context, ecosystem, name, source string) ([]domain.Finding, error) {
	finder, ok := any(a.store).(reputationPackageFinder)
	if !ok {
		return nil, nil
	}
	return finder.FindReputationFindings(ctx, ecosystem, name, source)
}

func (a *DBStoreAdapter) GetPackageCheckStatus(ctx context.Context, ecosystem, name, source string) (*db.PackageCheckStatus, error) {
	return a.store.GetPackageCheckStatus(ctx, ecosystem, name, source)
}

func (a *DBStoreAdapter) GetScanLogByIdempotencyKey(ctx context.Context, key string) (*db.ScanLogEntry, error) {
	return a.store.GetScanLogByIdempotencyKey(ctx, key)
}

func packageLookupsToDB(packages []PackageLookup) []db.PackageQuery {
	if len(packages) == 0 {
		return nil
	}
	out := make([]db.PackageQuery, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, db.PackageQuery{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Version:   pkg.Version,
		})
	}
	return out
}
