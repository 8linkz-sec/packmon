package main

import (
	"context"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

// noopStore satisfies db.Store with no-op implementations. It is used
// during development when no PostgreSQL instance is available. Every
// query method returns empty results; every write method succeeds
// silently.
type noopStore struct{}

var _ db.Store = (*noopStore)(nil)

func (*noopStore) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}

func (*noopStore) FindMalicious(context.Context, string, string) ([]domain.Finding, error) {
	return nil, nil
}

func (*noopStore) UpsertVulnerability(context.Context, *db.Vulnerability) error { return nil }

func (*noopStore) UpsertMaliciousFinding(context.Context, *db.MaliciousFinding) error { return nil }

func (*noopStore) DeleteVulnerability(context.Context, string) error { return nil }

func (*noopStore) DeleteMaliciousFinding(context.Context, string) error { return nil }

func (*noopStore) GetFeedSyncStatus(context.Context, string) (*db.FeedSyncStatus, error) {
	return nil, nil
}

func (*noopStore) UpsertFeedSyncStatus(context.Context, *db.FeedSyncStatus) error { return nil }

func (*noopStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	return nil, nil
}

func (*noopStore) EnqueueRefresh(context.Context, *db.RefreshJob) (bool, int, error) {
	return false, 0, nil
}

func (*noopStore) DequeueRefresh(context.Context, string) (*db.RefreshJob, error) {
	return nil, nil
}

func (*noopStore) CompleteRefresh(context.Context, int, error) error { return nil }

func (*noopStore) GetPackageCheckStatus(context.Context, string, string, string) (*db.PackageCheckStatus, error) {
	return nil, nil
}

func (*noopStore) UpsertPackageCheckStatus(context.Context, *db.PackageCheckStatus) error {
	return nil
}

func (*noopStore) InsertScanLog(context.Context, *db.ScanLogEntry) error { return nil }

func (*noopStore) FindAPIKeyByHash(context.Context, string) (*db.APIKey, error) {
	return nil, nil
}

func (*noopStore) TouchAPIKeyLastUsed(context.Context, int) error { return nil }

func (*noopStore) GetAdminAuth(context.Context) (*db.AdminAuth, error) {
	return nil, nil
}

func (*noopStore) UpsertAdminAuth(context.Context, string) error { return nil }

func (*noopStore) InsertAdminAuditLog(context.Context, *db.AdminAuditEntry) error { return nil }

func (*noopStore) Close() error { return nil }

// noopPinger satisfies health.Pinger and always succeeds.
type noopPinger struct{}

func (*noopPinger) Ping(context.Context) error { return nil }
