//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// closedStoreForFailurePaths starts a real store and then closes its pool. Every
// subsequent query fails at the driver, which is how these tests reach the error
// branch after each SQL call. One container covers them all.
func closedStoreForFailurePaths(t *testing.T) *Store {
	t.Helper()

	store, _ := startDockerPostgresStore(t)
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return store
}

// TestClosedStoreNeverReportsAnEmptyFindingSet is the security-relevant half. A
// lookup against an unusable database that returned no findings and no error
// would let the server answer a scan with "clean" while it cannot read its own
// advisory data.
func TestClosedStoreNeverReportsAnEmptyFindingSet(t *testing.T) {
	store := closedStoreForFailurePaths(t)
	ctx := context.Background()
	packages := []db.PackageQuery{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}}

	for name, call := range map[string]func() ([]domain.Finding, error){
		"FindVulnerabilities": func() ([]domain.Finding, error) {
			return store.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0")
		},
		"FindVulnerabilitiesBatch": func() ([]domain.Finding, error) {
			return store.FindVulnerabilitiesBatch(ctx, packages)
		},
		"FindMalicious": func() ([]domain.Finding, error) {
			return store.FindMalicious(ctx, "npm", "evil-pkg", "1.0.0")
		},
		"FindMaliciousBatch": func() ([]domain.Finding, error) {
			return store.FindMaliciousBatch(ctx, packages)
		},
		"FindLifecycleFindingsBatch": func() ([]domain.Finding, error) {
			return store.FindLifecycleFindingsBatch(ctx, packages, time.Now().UTC())
		},
	} {
		findings, err := call()
		if err == nil {
			t.Errorf("%s on a closed pool = %d findings, nil; want an error", name, len(findings))
		}
	}
}

// TestClosedStoreReportsAdminReadFailures covers the admin and dashboard reads.
// Each backs a page an operator uses to judge system health, so an empty page
// that looks like real data is worse than a visible error.
func TestClosedStoreReportsAdminReadFailures(t *testing.T) {
	store := closedStoreForFailurePaths(t)
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"GetAdminAuth":                 func() error { _, err := store.GetAdminAuth(ctx); return err },
		"ListAdminAuditLog":            func() error { _, err := store.ListAdminAuditLog(ctx, 10); return err },
		"ListAdminAuditLogPage":        func() error { _, err := store.ListAdminAuditLogPage(ctx, 10, 0); return err },
		"ListAPIKeys":                  func() error { _, err := store.ListAPIKeys(ctx); return err },
		"ListAPIKeysPage":              func() error { _, err := store.ListAPIKeysPage(ctx, 10, 0); return err },
		"FindAPIKeyByHash":             func() error { _, err := store.FindAPIKeyByHash(ctx, "hash"); return err },
		"ListFeedConfigs":              func() error { _, err := store.ListFeedConfigs(ctx); return err },
		"GetFeedConfig":                func() error { _, err := store.GetFeedConfig(ctx, "osv"); return err },
		"ListFeedSyncStatuses":         func() error { _, err := store.ListFeedSyncStatuses(ctx); return err },
		"GetFeedSyncStatus":            func() error { _, err := store.GetFeedSyncStatus(ctx, "osv"); return err },
		"DashboardStats":               func() error { _, err := store.DashboardStats(ctx); return err },
		"ScanTotals":                   func() error { _, err := store.ScanTotals(ctx); return err },
		"CountScansByDay":              func() error { _, err := store.CountScansByDay(ctx, 7); return err },
		"ListRecentVulnerabilities":    func() error { _, err := store.ListRecentVulnerabilities(ctx, 7, 10); return err },
		"CountUnknownSeverityFindings": func() error { _, err := store.CountUnknownSeverityFindings(ctx); return err },
		"CountVulnerabilitiesBySource": func() error { _, err := store.CountVulnerabilitiesBySource(ctx, "osv"); return err },
		"GetPackageCheckStatus": func() error {
			_, err := store.GetPackageCheckStatus(ctx, "npm", "left-pad", "socket")
			return err
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s on a closed pool = nil error, want a failure", name)
		}
	}
}

// TestClosedStoreReportsWriteFailures covers the mutating paths. A silently
// dropped write would leave the admin UI reporting success for a change that
// never happened.
func TestClosedStoreReportsWriteFailures(t *testing.T) {
	store := closedStoreForFailurePaths(t)
	ctx := context.Background()
	audit := &db.AdminAuditEntry{Action: "test", IP: "127.0.0.1"}

	for name, call := range map[string]func() error{
		"UpsertAdminAuth": func() error {
			return store.UpsertAdminAuth(ctx, "hash", true)
		},
		"UpsertAdminAuthWithAudit": func() error {
			return store.UpsertAdminAuthWithAudit(ctx, "hash", true, audit)
		},
		"InsertAdminAuditLog": func() error {
			return store.InsertAdminAuditLog(ctx, audit)
		},
		"CreateAPIKey": func() error {
			_, err := store.CreateAPIKey(ctx, "key", "hash", nil)
			return err
		},
		"RevokeAPIKey": func() error {
			return store.RevokeAPIKey(ctx, 1)
		},
		"DeleteAPIKey": func() error {
			return store.DeleteAPIKey(ctx, 1)
		},
		"TouchAPIKeyLastUsed": func() error {
			return store.TouchAPIKeyLastUsed(ctx, 1)
		},
		"UpsertFeedConfig": func() error {
			return store.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: "osv", Enabled: true})
		},
		"DeleteFeedConfig": func() error {
			return store.DeleteFeedConfig(ctx, "osv")
		},
		"UpsertFeedSyncStatus": func() error {
			return store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{FeedName: "osv"})
		},
		"UpsertMaliciousFinding": func() error {
			return store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
				ID: "MAL-1", Ecosystem: "npm", Name: "evil", Source: "socket", Severity: "HIGH",
			})
		},
		"UpsertPackageCheckStatus": func() error {
			return store.UpsertPackageCheckStatus(ctx, &db.PackageCheckStatus{
				Ecosystem: "npm", Name: "left-pad", Source: "socket",
			})
		},
		"EnqueueRefresh": func() error {
			_, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{
				Ecosystem: "npm", Name: "left-pad", Source: "scan",
			})
			return err
		},
		"EnqueueRefreshNoPosition": func() error {
			_, err := store.EnqueueRefreshNoPosition(ctx, &db.RefreshJob{
				Ecosystem: "npm", Name: "left-pad", Source: "scan",
			})
			return err
		},
		"DequeueRefresh": func() error {
			_, err := store.DequeueRefresh(ctx, "scan")
			return err
		},
		"CompleteRefresh": func() error {
			return store.CompleteRefresh(ctx, 1, nil)
		},
		"ResetStuckJobs": func() error {
			_, err := store.ResetStuckJobs(ctx, "scan", time.Hour)
			return err
		},
		"PruneAdminAuditLogs": func() error {
			_, err := store.PruneAdminAuditLogs(ctx, time.Hour)
			return err
		},
		"PrunePackageCheckStatus": func() error {
			_, err := store.PrunePackageCheckStatus(ctx, time.Hour)
			return err
		},
		"RepairCaseInsensitivePackageNames": func() error {
			_, err := store.RepairCaseInsensitivePackageNames(ctx)
			return err
		},
		"RepairGHSAAffectedPackages": func() error {
			_, err := store.RepairGHSAAffectedPackages(ctx)
			return err
		},
		"RecordNVDCVSSNegativeLookup": func() error {
			return store.RecordNVDCVSSNegativeLookup(ctx, "CVE-2026-10001")
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s on a closed pool = nil error, want a failure", name)
		}
	}
}

// TestClosedStoreReportsImportFailures covers the feed importers, which all open
// a transaction first. A swallowed failure here would mark a feed as synced
// while none of its advisories landed.
func TestClosedStoreReportsImportFailures(t *testing.T) {
	store := closedStoreForFailurePaths(t)
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"ImportVulnerabilityFeed": func() error {
			_, _, err := store.ImportVulnerabilityFeed(ctx, "osv", []db.Vulnerability{{
				ID: "GHSA-1", Severity: "HIGH",
			}}, nil, nil)
			return err
		},
		"ImportMaliciousFeed": func() error {
			_, _, err := store.ImportMaliciousFeed(ctx, "socket", []db.MaliciousFinding{{
				ID: "MAL-1", Ecosystem: "npm", Name: "evil", Source: "socket", Severity: "HIGH",
			}}, nil, nil)
			return err
		},
		"ImportCISAKEV": func() error {
			_, err := store.ImportCISAKEVWithAudit(ctx, "cisa_kev", []string{"CVE-2026-10001"}, nil, nil)
			return err
		},
		"ReplaceCISAKEV": func() error {
			_, _, err := store.ReplaceCISAKEVWithAudit(ctx, "cisa_kev", []string{"CVE-2026-10001"}, nil, nil)
			return err
		},
		"ImportEPSS": func() error {
			_, _, err := store.ImportEPSSWithAudit(ctx, "epss", []db.EPSSEntry{{
				CVEID: "CVE-2026-10001", Score: 0.1, Percentile: 0.5,
			}}, nil, nil)
			return err
		},
		"ImportVulnCheck": func() error {
			_, err := store.ImportVulnCheckWithAudit(ctx, "vulncheck", []db.VulnCheckEntry{{
				CVEID: "CVE-2026-10001",
			}}, nil, nil)
			return err
		},
		"ReplaceLifecycleProducts": func() error {
			_, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{{ProductSlug: "nodejs", Name: "Node.js"}})
			return err
		},
		"PruneMaliciousFindingsForSourceUpdatedBefore": func() error {
			_, err := store.PruneMaliciousFindingsForSourceUpdatedBefore(ctx, "socket", time.Now().UTC())
			return err
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s on a closed pool = nil error, want a failure", name)
		}
	}
}
