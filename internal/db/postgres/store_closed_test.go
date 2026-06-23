//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestPostgresStoreClosedPoolReturnsErrors(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	expectErr := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s error = nil, want closed pool error", name)
		}
	}

	expectErr("InsertScanLog", store.InsertScanLog(ctx, &db.ScanLogEntry{ScanID: "closed"}))
	_, err := store.ListRecentScans(ctx, 1)
	expectErr("ListRecentScans", err)
	_, err = store.ListRecentVulnerabilities(ctx, 1, 1)
	expectErr("ListRecentVulnerabilities", err)
	_, err = store.CountScansByDay(ctx, 1)
	expectErr("CountScansByDay", err)
	_, err = store.ScanTotals(ctx)
	expectErr("ScanTotals", err)
	_, err = store.SearchPackages(ctx, db.PackageSearchParams{Query: "pkg", Limit: 1})
	expectErr("SearchPackages", err)

	_, err = store.FindAPIKeyByHash(ctx, "hash")
	expectErr("FindAPIKeyByHash", err)
	expectErr("TouchAPIKeyLastUsed", store.TouchAPIKeyLastUsed(ctx, 1))
	_, err = store.ListAPIKeys(ctx)
	expectErr("ListAPIKeys", err)
	_, err = store.CreateAPIKey(ctx, "ci", "hash", nil)
	expectErr("CreateAPIKey", err)
	expectErr("RevokeAPIKey", store.RevokeAPIKey(ctx, 1))
	expectErr("DeleteAPIKey", store.DeleteAPIKey(ctx, 1))
	_, err = store.GetAdminAuth(ctx)
	expectErr("GetAdminAuth", err)
	expectErr("UpsertAdminAuth", store.UpsertAdminAuth(ctx, "hash", false))
	expectErr("InsertAdminAuditLog", store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{Action: "closed"}))
	_, err = store.ListAdminAuditLog(ctx, 1)
	expectErr("ListAdminAuditLog", err)

	_, err = store.QueueStats(ctx)
	expectErr("QueueStats", err)
	_, err = store.ListQueueJobs(ctx, "pending", 1)
	expectErr("ListQueueJobs", err)
	_, err = store.PurgeQueue(ctx)
	expectErr("PurgeQueue", err)
	expectErr("UpdateQueueJobPriority", store.UpdateQueueJobPriority(ctx, 1, 1))
	expectErr("RetryQueueJob", store.RetryQueueJob(ctx, 1))
	expectErr("PauseQueueJob", store.PauseQueueJob(ctx, 1))
	expectErr("ResumeQueueJob", store.ResumeQueueJob(ctx, 1))
	_, err = store.ClearQueue(ctx, []string{"pending"})
	expectErr("ClearQueue", err)
	_, err = store.DashboardStats(ctx)
	expectErr("DashboardStats", err)

	_, err = store.FindVulnerabilities(ctx, "npm", "pkg", "1.0.0")
	expectErr("FindVulnerabilities", err)
	_, err = store.FindMalicious(ctx, "npm", "pkg", "1.0.0")
	expectErr("FindMalicious", err)
	_, err = store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}})
	expectErr("FindVulnerabilitiesBatch", err)
	_, err = store.FindMaliciousBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}})
	expectErr("FindMaliciousBatch", err)
	expectErr("UpsertVulnerability", store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:       "GHSA-closed-0001",
		Severity: "LOW",
	}))
	expectErr("UpsertMaliciousFinding", store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "MAL-closed",
		Ecosystem: "npm",
		Name:      "pkg",
		Severity:  "LOW",
		RiskType:  "malware",
	}))
	expectErr("DeleteVulnerability", store.DeleteVulnerability(ctx, "GHSA-closed-0001"))
	expectErr("DeleteMaliciousFinding", store.DeleteMaliciousFinding(ctx, "MAL-closed"))
	_, err = store.ListMaliciousFindings(ctx, "", 1)
	expectErr("ListMaliciousFindings", err)
	_, err = store.SetCISAKEV(ctx, []string{"CVE-2026-0001"})
	expectErr("SetCISAKEV", err)
	_, err = store.ClearCISAKEV(ctx, []string{"CVE-2026-0001"})
	expectErr("ClearCISAKEV", err)
	_, err = store.PropagateSeverityViaAliases(ctx)
	expectErr("PropagateSeverityViaAliases", err)
	_, err = store.SetEPSSScores(ctx, []db.EPSSEntry{{CVEID: "CVE-2026-0001", Score: 0.1, Percentile: 0.2}})
	expectErr("SetEPSSScores", err)
	_, _, err = store.ReplaceEPSSScores(ctx, []db.EPSSEntry{{CVEID: "CVE-2026-0001", Score: 0.1, Percentile: 0.2}})
	expectErr("ReplaceEPSSScores", err)
	score := 5.5
	_, err = store.EnrichVulnCheck(ctx, []db.VulnCheckEntry{{CVEID: "CVE-2026-0001", CVSSScore: &score}})
	expectErr("EnrichVulnCheck", err)
	_, err = store.FindUnknownSeverityCVEAliases(ctx)
	expectErr("FindUnknownSeverityCVEAliases", err)
	expectErr("UpdateSeverityByCVE", store.UpdateSeverityByCVE(ctx, "CVE-2026-0001", "HIGH", 7.5))

	_, err = store.GetFeedSyncStatus(ctx, "osv")
	expectErr("GetFeedSyncStatus", err)
	expectErr("UpsertFeedSyncStatus", store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{FeedName: "osv"}))
	_, err = store.ListFeedSyncStatuses(ctx)
	expectErr("ListFeedSyncStatuses", err)
	_, _, err = store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "pkg", Source: "socket"})
	expectErr("EnqueueRefresh", err)
	_, err = store.DequeueRefresh(ctx, "socket")
	expectErr("DequeueRefresh", err)
	expectErr("CompleteRefresh", store.CompleteRefresh(ctx, 1, nil))
	_, err = store.ResetStuckJobs(ctx, "socket", time.Minute)
	expectErr("ResetStuckJobs", err)
	_, err = store.GetPackageCheckStatus(ctx, "npm", "pkg", "socket")
	expectErr("GetPackageCheckStatus", err)
	expectErr("UpsertPackageCheckStatus", store.UpsertPackageCheckStatus(ctx, &db.PackageCheckStatus{
		Ecosystem: "npm",
		Name:      "pkg",
		Source:    "socket",
	}))

	_, err = store.ExportSync(ctx, db.SyncExportOptions{})
	expectErr("ExportSync", err)
	_, err = store.exportSyncReputation(ctx, db.SyncExportOptions{}, time.Now().UTC(), 0)
	expectErr("exportSyncReputation", err)
	_, err = store.exportSyncMalicious(ctx, db.SyncExportOptions{}, time.Now().UTC(), 0)
	expectErr("exportSyncMalicious", err)

	expectErr("UpsertManualAdvisory", store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:closed",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "pkg",
		Severity:    "LOW",
		Summary:     "closed",
	}))
	expectErr("DeleteManualAdvisory", store.DeleteManualAdvisory(ctx, "manual:closed"))
	_, err = store.ListManualAdvisories(ctx, 1)
	expectErr("ListManualAdvisories", err)
	_, err = store.FindReputationFindings(ctx, "npm", "pkg", db.ReputationSourceReversingLabs)
	expectErr("FindReputationFindings", err)
	_, err = store.FindReputationFindingsBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}}, db.ReputationSourceReversingLabs)
	expectErr("FindReputationFindingsBatch", err)
	_, err = store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}}, time.Now().UTC())
	expectErr("FindLifecycleFindingsBatch", err)
	_, err = store.MarkPackageReputationDue(ctx, &db.PackageReputation{Ecosystem: "npm", Name: "pkg", Version: "1.0.0", Source: db.ReputationSourceReversingLabs})
	expectErr("MarkPackageReputationDue", err)
	_, err = store.ListDuePackageReputations(ctx, "npm", "pkg", db.ReputationSourceReversingLabs, 1)
	expectErr("ListDuePackageReputations", err)
	expectErr("UpsertPackageReputation", store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem:     "npm",
		Name:          "pkg",
		Version:       "1.0.0",
		Source:        db.ReputationSourceReversingLabs,
		Evidence:      json.RawMessage(`{}`),
		ReferenceURLs: json.RawMessage(`[]`),
	}))
	expectErr("UpsertLifecycleProducts", store.UpsertLifecycleProducts(ctx, []db.LifecycleProduct{{
		ProductSlug: "nodejs",
		Name:        "Node.js",
	}}))
}
