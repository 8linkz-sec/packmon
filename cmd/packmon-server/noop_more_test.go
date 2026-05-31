package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

func TestNoopStoreFindingsBatchSearchAndStats(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:       "manual:vuln",
		Severity: "high",
		Summary:  "manual vuln",
		Sources:  []db.VulnerabilitySource{{Source: "manual"}},
		AffectedPackages: []db.AffectedPackage{
			{Ecosystem: "npm", Name: "left-pad"},
		},
	}); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "M-1",
		Ecosystem: "npm",
		Name:      "left-pad",
		Versions:  []byte(`["1.0.0"]`),
		Severity:  "CRITICAL",
		RiskType:  "malware",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding() error = %v", err)
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "M-2",
		Ecosystem: "npm",
		Name:      "left-pad",
		Versions:  []byte(`["2.0.0"]`),
		Severity:  "HIGH",
		RiskType:  "typosquatting",
		Summary:   "wrong version",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding(M-2) error = %v", err)
	}

	vulns, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch() error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].Severity != "HIGH" || vulns[0].Source != "manual" {
		t.Fatalf("vulnerability batch = %+v, want normalized manual finding", vulns)
	}

	malicious, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "M-1" || malicious[0].Type != domain.FindingTypeMalicious {
		t.Fatalf("malicious batch = %+v, want only matching version", malicious)
	}

	results, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "left", Severity: "CRITICAL", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages() error = %v", err)
	}
	if len(results) != 1 || results[0].Name != "left-pad" || results[0].FindingsCount != 1 {
		t.Fatalf("SearchPackages() = %+v, want one critical malicious result", results)
	}

	stats, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats() error = %v", err)
	}
	if stats.TotalPackages != 1 || stats.TotalMalicious != 2 || stats.BySeverity["CRITICAL"] != 1 || stats.BySeverity["HIGH"] != 1 {
		t.Fatalf("DashboardStats() = %+v, want malicious dashboard counts", stats)
	}
}

func TestNoopStoreQueueLifecycleAndStuckReset(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	createdLow, posLow, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "slow", Source: "socket", Priority: 3})
	if err != nil {
		t.Fatalf("EnqueueRefresh(low) error = %v", err)
	}
	createdHigh, posHigh, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "fast", Source: "socket", Priority: 0})
	if err != nil {
		t.Fatalf("EnqueueRefresh(high) error = %v", err)
	}
	if !createdLow || !createdHigh || posLow <= 0 || posHigh <= 0 {
		t.Fatalf("created/positions = low(%v,%d) high(%v,%d), want created jobs with positive positions", createdLow, posLow, createdHigh, posHigh)
	}

	first, err := store.DequeueRefresh(ctx, "socket")
	if err != nil {
		t.Fatalf("DequeueRefresh() error = %v", err)
	}
	if first == nil || first.Name != "fast" || first.Status != "processing" {
		t.Fatalf("first dequeued job = %+v, want fast processing", first)
	}

	old := time.Now().UTC().Add(-10 * time.Minute)
	store.mu.Lock()
	for i := range store.refreshJobs {
		if store.refreshJobs[i].ID == first.ID {
			store.refreshJobs[i].ProcessedAt = &old
		}
	}
	store.mu.Unlock()
	reset, err := store.ResetStuckJobs(ctx, "socket", time.Minute)
	if err != nil {
		t.Fatalf("ResetStuckJobs() error = %v", err)
	}
	if reset != 1 {
		t.Fatalf("ResetStuckJobs() = %d, want 1", reset)
	}

	if err := store.UpdateQueueJobPriority(ctx, first.ID, 2); err != nil {
		t.Fatalf("UpdateQueueJobPriority() error = %v", err)
	}
	if err := store.PauseQueueJob(ctx, first.ID); err != nil {
		t.Fatalf("PauseQueueJob() error = %v", err)
	}
	if err := store.RetryQueueJob(ctx, first.ID); err != nil {
		t.Fatalf("RetryQueueJob(paused) error = %v", err)
	}
	job, err := store.DequeueRefresh(ctx, "socket")
	if err != nil {
		t.Fatalf("DequeueRefresh(after retry) error = %v", err)
	}
	if job == nil {
		t.Fatal("DequeueRefresh(after retry) = nil, want job")
	}
	if err := store.CompleteRefresh(ctx, job.ID, errors.New("upstream")); err != nil {
		t.Fatalf("CompleteRefresh(error) error = %v", err)
	}
	stats, err := store.QueueStats(ctx)
	if err != nil {
		t.Fatalf("QueueStats() error = %v", err)
	}
	if stats.Error != 1 {
		t.Fatalf("QueueStats().Error = %d, want 1", stats.Error)
	}
	purged, err := store.PurgeQueue(ctx)
	if err != nil {
		t.Fatalf("PurgeQueue() error = %v", err)
	}
	if purged != 1 {
		t.Fatalf("PurgeQueue() = %d, want 1", purged)
	}
	cleared, err := store.ClearQueue(ctx, []string{"pending", "bogus"})
	if err != nil {
		t.Fatalf("ClearQueue() error = %v", err)
	}
	if cleared != 1 {
		t.Fatalf("ClearQueue() = %d, want remaining pending job cleared", cleared)
	}
}

func TestNoopStoreFeedStatusConfigScanAndAPIKeyHelpers(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	metadata := []byte(`{"etag":"one"}`)
	now := time.Now().UTC()
	if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:         "osv",
		LastSyncAt:       &now,
		LastSyncStatus:   "success",
		EntriesSynced:    2,
		EntriesTotal:     3,
		Metadata:         metadata,
		LastCommitHash:   "abc",
		LastEtag:         "etag",
		LastSyncDuration: nil,
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus() error = %v", err)
	}
	metadata[0] = '['
	status, err := store.GetFeedSyncStatus(ctx, "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus() error = %v", err)
	}
	if status == nil || string(status.Metadata) != `{"etag":"one"}` {
		t.Fatalf("feed status = %+v, want copied metadata", status)
	}
	statuses, err := store.ListFeedSyncStatuses(ctx)
	if err != nil {
		t.Fatalf("ListFeedSyncStatuses() error = %v", err)
	}
	if len(statuses) != 1 || statuses[0].FeedName != "osv" {
		t.Fatalf("ListFeedSyncStatuses() = %+v", statuses)
	}

	interval := 30 * time.Minute
	if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: " GHSA ", Enabled: true, Mode: "self", SyncInterval: &interval}); err != nil {
		t.Fatalf("UpsertFeedConfig() error = %v", err)
	}
	cfg, err := store.GetFeedConfig(ctx, "ghsa")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if cfg == nil || cfg.FeedName != "ghsa" || cfg.SyncInterval == nil || *cfg.SyncInterval != interval {
		t.Fatalf("feed config = %+v", cfg)
	}
	configs, err := store.ListFeedConfigs(ctx)
	if err != nil {
		t.Fatalf("ListFeedConfigs() error = %v", err)
	}
	if len(configs) != 1 || configs[0].FeedName != "ghsa" {
		t.Fatalf("ListFeedConfigs() = %+v", configs)
	}
	if err := store.DeleteFeedConfig(ctx, "ghsa"); err != nil {
		t.Fatalf("DeleteFeedConfig() error = %v", err)
	}
	if cfg, _ := store.GetFeedConfig(ctx, "ghsa"); cfg != nil {
		t.Fatalf("GetFeedConfig(after delete) = %+v, want nil", cfg)
	}

	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{ScanID: "scan-1", ScannedAt: now, PackagesCount: 4, FindingsCount: 1}); err != nil {
		t.Fatalf("InsertScanLog(1) error = %v", err)
	}
	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{ScanID: "scan-2", ScannedAt: now.Add(time.Minute), PackagesCount: 6, FindingsCount: 2}); err != nil {
		t.Fatalf("InsertScanLog(2) error = %v", err)
	}
	recent, err := store.ListRecentScans(ctx, 1)
	if err != nil {
		t.Fatalf("ListRecentScans() error = %v", err)
	}
	if len(recent) != 1 || recent[0].ScanID != "scan-2" {
		t.Fatalf("ListRecentScans() = %+v, want newest scan", recent)
	}
	totals, err := store.ScanTotals(ctx)
	if err != nil {
		t.Fatalf("ScanTotals() error = %v", err)
	}
	if totals.PackagesScanned != 10 || totals.Findings != 3 {
		t.Fatalf("ScanTotals() = %+v, want cumulative counts", totals)
	}
	daily, err := store.CountScansByDay(ctx, 1)
	if err != nil {
		t.Fatalf("CountScansByDay() error = %v", err)
	}
	if len(daily) != 1 {
		t.Fatalf("CountScansByDay() len = %d, want 1", len(daily))
	}

	expires := time.Now().UTC().Add(time.Hour)
	keyID, err := store.CreateAPIKey(ctx, "ci", "hash", &expires)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	key, err := store.FindAPIKeyByHash(ctx, "hash")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash() error = %v", err)
	}
	if key == nil || key.ID != keyID {
		t.Fatalf("FindAPIKeyByHash() = %+v, want key id %d", key, keyID)
	}
	if err := store.TouchAPIKeyLastUsed(ctx, keyID); err != nil {
		t.Fatalf("TouchAPIKeyLastUsed() error = %v", err)
	}
	keys, err := store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 1 || keys[0].LastUsedAt == nil {
		t.Fatalf("ListAPIKeys() = %+v, want touched key", keys)
	}
}

func TestNoopStoreManualAdvisoryAndNoopMethods(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:vuln",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Summary:     "manual vuln",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(vulnerability) error = %v", err)
	}
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:mal",
		FindingType: "malicious",
		Ecosystem:   "pypi",
		Name:        "evil",
		Severity:    "HIGH",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(malicious) error = %v", err)
	}
	advisories, err := store.ListManualAdvisories(ctx, 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories() error = %v", err)
	}
	if len(advisories) != 2 {
		t.Fatalf("ListManualAdvisories() len = %d, want 2", len(advisories))
	}
	if err := store.DeleteManualAdvisory(ctx, "manual:vuln"); err != nil {
		t.Fatalf("DeleteManualAdvisory() error = %v", err)
	}
	advisories, err = store.ListManualAdvisories(ctx, 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories(after delete) error = %v", err)
	}
	if len(advisories) != 1 || advisories[0].ID != "manual:mal" {
		t.Fatalf("manual advisories after delete = %+v, want only malicious advisory", advisories)
	}

	if reps, err := store.FindReputationFindingsBatch(ctx, nil, "reversinglabs"); err != nil || reps != nil {
		t.Fatalf("FindReputationFindingsBatch() = %+v, %v; want nil nil", reps, err)
	}
	if queued, err := store.MarkPackageReputationDue(ctx, &db.PackageReputation{}); err != nil || queued {
		t.Fatalf("MarkPackageReputationDue() = %v, %v; want false nil", queued, err)
	}
	if due, err := store.ListDuePackageReputations(ctx, "npm", "left-pad", "reversinglabs", 10); err != nil || due != nil {
		t.Fatalf("ListDuePackageReputations() = %+v, %v; want nil nil", due, err)
	}
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{}); err != nil {
		t.Fatalf("UpsertPackageReputation() error = %v", err)
	}
	if updated, err := store.PropagateSeverityViaAliases(ctx); err != nil || updated != 0 {
		t.Fatalf("PropagateSeverityViaAliases() = %d, %v; want 0 nil", updated, err)
	}
	if updated, err := store.SetCISAKEV(ctx, nil); err != nil || updated != 0 {
		t.Fatalf("SetCISAKEV() = %d, %v; want 0 nil", updated, err)
	}
	if cleared, err := store.ClearCISAKEV(ctx, nil); err != nil || cleared != 0 {
		t.Fatalf("ClearCISAKEV() = %d, %v; want 0 nil", cleared, err)
	}
	if updated, err := store.SetEPSSScores(ctx, nil); err != nil || updated != 0 {
		t.Fatalf("SetEPSSScores() = %d, %v; want 0 nil", updated, err)
	}
	if updated, err := store.EnrichVulnCheck(ctx, nil); err != nil || updated != 0 {
		t.Fatalf("EnrichVulnCheck() = %d, %v; want 0 nil", updated, err)
	}
	if aliases, err := store.FindUnknownSeverityCVEAliases(ctx); err != nil || aliases != nil {
		t.Fatalf("FindUnknownSeverityCVEAliases() = %+v, %v; want nil nil", aliases, err)
	}
	if err := store.UpdateSeverityByCVE(ctx, "CVE-2026-0001", "HIGH", 7.5); err != nil {
		t.Fatalf("UpdateSeverityByCVE() error = %v", err)
	}
	if status, err := store.GetPackageCheckStatus(ctx, "npm", "left-pad", "socket"); err != nil || status != nil {
		t.Fatalf("GetPackageCheckStatus() = %+v, %v; want nil nil", status, err)
	}
	if err := store.UpsertPackageCheckStatus(ctx, &db.PackageCheckStatus{}); err != nil {
		t.Fatalf("UpsertPackageCheckStatus() error = %v", err)
	}
	if vulns, err := store.ListRecentVulnerabilities(ctx, 7, 10); err != nil || vulns != nil {
		t.Fatalf("ListRecentVulnerabilities() = %+v, %v; want nil nil", vulns, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := (&noopPinger{}).Ping(ctx); err != nil {
		t.Fatalf("noopPinger.Ping() error = %v", err)
	}
}
