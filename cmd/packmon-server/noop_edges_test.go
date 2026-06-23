package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestNoopStoreEdgeBranches(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if err := store.UpsertVulnerability(ctx, nil); err != nil {
		t.Fatalf("UpsertVulnerability(nil) error = %v", err)
	}
	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{ID: "   "}); err != nil {
		t.Fatalf("UpsertVulnerability(blank) error = %v", err)
	}
	if err := store.UpsertManualAdvisory(ctx, nil); err != nil {
		t.Fatalf("UpsertManualAdvisory(nil) error = %v", err)
	}

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:default-mal",
		FindingType: "malicious",
		Ecosystem:   "npm",
		Name:        "evil",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(default malicious) error = %v", err)
	}
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:default-vuln",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "vuln",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(default vulnerability) error = %v", err)
	}
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		FindingType: "malicious",
		Ecosystem:   "npm",
		Name:        "generated-mal",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(generated malicious) error = %v", err)
	}
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "generated-vuln",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(generated vulnerability) error = %v", err)
	}
	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:       "manual:empty-title",
		Severity: "LOW",
		Sources: []db.VulnerabilitySource{{
			Source:  "manual",
			RawJSON: json.RawMessage(`{"manual":true}`),
		}},
		AffectedPackages: []db.AffectedPackage{
			{Ecosystem: "npm", Name: "other", VersionRanges: json.RawMessage(`[]`), VersionsAffected: json.RawMessage(`[]`)},
			{Ecosystem: "npm", Name: "title-fallback", VersionRanges: json.RawMessage(`[]`), VersionsAffected: json.RawMessage(`[]`)},
		},
	}); err != nil {
		t.Fatalf("UpsertVulnerability(title fallback) error = %v", err)
	}
	vulnFindings, err := store.FindVulnerabilities(ctx, "npm", "title-fallback", "")
	if err != nil {
		t.Fatalf("FindVulnerabilities(title fallback) error = %v", err)
	}
	if len(vulnFindings) != 1 || vulnFindings[0].Title != "manual:empty-title" {
		t.Fatalf("FindVulnerabilities(title fallback) = %+v", vulnFindings)
	}

	manual, err := store.ListManualAdvisories(ctx, 1)
	if err != nil {
		t.Fatalf("ListManualAdvisories(limit) error = %v", err)
	}
	if len(manual) != 1 {
		t.Fatalf("ListManualAdvisories(limit) len = %d, want 1", len(manual))
	}

	malicious, err := store.ListMaliciousFindings(ctx, "manual", 1)
	if err != nil {
		t.Fatalf("ListMaliciousFindings() error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].Severity != "CRITICAL" || malicious[0].RiskType != "other" {
		t.Fatalf("ListMaliciousFindings() = %+v, want defaulted manual finding", malicious)
	}
	none, err := store.ListMaliciousFindings(ctx, "openssf", 10)
	if err != nil {
		t.Fatalf("ListMaliciousFindings(source miss) error = %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("ListMaliciousFindings(source miss) len = %d, want 0", len(none))
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "openssf-versions",
		Ecosystem: "npm",
		Name:      "versioned",
		Versions:  json.RawMessage(`["1.0.0"]`),
		Severity:  "HIGH",
		Source:    "openssf",
		RiskType:  "malware",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding(versioned) error = %v", err)
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "openssf-pypi",
		Ecosystem: "pypi",
		Name:      "aaa",
		Severity:  "LOW",
		Source:    "openssf",
		RiskType:  "malware",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding(pypi) error = %v", err)
	}
	limited, err := store.ListMaliciousFindings(ctx, "", 1)
	if err != nil {
		t.Fatalf("ListMaliciousFindings(limit) error = %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("ListMaliciousFindings(limit) len = %d, want 1", len(limited))
	}

	exported, err := store.ExportSync(ctx, db.SyncExportOptions{
		SnapshotAt: time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
		Ecosystems: []string{"npm"},
	})
	if err != nil {
		t.Fatalf("ExportSync() error = %v", err)
	}
	foundEvil := false
	for _, item := range exported.Malicious {
		if item.Name == "evil" {
			foundEvil = true
		}
	}
	if exported.SyncedAt.IsZero() || !foundEvil {
		t.Fatalf("ExportSync() = %+v, want npm malicious export containing evil", exported)
	}
	exportedAll, err := store.ExportSync(ctx, db.SyncExportOptions{})
	if err != nil {
		t.Fatalf("ExportSync(all) error = %v", err)
	}
	if len(exportedAll.Malicious) < 2 {
		t.Fatalf("ExportSync(all) malicious len = %d, want sorted rows", len(exportedAll.Malicious))
	}
	filtered, err := store.ExportSync(ctx, db.SyncExportOptions{Ecosystems: []string{"gem"}})
	if err != nil {
		t.Fatalf("ExportSync(filtered) error = %v", err)
	}
	if len(filtered.Malicious) != 0 {
		t.Fatalf("ExportSync(filtered) malicious len = %d, want 0", len(filtered.Malicious))
	}
	since := time.Date(2026, 5, 30, 11, 0, 0, 0, time.UTC)
	if err := store.DeleteMaliciousFinding(ctx, "manual:default-mal"); err != nil {
		t.Fatalf("DeleteMaliciousFinding() error = %v", err)
	}
	deletedExport, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &since})
	if err != nil {
		t.Fatalf("ExportSync(after delete) error = %v", err)
	}
	foundDeleted := false
	for _, item := range deletedExport.Malicious {
		if item.ID == "manual:default-mal" {
			if !item.Withdrawn {
				t.Fatalf("deleted malicious sync row = %+v, want withdrawn", item)
			}
			foundDeleted = true
		}
	}
	if !foundDeleted {
		t.Fatalf("ExportSync(after delete) missing manual:default-mal tombstone: %+v", deletedExport.Malicious)
	}

	if err := store.UpsertFeedSyncStatus(ctx, nil); err != nil {
		t.Fatalf("UpsertFeedSyncStatus(nil) error = %v", err)
	}
	if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{FeedName: "  "}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus(blank) error = %v", err)
	}
	if err := store.UpsertFeedConfig(ctx, nil); err != nil {
		t.Fatalf("UpsertFeedConfig(nil) error = %v", err)
	}
	if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: "  "}); err != nil {
		t.Fatalf("UpsertFeedConfig(blank) error = %v", err)
	}

	if settings, err := store.GetSystemSettings(ctx); err != nil || settings != nil {
		t.Fatalf("GetSystemSettings(empty) = %+v, %v; want nil nil", settings, err)
	}
	if err := store.UpsertSystemSettings(ctx, nil); err != nil {
		t.Fatalf("UpsertSystemSettings(nil) error = %v", err)
	}
	if err := store.UpsertSystemSettings(ctx, &db.SystemSettings{BlockThreshold: "LOW"}); err != nil {
		t.Fatalf("UpsertSystemSettings() error = %v", err)
	}
	settings, err := store.GetSystemSettings(ctx)
	if err != nil {
		t.Fatalf("GetSystemSettings() error = %v", err)
	}
	if settings == nil || settings.BlockThreshold != "LOW" || settings.UpdatedAt.IsZero() {
		t.Fatalf("GetSystemSettings() = %+v, want copied settings", settings)
	}
}

func TestNoopStoreQueueEdgeBranches(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	created, pos, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "pkg", Source: "socket", Priority: 5})
	if err != nil {
		t.Fatalf("EnqueueRefresh() error = %v", err)
	}
	if !created || pos != 1 {
		t.Fatalf("EnqueueRefresh() = %v,%d, want created position 1", created, pos)
	}
	created, pos, err = store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "pkg", Source: "socket", Priority: 1})
	if err != nil {
		t.Fatalf("EnqueueRefresh(duplicate) error = %v", err)
	}
	if created || pos != 1 {
		t.Fatalf("EnqueueRefresh(duplicate) = %v,%d, want existing position 1", created, pos)
	}

	if err := store.ResumeQueueJob(ctx, 1); err == nil {
		t.Fatal("ResumeQueueJob(pending) error = nil, want not paused")
	}
	if err := store.PauseQueueJob(ctx, 1); err != nil {
		t.Fatalf("PauseQueueJob() error = %v", err)
	}
	created, pos, err = store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "pkg", Source: "socket", Priority: 0})
	if err != nil {
		t.Fatalf("EnqueueRefresh(paused duplicate) error = %v", err)
	}
	if created || pos != 0 {
		t.Fatalf("EnqueueRefresh(paused duplicate) = %v,%d, want existing paused job outside active queue", created, pos)
	}
	if err := store.ResumeQueueJob(ctx, 1); err != nil {
		t.Fatalf("ResumeQueueJob(paused after duplicate) error = %v", err)
	}

	job, err := store.DequeueRefresh(ctx, "socket")
	if err != nil {
		t.Fatalf("DequeueRefresh() error = %v", err)
	}
	if job == nil || job.ID != 1 {
		t.Fatalf("DequeueRefresh() = %+v, want job 1", job)
	}
	stats, err := store.QueueStats(ctx)
	if err != nil {
		t.Fatalf("QueueStats(processing) error = %v", err)
	}
	if stats.Processing != 1 {
		t.Fatalf("QueueStats(processing) = %+v, want one processing job", stats)
	}
	if reset, err := store.ResetStuckJobs(ctx, "socket", time.Hour); err != nil || reset != 0 {
		t.Fatalf("ResetStuckJobs(not stuck) = %d, %v; want 0 nil", reset, err)
	}
	if err := store.PauseQueueJob(ctx, job.ID); err == nil {
		t.Fatal("PauseQueueJob(processing) error = nil, want not pending")
	}
	if err := store.RetryQueueJob(ctx, job.ID); err == nil {
		t.Fatal("RetryQueueJob(processing) error = nil, want not retryable")
	}
	if reset, err := store.ResetStuckJobs(ctx, "other", time.Nanosecond); err != nil || reset != 0 {
		t.Fatalf("ResetStuckJobs(other) = %d, %v; want 0 nil", reset, err)
	}
	if err := store.CompleteRefresh(ctx, job.ID, nil); err != nil {
		t.Fatalf("CompleteRefresh(success) error = %v", err)
	}
	stats, err = store.QueueStats(ctx)
	if err != nil {
		t.Fatalf("QueueStats(done) error = %v", err)
	}
	if stats.Done != 1 {
		t.Fatalf("QueueStats(done) = %+v, want one done job", stats)
	}
	if err := store.CompleteRefresh(ctx, 404, errors.New("missing")); err != nil {
		t.Fatalf("CompleteRefresh(missing) error = %v", err)
	}

	if err := store.UpdateQueueJobPriority(ctx, 404, 1); err == nil {
		t.Fatal("UpdateQueueJobPriority(missing) error = nil, want not found")
	}
	if err := store.RetryQueueJob(ctx, 404); err == nil {
		t.Fatal("RetryQueueJob(missing) error = nil, want not found")
	}
	if err := store.PauseQueueJob(ctx, 404); err == nil {
		t.Fatal("PauseQueueJob(missing) error = nil, want not found")
	}
	if err := store.ResumeQueueJob(ctx, 404); err == nil {
		t.Fatal("ResumeQueueJob(missing) error = nil, want not found")
	}

	jobs, err := store.ListQueueJobs(ctx, "done", 1)
	if err != nil {
		t.Fatalf("ListQueueJobs(done) error = %v", err)
	}
	if len(jobs) != 1 || jobs[0].Status != "done" {
		t.Fatalf("ListQueueJobs(done) = %+v, want done job", jobs)
	}
	if cleared, err := store.ClearQueue(ctx, []string{"bogus"}); err != nil || cleared != 0 {
		t.Fatalf("ClearQueue(bogus) = %d, %v; want 0 nil", cleared, err)
	}
	if created, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "other", Source: "other", Priority: 1}); err != nil || !created {
		t.Fatalf("EnqueueRefresh(other) = %v, %v; want created nil", created, err)
	}
	if job, err := store.DequeueRefresh(ctx, "socket"); err != nil || job != nil {
		t.Fatalf("DequeueRefresh(source miss) = %+v, %v; want nil nil", job, err)
	}
}

func TestNoopStoreAuthAndSearchEdgeBranches(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if auth, err := store.GetAdminAuth(ctx); err != nil || auth != nil {
		t.Fatalf("GetAdminAuth(empty) = %+v, %v; want nil nil", auth, err)
	}
	if err := store.UpsertAdminAuth(ctx, "hash-one", false); err != nil {
		t.Fatalf("UpsertAdminAuth(first) error = %v", err)
	}
	if err := store.UpsertAdminAuth(ctx, "hash-two", false); err != nil {
		t.Fatalf("UpsertAdminAuth(update) error = %v", err)
	}
	if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
		Action:  "login_success",
		Details: json.RawMessage(`{"ok":true}`),
		IP:      "127.0.0.1",
	}); err != nil {
		t.Fatalf("InsertAdminAuditLog() error = %v", err)
	}
	auth, err := store.GetAdminAuth(ctx)
	if err != nil {
		t.Fatalf("GetAdminAuth() error = %v", err)
	}
	if auth == nil || auth.PasswordHash != "hash-two" || auth.PasswordChangedAt == nil || auth.LastLoginAt == nil {
		t.Fatalf("GetAdminAuth() = %+v, want updated admin auth", auth)
	}
	audit, err := store.ListAdminAuditLog(ctx, 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || string(audit[0].Details) != `{"ok":true}` {
		t.Fatalf("ListAdminAuditLog() = %+v, want copied audit entry", audit)
	}
	if audit[0].IntegrityStatus != "verified" || !strings.HasPrefix(audit[0].RowDigest, "sha256:") {
		t.Fatalf("audit integrity = status %q digest %q, want verified sha256 digest", audit[0].IntegrityStatus, audit[0].RowDigest)
	}
	if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
		Action:  "feed_save",
		Details: json.RawMessage(`{"feed":"osv"}`),
		IP:      "127.0.0.1",
	}); err != nil {
		t.Fatalf("InsertAdminAuditLog(second) error = %v", err)
	}
	audit, err = store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog(chain) error = %v", err)
	}
	if len(audit) < 2 || audit[0].PreviousDigest != audit[1].RowDigest {
		t.Fatalf("audit digest chain = %+v, want newest previous digest to match older row digest", audit)
	}
	store.mu.Lock()
	store.auditLog[0].CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	store.auditLog[1].CreatedAt = time.Now().UTC().Add(-30 * time.Minute)
	store.mu.Unlock()
	prunedAudit, err := store.PruneAdminAuditLogs(ctx, time.Hour)
	if err != nil {
		t.Fatalf("PruneAdminAuditLogs() error = %v", err)
	}
	if prunedAudit != 1 {
		t.Fatalf("PruneAdminAuditLogs() = %d, want oldest audit row pruned", prunedAudit)
	}
	audit, err = store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog(after prune) error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "feed_save" {
		t.Fatalf("ListAdminAuditLog(after prune) = %+v, want only recent audit row", audit)
	}

	expired := time.Now().UTC().Add(-time.Hour)
	if _, err := store.CreateAPIKey(ctx, "expired", "expired-hash", &expired); err != nil {
		t.Fatalf("CreateAPIKey(expired) error = %v", err)
	}
	if key, err := store.FindAPIKeyByHash(ctx, "expired-hash"); err != nil || key != nil {
		t.Fatalf("FindAPIKeyByHash(expired) = %+v, %v; want nil nil", key, err)
	}
	if err := store.TouchAPIKeyLastUsed(ctx, 404); err != nil {
		t.Fatalf("TouchAPIKeyLastUsed(missing) error = %v", err)
	}
	if err := store.RevokeAPIKey(ctx, 404); err == nil {
		t.Fatal("RevokeAPIKey(missing) error = nil, want not found")
	}
	if err := store.DeleteAPIKey(ctx, 404); err == nil {
		t.Fatal("DeleteAPIKey(missing) error = nil, want not found")
	}

	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "M-1",
		Ecosystem: "npm",
		Name:      "alpha",
		Versions:  json.RawMessage(`not-json`),
		Severity:  "LOW",
		Source:    "openssf",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding(alpha) error = %v", err)
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "M-2",
		Ecosystem: "npm",
		Name:      "alpha",
		Severity:  "LOW",
		Source:    "manual",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding(alpha duplicate package) error = %v", err)
	}

	findings, err := store.FindMalicious(ctx, "npm", "alpha", "1.0.0")
	if err != nil {
		t.Fatalf("FindMalicious(invalid versions) error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("FindMalicious(invalid versions) len = %d, want 2", len(findings))
	}

	results, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "alp", Severity: "LOW", Limit: 1})
	if err != nil {
		t.Fatalf("SearchPackages(limit) error = %v", err)
	}
	if len(results) != 1 || results[0].FindingsCount != 2 {
		t.Fatalf("SearchPackages(limit) = %+v, want combined alpha result", results)
	}
	results, err = store.SearchPackages(ctx, db.PackageSearchParams{FindingType: "vulnerability", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages(vulnerability) error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("SearchPackages(vulnerability) len = %d, want 0", len(results))
	}
	results, err = store.SearchPackages(ctx, db.PackageSearchParams{})
	if err != nil {
		t.Fatalf("SearchPackages(empty) error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("SearchPackages(empty) len = %d, want 0", len(results))
	}
	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{ScanID: "s1", ScannedAt: time.Now().UTC(), PackagesCount: 1}); err != nil {
		t.Fatalf("InsertScanLog() error = %v", err)
	}
	recent, err := store.ListRecentScans(ctx, 0)
	if err != nil {
		t.Fatalf("ListRecentScans(default limit) error = %v", err)
	}
	if len(recent) != 1 {
		t.Fatalf("ListRecentScans(default limit) len = %d, want 1", len(recent))
	}
	byDay, err := store.CountScansByDay(ctx, 0)
	if err != nil {
		t.Fatalf("CountScansByDay(default days) error = %v", err)
	}
	if len(byDay) != 7 {
		t.Fatalf("CountScansByDay(default days) len = %d, want 7", len(byDay))
	}
}
