package devstore

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestNoopAdminEdgeContracts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()
	now := time.Now().UTC()
	store.apiKeys = append(store.apiKeys, db.APIKey{ID: 1, Name: "deleted", KeyHash: "gone", DeletedAt: &now})

	if err := store.TouchAPIKeyLastUsed(ctx, 1); err != nil {
		t.Fatalf("TouchAPIKeyLastUsed(deleted) error = %v", err)
	}
	if store.apiKeys[0].LastUsedAt != nil {
		t.Fatalf("TouchAPIKeyLastUsed(deleted) changed last-used timestamp to %v", store.apiKeys[0].LastUsedAt)
	}
	if err := store.RevokeAPIKeyWithAudit(ctx, 1, coverageAudit("revoke")); err == nil {
		t.Fatal("RevokeAPIKeyWithAudit(deleted) error = nil, want not found")
	}
	if err := store.RevokeAPIKey(ctx, 1); err == nil {
		t.Fatal("RevokeAPIKey(deleted) error = nil, want not found")
	}

	badAudit := &db.AdminAuditEntry{Action: "create", Details: json.RawMessage(`{"broken"`)}
	if _, err := store.CreateAPIKeyWithAudit(ctx, "ci", "hash", nil, badAudit); err == nil {
		t.Fatal("CreateAPIKeyWithAudit(invalid audit details) error = nil")
	}
	if len(store.apiKeys) != 1 {
		t.Fatalf("failed audited create mutated keys: %+v", store.apiKeys)
	}

	store.apiKeys = append(store.apiKeys, db.APIKey{ID: 2, RevokedAt: &now})
	if err := store.DeleteAPIKeyWithAudit(ctx, 2, nil); !errors.Is(err, db.ErrAdminAuditLog) {
		t.Fatalf("DeleteAPIKeyWithAudit(nil audit) error = %v, want ErrAdminAuditLog", err)
	}
	if len(store.apiKeys) != 2 {
		t.Fatal("failed audited delete removed the key")
	}

	if err := store.UpsertAdminAuth(ctx, "changed", false); err != nil {
		t.Fatalf("UpsertAdminAuth(non-bootstrap) error = %v", err)
	}
	if err := store.UpsertAdminAuth(ctx, "bootstrap", true); err != nil {
		t.Fatalf("UpsertAdminAuth(bootstrap reset) error = %v", err)
	}
	auth, err := store.GetAdminAuth(ctx)
	if err != nil || auth == nil || !auth.PasswordIsBootstrap || auth.PasswordChangedAt != nil {
		t.Fatalf("GetAdminAuth() = %+v, %v; want bootstrap state with no changed timestamp", auth, err)
	}

	for _, action := range []string{"oldest", "middle", "newest"} {
		if err := store.InsertAdminAuditLog(ctx, coverageAudit(action)); err != nil {
			t.Fatalf("InsertAdminAuditLog(%s) error = %v", action, err)
		}
	}
	page, err := store.ListAdminAuditLogPage(ctx, 1, 1)
	if err != nil || len(page) != 1 || page[0].Action != "middle" {
		t.Fatalf("ListAdminAuditLogPage(1, 1) = %+v, %v; want middle row", page, err)
	}
	page, err = store.ListAdminAuditLogPage(ctx, 99, -1)
	if err != nil || len(page) != 3 || page[0].Action != "newest" {
		t.Fatalf("ListAdminAuditLogPage(99, -1) = %+v, %v; want all newest-first", page, err)
	}
}

// TestNoopFeedRevisionFallbacksAndCopies covers every reachable revision branch.
// The remaining error returns in the four keyed imports and the audited feed and
// system-setting writes are structural: upsertFeedSyncStatusLocked and
// insertAdminAuditLogLocked cannot return an error for inputs supplied by those
// callers, and the development store deliberately has no failure-injection seam.
func TestNoopFeedRevisionFallbacksAndCopies(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()
	if status, err := store.GetFeedSyncStatus(ctx, "missing"); err != nil || status != nil {
		t.Fatalf("GetFeedSyncStatus(missing) = %+v, %v; want nil, nil", status, err)
	}
	for _, name := range []string{"z-feed", "a-feed"} {
		if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{FeedName: name}); err != nil {
			t.Fatalf("UpsertFeedSyncStatus(%s) error = %v", name, err)
		}
	}
	statuses, err := store.ListFeedSyncStatuses(ctx)
	if err != nil || len(statuses) != 2 || statuses[0].FeedName != "a-feed" {
		t.Fatalf("ListFeedSyncStatuses() = %+v, %v; want sorted statuses", statuses, err)
	}

	zero := time.Time{}
	interval := 15 * time.Minute
	if err := store.UpsertFeedConfigWithAudit(ctx, &db.FeedConfig{
		FeedName: " OSV ", SyncInterval: &interval, ExpectedUpdatedAt: &zero,
	}, coverageAudit("feed-create")); err != nil {
		t.Fatalf("UpsertFeedConfigWithAudit(create revision) error = %v", err)
	}
	configs, err := store.ListFeedConfigs(ctx)
	if err != nil || len(configs) != 1 || configs[0].FeedName != "osv" || configs[0].SyncInterval == nil || *configs[0].SyncInterval != interval {
		t.Fatalf("ListFeedConfigs() = %+v, %v; want normalized copied config", configs, err)
	}
	*configs[0].SyncInterval = time.Hour
	stored, err := store.GetFeedConfig(ctx, "OSV")
	if err != nil || stored == nil || *stored.SyncInterval != interval {
		t.Fatalf("GetFeedConfig() = %+v, %v; caller mutation leaked into store", stored, err)
	}
	if err := store.UpsertFeedConfigWithAudit(ctx, &db.FeedConfig{
		FeedName: "osv", ExpectedUpdatedAt: &zero,
	}, coverageAudit("feed-conflict")); !errors.Is(err, db.ErrConflict) {
		t.Fatalf("UpsertFeedConfigWithAudit(zero revision on existing) error = %v, want conflict", err)
	}
	current := stored.UpdatedAt
	if err := store.UpsertFeedConfigWithAudit(ctx, &db.FeedConfig{
		FeedName: "osv", UpdatedAt: current,
	}, coverageAudit("feed-update")); err != nil {
		t.Fatalf("UpsertFeedConfigWithAudit(UpdatedAt fallback) error = %v", err)
	}
	if err := store.UpsertFeedConfigWithAudit(ctx, &db.FeedConfig{
		FeedName: "missing", UpdatedAt: current,
	}, coverageAudit("feed-missing")); !errors.Is(err, db.ErrConflict) {
		t.Fatalf("UpsertFeedConfigWithAudit(missing revision target) error = %v, want conflict", err)
	}
	if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: "alpha"}); err != nil {
		t.Fatalf("UpsertFeedConfig(alpha) error = %v", err)
	}
	configs, err = store.ListFeedConfigs(ctx)
	if err != nil || len(configs) != 2 || configs[0].FeedName != "alpha" || configs[1].FeedName != "osv" {
		t.Fatalf("ListFeedConfigs(sorted) = %+v, %v", configs, err)
	}

	settingsStore := newNoopStore()
	if err := settingsStore.UpsertSystemSettingsWithAudit(ctx, &db.SystemSettings{
		BlockThreshold: "HIGH", ExpectedUpdatedAt: &zero,
	}, coverageAudit("settings-create")); err != nil {
		t.Fatalf("UpsertSystemSettingsWithAudit(create revision) error = %v", err)
	}
	if err := settingsStore.UpsertSystemSettingsWithAudit(ctx, &db.SystemSettings{
		ExpectedUpdatedAt: &zero,
	}, coverageAudit("settings-conflict")); !errors.Is(err, db.ErrConflict) {
		t.Fatalf("UpsertSystemSettingsWithAudit(zero revision on existing) error = %v, want conflict", err)
	}
	settings, err := settingsStore.GetSystemSettings(ctx)
	if err != nil || settings == nil {
		t.Fatalf("GetSystemSettings() = %+v, %v", settings, err)
	}
	if err := settingsStore.UpsertSystemSettingsWithAudit(ctx, &db.SystemSettings{
		BlockThreshold: "LOW", UpdatedAt: settings.UpdatedAt,
	}, coverageAudit("settings-update")); err != nil {
		t.Fatalf("UpsertSystemSettingsWithAudit(UpdatedAt fallback) error = %v", err)
	}
	if _, ok := expectedNoopFeedConfigUpdatedAt(nil); ok {
		t.Fatal("expectedNoopFeedConfigUpdatedAt(nil) reported a revision")
	}
	if _, ok := expectedNoopSystemSettingsUpdatedAt(nil); ok {
		t.Fatal("expectedNoopSystemSettingsUpdatedAt(nil) reported a revision")
	}
}

// TestNoopFindingFallbacksAndSourceScopedDeletes exercises the reachable failure
// path through a source-scoped import. Other uncovered import and batch error
// returns are structural because their in-memory callees are infallible.
func TestNoopFindingFallbacksAndSourceScopedDeletes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()
	if !noopVulnerabilityAffectsVersion("npm", "", `not-json`, `not-json`) {
		t.Fatal("blank vulnerability version should conservatively match")
	}
	if !noopVulnerabilityAffectsVersion("npm", "1.0.0", `not-json`, `not-json`) {
		t.Fatal("invalid vulnerability constraints should conservatively match")
	}
	if !noopMaliciousAffectsVersion("npm", "", `not-json`, `not-json`) {
		t.Fatal("blank malicious version should conservatively match")
	}

	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		Ecosystem: "npm", Name: "@Scope/PKG", Severity: "CRITICAL",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding(defaults) error = %v", err)
	}
	storedDefault := store.malicious["manual:1"]
	findings, err := store.FindMalicious(ctx, "npm", storedDefault.Name, "")
	if err != nil || len(findings) != 1 {
		t.Fatalf("FindMalicious(blank version) = %+v, %v", findings, err)
	}
	if findings[0].AdvisoryID != "manual:1" || findings[0].Source != domain.ManualAdvisorySource || findings[0].Title != "manual advisory for "+storedDefault.Name {
		t.Fatalf("FindMalicious(defaults) = %+v", findings[0])
	}

	vuln := db.Vulnerability{
		ID: "CVE-source", Severity: "HIGH",
		Sources: []db.VulnerabilitySource{{Source: "osv"}, {Source: "ghsa"}},
	}
	if err := store.UpsertVulnerability(ctx, &vuln); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	if err := store.DeleteVulnerabilityForSource(ctx, "missing", "osv"); err != nil {
		t.Fatalf("DeleteVulnerabilityForSource(missing) error = %v", err)
	}
	if err := store.DeleteVulnerabilityForSource(ctx, vuln.ID, "nvd"); err != nil {
		t.Fatalf("DeleteVulnerabilityForSource(source miss) error = %v", err)
	}
	if err := store.DeleteVulnerabilityForSource(ctx, vuln.ID, "osv"); err != nil {
		t.Fatalf("DeleteVulnerabilityForSource(partial) error = %v", err)
	}
	if got := store.vulnerable[vuln.ID].Sources; len(got) != 1 || got[0].Source != "ghsa" {
		t.Fatalf("remaining sources = %+v, want only ghsa", got)
	}
	if err := store.DeleteVulnerabilityForSource(ctx, vuln.ID, "ghsa"); err != nil {
		t.Fatalf("DeleteVulnerabilityForSource(last) error = %v", err)
	}
	if _, ok := store.vulnerable[vuln.ID]; ok {
		t.Fatal("last source deletion retained vulnerability")
	}

	store.malicious["feed-mal"] = db.MaliciousFinding{ID: "feed-mal", Ecosystem: "npm", Name: "bad", Source: "openssf"}
	if err := store.DeleteMaliciousFindingForSource(ctx, "feed-mal", "socket"); err != nil {
		t.Fatalf("DeleteMaliciousFindingForSource(source miss) error = %v", err)
	}
	if err := store.DeleteMaliciousFindingForSource(ctx, "feed-mal", "openssf"); err != nil {
		t.Fatalf("DeleteMaliciousFindingForSource(match) error = %v", err)
	}
	if _, ok := store.malicious["feed-mal"]; ok || !store.maliciousDel["feed-mal"].Withdrawn {
		t.Fatalf("source delete did not create tombstone: active=%v tombstone=%+v", ok, store.maliciousDel["feed-mal"])
	}

	if _, _, err := store.ImportVulnerabilityFeedWithAudit(ctx, "osv", nil, nil, nil, nil); err != nil {
		t.Fatalf("ImportVulnerabilityFeedWithAudit(nil audit) error = %v", err)
	}
	if _, _, err := store.ImportVulnerabilityFeedWithAudit(ctx, "", nil, []string{"CVE-delete"}, nil, nil); !errors.Is(err, db.ErrSourceScopedDeleteSourceRequired) {
		t.Fatalf("ImportVulnerabilityFeedWithAudit(blank delete source) error = %v, want source-required error", err)
	}
	if _, _, err := store.ImportMaliciousFeedWithAudit(ctx, "openssf", nil, nil, nil, nil); err != nil {
		t.Fatalf("ImportMaliciousFeedWithAudit(nil audit) error = %v", err)
	}
}

func TestNoopManualAdvisoryPaginationAndIsolation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()
	if err := store.UpsertManualAdvisoryWithAudit(ctx, nil, coverageAudit("ignored")); err != nil {
		t.Fatalf("UpsertManualAdvisoryWithAudit(nil) error = %v", err)
	}
	for _, advisory := range []db.ManualAdvisory{
		{ID: "manual:2", FindingType: "vulnerability", Ecosystem: "npm", Name: "two", Severity: "HIGH"},
		{ID: "manual:1", FindingType: "malicious", Ecosystem: "npm", Name: "one", Severity: "CRITICAL"},
	} {
		if err := store.UpsertManualAdvisory(ctx, &advisory); err != nil {
			t.Fatalf("UpsertManualAdvisory(%s) error = %v", advisory.ID, err)
		}
	}
	store.malicious["feed-only"] = db.MaliciousFinding{ID: "feed-only", Source: "openssf"}
	store.vulnerable["feed-vuln"] = db.Vulnerability{ID: "feed-vuln", Sources: []db.VulnerabilitySource{{Source: "osv"}}}

	page, err := store.ListManualAdvisoriesPage(ctx, 1, -1)
	if err != nil || len(page) != 1 || page[0].ID != "manual:2" || page[0].FindingType != "vulnerability" {
		t.Fatalf("ListManualAdvisoriesPage(1, -1) = %+v, %v", page, err)
	}
	page, err = store.ListManualAdvisoriesPage(ctx, 10, 1)
	if err != nil || len(page) != 1 || page[0].ID != "manual:1" {
		t.Fatalf("ListManualAdvisoriesPage(10, 1) = %+v, %v", page, err)
	}
	page, err = store.ListManualAdvisoriesPage(ctx, 10, 99)
	if err != nil || page != nil {
		t.Fatalf("ListManualAdvisoriesPage(offset past end) = %+v, %v; want nil", page, err)
	}
	if err := store.DeleteManualAdvisory(ctx, "feed-only"); err == nil {
		t.Fatal("DeleteManualAdvisory(feed-owned finding) error = nil")
	}
	if err := store.DeleteManualAdvisory(ctx, "feed-vuln"); err == nil {
		t.Fatal("DeleteManualAdvisory(feed-owned vulnerability) error = nil")
	}
}

func TestNoopQueueStatusAndRetentionEdges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()
	if err := store.CompleteClaimedRefresh(ctx, 1, nil, nil); err == nil {
		t.Fatal("CompleteClaimedRefresh(nil claim) error = nil")
	}
	claim := time.Now().UTC()
	if err := store.CompleteClaimedRefresh(ctx, 404, &claim, nil); err != nil {
		t.Fatalf("CompleteClaimedRefresh(missing) error = %v", err)
	}

	created, position, err := store.EnqueueRefresh(ctx, &db.RefreshJob{
		Ecosystem: "npm", Name: "terminal", Source: "socket", Status: "DONE",
	})
	if err != nil || !created || position != 0 {
		t.Fatalf("EnqueueRefresh(valid terminal status) = %t, %d, %v", created, position, err)
	}
	created, position, err = store.EnqueueRefresh(ctx, &db.RefreshJob{
		Ecosystem: "npm", Name: "invalid", Source: "socket", Status: "unexpected",
	})
	if err != nil || !created || position != 1 {
		t.Fatalf("EnqueueRefresh(invalid status) = %t, %d, %v; want pending position 1", created, position, err)
	}
	duplicateCreated, duplicatePosition, err := store.EnqueueRefresh(ctx, &db.RefreshJob{
		Ecosystem: "npm", Name: "invalid", Source: "socket", Priority: 99,
	})
	if err != nil || duplicateCreated || duplicatePosition != 1 {
		t.Fatalf("EnqueueRefresh(duplicate without priority improvement) = %t, %d, %v; want existing position 1", duplicateCreated, duplicatePosition, err)
	}
	if len(store.refreshJobs) != 2 {
		t.Fatalf("duplicate enqueue left %d jobs, want the original two", len(store.refreshJobs))
	}
	if got := store.refreshJobs[1]; got.Name != "invalid" || got.Priority != 0 || got.Status != db.RefreshStatusPending {
		t.Fatalf("duplicate enqueue changed existing job to %+v, want unchanged priority 0 pending job", got)
	}

	old := time.Now().UTC().Add(-48 * time.Hour)
	fresh := time.Now().UTC()
	for _, status := range []db.PackageCheckStatus{
		{Ecosystem: "npm", Name: "old-next", Source: "socket", NextCheckAt: &old},
		{Ecosystem: "npm", Name: "fresh-next", Source: "socket", NextCheckAt: &fresh},
		{Ecosystem: "npm", Name: "other-source", Source: "other", NextCheckAt: &old},
		{Ecosystem: "npm", Name: "zero-time", Source: "socket"},
	} {
		status := status
		if err := store.UpsertPackageCheckStatus(ctx, &status); err != nil {
			t.Fatalf("UpsertPackageCheckStatus(%s) error = %v", status.Name, err)
		}
	}
	pruned, err := store.PrunePackageCheckStatus(ctx, 24*time.Hour)
	if err != nil || pruned != 2 {
		t.Fatalf("PrunePackageCheckStatus() = %d, %v; want old-next and zero-time pruned", pruned, err)
	}
	if got, _ := store.GetPackageCheckStatus(ctx, "npm", "fresh-next", "socket"); got == nil {
		t.Fatal("PrunePackageCheckStatus removed fresh NextCheckAt row")
	}
	if got, _ := store.GetPackageCheckStatus(ctx, "npm", "other-source", "other"); got == nil {
		t.Fatal("PrunePackageCheckStatus removed non-socket row")
	}

	store.mu.Lock()
	store.refreshJobs = append(store.refreshJobs,
		db.RefreshJob{ID: 20, Name: "newest-paused", Status: db.RefreshStatusPaused, Source: "socket", RequestedAt: old},
		db.RefreshJob{ID: 21, Name: "newest-pending", Status: db.RefreshStatusPending, Source: "", RequestedAt: old},
	)
	store.mu.Unlock()
	stats, err := store.QueueStats(ctx)
	if err != nil || stats.Paused != 1 {
		t.Fatalf("QueueStats() = %+v, %v; want one paused job", stats, err)
	}
	oldest, err := store.OldestQueueJobs(ctx)
	if err != nil {
		t.Fatalf("OldestQueueJobs() error = %v", err)
	}
	if _, ok := oldest[""]; ok {
		t.Fatalf("OldestQueueJobs() retained empty source: %+v", oldest)
	}
	jobs, err := store.ListQueueJobsPage(ctx, "not-a-status", 2, -1)
	if err != nil || len(jobs) != 2 ||
		jobs[0].ID != 21 || jobs[0].Name != "newest-pending" || jobs[0].Status != db.RefreshStatusPending ||
		jobs[1].ID != 20 || jobs[1].Name != "newest-paused" || jobs[1].Status != db.RefreshStatusPaused {
		t.Fatalf("ListQueueJobsPage(invalid, negative offset) = %+v, %v", jobs, err)
	}
	jobs, err = store.ListQueueJobsPage(ctx, "", 10, 99)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("ListQueueJobsPage(offset past end) = %+v, %v", jobs, err)
	}
	if got, err := store.ClearQueueWithAudit(ctx, []string{"bogus"}, nil); err != nil || got != 0 {
		t.Fatalf("ClearQueueWithAudit(bogus, nil audit) = %d, %v", got, err)
	}
	if got := store.queuePositionLocked(404); got != 0 {
		t.Fatalf("queuePositionLocked(missing) = %d, want 0", got)
	}
}

func TestNoopQueueOrderingAndRequestedAtPruning(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	if !noopRefreshJobBefore(db.RefreshJob{Priority: 1}, db.RefreshJob{Priority: 2}) {
		t.Fatal("lower numeric priority should sort first")
	}
	if !noopRefreshJobBefore(
		db.RefreshJob{Priority: 1, RequestedAt: now.Add(-time.Second)},
		db.RefreshJob{Priority: 1, RequestedAt: now},
	) {
		t.Fatal("older equal-priority request should sort first")
	}
	if !noopRefreshJobBefore(
		db.RefreshJob{ID: 1, Priority: 1, RequestedAt: now},
		db.RefreshJob{ID: 2, Priority: 1, RequestedAt: now},
	) {
		t.Fatal("lower ID should break an exact queue-order tie")
	}
	if noopRefreshJobBefore(
		db.RefreshJob{ID: 2, Priority: 1, RequestedAt: now},
		db.RefreshJob{ID: 1, Priority: 1, RequestedAt: now},
	) {
		t.Fatal("higher ID sorted before lower ID")
	}

	store := newNoopStore()
	old := now.Add(-48 * time.Hour)
	store.refreshJobs = append(store.refreshJobs, db.RefreshJob{
		ID: 1, Status: db.RefreshStatusDone, RequestedAt: old,
	})
	pruned, err := store.PruneRefreshQueue(context.Background(), 24*time.Hour)
	if err != nil || pruned != 1 {
		t.Fatalf("PruneRefreshQueue(RequestedAt fallback) = %d, %v; want 1", pruned, err)
	}
}

func TestNoopScanLogPaginationAndSearchEdges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()
	for _, entry := range []db.ScanLogEntry{
		{ScanID: "one", IdempotencyKey: "same", ScannedAt: time.Now().UTC()},
		{ScanID: "duplicate", IdempotencyKey: "same", ScannedAt: time.Now().UTC()},
		{ScanID: "two", ScannedAt: time.Now().UTC()},
	} {
		entry := entry
		if err := store.InsertScanLog(ctx, &entry); err != nil {
			t.Fatalf("InsertScanLog(%s) error = %v", entry.ScanID, err)
		}
	}
	if len(store.scanLogs) != 2 {
		t.Fatalf("idempotent insert stored %d rows, want 2", len(store.scanLogs))
	}
	if got, err := store.GetScanLogByIdempotencyKey(ctx, "missing"); err != nil || got != nil {
		t.Fatalf("GetScanLogByIdempotencyKey(missing) = %+v, %v", got, err)
	}
	recent, err := store.ListRecentScans(ctx, 1, -1)
	if err != nil || len(recent) != 1 || recent[0].ScanID != "two" {
		t.Fatalf("ListRecentScans(1, -1) = %+v, %v", recent, err)
	}
	recent, err = store.ListRecentScans(ctx, 1, 1)
	if err != nil || len(recent) != 1 || recent[0].ScanID != "one" {
		t.Fatalf("ListRecentScans(1, 1) = %+v, %v", recent, err)
	}
	recent, err = store.ListRecentScans(ctx, 1, 99)
	if err != nil || len(recent) != 0 {
		t.Fatalf("ListRecentScans(offset past end) = %+v, %v", recent, err)
	}

	withdrawn := time.Now().UTC()
	store.vulnerable = map[string]db.Vulnerability{
		"ACTIVE": {
			ID: "ACTIVE", Severity: "", Sources: nil,
			AffectedPackages: []db.AffectedPackage{
				{Ecosystem: "npm", Name: "pkg"},
				{Ecosystem: "npm", Name: "pkg"},
			},
		},
		"WITHDRAWN": {
			ID: "WITHDRAWN", Severity: "CRITICAL", Withdrawn: &withdrawn,
			AffectedPackages: []db.AffectedPackage{{Ecosystem: "npm", Name: "pkg"}},
		},
		"OTHER": {
			ID: "OTHER", Severity: "HIGH", Sources: []db.VulnerabilitySource{{Source: "  "}},
			AffectedPackages: []db.AffectedPackage{{Ecosystem: "pypi", Name: "other-vuln"}},
		},
	}
	store.malicious = map[string]db.MaliciousFinding{
		"M1": {ID: "M1", Ecosystem: "npm", Name: "pkg", Severity: "LOW", Source: "  "},
		"M2": {ID: "M2", Ecosystem: "pypi", Name: "other-mal", Severity: "HIGH", Source: "openssf"},
	}
	results, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "pkg", FindingType: "vulnerability"})
	if err != nil || len(results) != 1 || results[0].FindingsCount != 1 || results[0].Sources != "unknown" {
		t.Fatalf("SearchPackages(active duplicate package) = %+v, %v", results, err)
	}
	results, err = store.SearchPackages(ctx, db.PackageSearchParams{Query: "pkg", Severity: "HIGH"})
	if err != nil || len(results) != 0 {
		t.Fatalf("SearchPackages(severity mismatch) = %+v, %v", results, err)
	}
	results, err = store.SearchPackages(ctx, db.PackageSearchParams{Query: "other", Limit: 1, Offset: 1})
	if err != nil || len(results) != 1 || results[0].Ecosystem != "pypi" || results[0].Name != "other-vuln" || results[0].VulnerabilityCount != 1 {
		t.Fatalf("SearchPackages(limit/offset) = %+v, %v", results, err)
	}
	results, err = store.SearchPackages(ctx, db.PackageSearchParams{Query: "absent"})
	if err != nil || len(results) != 0 {
		t.Fatalf("SearchPackages(query miss) = %+v, %v", results, err)
	}
	stats, err := store.DashboardStats(ctx)
	if err != nil || stats.TotalVulnerabilities != 2 || stats.TotalMalicious != 2 || stats.BySeverity["UNKNOWN"] != 1 {
		t.Fatalf("DashboardStats() = %+v, %v", stats, err)
	}
}

func TestNoopSyncSparseTombstonesRespectEcosystemFilter(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()
	for _, finding := range []db.MaliciousFinding{
		{ID: "npm-sparse", Ecosystem: "npm", Name: "sparse", Source: "openssf"},
		{ID: "gem-full", Ecosystem: "gem", Name: "full", Source: "openssf", Versions: json.RawMessage(`["1"]`), VersionRanges: json.RawMessage(`[{"type":"ECOSYSTEM"}]`), ReferenceURLs: json.RawMessage(`["https://example.test"]`)},
	} {
		finding := finding
		if err := store.UpsertMaliciousFinding(ctx, &finding); err != nil {
			t.Fatalf("UpsertMaliciousFinding(%s) error = %v", finding.ID, err)
		}
		if err := store.DeleteMaliciousFinding(ctx, finding.ID); err != nil {
			t.Fatalf("DeleteMaliciousFinding(%s) error = %v", finding.ID, err)
		}
	}
	since := time.Now().UTC().Add(-time.Minute)
	exported, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &since, Ecosystems: []string{"npm"}})
	if err != nil {
		t.Fatalf("ExportSync() error = %v", err)
	}
	if len(exported.Malicious) != 1 {
		t.Fatalf("ExportSync(npm tombstones) = %+v, want one row", exported.Malicious)
	}
	row := exported.Malicious[0]
	if row.ID != "npm-sparse" || !row.Withdrawn || row.Versions != "" || row.VersionRanges != "" || row.ReferenceURLs != "" {
		t.Fatalf("ExportSync(npm sparse tombstone) = %+v", row)
	}
	full := store.maliciousDel["gem-full"]
	if full.Versions == "" || full.VersionRanges == "" || full.ReferenceURLs == "" {
		t.Fatalf("full tombstone lost metadata: %+v", full)
	}
}
