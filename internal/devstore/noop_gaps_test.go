package devstore

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func coverageAudit(action string) *db.AdminAuditEntry {
	return &db.AdminAuditEntry{
		Action:  action,
		Details: json.RawMessage(`{"source":"devstore-gaps-test"}`),
		IP:      "127.0.0.1",
	}
}

func TestNoopStoreDBPoolStatsReturnsZeroValue(t *testing.T) {
	t.Parallel()

	stats := newNoopStore().DBPoolStats()
	if stats.MaxConns != 0 || stats.AcquiredConns != 0 || stats.AcquireCount != 0 {
		t.Fatalf("DBPoolStats() = %+v, want zero-value stats for the in-memory store", stats)
	}
}

func TestNoopStoreCreateAPIKeyWithAuditRecordsKeyAndAudit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	expiresAt := time.Now().UTC().Add(time.Hour)
	keyID, err := store.CreateAPIKeyWithAudit(ctx, "ci", "hash-ci", &expiresAt, coverageAudit("api_key_create"))
	if err != nil {
		t.Fatalf("CreateAPIKeyWithAudit() error = %v", err)
	}
	keys := mustNoopAPIKeys(t, store)
	if len(keys) != 1 || keys[0].ID != keyID || keys[0].Name != "ci" {
		t.Fatalf("ListAPIKeys() after audited create = %+v, want created key %d", keys, keyID)
	}
	if audit := mustNoopAuditLog(t, store, 10); len(audit) != 1 || audit[0].Action != "api_key_create" {
		t.Fatalf("ListAdminAuditLog() after audited create = %+v, want create audit row", audit)
	}
}

func TestNoopStoreAdminAuthWithAuditFlows(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	if err := store.UpsertAdminAuthWithAudit(ctx, "hash-initial", true, coverageAudit("admin_bootstrap")); err != nil {
		t.Fatalf("UpsertAdminAuthWithAudit() error = %v", err)
	}
	auth, err := store.GetAdminAuth(ctx)
	if err != nil || auth == nil || auth.PasswordHash != "hash-initial" || !auth.PasswordIsBootstrap {
		t.Fatalf("GetAdminAuth() = %+v, %v; want bootstrap auth persisted", auth, err)
	}

	if err := store.ChangeAdminPasswordWithAudit(ctx, "hash-new", "hash-wrong", coverageAudit("admin_password_change")); err == nil {
		t.Fatal("ChangeAdminPasswordWithAudit(wrong old hash) error = nil, want conflict")
	}
	if err := store.ChangeAdminPasswordWithAudit(ctx, "hash-new", "hash-initial", coverageAudit("admin_password_change")); err != nil {
		t.Fatalf("ChangeAdminPasswordWithAudit() error = %v", err)
	}
	auth, err = store.GetAdminAuth(ctx)
	if err != nil || auth == nil || auth.PasswordHash != "hash-new" || auth.PasswordIsBootstrap {
		t.Fatalf("GetAdminAuth() after change = %+v, %v; want rotated non-bootstrap auth", auth, err)
	}
}

func TestNoopStoreManualAdvisoryLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	if missing, err := store.GetManualAdvisory(ctx, "manual:missing"); err != nil || missing != nil {
		t.Fatalf("GetManualAdvisory(missing) = %+v, %v; want nil, nil", missing, err)
	}
	if err := store.DeleteManualAdvisoryWithAudit(ctx, "manual:missing", coverageAudit("manual_advisory_delete")); err == nil {
		t.Fatal("DeleteManualAdvisoryWithAudit(missing) error = nil, want not found")
	}

	if err := store.UpsertManualAdvisoryWithAudit(ctx, &db.ManualAdvisory{
		ID:          "manual:coverage-malicious",
		FindingType: "malicious",
		Ecosystem:   "npm",
		Name:        "evil-package",
		Severity:    "CRITICAL",
		RiskType:    "malware",
		Summary:     "coverage manual advisory",
	}, coverageAudit("manual_advisory_upsert")); err != nil {
		t.Fatalf("UpsertManualAdvisoryWithAudit() error = %v", err)
	}

	advisory, err := store.GetManualAdvisory(ctx, "manual:coverage-malicious")
	if err != nil || advisory == nil {
		t.Fatalf("GetManualAdvisory() = %+v, %v; want stored advisory", advisory, err)
	}
	if advisory.FindingType != "malicious" || advisory.Name != "evil-package" {
		t.Fatalf("GetManualAdvisory() = %+v, want stored malicious advisory fields", advisory)
	}

	listed, err := store.ListManualAdvisories(ctx, 10)
	if err != nil || len(listed) != 1 {
		t.Fatalf("ListManualAdvisories() = %+v, %v; want the stored advisory", listed, err)
	}

	if err := store.DeleteManualAdvisoryWithAudit(ctx, "manual:coverage-malicious", coverageAudit("manual_advisory_delete")); err != nil {
		t.Fatalf("DeleteManualAdvisoryWithAudit() error = %v", err)
	}
	if advisory, err := store.GetManualAdvisory(ctx, "manual:coverage-malicious"); err != nil || advisory != nil {
		t.Fatalf("GetManualAdvisory(after delete) = %+v, %v; want nil, nil", advisory, err)
	}
}

func TestNoopStoreFeedConfigWithAuditRevisionChecks(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	if err := store.UpsertFeedConfigWithAudit(ctx, &db.FeedConfig{FeedName: "osv"}, coverageAudit("feed_config_create")); err != nil {
		t.Fatalf("UpsertFeedConfigWithAudit(create) error = %v", err)
	}
	configs, err := store.ListFeedConfigs(ctx)
	if err != nil || len(configs) != 1 || configs[0].FeedName != "osv" {
		t.Fatalf("ListFeedConfigs() = %+v, %v; want stored osv config", configs, err)
	}

	stale := configs[0].UpdatedAt.Add(-time.Hour)
	if err := store.UpsertFeedConfigWithAudit(ctx, &db.FeedConfig{
		FeedName:          "osv",
		ExpectedUpdatedAt: &stale,
	}, coverageAudit("feed_config_conflict")); err == nil {
		t.Fatal("UpsertFeedConfigWithAudit(stale revision) error = nil, want conflict")
	}

	current := configs[0].UpdatedAt
	if err := store.UpsertFeedConfigWithAudit(ctx, &db.FeedConfig{
		FeedName:          "osv",
		ExpectedUpdatedAt: &current,
	}, coverageAudit("feed_config_update")); err != nil {
		t.Fatalf("UpsertFeedConfigWithAudit(matching revision) error = %v", err)
	}

	if err := store.DeleteFeedConfigWithAudit(ctx, "osv", &stale, coverageAudit("feed_config_delete")); err == nil {
		t.Fatal("DeleteFeedConfigWithAudit(stale revision) error = nil, want conflict")
	}
	configs, err = store.ListFeedConfigs(ctx)
	if err != nil || len(configs) != 1 {
		t.Fatalf("ListFeedConfigs() after conflicting delete = %+v, %v; want config retained", configs, err)
	}
	current = configs[0].UpdatedAt
	if err := store.DeleteFeedConfigWithAudit(ctx, "osv", &current, coverageAudit("feed_config_delete")); err != nil {
		t.Fatalf("DeleteFeedConfigWithAudit(matching revision) error = %v", err)
	}
	if configs, err := store.ListFeedConfigs(ctx); err != nil || len(configs) != 0 {
		t.Fatalf("ListFeedConfigs() after delete = %+v, %v; want empty", configs, err)
	}
}

func TestNoopStoreSystemSettingsWithAuditRevisionChecks(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	nonZero := time.Now().UTC()
	if err := store.UpsertSystemSettingsWithAudit(ctx, &db.SystemSettings{
		ExpectedUpdatedAt: &nonZero,
	}, coverageAudit("system_settings_conflict")); err == nil {
		t.Fatal("UpsertSystemSettingsWithAudit(revision on empty settings) error = nil, want conflict")
	}

	if err := store.UpsertSystemSettingsWithAudit(ctx, &db.SystemSettings{}, coverageAudit("system_settings_create")); err != nil {
		t.Fatalf("UpsertSystemSettingsWithAudit(create) error = %v", err)
	}
	settings, err := store.GetSystemSettings(ctx)
	if err != nil || settings == nil {
		t.Fatalf("GetSystemSettings() = %+v, %v; want stored settings", settings, err)
	}

	stale := settings.UpdatedAt.Add(-time.Hour)
	if err := store.UpsertSystemSettingsWithAudit(ctx, &db.SystemSettings{
		ExpectedUpdatedAt: &stale,
	}, coverageAudit("system_settings_conflict")); err == nil {
		t.Fatal("UpsertSystemSettingsWithAudit(stale revision) error = nil, want conflict")
	}
	current := settings.UpdatedAt
	if err := store.UpsertSystemSettingsWithAudit(ctx, &db.SystemSettings{
		ExpectedUpdatedAt: &current,
	}, coverageAudit("system_settings_update")); err != nil {
		t.Fatalf("UpsertSystemSettingsWithAudit(matching revision) error = %v", err)
	}
}

func TestNoopStoreImportMaliciousFeedImportsAndDeletes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	imported, deleted, err := store.ImportMaliciousFeed(ctx, "openssf", []db.MaliciousFinding{{
		ID:        "MAL-import-1",
		Ecosystem: "npm",
		Name:      "evil-import",
		Versions:  json.RawMessage(`["1.0.0"]`),
		Source:    "openssf",
		RiskType:  "malware",
		Severity:  "CRITICAL",
		Summary:   "imported finding",
		CreatedBy: "feed",
	}}, nil, &db.FeedSyncStatus{FeedName: "openssf", LastSyncStatus: "success"})
	if err != nil || imported != 1 || deleted != 0 {
		t.Fatalf("ImportMaliciousFeed() = %d, %d, %v; want 1 imported", imported, deleted, err)
	}

	imported, deleted, err = store.ImportMaliciousFeed(ctx, "openssf", nil, []string{"MAL-import-1"}, nil)
	if err != nil || imported != 0 || deleted != 1 {
		t.Fatalf("ImportMaliciousFeed(delete pass) = %d, %d, %v; want 1 deleted", imported, deleted, err)
	}
}

func TestNoopStorePrunePackageReputationAndCheckStatus(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	if pruned, err := store.PrunePackageReputation(ctx, "socket", 0); err != nil || pruned != 0 {
		t.Fatalf("PrunePackageReputation(0) = %d, %v; want no-op", pruned, err)
	}
	if pruned, err := store.PrunePackageReputation(ctx, "socket", 24*time.Hour); err != nil || pruned != 0 {
		t.Fatalf("PrunePackageReputation(empty store) = %d, %v; want nothing pruned", pruned, err)
	}

	checkedAt := time.Now().UTC()
	if err := store.UpsertPackageCheckStatus(ctx, &db.PackageCheckStatus{
		Ecosystem:     "npm",
		Name:          "lodash",
		Source:        "socket",
		LastCheckedAt: &checkedAt,
	}); err != nil {
		t.Fatalf("UpsertPackageCheckStatus() error = %v", err)
	}
	status, err := store.GetPackageCheckStatus(ctx, "npm", "lodash", "socket")
	if err != nil || status == nil {
		t.Fatalf("GetPackageCheckStatus() = %+v, %v; want stored status", status, err)
	}

	if pruned, err := store.PrunePackageCheckStatus(ctx, 0); err != nil || pruned != 0 {
		t.Fatalf("PrunePackageCheckStatus(0) = %d, %v; want no-op", pruned, err)
	}
	if pruned, err := store.PrunePackageCheckStatus(ctx, 24*time.Hour); err != nil || pruned != 0 {
		t.Fatalf("PrunePackageCheckStatus(fresh row) = %d, %v; want fresh status retained", pruned, err)
	}
}

func TestNoopStoreQueueJobAuditedMutationsAndOldestJobs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	if err := store.UpdateQueueJobPriorityWithAudit(ctx, 404, 5, coverageAudit("queue_priority")); err == nil {
		t.Fatal("UpdateQueueJobPriorityWithAudit(missing job) error = nil, want not found")
	}
	if err := store.RetryQueueJobWithAudit(ctx, 404, coverageAudit("queue_retry")); err == nil {
		t.Fatal("RetryQueueJobWithAudit(missing job) error = nil, want not found")
	}

	created, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{
		Ecosystem: "npm",
		Name:      "lodash",
		Source:    "socket",
	})
	if err != nil || !created {
		t.Fatalf("EnqueueRefresh() = %t, %v; want created job", created, err)
	}
	jobs, err := store.ListQueueJobs(ctx, "", 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("ListQueueJobs() = %+v, %v; want one job", jobs, err)
	}
	jobID := jobs[0].ID

	if err := store.UpdateQueueJobPriorityWithAudit(ctx, jobID, 7, coverageAudit("queue_priority")); err != nil {
		t.Fatalf("UpdateQueueJobPriorityWithAudit() error = %v", err)
	}

	oldest, err := store.OldestQueueJobs(ctx)
	if err != nil {
		t.Fatalf("OldestQueueJobs() error = %v", err)
	}
	if len(oldest) == 0 {
		t.Fatalf("OldestQueueJobs() = %+v, want at least the pending job age", oldest)
	}

	store.mu.Lock()
	for i := range store.refreshJobs {
		if store.refreshJobs[i].ID == jobID {
			store.refreshJobs[i].Status = db.RefreshStatusError
			store.refreshJobs[i].Error = "boom " + strconv.Itoa(jobID)
		}
	}
	store.mu.Unlock()

	if err := store.RetryQueueJobWithAudit(ctx, jobID, coverageAudit("queue_retry")); err != nil {
		t.Fatalf("RetryQueueJobWithAudit() error = %v", err)
	}
	jobs, err = store.ListQueueJobs(ctx, string(db.RefreshStatusPending), 10)
	if err != nil || len(jobs) != 1 || jobs[0].Error != "" {
		t.Fatalf("ListQueueJobs(pending) after retry = %+v, %v; want reset pending job", jobs, err)
	}
}
