//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	postgres "github.com/8linkz-sec/packmon/internal/db/postgres"
)

// startPostgresStore brings up a throwaway PostgreSQL container, runs the
// migrations via the server binary, and returns a connected store. It reuses
// the docker helpers from production_test.go.
func startPostgresStore(t *testing.T) *postgres.Store {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; tagged integration tests require Docker: %v", err)
	}

	_, dbPort := startIntegrationPostgres(t, "packmon-store-it")

	env := []string{
		"PACKMON_SERVER_MODE=production",
		"PACKMON_LOG_LEVEL=warn",
		"PACKMON_LOG_FORMAT=console",
		"PACKMON_DB_HOST=127.0.0.1",
		fmt.Sprintf("PACKMON_DB_PORT=%d", dbPort),
		"PACKMON_DB_NAME=packmon",
		"PACKMON_DB_USER=packmon",
		"PACKMON_DB_PASSWORD=packmon",
		"PACKMON_DB_SSLMODE=disable",
		"PACKMON_ADMIN_INITIAL_PASSWORD=integration-admin",
		"PACKMON_ENCRYPTION_KEY=integration-encryption-key",
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"USERPROFILE=" + os.Getenv("USERPROFILE"),
		"TEMP=" + os.Getenv("TEMP"),
		"TMP=" + os.Getenv("TMP"),
	}
	runMigrateWithRetry(t, serverBinaryPath(t), env)

	dsn := fmt.Sprintf("postgres://packmon:packmon@127.0.0.1:%d/packmon?sslmode=disable", dbPort)
	store, err := postgres.New(context.Background(), dsn, nil, nil)
	if err != nil {
		t.Fatalf("connect store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// findQueueJob returns the queue job matching ecosystem/name, or fails.
func findQueueJob(t *testing.T, store *postgres.Store, ecosystem, name string) db.RefreshJob {
	t.Helper()
	jobs, err := store.ListQueueJobs(context.Background(), "", 100)
	if err != nil {
		t.Fatalf("ListQueueJobs: %v", err)
	}
	for _, j := range jobs {
		if j.Ecosystem == ecosystem && j.Name == name {
			return j
		}
	}
	t.Fatalf("queue job %s/%s not found among %d jobs", ecosystem, name, len(jobs))
	return db.RefreshJob{}
}

// TestPostgresQueuePauseSurvivesReEnqueue is the store-level regression test for
// the queue pause-durability fix (M3): a paused job must not be flipped back to
// pending when the same package is enqueued again.
func TestPostgresQueuePauseSurvivesReEnqueue(t *testing.T) {
	store := startPostgresStore(t)
	ctx := context.Background()

	created, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{
		Ecosystem: "npm", Name: "left-pad", Source: "socket", Priority: 3,
	})
	if err != nil {
		t.Fatalf("EnqueueRefresh (initial): %v", err)
	}
	if !created {
		t.Fatal("expected the first enqueue to create a new job")
	}

	job := findQueueJob(t, store, "npm", "left-pad")
	if err := store.PauseQueueJob(ctx, job.ID); err != nil {
		t.Fatalf("PauseQueueJob: %v", err)
	}
	if got := findQueueJob(t, store, "npm", "left-pad"); got.Status != "paused" {
		t.Fatalf("status after pause = %q, want paused", got.Status)
	}

	// Re-enqueue the same package: the admin pause must hold.
	created, _, err = store.EnqueueRefresh(ctx, &db.RefreshJob{
		Ecosystem: "npm", Name: "left-pad", Source: "socket", Priority: 0,
	})
	if err != nil {
		t.Fatalf("EnqueueRefresh (re-enqueue): %v", err)
	}
	if created {
		t.Fatal("re-enqueue of an existing job must not report created=true")
	}
	if got := findQueueJob(t, store, "npm", "left-pad"); got.Status != "paused" {
		t.Fatalf("status after re-enqueue = %q, want paused (pause must be durable)", got.Status)
	}
}

// TestPostgresManualVulnerabilityMatchesConcreteVersion verifies that a manual
// vulnerability advisory (stored with empty version ranges) is surfaced for a
// concrete scanned version -- the store-level confirmation that Audit.md H1 is
// not a defect.
func TestPostgresManualVulnerabilityMatchesConcreteVersion(t *testing.T) {
	store := startPostgresStore(t)
	ctx := context.Background()

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:store-it-1",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "lodash",
		Severity:    "HIGH",
		Summary:     "manual advisory",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory: %v", err)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "lodash", "4.17.15")
	if err != nil {
		t.Fatalf("FindVulnerabilities: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (manual advisory must match a concrete version)", len(findings))
	}
	if findings[0].Source != "manual" || findings[0].AdvisoryID != "manual:store-it-1" {
		t.Fatalf("unexpected finding = %+v", findings[0])
	}
}

// TestPostgresSystemSettingsRoundTrip verifies the system-settings store path
// used for persisted admin configuration (M9 coverage).
func TestPostgresSystemSettingsRoundTrip(t *testing.T) {
	store := startPostgresStore(t)
	ctx := context.Background()

	want := &db.SystemSettings{
		BlockThreshold:      "HIGH",
		RateLimitPerMinute:  120,
		RateLimitBurst:      30,
		ScanLogRetention:    45 * 24 * time.Hour,
		AdminAuditRetention: 14 * 24 * time.Hour,
	}
	if err := store.UpsertSystemSettings(ctx, want); err != nil {
		t.Fatalf("UpsertSystemSettings: %v", err)
	}

	got, err := store.GetSystemSettings(ctx)
	if err != nil {
		t.Fatalf("GetSystemSettings: %v", err)
	}
	if got == nil {
		t.Fatal("GetSystemSettings returned nil")
	}
	if got.BlockThreshold != "HIGH" || got.RateLimitPerMinute != 120 || got.RateLimitBurst != 30 {
		t.Fatalf("round-trip mismatch: got %+v", got)
	}
	if got.ScanLogRetention != 45*24*time.Hour || got.AdminAuditRetention != 14*24*time.Hour {
		t.Fatalf("round-trip retention mismatch: got scan %s admin %s", got.ScanLogRetention, got.AdminAuditRetention)
	}
}

func TestPostgresAPIKeyExpirationRevocationAndDeletion(t *testing.T) {
	store := startPostgresStore(t)
	ctx := context.Background()

	future := time.Now().UTC().Add(24 * time.Hour)
	keyID, err := store.CreateAPIKey(ctx, "ci-runner", "hash-active", &future)
	if err != nil {
		t.Fatalf("CreateAPIKey(active): %v", err)
	}

	key, err := store.FindAPIKeyByHash(ctx, "hash-active")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash(active): %v", err)
	}
	if key == nil || key.ID != keyID || key.ExpiresAt == nil {
		t.Fatalf("active key = %+v, want id %d with expiration", key, keyID)
	}
	if err := store.TouchAPIKeyLastUsed(ctx, keyID); err != nil {
		t.Fatalf("TouchAPIKeyLastUsed: %v", err)
	}
	keys, err := store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].LastUsedAt == nil {
		t.Fatalf("keys after touch = %+v, want LastUsedAt", keys)
	}

	past := time.Now().UTC().Add(-1 * time.Hour)
	if _, err := store.CreateAPIKey(ctx, "expired", "hash-expired", &past); err != nil {
		t.Fatalf("CreateAPIKey(expired): %v", err)
	}
	expired, err := store.FindAPIKeyByHash(ctx, "hash-expired")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash(expired): %v", err)
	}
	if expired != nil {
		t.Fatalf("expired key = %+v, want nil", expired)
	}

	if err := store.RevokeAPIKey(ctx, keyID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	revoked, err := store.FindAPIKeyByHash(ctx, "hash-active")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash(revoked): %v", err)
	}
	if revoked != nil {
		t.Fatalf("revoked key = %+v, want nil", revoked)
	}
	if err := store.DeleteAPIKey(ctx, keyID); err != nil {
		t.Fatalf("DeleteAPIKey(revoked): %v", err)
	}
	keys, err = store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys(after delete): %v", err)
	}
	var deleted *db.APIKey
	for i := range keys {
		if keys[i].ID == keyID {
			deleted = &keys[i]
			break
		}
	}
	if deleted == nil || deleted.DeletedAt == nil || deleted.Name != "" || deleted.KeyHash != fmt.Sprintf("deleted:%d", keyID) || deleted.LastUsedAt == nil || deleted.RevokedAt == nil || deleted.ExpiresAt == nil {
		t.Fatalf("soft-deleted key metadata = %+v in %+v, want scrubbed identity and lifecycle metadata retained", deleted, keys)
	}
}

func TestPostgresStoreSearchSyncReputationAndAdminStats(t *testing.T) {
	store := startPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	vuln := &db.Vulnerability{
		ID:        "GHSA-store-0001",
		Summary:   "store integration vulnerability",
		Severity:  "HIGH",
		Published: now.Add(-2 * time.Hour),
		Modified:  now.Add(-1 * time.Hour),
		Aliases: []db.VulnerabilityAlias{
			{AliasID: "CVE-2026-0001"},
		},
		Sources: []db.VulnerabilitySource{
			{Source: "osv", SourceID: "GHSA-store-0001", URL: "https://osv.dev/vulnerability/GHSA-store-0001"},
		},
		References: []db.VulnerabilityReference{
			{Type: "ADVISORY", URL: "https://github.com/advisories/GHSA-store-0001", Source: "ghsa"},
		},
		AffectedPackages: []db.AffectedPackage{
			{
				Ecosystem:        "npm",
				Name:             "left-pad",
				VersionRanges:    json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`),
				VersionsAffected: json.RawMessage(`[]`),
			},
		},
	}
	if err := store.UpsertVulnerability(ctx, vuln); err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}
	if _, err := store.SetCISAKEV(ctx, []string{"CVE-2026-0001"}); err != nil {
		t.Fatalf("SetCISAKEV: %v", err)
	}
	cvss := 9.8
	if _, err := store.EnrichVulnCheck(ctx, []db.VulnCheckEntry{
		{CVEID: "CVE-2026-0001", CVSSScore: &cvss, ExploitExists: true, SourceURL: "https://vulncheck.test/CVE-2026-0001"},
	}); err != nil {
		t.Fatalf("EnrichVulnCheck: %v", err)
	}
	if _, err := store.SetEPSSScores(ctx, []db.EPSSEntry{{CVEID: "CVE-2026-0001", Score: 0.91, Percentile: 0.99}}); err != nil {
		t.Fatalf("SetEPSSScores: %v", err)
	}

	vulnFindings, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities: %v", err)
	}
	if len(vulnFindings) != 1 || vulnFindings[0].AdvisoryID != "GHSA-store-0001" {
		t.Fatalf("vulnerability findings = %+v", vulnFindings)
	}
	vulnBatch, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "left-pad", Version: "1.5.0"}})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch: %v", err)
	}
	if len(vulnBatch) != 1 {
		t.Fatalf("batch vulnerability findings = %d, want 1", len(vulnBatch))
	}

	malPublished := now.Add(-30 * time.Minute)
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:            "MAL-store-0001",
		Ecosystem:     "npm",
		Name:          "evil-pkg",
		Versions:      json.RawMessage(`["9.9.9"]`),
		Source:        "openssf",
		RiskType:      "malware",
		Severity:      "CRITICAL",
		Summary:       "malicious package",
		ReferenceURLs: json.RawMessage(`["https://example.test/mal"]`),
		Published:     &malPublished,
		CreatedBy:     "feed-sync",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding: %v", err)
	}
	malicious, err := store.FindMalicious(ctx, "npm", "evil-pkg", "9.9.9")
	if err != nil {
		t.Fatalf("FindMalicious: %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "MAL-store-0001" {
		t.Fatalf("malicious findings = %+v", malicious)
	}
	maliciousBatch, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "evil-pkg", Version: "9.9.9"}})
	if err != nil {
		t.Fatalf("FindMaliciousBatch: %v", err)
	}
	if len(maliciousBatch) != 1 {
		t.Fatalf("batch malicious findings = %d, want 1", len(maliciousBatch))
	}

	nextCheck := now.Add(-time.Minute)
	lastChecked := now.Add(-2 * time.Hour)
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem:     "npm",
		Name:          "removed-pkg",
		Version:       "1.0.0",
		Source:        db.ReputationSourceReversingLabs,
		Status:        "removed",
		Severity:      "LOW",
		Summary:       "package version was removed",
		ReferenceURLs: json.RawMessage(`["https://rl.example/removed"]`),
		Evidence:      json.RawMessage(`{"removed":true}`),
		LastCheckedAt: &lastChecked,
		NextCheckAt:   &nextCheck,
	}); err != nil {
		t.Fatalf("UpsertPackageReputation: %v", err)
	}
	repFindings, err := store.FindReputationFindings(ctx, "npm", "removed-pkg", db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindings: %v", err)
	}
	if len(repFindings) != 1 || repFindings[0].Type != "supply_chain_risk" {
		t.Fatalf("reputation findings = %+v", repFindings)
	}
	repBatch, err := store.FindReputationFindingsBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "removed-pkg", Version: "1.0.0"}}, db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindingsBatch: %v", err)
	}
	if len(repBatch) != 1 {
		t.Fatalf("batch reputation findings = %d, want 1", len(repBatch))
	}
	queued, err := store.MarkPackageReputationDue(ctx, &db.PackageReputation{
		Ecosystem: "npm", Name: "due-pkg", Version: "1.0.0", Source: db.ReputationSourceReversingLabs,
	})
	if err != nil {
		t.Fatalf("MarkPackageReputationDue: %v", err)
	}
	if !queued {
		t.Fatal("MarkPackageReputationDue queued = false, want true for new package")
	}
	due, err := store.ListDuePackageReputations(ctx, "npm", "due-pkg", db.ReputationSourceReversingLabs, 10)
	if err != nil {
		t.Fatalf("ListDuePackageReputations: %v", err)
	}
	if len(due) != 1 || due[0].Status != "pending" {
		t.Fatalf("due reputations = %+v", due)
	}

	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
		ScanID:         "scan-store-1",
		RepoName:       "packmon",
		ScannedAt:      now,
		PackagesCount:  3,
		FindingsCount:  3,
		DurationMs:     12,
		ClientIP:       "127.0.0.1",
		BlockThreshold: "CRITICAL",
		FeedStatus:     "healthy",
	}); err != nil {
		t.Fatalf("InsertScanLog: %v", err)
	}
	recentScans, err := store.ListRecentScans(ctx, 5, 0)
	if err != nil {
		t.Fatalf("ListRecentScans: %v", err)
	}
	if len(recentScans) != 1 || recentScans[0].ScanID != "scan-store-1" {
		t.Fatalf("recent scans = %+v", recentScans)
	}
	totals, err := store.ScanTotals(ctx)
	if err != nil {
		t.Fatalf("ScanTotals: %v", err)
	}
	if totals.PackagesScanned != 3 || totals.Findings != 3 {
		t.Fatalf("scan totals = %+v", totals)
	}
	byDay, err := store.CountScansByDay(ctx, 7)
	if err != nil {
		t.Fatalf("CountScansByDay: %v", err)
	}
	if len(byDay) == 0 {
		t.Fatal("CountScansByDay returned no rows")
	}

	search, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "left", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages: %v", err)
	}
	if len(search) == 0 || search[0].Name != "left-pad" {
		t.Fatalf("search results = %+v", search)
	}
	recentVulns, err := store.ListRecentVulnerabilities(ctx, 30, 10)
	if err != nil {
		t.Fatalf("ListRecentVulnerabilities: %v", err)
	}
	if len(recentVulns) == 0 || recentVulns[0].ID != "GHSA-store-0001" {
		t.Fatalf("recent vulnerabilities = %+v", recentVulns)
	}

	exported, err := store.ExportSync(ctx, db.SyncExportOptions{SnapshotAt: time.Now().UTC().Add(time.Minute)})
	if err != nil {
		t.Fatalf("ExportSync: %v", err)
	}
	if len(exported.Vulnerabilities) == 0 || len(exported.Malicious) == 0 || len(exported.Reputation) == 0 {
		t.Fatalf("sync export missing rows: vulns=%d malicious=%d reputation=%d", len(exported.Vulnerabilities), len(exported.Malicious), len(exported.Reputation))
	}
}

func TestPostgresUnknownSeverityAliasUpdate(t *testing.T) {
	store := startPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:        "OSV-UNKNOWN-1",
		Summary:   "unknown severity",
		Severity:  "UNKNOWN",
		Published: now,
		Modified:  now,
		Aliases:   []db.VulnerabilityAlias{{AliasID: "CVE-2026-0999"}},
		Sources:   []db.VulnerabilitySource{{Source: "osv", SourceID: "OSV-UNKNOWN-1"}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "unknown-severity-pkg",
			VersionRanges:    json.RawMessage(`[]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}); err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}

	unknown, err := store.FindUnknownSeverityCVEIDs(ctx, "", 100)
	if err != nil {
		t.Fatalf("FindUnknownSeverityCVEIDs: %v", err)
	}
	found := false
	for _, item := range unknown {
		if item == "CVE-2026-0999" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("unknown CVE aliases = %+v, want CVE-2026-0999", unknown)
	}

	if err := store.UpdateSeverityByCVE(ctx, "CVE-2026-0999", "CRITICAL", 9.9); err != nil {
		t.Fatalf("UpdateSeverityByCVE: %v", err)
	}
	findings, err := store.FindVulnerabilities(ctx, "npm", "unknown-severity-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != "CRITICAL" {
		t.Fatalf("findings after severity update = %+v", findings)
	}
}
