package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/db/postgres/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func startDockerPostgresStore(t *testing.T) (*Store, string) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	containerName := fmt.Sprintf("packmon-pg-unit-%d", time.Now().UnixNano())
	port := freePostgresTestPort(t)
	run := exec.Command("docker", "run", "-d", "--rm", // #nosec G204 -- test launches a fixed docker image with generated container name/port.
		"--name", containerName,
		"-e", "POSTGRES_DB=packmon",
		"-e", "POSTGRES_USER=packmon",
		"-e", "POSTGRES_PASSWORD=packmon",
		"-p", fmt.Sprintf("%d:5432", port),
		"postgres:18-alpine",
	)
	out, err := run.Output()
	if err != nil {
		t.Skipf("docker postgres unavailable: %v", err)
	}
	containerID := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run() // #nosec G204 -- cleanup uses generated test container name.
		_ = exec.Command("docker", "rm", "-f", containerID).Run()   // #nosec G204 -- cleanup uses docker-returned test container ID.
	})

	waitForPostgresContainer(t, containerName)

	dsn := fmt.Sprintf("postgres://packmon:packmon@127.0.0.1:%d/packmon?sslmode=disable", port)
	waitForPostgresDSN(t, dsn)
	if err := migrations.Run(dsn); err != nil {
		t.Fatalf("migrations.Run() error = %v", err)
	}
	version, dirty, err := migrations.Version(dsn)
	if err != nil {
		t.Fatalf("migrations.Version() error = %v", err)
	}
	if dirty || version != migrations.ExpectedVersion {
		t.Fatalf("schema version = %d dirty=%v, want %d clean", version, dirty, migrations.ExpectedVersion)
	}

	store, err := New(context.Background(), dsn, nil, &PoolConfig{MaxConns: 2, MinConns: 1})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	return store, dsn
}

func freePostgresTestPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForPostgresContainer(t *testing.T, containerName string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		// #nosec G204 -- test helper executes docker with fixed test-provided container name.
		cmd := exec.Command("docker", "exec", containerName, "pg_isready", "-U", "packmon", "-d", "packmon")
		if err := cmd.Run(); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres container %s did not become ready", containerName)
}

func waitForPostgresDSN(t *testing.T, dsn string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			err = pool.Ping(ctx)
			pool.Close()
		}
		cancel()
		if err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres DSN did not become reachable")
}

func TestPostgresStoreDockerEndToEnd(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if err := store.Ping(ctx); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if stats := store.DBPoolStats(); stats.MaxConns != 2 {
		t.Fatalf("DBPoolStats().MaxConns = %d, want 2", stats.MaxConns)
	}

	now := time.Now().UTC()
	cvss := 9.8
	vuln := &db.Vulnerability{
		ID:            "GHSA-docker-0001",
		Summary:       "docker store vulnerability",
		Details:       "details",
		Severity:      "HIGH",
		CVSSScore:     &cvss,
		Published:     now.Add(-2 * time.Hour),
		Modified:      now.Add(-time.Hour),
		ExploitExists: true,
		Aliases: []db.VulnerabilityAlias{
			{AliasID: "CVE-2026-9001"},
		},
		Sources: []db.VulnerabilitySource{
			{
				Source:   "osv",
				SourceID: "GHSA-docker-0001",
				URL:      "https://osv.dev/vulnerability/GHSA-docker-0001",
				RawJSON:  json.RawMessage(`{"id":"GHSA-docker-0001"}`),
			},
		},
		References: []db.VulnerabilityReference{
			{Type: "ADVISORY", URL: "https://github.com/advisories/GHSA-docker-0001", Source: "ghsa"},
			{Type: "WEB", URL: "https://packetstorm.news/files/id/1", Source: "osv"},
			{Type: "REPORT", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-9001", Source: "nvd"},
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
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	removed, err := store.RemovePacketStormReferences(ctx)
	if err != nil {
		t.Fatalf("RemovePacketStormReferences() error = %v", err)
	}
	if removed != 0 {
		t.Fatalf("RemovePacketStormReferences() = %d, want 0 because Packet Storm refs are filtered on upsert", removed)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 1 || findings[0].AdvisoryID != "GHSA-docker-0001" || findings[0].FixedVersion != ">= 2.0.0" {
		t.Fatalf("FindVulnerabilities() = %+v, want matching fixed vulnerability", findings)
	}
	unaffected, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "2.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(unaffected) error = %v", err)
	}
	if len(unaffected) != 0 {
		t.Fatalf("FindVulnerabilities(unaffected) = %+v, want none", unaffected)
	}
	batchFindings, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.5.0"},
		{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0"},
	})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch() error = %v", err)
	}
	if len(batchFindings) != 1 {
		t.Fatalf("FindVulnerabilitiesBatch() len = %d, want one affected version", len(batchFindings))
	}

	unknown := *vuln
	unknown.ID = "GO-2026-9002"
	unknown.Severity = "UNKNOWN"
	unknown.CVSSScore = nil
	unknown.Aliases = []db.VulnerabilityAlias{{AliasID: "CVE-2026-9002"}}
	unknown.Sources = []db.VulnerabilitySource{{Source: "osv", SourceID: "GO-2026-9002"}}
	unknown.References = nil
	unknown.AffectedPackages = []db.AffectedPackage{{
		Ecosystem:        "go",
		Name:             "example.com/pkg",
		VersionRanges:    json.RawMessage(`[]`),
		VersionsAffected: json.RawMessage(`[]`),
	}}
	if err := store.UpsertVulnerability(ctx, &unknown); err != nil {
		t.Fatalf("UpsertVulnerability(unknown) error = %v", err)
	}
	unknownAliases, err := store.FindUnknownSeverityCVEAliases(ctx)
	if err != nil {
		t.Fatalf("FindUnknownSeverityCVEAliases() error = %v", err)
	}
	if len(unknownAliases) == 0 {
		t.Fatal("FindUnknownSeverityCVEAliases() returned no rows")
	}
	if err := store.UpdateSeverityByCVE(ctx, "CVE-2026-9002", "CRITICAL", 9.9); err != nil {
		t.Fatalf("UpdateSeverityByCVE() error = %v", err)
	}
	updated, err := store.FindVulnerabilities(ctx, "go", "example.com/pkg", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(updated) error = %v", err)
	}
	if len(updated) != 1 || updated[0].Severity != "CRITICAL" {
		t.Fatalf("updated findings = %+v, want CRITICAL", updated)
	}

	if count, err := store.SetCISAKEV(ctx, []string{"CVE-2026-9001"}); err != nil || count != 1 {
		t.Fatalf("SetCISAKEV() = %d, %v; want 1 nil", count, err)
	}
	if count, err := store.ClearCISAKEV(ctx, []string{"CVE-2026-9002"}); err != nil || count != 1 {
		t.Fatalf("ClearCISAKEV() = %d, %v; want 1 nil", count, err)
	}
	if count, err := store.SetEPSSScores(ctx, []db.EPSSEntry{{CVEID: "CVE-2026-9001", Score: 0.91, Percentile: 0.99}}); err != nil || count != 1 {
		t.Fatalf("SetEPSSScores() = %d, %v; want 1 nil", count, err)
	}
	if count, err := store.EnrichVulnCheck(ctx, []db.VulnCheckEntry{{CVEID: "CVE-2026-9001", CVSSScore: &cvss, ExploitExists: true, SourceURL: "https://vulncheck.example/CVE-2026-9001"}}); err != nil || count != 1 {
		t.Fatalf("EnrichVulnCheck() = %d, %v; want 1 nil", count, err)
	}
	if count, err := store.PropagateSeverityViaAliases(ctx); err != nil || count != 0 {
		t.Fatalf("PropagateSeverityViaAliases() = %d, %v; want 0 nil", count, err)
	}

	ghsaRepair := &db.Vulnerability{
		ID:        "GHSA-repair-0001",
		Summary:   "repair raw affected",
		Severity:  "MEDIUM",
		Published: now,
		Modified:  now,
		Sources: []db.VulnerabilitySource{
			{
				Source:   "ghsa",
				SourceID: "GHSA-repair-0001",
				RawJSON:  json.RawMessage(`{"affected":[{"package":{"ecosystem":"GitHub Actions","name":"actions/checkout"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`),
			},
		},
	}
	if err := store.UpsertVulnerability(ctx, ghsaRepair); err != nil {
		t.Fatalf("UpsertVulnerability(ghsa repair) error = %v", err)
	}
	if count, err := store.RepairGHSAAffectedPackages(ctx); err != nil || count != 1 {
		t.Fatalf("RepairGHSAAffectedPackages() = %d, %v; want 1 nil", count, err)
	}

	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:            "MAL-docker-1",
		Ecosystem:     "npm",
		Name:          "evil-pad",
		Versions:      json.RawMessage(`["9.9.9"]`),
		Source:        "openssf",
		RiskType:      "malware",
		Severity:      "CRITICAL",
		Summary:       "evil package",
		ReferenceURLs: json.RawMessage(`["https://example.test/mal"]`),
		CreatedBy:     "feed",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding() error = %v", err)
	}
	malicious, err := store.FindMalicious(ctx, "npm", "evil-pad", "9.9.9")
	if err != nil {
		t.Fatalf("FindMalicious() error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "MAL-docker-1" {
		t.Fatalf("FindMalicious() = %+v, want malicious row", malicious)
	}
	maliciousBatch, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "evil-pad", Version: "9.9.9"}})
	if err != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", err)
	}
	if len(maliciousBatch) != 1 {
		t.Fatalf("FindMaliciousBatch() len = %d, want 1", len(maliciousBatch))
	}
	listedMalicious, err := store.ListMaliciousFindings(ctx, "openssf", 10)
	if err != nil {
		t.Fatalf("ListMaliciousFindings() error = %v", err)
	}
	if len(listedMalicious) != 1 {
		t.Fatalf("ListMaliciousFindings() len = %d, want 1", len(listedMalicious))
	}

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:docker-vuln",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "manual-pkg",
		Severity:    "HIGH",
		Summary:     "manual vuln",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(vulnerability) error = %v", err)
	}
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:docker-mal",
		FindingType: "malicious",
		Ecosystem:   "pypi",
		Name:        "evil-manual",
		Severity:    "CRITICAL",
		RiskType:    "malware",
		Summary:     "manual malware",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(malicious) error = %v", err)
	}
	manual, err := store.ListManualAdvisories(ctx, 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories() error = %v", err)
	}
	if len(manual) != 2 {
		t.Fatalf("ListManualAdvisories() len = %d, want 2", len(manual))
	}
	if err := store.DeleteManualAdvisory(ctx, "manual:docker-mal"); err != nil {
		t.Fatalf("DeleteManualAdvisory() error = %v", err)
	}

	if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:         "osv",
		LastSyncStatus:   "success",
		EntriesSynced:    5,
		EntriesTotal:     6,
		LastError:        "previous warning",
		LastEtag:         "etag",
		LastCommitHash:   "commit",
		LastSyncAt:       &now,
		LastSyncDuration: ptrDuration(time.Second),
		Metadata:         json.RawMessage(`{"ok":true}`),
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus() error = %v", err)
	}
	status, err := store.GetFeedSyncStatus(ctx, "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus() error = %v", err)
	}
	if status == nil || status.LastSyncStatus != "success" || status.EntriesTotal != 6 {
		t.Fatalf("GetFeedSyncStatus() = %+v, want stored status", status)
	}
	if status.LastError != "previous warning" {
		t.Fatalf("GetFeedSyncStatus().LastError = %q", status.LastError)
	}
	if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncStatus: "success",
		EntriesSynced:  0,
		EntriesTotal:   0,
		LastSyncAt:     &now,
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus(no-op success) error = %v", err)
	}
	status, err = store.GetFeedSyncStatus(ctx, "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(after no-op) error = %v", err)
	}
	if status.EntriesSynced != 5 || status.EntriesTotal != 6 {
		t.Fatalf("no-op success counters = %d/%d, want preserved 5/6", status.EntriesSynced, status.EntriesTotal)
	}
	missingStatus, err := store.GetFeedSyncStatus(ctx, "missing-feed")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(missing) error = %v", err)
	}
	if missingStatus != nil {
		t.Fatalf("GetFeedSyncStatus(missing) = %+v, want nil", missingStatus)
	}
	statuses, err := store.ListFeedSyncStatuses(ctx)
	if err != nil {
		t.Fatalf("ListFeedSyncStatuses() error = %v", err)
	}
	if len(statuses) == 0 {
		t.Fatal("ListFeedSyncStatuses() returned no rows")
	}

	interval := 30 * time.Minute
	if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: "vulncheck", Enabled: true, Mode: "self", SyncInterval: &interval, APIKey: "secret"}); err != nil {
		t.Fatalf("UpsertFeedConfig() error = %v", err)
	}
	feedCfg, err := store.GetFeedConfig(ctx, "vulncheck")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if feedCfg == nil || feedCfg.APIKey != "secret" || feedCfg.SyncInterval == nil || *feedCfg.SyncInterval != interval {
		t.Fatalf("GetFeedConfig() = %+v, want saved config", feedCfg)
	}
	feedConfigs, err := store.ListFeedConfigs(ctx)
	if err != nil {
		t.Fatalf("ListFeedConfigs() error = %v", err)
	}
	if len(feedConfigs) != 1 {
		t.Fatalf("ListFeedConfigs() len = %d, want 1", len(feedConfigs))
	}
	if err := store.DeleteFeedConfig(ctx, "vulncheck"); err != nil {
		t.Fatalf("DeleteFeedConfig() error = %v", err)
	}

	if err := store.UpsertSystemSettings(ctx, &db.SystemSettings{BlockThreshold: "HIGH", RateLimitPerMinute: 120, RateLimitBurst: 30}); err != nil {
		t.Fatalf("UpsertSystemSettings() error = %v", err)
	}
	settings, err := store.GetSystemSettings(ctx)
	if err != nil {
		t.Fatalf("GetSystemSettings() error = %v", err)
	}
	if settings == nil || settings.BlockThreshold != "HIGH" {
		t.Fatalf("GetSystemSettings() = %+v, want HIGH", settings)
	}

	activeExpiry := time.Now().UTC().Add(time.Hour)
	keyID, err := store.CreateAPIKey(ctx, "ci", "hash-ci", &activeExpiry)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	key, err := store.FindAPIKeyByHash(ctx, "hash-ci")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash() error = %v", err)
	}
	if key == nil || key.ID != keyID || key.ExpiresAt == nil {
		t.Fatalf("FindAPIKeyByHash() = %+v, want active key", key)
	}
	missingKey, err := store.FindAPIKeyByHash(ctx, "missing-hash")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash(missing) error = %v", err)
	}
	if missingKey != nil {
		t.Fatalf("FindAPIKeyByHash(missing) = %+v, want nil", missingKey)
	}
	if err := store.TouchAPIKeyLastUsed(ctx, keyID); err != nil {
		t.Fatalf("TouchAPIKeyLastUsed() error = %v", err)
	}
	keys, err := store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 1 || keys[0].ID != keyID || keys[0].LastUsedAt == nil {
		t.Fatalf("ListAPIKeys() = %+v, want touched key", keys)
	}
	if err := store.RevokeAPIKey(ctx, keyID); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}
	if err := store.DeleteAPIKey(ctx, keyID); err != nil {
		t.Fatalf("DeleteAPIKey() error = %v", err)
	}
	unrevokedID, err := store.CreateAPIKey(ctx, "delete-before-revoke", "hash-unrevoked", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(unrevoked) error = %v", err)
	}
	if err := store.DeleteAPIKey(ctx, unrevokedID); err == nil {
		t.Fatal("DeleteAPIKey(unrevoked) error = nil, want not revoked")
	}

	if err := store.UpsertAdminAuth(ctx, "hash", true); err != nil {
		t.Fatalf("UpsertAdminAuth() error = %v", err)
	}
	adminAuth, err := store.GetAdminAuth(ctx)
	if err != nil {
		t.Fatalf("GetAdminAuth() error = %v", err)
	}
	if adminAuth == nil || !adminAuth.PasswordIsBootstrap {
		t.Fatalf("GetAdminAuth() = %+v, want bootstrap auth", adminAuth)
	}
	if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{Action: "login_success", Details: json.RawMessage(`{"ip":"127.0.0.1"}`), IP: "127.0.0.1"}); err != nil {
		t.Fatalf("InsertAdminAuditLog() error = %v", err)
	}
	auditLog, err := store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(auditLog) == 0 || auditLog[0].Action != "login_success" {
		t.Fatalf("ListAdminAuditLog() = %+v, want login_success", auditLog)
	}

	created, position, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "left-pad", Source: "socket", Priority: 3})
	if err != nil {
		t.Fatalf("EnqueueRefresh() error = %v", err)
	}
	if !created || position <= 0 {
		t.Fatalf("EnqueueRefresh() = created %v position %d, want created with position", created, position)
	}
	created, position, err = store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "left-pad", Source: "socket", Priority: 1})
	if err != nil {
		t.Fatalf("EnqueueRefresh(duplicate) error = %v", err)
	}
	if created || position <= 0 {
		t.Fatalf("EnqueueRefresh(duplicate) = created %v position %d, want existing job", created, position)
	}
	jobs, err := store.ListQueueJobs(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListQueueJobs() error = %v", err)
	}
	pendingJobs, err := store.ListQueueJobs(ctx, "pending", 10)
	if err != nil {
		t.Fatalf("ListQueueJobs(pending) error = %v", err)
	}
	if len(pendingJobs) == 0 {
		t.Fatal("ListQueueJobs(pending) returned no rows")
	}
	jobID := jobs[0].ID
	if err := store.UpdateQueueJobPriority(ctx, jobID, 0); err != nil {
		t.Fatalf("UpdateQueueJobPriority() error = %v", err)
	}
	if err := store.PauseQueueJob(ctx, jobID); err != nil {
		t.Fatalf("PauseQueueJob() error = %v", err)
	}
	created, position, err = store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "left-pad", Source: "socket", Priority: 0})
	if err != nil {
		t.Fatalf("EnqueueRefresh(paused duplicate) error = %v", err)
	}
	if created {
		t.Fatalf("EnqueueRefresh(paused duplicate) = created %v position %d, want paused existing job", created, position)
	}
	if err := store.ResumeQueueJob(ctx, jobID); err != nil {
		t.Fatalf("ResumeQueueJob() error = %v", err)
	}
	dequeued, err := store.DequeueRefresh(ctx, "socket")
	if err != nil {
		t.Fatalf("DequeueRefresh() error = %v", err)
	}
	if dequeued == nil || dequeued.ID != jobID {
		t.Fatalf("DequeueRefresh() = %+v, want job %d", dequeued, jobID)
	}
	if err := store.CompleteRefresh(ctx, jobID, errors.New("temporary")); err != nil {
		t.Fatalf("CompleteRefresh(error) error = %v", err)
	}
	errorJobs, err := store.ListQueueJobs(ctx, "error", 10)
	if err != nil {
		t.Fatalf("ListQueueJobs(error) error = %v", err)
	}
	if len(errorJobs) == 0 || errorJobs[0].Error == "" {
		t.Fatalf("ListQueueJobs(error) = %+v, want error text", errorJobs)
	}
	if err := store.RetryQueueJob(ctx, jobID); err != nil {
		t.Fatalf("RetryQueueJob() error = %v", err)
	}
	if reset, err := store.ResetStuckJobs(ctx, "socket", time.Nanosecond); err != nil || reset != 0 {
		t.Fatalf("ResetStuckJobs() = %d, %v; want 0 nil", reset, err)
	}
	statsQueue, err := store.QueueStats(ctx)
	if err != nil {
		t.Fatalf("QueueStats() error = %v", err)
	}
	if statsQueue.Pending == 0 {
		t.Fatalf("QueueStats() = %+v, want pending job", statsQueue)
	}
	if cleared, err := store.ClearQueue(ctx, []string{"pending"}); err != nil || cleared != 1 {
		t.Fatalf("ClearQueue() = %d, %v; want 1 nil", cleared, err)
	}
	if dequeued, err := store.DequeueRefresh(ctx, "socket"); err != nil || dequeued != nil {
		t.Fatalf("DequeueRefresh(empty) = %+v, %v; want nil nil", dequeued, err)
	}
	if purged, err := store.PurgeQueue(ctx); err != nil || purged != 0 {
		t.Fatalf("PurgeQueue() = %d, %v; want 0 nil", purged, err)
	}

	lastPackageCheck := time.Now().UTC()
	nextPackageCheck := lastPackageCheck.Add(24 * time.Hour)
	if err := store.UpsertPackageCheckStatus(ctx, &db.PackageCheckStatus{
		Ecosystem:     "npm",
		Name:          "left-pad",
		Source:        "socket",
		LastCheckedAt: &lastPackageCheck,
		NextCheckAt:   &nextPackageCheck,
		LastResult:    json.RawMessage(`{"score":1}`),
	}); err != nil {
		t.Fatalf("UpsertPackageCheckStatus(first) error = %v", err)
	}
	if err := store.UpsertPackageCheckStatus(ctx, &db.PackageCheckStatus{
		Ecosystem:  "npm",
		Name:       "left-pad",
		Source:     "socket",
		CheckCount: 2,
		LastResult: json.RawMessage(`{"score":2}`),
	}); err != nil {
		t.Fatalf("UpsertPackageCheckStatus(second) error = %v", err)
	}
	checkStatus, err := store.GetPackageCheckStatus(ctx, "npm", "left-pad", "socket")
	if err != nil {
		t.Fatalf("GetPackageCheckStatus() error = %v", err)
	}
	if checkStatus == nil || checkStatus.CheckCount != 3 || !strings.Contains(string(checkStatus.LastResult), `"score"`) || !strings.Contains(string(checkStatus.LastResult), "2") {
		t.Fatalf("GetPackageCheckStatus() = %+v, want cumulative count and latest result", checkStatus)
	}

	queued, err := store.MarkPackageReputationDue(ctx, &db.PackageReputation{
		Ecosystem: "npm", Name: "removed-pkg", Version: "1.0.0", Source: db.ReputationSourceReversingLabs,
	})
	if err != nil {
		t.Fatalf("MarkPackageReputationDue() error = %v", err)
	}
	if !queued {
		t.Fatal("MarkPackageReputationDue() queued = false, want true")
	}
	due, err := store.ListDuePackageReputations(ctx, "npm", "removed-pkg", db.ReputationSourceReversingLabs, 10)
	if err != nil {
		t.Fatalf("ListDuePackageReputations() error = %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("ListDuePackageReputations() len = %d, want 1", len(due))
	}
	lastChecked := time.Now().UTC().Add(-time.Hour)
	nextCheck := time.Now().UTC().Add(-time.Minute)
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem:     "npm",
		Name:          "removed-pkg",
		Version:       "1.0.0",
		Source:        db.ReputationSourceReversingLabs,
		Status:        "removed",
		Severity:      "LOW",
		Summary:       "removed package",
		ReferenceURLs: json.RawMessage(`["https://rl.example/removed"]`),
		LastCheckedAt: &lastChecked,
		NextCheckAt:   &nextCheck,
	}); err != nil {
		t.Fatalf("UpsertPackageReputation() error = %v", err)
	}
	reputation, err := store.FindReputationFindings(ctx, "npm", "removed-pkg", db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindings() error = %v", err)
	}
	if len(reputation) != 1 {
		t.Fatalf("FindReputationFindings() len = %d, want 1", len(reputation))
	}
	reputationBatch, err := store.FindReputationFindingsBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "removed-pkg", Version: "1.0.0"}}, db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindingsBatch() error = %v", err)
	}
	if len(reputationBatch) != 1 {
		t.Fatalf("FindReputationFindingsBatch() len = %d, want 1", len(reputationBatch))
	}

	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{ScanID: "scan-1", RepoName: "repo", Branch: "main", ScannedAt: now, PackagesCount: 4, FindingsCount: 2, DurationMs: 10, ClientIP: "127.0.0.1"}); err != nil {
		t.Fatalf("InsertScanLog() error = %v", err)
	}
	recentScans, err := store.ListRecentScans(ctx, 10)
	if err != nil {
		t.Fatalf("ListRecentScans() error = %v", err)
	}
	if len(recentScans) != 1 || recentScans[0].ScanID != "scan-1" {
		t.Fatalf("ListRecentScans() = %+v, want scan-1", recentScans)
	}
	scanTotals, err := store.ScanTotals(ctx)
	if err != nil {
		t.Fatalf("ScanTotals() error = %v", err)
	}
	if scanTotals.PackagesScanned != 4 || scanTotals.Findings != 2 {
		t.Fatalf("ScanTotals() = %+v, want 4/2", scanTotals)
	}
	byDay, err := store.CountScansByDay(ctx, 7)
	if err != nil {
		t.Fatalf("CountScansByDay() error = %v", err)
	}
	if len(byDay) != 7 {
		t.Fatalf("CountScansByDay() len = %d, want 7", len(byDay))
	}
	search, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "left", Limit: 20})
	if err != nil {
		t.Fatalf("SearchPackages() error = %v", err)
	}
	if len(search) == 0 {
		t.Fatal("SearchPackages() returned no results")
	}
	dashboard, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats() error = %v", err)
	}
	if dashboard.TotalPackages == 0 || dashboard.TotalVulnerabilities == 0 {
		t.Fatalf("DashboardStats() = %+v, want non-zero dashboard", dashboard)
	}
	recentVulns, err := store.ListRecentVulnerabilities(ctx, 30, 10)
	if err != nil {
		t.Fatalf("ListRecentVulnerabilities() error = %v", err)
	}
	if len(recentVulns) == 0 {
		t.Fatal("ListRecentVulnerabilities() returned no rows")
	}
	exported, err := store.ExportSync(ctx, db.SyncExportOptions{SnapshotAt: time.Now().UTC().Add(time.Minute), Limit: 100})
	if err != nil {
		t.Fatalf("ExportSync() error = %v", err)
	}
	if len(exported.Vulnerabilities) == 0 || len(exported.Malicious) == 0 || len(exported.Reputation) == 0 {
		t.Fatalf("ExportSync() missing rows: vulns=%d malicious=%d reputation=%d", len(exported.Vulnerabilities), len(exported.Malicious), len(exported.Reputation))
	}
	since := now.Add(-24 * time.Hour)
	if _, err := store.ExportSync(ctx, db.SyncExportOptions{
		Since:      &since,
		Ecosystems: []string{"npm"},
		Limit:      1,
		Offset:     1,
	}); err != nil {
		t.Fatalf("ExportSync(filtered page) error = %v", err)
	}

	if err := store.DeleteVulnerability(ctx, "GHSA-docker-0001"); err != nil {
		t.Fatalf("DeleteVulnerability() error = %v", err)
	}
	beforeMaliciousDelete := time.Now().UTC().Add(-time.Second)
	if err := store.DeleteMaliciousFinding(ctx, "MAL-docker-1"); err != nil {
		t.Fatalf("DeleteMaliciousFinding() error = %v", err)
	}
	deletedMalicious, err := store.FindMalicious(ctx, "npm", "evil-pad", "9.9.9")
	if err != nil {
		t.Fatalf("FindMalicious(after delete) error = %v", err)
	}
	if len(deletedMalicious) != 0 {
		t.Fatalf("FindMalicious(after delete) = %+v, want no active findings", deletedMalicious)
	}
	tombstoneExport, err := store.ExportSync(ctx, db.SyncExportOptions{
		Since:      &beforeMaliciousDelete,
		SnapshotAt: time.Now().UTC().Add(time.Minute),
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("ExportSync(after malicious delete) error = %v", err)
	}
	var foundTombstone bool
	for _, item := range tombstoneExport.Malicious {
		if item.ID == "MAL-docker-1" {
			if !item.Withdrawn {
				t.Fatalf("malicious tombstone = %+v, want withdrawn", item)
			}
			foundTombstone = true
		}
	}
	if !foundTombstone {
		t.Fatalf("ExportSync(after malicious delete) missing MAL-docker-1 tombstone: %+v", tombstoneExport.Malicious)
	}
}

func ptrDuration(d time.Duration) *time.Duration {
	return &d
}
