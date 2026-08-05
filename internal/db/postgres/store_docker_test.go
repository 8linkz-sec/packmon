//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/db/postgres/migrations"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

const postgresDockerTestImage = "cgr.dev/chainguard/postgres:18@sha256:891139a6d9036632791857fb7585425f1bf0c64516fc52bc39da94305ee92461"

func startDockerPostgresStore(t *testing.T) (*Store, string) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; Docker-backed PostgreSQL tests require the explicit integration gate to run against Docker: %v", err)
	}

	containerName := fmt.Sprintf("packmon-pg-unit-%d", time.Now().UnixNano())
	run := exec.Command("docker", "run", "-d", "--rm", // #nosec G204 -- test launches a fixed docker image with generated container name/port.
		"--name", containerName,
		"-e", "POSTGRES_DB=packmon",
		"-e", "POSTGRES_USER=packmon",
		"-e", "POSTGRES_PASSWORD=packmon",
		"-p", "127.0.0.1::5432",
		postgresDockerTestImage,
	)
	out, err := run.Output()
	if err != nil {
		t.Fatalf("docker postgres unavailable: %v", err)
	}
	containerID := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run() // #nosec G204 -- cleanup uses generated test container name.
		_ = exec.Command("docker", "rm", "-f", containerID).Run()   // #nosec G204 -- cleanup uses docker-returned test container ID.
	})

	waitForPostgresContainer(t, containerName)

	port := dockerPostgresPublishedPort(t, containerName, "5432/tcp")
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

func dockerPostgresPublishedPort(t *testing.T, containerName, containerPort string) int {
	t.Helper()

	out, err := exec.Command("docker", "port", containerName, containerPort).Output() // #nosec G204 -- test helper executes docker with fixed test-provided container name.
	if err != nil {
		t.Fatalf("docker port %s %s: %v", containerName, containerPort, err)
	}
	lines := strings.Fields(strings.TrimSpace(string(out)))
	if len(lines) == 0 {
		t.Fatalf("docker port %s %s returned no mapping", containerName, containerPort)
	}
	_, port, err := net.SplitHostPort(lines[len(lines)-1])
	if err != nil {
		t.Fatalf("parse docker port mapping %q: %v", lines[len(lines)-1], err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse docker host port %q: %v", port, err)
	}
	return n
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

func failingAdminAuditEntry(action string) *db.AdminAuditEntry {
	return &db.AdminAuditEntry{
		Action:  action,
		Details: json.RawMessage(`{"forced":"audit_failure"}`),
		IP:      "not-an-ip",
	}
}

func requireAdminAuditFailure(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, db.ErrAdminAuditLog) {
		t.Fatalf("audited mutation error = %v, want ErrAdminAuditLog", err)
	}
}

func requireNoAdminAuditRows(t *testing.T, store *Store, ctx context.Context) {
	t.Helper()
	audit, err := store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("admin audit rows = %+v, want none after failed audited mutation", audit)
	}
}

func apiKeyByID(t *testing.T, store *Store, ctx context.Context, keyID int) db.APIKey {
	t.Helper()
	keys, err := store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	for _, key := range keys {
		if key.ID == keyID {
			return key
		}
	}
	t.Fatalf("ListAPIKeys() missing key %d: %+v", keyID, keys)
	return db.APIKey{}
}

func queueJobByID(t *testing.T, store *Store, ctx context.Context, jobID int) db.RefreshJob {
	t.Helper()
	jobs, err := store.ListQueueJobs(ctx, "", 200)
	if err != nil {
		t.Fatalf("ListQueueJobs() error = %v", err)
	}
	for _, job := range jobs {
		if job.ID == jobID {
			return job
		}
	}
	t.Fatalf("ListQueueJobs() missing job %d: %+v", jobID, jobs)
	return db.RefreshJob{}
}

func TestPostgresStoreAPIKeyDeleteScrubsLabelAndHashAgainstDocker(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	expiresAt := time.Now().UTC().Add(time.Hour)
	keyID, err := store.CreateAPIKey(ctx, "operator-ci", "hash-operator-ci", &expiresAt)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if err := store.RevokeAPIKey(ctx, keyID); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}
	if err := store.DeleteAPIKey(ctx, keyID); err != nil {
		t.Fatalf("DeleteAPIKey() error = %v", err)
	}

	keys, err := store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	for _, key := range keys {
		if key.ID == keyID {
			t.Fatalf("ListAPIKeys() still contains permanently deleted key %d: %+v", keyID, keys)
		}
	}
	if found, err := store.FindAPIKeyByHash(ctx, "hash-operator-ci"); err != nil || found != nil {
		t.Fatalf("FindAPIKeyByHash(old hash) = %+v, %v; want nil, nil", found, err)
	}
}

func TestAdminAuditedAPIKeyAndPasswordWritesRollBackOnAuditFailure(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	expiresAt := time.Now().UTC().Add(time.Hour)

	if _, err := store.CreateAPIKeyWithAudit(ctx, "create-rollback", "hash-create-rollback", &expiresAt, failingAdminAuditEntry("api_key_create")); err == nil {
		t.Fatal("CreateAPIKeyWithAudit() error = nil, want audit failure")
	} else {
		requireAdminAuditFailure(t, err)
	}
	if key, err := store.FindAPIKeyByHash(ctx, "hash-create-rollback"); err != nil || key != nil {
		t.Fatalf("FindAPIKeyByHash(after failed create) = %+v, %v; want nil, nil", key, err)
	}
	if keys, err := store.ListAPIKeys(ctx); err != nil || len(keys) != 0 {
		t.Fatalf("ListAPIKeys(after failed create) = %+v, %v; want no keys", keys, err)
	}

	keyID, err := store.CreateAPIKey(ctx, "rollback-key", "hash-rollback-key", &expiresAt)
	if err != nil {
		t.Fatalf("CreateAPIKey(base) error = %v", err)
	}
	err = store.RevokeAPIKeyWithAudit(ctx, keyID, failingAdminAuditEntry("api_key_revoke"))
	requireAdminAuditFailure(t, err)
	key := apiKeyByID(t, store, ctx, keyID)
	if key.RevokedAt != nil || key.DeletedAt != nil || key.Name != "rollback-key" || key.KeyHash != "hash-rollback-key" {
		t.Fatalf("API key after failed audited revoke = %+v, want active original key", key)
	}

	if err := store.RevokeAPIKey(ctx, keyID); err != nil {
		t.Fatalf("RevokeAPIKey(base) error = %v", err)
	}
	err = store.DeleteAPIKeyWithAudit(ctx, keyID, failingAdminAuditEntry("api_key_delete"))
	requireAdminAuditFailure(t, err)
	key = apiKeyByID(t, store, ctx, keyID)
	if key.RevokedAt == nil || key.DeletedAt != nil || key.Name != "rollback-key" || key.KeyHash != "hash-rollback-key" {
		t.Fatalf("API key after failed audited delete = %+v, want revoked unscrubbed key", key)
	}

	if err := store.UpsertAdminAuth(ctx, "hash-original", true); err != nil {
		t.Fatalf("UpsertAdminAuth(base) error = %v", err)
	}
	err = store.UpsertAdminAuthWithAudit(ctx, "hash-upserted", false, failingAdminAuditEntry("admin_password_bootstrap"))
	requireAdminAuditFailure(t, err)
	auth, err := store.GetAdminAuth(ctx)
	if err != nil {
		t.Fatalf("GetAdminAuth(after failed audited upsert) error = %v", err)
	}
	if auth == nil || auth.PasswordHash != "hash-original" || !auth.PasswordIsBootstrap {
		t.Fatalf("admin auth after failed audited upsert = %+v, want original bootstrap hash", auth)
	}

	err = store.ChangeAdminPasswordWithAudit(ctx, "hash-changed", "hash-original", failingAdminAuditEntry("admin_password_change"))
	requireAdminAuditFailure(t, err)
	auth, err = store.GetAdminAuth(ctx)
	if err != nil {
		t.Fatalf("GetAdminAuth(after failed audited change) error = %v", err)
	}
	if auth == nil || auth.PasswordHash != "hash-original" || !auth.PasswordIsBootstrap {
		t.Fatalf("admin auth after failed audited password change = %+v, want original bootstrap hash", auth)
	}
	requireNoAdminAuditRows(t, store, ctx)
}

func TestUpsertMaliciousFindingRejectsNonArrayVersions(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "MAL-invalid-versions",
		Ecosystem: "npm",
		Name:      "bad-versions",
		Versions:  json.RawMessage(`{"introduced":"1.0.0"}`),
		Source:    "openssf",
		RiskType:  "malware",
		Severity:  "CRITICAL",
		Summary:   "invalid versions shape",
		CreatedBy: "feed",
	})
	if err == nil {
		t.Fatal("UpsertMaliciousFinding() error = nil, want invalid versions error")
	}
	if !strings.Contains(err.Error(), "MAL-invalid-versions") {
		t.Fatalf("UpsertMaliciousFinding() error = %q, want finding ID", err)
	}

	findings, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "bad-versions", Version: "2.0.0"},
	})
	if err != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("FindMaliciousBatch() = %+v, want rejected finding absent", findings)
	}
}

func TestCountVulnerabilitiesBySourceAgainstDocker(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for _, vuln := range []*db.Vulnerability{
		{
			ID: "GHSA-count-0001", Summary: "count one", Severity: "LOW", Published: now, Modified: now,
			Sources: []db.VulnerabilitySource{{Source: "ghsa", SourceID: "GHSA-count-0001"}},
		},
		{
			ID: "GHSA-count-0002", Summary: "count two", Severity: "LOW", Published: now, Modified: now,
			Sources: []db.VulnerabilitySource{{Source: "ghsa", SourceID: "GHSA-count-0002"}},
		},
		{
			ID: "OSV-count-0001", Summary: "other source", Severity: "LOW", Published: now, Modified: now,
			Sources: []db.VulnerabilitySource{{Source: "osv", SourceID: "OSV-count-0001"}},
		},
	} {
		if err := store.UpsertVulnerability(ctx, vuln); err != nil {
			t.Fatalf("UpsertVulnerability(%s) error = %v", vuln.ID, err)
		}
	}

	if count, err := store.CountVulnerabilitiesBySource(ctx, "ghsa"); err != nil || count != 2 {
		t.Fatalf("CountVulnerabilitiesBySource(ghsa) = %d, %v; want 2 nil", count, err)
	}
	if count, err := store.CountVulnerabilitiesBySource(ctx, "osv"); err != nil || count != 1 {
		t.Fatalf("CountVulnerabilitiesBySource(osv) = %d, %v; want 1 nil", count, err)
	}
	if count, err := store.CountVulnerabilitiesBySource(ctx, "nvd"); err != nil || count != 0 {
		t.Fatalf("CountVulnerabilitiesBySource(nvd) = %d, %v; want 0 nil", count, err)
	}
}

// TestUpsertMaliciousFindingRefreshesUpdatedAtOnUnchangedResync guards the
// OpenSSF sync contract: pruneStaleFindings withdraws findings whose updated_at
// predates the sync start, so every entry re-seen in a sync -- even one whose
// content is byte-for-byte identical to the stored row -- must have its
// updated_at refreshed. If the no-op upsert skips the timestamp, the very next
// sync of an unchanged catalog treats all live malware as stale and withdraws
// it (231k findings vanished this way in production).
func TestUpsertMaliciousFindingRefreshesUpdatedAtOnUnchangedResync(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	mf := &db.MaliciousFinding{
		ID:        "MAL-resync-updated-at",
		Ecosystem: "npm",
		Name:      "resync-guard",
		Source:    "openssf",
		RiskType:  "malware",
		Severity:  "CRITICAL",
		Summary:   "supply chain malware that must survive unchanged resyncs",
	}

	if err := store.UpsertMaliciousFinding(ctx, mf); err != nil {
		t.Fatalf("UpsertMaliciousFinding(initial) error = %v", err)
	}
	var first time.Time
	if err := store.pool.QueryRow(ctx, `SELECT updated_at FROM malicious_findings WHERE id = $1`, mf.ID).Scan(&first); err != nil {
		t.Fatalf("read initial updated_at: %v", err)
	}

	// Re-import the identical entry, exactly as a subsequent unchanged feed sync does.
	if err := store.UpsertMaliciousFinding(ctx, mf); err != nil {
		t.Fatalf("UpsertMaliciousFinding(resync) error = %v", err)
	}
	var second time.Time
	if err := store.pool.QueryRow(ctx, `SELECT updated_at FROM malicious_findings WHERE id = $1`, mf.ID).Scan(&second); err != nil {
		t.Fatalf("read resynced updated_at: %v", err)
	}

	if !second.After(first) {
		t.Fatalf("updated_at not refreshed on unchanged resync (first=%s second=%s); the cutoff prune would withdraw live malware", first, second)
	}
}

func TestUpsertVulnerabilityRejectsNonArrayAffectedVersionJSON(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:        "GHSA-invalid-version-json",
		Summary:   "invalid affected package version JSON",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "bad-vuln-range",
			VersionRanges:    json.RawMessage(`{"introduced":"1.0.0"}`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	})
	if err == nil {
		t.Fatal("UpsertVulnerability(non-array version_ranges) error = nil, want rejection")
	}
	if !strings.Contains(err.Error(), "GHSA-invalid-version-json") || !strings.Contains(err.Error(), "version_ranges") {
		t.Fatalf("UpsertVulnerability(non-array version_ranges) error = %q, want ID and field", err)
	}

	err = store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:        "GHSA-invalid-versions-affected",
		Summary:   "invalid affected versions JSON",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "bad-vuln-versions",
			VersionRanges:    json.RawMessage(`[]`),
			VersionsAffected: json.RawMessage(`{"all":true}`),
		}},
	})
	if err == nil {
		t.Fatal("UpsertVulnerability(non-array versions_affected) error = nil, want rejection")
	}
	if !strings.Contains(err.Error(), "GHSA-invalid-versions-affected") || !strings.Contains(err.Error(), "versions_affected") {
		t.Fatalf("UpsertVulnerability(non-array versions_affected) error = %q, want ID and field", err)
	}
}

func TestUpsertMaliciousFindingRejectsMalformedVersionRanges(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:            "MAL-invalid-version-ranges",
		Ecosystem:     "npm",
		Name:          "bad-ranges",
		VersionRanges: json.RawMessage(`{"introduced":"1.0.0"}`),
		Source:        "openssf",
		RiskType:      "malware",
		Severity:      "CRITICAL",
		Summary:       "invalid version ranges shape",
		CreatedBy:     "feed",
	})
	if err == nil {
		t.Fatal("UpsertMaliciousFinding() error = nil, want invalid version_ranges error")
	}
	if !strings.Contains(err.Error(), "MAL-invalid-version-ranges") || !strings.Contains(err.Error(), "version_ranges") {
		t.Fatalf("UpsertMaliciousFinding() error = %q, want finding ID and field", err)
	}

	findings, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "bad-ranges", Version: "2.0.0"},
	})
	if err != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("FindMaliciousBatch() = %+v, want rejected finding absent", findings)
	}
}

func TestPostgresDomainConstraintsRejectInvalidFindingAndQueueValues(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:        "GHSA-invalid-ecosystem",
		Summary:   "invalid ecosystem",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem: "npmm",
			Name:      "left-pad",
		}},
	}); err == nil {
		t.Fatal("UpsertVulnerability(invalid ecosystem) error = nil, want rejection")
	}

	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "MAL-invalid-risk",
		Ecosystem: "npm",
		Name:      "evil-risk",
		Source:    "openssf",
		RiskType:  "other",
		Severity:  "CRITICAL",
		Summary:   "invalid risk type",
	}); err == nil {
		t.Fatal("UpsertMaliciousFinding(invalid risk_type) error = nil, want rejection")
	}

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "CVE-2026-0001",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "manual-id",
		Severity:    "HIGH",
		Summary:     "invalid manual ID",
	}); err == nil {
		t.Fatal("UpsertManualAdvisory(feed-owned id) error = nil, want rejection")
	}

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{
		Ecosystem: "npm",
		Name:      "bad-priority",
		Source:    "socket",
		Priority:  4,
	}); err == nil {
		t.Fatal("EnqueueRefresh(priority 4) error = nil, want rejection")
	}

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO refresh_queue (ecosystem, name, source, priority, status)
		VALUES ('npm', 'bad-status', 'socket', 1, 'waiting')`); err == nil {
		t.Fatal("direct refresh_queue insert with invalid status error = nil, want check constraint")
	}

	if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:       "bad-feed-counts",
		LastSyncStatus: "success",
		EntriesSynced:  2,
		EntriesTotal:   1,
	}); err == nil {
		t.Fatal("UpsertFeedSyncStatus(entries_synced > entries_total) error = nil, want rejection")
	}

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO feed_sync_status (feed_name, last_sync_status, entries_synced, entries_total)
		VALUES ('bad-feed-status', 'failed', 0, 0)`); err == nil {
		t.Fatal("direct feed_sync_status insert with invalid status error = nil, want check constraint")
	}

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO feed_sync_status (feed_name, last_sync_status, entries_synced, entries_total, last_sync_duration)
		VALUES ('bad-feed-counts', 'success', -1, -2, '-1 second'::interval)`); err == nil {
		t.Fatal("direct feed_sync_status insert with invalid counts/duration error = nil, want check constraint")
	}
}

func TestPostgresSeverityConstraintRejectsInvalidDirectWrites(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities (id, summary, severity, published, modified)
		VALUES ('GHSA-invalid-severity', 'bad severity', 'INFO', NOW(), NOW())`); err == nil {
		t.Fatal("direct vulnerability insert with INFO severity error = nil, want check constraint")
	}

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO malicious_findings (id, ecosystem, name, source, risk_type, severity, summary)
		VALUES ('MAL-invalid-severity', 'npm', 'evil-severity', 'openssf', 'malware', 'INFO', 'bad severity')`); err == nil {
		t.Fatal("direct malicious insert with INFO severity error = nil, want check constraint")
	}
}

func TestDeleteMaliciousFindingForSourcePreservesOtherSources(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:source-scoped-mal",
		FindingType: "malicious",
		Ecosystem:   "npm",
		Name:        "manual-owned",
		Severity:    "CRITICAL",
		RiskType:    "malware",
		Summary:     "manual malware",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory() error = %v", err)
	}
	if err := store.DeleteMaliciousFindingForSource(ctx, "manual:source-scoped-mal", "socket"); err != nil {
		t.Fatalf("DeleteMaliciousFindingForSource(manual/socket) error = %v", err)
	}
	manual, err := store.ListManualAdvisories(ctx, 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories() error = %v", err)
	}
	if len(manual) != 1 || manual[0].ID != "manual:source-scoped-mal" {
		t.Fatalf("manual advisories after wrong-source delete = %+v, want manual row preserved", manual)
	}

	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "MAL-source-scoped",
		Ecosystem: "npm",
		Name:      "source-owned",
		Versions:  json.RawMessage(`["1.0.0"]`),
		Source:    "socket",
		RiskType:  "malware",
		Severity:  "CRITICAL",
		Summary:   "socket malware",
		CreatedBy: "feed",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding(socket) error = %v", err)
	}
	if err := store.DeleteMaliciousFindingForSource(ctx, "MAL-source-scoped", "openssf"); err != nil {
		t.Fatalf("DeleteMaliciousFindingForSource(wrong source) error = %v", err)
	}
	findings, err := store.FindMalicious(ctx, "npm", "source-owned", "1.0.0")
	if err != nil {
		t.Fatalf("FindMalicious(after wrong source delete) error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("FindMalicious(after wrong source delete) = %+v, want socket row preserved", findings)
	}

	if err := store.DeleteMaliciousFindingForSource(ctx, "MAL-source-scoped", "socket"); err != nil {
		t.Fatalf("DeleteMaliciousFindingForSource(socket) error = %v", err)
	}
	findings, err = store.FindMalicious(ctx, "npm", "source-owned", "1.0.0")
	if err != nil {
		t.Fatalf("FindMalicious(after matching source delete) error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("FindMalicious(after matching source delete) = %+v, want removed", findings)
	}
}

func TestFindMaliciousSinglePackageIncludesRequestedVersion(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:            "MAL-requested-version",
		Ecosystem:     "npm",
		Name:          "versioned-evil",
		VersionRanges: json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]`),
		Versions:      json.RawMessage(`["2.1.5-bad"]`),
		Source:        "openssf",
		RiskType:      "malware",
		Severity:      "CRITICAL",
		Summary:       "versioned malicious package",
		CreatedBy:     "feed",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding() error = %v", err)
	}

	rangeHit, err := store.FindMalicious(ctx, "npm", "versioned-evil", "1.5.0")
	if err != nil {
		t.Fatalf("FindMalicious(range hit) error = %v", err)
	}
	if len(rangeHit) != 1 || rangeHit[0].Version != "1.5.0" {
		t.Fatalf("FindMalicious(range hit) = %+v, want requested version", rangeHit)
	}

	explicitHit, err := store.FindMalicious(ctx, "npm", "versioned-evil", "2.1.5-bad")
	if err != nil {
		t.Fatalf("FindMalicious(explicit hit) error = %v", err)
	}
	if len(explicitHit) != 1 || explicitHit[0].Version != "2.1.5-bad" {
		t.Fatalf("FindMalicious(explicit hit) = %+v, want requested version", explicitHit)
	}
}

func TestDashboardStatsAndVulnerabilityUpsertsPreserveCurrentFindingState(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	vuln := &db.Vulnerability{
		ID:        "GHSA-noop-upsert-0001",
		Summary:   "stable vulnerability",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Sources:   []db.VulnerabilitySource{{Source: "osv", SourceID: "GHSA-noop-upsert-0001"}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "stable-left-pad",
			VersionRanges:    json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"0"}]}]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}
	if err := store.UpsertVulnerability(ctx, vuln); err != nil {
		t.Fatalf("UpsertVulnerability(first) error = %v", err)
	}
	var firstVulnUpdatedAt, firstAffectedUpdatedAt time.Time
	if err := store.pool.QueryRow(ctx, `SELECT updated_at FROM vulnerabilities WHERE id = $1`, vuln.ID).Scan(&firstVulnUpdatedAt); err != nil {
		t.Fatalf("read first vulnerability updated_at: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT updated_at FROM affected_packages WHERE vulnerability_id = $1 AND ecosystem = 'npm' AND name = 'stable-left-pad'`, vuln.ID).Scan(&firstAffectedUpdatedAt); err != nil {
		t.Fatalf("read first affected package updated_at: %v", err)
	}

	time.Sleep(20 * time.Millisecond)
	if err := store.UpsertVulnerability(ctx, vuln); err != nil {
		t.Fatalf("UpsertVulnerability(identical) error = %v", err)
	}
	var secondVulnUpdatedAt, secondAffectedUpdatedAt time.Time
	if err := store.pool.QueryRow(ctx, `SELECT updated_at FROM vulnerabilities WHERE id = $1`, vuln.ID).Scan(&secondVulnUpdatedAt); err != nil {
		t.Fatalf("read second vulnerability updated_at: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT updated_at FROM affected_packages WHERE vulnerability_id = $1 AND ecosystem = 'npm' AND name = 'stable-left-pad'`, vuln.ID).Scan(&secondAffectedUpdatedAt); err != nil {
		t.Fatalf("read second affected package updated_at: %v", err)
	}
	if !secondVulnUpdatedAt.Equal(firstVulnUpdatedAt) {
		t.Fatalf("vulnerability updated_at changed on identical upsert: first=%s second=%s", firstVulnUpdatedAt, secondVulnUpdatedAt)
	}
	if !secondAffectedUpdatedAt.Equal(firstAffectedUpdatedAt) {
		t.Fatalf("affected package updated_at changed on identical upsert: first=%s second=%s", firstAffectedUpdatedAt, secondAffectedUpdatedAt)
	}

	otherSource := *vuln
	otherSource.Sources = []db.VulnerabilitySource{{Source: "ghsa", SourceID: "GHSA-noop-upsert-0001"}}
	otherSource.AffectedPackages = []db.AffectedPackage{{
		Ecosystem:        "pypi",
		Name:             "stable-pkg",
		VersionRanges:    json.RawMessage(`[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]`),
		VersionsAffected: json.RawMessage(`[]`),
	}}
	if err := store.UpsertVulnerability(ctx, &otherSource); err != nil {
		t.Fatalf("UpsertVulnerability(other source) error = %v", err)
	}
	rows, err := store.pool.Query(ctx, `SELECT ecosystem, name FROM affected_packages WHERE vulnerability_id = $1 ORDER BY ecosystem, name`, vuln.ID)
	if err != nil {
		t.Fatalf("read affected packages after source merge: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	var affected []string
	for rows.Next() {
		var ecosystem, name string
		if err := rows.Scan(&ecosystem, &name); err != nil {
			t.Fatalf("scan affected package: %v", err)
		}
		affected = append(affected, ecosystem+"/"+name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate affected packages: %v", err)
	}
	if strings.Join(affected, ",") != "npm/stable-left-pad,pypi/stable-pkg" {
		t.Fatalf("affected packages after source merge = %v, want npm and pypi rows preserved", affected)
	}

	sourceA := *vuln
	sourceA.ID = "GHSA-source-aware-upsert"
	sourceA.Summary = "source-aware upsert"
	sourceA.Sources = []db.VulnerabilitySource{{Source: "osv", SourceID: "GHSA-source-aware-upsert"}}
	sourceA.Aliases = []db.VulnerabilityAlias{{AliasID: "CVE-2026-2050"}}
	sourceA.References = []db.VulnerabilityReference{
		{Type: "ADVISORY", URL: "https://osv.dev/vulnerability/GHSA-source-aware-upsert", Source: "osv"},
		{Type: "WEB", URL: "https://vendor.example/osv-old", Source: "osv"},
	}
	if err := store.UpsertVulnerability(ctx, &sourceA); err != nil {
		t.Fatalf("UpsertVulnerability(sourceA) error = %v", err)
	}

	sourceB := sourceA
	sourceB.Sources = []db.VulnerabilitySource{{Source: "ghsa", SourceID: "GHSA-source-aware-upsert"}}
	sourceB.Aliases = []db.VulnerabilityAlias{{AliasID: "CVE-2026-2051"}}
	sourceB.References = []db.VulnerabilityReference{
		{Type: "ADVISORY", URL: "https://github.com/advisories/GHSA-source-aware-upsert", Source: "ghsa"},
	}
	if err := store.UpsertVulnerability(ctx, &sourceB); err != nil {
		t.Fatalf("UpsertVulnerability(sourceB) error = %v", err)
	}

	sourceA.References = []db.VulnerabilityReference{
		{Type: "ADVISORY", URL: "https://osv.dev/vulnerability/GHSA-source-aware-upsert", Source: "osv"},
	}
	if err := store.UpsertVulnerability(ctx, &sourceA); err != nil {
		t.Fatalf("UpsertVulnerability(sourceA refresh) error = %v", err)
	}

	aliases := readVulnerabilityAliases(t, store, ctx, sourceA.ID)
	if strings.Join(aliases, ",") != "CVE-2026-2050,CVE-2026-2051" {
		t.Fatalf("aliases after multi-source upserts = %v, want both source aliases preserved", aliases)
	}
	refs := readVulnerabilityReferences(t, store, ctx, sourceA.ID)
	wantRefs := strings.Join([]string{
		"ghsa https://github.com/advisories/GHSA-source-aware-upsert",
		"osv https://osv.dev/vulnerability/GHSA-source-aware-upsert",
	}, ",")
	if strings.Join(refs, ",") != wantRefs {
		t.Fatalf("references after source refresh = %v, want %s", refs, wantRefs)
	}

	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem: "npm",
		Name:      "rep-risk",
		Version:   "1.0.0",
		Source:    db.ReputationSourceReversingLabs,
		Status:    "removed",
		Severity:  "MEDIUM",
		Summary:   "removed package",
	}); err != nil {
		t.Fatalf("UpsertPackageReputation(removed) error = %v", err)
	}
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem: "npm",
		Name:      "rep-mal",
		Version:   "2.0.0",
		Source:    db.ReputationSourceReversingLabs,
		Status:    "malicious",
		Severity:  "CRITICAL",
		Summary:   "malware",
	}); err != nil {
		t.Fatalf("UpsertPackageReputation(malicious) error = %v", err)
	}

	stats, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats() error = %v", err)
	}
	if stats.BySeverity["HIGH"] != 2 || stats.BySeverity["MEDIUM"] != 1 || stats.BySeverity["CRITICAL"] != 1 {
		t.Fatalf("DashboardStats().BySeverity = %#v, want two HIGH vulns plus MEDIUM/CRITICAL reputation findings", stats.BySeverity)
	}
}

func TestDashboardStatsTotalPackagesIncludesReputationAndLifecyclePackages(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	past := now.AddDate(0, 0, -1)
	soon := now.AddDate(0, 0, 1)

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:        "GHSA-dashboard-total-packages",
		Summary:   "dashboard package total fixture",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "dashboard-shared",
			VersionRanges:    json.RawMessage(`[]`),
			VersionsAffected: json.RawMessage(`[]`),
		}, {
			Ecosystem:        "pypi",
			Name:             "dashboard-vulnerability-only",
			VersionRanges:    json.RawMessage(`[]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "MAL-dashboard-shared",
		Ecosystem: "npm",
		Name:      "dashboard-shared",
		Source:    "openssf",
		RiskType:  "malware",
		Severity:  "CRITICAL",
		Summary:   "overlaps vulnerability package",
		CreatedBy: "feed",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding() error = %v", err)
	}

	for _, rep := range []db.PackageReputation{
		{
			Ecosystem: "npm",
			Name:      "dashboard-reputation-only",
			Version:   "1.0.0",
			Source:    db.ReputationSourceReversingLabs,
			Status:    "removed",
			Severity:  "MEDIUM",
			Summary:   "removed package version",
		},
		{
			Ecosystem: "npm",
			Name:      "dashboard-reputation-only",
			Version:   "2.0.0",
			Source:    db.ReputationSourceReversingLabs,
			Status:    "risk",
			Severity:  "LOW",
			Summary:   "historical risk package version",
		},
		{
			Ecosystem: "pypi",
			Name:      "dashboard-reputation-malicious-only",
			Version:   "1.0.0",
			Source:    db.ReputationSourceReversingLabs,
			Status:    "malicious",
			Severity:  "CRITICAL",
			Summary:   "malicious reputation package",
		},
		{
			Ecosystem: "npm",
			Name:      "dashboard-benign-reputation",
			Version:   "1.0.0",
			Source:    db.ReputationSourceReversingLabs,
			Status:    "clean",
			Severity:  "LOW",
			Summary:   "clean reputation row",
		},
	} {
		rep := rep
		if err := store.UpsertPackageReputation(ctx, &rep); err != nil {
			t.Fatalf("UpsertPackageReputation(%s/%s@%s) error = %v", rep.Ecosystem, rep.Name, rep.Version, err)
		}
	}

	if _, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{
		{
			ProductSlug: "dashboard-eol-only",
			Name:        "Dashboard EOL Only",
			Releases: []db.LifecycleRelease{{
				ProductSlug: "dashboard-eol-only",
				Cycle:       "1",
				Latest:      "1.0.0",
				IsEOL:       true,
				EOLFrom:     &past,
			}},
			PackageMaps: []db.LifecyclePackageMap{{
				Ecosystem:   "gem",
				Name:        "dashboard-lifecycle-eol-only",
				ProductSlug: "dashboard-eol-only",
				PURLType:    "gem",
				PURLName:    "dashboard-lifecycle-eol-only",
				Source:      "endoflife.date",
			}},
		},
		{
			ProductSlug: "dashboard-eol-soon-only",
			Name:        "Dashboard EOL Soon Only",
			Releases: []db.LifecycleRelease{{
				ProductSlug: "dashboard-eol-soon-only",
				Cycle:       "2",
				Latest:      "2.0.0",
				EOLFrom:     &soon,
			}},
			PackageMaps: []db.LifecyclePackageMap{{
				Ecosystem:   "cargo",
				Name:        "dashboard-lifecycle-soon-only",
				ProductSlug: "dashboard-eol-soon-only",
				PURLType:    "cargo",
				PURLName:    "dashboard-lifecycle-soon-only",
				Source:      "endoflife.date",
			}},
		},
		{
			ProductSlug: "dashboard-lifecycle-overlap",
			Name:        "Dashboard Lifecycle Overlap",
			Releases: []db.LifecycleRelease{{
				ProductSlug: "dashboard-lifecycle-overlap",
				Cycle:       "1",
				Latest:      "1.0.0",
				IsEOL:       true,
				EOLFrom:     &past,
			}},
			PackageMaps: []db.LifecyclePackageMap{{
				Ecosystem:   "npm",
				Name:        "dashboard-reputation-only",
				ProductSlug: "dashboard-lifecycle-overlap",
				PURLType:    "npm",
				PURLName:    "dashboard-reputation-only",
				Source:      "endoflife.date",
			}},
		},
		{
			ProductSlug: "dashboard-healthy-lifecycle",
			Name:        "Dashboard Healthy Lifecycle",
			Releases: []db.LifecycleRelease{{
				ProductSlug:    "dashboard-healthy-lifecycle",
				Cycle:          "3",
				Latest:         "3.0.0",
				IsMaintained:   true,
				IsEOAS:         false,
				IsEOL:          false,
				IsDiscontinued: false,
			}},
			PackageMaps: []db.LifecyclePackageMap{{
				Ecosystem:   "go",
				Name:        "dashboard-healthy-lifecycle",
				ProductSlug: "dashboard-healthy-lifecycle",
				PURLType:    "golang",
				PURLName:    "dashboard-healthy-lifecycle",
				Source:      "endoflife.date",
			}},
		},
	}); err != nil {
		t.Fatalf("ReplaceLifecycleProducts() error = %v", err)
	}

	stats, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats() error = %v", err)
	}
	if stats.TotalPackages != 6 {
		t.Fatalf("DashboardStats().TotalPackages = %d, want 6 unique active finding packages", stats.TotalPackages)
	}
}

func TestImportVulnerabilityFeedRollsBackWhenStatusWriteFails(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_, _, err := store.ImportVulnerabilityFeed(ctx, "osv", []db.Vulnerability{{
		ID:        "GHSA-atomic-rollback",
		Summary:   "rollback fixture",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Sources: []db.VulnerabilitySource{{
			Source:   "osv",
			SourceID: "GHSA-atomic-rollback",
		}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem: "npm",
			Name:      "atomic-rollback",
		}},
	}}, nil, &db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncStatus: "success",
		EntriesSynced:  1,
		EntriesTotal:   1,
		Metadata:       json.RawMessage(`{`),
	})
	if err == nil {
		t.Fatal("ImportVulnerabilityFeed() error = nil, want status write failure")
	}

	findings, findErr := store.FindVulnerabilities(ctx, "npm", "atomic-rollback", "")
	if findErr != nil {
		t.Fatalf("FindVulnerabilities() error = %v", findErr)
	}
	if len(findings) != 0 {
		t.Fatalf("FindVulnerabilities() = %+v, want rollback with no findings", findings)
	}
}

func TestImportMaliciousFeedRollsBackWhenStatusWriteFails(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	_, _, err := store.ImportMaliciousFeed(ctx, "socket", []db.MaliciousFinding{{
		ID:        "MAL-atomic-rollback",
		Ecosystem: "npm",
		Name:      "atomic-malicious-rollback",
		Source:    "socket",
		Severity:  "HIGH",
		Summary:   "rollback fixture",
	}}, nil, &db.FeedSyncStatus{
		FeedName:       "socket",
		LastSyncStatus: "success",
		EntriesSynced:  1,
		EntriesTotal:   1,
		Metadata:       json.RawMessage(`{`),
	})
	if err == nil {
		t.Fatal("ImportMaliciousFeed() error = nil, want status write failure")
	}

	findings, findErr := store.ListMaliciousFindings(ctx, "socket", 10)
	if findErr != nil {
		t.Fatalf("ListMaliciousFindings() error = %v", findErr)
	}
	for _, finding := range findings {
		if finding.ID == "MAL-atomic-rollback" {
			t.Fatalf("ListMaliciousFindings() retained rolled-back finding: %+v", findings)
		}
	}
}

func TestDeleteMaliciousFindingsNotInSourcePrunesOnlyMatchingSource(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	for _, finding := range []db.MaliciousFinding{
		{ID: "MAL-prune-keep", Ecosystem: "npm", Name: "keep", Versions: json.RawMessage(`["1.0.0"]`), Source: "openssf", RiskType: "malware", Severity: "HIGH", Summary: "keep"},
		{ID: "MAL-prune-remove", Ecosystem: "npm", Name: "remove", Versions: json.RawMessage(`["1.0.0"]`), Source: "openssf", RiskType: "malware", Severity: "HIGH", Summary: "remove"},
		{ID: "MAL-prune-socket", Ecosystem: "npm", Name: "socket-owned", Versions: json.RawMessage(`["1.0.0"]`), Source: "socket", RiskType: "malware", Severity: "HIGH", Summary: "socket"},
	} {
		finding := finding
		if err := store.UpsertMaliciousFinding(ctx, &finding); err != nil {
			t.Fatalf("UpsertMaliciousFinding(%s) error = %v", finding.ID, err)
		}
	}
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:malicious-prune",
		FindingType: "malicious",
		Ecosystem:   "npm",
		Name:        "manual-prune",
		Severity:    "CRITICAL",
		RiskType:    "malware",
		Summary:     "manual",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory() error = %v", err)
	}

	pruned, err := store.DeleteMaliciousFindingsNotInSource(ctx, "openssf", []string{"MAL-prune-keep"})
	if err != nil {
		t.Fatalf("DeleteMaliciousFindingsNotInSource() error = %v", err)
	}
	if pruned != 1 {
		t.Fatalf("DeleteMaliciousFindingsNotInSource() = %d, want only stale openssf row", pruned)
	}

	checks := []struct {
		name    string
		wantLen int
	}{
		{name: "keep", wantLen: 1},
		{name: "remove", wantLen: 0},
		{name: "socket-owned", wantLen: 1},
		{name: "manual-prune", wantLen: 1},
	}
	for _, check := range checks {
		findings, err := store.FindMalicious(ctx, "npm", check.name, "1.0.0")
		if err != nil {
			t.Fatalf("FindMalicious(%s) error = %v", check.name, err)
		}
		if len(findings) != check.wantLen {
			t.Fatalf("FindMalicious(%s) = %+v, want %d findings", check.name, findings, check.wantLen)
		}
	}
}

func TestRepairCaseInsensitivePackageNamesAgainstDocker(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified)
		VALUES
			('PYSEC-repair-normalized', 'pypi repair', 'HIGH', NOW(), NOW()),
			('GHSA-nuget-repair-normalized', 'nuget repair', 'HIGH', NOW(), NOW());
		INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected)
		VALUES
			('PYSEC-repair-normalized', 'pypi', 'My.Pkg_Name', '[]'::jsonb, '["1.0.0"]'::jsonb),
			('PYSEC-repair-normalized', 'pypi', 'my-pkg-name', '[]'::jsonb, '["1.0.1"]'::jsonb),
			('GHSA-nuget-repair-normalized', 'nuget', 'Newtonsoft.Json', '[]'::jsonb, '["13.0.3"]'::jsonb);
		INSERT INTO malicious_findings(
			id, ecosystem, name, version_ranges, versions, source, risk_type, severity, summary, reference_urls, created_by
		)
		VALUES (
			'MAL-repair-normalized', 'pypi', 'Django', '[]'::jsonb, '["4.2.11"]'::jsonb,
			'openssf', 'malware', 'CRITICAL', 'mixed case malicious', '[]'::jsonb, 'feed'
		);
	`); err != nil {
		t.Fatalf("insert mixed-case legacy rows: %v", err)
	}

	repaired, err := store.RepairCaseInsensitivePackageNamesWithAudit(ctx, &db.AdminAuditEntry{
		Action:  "startup_package_name_repair",
		Details: json.RawMessage(`{"repair":"case_insensitive_package_names"}`),
	})
	if err != nil {
		t.Fatalf("RepairCaseInsensitivePackageNamesWithAudit() error = %v", err)
	}
	if repaired < 3 {
		t.Fatalf("RepairCaseInsensitivePackageNamesWithAudit() = %d, want at least affected, nuget, malicious repairs", repaired)
	}
	audit, err := store.ListAdminAuditLog(ctx, 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "startup_package_name_repair" {
		t.Fatalf("ListAdminAuditLog() = %+v, want startup_package_name_repair entry", audit)
	}
	if audit[0].IntegrityStatus != db.AdminAuditIntegrityVerified {
		t.Fatalf("startup repair audit integrity = %q, want verified", audit[0].IntegrityStatus)
	}
	details := map[string]string{}
	if err := json.Unmarshal(audit[0].Details, &details); err != nil {
		t.Fatalf("startup repair audit details are invalid JSON: %v", err)
	}
	if details["repair"] != "case_insensitive_package_names" {
		t.Fatalf("startup repair audit repair detail = %q, want case_insensitive_package_names", details["repair"])
	}
	if details["repaired"] != strconv.Itoa(repaired) {
		t.Fatalf("startup repair audit repaired detail = %q, want %d", details["repaired"], repaired)
	}

	for _, version := range []string{"1.0.0", "1.0.1"} {
		findings, err := store.FindVulnerabilities(ctx, "pypi", "my-pkg-name", version)
		if err != nil {
			t.Fatalf("FindVulnerabilities(pypi %s) error = %v", version, err)
		}
		if len(findings) != 1 || findings[0].AdvisoryID != "PYSEC-repair-normalized" || findings[0].Name != "my-pkg-name" {
			t.Fatalf("FindVulnerabilities(pypi %s) = %+v, want merged normalized advisory", version, findings)
		}
	}
	nuget, err := store.FindVulnerabilities(ctx, "nuget", "newtonsoft.json", "13.0.3")
	if err != nil {
		t.Fatalf("FindVulnerabilities(nuget) error = %v", err)
	}
	if len(nuget) != 1 || nuget[0].AdvisoryID != "GHSA-nuget-repair-normalized" || nuget[0].Name != "newtonsoft.json" {
		t.Fatalf("FindVulnerabilities(nuget) = %+v, want normalized advisory", nuget)
	}
	malicious, err := store.FindMalicious(ctx, "pypi", "django", "4.2.11")
	if err != nil {
		t.Fatalf("FindMalicious(pypi) error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "MAL-repair-normalized" || malicious[0].Name != "django" {
		t.Fatalf("FindMalicious(pypi) = %+v, want normalized malicious finding", malicious)
	}
}

func TestPostgresPrivacyExportByClientIPAuditsWithoutRawSelector(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
		ScanID:                "privacy-scan-match",
		RepoName:              "org/private",
		ScannedAt:             time.Now().UTC(),
		PackagesCount:         2,
		FindingsCount:         1,
		DurationMs:            12,
		ClientIP:              "203.0.113.10",
		ClientVersion:         "packmon/1.2.3",
		CorrelationID:         "privacy-corr-match",
		ResultDigest:          "sha256:result",
		FindingsBlocking:      true,
		BlockThreshold:        "HIGH",
		FeedStatus:            "healthy",
		FeedVersions:          map[string]string{"osv": "2026-06-28"},
		FindingIDs:            []string{"OSV-TEST"},
		FindingSeverities:     []string{"HIGH"},
		ManualAdvisoriesCount: 0,
	}); err != nil {
		t.Fatalf("InsertScanLog(match) error = %v", err)
	}
	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
		ScanID:            "privacy-scan-other",
		ScannedAt:         time.Now().UTC(),
		ClientIP:          "203.0.113.20",
		BlockThreshold:    "HIGH",
		FeedStatus:        "healthy",
		FeedVersions:      map[string]string{},
		FindingIDs:        []string{},
		FindingSeverities: []string{},
	}); err != nil {
		t.Fatalf("InsertScanLog(other) error = %v", err)
	}
	if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
		Action:  "privacy_seed_match",
		Details: json.RawMessage(`{"event":"match"}`),
		IP:      "203.0.113.10",
	}); err != nil {
		t.Fatalf("InsertAdminAuditLog(match) error = %v", err)
	}
	if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
		Action:  "privacy_seed_other",
		Details: json.RawMessage(`{"event":"other","client_ip":"203.0.113.20"}`),
		IP:      "203.0.113.20",
	}); err != nil {
		t.Fatalf("InsertAdminAuditLog(other) error = %v", err)
	}

	selector := db.PrivacyExportSelector{Type: db.PrivacySelectorClientIP, Value: "203.0.113.10"}
	export, err := store.ExportPrivacyMetadata(ctx, selector, &db.AdminAuditEntry{
		Action:  "privacy_export",
		Details: json.RawMessage(`{"operator":"cli"}`),
	})
	if err != nil {
		t.Fatalf("ExportPrivacyMetadata() error = %v", err)
	}
	if export.ScanLogCount != 1 || len(export.ScanLogs) != 1 || export.ScanLogs[0].ScanID != "privacy-scan-match" {
		t.Fatalf("export scan logs = %+v, want only matching scan", export.ScanLogs)
	}
	if export.AdminAuditCount != 1 || len(export.AdminAuditLogs) != 1 || export.AdminAuditLogs[0].Action != "privacy_seed_match" {
		t.Fatalf("export audit logs = %+v, want only matching seed audit", export.AdminAuditLogs)
	}

	audit, err := store.ListAdminAuditLog(ctx, 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "privacy_export" {
		t.Fatalf("latest audit = %+v, want privacy_export", audit)
	}
	if audit[0].IntegrityStatus != db.AdminAuditIntegrityVerified {
		t.Fatalf("privacy export audit integrity = %q, want verified", audit[0].IntegrityStatus)
	}
	if strings.Contains(string(audit[0].Details), selector.Value) {
		t.Fatalf("privacy export audit leaked raw selector value: %s", audit[0].Details)
	}
	details := map[string]string{}
	if err := json.Unmarshal(audit[0].Details, &details); err != nil {
		t.Fatalf("privacy export audit details JSON error = %v", err)
	}
	for key, want := range map[string]string{
		"operator":          "cli",
		"selector_type":     selector.Type,
		"selector_digest":   selector.Digest(),
		"scan_log_count":    "1",
		"admin_audit_count": "1",
	} {
		if details[key] != want {
			t.Fatalf("privacy export audit detail %s = %q, want %q; details=%v", key, details[key], want, details)
		}
	}
}

func TestPostgresEnrichVulnCheckRollsBackOnSourceError(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	initialCVSS := 4.5
	vuln := &db.Vulnerability{
		ID:        "CVE-2026-ROLLBACK",
		Summary:   "rollback check",
		Severity:  "MEDIUM",
		CVSSScore: &initialCVSS,
		Published: now,
		Modified:  now,
		Sources:   []db.VulnerabilitySource{{Source: "osv", SourceID: "CVE-2026-ROLLBACK"}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "rollback-pkg",
			VersionRanges:    json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"0"}]}]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}
	if err := store.UpsertVulnerability(ctx, vuln); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}

	enrichedCVSS := 9.5
	updated, err := store.EnrichVulnCheck(ctx, []db.VulnCheckEntry{{
		CVEID:         "CVE-2026-ROLLBACK",
		CVSSScore:     &enrichedCVSS,
		ExploitExists: true,
		SourceURL:     "https://vulncheck.example/CVE-2026-ROLLBACK",
		RawJSON:       json.RawMessage(`{bad json`),
	}})
	if err == nil {
		t.Fatal("EnrichVulnCheck(invalid source json) error = nil, want source upsert error")
	}
	if updated != 0 {
		t.Fatalf("EnrichVulnCheck(invalid source json) updated = %d, want 0 on rollback", updated)
	}

	var cvss sql.NullFloat64
	var exploitExists bool
	if err := store.pool.QueryRow(ctx, `
		SELECT cvss_score::float8, exploit_exists
		FROM vulnerabilities
		WHERE id = $1`, "CVE-2026-ROLLBACK").Scan(&cvss, &exploitExists); err != nil {
		t.Fatalf("read vulnerability after failed enrichment: %v", err)
	}
	if !cvss.Valid || cvss.Float64 != initialCVSS || exploitExists {
		t.Fatalf("vulnerability after failed enrichment = cvss %v exploit %v, want original %.1f false", cvss, exploitExists, initialCVSS)
	}

	var sourceRows int
	if err := store.pool.QueryRow(ctx, `
		SELECT COUNT(*)::int
		FROM vulnerability_sources
		WHERE vulnerability_id = $1 AND source = 'vulncheck'`, "CVE-2026-ROLLBACK").Scan(&sourceRows); err != nil {
		t.Fatalf("count vulncheck source rows: %v", err)
	}
	if sourceRows != 0 {
		t.Fatalf("vulncheck source rows = %d, want 0 after rollback", sourceRows)
	}
}

func TestPostgresVulnCheckEnrichmentAddsUserFacingAttribution(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const (
		advisoryID      = "OSV-2026-1160"
		cveID           = "CVE-2026-1160"
		vulnCheckSource = "https://vulncheck.com/cve/CVE-2026-1160"
	)

	vuln := &db.Vulnerability{
		ID:        advisoryID,
		Summary:   "needs VulnCheck attribution",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Aliases:   []db.VulnerabilityAlias{{AliasID: cveID}},
		Sources: []db.VulnerabilitySource{{
			Source:   "osv",
			SourceID: advisoryID,
			URL:      "https://osv.dev/vulnerability/" + advisoryID,
			RawJSON:  json.RawMessage(`{"source":"osv"}`),
		}},
		References: []db.VulnerabilityReference{{
			Type:   "ADVISORY",
			URL:    "https://osv.dev/vulnerability/" + advisoryID,
			Source: "osv",
		}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "vulncheck-attribution",
			VersionRanges:    json.RawMessage(`[{"events":[{"introduced":"0"}]}]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}
	if err := store.UpsertVulnerability(ctx, vuln); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}

	score := 9.6
	updated, err := store.EnrichVulnCheck(ctx, []db.VulnCheckEntry{{
		CVEID:         cveID,
		CVSSScore:     &score,
		ExploitExists: true,
		SourceURL:     vulnCheckSource,
		RawJSON:       json.RawMessage(`{"source":"vulncheck"}`),
	}})
	if err != nil {
		t.Fatalf("EnrichVulnCheck() error = %v", err)
	}
	if updated != 1 {
		t.Fatalf("EnrichVulnCheck() updated = %d, want 1", updated)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "vulncheck-attribution", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 1 || !hasResource(findings[0].Resources, "VulnCheck", vulnCheckSource) {
		t.Fatalf("FindVulnerabilities() = %+v, want VulnCheck resource attribution", findings)
	}

	batchFindings, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{{
		Ecosystem: "npm",
		Name:      "vulncheck-attribution",
		Version:   "1.0.0",
	}})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch() error = %v", err)
	}
	if len(batchFindings) != 1 || !hasResource(batchFindings[0].Resources, "VulnCheck", vulnCheckSource) {
		t.Fatalf("FindVulnerabilitiesBatch() = %+v, want VulnCheck resource attribution", batchFindings)
	}

	exported, err := store.ExportSync(ctx, db.SyncExportOptions{
		SnapshotAt: time.Now().UTC().Add(time.Minute),
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("ExportSync() error = %v", err)
	}
	if !syncExportReferencesContain(exported.Vulnerabilities, advisoryID, "VULNCHECK", vulnCheckSource) {
		t.Fatalf("ExportSync().Vulnerabilities = %+v, want VulnCheck reference attribution", exported.Vulnerabilities)
	}
}

func hasResource(resources []domain.ResourceLink, label, targetURL string) bool {
	for _, resource := range resources {
		if resource.Label == label && resource.URL == targetURL {
			return true
		}
	}
	return false
}

func syncExportReferencesContain(vulns []db.SyncVulnerability, advisoryID, refType, targetURL string) bool {
	for _, vuln := range vulns {
		if vuln.ID != advisoryID {
			continue
		}
		var refs []db.VulnerabilityReference
		if err := json.Unmarshal([]byte(vuln.References), &refs); err != nil {
			return false
		}
		for _, ref := range refs {
			if ref.Type == refType && ref.URL == targetURL {
				return true
			}
		}
	}
	return false
}

func TestPostgresRefreshQueueLifecycle(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

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
	created, position, err = store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "left-pad", Source: "socket", Priority: 0})
	if err != nil {
		t.Fatalf("EnqueueRefresh(processing duplicate) error = %v", err)
	}
	if created || position <= 0 {
		t.Fatalf("EnqueueRefresh(processing duplicate) = created %v position %d, want existing processing job", created, position)
	}
	processingJobs, err := store.ListQueueJobs(ctx, "processing", 10)
	if err != nil {
		t.Fatalf("ListQueueJobs(processing) error = %v", err)
	}
	if len(processingJobs) != 1 || processingJobs[0].ID != jobID || processingJobs[0].ProcessedAt == nil {
		t.Fatalf("processing jobs after duplicate enqueue = %+v, want claimed job %d still processing", processingJobs, jobID)
	}
	pendingAfterProcessingDuplicate, err := store.ListQueueJobs(ctx, "pending", 10)
	if err != nil {
		t.Fatalf("ListQueueJobs(pending after processing duplicate) error = %v", err)
	}
	for _, pendingJob := range pendingAfterProcessingDuplicate {
		if pendingJob.ID == jobID {
			t.Fatalf("processing job %d was requeued as pending after duplicate enqueue", jobID)
		}
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
}

func TestDeleteManualAdvisoryRejectsFeedOnlyIDAndPreservesFeedData(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:       "GHSA-feed-only",
		Summary:  "feed vuln",
		Severity: "HIGH",
		Sources: []db.VulnerabilitySource{{
			Source:   "ghsa",
			SourceID: "GHSA-feed-only",
		}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "left-pad",
			VersionRanges:    json.RawMessage("[]"),
			VersionsAffected: json.RawMessage("[]"),
		}},
	}); err != nil {
		t.Fatalf("UpsertVulnerability(feed) error = %v", err)
	}

	if err := store.DeleteManualAdvisory(ctx, "GHSA-feed-only"); err == nil {
		t.Fatal("DeleteManualAdvisory(feed-only id) error = nil, want failure")
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 1 || findings[0].AdvisoryID != "GHSA-feed-only" {
		t.Fatalf("findings after feed-only manual delete = %+v, want feed finding preserved", findings)
	}
}

func TestUpsertManualAdvisoryTypeChangeRollsBackWhenCounterpartDeleteFails(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:atomic",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "manual vulnerability",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(vulnerability) error = %v", err)
	}

	if _, err := store.pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION fail_manual_atomic_withdraw() RETURNS trigger AS $$
		BEGIN
			IF NEW.withdrawn IS NOT NULL AND OLD.withdrawn IS NULL THEN
				RAISE EXCEPTION 'forced manual withdraw failure';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER fail_manual_atomic_withdraw
		BEFORE UPDATE ON vulnerabilities
		FOR EACH ROW
		WHEN (OLD.id = 'manual:atomic')
		EXECUTE FUNCTION fail_manual_atomic_withdraw();`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}

	err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:atomic",
		FindingType: "malicious",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "CRITICAL",
		RiskType:    "malware",
		Summary:     "manual malicious",
	})
	if err == nil {
		t.Fatal("UpsertManualAdvisory(type change) error = nil, want forced delete failure")
	}

	manual, err := store.ListManualAdvisories(ctx, 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories() error = %v", err)
	}
	if len(manual) != 1 || manual[0].ID != "manual:atomic" || manual[0].FindingType != "vulnerability" {
		t.Fatalf("manual advisories after failed type change = %+v, want original vulnerability only", manual)
	}
	malicious, err := store.FindMalicious(ctx, "npm", "left-pad", "1.0.0")
	if err != nil {
		t.Fatalf("FindMalicious() error = %v", err)
	}
	if len(malicious) != 0 {
		t.Fatalf("malicious findings after failed type change = %+v, want rollback", malicious)
	}
}

func TestUpsertManualAdvisoryWithAuditRejectsStaleRevision(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:stale",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "MEDIUM",
		Summary:     "original",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(create) error = %v", err)
	}
	loaded, err := store.GetManualAdvisory(ctx, "manual:stale")
	if err != nil {
		t.Fatalf("GetManualAdvisory() error = %v", err)
	}
	if loaded == nil || loaded.UpdatedAt.IsZero() {
		t.Fatalf("GetManualAdvisory() = %+v, want revision", loaded)
	}

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:stale",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "concurrent",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(concurrent) error = %v", err)
	}

	err = store.UpsertManualAdvisoryWithAudit(ctx, &db.ManualAdvisory{
		ID:          "manual:stale",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "LOW",
		Summary:     "stale submit",
		UpdatedAt:   loaded.UpdatedAt,
	}, &db.AdminAuditEntry{Action: "advisory_update"})
	if !errors.Is(err, db.ErrConflict) {
		t.Fatalf("UpsertManualAdvisoryWithAudit(stale) error = %v, want ErrConflict", err)
	}

	current, err := store.GetManualAdvisory(ctx, "manual:stale")
	if err != nil {
		t.Fatalf("GetManualAdvisory(after stale) error = %v", err)
	}
	if current == nil || current.Summary != "concurrent" || current.Severity != "HIGH" {
		t.Fatalf("manual advisory after stale update = %+v, want concurrent edit preserved", current)
	}
	audit, err := store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("audit after stale update = %+v, want none", audit)
	}
}

func TestManualAdvisoryWithAuditRollsBackOnAuditFailure(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	err := store.UpsertManualAdvisoryWithAudit(ctx, &db.ManualAdvisory{
		ID:          "manual:audit-upsert-rollback",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "should roll back when audit insert fails",
	}, failingAdminAuditEntry("advisory_update"))
	requireAdminAuditFailure(t, err)
	advisory, err := store.GetManualAdvisory(ctx, "manual:audit-upsert-rollback")
	if err != nil {
		t.Fatalf("GetManualAdvisory(after failed audited upsert) error = %v", err)
	}
	if advisory != nil {
		t.Fatalf("manual advisory after failed audited upsert = %+v, want nil", advisory)
	}

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:audit-delete-rollback",
		FindingType: "malicious",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "CRITICAL",
		RiskType:    "malware",
		Summary:     "should survive failed audited delete",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(base malicious) error = %v", err)
	}
	err = store.DeleteManualAdvisoryWithAudit(ctx, "manual:audit-delete-rollback", failingAdminAuditEntry("advisory_delete"))
	requireAdminAuditFailure(t, err)
	advisory, err = store.GetManualAdvisory(ctx, "manual:audit-delete-rollback")
	if err != nil {
		t.Fatalf("GetManualAdvisory(after failed audited delete) error = %v", err)
	}
	if advisory == nil || advisory.FindingType != "malicious" || advisory.Summary != "should survive failed audited delete" {
		t.Fatalf("manual advisory after failed audited delete = %+v, want original malicious advisory", advisory)
	}
	requireNoAdminAuditRows(t, store, ctx)
}

func TestUpsertManualAdvisoryWaitsForPerIDAdvisoryLock(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	conn, err := store.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer conn.Release()

	lockKey := manualAdvisoryLockKey("manual:locked")
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		t.Fatalf("acquire manual advisory lock: %v", err)
	}
	defer func() {
		var unlocked bool
		if err := conn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, lockKey).Scan(&unlocked); err != nil {
			t.Fatalf("release manual advisory lock: %v", err)
		}
		if !unlocked {
			t.Fatal("manual advisory lock was not held")
		}
	}()

	blockedCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	err = store.UpsertManualAdvisory(blockedCtx, &db.ManualAdvisory{
		ID:          "manual:locked",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "blocked by per-id advisory lock",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("UpsertManualAdvisory while per-id lock held error = %v, want context deadline", err)
	}
}

func TestReplaceEPSSScoresStreamIsAtomicAndClearsStaleScores(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for _, id := range []string{"CVE-2026-9101", "CVE-2026-9102"} {
		if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
			ID:        id,
			Summary:   "EPSS streaming test",
			Severity:  "HIGH",
			Published: now,
			Modified:  now,
			Sources:   []db.VulnerabilitySource{{Source: "osv", SourceID: id}},
			AffectedPackages: []db.AffectedPackage{{
				Ecosystem:        "npm",
				Name:             "epss-streaming-test",
				VersionRanges:    json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"0"}]}]`),
				VersionsAffected: json.RawMessage(`[]`),
			}},
		}); err != nil {
			t.Fatalf("UpsertVulnerability(%s) error = %v", id, err)
		}
	}
	if updated, err := store.SetEPSSScores(ctx, []db.EPSSEntry{
		{CVEID: "CVE-2026-9101", Score: 0.91, Percentile: 0.99},
		{CVEID: "CVE-2026-9102", Score: 0.42, Percentile: 0.77},
	}); err != nil || updated != 2 {
		t.Fatalf("SetEPSSScores() = %d, %v; want 2 nil", updated, err)
	}

	updated, cleared, total, err := store.ReplaceEPSSScoresStream(ctx, func(yield func([]db.EPSSEntry) error) error {
		return yield([]db.EPSSEntry{{CVEID: "CVE-2026-9101", Score: 0.11, Percentile: 0.22}})
	})
	if err != nil || updated != 1 || cleared != 1 || total != 1 {
		t.Fatalf("ReplaceEPSSScoresStream() = %d, %d, %d, %v; want 1 1 1 nil", updated, cleared, total, err)
	}
	score, percentile := readEPSSScore(t, store, ctx, "CVE-2026-9101")
	if !score.Valid || !percentile.Valid || score.Float64 < 0.10 || score.Float64 > 0.12 || percentile.Float64 < 0.21 || percentile.Float64 > 0.23 {
		t.Fatalf("CVE-2026-9101 EPSS = %v/%v, want 0.11/0.22", score, percentile)
	}
	score, percentile = readEPSSScore(t, store, ctx, "CVE-2026-9102")
	if score.Valid || percentile.Valid {
		t.Fatalf("CVE-2026-9102 EPSS = %v/%v, want cleared", score, percentile)
	}
	exported, err := store.ExportSync(ctx, db.SyncExportOptions{SnapshotAt: time.Now().UTC().Add(time.Minute), Limit: 100})
	if err != nil {
		t.Fatalf("ExportSync() error = %v", err)
	}
	exportedScore, exportedPercentile, ok := syncVulnerabilityExportEPSS(exported.Vulnerabilities, "CVE-2026-9101")
	if !ok || exportedScore == nil || exportedPercentile == nil || *exportedScore < 0.10 || *exportedScore > 0.12 || *exportedPercentile < 0.21 || *exportedPercentile > 0.23 {
		t.Fatalf("ExportSync() EPSS = score %v percentile %v ok %v, want 0.11/0.22", exportedScore, exportedPercentile, ok)
	}

	if updated, err := store.SetEPSSScores(ctx, []db.EPSSEntry{{CVEID: "CVE-2026-9101", Score: 0.33, Percentile: 0.44}}); err != nil || updated != 1 {
		t.Fatalf("SetEPSSScores(reset) = %d, %v; want 1 nil", updated, err)
	}
	streamErr := errors.New("stream stopped")
	if _, _, _, err := store.ReplaceEPSSScoresStream(ctx, func(yield func([]db.EPSSEntry) error) error {
		if err := yield([]db.EPSSEntry{{CVEID: "CVE-2026-9101", Score: 0.88, Percentile: 0.89}}); err != nil {
			return err
		}
		return streamErr
	}); !errors.Is(err, streamErr) {
		t.Fatalf("ReplaceEPSSScoresStream(failing) error = %v, want %v", err, streamErr)
	}
	score, percentile = readEPSSScore(t, store, ctx, "CVE-2026-9101")
	if !score.Valid || !percentile.Valid || score.Float64 < 0.32 || score.Float64 > 0.34 || percentile.Float64 < 0.43 || percentile.Float64 > 0.45 {
		t.Fatalf("CVE-2026-9101 EPSS after rollback = %v/%v, want 0.33/0.44", score, percentile)
	}
}

func TestReplaceEPSSScoresRejectsEmptyOrMalformedSnapshotWithoutClearing(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:        "CVE-2026-9201",
		Summary:   "EPSS validation guard test",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Sources:   []db.VulnerabilitySource{{Source: "osv", SourceID: "CVE-2026-9201"}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "epss-validation-test",
			VersionRanges:    json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"0"}]}]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}

	tests := []struct {
		name string
		run  func() (updated, cleared int, err error)
	}{
		{
			name: "empty slice",
			run: func() (int, int, error) {
				return store.ReplaceEPSSScores(ctx, nil)
			},
		},
		{
			name: "empty stream",
			run: func() (int, int, error) {
				updated, cleared, _, err := store.ReplaceEPSSScoresStream(ctx, func(func([]db.EPSSEntry) error) error {
					return nil
				})
				return updated, cleared, err
			},
		},
		{
			name: "empty cve id",
			run: func() (int, int, error) {
				return store.ReplaceEPSSScores(ctx, []db.EPSSEntry{{CVEID: "", Score: 0.11, Percentile: 0.22}})
			},
		},
		{
			name: "malformed cve id",
			run: func() (int, int, error) {
				return store.ReplaceEPSSScores(ctx, []db.EPSSEntry{{CVEID: "not-a-cve", Score: 0.11, Percentile: 0.22}})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if updated, err := store.SetEPSSScores(ctx, []db.EPSSEntry{{CVEID: "CVE-2026-9201", Score: 0.61, Percentile: 0.71}}); err != nil || updated > 1 {
				t.Fatalf("SetEPSSScores(reset) = %d, %v; want <=1 nil", updated, err)
			}

			updated, cleared, err := tt.run()
			if err == nil {
				t.Fatal("ReplaceEPSSScores() error = nil, want validation error")
			}
			if updated != 0 || cleared != 0 {
				t.Fatalf("ReplaceEPSSScores() = updated %d cleared %d, want 0/0 on rejected snapshot", updated, cleared)
			}
			score, percentile := readEPSSScore(t, store, ctx, "CVE-2026-9201")
			if !score.Valid || !percentile.Valid || score.Float64 < 0.60 || score.Float64 > 0.62 || percentile.Float64 < 0.70 || percentile.Float64 > 0.72 {
				t.Fatalf("EPSS score after rejected snapshot = %v/%v, want preserved 0.61/0.71", score, percentile)
			}
		})
	}
}

func readEPSSScore(t *testing.T, store *Store, ctx context.Context, id string) (sql.NullFloat64, sql.NullFloat64) {
	t.Helper()
	var score, percentile sql.NullFloat64
	if err := store.pool.QueryRow(ctx, `SELECT epss_score, epss_percentile FROM vulnerabilities WHERE id = $1`, id).Scan(&score, &percentile); err != nil {
		t.Fatalf("read EPSS score for %s: %v", id, err)
	}
	return score, percentile
}

func syncVulnerabilityExportEPSS(items []db.SyncVulnerability, id string) (*float64, *float64, bool) {
	for _, item := range items {
		if item.ID == id && !item.Withdrawn {
			return item.EPSSScore, item.EPSSPercentile, true
		}
	}
	return nil, nil, false
}

func readVulnerabilityAliases(t *testing.T, store *Store, ctx context.Context, advisoryID string) []string {
	t.Helper()

	rows, err := store.pool.Query(ctx, `
		SELECT alias_id
		FROM vulnerability_aliases
		WHERE vulnerability_id = $1
		ORDER BY alias_id`, advisoryID)
	if err != nil {
		t.Fatalf("read vulnerability aliases: %v", err)
	}
	defer ioutils.CloseSilently(rows)

	var aliases []string
	for rows.Next() {
		var alias string
		if err := rows.Scan(&alias); err != nil {
			t.Fatalf("scan vulnerability alias: %v", err)
		}
		aliases = append(aliases, alias)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate vulnerability aliases: %v", err)
	}
	return aliases
}

func readVulnerabilityReferences(t *testing.T, store *Store, ctx context.Context, advisoryID string) []string {
	t.Helper()

	rows, err := store.pool.Query(ctx, `
		SELECT COALESCE(source, ''), url
		FROM vulnerability_references
		WHERE vulnerability_id = $1
		ORDER BY source, url`, advisoryID)
	if err != nil {
		t.Fatalf("read vulnerability references: %v", err)
	}
	defer ioutils.CloseSilently(rows)

	var refs []string
	for rows.Next() {
		var source, url string
		if err := rows.Scan(&source, &url); err != nil {
			t.Fatalf("scan vulnerability reference: %v", err)
		}
		refs = append(refs, source+" "+url)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate vulnerability references: %v", err)
	}
	return refs
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

	now := time.Now().UTC().Truncate(time.Microsecond)
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

	normalizedVuln := &db.Vulnerability{
		ID:        "PYSEC-normalized-0001",
		Summary:   "normalized package vulnerability",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Sources:   []db.VulnerabilitySource{{Source: "osv", SourceID: "PYSEC-normalized-0001"}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "pypi",
			Name:             "My.Pkg_Name",
			VersionRanges:    json.RawMessage(`[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`),
			VersionsAffected: json.RawMessage(`[]`),
		}, {
			Ecosystem:        "nuget",
			Name:             "Newtonsoft.Json",
			VersionRanges:    json.RawMessage(`[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"14.0.0"}]}]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}
	if err := store.UpsertVulnerability(ctx, normalizedVuln); err != nil {
		t.Fatalf("UpsertVulnerability(normalized) error = %v", err)
	}
	normalizedFindings, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{
		{Ecosystem: "pypi", Name: "my-pkg-name", Version: "1.5.0"},
		{Ecosystem: "nuget", Name: "newtonsoft.json", Version: "13.0.3"},
	})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch(normalized) error = %v", err)
	}
	if len(normalizedFindings) != 2 {
		t.Fatalf("FindVulnerabilitiesBatch(normalized) = %+v, want pypi and nuget matches", normalizedFindings)
	}

	lowerSeverity := *vuln
	lowerSeverity.Severity = "LOW"
	lowerSeverity.CVSSScore = nil
	if err := store.UpsertVulnerability(ctx, &lowerSeverity); err != nil {
		t.Fatalf("UpsertVulnerability(lower severity) error = %v", err)
	}
	stillHigh, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(after lower severity) error = %v", err)
	}
	if len(stillHigh) != 1 || stillHigh[0].Severity != "HIGH" {
		t.Fatalf("severity after lower-severity upsert = %+v, want preserved HIGH", stillHigh)
	}

	withdrawnAt := now.Add(-30 * time.Minute)
	withdrawn := *vuln
	withdrawn.ID = "GHSA-withdrawn-0001"
	withdrawn.Withdrawn = &withdrawnAt
	withdrawn.Aliases = []db.VulnerabilityAlias{{AliasID: "CVE-2026-9003"}}
	withdrawn.Sources = []db.VulnerabilitySource{{Source: "ghsa", SourceID: "GHSA-withdrawn-0001"}}
	withdrawn.AffectedPackages = []db.AffectedPackage{{
		Ecosystem:        "npm",
		Name:             "withdrawn-pkg",
		VersionRanges:    json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"0"}]}]`),
		VersionsAffected: json.RawMessage(`[]`),
	}}
	if err := store.UpsertVulnerability(ctx, &withdrawn); err != nil {
		t.Fatalf("UpsertVulnerability(withdrawn) error = %v", err)
	}
	withdrawnFindings, err := store.FindVulnerabilities(ctx, "npm", "withdrawn-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(withdrawn) error = %v", err)
	}
	if len(withdrawnFindings) != 0 {
		t.Fatalf("FindVulnerabilities(withdrawn) = %+v, want no active findings", withdrawnFindings)
	}
	withdrawnBatch, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "withdrawn-pkg", Version: "1.0.0"}})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch(withdrawn) error = %v", err)
	}
	if len(withdrawnBatch) != 0 {
		t.Fatalf("FindVulnerabilitiesBatch(withdrawn) = %+v, want no active findings", withdrawnBatch)
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
	unknownAliases, err := store.FindUnknownSeverityCVEIDs(ctx, "", 100)
	if err != nil {
		t.Fatalf("FindUnknownSeverityCVEIDs() error = %v", err)
	}
	if len(unknownAliases) == 0 {
		t.Fatal("FindUnknownSeverityCVEIDs() returned no rows")
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
	if updated, cleared, err := store.ReplaceCISAKEV(ctx, []string{"CVE-2026-9002"}); err != nil || updated != 1 || cleared != 0 {
		t.Fatalf("ReplaceCISAKEV(first) = %d, %d, %v; want 1 0 nil", updated, cleared, err)
	}
	if updated, cleared, err := store.ReplaceCISAKEV(ctx, []string{"CVE-2026-9001"}); err != nil || updated != 1 || cleared != 1 {
		t.Fatalf("ReplaceCISAKEV(second) = %d, %d, %v; want 1 1 nil", updated, cleared, err)
	}
	if count, err := store.SetEPSSScores(ctx, []db.EPSSEntry{{CVEID: "CVE-2026-9001", Score: 0.91, Percentile: 0.99}}); err != nil || count != 1 {
		t.Fatalf("SetEPSSScores() = %d, %v; want 1 nil", count, err)
	}
	if count, err := store.SetEPSSScores(ctx, []db.EPSSEntry{{CVEID: "CVE-2026-9001", Score: 0.91, Percentile: 0.99}}); err != nil || count != 0 {
		t.Fatalf("SetEPSSScores(unchanged) = %d, %v; want 0 nil", count, err)
	}
	if updated, cleared, err := store.ReplaceEPSSScores(ctx, []db.EPSSEntry{{CVEID: "CVE-2026-9002", Score: 0.42, Percentile: 0.77}}); err != nil || updated != 1 || cleared != 1 {
		t.Fatalf("ReplaceEPSSScores() = %d, %d, %v; want 1 1 nil", updated, cleared, err)
	}
	vulnCheckCVSS := 9.7
	if count, err := store.EnrichVulnCheck(ctx, []db.VulnCheckEntry{{CVEID: "CVE-2026-9001", CVSSScore: &vulnCheckCVSS, ExploitExists: true, SourceURL: "https://vulncheck.example/CVE-2026-9001"}}); err != nil || count != 1 {
		t.Fatalf("EnrichVulnCheck() = %d, %v; want 1 nil", count, err)
	}
	if count, err := store.EnrichVulnCheck(ctx, []db.VulnCheckEntry{{CVEID: "CVE-2026-9001", CVSSScore: &vulnCheckCVSS, ExploitExists: true, SourceURL: "https://vulncheck.example/CVE-2026-9001"}}); err != nil || count != 0 {
		t.Fatalf("EnrichVulnCheck(unchanged) = %d, %v; want 0 nil", count, err)
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
	var sinceGHSARepair time.Time
	if err := store.pool.QueryRow(ctx, `SELECT NOW()`).Scan(&sinceGHSARepair); err != nil {
		t.Fatalf("read database time before GHSA repair: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if count, err := store.RepairGHSAAffectedPackages(ctx); err != nil || count != 1 {
		t.Fatalf("RepairGHSAAffectedPackages() = %d, %v; want 1 nil", count, err)
	}
	repairedExport, err := store.ExportSync(ctx, db.SyncExportOptions{
		Since:      &sinceGHSARepair,
		SnapshotAt: time.Now().UTC().Add(time.Minute),
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("ExportSync(after GHSA repair) error = %v", err)
	}
	if !syncVulnerabilityExportContains(repairedExport.Vulnerabilities, "GHSA-repair-0001", false) {
		t.Fatalf("ExportSync(after GHSA repair) missing repaired vulnerability row: %+v", repairedExport.Vulnerabilities)
	}

	ghsaMergeRepair := &db.Vulnerability{
		ID:        "GHSA-repair-merge-0001",
		Summary:   "repair merged affected ranges",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Sources: []db.VulnerabilitySource{
			{
				Source:   "ghsa",
				SourceID: "GHSA-repair-merge-0001",
				RawJSON: json.RawMessage(`{
					"affected":[
						{
							"package":{"ecosystem":"GitHub Actions","name":"github/codeql-action"},
							"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.26.11"},{"fixed":"3.28.3"}]}]
						},
						{
							"package":{"ecosystem":"GitHub Actions","name":"github/codeql-action"},
							"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.26.11"}]}],
							"database_specific":{"last_known_affected_version_range":"< 3.0.0"}
						}
					]
				}`),
			},
		},
		AffectedPackages: []db.AffectedPackage{
			{
				Ecosystem:     "actions",
				Name:          "github/codeql-action",
				VersionRanges: json.RawMessage(`[{"type":"ECOSYSTEM","events":[{"introduced":"2.26.11"}]}]`),
			},
		},
	}
	if err := store.UpsertVulnerability(ctx, ghsaMergeRepair); err != nil {
		t.Fatalf("UpsertVulnerability(ghsa merge repair) error = %v", err)
	}
	if count, err := store.RepairGHSAAffectedPackages(ctx); err != nil || count != 1 {
		t.Fatalf("RepairGHSAAffectedPackages(merge) = %d, %v; want 1 nil", count, err)
	}
	if findings, err := store.FindVulnerabilities(ctx, "actions", "github/codeql-action", "v4.36.2"); err != nil || len(findings) != 0 {
		t.Fatalf("FindVulnerabilities(fixed CodeQL Action) = %+v, %v; want none", findings, err)
	}
	if findings, err := store.FindVulnerabilities(ctx, "actions", "github/codeql-action", "v3.27.0"); err != nil || len(findings) != 1 {
		t.Fatalf("FindVulnerabilities(vulnerable CodeQL Action v3) = %+v, %v; want one", findings, err)
	}
	if findings, err := store.FindVulnerabilities(ctx, "actions", "github/codeql-action", "v2.27.0"); err != nil || len(findings) != 1 {
		t.Fatalf("FindVulnerabilities(vulnerable CodeQL Action v2) = %+v, %v; want one", findings, err)
	}

	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:            "MAL-docker-1",
		Ecosystem:     "npm",
		Name:          "evil-pad",
		VersionRanges: json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"9.0.0"},{"fixed":"10.0.0"}]}]`),
		Versions:      json.RawMessage(`["10.1.0-bad"]`),
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
		t.Fatalf("FindMalicious(range hit) = %+v, want malicious row", malicious)
	}
	if malicious[0].Version != "9.9.9" {
		t.Fatalf("FindMalicious(range hit) version = %q, want requested version", malicious[0].Version)
	}
	malicious, err = store.FindMalicious(ctx, "npm", "evil-pad", "10.0.0")
	if err != nil {
		t.Fatalf("FindMalicious(range miss) error = %v", err)
	}
	if len(malicious) != 0 {
		t.Fatalf("FindMalicious(range miss) = %+v, want no row", malicious)
	}
	malicious, err = store.FindMalicious(ctx, "npm", "evil-pad", "10.1.0-bad")
	if err != nil {
		t.Fatalf("FindMalicious(explicit hit) error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "MAL-docker-1" {
		t.Fatalf("FindMalicious(explicit hit) = %+v, want malicious row", malicious)
	}
	if malicious[0].Version != "10.1.0-bad" {
		t.Fatalf("FindMalicious(explicit hit) version = %q, want requested version", malicious[0].Version)
	}
	maliciousBatch, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "evil-pad", Version: "9.9.9"},
		{Ecosystem: "npm", Name: "evil-pad", Version: "10.0.0"},
		{Ecosystem: "npm", Name: "evil-pad", Version: "10.1.0-bad"},
	})
	if err != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", err)
	}
	if len(maliciousBatch) != 2 {
		t.Fatalf("FindMaliciousBatch() len = %d, want range hit and explicit hit", len(maliciousBatch))
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "MAL-normalized-pypi",
		Ecosystem: "pypi",
		Name:      "Django",
		Versions:  json.RawMessage(`["4.2.11"]`),
		Source:    "normalization-test",
		RiskType:  "malware",
		Severity:  "CRITICAL",
		Summary:   "normalized pypi malicious",
		CreatedBy: "feed",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding(normalized pypi) error = %v", err)
	}
	malicious, err = store.FindMalicious(ctx, "pypi", "django", "4.2.11")
	if err != nil {
		t.Fatalf("FindMalicious(normalized pypi) error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "MAL-normalized-pypi" || malicious[0].Name != "django" {
		t.Fatalf("FindMalicious(normalized pypi) = %+v, want canonical match", malicious)
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "MAL-normalized-nuget",
		Ecosystem: "nuget",
		Name:      "Newtonsoft.Json",
		Versions:  json.RawMessage(`["13.0.3"]`),
		Source:    "normalization-test",
		RiskType:  "malware",
		Severity:  "CRITICAL",
		Summary:   "normalized nuget malicious",
		CreatedBy: "feed",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding(normalized nuget) error = %v", err)
	}
	normalizedMaliciousBatch, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "nuget", Name: "newtonsoft.json", Version: "13.0.3"},
	})
	if err != nil {
		t.Fatalf("FindMaliciousBatch(normalized nuget) error = %v", err)
	}
	if len(normalizedMaliciousBatch) != 1 || normalizedMaliciousBatch[0].AdvisoryID != "MAL-normalized-nuget" || normalizedMaliciousBatch[0].Name != "newtonsoft.json" {
		t.Fatalf("FindMaliciousBatch(normalized nuget) = %+v, want canonical match", normalizedMaliciousBatch)
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
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          "manual:docker-bad-type",
		FindingType: "typo",
		Ecosystem:   "npm",
		Name:        "bad-type",
		Summary:     "bad type",
	}); err == nil {
		t.Fatal("UpsertManualAdvisory(unsupported finding type) error = nil")
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
		LastETag:         "etag",
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
		LastSyncStatus: "rejected",
		LastError:      "validation failed",
		EntriesSynced:  0,
		EntriesTotal:   2,
		Metadata:       json.RawMessage(`{"rejected_count":2}`),
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus(rejected) error = %v", err)
	}
	status, err = store.GetFeedSyncStatus(ctx, "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(after rejected) error = %v", err)
	}
	if status.LastSyncStatus != "rejected" || status.LastError != "validation failed" || status.EntriesSynced != 0 || status.EntriesTotal != 2 {
		t.Fatalf("rejected status = %+v", status)
	}
	if status.LastSyncAt == nil || !status.LastSyncAt.Equal(now) {
		t.Fatalf("rejected status LastSyncAt = %v, want preserved successful sync %v", status.LastSyncAt, now)
	}
	if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncStatus: "success",
		EntriesSynced:  0,
		EntriesTotal:   0,
		LastSyncAt:     &now,
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus(zero-entry success) error = %v", err)
	}
	status, err = store.GetFeedSyncStatus(ctx, "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(after zero-entry success) error = %v", err)
	}
	if status.EntriesSynced != 0 || status.EntriesTotal != 0 {
		t.Fatalf("zero-entry success counters = %d/%d, want 0/0", status.EntriesSynced, status.EntriesTotal)
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

	{
		auditedInterval := 15 * time.Minute
		if err := store.UpsertFeedConfigWithAudit(ctx,
			&db.FeedConfig{FeedName: "socket", Enabled: true, Mode: "self", SyncInterval: &auditedInterval, APIKey: "socket-secret"},
			&db.AdminAuditEntry{Action: "feed_config_save", Details: json.RawMessage(`{"feed":"socket"}`), IP: "127.0.0.1"},
		); err != nil {
			t.Fatalf("UpsertFeedConfigWithAudit() error = %v", err)
		}
		feedCfg, err = store.GetFeedConfig(ctx, "socket")
		if err != nil {
			t.Fatalf("GetFeedConfig(socket) error = %v", err)
		}
		if feedCfg == nil || feedCfg.APIKey != "socket-secret" || feedCfg.SyncInterval == nil || *feedCfg.SyncInterval != auditedInterval {
			t.Fatalf("GetFeedConfig(socket) = %+v, want audited saved config", feedCfg)
		}
		auditLog, err := store.ListAdminAuditLog(ctx, 10)
		if err != nil {
			t.Fatalf("ListAdminAuditLog(after audited feed save) error = %v", err)
		}
		if len(auditLog) == 0 || auditLog[0].Action != "feed_config_save" {
			t.Fatalf("latest audit after feed save = %+v, want feed_config_save", auditLog)
		}
		if err := store.DeleteFeedConfigWithAudit(ctx, "socket", nil, &db.AdminAuditEntry{Action: "feed_config_reset", Details: json.RawMessage(`{"feed":"socket"}`), IP: "127.0.0.1"}); err != nil {
			t.Fatalf("DeleteFeedConfigWithAudit() error = %v", err)
		}
		feedCfg, err = store.GetFeedConfig(ctx, "socket")
		if err != nil {
			t.Fatalf("GetFeedConfig(socket after reset) error = %v", err)
		}
		if feedCfg != nil {
			t.Fatalf("GetFeedConfig(socket after reset) = %+v, want nil", feedCfg)
		}
		auditLog, err = store.ListAdminAuditLog(ctx, 10)
		if err != nil {
			t.Fatalf("ListAdminAuditLog(after audited feed reset) error = %v", err)
		}
		if len(auditLog) == 0 || auditLog[0].Action != "feed_config_reset" {
			t.Fatalf("latest audit after feed reset = %+v, want feed_config_reset", auditLog)
		}
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

	loadedSettings := *settings
	time.Sleep(10 * time.Millisecond)
	if err := store.UpsertSystemSettings(ctx, &db.SystemSettings{BlockThreshold: "LOW", RateLimitPerMinute: 240, RateLimitBurst: 40}); err != nil {
		t.Fatalf("UpsertSystemSettings(concurrent) error = %v", err)
	}
	loadedSettings.BlockThreshold = "CRITICAL"
	loadedSettings.RateLimitPerMinute = 300
	loadedSettings.RateLimitBurst = 50
	err = store.UpsertSystemSettingsWithAudit(ctx, &loadedSettings, &db.AdminAuditEntry{Action: "system_settings_save", Details: json.RawMessage(`{}`), IP: "127.0.0.1"})
	if !errors.Is(err, db.ErrConflict) {
		t.Fatalf("UpsertSystemSettingsWithAudit(stale) error = %v, want ErrConflict", err)
	}
	settings, err = store.GetSystemSettings(ctx)
	if err != nil {
		t.Fatalf("GetSystemSettings(after stale) error = %v", err)
	}
	if settings == nil || settings.BlockThreshold != "LOW" || settings.RateLimitPerMinute != 240 || settings.RateLimitBurst != 40 {
		t.Fatalf("settings after stale save = %+v, want concurrent LOW settings preserved", settings)
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
	if err := store.RevokeAPIKey(ctx, keyID); err == nil {
		t.Fatal("RevokeAPIKey(already revoked) error = nil, want failure")
	}
	if err := store.DeleteAPIKey(ctx, keyID); err != nil {
		t.Fatalf("DeleteAPIKey() error = %v", err)
	}
	keys, err = store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys(after delete) error = %v", err)
	}
	// Deletion is permanent: the row is removed rather than tombstoned. The
	// deletion stays traceable through the admin audit log, and scan_log rows
	// keep their history with api_key_id cleared by ON DELETE SET NULL.
	for _, key := range keys {
		if key.ID == keyID {
			t.Fatalf("ListAPIKeys(after delete) still returns %+v, want the row permanently removed", key)
		}
	}
	if len(keys) != 0 {
		t.Fatalf("ListAPIKeys(after delete) = %+v, want no keys left", keys)
	}
	deletedKey, err := store.FindAPIKeyByHash(ctx, "hash-ci")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash(deleted) error = %v", err)
	}
	if deletedKey != nil {
		t.Fatalf("FindAPIKeyByHash(deleted) = %+v, want nil", deletedKey)
	}
	if err := store.RevokeAPIKey(ctx, keyID); err == nil {
		t.Fatal("RevokeAPIKey(deleted) error = nil, want not found")
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
		t.Fatalf("InsertAdminAuditLog(first) error = %v", err)
	}
	if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{Action: "feed_save", Details: json.RawMessage(`{"feed":"osv"}`), IP: "127.0.0.1"}); err != nil {
		t.Fatalf("InsertAdminAuditLog(second) error = %v", err)
	}
	auditLog, err := store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(auditLog) < 2 || auditLog[0].Action != "feed_save" || auditLog[1].Action != "login_success" {
		t.Fatalf("ListAdminAuditLog() = %+v, want newest feed_save then login_success", auditLog)
	}
	if auditLog[0].IntegrityStatus != "verified" || !strings.HasPrefix(auditLog[0].RowDigest, "sha256:") {
		t.Fatalf("newest audit integrity = status %q digest %q, want verified sha256", auditLog[0].IntegrityStatus, auditLog[0].RowDigest)
	}
	if auditLog[0].PreviousDigest != auditLog[1].RowDigest {
		t.Fatalf("audit digest chain = %+v, want newest previous digest to match older row digest", auditLog)
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
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem:     "npm",
		Name:          "clean-pkg",
		Version:       "1.0.0",
		Source:        db.ReputationSourceReversingLabs,
		Status:        "clean",
		Severity:      "LOW",
		Summary:       "clean package",
		LastCheckedAt: &lastChecked,
		NextCheckAt:   &nextCheck,
	}); err != nil {
		t.Fatalf("UpsertPackageReputation(clean) error = %v", err)
	}
	if _, err := store.pool.Exec(ctx,
		`UPDATE package_reputation_cache SET updated_at = NOW() - interval '48 hours' WHERE source = $1 AND name = $2`,
		db.ReputationSourceReversingLabs,
		"clean-pkg",
	); err != nil {
		t.Fatalf("age clean reputation row: %v", err)
	}
	pruned, err := store.PrunePackageReputation(ctx, db.ReputationSourceReversingLabs, time.Hour)
	if err != nil {
		t.Fatalf("PrunePackageReputation() error = %v", err)
	}
	if pruned != 1 {
		t.Fatalf("PrunePackageReputation() = %d, want 1 clean row", pruned)
	}
	reputation, err = store.FindReputationFindings(ctx, "npm", "removed-pkg", db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindings(after prune) error = %v", err)
	}
	if len(reputation) != 1 {
		t.Fatalf("FindReputationFindings(after prune) len = %d, want removed finding retained", len(reputation))
	}
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem:     "npm",
		Name:          "benign-sync-pkg",
		Version:       "1.0.0",
		Source:        db.ReputationSourceReversingLabs,
		Status:        "clean",
		Severity:      "LOW",
		Summary:       "clean package",
		LastCheckedAt: &lastChecked,
		NextCheckAt:   &nextCheck,
	}); err != nil {
		t.Fatalf("UpsertPackageReputation(benign sync) error = %v", err)
	}
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem:     "npm",
		Name:          "risk-sync-pkg",
		Version:       "1.0.0",
		Source:        db.ReputationSourceReversingLabs,
		Status:        "risk",
		Severity:      "HIGH",
		Summary:       "historical risk package",
		LastCheckedAt: &lastChecked,
		NextCheckAt:   &nextCheck,
	}); err != nil {
		t.Fatalf("UpsertPackageReputation(risk sync) error = %v", err)
	}
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem:     "npm",
		Name:          "malicious-rep-pkg",
		Version:       "1.0.0",
		Source:        db.ReputationSourceReversingLabs,
		Status:        "malicious",
		Severity:      "CRITICAL",
		Summary:       "reputation malware",
		LastCheckedAt: &lastChecked,
		NextCheckAt:   &nextCheck,
	}); err != nil {
		t.Fatalf("UpsertPackageReputation(malicious reputation) error = %v", err)
	}
	if _, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{{
		ProductSlug: "django",
		Name:        "Django",
		Releases: []db.LifecycleRelease{{
			ProductSlug: "django",
			Cycle:       "3.2",
			Latest:      "3.2.25",
			IsEOL:       true,
			EOLFrom:     &now,
		}, {
			ProductSlug: "django",
			Cycle:       "4.2",
			Latest:      "4.2.11",
			IsEOAS:      true,
			EOASFrom:    &now,
		}},
		PackageMaps: []db.LifecyclePackageMap{{
			Ecosystem:   "pypi",
			Name:        "django",
			ProductSlug: "django",
			PURLType:    "pypi",
			PURLName:    "django",
			Source:      "endoflife.date",
		}},
	}}); err != nil {
		t.Fatalf("ReplaceLifecycleProducts() error = %v", err)
	}

	// scan_log.api_key_id carries a foreign key, so the identity columns need a
	// real key rather than an invented ID.
	scanKeyID, err := store.CreateAPIKey(ctx, "n8n-import", "hash-n8n-import", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(scan identity) error = %v", err)
	}

	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
		ScanID:         "scan-1",
		RepoName:       "repo",
		BlockThreshold: "CRITICAL",
		FeedStatus:     "healthy",
		ScannedAt:      now,
		PackagesCount:  4,
		FindingsCount:  2,
		DurationMs:     10,
		ClientIP:       "127.0.0.1",
		ClientVersion:  "1.2.3",
		APIKeyID:       scanKeyID,
		APIKeyName:     "n8n-import",
		ResultDigest:   "sha256:abc123",
	}); err != nil {
		t.Fatalf("InsertScanLog() error = %v", err)
	}
	recentScans, err := store.ListRecentScans(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListRecentScans() error = %v", err)
	}
	if len(recentScans) != 1 || recentScans[0].ScanID != "scan-1" {
		t.Fatalf("ListRecentScans() = %+v, want scan-1", recentScans)
	}
	if recentScans[0].APIKeyID != scanKeyID || recentScans[0].APIKeyName != "n8n-import" {
		t.Fatalf("ListRecentScans() API key identity = (%d,%q), want (%d,n8n-import)", recentScans[0].APIKeyID, recentScans[0].APIKeyName, scanKeyID)
	}

	// Permanent key deletion must not take scan history with it: migration 046
	// relies on ON DELETE SET NULL to keep the row and clear only the reference.
	if err := store.RevokeAPIKey(ctx, scanKeyID); err != nil {
		t.Fatalf("RevokeAPIKey(scan identity) error = %v", err)
	}
	if err := store.DeleteAPIKey(ctx, scanKeyID); err != nil {
		t.Fatalf("DeleteAPIKey(scan identity) error = %v", err)
	}
	afterDelete, err := store.ListRecentScans(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListRecentScans(after key delete) error = %v", err)
	}
	if len(afterDelete) != 1 || afterDelete[0].ScanID != "scan-1" {
		t.Fatalf("ListRecentScans(after key delete) = %+v, want the scan history retained", afterDelete)
	}
	if afterDelete[0].APIKeyID != 0 {
		t.Fatalf("ListRecentScans(after key delete) APIKeyID = %d, want the reference cleared", afterDelete[0].APIKeyID)
	}
	if afterDelete[0].APIKeyName != "n8n-import" {
		t.Fatalf("ListRecentScans(after key delete) APIKeyName = %q, want the recorded label retained", afterDelete[0].APIKeyName)
	}
	if recentScans[0].ClientVersion != "1.2.3" {
		t.Fatalf("ListRecentScans() client version = %q, want retained normalized version", recentScans[0].ClientVersion)
	}
	if recentScans[0].ResultDigest != "sha256:abc123" {
		t.Fatalf("ListRecentScans() result digest = %q, want sha256:abc123", recentScans[0].ResultDigest)
	}
	scanTotals, err := store.ScanTotals(ctx)
	if err != nil {
		t.Fatalf("ScanTotals() error = %v", err)
	}
	if scanTotals.PackagesScanned != 4 || scanTotals.Findings != 2 {
		t.Fatalf("ScanTotals() = %+v, want 4/2", scanTotals)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE scan_log_totals SET packages_scanned = 41, findings = 7`); err == nil {
		t.Fatal("direct scan_log_totals update succeeded; totals must be derived from scan_log")
	}
	scanTotals, err = store.ScanTotals(ctx)
	if err != nil {
		t.Fatalf("ScanTotals(after rollup override) error = %v", err)
	}
	if scanTotals.PackagesScanned != 4 || scanTotals.Findings != 2 {
		t.Fatalf("ScanTotals(after rejected rollup override) = %+v, want derived totals 4/2", scanTotals)
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
	if got, ok := packageSearchFindingTypes(search, "npm", "left-pad", ""); !ok || got != "vulnerability" {
		t.Fatalf("SearchPackages() left-pad finding types = (%q,%v), want vulnerability", got, ok)
	}
	maliciousSearch, err := store.SearchPackages(ctx, db.PackageSearchParams{FindingType: "malicious", Limit: 20})
	if err != nil {
		t.Fatalf("SearchPackages(malicious) error = %v", err)
	}
	if !packageSearchContains(maliciousSearch, "npm", "malicious-rep-pkg") {
		t.Fatalf("SearchPackages(malicious) = %+v, want reputation-backed malicious package", maliciousSearch)
	}
	if got, ok := packageSearchFindingTypes(maliciousSearch, "npm", "malicious-rep-pkg", "1.0.0"); !ok || got != "malicious" {
		t.Fatalf("SearchPackages(malicious) finding types = (%q,%v), want malicious", got, ok)
	}
	supplySearch, err := store.SearchPackages(ctx, db.PackageSearchParams{FindingType: "supply_chain_risk", Limit: 20})
	if err != nil {
		t.Fatalf("SearchPackages(supply_chain_risk) error = %v", err)
	}
	for _, name := range []string{"removed-pkg", "risk-sync-pkg"} {
		if !packageSearchContains(supplySearch, "npm", name) {
			t.Fatalf("SearchPackages(supply_chain_risk) = %+v, want %s", supplySearch, name)
		}
		if got, ok := packageSearchFindingTypes(supplySearch, "npm", name, "1.0.0"); !ok || got != "supply_chain_risk" {
			t.Fatalf("SearchPackages(supply_chain_risk) %s finding types = (%q,%v), want supply_chain_risk", name, got, ok)
		}
	}
	if !packageSearchContainsVersion(supplySearch, "pypi", "django", "3.2.25") {
		t.Fatalf("SearchPackages(supply_chain_risk) = %+v, want django EOL version 3.2.25", supplySearch)
	}
	if got, ok := packageSearchFindingTypes(supplySearch, "pypi", "django", "3.2.25"); !ok || got != "supply_chain_risk" {
		t.Fatalf("SearchPackages(supply_chain_risk) django EOL finding types = (%q,%v), want supply_chain_risk", got, ok)
	}
	lifecycleSearch, err := store.SearchPackages(ctx, db.PackageSearchParams{FindingType: "lifecycle", Limit: 20})
	if err != nil {
		t.Fatalf("SearchPackages(lifecycle) error = %v", err)
	}
	if !packageSearchContainsVersion(lifecycleSearch, "pypi", "django", "4.2.11") {
		t.Fatalf("SearchPackages(lifecycle) = %+v, want django lifecycle version 4.2.11", lifecycleSearch)
	}
	if got, ok := packageSearchFindingTypes(lifecycleSearch, "pypi", "django", "4.2.11"); !ok || got != "lifecycle" {
		t.Fatalf("SearchPackages(lifecycle) finding types = (%q,%v), want lifecycle", got, ok)
	}
	dashboard, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats() error = %v", err)
	}
	if dashboard.TotalPackages == 0 || dashboard.TotalVulnerabilities == 0 {
		t.Fatalf("DashboardStats() = %+v, want non-zero dashboard", dashboard)
	}
	if dashboard.TotalMalicious == 0 || dashboard.TotalSupplyChainRisk < 2 || dashboard.TotalLifecycle == 0 {
		t.Fatalf("DashboardStats() = %+v, want malicious, supply-chain, and lifecycle counts", dashboard)
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
	if !syncReputationExportContains(exported.Reputation, "reversinglabs:npm/removed-pkg@1.0.0") {
		t.Fatalf("ExportSync().Reputation missing active removed package row: %+v", exported.Reputation)
	}
	if !syncReputationExportContains(exported.Reputation, "reversinglabs:npm/risk-sync-pkg@1.0.0") {
		t.Fatalf("ExportSync().Reputation missing active historical-risk package row: %+v", exported.Reputation)
	}
	if !syncReputationExportContains(exported.Reputation, "reversinglabs:npm/malicious-rep-pkg@1.0.0") {
		t.Fatalf("ExportSync().Reputation missing active malicious reputation row: %+v", exported.Reputation)
	}
	for _, id := range []string{"reversinglabs:npm/benign-sync-pkg@1.0.0"} {
		if syncReputationExportContains(exported.Reputation, id) {
			t.Fatalf("ExportSync().Reputation leaked non-active reputation row %s: %+v", id, exported.Reputation)
		}
	}
	if exported.SyncedXID == 0 {
		t.Fatalf("ExportSync().SyncedXID = 0, want database xid watermark")
	}
	if source, ok := syncVulnerabilityExportSource(exported.Vulnerabilities, "GHSA-docker-0001", false); !ok || source != "osv" {
		t.Fatalf("ExportSync().Vulnerabilities source = %q, %v; want GHSA-docker-0001 from osv", source, ok)
	}
	if source, ok := syncMaliciousExportSource(exported.Malicious, "MAL-docker-1", false); !ok || source != "openssf" {
		t.Fatalf("ExportSync().Malicious source = %q, %v; want MAL-docker-1 from openssf", source, ok)
	}
	firstPage, err := store.ExportSync(ctx, db.SyncExportOptions{SnapshotAt: time.Now().UTC().Add(time.Minute), Limit: 1})
	if err != nil {
		t.Fatalf("ExportSync(first keyset page) error = %v", err)
	}
	if !firstPage.Truncated || firstPage.NextCursor == nil || firstPage.NextCursor.VulnerabilitiesCursor == "" {
		t.Fatalf("first keyset page cursor = truncated %v cursor %+v", firstPage.Truncated, firstPage.NextCursor)
	}
	secondPage, err := store.ExportSync(ctx, db.SyncExportOptions{
		SnapshotAt:  firstPage.SyncedAt,
		SnapshotXID: firstPage.SyncedXID,
		Limit:       1,
		Cursor:      *firstPage.NextCursor,
	})
	if err != nil {
		t.Fatalf("ExportSync(second keyset page) error = %v", err)
	}
	if len(firstPage.Vulnerabilities) == 1 && len(secondPage.Vulnerabilities) == 1 && firstPage.Vulnerabilities[0].ID == secondPage.Vulnerabilities[0].ID {
		t.Fatalf("second keyset page repeated first vulnerability %+v", firstPage.Vulnerabilities[0])
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

	multiSource := *vuln
	multiSource.ID = "GHSA-source-0001"
	multiSource.Severity = "HIGH"
	multiSource.Sources = []db.VulnerabilitySource{
		{Source: "osv", SourceID: "GHSA-source-0001"},
		{Source: "ghsa", SourceID: "GHSA-source-0001"},
	}
	multiSource.AffectedPackages = []db.AffectedPackage{{
		Ecosystem:        "npm",
		Name:             "multi-source",
		VersionRanges:    json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"0"}]}]`),
		VersionsAffected: json.RawMessage(`[]`),
	}}
	if err := store.UpsertVulnerability(ctx, &multiSource); err != nil {
		t.Fatalf("UpsertVulnerability(multi source) error = %v", err)
	}
	if err := store.DeleteVulnerabilityForSource(ctx, "GHSA-source-0001", "osv"); err != nil {
		t.Fatalf("DeleteVulnerabilityForSource(osv) error = %v", err)
	}
	sourceScopedFindings, err := store.FindVulnerabilities(ctx, "npm", "multi-source", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(after source delete) error = %v", err)
	}
	if len(sourceScopedFindings) != 1 {
		t.Fatalf("FindVulnerabilities(after one source delete) = %+v, want still active via ghsa", sourceScopedFindings)
	}
	var sourceScopedWithdrawn sql.NullTime
	if err := store.pool.QueryRow(ctx, `
		SELECT withdrawn
		FROM vulnerabilities
		WHERE id = $1`, "GHSA-source-0001").Scan(&sourceScopedWithdrawn); err != nil {
		t.Fatalf("read source-scoped vulnerability withdrawn timestamp: %v", err)
	}
	if sourceScopedWithdrawn.Valid {
		t.Fatalf("source-scoped vulnerability withdrawn = %s, want NULL while ghsa source remains", sourceScopedWithdrawn.Time)
	}

	beforeSourceDelete := time.Now().UTC().Add(-time.Second)
	if err := store.DeleteVulnerabilityForSource(ctx, "GHSA-source-0001", "ghsa"); err != nil {
		t.Fatalf("DeleteVulnerabilityForSource(ghsa) error = %v", err)
	}
	sourceTombstoneExport, err := store.ExportSync(ctx, db.SyncExportOptions{
		Since:      &beforeSourceDelete,
		SnapshotAt: time.Now().UTC().Add(time.Minute),
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("ExportSync(after final source delete) error = %v", err)
	}
	if !syncVulnerabilityExportContains(sourceTombstoneExport.Vulnerabilities, "GHSA-source-0001", true) {
		t.Fatalf("ExportSync(after final source delete) missing withdrawn row: %+v", sourceTombstoneExport.Vulnerabilities)
	}

	beforeVulnerabilityDelete := time.Now().UTC().Add(-time.Second)
	if err := store.DeleteVulnerability(ctx, "GHSA-docker-0001"); err != nil {
		t.Fatalf("DeleteVulnerability() error = %v", err)
	}
	deletedVulnFindings, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(after delete) error = %v", err)
	}
	if len(deletedVulnFindings) != 0 {
		t.Fatalf("FindVulnerabilities(after delete) = %+v, want no active findings", deletedVulnFindings)
	}
	deletedVulnExport, err := store.ExportSync(ctx, db.SyncExportOptions{
		Since:      &beforeVulnerabilityDelete,
		SnapshotAt: time.Now().UTC().Add(time.Minute),
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("ExportSync(after vulnerability delete) error = %v", err)
	}
	if !syncVulnerabilityExportContains(deletedVulnExport.Vulnerabilities, "GHSA-docker-0001", true) {
		t.Fatalf("ExportSync(after vulnerability delete) missing withdrawn row: %+v", deletedVulnExport.Vulnerabilities)
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

func TestStorePrunesScanAndAdminAuditLogs(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	oldTime := time.Now().UTC().Add(-2 * time.Hour)
	recentTime := time.Now().UTC().Add(-30 * time.Minute)

	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
		ScanID:         "old-scan",
		ScannedAt:      oldTime,
		PackagesCount:  1,
		BlockThreshold: "CRITICAL",
		FeedStatus:     "healthy",
	}); err != nil {
		t.Fatalf("InsertScanLog(old) error = %v", err)
	}
	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
		ScanID:         "recent-scan",
		ScannedAt:      recentTime,
		PackagesCount:  1,
		BlockThreshold: "CRITICAL",
		FeedStatus:     "healthy",
	}); err != nil {
		t.Fatalf("InsertScanLog(recent) error = %v", err)
	}

	if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
		Action:  "retention_old",
		Details: json.RawMessage(`{"row":"old"}`),
		IP:      "127.0.0.1",
	}); err != nil {
		t.Fatalf("InsertAdminAuditLog(old) error = %v", err)
	}
	if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
		Action:  "retention_recent",
		Details: json.RawMessage(`{"row":"recent"}`),
		IP:      "127.0.0.1",
	}); err != nil {
		t.Fatalf("InsertAdminAuditLog(recent) error = %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE admin_audit_log SET created_at = $1 WHERE action = 'retention_old'`, oldTime); err != nil {
		t.Fatalf("age old audit row: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE admin_audit_log SET created_at = $1 WHERE action = 'retention_recent'`, recentTime); err != nil {
		t.Fatalf("age recent audit row: %v", err)
	}

	prunedScans, err := store.PruneScanLogs(ctx, time.Hour)
	if err != nil {
		t.Fatalf("PruneScanLogs() error = %v", err)
	}
	if prunedScans != 1 {
		t.Fatalf("PruneScanLogs() = %d, want 1", prunedScans)
	}
	scanTotals, err := store.ScanTotals(ctx)
	if err != nil {
		t.Fatalf("ScanTotals(after prune) error = %v", err)
	}
	if scanTotals.PackagesScanned != 1 || scanTotals.Findings != 0 {
		t.Fatalf("ScanTotals(after prune) = %+v, want only recent scan", scanTotals)
	}
	prunedAudit, err := store.PruneAdminAuditLogs(ctx, time.Hour)
	if err != nil {
		t.Fatalf("PruneAdminAuditLogs() error = %v", err)
	}
	if prunedAudit != 1 {
		t.Fatalf("PruneAdminAuditLogs() = %d, want 1", prunedAudit)
	}

	scans, err := store.ListRecentScans(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListRecentScans() error = %v", err)
	}
	if len(scans) != 1 || scans[0].ScanID != "recent-scan" {
		t.Fatalf("ListRecentScans() = %+v, want only recent-scan", scans)
	}
	audit, err := store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "retention_recent" {
		t.Fatalf("ListAdminAuditLog() = %+v, want only retention_recent", audit)
	}
}

func TestStoreScanLogIdempotencyKeyDeduplicatesTotals(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
		ScanID:         "scan-idempotent-1",
		ScannedAt:      now,
		BlockThreshold: "CRITICAL",
		FeedStatus:     "healthy",
		PackagesCount:  2,
		FindingsCount:  1,
		IdempotencyKey: "ci-retry-1",
		RequestDigest:  "sha256:request-a",
		ResultDigest:   "sha256:result-a",
	}); err != nil {
		t.Fatalf("InsertScanLog(first) error = %v", err)
	}
	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
		ScanID:         "scan-idempotent-duplicate",
		ScannedAt:      now.Add(time.Second),
		BlockThreshold: "CRITICAL",
		FeedStatus:     "healthy",
		PackagesCount:  200,
		FindingsCount:  100,
		IdempotencyKey: "ci-retry-1",
		RequestDigest:  "sha256:request-a",
		ResultDigest:   "sha256:result-duplicate",
	}); err != nil {
		t.Fatalf("InsertScanLog(duplicate) error = %v", err)
	}

	existing, err := store.GetScanLogByIdempotencyKey(ctx, "ci-retry-1")
	if err != nil {
		t.Fatalf("GetScanLogByIdempotencyKey() error = %v", err)
	}
	if existing == nil {
		t.Fatal("GetScanLogByIdempotencyKey() = nil, want existing scan")
	}
	if existing.ScanID != "scan-idempotent-1" || existing.RequestDigest != "sha256:request-a" || existing.ResultDigest != "sha256:result-a" {
		t.Fatalf("GetScanLogByIdempotencyKey() = %+v, want original scan metadata", existing)
	}

	recent, err := store.ListRecentScans(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListRecentScans() error = %v", err)
	}
	if len(recent) != 1 {
		t.Fatalf("ListRecentScans() len = %d, want 1: %+v", len(recent), recent)
	}
	if recent[0].IdempotencyKey != "ci-retry-1" || recent[0].RequestDigest != "sha256:request-a" {
		t.Fatalf("ListRecentScans()[0] = %+v, want idempotency metadata", recent[0])
	}

	totals, err := store.ScanTotals(ctx)
	if err != nil {
		t.Fatalf("ScanTotals() error = %v", err)
	}
	if totals.PackagesScanned != 2 || totals.Findings != 1 {
		t.Fatalf("ScanTotals() = %+v, want first insert only", totals)
	}
}

func TestStorePrunesOldTerminalRefreshQueueJobs(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	oldTime := now.Add(-48 * time.Hour)
	recentTime := now.Add(-time.Hour)

	for _, name := range []string{"old-done", "old-error", "recent-done", "old-pending", "old-paused"} {
		if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: name, Source: "socket", Priority: 1}); err != nil {
			t.Fatalf("EnqueueRefresh(%s) error = %v", name, err)
		}
	}
	oldDone := mustQueueJobID(t, store, ctx, "old-done")
	oldError := mustQueueJobID(t, store, ctx, "old-error")
	recentDone := mustQueueJobID(t, store, ctx, "recent-done")
	oldPending := mustQueueJobID(t, store, ctx, "old-pending")
	oldPaused := mustQueueJobID(t, store, ctx, "old-paused")

	if err := store.CompleteRefresh(ctx, oldDone, nil); err != nil {
		t.Fatalf("CompleteRefresh(old-done) error = %v", err)
	}
	if err := store.CompleteRefresh(ctx, oldError, errors.New("failed")); err != nil {
		t.Fatalf("CompleteRefresh(old-error) error = %v", err)
	}
	if err := store.CompleteRefresh(ctx, recentDone, nil); err != nil {
		t.Fatalf("CompleteRefresh(recent-done) error = %v", err)
	}
	if err := store.PauseQueueJob(ctx, oldPaused); err != nil {
		t.Fatalf("PauseQueueJob(old-paused) error = %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		UPDATE refresh_queue
		SET processed_at = CASE id
			WHEN $1 THEN $3
			WHEN $2 THEN $3
			WHEN $4 THEN $5
			ELSE processed_at
		END,
		requested_at = CASE id
			WHEN $6 THEN $3
			WHEN $7 THEN $3
			ELSE requested_at
		END
		WHERE id IN ($1, $2, $4, $6, $7)`,
		oldDone, oldError, oldTime, recentDone, recentTime, oldPending, oldPaused); err != nil {
		t.Fatalf("age refresh queue jobs: %v", err)
	}

	pruned, err := store.PruneRefreshQueue(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("PruneRefreshQueue() error = %v", err)
	}
	if pruned != 2 {
		t.Fatalf("PruneRefreshQueue() = %d, want 2 old terminal jobs", pruned)
	}

	jobs, err := store.ListQueueJobs(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListQueueJobs() error = %v", err)
	}
	names := make(map[string]string, len(jobs))
	for _, job := range jobs {
		names[job.Name] = job.Status
	}
	for _, name := range []string{"recent-done", "old-pending", "old-paused"} {
		if _, ok := names[name]; !ok {
			t.Fatalf("ListQueueJobs() missing %s after prune: %+v", name, jobs)
		}
	}
	for _, name := range []string{"old-done", "old-error"} {
		if _, ok := names[name]; ok {
			t.Fatalf("ListQueueJobs() retained %s after prune: %+v", name, jobs)
		}
	}
}

func TestStorePrunesOldPackageCheckStatusRows(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	oldTime := time.Now().UTC().Add(-48 * time.Hour)
	recentTime := time.Now().UTC().Add(-time.Hour)

	for _, status := range []db.PackageCheckStatus{
		{
			Ecosystem:     "npm",
			Name:          "old-socket",
			Source:        "socket",
			LastCheckedAt: &oldTime,
			NextCheckAt:   &oldTime,
			LastResult:    json.RawMessage(`{"status":"clean"}`),
		},
		{
			Ecosystem:     "npm",
			Name:          "recent-socket",
			Source:        "socket",
			LastCheckedAt: &recentTime,
			NextCheckAt:   &recentTime,
			LastResult:    json.RawMessage(`{"status":"clean"}`),
		},
		{
			Ecosystem:     "npm",
			Name:          "old-other",
			Source:        "other",
			LastCheckedAt: &oldTime,
			NextCheckAt:   &oldTime,
			LastResult:    json.RawMessage(`{"status":"clean"}`),
		},
	} {
		status := status
		if err := store.UpsertPackageCheckStatus(ctx, &status); err != nil {
			t.Fatalf("UpsertPackageCheckStatus(%s) error = %v", status.Name, err)
		}
	}
	if _, err := store.pool.Exec(ctx, `
		UPDATE package_check_status
		SET updated_at = CASE name
			WHEN 'old-socket' THEN $1::timestamptz
			WHEN 'old-other' THEN $1::timestamptz
			ELSE $2::timestamptz
		END`, oldTime, recentTime); err != nil {
		t.Fatalf("age package check status rows: %v", err)
	}

	pruned, err := store.PrunePackageCheckStatus(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("PrunePackageCheckStatus() error = %v", err)
	}
	if pruned != 1 {
		t.Fatalf("PrunePackageCheckStatus() = %d, want only old Socket.dev row", pruned)
	}

	oldSocket, err := store.GetPackageCheckStatus(ctx, "npm", "old-socket", "socket")
	if err != nil {
		t.Fatalf("GetPackageCheckStatus(old socket) error = %v", err)
	}
	if oldSocket != nil {
		t.Fatalf("GetPackageCheckStatus(old socket) = %+v, want pruned", oldSocket)
	}
	recentSocket, err := store.GetPackageCheckStatus(ctx, "npm", "recent-socket", "socket")
	if err != nil {
		t.Fatalf("GetPackageCheckStatus(recent socket) error = %v", err)
	}
	if recentSocket == nil {
		t.Fatal("GetPackageCheckStatus(recent socket) = nil, want retained")
	}
	oldOther, err := store.GetPackageCheckStatus(ctx, "npm", "old-other", "other")
	if err != nil {
		t.Fatalf("GetPackageCheckStatus(old other) error = %v", err)
	}
	if oldOther == nil {
		t.Fatal("GetPackageCheckStatus(old other) = nil, want non-Socket row retained")
	}
}

func TestQueueClearAndPurgeAuditPreserveJobIdentities(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "left-pad", Source: "socket", Priority: 2}); err != nil {
		t.Fatalf("EnqueueRefresh(pending) error = %v", err)
	}
	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "pypi", Name: "django", Source: "reversinglabs", Priority: 1}); err != nil {
		t.Fatalf("EnqueueRefresh(error target) error = %v", err)
	}
	pendingID := mustQueueJobID(t, store, ctx, "left-pad")
	errorID := mustQueueJobID(t, store, ctx, "django")
	if err := store.CompleteRefresh(ctx, errorID, errors.New("upstream token=query-secret failed")); err != nil {
		t.Fatalf("CompleteRefresh(error target) error = %v", err)
	}

	cleared, err := store.ClearQueueWithAudit(ctx, []string{"pending"}, &db.AdminAuditEntry{Action: "queue_clear", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("ClearQueueWithAudit() error = %v", err)
	}
	if cleared != 1 {
		t.Fatalf("ClearQueueWithAudit() = %d, want 1", cleared)
	}
	audit, err := store.ListAdminAuditLog(ctx, 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog(clear) error = %v", err)
	}
	clearedJobs := queueAuditJobsFromEntry(t, audit[0], "cleared_jobs")
	if len(clearedJobs) != 1 {
		t.Fatalf("cleared_jobs len = %d, want 1: %+v", len(clearedJobs), clearedJobs)
	}
	if job := clearedJobs[0]; job.ID != pendingID || job.Ecosystem != "npm" || job.Name != "left-pad" || job.Source != "socket" || job.Priority != 2 || job.Status != "pending" || job.RequestedAt == "" {
		t.Fatalf("cleared_jobs[0] = %+v, want pending left-pad identity", job)
	}

	purged, err := store.PurgeQueueWithAudit(ctx, &db.AdminAuditEntry{Action: "queue_purge", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("PurgeQueueWithAudit() error = %v", err)
	}
	if purged != 1 {
		t.Fatalf("PurgeQueueWithAudit() = %d, want 1", purged)
	}
	audit, err = store.ListAdminAuditLog(ctx, 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog(purge) error = %v", err)
	}
	purgedJobs := queueAuditJobsFromEntry(t, audit[0], "purged_jobs")
	if len(purgedJobs) != 1 {
		t.Fatalf("purged_jobs len = %d, want 1: %+v", len(purgedJobs), purgedJobs)
	}
	if job := purgedJobs[0]; job.ID != errorID || job.Ecosystem != "pypi" || job.Name != "django" || job.Source != "reversinglabs" || job.Priority != 1 || job.Status != "error" || job.RequestedAt == "" || job.ProcessedAt == "" {
		t.Fatalf("purged_jobs[0] = %+v, want errored django identity", job)
	}
	if strings.Contains(purgedJobs[0].Error, "query-secret") {
		t.Fatalf("purged_jobs[0].error leaked secret: %q", purgedJobs[0].Error)
	}
	if !strings.Contains(purgedJobs[0].Error, "token=[redacted]") {
		t.Fatalf("purged_jobs[0].error = %q, want redacted token marker", purgedJobs[0].Error)
	}
}

func TestSingleQueueJobAuditIncludesTransitionSnapshots(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "priority-transition", Source: "socket", Priority: 3}); err != nil {
		t.Fatalf("EnqueueRefresh(priority target) error = %v", err)
	}
	priorityID := mustQueueJobID(t, store, ctx, "priority-transition")
	if err := store.UpdateQueueJobPriorityWithAudit(ctx, priorityID, 0, queueAuditEntry("queue_priority_update", priorityID)); err != nil {
		t.Fatalf("UpdateQueueJobPriorityWithAudit() error = %v", err)
	}
	assertQueueTransitionAudit(t, store, ctx, queueTransitionAuditExpectation{
		action:           "queue_priority_update",
		jobID:            priorityID,
		name:             "priority-transition",
		previousStatus:   db.RefreshStatusPending,
		newStatus:        db.RefreshStatusPending,
		previousPriority: 3,
		newPriority:      0,
	})

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "pause-transition", Source: "socket", Priority: 1}); err != nil {
		t.Fatalf("EnqueueRefresh(pause target) error = %v", err)
	}
	pauseID := mustQueueJobID(t, store, ctx, "pause-transition")
	if err := store.PauseQueueJobWithAudit(ctx, pauseID, queueAuditEntry("queue_pause", pauseID)); err != nil {
		t.Fatalf("PauseQueueJobWithAudit() error = %v", err)
	}
	assertQueueTransitionAudit(t, store, ctx, queueTransitionAuditExpectation{
		action:           "queue_pause",
		jobID:            pauseID,
		name:             "pause-transition",
		previousStatus:   db.RefreshStatusPending,
		newStatus:        db.RefreshStatusPaused,
		previousPriority: 1,
		newPriority:      1,
	})

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "resume-transition", Source: "socket", Priority: 1}); err != nil {
		t.Fatalf("EnqueueRefresh(resume target) error = %v", err)
	}
	resumeID := mustQueueJobID(t, store, ctx, "resume-transition")
	if err := store.PauseQueueJob(ctx, resumeID); err != nil {
		t.Fatalf("PauseQueueJob(resume target) error = %v", err)
	}
	if err := store.ResumeQueueJobWithAudit(ctx, resumeID, queueAuditEntry("queue_resume", resumeID)); err != nil {
		t.Fatalf("ResumeQueueJobWithAudit() error = %v", err)
	}
	assertQueueTransitionAudit(t, store, ctx, queueTransitionAuditExpectation{
		action:           "queue_resume",
		jobID:            resumeID,
		name:             "resume-transition",
		previousStatus:   db.RefreshStatusPaused,
		newStatus:        db.RefreshStatusPending,
		previousPriority: 1,
		newPriority:      1,
	})

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "retry-transition", Source: "socket", Priority: 1}); err != nil {
		t.Fatalf("EnqueueRefresh(retry target) error = %v", err)
	}
	retryID := mustQueueJobID(t, store, ctx, "retry-transition")
	if err := store.CompleteRefresh(ctx, retryID, errors.New("upstream token=query-secret failed")); err != nil {
		t.Fatalf("CompleteRefresh(retry target) error = %v", err)
	}
	if err := store.RetryQueueJobWithAudit(ctx, retryID, queueAuditEntry("queue_retry", retryID)); err != nil {
		t.Fatalf("RetryQueueJobWithAudit() error = %v", err)
	}
	assertQueueTransitionAudit(t, store, ctx, queueTransitionAuditExpectation{
		action:            "queue_retry",
		jobID:             retryID,
		name:              "retry-transition",
		previousStatus:    db.RefreshStatusError,
		newStatus:         db.RefreshStatusPending,
		previousPriority:  1,
		newPriority:       1,
		wantRedactedError: true,
	})
}

func TestQueueClearAndPurgeAuditSamplesDeletedJobs(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	const wantSampleLimit = 100
	totalJobs := wantSampleLimit + 3

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO refresh_queue (ecosystem, name, source, priority, status, requested_at)
		SELECT 'npm', 'clear-sample-' || g::text, 'socket', 1, 'pending', NOW()
		FROM generate_series(1, $1) AS g`, totalJobs); err != nil {
		t.Fatalf("insert clear sample jobs: %v", err)
	}

	cleared, err := store.ClearQueueWithAudit(ctx, []string{"pending"}, &db.AdminAuditEntry{Action: "queue_clear", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("ClearQueueWithAudit() error = %v", err)
	}
	if cleared != totalJobs {
		t.Fatalf("ClearQueueWithAudit() = %d, want %d", cleared, totalJobs)
	}
	assertQueueAuditSample(t, store, ctx, "cleared_jobs", totalJobs, wantSampleLimit)
	pendingJobs, err := store.ListQueueJobs(ctx, "pending", totalJobs+1)
	if err != nil {
		t.Fatalf("ListQueueJobs(pending) error = %v", err)
	}
	if len(pendingJobs) != 0 {
		t.Fatalf("pending jobs after clear = %d, want 0", len(pendingJobs))
	}

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO refresh_queue (ecosystem, name, source, priority, status, requested_at, processed_at, error)
		SELECT 'npm',
		       'purge-sample-' || g::text,
		       'socket',
		       1,
		       CASE WHEN g % 2 = 0 THEN 'done' ELSE 'error' END,
		       NOW(),
		       NOW(),
		       'upstream token=query-secret failed'
		FROM generate_series(1, $1) AS g`, totalJobs); err != nil {
		t.Fatalf("insert purge sample jobs: %v", err)
	}

	purged, err := store.PurgeQueueWithAudit(ctx, &db.AdminAuditEntry{Action: "queue_purge", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("PurgeQueueWithAudit() error = %v", err)
	}
	if purged != totalJobs {
		t.Fatalf("PurgeQueueWithAudit() = %d, want %d", purged, totalJobs)
	}
	assertQueueAuditSample(t, store, ctx, "purged_jobs", totalJobs, wantSampleLimit)
	terminalJobs, err := store.ListQueueJobs(ctx, "done", totalJobs+1)
	if err != nil {
		t.Fatalf("ListQueueJobs(done) error = %v", err)
	}
	if len(terminalJobs) != 0 {
		t.Fatalf("done jobs after purge = %d, want 0", len(terminalJobs))
	}
	terminalJobs, err = store.ListQueueJobs(ctx, "error", totalJobs+1)
	if err != nil {
		t.Fatalf("ListQueueJobs(error) error = %v", err)
	}
	if len(terminalJobs) != 0 {
		t.Fatalf("error jobs after purge = %d, want 0", len(terminalJobs))
	}
}

func TestQueueClearAndPurgeWithAuditRollBackOnAuditFailure(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "clear-audit-rollback", Source: "socket", Priority: 2}); err != nil {
		t.Fatalf("EnqueueRefresh(clear target) error = %v", err)
	}
	clearID := mustQueueJobID(t, store, ctx, "clear-audit-rollback")
	_, err := store.ClearQueueWithAudit(ctx, []string{"pending"}, failingAdminAuditEntry("queue_clear"))
	requireAdminAuditFailure(t, err)
	clearJob := queueJobByID(t, store, ctx, clearID)
	if clearJob.Status != db.RefreshStatusPending || clearJob.Name != "clear-audit-rollback" || clearJob.Priority != 2 {
		t.Fatalf("queue job after failed audited clear = %+v, want original pending job", clearJob)
	}

	if err := store.CompleteRefresh(ctx, clearID, nil); err != nil {
		t.Fatalf("CompleteRefresh(purge target) error = %v", err)
	}
	_, err = store.PurgeQueueWithAudit(ctx, failingAdminAuditEntry("queue_purge"))
	requireAdminAuditFailure(t, err)
	purgeJob := queueJobByID(t, store, ctx, clearID)
	if purgeJob.Status != db.RefreshStatusDone || purgeJob.Name != "clear-audit-rollback" || purgeJob.ProcessedAt == nil {
		t.Fatalf("queue job after failed audited purge = %+v, want original done job", purgeJob)
	}
	requireNoAdminAuditRows(t, store, ctx)
}

func TestSingleQueueJobWithAuditRollsBackOnAuditFailure(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "priority-audit-rollback", Source: "socket", Priority: 3}); err != nil {
		t.Fatalf("EnqueueRefresh(priority target) error = %v", err)
	}
	priorityID := mustQueueJobID(t, store, ctx, "priority-audit-rollback")
	err := store.UpdateQueueJobPriorityWithAudit(ctx, priorityID, 0, failingAdminAuditEntry("queue_priority"))
	requireAdminAuditFailure(t, err)
	priorityJob := queueJobByID(t, store, ctx, priorityID)
	if priorityJob.Priority != 3 || priorityJob.Status != db.RefreshStatusPending {
		t.Fatalf("queue job after failed audited priority update = %+v, want original priority 3 pending job", priorityJob)
	}

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "pause-audit-rollback", Source: "socket", Priority: 1}); err != nil {
		t.Fatalf("EnqueueRefresh(pause target) error = %v", err)
	}
	pauseID := mustQueueJobID(t, store, ctx, "pause-audit-rollback")
	err = store.PauseQueueJobWithAudit(ctx, pauseID, failingAdminAuditEntry("queue_pause"))
	requireAdminAuditFailure(t, err)
	pauseJob := queueJobByID(t, store, ctx, pauseID)
	if pauseJob.Status != db.RefreshStatusPending {
		t.Fatalf("queue job after failed audited pause = %+v, want pending job", pauseJob)
	}

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "resume-audit-rollback", Source: "socket", Priority: 1}); err != nil {
		t.Fatalf("EnqueueRefresh(resume target) error = %v", err)
	}
	resumeID := mustQueueJobID(t, store, ctx, "resume-audit-rollback")
	if err := store.PauseQueueJob(ctx, resumeID); err != nil {
		t.Fatalf("PauseQueueJob(resume target) error = %v", err)
	}
	err = store.ResumeQueueJobWithAudit(ctx, resumeID, failingAdminAuditEntry("queue_resume"))
	requireAdminAuditFailure(t, err)
	resumeJob := queueJobByID(t, store, ctx, resumeID)
	if resumeJob.Status != db.RefreshStatusPaused {
		t.Fatalf("queue job after failed audited resume = %+v, want paused job", resumeJob)
	}

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "retry-audit-rollback", Source: "socket", Priority: 1}); err != nil {
		t.Fatalf("EnqueueRefresh(retry target) error = %v", err)
	}
	retryID := mustQueueJobID(t, store, ctx, "retry-audit-rollback")
	if err := store.CompleteRefresh(ctx, retryID, errors.New("upstream failed")); err != nil {
		t.Fatalf("CompleteRefresh(retry target) error = %v", err)
	}
	err = store.RetryQueueJobWithAudit(ctx, retryID, failingAdminAuditEntry("queue_retry"))
	requireAdminAuditFailure(t, err)
	retryJob := queueJobByID(t, store, ctx, retryID)
	if retryJob.Status != db.RefreshStatusError || retryJob.Error == "" || retryJob.ProcessedAt == nil {
		t.Fatalf("queue job after failed audited retry = %+v, want original error job", retryJob)
	}
	requireNoAdminAuditRows(t, store, ctx)
}

type queueAuditJobFixture struct {
	ID          int    `json:"id"`
	Ecosystem   string `json:"ecosystem"`
	Name        string `json:"name"`
	Source      string `json:"source"`
	Priority    int    `json:"priority"`
	Status      string `json:"status"`
	RequestedAt string `json:"requested_at"`
	ProcessedAt string `json:"processed_at"`
	Error       string `json:"error"`
}

type queueTransitionAuditExpectation struct {
	action            string
	jobID             int
	name              string
	previousStatus    string
	newStatus         string
	previousPriority  int
	newPriority       int
	wantRedactedError bool
}

func queueAuditEntry(action string, jobID int) *db.AdminAuditEntry {
	return &db.AdminAuditEntry{
		Action:  action,
		Details: json.RawMessage(fmt.Sprintf(`{"job_id":"%d"}`, jobID)),
		IP:      "127.0.0.1",
	}
}

func assertQueueTransitionAudit(t *testing.T, store *Store, ctx context.Context, want queueTransitionAuditExpectation) {
	t.Helper()

	audit, err := store.ListAdminAuditLog(ctx, 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog(%s) error = %v", want.action, err)
	}
	if len(audit) != 1 {
		t.Fatalf("ListAdminAuditLog(%s) = %d rows, want 1", want.action, len(audit))
	}
	entry := audit[0]
	if entry.Action != want.action {
		t.Fatalf("latest audit action = %q, want %q", entry.Action, want.action)
	}
	details := queueAuditDetailsFromEntry(t, entry)
	for key, value := range map[string]string{
		"job_id":            strconv.Itoa(want.jobID),
		"previous_status":   want.previousStatus,
		"new_status":        want.newStatus,
		"previous_priority": strconv.Itoa(want.previousPriority),
		"new_priority":      strconv.Itoa(want.newPriority),
	} {
		if details[key] != value {
			t.Fatalf("%s detail %s = %q, want %q; details=%v", want.action, key, details[key], value, details)
		}
	}

	previous := queueAuditJobsFromEntry(t, entry, "previous_job")
	next := queueAuditJobsFromEntry(t, entry, "new_job")
	if len(previous) != 1 || len(next) != 1 {
		t.Fatalf("%s audit snapshots previous/new = %d/%d, want 1/1", want.action, len(previous), len(next))
	}
	before := previous[0]
	after := next[0]
	if before.ID != want.jobID || after.ID != want.jobID || before.Name != want.name || after.Name != want.name {
		t.Fatalf("%s snapshots = %+v -> %+v, want job %d %q", want.action, before, after, want.jobID, want.name)
	}
	if before.Ecosystem != "npm" || after.Ecosystem != "npm" || before.Source != "socket" || after.Source != "socket" {
		t.Fatalf("%s snapshots missing package identity: %+v -> %+v", want.action, before, after)
	}
	if before.Status != want.previousStatus || after.Status != want.newStatus || before.Priority != want.previousPriority || after.Priority != want.newPriority {
		t.Fatalf("%s snapshots state = %+v -> %+v, want status %s->%s priority %d->%d", want.action, before, after, want.previousStatus, want.newStatus, want.previousPriority, want.newPriority)
	}
	if before.RequestedAt == "" || after.RequestedAt == "" {
		t.Fatalf("%s snapshots missing requested_at: %+v -> %+v", want.action, before, after)
	}
	if want.wantRedactedError {
		if strings.Contains(before.Error, "query-secret") {
			t.Fatalf("%s previous error leaked secret: %q", want.action, before.Error)
		}
		if !strings.Contains(before.Error, "token=[redacted]") {
			t.Fatalf("%s previous error = %q, want redacted token marker", want.action, before.Error)
		}
		if before.ProcessedAt == "" {
			t.Fatalf("%s previous retry snapshot missing processed_at: %+v", want.action, before)
		}
		if after.Error != "" || after.ProcessedAt != "" {
			t.Fatalf("%s retry new snapshot = %+v, want cleared error and processed_at", want.action, after)
		}
	}
}

func queueAuditJobsFromEntry(t *testing.T, entry db.AdminAuditLogEntry, key string) []queueAuditJobFixture {
	t.Helper()

	details := map[string]string{}
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("audit details unmarshal error = %v; raw=%s", err, entry.Details)
	}
	raw, ok := details[key]
	if !ok {
		t.Fatalf("audit details missing %q: %v", key, details)
	}
	var jobs []queueAuditJobFixture
	if err := json.Unmarshal([]byte(raw), &jobs); err != nil {
		t.Fatalf("audit detail %q unmarshal error = %v; raw=%s", key, err, raw)
	}
	return jobs
}

func queueAuditDetailsFromEntry(t *testing.T, entry db.AdminAuditLogEntry) map[string]string {
	t.Helper()

	details := map[string]string{}
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("audit details unmarshal error = %v; raw=%s", err, entry.Details)
	}
	return details
}

func assertQueueAuditSample(t *testing.T, store *Store, ctx context.Context, jobsKey string, totalJobs, wantSampleLimit int) {
	t.Helper()

	audit, err := store.ListAdminAuditLog(ctx, 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog(%s) error = %v", jobsKey, err)
	}
	details := queueAuditDetailsFromEntry(t, audit[0])
	if details["total_deleted"] != strconv.Itoa(totalJobs) {
		t.Fatalf("total_deleted = %q, want %d; details=%v", details["total_deleted"], totalJobs, details)
	}
	if details["sample_count"] != strconv.Itoa(wantSampleLimit) {
		t.Fatalf("sample_count = %q, want %d; details=%v", details["sample_count"], wantSampleLimit, details)
	}
	if details["truncated"] != "true" {
		t.Fatalf("truncated = %q, want true; details=%v", details["truncated"], details)
	}

	jobs := queueAuditJobsFromEntry(t, audit[0], jobsKey)
	if len(jobs) != wantSampleLimit {
		t.Fatalf("%s len = %d, want %d", jobsKey, len(jobs), wantSampleLimit)
	}
	for _, job := range jobs {
		if strings.Contains(job.Error, "query-secret") {
			t.Fatalf("%s leaked secret in sampled error: %+v", jobsKey, job)
		}
	}
}

func mustQueueJobID(t *testing.T, store *Store, ctx context.Context, name string) int {
	t.Helper()

	jobs, err := store.ListQueueJobs(ctx, "", 50)
	if err != nil {
		t.Fatalf("ListQueueJobs() error = %v", err)
	}
	for _, job := range jobs {
		if job.Name == name {
			return job.ID
		}
	}
	t.Fatalf("ListQueueJobs() missing job %q: %+v", name, jobs)
	return 0
}

func TestOldestQueueJobsAgainstDocker(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	oldSocket := now.Add(-3 * time.Hour)
	newSocket := now.Add(-time.Minute)
	processingSocket := now.Add(-4 * time.Hour)
	doneOther := now.Add(-24 * time.Hour)

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "socket-old", Source: "socket", Priority: 1}); err != nil {
		t.Fatalf("enqueue socket-old: %v", err)
	}
	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "socket-new", Source: "socket", Priority: 1}); err != nil {
		t.Fatalf("enqueue socket-new: %v", err)
	}
	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "other-done", Source: "other", Priority: 1}); err != nil {
		t.Fatalf("enqueue other-done: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		UPDATE refresh_queue
		SET requested_at = CASE name
			WHEN 'socket-old' THEN $1
			WHEN 'socket-new' THEN $2
			WHEN 'other-done' THEN $3
			ELSE requested_at
		END`, oldSocket, newSocket, doneOther); err != nil {
		t.Fatalf("age queue jobs: %v", err)
	}
	if doneJob, err := store.DequeueRefresh(ctx, "other"); err != nil || doneJob == nil {
		t.Fatalf("dequeue other = %+v, %v", doneJob, err)
	} else if err := store.CompleteRefresh(ctx, doneJob.ID, nil); err != nil {
		t.Fatalf("complete other done: %v", err)
	}
	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "socket-processing", Source: "socket", Priority: 0}); err != nil {
		t.Fatalf("enqueue socket-processing: %v", err)
	}
	processingJob, err := store.DequeueRefresh(ctx, "socket")
	if err != nil || processingJob == nil {
		t.Fatalf("dequeue socket processing = %+v, %v", processingJob, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE refresh_queue SET requested_at = $1 WHERE id = $2`, processingSocket, processingJob.ID); err != nil {
		t.Fatalf("age processing job: %v", err)
	}

	oldest, err := store.OldestQueueJobs(ctx)
	if err != nil {
		t.Fatalf("OldestQueueJobs() error = %v", err)
	}
	if got := oldest["socket"]; !got.Equal(processingSocket) {
		t.Fatalf("OldestQueueJobs()[socket] = %s, want processing job %s (all=%+v)", got, processingSocket, oldest)
	}
	if _, ok := oldest["other"]; ok {
		t.Fatalf("OldestQueueJobs() included completed source: %+v", oldest)
	}
}

func syncVulnerabilityExportContains(items []db.SyncVulnerability, id string, withdrawn bool) bool {
	for _, item := range items {
		if item.ID == id && item.Withdrawn == withdrawn {
			return true
		}
	}
	return false
}

func syncVulnerabilityExportSource(items []db.SyncVulnerability, id string, withdrawn bool) (string, bool) {
	for _, item := range items {
		if item.ID == id && item.Withdrawn == withdrawn {
			return item.Source, true
		}
	}
	return "", false
}

func syncMaliciousExportSource(items []db.SyncMalicious, id string, withdrawn bool) (string, bool) {
	for _, item := range items {
		if item.ID == id && item.Withdrawn == withdrawn {
			return item.Source, true
		}
	}
	return "", false
}

func packageSearchContains(items []db.PackageSearchResult, ecosystem, name string) bool {
	for _, item := range items {
		if item.Ecosystem == ecosystem && item.Name == name {
			return true
		}
	}
	return false
}

func packageSearchContainsVersion(items []db.PackageSearchResult, ecosystem, name, version string) bool {
	for _, item := range items {
		if item.Ecosystem == ecosystem && item.Name == name && item.Version == version {
			return true
		}
	}
	return false
}

func packageSearchFindingTypes(items []db.PackageSearchResult, ecosystem, name, version string) (string, bool) {
	for _, item := range items {
		if item.Ecosystem == ecosystem && item.Name == name && item.Version == version {
			return item.FindingTypes, true
		}
	}
	return "", false
}

func syncReputationExportContains(items []db.SyncReputationFinding, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}

func ptrDuration(d time.Duration) *time.Duration {
	return &d
}

func TestCountUnknownSeverityFindingsAgainstDocker(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if count, err := store.CountUnknownSeverityFindings(ctx); err != nil || count != 0 {
		t.Fatalf("CountUnknownSeverityFindings(empty) = %d, %v; want 0 nil", count, err)
	}

	// Check constraints restrict all finding severities to the four supported
	// values, so the unknown bucket can only be filled by legacy rows imported
	// before the constraints existed; the counter must still answer cheaply
	// and without error for that defensive case.
}
