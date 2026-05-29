//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
	postgres "github.com/8linkz/packmon/internal/db/postgres"
)

// startPostgresStore brings up a throwaway PostgreSQL container, runs the
// migrations via the server binary, and returns a connected store. It reuses
// the docker helpers from production_test.go.
func startPostgresStore(t *testing.T) *postgres.Store {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	containerName := fmt.Sprintf("packmon-store-it-%d", time.Now().UnixNano())
	dbPort := freePort(t)

	run := exec.Command("docker", "run", "-d", "--rm",
		"--name", containerName,
		"-e", "POSTGRES_DB=packmon",
		"-e", "POSTGRES_USER=packmon",
		"-e", "POSTGRES_PASSWORD=packmon",
		"-p", fmt.Sprintf("%d:5432", dbPort),
		"postgres:16-alpine",
	)
	out, err := run.Output()
	if err != nil {
		t.Fatalf("docker run postgres: %v", err)
	}
	containerID := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	})

	waitForDockerPostgres(t, containerName)

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
		BlockThreshold:     "HIGH",
		RateLimitPerMinute: 120,
		RateLimitBurst:     30,
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
}
