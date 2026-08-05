package devstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

// enqueueTestJob puts one pending job in the queue and returns its ID.
func enqueueTestJob(t *testing.T, store *Store, name string) int {
	t.Helper()

	if _, _, err := store.EnqueueRefresh(context.Background(), &db.RefreshJob{
		Ecosystem: "npm",
		Name:      name,
		Source:    "admin",
		Priority:  db.RefreshPriorityManual,
	}); err != nil {
		t.Fatalf("EnqueueRefresh(%s): %v", name, err)
	}

	jobs, err := store.ListQueueJobs(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("ListQueueJobs: %v", err)
	}
	for _, job := range jobs {
		if job.Name == name {
			return job.ID
		}
	}
	t.Fatalf("job %s was not queued", name)
	return 0
}

// TestEnqueueRefreshWithAuditReportsThePositionToTheCallback covers the audited
// enqueue on the dev store. The admin queue form uses it, and the callback has to
// see the same position the caller gets or the audit log and the UI disagree.
func TestEnqueueRefreshWithAuditReportsThePositionToTheCallback(t *testing.T) {
	t.Parallel()

	store := NewStore()
	var seenCreated bool
	var seenPosition int

	created, position, err := store.EnqueueRefreshWithAudit(context.Background(), &db.RefreshJob{
		Ecosystem: "npm",
		Name:      "audited-enqueue",
		Source:    "admin",
		Priority:  db.RefreshPriorityManual,
	}, func(created bool, position int) db.AdminAuditEntry {
		seenCreated, seenPosition = created, position
		return db.AdminAuditEntry{Action: "queue.enqueue", IP: "127.0.0.1"}
	})
	if err != nil {
		t.Fatalf("EnqueueRefreshWithAudit: %v", err)
	}
	if !created {
		t.Fatal("the first enqueue reported no new job")
	}
	if seenCreated != created || seenPosition != position {
		t.Fatalf("callback saw (%v, %d), want the returned (%v, %d)",
			seenCreated, seenPosition, created, position)
	}

	entries, err := store.ListAdminAuditLog(context.Background(), 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if len(entries) != 1 || entries[0].Action != "queue.enqueue" {
		t.Fatalf("audit log = %+v, want the enqueue recorded", entries)
	}
}

// TestEnqueueRefreshWithAuditDeduplicatesPendingJobs pins that the audited path
// shares the dedup guard with the plain one. Without it the admin form would
// queue a second job for a package already waiting.
func TestEnqueueRefreshWithAuditDeduplicatesPendingJobs(t *testing.T) {
	t.Parallel()

	store := NewStore()
	job := func() *db.RefreshJob {
		return &db.RefreshJob{Ecosystem: "npm", Name: "dedup", Source: "admin", Priority: db.RefreshPriorityManual}
	}

	if _, _, err := store.EnqueueRefreshWithAudit(context.Background(), job(), nil); err != nil {
		t.Fatalf("first EnqueueRefreshWithAudit: %v", err)
	}
	created, _, err := store.EnqueueRefreshWithAudit(context.Background(), job(), nil)
	if err != nil {
		t.Fatalf("second EnqueueRefreshWithAudit: %v", err)
	}
	if created {
		t.Fatal("a duplicate pending job was created")
	}
}

// TestPauseQueueJobWithAuditRequiresAPendingJob covers the state guard. Pausing
// a job that is already running or done would silently do nothing while the UI
// reports success.
func TestPauseQueueJobWithAuditRequiresAPendingJob(t *testing.T) {
	t.Parallel()

	store := NewStore()
	ctx := context.Background()
	jobID := enqueueTestJob(t, store, "pausable")

	if err := store.PauseQueueJobWithAudit(ctx, jobID,
		&db.AdminAuditEntry{Action: "queue.pause", IP: "127.0.0.1"}); err != nil {
		t.Fatalf("PauseQueueJobWithAudit: %v", err)
	}

	jobs, err := store.ListQueueJobs(ctx, "", 50)
	if err != nil {
		t.Fatalf("ListQueueJobs: %v", err)
	}
	var status string
	for _, job := range jobs {
		if job.ID == jobID {
			status = job.Status
		}
	}
	if status != db.RefreshStatusPaused {
		t.Fatalf("status = %q, want the job paused", status)
	}

	// Pausing an already-paused job must be refused, not silently repeated.
	err = store.PauseQueueJobWithAudit(ctx, jobID, &db.AdminAuditEntry{Action: "queue.pause"})
	if err == nil {
		t.Fatal("pausing an already-paused job succeeded")
	}
	if !strings.Contains(err.Error(), "not pending") {
		t.Errorf("error = %v, want it to name the wrong state", err)
	}

	// An unknown job ID must be reported rather than treated as a no-op.
	if err := store.PauseQueueJobWithAudit(ctx, 999999, nil); err == nil {
		t.Error("pausing an unknown job succeeded")
	}
}

// TestResumeQueueJobWithAuditRequiresAPausedJob is the mirror image, and also
// pins the reset: a resumed job must lose its previous error and processed
// timestamp, or the queue page would still show it as failed.
func TestResumeQueueJobWithAuditRequiresAPausedJob(t *testing.T) {
	t.Parallel()

	store := NewStore()
	ctx := context.Background()
	jobID := enqueueTestJob(t, store, "resumable")

	// Resuming a job that was never paused must be refused.
	err := store.ResumeQueueJobWithAudit(ctx, jobID, nil)
	if err == nil {
		t.Fatal("resuming a pending job succeeded")
	}
	if !strings.Contains(err.Error(), "not paused") {
		t.Errorf("error = %v, want it to name the wrong state", err)
	}

	if err := store.PauseQueueJobWithAudit(ctx, jobID, nil); err != nil {
		t.Fatalf("PauseQueueJobWithAudit: %v", err)
	}
	if err := store.ResumeQueueJobWithAudit(ctx, jobID,
		&db.AdminAuditEntry{Action: "queue.resume", IP: "127.0.0.1"}); err != nil {
		t.Fatalf("ResumeQueueJobWithAudit: %v", err)
	}

	jobs, err := store.ListQueueJobs(ctx, "", 50)
	if err != nil {
		t.Fatalf("ListQueueJobs: %v", err)
	}
	for _, job := range jobs {
		if job.ID != jobID {
			continue
		}
		if job.Status != db.RefreshStatusPending {
			t.Errorf("status = %q, want the job back in pending", job.Status)
		}
		if job.ProcessedAt != nil {
			t.Errorf("ProcessedAt = %v, want it cleared on resume", job.ProcessedAt)
		}
		if job.Error != "" {
			t.Errorf("Error = %q, want it cleared on resume", job.Error)
		}
	}

	if err := store.ResumeQueueJobWithAudit(ctx, 999999, nil); err == nil {
		t.Error("resuming an unknown job succeeded")
	}
}

// TestDeleteVulnerabilityForSourceRequiresASource is the safety guard on the
// source-scoped delete. Without a source the delete would match every row for
// the advisory, wiping other feeds' data during a single feed's cleanup.
func TestDeleteVulnerabilityForSourceRequiresASource(t *testing.T) {
	t.Parallel()

	store := NewStore()
	ctx := context.Background()

	for _, source := range []string{"", "   "} {
		err := store.DeleteVulnerabilityForSource(ctx, "GHSA-1", source)
		if !errors.Is(err, db.ErrSourceScopedDeleteSourceRequired) {
			t.Errorf("DeleteVulnerabilityForSource(%q) = %v, want the source-required sentinel", source, err)
		}
	}

	// Deleting an advisory that is not stored is not an error -- the feed may
	// simply have removed a record this store never had.
	if err := store.DeleteVulnerabilityForSource(ctx, "GHSA-missing", "osv"); err != nil {
		t.Errorf("DeleteVulnerabilityForSource(unknown id) = %v, want a no-op", err)
	}
}

// TestDeleteMaliciousFindingForSourceRequiresASource is the same guard for
// malicious findings, where an over-broad delete would silently unblock a
// package the scanner must keep blocking.
func TestDeleteMaliciousFindingForSourceRequiresASource(t *testing.T) {
	t.Parallel()

	store := NewStore()
	ctx := context.Background()

	for _, source := range []string{"", "\t"} {
		err := store.DeleteMaliciousFindingForSource(ctx, "MAL-1", source)
		if !errors.Is(err, db.ErrSourceScopedDeleteSourceRequired) {
			t.Errorf("DeleteMaliciousFindingForSource(%q) = %v, want the source-required sentinel", source, err)
		}
	}

	if err := store.DeleteMaliciousFindingForSource(ctx, "MAL-missing", "socket"); err != nil {
		t.Errorf("DeleteMaliciousFindingForSource(unknown id) = %v, want a no-op", err)
	}
}

// TestImportVulnerabilityFeedWithAuditRecordsTheImport covers the audited
// advisory import on the dev store, which backs the API when no PostgreSQL is
// configured.
func TestImportVulnerabilityFeedWithAuditRecordsTheImport(t *testing.T) {
	t.Parallel()

	store := NewStore()
	ctx := context.Background()

	var seenImported int
	imported, _, err := store.ImportVulnerabilityFeedWithAudit(ctx, "osv", []db.Vulnerability{{
		ID:       "GHSA-devstore-1",
		Summary:  "devstore fixture",
		Severity: "HIGH",
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem: "npm",
			Name:      "devstore-fixture",
		}},
	}}, nil, nil, func(imported, _ int) db.AdminAuditEntry {
		seenImported = imported
		return db.AdminAuditEntry{Action: "feed.vulnerability.import", IP: "127.0.0.1"}
	})
	if err != nil {
		t.Fatalf("ImportVulnerabilityFeedWithAudit: %v", err)
	}
	if imported != 1 {
		t.Fatalf("imported = %d, want 1", imported)
	}
	if seenImported != imported {
		t.Fatalf("callback saw %d imports, want the returned %d", seenImported, imported)
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if len(entries) != 1 || entries[0].Action != "feed.vulnerability.import" {
		t.Fatalf("audit log = %+v, want the import recorded", entries)
	}
}

// TestImportVulnerabilityFeedWithoutAuditWritesNoAuditEntry covers the unaudited
// path: a sync-worker import must not manufacture an admin audit trail.
func TestImportVulnerabilityFeedWithoutAuditWritesNoAuditEntry(t *testing.T) {
	t.Parallel()

	store := NewStore()
	ctx := context.Background()

	if _, _, err := store.ImportVulnerabilityFeedWithAudit(ctx, "osv", []db.Vulnerability{{
		ID:       "GHSA-devstore-2",
		Severity: "HIGH",
	}}, nil, nil, nil); err != nil {
		t.Fatalf("ImportVulnerabilityFeedWithAudit(nil audit): %v", err)
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("unaudited import wrote %d audit entries, want 0", len(entries))
	}
}
