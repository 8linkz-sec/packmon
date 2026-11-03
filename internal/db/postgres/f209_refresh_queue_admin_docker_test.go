//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF209RefreshQueueAdminStateAndAuditContractsAgainstPostgres(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)

	insert := func(name, source, status string, priority int, requested time.Time, processed *time.Time, diagnostic *string) int {
		t.Helper()
		var id int
		if err := store.pool.QueryRow(ctx, `
			INSERT INTO refresh_queue (ecosystem, name, source, priority, status, requested_at, processed_at, error)
			VALUES ('npm', $1, $2, $3, $4, $5, $6, $7)
			RETURNING id`, name, source, priority, status, requested, processed, diagnostic).Scan(&id); err != nil {
			t.Fatalf("insert queue fixture %q: %v", name, err)
		}
		return id
	}

	pendingOld := insert("pending-old", "socket", db.RefreshStatusPending, 3, base, nil, nil)
	pendingNew := insert("pending-new", "socket", db.RefreshStatusPending, 2, base.Add(10*time.Minute), nil, nil)
	processingOld := insert("processing-old", "socket", db.RefreshStatusProcessing, 1, base.Add(-time.Minute), &base, nil)
	pausedID := insert("paused", "socket", db.RefreshStatusPaused, 2, base.Add(-2*time.Hour), &base, f209StringPtr("paused diagnostic"))
	doneAt := base.Add(20 * time.Minute)
	doneID := insert("done", "other", db.RefreshStatusDone, 1, base.Add(-3*time.Hour), &doneAt, nil)
	errorAt := base.Add(30 * time.Minute)
	errorID := insert("error", "other", db.RefreshStatusError, 1, base.Add(-4*time.Hour), &errorAt, f209StringPtr("upstream token=query-secret failed"))
	insert("empty-source", "", db.RefreshStatusPending, 1, base.Add(-5*time.Hour), nil, nil)

	oldest, err := store.OldestQueueJobs(ctx)
	if err != nil {
		t.Fatalf("OldestQueueJobs() error = %v", err)
	}
	if got := oldest["socket"]; !got.Equal(base.Add(-time.Minute)) {
		t.Fatalf("OldestQueueJobs()[socket] = %s, want processing timestamp %s", got, base.Add(-time.Minute))
	}
	if _, ok := oldest["other"]; ok {
		t.Fatalf("OldestQueueJobs() included terminal source: %#v", oldest)
	}
	if _, ok := oldest[""]; ok {
		t.Fatalf("OldestQueueJobs() included empty source: %#v", oldest)
	}

	paused, err := store.ListQueueJobsPage(ctx, " PAUSED ", 10, -4)
	if err != nil || len(paused) != 1 || paused[0].ID != pausedID || paused[0].Error != "paused diagnostic" || paused[0].ProcessedAt == nil {
		t.Fatalf("ListQueueJobsPage(paused) = %+v, %v; want complete paused row", paused, err)
	}
	all, err := store.ListQueueJobsPage(ctx, "not-a-status", 3, 1)
	if err != nil || len(all) != 3 {
		t.Fatalf("ListQueueJobsPage(invalid status) len/error = %d/%v, want unfiltered page of 3", len(all), err)
	}

	if count, err := store.PruneRefreshQueue(ctx, 0); count != 0 || err != nil {
		t.Fatalf("PruneRefreshQueue(disabled) = %d, %v; want 0, nil", count, err)
	}

	if err := store.UpdateQueueJobPriorityWithAudit(ctx, pendingOld, 0, queueAuditEntry("f209_priority", pendingOld)); err != nil {
		t.Fatalf("UpdateQueueJobPriorityWithAudit() error = %v", err)
	}
	assertF209QueueAuditTransition(t, store, ctx, "f209_priority", db.RefreshStatusPending, db.RefreshStatusPending, 3, 0)

	if err := store.PauseQueueJobWithAudit(ctx, pendingOld, queueAuditEntry("f209_pause", pendingOld)); err != nil {
		t.Fatalf("PauseQueueJobWithAudit() error = %v", err)
	}
	assertF209QueueAuditTransition(t, store, ctx, "f209_pause", db.RefreshStatusPending, db.RefreshStatusPaused, 0, 0)

	if err := store.ResumeQueueJobWithAudit(ctx, pendingOld, queueAuditEntry("f209_resume", pendingOld)); err != nil {
		t.Fatalf("ResumeQueueJobWithAudit() error = %v", err)
	}
	assertF209QueueAuditTransition(t, store, ctx, "f209_resume", db.RefreshStatusPaused, db.RefreshStatusPending, 0, 0)

	if err := store.RetryQueueJobWithAudit(ctx, pausedID, queueAuditEntry("f209_retry", pausedID)); err != nil {
		t.Fatalf("RetryQueueJobWithAudit(paused) error = %v", err)
	}
	retried := queueJobByID(t, store, ctx, pausedID)
	if retried.Status != db.RefreshStatusPending || retried.ProcessedAt != nil || retried.Error != "" || !retried.RequestedAt.After(base) {
		t.Fatalf("retried paused job = %+v, want fresh pending state", retried)
	}
	assertF209QueueAuditTransition(t, store, ctx, "f209_retry", db.RefreshStatusPaused, db.RefreshStatusPending, 2, 2)

	if err := store.UpdateQueueJobPriority(ctx, pendingNew, 1); err != nil {
		t.Fatalf("UpdateQueueJobPriority() error = %v", err)
	}
	if err := store.PauseQueueJob(ctx, pendingNew); err != nil {
		t.Fatalf("PauseQueueJob() error = %v", err)
	}
	if err := store.ResumeQueueJob(ctx, pendingNew); err != nil {
		t.Fatalf("ResumeQueueJob() error = %v", err)
	}
	if err := store.PauseQueueJob(ctx, pendingNew); err != nil {
		t.Fatalf("PauseQueueJob(retry fixture) error = %v", err)
	}
	if err := store.RetryQueueJob(ctx, pendingNew); err != nil {
		t.Fatalf("RetryQueueJob() error = %v", err)
	}
	if got := queueJobByID(t, store, ctx, pendingNew); got.Status != db.RefreshStatusPending || got.Priority != 1 || got.ProcessedAt != nil || got.Error != "" {
		t.Fatalf("direct queue transition wrappers left job in unexpected state: %+v", got)
	}

	failureCases := []struct {
		name string
		call func() error
	}{
		{name: "invalid priority", call: func() error {
			return store.UpdateQueueJobPriorityWithAudit(ctx, pendingOld, 4, queueAuditEntry("f209_invalid_priority", pendingOld))
		}},
		{name: "priority missing", call: func() error {
			return store.UpdateQueueJobPriorityWithAudit(ctx, 999999, 1, queueAuditEntry("f209_missing_priority", 999999))
		}},
		{name: "retry missing", call: func() error {
			return store.RetryQueueJobWithAudit(ctx, 999999, queueAuditEntry("f209_missing_retry", 999999))
		}},
		{name: "pause missing", call: func() error {
			return store.PauseQueueJobWithAudit(ctx, 999999, queueAuditEntry("f209_missing_pause", 999999))
		}},
		{name: "resume missing", call: func() error {
			return store.ResumeQueueJobWithAudit(ctx, 999999, queueAuditEntry("f209_missing_resume", 999999))
		}},
		{name: "pause terminal", call: func() error {
			return store.PauseQueueJobWithAudit(ctx, doneID, queueAuditEntry("f209_invalid_pause", doneID))
		}},
		{name: "resume pending", call: func() error {
			return store.ResumeQueueJobWithAudit(ctx, pendingOld, queueAuditEntry("f209_invalid_resume", pendingOld))
		}},
		{name: "retry pending", call: func() error {
			return store.RetryQueueJobWithAudit(ctx, pendingOld, queueAuditEntry("f209_invalid_retry", pendingOld))
		}},
	}
	for _, tc := range failureCases {
		t.Run(tc.name, func(t *testing.T) {
			before := f209QueueAuditCount(t, store, ctx)
			if err := tc.call(); err == nil {
				t.Fatalf("queue action error = nil, want refusal")
			}
			if after := f209QueueAuditCount(t, store, ctx); after != before {
				t.Fatalf("audit rows after refused action = %d, want %d", after, before)
			}
		})
	}
	if got := queueJobByID(t, store, ctx, pendingOld); got.Status != db.RefreshStatusPending || got.Priority != 0 {
		t.Fatalf("refused actions changed pending job: %+v", got)
	}
	if got := queueJobByID(t, store, ctx, doneID); got.Status != db.RefreshStatusDone {
		t.Fatalf("refused pause changed done job: %+v", got)
	}

	malformedPriorityID := insert("malformed-priority", "audit", db.RefreshStatusPending, 3, base, nil, nil)
	malformedPauseID := insert("malformed-pause", "audit", db.RefreshStatusPending, 2, base, nil, nil)
	malformedRetryID := insert("malformed-retry", "audit", db.RefreshStatusPaused, 1, base, &base, f209StringPtr("retry failure"))
	malformedResumeID := insert("malformed-resume", "audit", db.RefreshStatusPaused, 1, base, &base, f209StringPtr("resume failure"))
	malformedTransitions := []struct {
		name       string
		jobID      int
		wantStatus string
		wantPrio   int
		call       func(*db.AdminAuditEntry) error
	}{
		{name: "priority", jobID: malformedPriorityID, wantStatus: db.RefreshStatusPending, wantPrio: 3, call: func(audit *db.AdminAuditEntry) error {
			return store.UpdateQueueJobPriorityWithAudit(ctx, malformedPriorityID, 0, audit)
		}},
		{name: "pause", jobID: malformedPauseID, wantStatus: db.RefreshStatusPending, wantPrio: 2, call: func(audit *db.AdminAuditEntry) error {
			return store.PauseQueueJobWithAudit(ctx, malformedPauseID, audit)
		}},
		{name: "retry", jobID: malformedRetryID, wantStatus: db.RefreshStatusPaused, wantPrio: 1, call: func(audit *db.AdminAuditEntry) error {
			return store.RetryQueueJobWithAudit(ctx, malformedRetryID, audit)
		}},
		{name: "resume", jobID: malformedResumeID, wantStatus: db.RefreshStatusPaused, wantPrio: 1, call: func(audit *db.AdminAuditEntry) error {
			return store.ResumeQueueJobWithAudit(ctx, malformedResumeID, audit)
		}},
	}
	for _, tc := range malformedTransitions {
		t.Run("malformed "+tc.name+" audit", func(t *testing.T) {
			beforeAudit := f209QueueAuditCount(t, store, ctx)
			audit := &db.AdminAuditEntry{Action: "f209_malformed_" + tc.name, Details: json.RawMessage(`{"broken"`), IP: "127.0.0.1"}
			err := tc.call(audit)
			if err == nil || !strings.Contains(err.Error(), "encode queue "+tc.name+" audit details") {
				t.Fatalf("malformed %s audit error = %v", tc.name, err)
			}
			if afterAudit := f209QueueAuditCount(t, store, ctx); afterAudit != beforeAudit {
				t.Fatalf("malformed %s audit appended row: before=%d after=%d", tc.name, beforeAudit, afterAudit)
			}
			job := queueJobByID(t, store, ctx, tc.jobID)
			if job.Status != tc.wantStatus || job.Priority != tc.wantPrio {
				t.Fatalf("malformed %s audit did not roll back job: %+v", tc.name, job)
			}
		})
	}

	malformed := &db.AdminAuditEntry{Action: "f209_malformed_clear", Details: json.RawMessage(`{"broken"`), IP: "127.0.0.1"}
	if _, err := store.ClearQueueWithAudit(ctx, []string{"pending"}, malformed); err == nil || !strings.Contains(err.Error(), "encode queue clear audit job details") {
		t.Fatalf("ClearQueueWithAudit(malformed details) error = %v", err)
	}
	for _, id := range []int{pendingOld, pausedID} {
		if got := queueJobByID(t, store, ctx, id); got.Status != db.RefreshStatusPending {
			t.Fatalf("failed audited clear changed job %d: %+v", id, got)
		}
	}

	beforeEmptyClear := f209QueueAuditCount(t, store, ctx)
	cleared, err := store.ClearQueueWithAudit(ctx, []string{"processing", "unknown"}, &db.AdminAuditEntry{Action: "f209_empty_clear", IP: "127.0.0.1"})
	if err != nil || cleared != 0 {
		t.Fatalf("ClearQueueWithAudit(non-clearable) = %d, %v; want 0, nil", cleared, err)
	}
	if got := queueJobByID(t, store, ctx, processingOld); got.Status != db.RefreshStatusProcessing {
		t.Fatalf("empty clear changed processing job: %+v", got)
	}
	if count := f209QueueAuditCount(t, store, ctx); count != beforeEmptyClear+1 {
		t.Fatalf("empty clear audit count = %d, want %d", count, beforeEmptyClear+1)
	}
	entry := f209LatestQueueAudit(t, store, ctx, "f209_empty_clear")
	details := queueAuditDetailsFromEntry(t, entry)
	if details["cleared"] != "0" || details["total_deleted"] != "0" || details["sample_count"] != "0" || details["truncated"] != "false" {
		t.Fatalf("empty clear audit details = %#v, want zero summary", details)
	}
	if jobs := queueAuditJobsFromEntry(t, entry, "cleared_jobs"); len(jobs) != 0 {
		t.Fatalf("empty clear audit jobs = %+v, want empty", jobs)
	}

	nilAuditBefore := queueJobByID(t, store, ctx, errorID)
	malformedPurge := &db.AdminAuditEntry{Action: "f209_malformed_purge", Details: json.RawMessage(`{"broken"`), IP: "127.0.0.1"}
	if _, err := store.PurgeQueueWithAudit(ctx, malformedPurge); err == nil || !strings.Contains(err.Error(), "encode queue purge audit job details") {
		t.Fatalf("PurgeQueueWithAudit(malformed details) error = %v", err)
	}
	if afterMalformed := queueJobByID(t, store, ctx, errorID); afterMalformed.Status != nilAuditBefore.Status || afterMalformed.Error != nilAuditBefore.Error {
		t.Fatalf("failed malformed-audit purge changed job: before=%+v after=%+v", nilAuditBefore, afterMalformed)
	}
	if _, err := store.PurgeQueueWithAudit(ctx, nil); !errors.Is(err, db.ErrAdminAuditLog) {
		t.Fatalf("PurgeQueueWithAudit(nil audit) error = %v, want ErrAdminAuditLog", err)
	}
	nilAuditAfter := queueJobByID(t, store, ctx, errorID)
	if nilAuditAfter.Status != nilAuditBefore.Status || nilAuditAfter.Error != nilAuditBefore.Error || nilAuditAfter.ProcessedAt == nil {
		t.Fatalf("failed nil-audit purge changed job: before=%+v after=%+v", nilAuditBefore, nilAuditAfter)
	}

	purged, err := store.PurgeQueueWithAudit(ctx, &db.AdminAuditEntry{Action: "f209_purge", IP: "127.0.0.1"})
	if err != nil || purged != 2 {
		t.Fatalf("PurgeQueueWithAudit() = %d, %v; want 2, nil", purged, err)
	}
	purgeEntry := f209LatestQueueAudit(t, store, ctx, "f209_purge")
	purgeDetails := queueAuditDetailsFromEntry(t, purgeEntry)
	if purgeDetails["purged"] != "2" || purgeDetails["total_deleted"] != "2" || purgeDetails["sample_count"] != "2" || purgeDetails["truncated"] != "false" {
		t.Fatalf("purge audit details = %#v, want complete two-row summary", purgeDetails)
	}
	purgedJobs := queueAuditJobsFromEntry(t, purgeEntry, "purged_jobs")
	if len(purgedJobs) != 2 {
		t.Fatalf("purged audit jobs = %+v, want two terminal jobs", purgedJobs)
	}
	for _, job := range purgedJobs {
		if strings.Contains(job.Error, "query-secret") {
			t.Fatalf("purge audit leaked diagnostic secret: %+v", job)
		}
	}
}

func TestF209RefreshQueueAdminClosedPoolErrorsReturnNoPartialResults(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if oldest, err := store.OldestQueueJobs(ctx); err == nil || oldest != nil || !strings.Contains(err.Error(), "oldest queue jobs") {
		t.Fatalf("OldestQueueJobs(closed) = %#v, %v; want nil wrapped error", oldest, err)
	}
	if jobs, err := store.ListQueueJobsPage(ctx, "pending", 10, 0); err == nil || jobs != nil || !strings.Contains(err.Error(), "list queue jobs") {
		t.Fatalf("ListQueueJobsPage(closed) = %#v, %v; want nil wrapped error", jobs, err)
	}
	if count, err := store.PruneRefreshQueue(ctx, time.Hour); err == nil || count != 0 || !strings.Contains(err.Error(), "prune refresh queue") {
		t.Fatalf("PruneRefreshQueue(closed) = %d, %v; want zero wrapped error", count, err)
	}
	if count, err := store.PurgeQueue(ctx); err == nil || count != 0 || !strings.Contains(err.Error(), "purge queue") {
		t.Fatalf("PurgeQueue(closed) = %d, %v; want zero wrapped error", count, err)
	}
	if count, err := store.ClearQueue(ctx, []string{"pending"}); err == nil || count != 0 || !strings.Contains(err.Error(), "clear queue") {
		t.Fatalf("ClearQueue(closed) = %d, %v; want zero wrapped error", count, err)
	}
}

func assertF209QueueAuditTransition(t *testing.T, store *Store, ctx context.Context, action, beforeStatus, afterStatus string, beforePriority, afterPriority int) {
	t.Helper()
	entry := f209LatestQueueAudit(t, store, ctx, action)
	details := queueAuditDetailsFromEntry(t, entry)
	if details["previous_status"] != beforeStatus || details["new_status"] != afterStatus ||
		details["previous_priority"] != strconv.Itoa(beforePriority) || details["new_priority"] != strconv.Itoa(afterPriority) {
		t.Fatalf("%s transition audit details = %#v", action, details)
	}
	if previous, next := queueAuditJobsFromEntry(t, entry, "previous_job"), queueAuditJobsFromEntry(t, entry, "new_job"); len(previous) != 1 || len(next) != 1 || previous[0].Status != beforeStatus || next[0].Status != afterStatus {
		t.Fatalf("%s transition snapshots = %+v -> %+v", action, previous, next)
	}
}

func f209LatestQueueAudit(t *testing.T, store *Store, ctx context.Context, action string) db.AdminAuditLogEntry {
	t.Helper()
	entries, err := store.ListAdminAuditLog(ctx, 1)
	if err != nil || len(entries) != 1 || entries[0].Action != action {
		t.Fatalf("latest audit = %+v, %v; want action %q", entries, err, action)
	}
	return entries[0]
}

func f209QueueAuditCount(t *testing.T, store *Store, ctx context.Context) int {
	t.Helper()
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*)::int FROM admin_audit_log`).Scan(&count); err != nil {
		t.Fatalf("count admin audit rows: %v", err)
	}
	return count
}
