package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type f209QueueRow struct {
	scan func(...any) error
}

func (r f209QueueRow) Scan(dest ...any) error {
	return r.scan(dest...)
}

type f209QueueExecer struct {
	sql   string
	args  []any
	tag   pgconn.CommandTag
	err   error
	calls int
}

func (e *f209QueueExecer) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	e.calls++
	e.sql = sql
	e.args = append([]any(nil), args...)
	return e.tag, e.err
}

type f209QueueQueryRower struct {
	sql   string
	args  []any
	row   pgx.Row
	calls int
}

func (q *f209QueueQueryRower) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.calls++
	q.sql = sql
	q.args = append([]any(nil), args...)
	return q.row
}

func TestF209QueueMutationHelpersReportDriverAndStateFailures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	sentinel := errors.New("queue driver failed")
	tests := []struct {
		name      string
		tag       pgconn.CommandTag
		driverErr error
		call      func(postgresExecer) error
		wantError string
		wantArgs  []any
	}{
		{
			name:      "priority driver failure",
			driverErr: sentinel,
			call:      func(e postgresExecer) error { return updateQueueJobPriorityTx(ctx, e, 17, 2) },
			wantError: "postgres: update queue job 17 priority",
			wantArgs:  []any{17, 2},
		},
		{
			name:      "priority missing job",
			tag:       pgconn.NewCommandTag("UPDATE 0"),
			call:      func(e postgresExecer) error { return updateQueueJobPriorityTx(ctx, e, 17, 2) },
			wantError: "job not found",
			wantArgs:  []any{17, 2},
		},
		{
			name:      "retry driver failure",
			driverErr: sentinel,
			call:      func(e postgresExecer) error { return retryQueueJobTx(ctx, e, 18) },
			wantError: "postgres: retry queue job 18",
			wantArgs:  []any{18, db.RefreshStatusPending, db.RetryableRefreshStatuses()},
		},
		{
			name:      "retry invalid state",
			tag:       pgconn.NewCommandTag("UPDATE 0"),
			call:      func(e postgresExecer) error { return retryQueueJobTx(ctx, e, 18) },
			wantError: "job not found or not retryable",
			wantArgs:  []any{18, db.RefreshStatusPending, db.RetryableRefreshStatuses()},
		},
		{
			name:      "pause driver failure",
			driverErr: sentinel,
			call:      func(e postgresExecer) error { return pauseQueueJobTx(ctx, e, 19) },
			wantError: "postgres: pause queue job 19",
			wantArgs:  []any{19, db.RefreshStatusPaused, db.RefreshStatusPending},
		},
		{
			name:      "pause invalid state",
			tag:       pgconn.NewCommandTag("UPDATE 0"),
			call:      func(e postgresExecer) error { return pauseQueueJobTx(ctx, e, 19) },
			wantError: "job not found or not pending",
			wantArgs:  []any{19, db.RefreshStatusPaused, db.RefreshStatusPending},
		},
		{
			name:      "resume driver failure",
			driverErr: sentinel,
			call:      func(e postgresExecer) error { return resumeQueueJobTx(ctx, e, 20) },
			wantError: "postgres: resume queue job 20",
			wantArgs:  []any{20, db.RefreshStatusPending, db.RefreshStatusPaused},
		},
		{
			name:      "resume invalid state",
			tag:       pgconn.NewCommandTag("UPDATE 0"),
			call:      func(e postgresExecer) error { return resumeQueueJobTx(ctx, e, 20) },
			wantError: "job not found or not paused",
			wantArgs:  []any{20, db.RefreshStatusPending, db.RefreshStatusPaused},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			execer := &f209QueueExecer{tag: tc.tag, err: tc.driverErr}
			err := tc.call(execer)
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("queue mutation error = %v, want error containing %q", err, tc.wantError)
			}
			if tc.driverErr != nil && !errors.Is(err, sentinel) {
				t.Fatalf("queue mutation error = %v, want wrapped driver failure", err)
			}
			if execer.calls != 1 {
				t.Fatalf("Exec calls = %d, want 1", execer.calls)
			}
			if !reflect.DeepEqual(execer.args, tc.wantArgs) {
				t.Fatalf("Exec args = %#v, want %#v", execer.args, tc.wantArgs)
			}
		})
	}

	t.Run("priority validation precedes query", func(t *testing.T) {
		execer := &f209QueueExecer{}
		err := updateQueueJobPriorityTx(ctx, execer, 17, 4)
		if err == nil || !strings.Contains(err.Error(), "priority") {
			t.Fatalf("updateQueueJobPriorityTx() error = %v, want priority validation error", err)
		}
		if execer.calls != 0 {
			t.Fatalf("Exec calls = %d, want 0 for invalid priority", execer.calls)
		}
	})
}

func TestF209QueueDeleteHelpersNormalizeAndPreserveAtomicResults(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	t.Run("empty selection avoids query", func(t *testing.T) {
		t.Parallel()
		queryer := &f209QueueQueryRower{}
		jobs, total, err := deleteQueueJobsForStatusesWithAuditSampleTx(ctx, queryer, []string{"processing", "unknown"})
		if err != nil || jobs != nil || total != 0 {
			t.Fatalf("delete helper = %#v, %d, %v; want nil, 0, nil", jobs, total, err)
		}
		if queryer.calls != 0 {
			t.Fatalf("QueryRow calls = %d, want 0", queryer.calls)
		}
	})

	t.Run("scan failure returns no partial result", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("delete sample scan failed")
		queryer := &f209QueueQueryRower{row: f209QueueRow{scan: func(...any) error { return sentinel }}}
		jobs, total, err := deleteQueueJobsForStatusesWithAuditSampleTx(ctx, queryer, []string{" pending ", "PENDING", "error"})
		if jobs != nil || total != 0 || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "delete queue jobs for audit") {
			t.Fatalf("delete helper = %#v, %d, %v; want no partial result and wrapped failure", jobs, total, err)
		}
		wantStatuses := []string{db.RefreshStatusPending, db.RefreshStatusError}
		if queryer.calls != 1 || len(queryer.args) != 2 || !reflect.DeepEqual(queryer.args[0], wantStatuses) || queryer.args[1] != adminAuditQueueJobSampleLimit {
			t.Fatalf("QueryRow calls/args = %d/%#v, want normalized statuses and sample limit", queryer.calls, queryer.args)
		}
	})

	t.Run("decode failure returns no partial result", func(t *testing.T) {
		t.Parallel()
		queryer := &f209QueueQueryRower{row: f209QueueRow{scan: func(dest ...any) error {
			*dest[0].(*int) = 3
			*dest[1].(*string) = `{"broken"`
			return nil
		}}}
		jobs, total, err := deleteQueueJobsForStatusesWithAuditSampleTx(ctx, queryer, []string{"done"})
		if jobs != nil || total != 0 || err == nil || !strings.Contains(err.Error(), "decode queue audit sample") {
			t.Fatalf("delete helper = %#v, %d, %v; want no partial result and decode error", jobs, total, err)
		}
	})

	t.Run("sample preserves nullable fields", func(t *testing.T) {
		t.Parallel()
		requested := time.Date(2026, 11, 3, 7, 0, 0, 123000000, time.UTC)
		processed := requested.Add(time.Minute)
		raw, err := json.Marshal([]queueAuditSampleRow{
			{ID: 7, Ecosystem: "npm", Name: "pending", Source: "socket", Priority: 2, Status: db.RefreshStatusPending, RequestedAt: requested},
			{ID: 8, Ecosystem: "pypi", Name: "failed", Source: "socket", Priority: 1, Status: db.RefreshStatusError, RequestedAt: requested, ProcessedAt: &processed, Error: f209StringPtr("upstream failed")},
		})
		if err != nil {
			t.Fatalf("marshal fixture: %v", err)
		}
		queryer := &f209QueueQueryRower{row: f209QueueRow{scan: func(dest ...any) error {
			*dest[0].(*int) = 2
			*dest[1].(*string) = string(raw)
			return nil
		}}}
		jobs, total, err := deleteQueueJobsForStatusesWithAuditSampleTx(ctx, queryer, []string{"pending", "error"})
		if err != nil || total != 2 || len(jobs) != 2 {
			t.Fatalf("delete helper = %#v, %d, %v; want two decoded jobs", jobs, total, err)
		}
		if jobs[0].ProcessedAt != nil || jobs[0].Error != "" {
			t.Fatalf("first decoded job = %+v, want absent processed/error fields", jobs[0])
		}
		if jobs[1].ProcessedAt == nil || !jobs[1].ProcessedAt.Equal(processed) || jobs[1].Error != "upstream failed" {
			t.Fatalf("second decoded job = %+v, want populated processed/error fields", jobs[1])
		}
	})
}

func f209StringPtr(value string) *string {
	return &value
}

func TestF209QueueJobAuditReadAndDetailFailures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	requested := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	processed := requested.Add(time.Minute)
	diagnostic := "token=[redacted]"

	t.Run("locked row maps nullable values", func(t *testing.T) {
		t.Parallel()
		queryer := &f209QueueQueryRower{row: f209QueueRow{scan: func(dest ...any) error {
			*dest[0].(*int) = 31
			*dest[1].(*string) = "npm"
			*dest[2].(*string) = "left-pad"
			*dest[3].(*string) = "socket"
			*dest[4].(*int) = 2
			*dest[5].(*string) = db.RefreshStatusError
			*dest[6].(*time.Time) = requested
			*dest[7].(**time.Time) = &processed
			*dest[8].(**string) = &diagnostic
			return nil
		}}}
		job, err := queueJobForAuditTx(ctx, queryer, 31, true)
		if err != nil {
			t.Fatalf("queueJobForAuditTx() error = %v", err)
		}
		if job.ID != 31 || job.Name != "left-pad" || job.ProcessedAt == nil || !job.ProcessedAt.Equal(processed) || job.Error != diagnostic {
			t.Fatalf("queueJobForAuditTx() = %+v, want complete row", job)
		}
		if !strings.Contains(queryer.sql, "FOR UPDATE") || !reflect.DeepEqual(queryer.args, []any{31}) {
			t.Fatalf("locked query = %q args=%#v", queryer.sql, queryer.args)
		}
	})

	t.Run("missing row", func(t *testing.T) {
		t.Parallel()
		queryer := &f209QueueQueryRower{row: f209QueueRow{scan: func(...any) error { return pgx.ErrNoRows }}}
		job, err := queueJobForAuditTx(ctx, queryer, 404, false)
		if job.ID != 0 || err == nil || !strings.Contains(err.Error(), "queue job 404 not found") {
			t.Fatalf("queueJobForAuditTx() = %+v, %v; want not-found error", job, err)
		}
		if strings.Contains(queryer.sql, "FOR UPDATE") {
			t.Fatalf("unlocked query unexpectedly contains FOR UPDATE: %q", queryer.sql)
		}
	})

	t.Run("driver failure", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("read failed")
		queryer := &f209QueueQueryRower{row: f209QueueRow{scan: func(...any) error { return sentinel }}}
		job, err := queueJobForAuditTx(ctx, queryer, 32, true)
		if job.ID != 0 || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "read queue job 32 for audit") {
			t.Fatalf("queueJobForAuditTx() = %+v, %v; want wrapped read error", job, err)
		}
	})

	t.Run("malformed transition detail is not replaced", func(t *testing.T) {
		t.Parallel()
		audit := &db.AdminAuditEntry{Details: json.RawMessage(`{"broken"`)}
		before := append(json.RawMessage(nil), audit.Details...)
		err := setQueueTransitionAuditDetails(audit, db.RefreshJob{ID: 1}, db.RefreshJob{ID: 1})
		if err == nil || !reflect.DeepEqual(audit.Details, before) {
			t.Fatalf("setQueueTransitionAuditDetails() = %v, details=%q; want error without mutation", err, audit.Details)
		}
	})

	t.Run("delete summary is complete", func(t *testing.T) {
		t.Parallel()
		audit := &db.AdminAuditEntry{Details: json.RawMessage(`{"preserved":"yes"}`)}
		if err := setQueueAuditDeleteSummary(audit, 101, 100); err != nil {
			t.Fatalf("setQueueAuditDeleteSummary() error = %v", err)
		}
		details := map[string]string{}
		if err := json.Unmarshal(audit.Details, &details); err != nil {
			t.Fatalf("decode audit details: %v", err)
		}
		want := map[string]string{"preserved": "yes", "total_deleted": "101", "sample_count": "100", "truncated": "true"}
		if !reflect.DeepEqual(details, want) {
			t.Fatalf("delete summary = %#v, want %#v", details, want)
		}
	})
}

func TestF209QueueDeleteExecHelpersHandleEmptySuccessAndFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	sentinel := errors.New("delete failed")

	t.Run("clear empty selection", func(t *testing.T) {
		t.Parallel()
		execer := &f209QueueExecer{}
		count, err := clearQueueTx(ctx, execer, []string{"processing", "invalid"})
		if count != 0 || err != nil || execer.calls != 0 {
			t.Fatalf("clearQueueTx() = %d, %v, calls=%d; want 0, nil, 0", count, err, execer.calls)
		}
	})

	t.Run("clear normalized success", func(t *testing.T) {
		t.Parallel()
		execer := &f209QueueExecer{tag: pgconn.NewCommandTag("DELETE 3")}
		count, err := clearQueueTx(ctx, execer, []string{" pending ", "PENDING", "done"})
		if count != 3 || err != nil {
			t.Fatalf("clearQueueTx() = %d, %v; want 3, nil", count, err)
		}
		want := []string{db.RefreshStatusPending, db.RefreshStatusDone}
		if len(execer.args) != 1 || !reflect.DeepEqual(execer.args[0], want) {
			t.Fatalf("clearQueueTx args = %#v, want normalized statuses", execer.args)
		}
	})

	t.Run("clear driver failure", func(t *testing.T) {
		t.Parallel()
		execer := &f209QueueExecer{err: sentinel}
		count, err := clearQueueTx(ctx, execer, []string{"error"})
		if count != 0 || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "clear queue") {
			t.Fatalf("clearQueueTx() = %d, %v; want wrapped failure", count, err)
		}
	})

	for _, tc := range []struct {
		name      string
		tag       pgconn.CommandTag
		err       error
		wantCount int
	}{
		{name: "purge success", tag: pgconn.NewCommandTag("DELETE 4"), wantCount: 4},
		{name: "purge failure", err: sentinel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			execer := &f209QueueExecer{tag: tc.tag, err: tc.err}
			count, err := purgeQueueTx(ctx, execer)
			if count != tc.wantCount {
				t.Fatalf("purgeQueueTx() count = %d, want %d", count, tc.wantCount)
			}
			if tc.err == nil && err != nil {
				t.Fatalf("purgeQueueTx() error = %v, want nil", err)
			}
			if tc.err != nil && (!errors.Is(err, sentinel) || !strings.Contains(err.Error(), "purge queue")) {
				t.Fatalf("purgeQueueTx() error = %v, want wrapped failure", err)
			}
			if len(execer.args) != 1 || !reflect.DeepEqual(execer.args[0], db.TerminalRefreshStatuses()) {
				t.Fatalf("purgeQueueTx args = %#v, want terminal statuses", execer.args)
			}
		})
	}
}
