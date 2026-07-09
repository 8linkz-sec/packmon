package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/jackc/pgx/v5"
)

const adminAuditQueueJobSampleLimit = 100

func (s *Store) QueueStats(ctx context.Context) (*db.QueueStatsResult, error) {
	stats := &db.QueueStatsResult{}
	if err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status = $1)::int,
			COUNT(*) FILTER (WHERE status = $2)::int,
			COUNT(*) FILTER (WHERE status = $3)::int,
			COUNT(*) FILTER (WHERE status = $4)::int,
			COUNT(*) FILTER (WHERE status = $5)::int
		FROM refresh_queue`,
		db.RefreshStatusPending,
		db.RefreshStatusProcessing,
		db.RefreshStatusDone,
		db.RefreshStatusError,
		db.RefreshStatusPaused,
	).Scan(&stats.Pending, &stats.Processing, &stats.Done, &stats.Error, &stats.Paused); err != nil {
		return nil, fmt.Errorf("postgres: queue stats: %w", err)
	}
	return stats, nil
}

func (s *Store) OldestQueueJobs(ctx context.Context) (map[string]time.Time, error) {
	query := fmt.Sprintf(`
		SELECT source, MIN(requested_at)
		FROM refresh_queue
		WHERE %s
		  AND source <> ''
		GROUP BY source`, db.DrainableRefreshStatusPredicateSQL())
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("postgres: oldest queue jobs: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make(map[string]time.Time)
	for rows.Next() {
		var source string
		var requestedAt time.Time
		if err := rows.Scan(&source, &requestedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan oldest queue job: %w", err)
		}
		out[source] = requestedAt
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate oldest queue jobs: %w", err)
	}
	return out, nil
}

func (s *Store) ListQueueJobs(ctx context.Context, status string, limit int) ([]db.RefreshJob, error) {
	return s.ListQueueJobsPage(ctx, status, limit, 0)
}

func (s *Store) ListQueueJobsPage(ctx context.Context, status string, limit, offset int) ([]db.RefreshJob, error) {
	limit = clampLimit(limit, 50, 1000)
	if offset < 0 {
		offset = 0
	}
	if normalized, ok := db.NormalizeRefreshStatus(status); ok {
		status = normalized
	} else {
		status = ""
	}

	query := `
		SELECT id, ecosystem, name, source, priority, status, requested_at, processed_at, error
		FROM refresh_queue`
	args := []any{}
	if status != "" {
		query += ` WHERE status = $1`
		args = append(args, status)
	}
	query += fmt.Sprintf(` ORDER BY requested_at DESC, id DESC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list queue jobs: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make([]db.RefreshJob, 0)
	for rows.Next() {
		var (
			item        db.RefreshJob
			processedAt *time.Time
			errorText   *string
		)
		if err := rows.Scan(
			&item.ID,
			&item.Ecosystem,
			&item.Name,
			&item.Source,
			&item.Priority,
			&item.Status,
			&item.RequestedAt,
			&processedAt,
			&errorText,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan queue job row: %w", err)
		}
		item.ProcessedAt = processedAt
		if errorText != nil {
			item.Error = *errorText
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate queue jobs: %w", err)
	}
	return out, nil
}

func (s *Store) PurgeQueue(ctx context.Context) (int, error) {
	return purgeQueueTx(ctx, s.pool)
}

func (s *Store) PruneRefreshQueue(ctx context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-retention)
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM refresh_queue
		WHERE status = ANY($2::text[])
		  AND COALESCE(processed_at, requested_at) < $1`, cutoff, db.TerminalRefreshStatuses())
	if err != nil {
		return 0, fmt.Errorf("postgres: prune refresh queue: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) PurgeQueueWithAudit(ctx context.Context, audit *db.AdminAuditEntry) (int, error) {
	var purged int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		jobs, totalDeleted, err := deleteQueueJobsForStatusesWithAuditSampleTx(ctx, tx, db.TerminalRefreshStatuses())
		if err != nil {
			return err
		}
		if err := db.SetAdminAuditQueueJobsDetail(audit, "purged_jobs", jobs); err != nil {
			return fmt.Errorf("postgres: encode queue purge audit job details: %w", err)
		}
		purged = totalDeleted
		if err := db.SetAdminAuditDetail(audit, "purged", strconv.Itoa(purged)); err != nil {
			return fmt.Errorf("postgres: encode queue purge audit details: %w", err)
		}
		if err := setQueueAuditDeleteSummary(audit, totalDeleted, len(jobs)); err != nil {
			return fmt.Errorf("postgres: encode queue purge audit summary: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
	return purged, err
}

func purgeQueueTx(ctx context.Context, execer postgresExecer) (int, error) {
	tag, err := execer.Exec(ctx, `DELETE FROM refresh_queue WHERE status = ANY($1::text[])`, db.TerminalRefreshStatuses())
	if err != nil {
		return 0, fmt.Errorf("postgres: purge queue: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) UpdateQueueJobPriority(ctx context.Context, jobID, priority int) error {
	return updateQueueJobPriorityTx(ctx, s.pool, jobID, priority)
}

func (s *Store) UpdateQueueJobPriorityWithAudit(ctx context.Context, jobID, priority int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		normalizedPriority, err := normalizeRefreshQueuePriority(priority)
		if err != nil {
			return err
		}
		before, err := queueJobForAuditTx(ctx, tx, jobID, true)
		if err != nil {
			return err
		}
		if err := updateQueueJobPriorityTx(ctx, tx, jobID, normalizedPriority); err != nil {
			return err
		}
		after, err := queueJobForAuditTx(ctx, tx, jobID, false)
		if err != nil {
			return err
		}
		if err := setQueueTransitionAuditDetails(audit, before, after); err != nil {
			return fmt.Errorf("postgres: encode queue priority audit details: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func updateQueueJobPriorityTx(ctx context.Context, execer postgresExecer, jobID, priority int) error {
	priority, err := normalizeRefreshQueuePriority(priority)
	if err != nil {
		return err
	}
	tag, err := execer.Exec(ctx, `UPDATE refresh_queue SET priority = $2 WHERE id = $1`, jobID, priority)
	if err != nil {
		return fmt.Errorf("postgres: update queue job %d priority: %w", jobID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: update queue job %d priority: job not found", jobID)
	}
	return nil
}

func (s *Store) RetryQueueJob(ctx context.Context, jobID int) error {
	return retryQueueJobTx(ctx, s.pool, jobID)
}

func (s *Store) RetryQueueJobWithAudit(ctx context.Context, jobID int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		before, err := queueJobForAuditTx(ctx, tx, jobID, true)
		if err != nil {
			return err
		}
		if err := retryQueueJobTx(ctx, tx, jobID); err != nil {
			return err
		}
		after, err := queueJobForAuditTx(ctx, tx, jobID, false)
		if err != nil {
			return err
		}
		if err := setQueueTransitionAuditDetails(audit, before, after); err != nil {
			return fmt.Errorf("postgres: encode queue retry audit details: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func retryQueueJobTx(ctx context.Context, execer postgresExecer, jobID int) error {
	tag, err := execer.Exec(ctx, `
		UPDATE refresh_queue
		SET status = $2, requested_at = NOW(), processed_at = NULL, error = NULL
		WHERE id = $1 AND status = ANY($3::text[])`, jobID, db.RefreshStatusPending, db.RetryableRefreshStatuses())
	if err != nil {
		return fmt.Errorf("postgres: retry queue job %d: %w", jobID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: retry queue job %d: job not found or not retryable", jobID)
	}
	return nil
}

func (s *Store) PauseQueueJob(ctx context.Context, jobID int) error {
	return pauseQueueJobTx(ctx, s.pool, jobID)
}

func (s *Store) PauseQueueJobWithAudit(ctx context.Context, jobID int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		before, err := queueJobForAuditTx(ctx, tx, jobID, true)
		if err != nil {
			return err
		}
		if err := pauseQueueJobTx(ctx, tx, jobID); err != nil {
			return err
		}
		after, err := queueJobForAuditTx(ctx, tx, jobID, false)
		if err != nil {
			return err
		}
		if err := setQueueTransitionAuditDetails(audit, before, after); err != nil {
			return fmt.Errorf("postgres: encode queue pause audit details: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func pauseQueueJobTx(ctx context.Context, execer postgresExecer, jobID int) error {
	tag, err := execer.Exec(ctx, `UPDATE refresh_queue SET status = $2 WHERE id = $1 AND status = $3`, jobID, db.RefreshStatusPaused, db.RefreshStatusPending)
	if err != nil {
		return fmt.Errorf("postgres: pause queue job %d: %w", jobID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: pause queue job %d: job not found or not pending", jobID)
	}
	return nil
}

func (s *Store) ResumeQueueJob(ctx context.Context, jobID int) error {
	return resumeQueueJobTx(ctx, s.pool, jobID)
}

func (s *Store) ResumeQueueJobWithAudit(ctx context.Context, jobID int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		before, err := queueJobForAuditTx(ctx, tx, jobID, true)
		if err != nil {
			return err
		}
		if err := resumeQueueJobTx(ctx, tx, jobID); err != nil {
			return err
		}
		after, err := queueJobForAuditTx(ctx, tx, jobID, false)
		if err != nil {
			return err
		}
		if err := setQueueTransitionAuditDetails(audit, before, after); err != nil {
			return fmt.Errorf("postgres: encode queue resume audit details: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func resumeQueueJobTx(ctx context.Context, execer postgresExecer, jobID int) error {
	tag, err := execer.Exec(ctx, `UPDATE refresh_queue SET status = $2, processed_at = NULL, error = NULL WHERE id = $1 AND status = $3`, jobID, db.RefreshStatusPending, db.RefreshStatusPaused)
	if err != nil {
		return fmt.Errorf("postgres: resume queue job %d: %w", jobID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: resume queue job %d: job not found or not paused", jobID)
	}
	return nil
}

func queueJobForAuditTx(ctx context.Context, queryer postgresQueryRower, jobID int, lock bool) (db.RefreshJob, error) {
	query := `
		SELECT id, ecosystem, name, source, priority, status, requested_at, processed_at, error
		FROM refresh_queue
		WHERE id = $1`
	if lock {
		query += ` FOR UPDATE`
	}
	var (
		job         db.RefreshJob
		processedAt *time.Time
		errorText   *string
	)
	err := queryer.QueryRow(ctx, query, jobID).Scan(
		&job.ID,
		&job.Ecosystem,
		&job.Name,
		&job.Source,
		&job.Priority,
		&job.Status,
		&job.RequestedAt,
		&processedAt,
		&errorText,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return db.RefreshJob{}, fmt.Errorf("postgres: queue job %d not found", jobID)
		}
		return db.RefreshJob{}, fmt.Errorf("postgres: read queue job %d for audit: %w", jobID, err)
	}
	job.ProcessedAt = processedAt
	if errorText != nil {
		job.Error = *errorText
	}
	return job, nil
}

func setQueueTransitionAuditDetails(audit *db.AdminAuditEntry, before, after db.RefreshJob) error {
	if err := db.SetAdminAuditQueueJobsDetail(audit, "previous_job", []db.RefreshJob{before}); err != nil {
		return err
	}
	if err := db.SetAdminAuditQueueJobsDetail(audit, "new_job", []db.RefreshJob{after}); err != nil {
		return err
	}
	for key, value := range map[string]string{
		"previous_status":   before.Status,
		"new_status":        after.Status,
		"previous_priority": strconv.Itoa(before.Priority),
		"new_priority":      strconv.Itoa(after.Priority),
	} {
		if err := db.SetAdminAuditDetail(audit, key, value); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ClearQueue(ctx context.Context, statuses []string) (int, error) {
	return clearQueueTx(ctx, s.pool, statuses)
}

func (s *Store) ClearQueueWithAudit(ctx context.Context, statuses []string, audit *db.AdminAuditEntry) (int, error) {
	var cleared int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		normalized := db.NormalizeClearableRefreshStatuses(statuses)
		jobs, totalDeleted, err := deleteQueueJobsForStatusesWithAuditSampleTx(ctx, tx, normalized)
		if err != nil {
			return err
		}
		if err := db.SetAdminAuditQueueJobsDetail(audit, "cleared_jobs", jobs); err != nil {
			return fmt.Errorf("postgres: encode queue clear audit job details: %w", err)
		}
		cleared = totalDeleted
		if err := db.SetAdminAuditDetail(audit, "cleared", strconv.Itoa(cleared)); err != nil {
			return fmt.Errorf("postgres: encode queue clear audit details: %w", err)
		}
		if err := setQueueAuditDeleteSummary(audit, totalDeleted, len(jobs)); err != nil {
			return fmt.Errorf("postgres: encode queue clear audit summary: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
	return cleared, err
}

func deleteQueueJobsForStatusesWithAuditSampleTx(ctx context.Context, queryer postgresQueryRower, statuses []string) ([]db.RefreshJob, int, error) {
	statuses = db.NormalizeClearableRefreshStatuses(statuses)
	if len(statuses) == 0 {
		return nil, 0, nil
	}

	const query = `
		WITH deleted AS (
			DELETE FROM refresh_queue
			WHERE status = ANY($1::text[])
			RETURNING id, ecosystem, name, source, priority, status, requested_at, processed_at, error
		),
		stats AS (
			SELECT COUNT(*)::int AS total_deleted FROM deleted
		),
		sampled AS (
			SELECT id, ecosystem, name, source, priority, status, requested_at, processed_at, error
			FROM deleted
			ORDER BY id
			LIMIT $2
		)
		SELECT
			stats.total_deleted,
			COALESCE(
				jsonb_agg(
					jsonb_build_object(
						'id', sampled.id,
						'ecosystem', sampled.ecosystem,
						'name', sampled.name,
						'source', sampled.source,
						'priority', sampled.priority,
						'status', sampled.status,
						'requested_at', sampled.requested_at,
						'processed_at', sampled.processed_at,
						'error', sampled.error
					)
					ORDER BY sampled.id
				) FILTER (WHERE sampled.id IS NOT NULL),
				'[]'::jsonb
			)::text
		FROM stats
		LEFT JOIN sampled ON TRUE
		GROUP BY stats.total_deleted`

	var totalDeleted int
	var sampleJSON string
	if err := queryer.QueryRow(ctx, query, statuses, adminAuditQueueJobSampleLimit).Scan(&totalDeleted, &sampleJSON); err != nil {
		return nil, 0, fmt.Errorf("postgres: delete queue jobs for audit: %w", err)
	}

	jobs, err := decodeQueueAuditSample(sampleJSON)
	if err != nil {
		return nil, 0, err
	}
	return jobs, totalDeleted, nil
}

type queueAuditSampleRow struct {
	ID          int        `json:"id"`
	Ecosystem   string     `json:"ecosystem"`
	Name        string     `json:"name"`
	Source      string     `json:"source"`
	Priority    int        `json:"priority"`
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requested_at"`
	ProcessedAt *time.Time `json:"processed_at"`
	Error       *string    `json:"error"`
}

func decodeQueueAuditSample(raw string) ([]db.RefreshJob, error) {
	var rows []queueAuditSampleRow
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil, fmt.Errorf("postgres: decode queue audit sample: %w", err)
	}

	jobs := make([]db.RefreshJob, 0, len(rows))
	for _, row := range rows {
		job := db.RefreshJob{
			ID:          row.ID,
			Ecosystem:   row.Ecosystem,
			Name:        row.Name,
			Source:      row.Source,
			Priority:    row.Priority,
			Status:      row.Status,
			RequestedAt: row.RequestedAt,
			ProcessedAt: row.ProcessedAt,
		}
		if row.Error != nil {
			job.Error = *row.Error
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func setQueueAuditDeleteSummary(audit *db.AdminAuditEntry, totalDeleted, sampleCount int) error {
	if err := db.SetAdminAuditDetail(audit, "total_deleted", strconv.Itoa(totalDeleted)); err != nil {
		return err
	}
	if err := db.SetAdminAuditDetail(audit, "sample_count", strconv.Itoa(sampleCount)); err != nil {
		return err
	}
	return db.SetAdminAuditDetail(audit, "truncated", strconv.FormatBool(totalDeleted > sampleCount))
}

func clearQueueTx(ctx context.Context, execer postgresExecer, statuses []string) (int, error) {
	statuses = db.NormalizeClearableRefreshStatuses(statuses)
	if len(statuses) == 0 {
		return 0, nil
	}

	tag, err := execer.Exec(ctx, `DELETE FROM refresh_queue WHERE status = ANY($1::text[])`, statuses)
	if err != nil {
		return 0, fmt.Errorf("postgres: clear queue: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
