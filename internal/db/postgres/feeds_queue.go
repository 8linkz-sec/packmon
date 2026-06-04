package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/jackc/pgx/v5"
)

func (s *Store) GetFeedSyncStatus(ctx context.Context, feedName string) (*db.FeedSyncStatus, error) {
	const query = `
		SELECT
			feed_name,
			last_sync_at,
			EXTRACT(EPOCH FROM last_sync_duration),
			last_sync_status,
			last_error,
			entries_synced,
			entries_total,
			last_etag,
			last_commit_hash,
			metadata::text
		FROM feed_sync_status
		WHERE feed_name = $1`

	var (
		status      db.FeedSyncStatus
		lastSyncAt  *time.Time
		durationSec *float64
		lastError   *string
		lastETag    *string
		lastCommit  *string
		metadataRaw *string
	)

	err := s.pool.QueryRow(ctx, query, feedName).Scan(
		&status.FeedName,
		&lastSyncAt,
		&durationSec,
		&status.LastSyncStatus,
		&lastError,
		&status.EntriesSynced,
		&status.EntriesTotal,
		&lastETag,
		&lastCommit,
		&metadataRaw,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get feed sync status %s: %w", feedName, err)
	}

	status.LastSyncAt = lastSyncAt
	if durationSec != nil {
		d := time.Duration(*durationSec * float64(time.Second))
		status.LastSyncDuration = &d
	}
	if lastError != nil {
		status.LastError = *lastError
	}
	if lastETag != nil {
		status.LastEtag = *lastETag
	}
	if lastCommit != nil {
		status.LastCommitHash = *lastCommit
	}
	if metadataRaw != nil {
		status.Metadata = []byte(*metadataRaw)
	}

	return &status, nil
}

func (s *Store) UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error {
	const query = `
		INSERT INTO feed_sync_status (
			feed_name, last_sync_at, last_sync_duration, last_sync_status, last_error,
			entries_synced, entries_total, last_etag, last_commit_hash, metadata
		) VALUES (
			$1, $2, ($3 * interval '1 microsecond'), $4, $5,
			$6, $7, $8, $9, $10
		)
		ON CONFLICT (feed_name) DO UPDATE SET
			last_sync_at = EXCLUDED.last_sync_at,
			last_sync_duration = COALESCE(EXCLUDED.last_sync_duration, feed_sync_status.last_sync_duration),
			last_sync_status = EXCLUDED.last_sync_status,
			last_error = EXCLUDED.last_error,
			entries_synced = CASE
				WHEN EXCLUDED.last_sync_status = 'success'
					AND EXCLUDED.entries_synced = 0
					AND EXCLUDED.entries_total = 0
					THEN feed_sync_status.entries_synced
				ELSE EXCLUDED.entries_synced
			END,
			entries_total = CASE
				WHEN EXCLUDED.last_sync_status = 'success'
					AND EXCLUDED.entries_synced = 0
					AND EXCLUDED.entries_total = 0
					THEN feed_sync_status.entries_total
				ELSE EXCLUDED.entries_total
			END,
			last_etag = COALESCE(NULLIF(EXCLUDED.last_etag, ''), feed_sync_status.last_etag),
			last_commit_hash = COALESCE(NULLIF(EXCLUDED.last_commit_hash, ''), feed_sync_status.last_commit_hash),
			metadata = CASE
				WHEN EXCLUDED.metadata IS NULL OR EXCLUDED.metadata = '{}'::jsonb THEN feed_sync_status.metadata
				ELSE EXCLUDED.metadata
			END,
			updated_at = NOW()`

	var durationMicros any
	if status.LastSyncDuration != nil {
		durationMicros = status.LastSyncDuration.Microseconds()
	}

	_, err := s.pool.Exec(ctx, query,
		status.FeedName,
		status.LastSyncAt,
		durationMicros,
		status.LastSyncStatus,
		nullableString(status.LastError),
		status.EntriesSynced,
		status.EntriesTotal,
		nullableString(status.LastEtag),
		nullableString(status.LastCommitHash),
		normalizeJSON(status.Metadata, []byte("{}")),
	)
	if err != nil {
		return fmt.Errorf("postgres: upsert feed sync status %s: %w", status.FeedName, err)
	}
	return nil
}

func (s *Store) ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error) {
	const query = `
		SELECT
			feed_name,
			last_sync_at,
			EXTRACT(EPOCH FROM last_sync_duration),
			last_sync_status,
			last_error,
			entries_synced,
			entries_total,
			last_etag,
			last_commit_hash,
			metadata::text
		FROM feed_sync_status
		ORDER BY feed_name`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("postgres: list feed sync statuses: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.FeedSyncStatus, 0)
	for rows.Next() {
		var (
			status      db.FeedSyncStatus
			lastSyncAt  *time.Time
			durationSec *float64
			lastError   *string
			lastETag    *string
			lastCommit  *string
			metadataRaw *string
		)

		if err := rows.Scan(
			&status.FeedName,
			&lastSyncAt,
			&durationSec,
			&status.LastSyncStatus,
			&lastError,
			&status.EntriesSynced,
			&status.EntriesTotal,
			&lastETag,
			&lastCommit,
			&metadataRaw,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan feed sync status row: %w", err)
		}

		status.LastSyncAt = lastSyncAt
		if durationSec != nil {
			d := time.Duration(*durationSec * float64(time.Second))
			status.LastSyncDuration = &d
		}
		if lastError != nil {
			status.LastError = *lastError
		}
		if lastETag != nil {
			status.LastEtag = *lastETag
		}
		if lastCommit != nil {
			status.LastCommitHash = *lastCommit
		}
		if metadataRaw != nil {
			status.Metadata = []byte(*metadataRaw)
		}

		out = append(out, status)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate feed sync statuses: %w", err)
	}

	return out, nil
}

func (s *Store) EnqueueRefresh(ctx context.Context, job *db.RefreshJob) (bool, int, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, 0, fmt.Errorf("postgres: begin enqueue refresh tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const insertQuery = `
		INSERT INTO refresh_queue (ecosystem, name, source, priority, status)
		VALUES ($1, $2, $3, $4, 'pending')
		ON CONFLICT DO NOTHING
		RETURNING id`

	// Raise the priority of an already-active (pending/processing) job.
	const updateQuery = `
		UPDATE refresh_queue
		SET priority = LEAST(priority, $4),
		    status = 'pending',
		    processed_at = NULL,
		    error = NULL
		WHERE ecosystem = $1 AND name = $2 AND source = $3
		  AND status IN ('pending', 'processing')
		RETURNING id`

	// A job an admin has explicitly paused must never be resurrected; locate it
	// so we can report its position without changing its state.
	const selectPausedQuery = `
		SELECT id
		FROM refresh_queue
		WHERE ecosystem = $1 AND name = $2 AND source = $3
		  AND status = 'paused'
		ORDER BY id ASC
		LIMIT 1`

	var (
		jobID   int
		created bool
		settled bool
	)
	// The dedup index covers pending/processing/paused. Under READ COMMITTED the
	// INSERT, UPDATE and SELECT each take a fresh snapshot, so a conflicting job
	// can transition to done/error between statements. When that happens the row
	// leaves the partial index and none of the three statements match; retrying
	// the INSERT then succeeds because the conflict is gone. The loop is bounded
	// so a pathological churn cannot spin forever.
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts && !settled; attempt++ {
		switch insErr := tx.QueryRow(ctx, insertQuery, job.Ecosystem, job.Name, job.Source, job.Priority).Scan(&jobID); {
		case insErr == nil:
			created, settled = true, true
		case !errors.Is(insErr, pgx.ErrNoRows):
			return false, 0, fmt.Errorf("postgres: insert refresh job: %w", insErr)
		default:
			// Conflict with an existing pending/processing/paused job.
			switch updErr := tx.QueryRow(ctx, updateQuery, job.Ecosystem, job.Name, job.Source, job.Priority).Scan(&jobID); {
			case updErr == nil:
				settled = true
			case !errors.Is(updErr, pgx.ErrNoRows):
				return false, 0, fmt.Errorf("postgres: update existing refresh job: %w", updErr)
			default:
				// No active job to bump: it is either paused (leave it paused)
				// or it just transitioned to done/error (retry the insert).
				switch selErr := tx.QueryRow(ctx, selectPausedQuery, job.Ecosystem, job.Name, job.Source).Scan(&jobID); {
				case selErr == nil:
					settled = true
				case !errors.Is(selErr, pgx.ErrNoRows):
					return false, 0, fmt.Errorf("postgres: locate existing refresh job: %w", selErr)
				}
				// selErr == ErrNoRows: the conflicting job left the dedup index
				// between statements; loop to retry the insert.
			}
		}
	}
	if !settled {
		return false, 0, fmt.Errorf("postgres: enqueue refresh job: no row settled after %d attempts", maxAttempts)
	}

	position, err := queuePosition(ctx, tx, jobID, job.Source)
	if err != nil {
		return false, 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return false, 0, fmt.Errorf("postgres: commit enqueue refresh tx: %w", err)
	}
	return created, position, nil
}

func (s *Store) DequeueRefresh(ctx context.Context, source string) (*db.RefreshJob, error) {
	const query = `
		WITH next_job AS (
			SELECT id
			FROM refresh_queue
			WHERE source = $1 AND status = 'pending'
			ORDER BY priority ASC, requested_at ASC, id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE refresh_queue q
		SET status = 'processing', processed_at = NOW(), error = NULL
		FROM next_job
		WHERE q.id = next_job.id
		RETURNING q.id, q.ecosystem, q.name, q.source, q.priority, q.status, q.requested_at, q.processed_at, q.error`

	var (
		job         db.RefreshJob
		processedAt *time.Time
		errorText   *string
	)

	err := s.pool.QueryRow(ctx, query, source).Scan(
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
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: dequeue refresh: %w", err)
	}

	job.ProcessedAt = processedAt
	if errorText != nil {
		job.Error = *errorText
	}
	return &job, nil
}

func (s *Store) CompleteRefresh(ctx context.Context, jobID int, jobErr error) error {
	status := "done"
	var errorText any
	if jobErr != nil {
		status = "error"
		errorText = jobErr.Error()
	}

	_, err := s.pool.Exec(ctx,
		`UPDATE refresh_queue SET status = $2, processed_at = NOW(), error = $3 WHERE id = $1`,
		jobID, status, errorText,
	)
	if err != nil {
		return fmt.Errorf("postgres: complete refresh job %d: %w", jobID, err)
	}
	return nil
}

func (s *Store) ResetStuckJobs(ctx context.Context, source string, stuckThreshold time.Duration) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE refresh_queue
		SET status = 'pending', processed_at = NULL, error = NULL
		WHERE source = $1
		  AND status = 'processing'
		  AND processed_at IS NOT NULL
		  AND processed_at < NOW() - ($2 * interval '1 microsecond')`,
		source,
		stuckThreshold.Microseconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("postgres: reset stuck jobs for %s: %w", source, err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) GetPackageCheckStatus(ctx context.Context, ecosystem, name, source string) (*db.PackageCheckStatus, error) {
	const query = `
		SELECT ecosystem, name, source, last_checked_at, next_check_at, check_count, last_result::text
		FROM package_check_status
		WHERE ecosystem = $1 AND name = $2 AND source = $3`

	var (
		status        db.PackageCheckStatus
		lastCheckedAt *time.Time
		nextCheckAt   *time.Time
		lastResultRaw *string
	)

	err := s.pool.QueryRow(ctx, query, ecosystem, name, source).Scan(
		&status.Ecosystem,
		&status.Name,
		&status.Source,
		&lastCheckedAt,
		&nextCheckAt,
		&status.CheckCount,
		&lastResultRaw,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get package check status: %w", err)
	}

	status.LastCheckedAt = lastCheckedAt
	status.NextCheckAt = nextCheckAt
	if lastResultRaw != nil {
		status.LastResult = []byte(*lastResultRaw)
	}
	return &status, nil
}

func (s *Store) UpsertPackageCheckStatus(ctx context.Context, status *db.PackageCheckStatus) error {
	increment := status.CheckCount
	if increment <= 0 {
		increment = 1
	}

	const query = `
		INSERT INTO package_check_status (
			ecosystem, name, source, last_checked_at, next_check_at, check_count, last_result
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (ecosystem, name, source) DO UPDATE SET
			last_checked_at = EXCLUDED.last_checked_at,
			next_check_at = EXCLUDED.next_check_at,
			check_count = package_check_status.check_count + $6,
			last_result = EXCLUDED.last_result,
			updated_at = NOW()`

	_, err := s.pool.Exec(ctx, query,
		status.Ecosystem,
		status.Name,
		status.Source,
		status.LastCheckedAt,
		status.NextCheckAt,
		increment,
		normalizeJSON(status.LastResult, nil),
	)
	if err != nil {
		return fmt.Errorf("postgres: upsert package check status: %w", err)
	}
	return nil
}

func queuePosition(ctx context.Context, tx pgx.Tx, jobID int, source string) (int, error) {
	const query = `
		WITH selected AS (
			SELECT priority, requested_at, id
			FROM refresh_queue
			WHERE id = $1
		)
		SELECT COUNT(*)::int
		FROM refresh_queue q
		CROSS JOIN selected s
		WHERE q.source = $2
		  AND q.status IN ('pending', 'processing')
		  AND (
			q.priority < s.priority OR
			(q.priority = s.priority AND q.requested_at < s.requested_at) OR
			(q.priority = s.priority AND q.requested_at = s.requested_at AND q.id <= s.id)
		  )`

	var position int
	if err := tx.QueryRow(ctx, query, jobID, source).Scan(&position); err != nil {
		return 0, fmt.Errorf("postgres: queue position for job %d: %w", jobID, err)
	}
	return position, nil
}
