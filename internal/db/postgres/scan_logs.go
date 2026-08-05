package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/jackc/pgx/v5"
)

func (s *Store) InsertScanLog(ctx context.Context, entry *db.ScanLogEntry) error {
	feedVersionsJSON, err := scanLogJSON(entry.FeedVersions, map[string]string{})
	if err != nil {
		return err
	}
	findingIDsJSON, err := scanLogJSON(entry.FindingIDs, []string{})
	if err != nil {
		return err
	}
	findingSeveritiesJSON, err := scanLogJSON(entry.FindingSeverities, []string{})
	if err != nil {
		return err
	}

	const query = `
		INSERT INTO scan_log (
			scan_id, repo_name, scanned_at,
			packages_count, findings_count, duration_ms, client_ip,
			client_version, api_key_id, api_key_name, correlation_id, idempotency_key, request_digest, result_digest,
			findings_blocking, block_threshold, feed_status, feed_versions, finding_ids, finding_severities,
			manual_advisories_count
		) VALUES (
			$1, $2, $3, $4, $5, $6, NULLIF($7, '')::inet, NULLIF($8, ''),
			NULLIF($9, 0), NULLIF($10, ''), $11, NULLIF($12, ''), $13, $14, $15, $16, $17,
			$18::jsonb, $19::jsonb, $20::jsonb, $21
		)
		ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING`

	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query,
			entry.ScanID,
			nullableString(entry.RepoName),
			entry.ScannedAt,
			entry.PackagesCount,
			entry.FindingsCount,
			entry.DurationMs,
			entry.ClientIP,
			nullableString(entry.ClientVersion),
			entry.APIKeyID,
			entry.APIKeyName,
			entry.CorrelationID,
			entry.IdempotencyKey,
			entry.RequestDigest,
			entry.ResultDigest,
			entry.FindingsBlocking,
			entry.BlockThreshold,
			entry.FeedStatus,
			string(feedVersionsJSON),
			string(findingIDsJSON),
			string(findingSeveritiesJSON),
			entry.ManualAdvisoriesCount,
		); err != nil {
			return fmt.Errorf("postgres: insert scan log: %w", err)
		}

		return nil
	})
}

func (s *Store) GetScanLogByIdempotencyKey(ctx context.Context, key string) (*db.ScanLogEntry, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, nil
	}
	var entry db.ScanLogEntry
	err := s.pool.QueryRow(ctx, `
		SELECT scan_id, COALESCE(request_digest, ''), COALESCE(result_digest, '')
		FROM scan_log
		WHERE idempotency_key = $1
		ORDER BY id DESC
		LIMIT 1`, key).Scan(&entry.ScanID, &entry.RequestDigest, &entry.ResultDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get scan log by idempotency key: %w", err)
	}
	entry.IdempotencyKey = key
	return &entry, nil
}

func (s *Store) ListRecentScans(ctx context.Context, limit, offset int) ([]db.ScanLogEntry, error) {
	limit = clampLimit(limit, 15, 100)
	if offset < 0 {
		offset = 0
	}

	rows, err := s.pool.Query(ctx, `
		SELECT scan_id, COALESCE(repo_name, ''), scanned_at, packages_count, findings_count, duration_ms,
		       COALESCE(client_ip::text, ''), COALESCE(client_version, ''), COALESCE(api_key_id, 0), COALESCE(api_key_name, ''),
		       COALESCE(correlation_id, ''), COALESCE(idempotency_key, ''), COALESCE(request_digest, ''), COALESCE(result_digest, ''),
		       findings_blocking, COALESCE(block_threshold, ''), COALESCE(feed_status, ''),
		       COALESCE(feed_versions, '{}'::jsonb)::text, COALESCE(finding_ids, '[]'::jsonb)::text,
		       COALESCE(finding_severities, '[]'::jsonb)::text, manual_advisories_count
		FROM scan_log
		ORDER BY scanned_at DESC, id DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("postgres: list recent scans: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make([]db.ScanLogEntry, 0)
	for rows.Next() {
		var entry db.ScanLogEntry
		var feedVersionsJSON string
		var findingIDsJSON string
		var findingSeveritiesJSON string
		if err := rows.Scan(
			&entry.ScanID,
			&entry.RepoName,
			&entry.ScannedAt,
			&entry.PackagesCount,
			&entry.FindingsCount,
			&entry.DurationMs,
			&entry.ClientIP,
			&entry.ClientVersion,
			&entry.APIKeyID,
			&entry.APIKeyName,
			&entry.CorrelationID,
			&entry.IdempotencyKey,
			&entry.RequestDigest,
			&entry.ResultDigest,
			&entry.FindingsBlocking,
			&entry.BlockThreshold,
			&entry.FeedStatus,
			&feedVersionsJSON,
			&findingIDsJSON,
			&findingSeveritiesJSON,
			&entry.ManualAdvisoriesCount,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan recent scan row: %w", err)
		}
		if err := decodeScanLogJSON(feedVersionsJSON, &entry.FeedVersions); err != nil {
			return nil, fmt.Errorf("postgres: decode scan log feed versions: %w", err)
		}
		if err := decodeScanLogJSON(findingIDsJSON, &entry.FindingIDs); err != nil {
			return nil, fmt.Errorf("postgres: decode scan log finding ids: %w", err)
		}
		if err := decodeScanLogJSON(findingSeveritiesJSON, &entry.FindingSeverities); err != nil {
			return nil, fmt.Errorf("postgres: decode scan log finding severities: %w", err)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate recent scans: %w", err)
	}
	return out, nil
}

func (s *Store) PruneScanLogs(ctx context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-retention)
	var removed int
	if err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			WITH deleted AS (
				DELETE FROM scan_log
				WHERE scanned_at < $1
				RETURNING 1
			)
			SELECT COUNT(*)::int
			FROM deleted`, cutoff).Scan(&removed); err != nil {
			return fmt.Errorf("postgres: prune scan logs: %w", err)
		}
		return nil
	}); err != nil {
		return 0, err
	}
	return removed, nil
}

func scanLogJSON(value, fallback any) ([]byte, error) {
	switch typed := value.(type) {
	case map[string]string:
		if typed == nil {
			value = fallback
		}
	case []string:
		if typed == nil {
			value = fallback
		}
	}
	out, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("postgres: encode scan log json: %w", err)
	}
	return out, nil
}

func decodeScanLogJSON(raw string, target any) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "null"
	}
	return json.Unmarshal([]byte(raw), target)
}
