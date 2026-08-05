package postgres

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ExportPrivacyMetadata(ctx context.Context, selector db.PrivacyExportSelector, audit *db.AdminAuditEntry) (*db.PrivacyExport, error) {
	var export *db.PrivacyExport
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		scans, err := queryPrivacyScanLogs(ctx, tx, selector)
		if err != nil {
			return err
		}
		audits, err := queryPrivacyAdminAuditLogs(ctx, tx, selector)
		if err != nil {
			return err
		}

		export = &db.PrivacyExport{
			GeneratedAt:     time.Now().UTC(),
			Selector:        selector,
			ScanLogs:        scans,
			AdminAuditLogs:  audits,
			ScanLogCount:    len(scans),
			AdminAuditCount: len(audits),
		}
		if err := db.SetAdminAuditDetail(audit, "selector_type", selector.Type); err != nil {
			return fmt.Errorf("postgres: encode privacy export audit details: %w", err)
		}
		if err := db.SetAdminAuditDetail(audit, "selector_digest", selector.Digest()); err != nil {
			return fmt.Errorf("postgres: encode privacy export audit details: %w", err)
		}
		if err := db.SetAdminAuditDetail(audit, "scan_log_count", strconv.Itoa(export.ScanLogCount)); err != nil {
			return fmt.Errorf("postgres: encode privacy export audit details: %w", err)
		}
		if err := db.SetAdminAuditDetail(audit, "admin_audit_count", strconv.Itoa(export.AdminAuditCount)); err != nil {
			return fmt.Errorf("postgres: encode privacy export audit details: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return export, nil
}

func queryPrivacyScanLogs(ctx context.Context, tx pgx.Tx, selector db.PrivacyExportSelector) ([]db.PrivacyExportScanLog, error) {
	where, args, err := privacyScanLogPredicate(selector)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT scan_id, COALESCE(repo_name, ''), scanned_at, packages_count, findings_count, duration_ms,
		       COALESCE(client_ip::text, ''), COALESCE(client_version, ''), COALESCE(api_key_id, 0), COALESCE(api_key_name, ''),
		       COALESCE(correlation_id, ''), COALESCE(idempotency_key, ''), COALESCE(request_digest, ''), COALESCE(result_digest, ''),
		       findings_blocking, COALESCE(block_threshold, ''), COALESCE(feed_status, ''),
		       COALESCE(feed_versions, '{}'::jsonb)::text, COALESCE(finding_ids, '[]'::jsonb)::text,
		       COALESCE(finding_severities, '[]'::jsonb)::text, manual_advisories_count
		FROM scan_log
		WHERE `+where+`
		ORDER BY scanned_at DESC, id DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: privacy export scan log: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make([]db.PrivacyExportScanLog, 0)
	for rows.Next() {
		var entry db.PrivacyExportScanLog
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
			return nil, fmt.Errorf("postgres: scan privacy scan log row: %w", err)
		}
		if err := decodeScanLogJSON(feedVersionsJSON, &entry.FeedVersions); err != nil {
			return nil, fmt.Errorf("postgres: decode privacy scan log feed versions: %w", err)
		}
		if err := decodeScanLogJSON(findingIDsJSON, &entry.FindingIDs); err != nil {
			return nil, fmt.Errorf("postgres: decode privacy scan log finding ids: %w", err)
		}
		if err := decodeScanLogJSON(findingSeveritiesJSON, &entry.FindingSeverities); err != nil {
			return nil, fmt.Errorf("postgres: decode privacy scan log finding severities: %w", err)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate privacy scan log rows: %w", err)
	}
	return out, nil
}

func queryPrivacyAdminAuditLogs(ctx context.Context, tx pgx.Tx, selector db.PrivacyExportSelector) ([]db.PrivacyExportAdminAudit, error) {
	where, args, err := privacyAdminAuditPredicate(selector)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id, action, details::text, COALESCE(ip::text, ''), COALESCE(correlation_id, ''), created_at, previous_digest, row_digest
		FROM admin_audit_log
		WHERE `+where+`
		ORDER BY created_at DESC, id DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: privacy export admin audit log: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make([]db.PrivacyExportAdminAudit, 0)
	for rows.Next() {
		var entry db.PrivacyExportAdminAudit
		var detailsRaw *string
		if err := rows.Scan(&entry.ID, &entry.Action, &detailsRaw, &entry.IP, &entry.CorrelationID, &entry.CreatedAt, &entry.PreviousDigest, &entry.RowDigest); err != nil {
			return nil, fmt.Errorf("postgres: scan privacy admin audit row: %w", err)
		}
		if detailsRaw != nil {
			entry.Details = []byte(*detailsRaw)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate privacy admin audit rows: %w", err)
	}
	annotatePrivacyAdminAuditIntegrity(out)
	return out, nil
}

func privacyScanLogPredicate(selector db.PrivacyExportSelector) (string, []any, error) {
	switch selector.Type {
	case db.PrivacySelectorClientIP:
		return `client_ip = $1::inet`, []any{selector.Value}, nil
	case db.PrivacySelectorRepoName:
		return `repo_name = $1`, []any{selector.Value}, nil
	case db.PrivacySelectorAPIKeyID:
		return `api_key_id = $1::int`, []any{selector.Value}, nil
	case db.PrivacySelectorAPIKeyName:
		return `api_key_name = $1`, []any{selector.Value}, nil
	case db.PrivacySelectorCorrelationID:
		return `correlation_id = $1`, []any{selector.Value}, nil
	default:
		return "", nil, fmt.Errorf("postgres: unsupported privacy selector %q", selector.Type)
	}
}

func privacyAdminAuditPredicate(selector db.PrivacyExportSelector) (string, []any, error) {
	switch selector.Type {
	case db.PrivacySelectorClientIP:
		return `(ip = $1::inet OR details->>'client_ip' = $2)`, []any{selector.Value, selector.Value}, nil
	case db.PrivacySelectorRepoName:
		return `(details->>'repo_name' = $1 OR details->>'repo' = $1)`, []any{selector.Value}, nil
	case db.PrivacySelectorAPIKeyID:
		return `(details->>'api_key_id' = $1 OR details->>'key_id' = $1)`, []any{selector.Value}, nil
	case db.PrivacySelectorAPIKeyName:
		return `(details->>'api_key_name' = $1 OR details->>'key_name' = $1)`, []any{selector.Value}, nil
	case db.PrivacySelectorCorrelationID:
		return `(correlation_id = $1 OR details->>'correlation_id' = $1)`, []any{selector.Value}, nil
	default:
		return "", nil, fmt.Errorf("postgres: unsupported privacy selector %q", selector.Type)
	}
}

func annotatePrivacyAdminAuditIntegrity(entries []db.PrivacyExportAdminAudit) {
	auditEntries := make([]db.AdminAuditLogEntry, 0, len(entries))
	for _, entry := range entries {
		auditEntries = append(auditEntries, db.AdminAuditLogEntry{
			ID:             entry.ID,
			Action:         entry.Action,
			Details:        entry.Details,
			IP:             entry.IP,
			CorrelationID:  entry.CorrelationID,
			CreatedAt:      entry.CreatedAt,
			PreviousDigest: entry.PreviousDigest,
			RowDigest:      entry.RowDigest,
		})
	}
	db.AnnotateAdminAuditIntegrity(auditEntries)
	for i := range auditEntries {
		entries[i].IntegrityStatus = auditEntries[i].IntegrityStatus
	}
}
