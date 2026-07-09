package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/jackc/pgx/v5"
)

func (s *Store) GetAdminAuth(ctx context.Context) (*db.AdminAuth, error) {
	const query = `
		SELECT password_hash, password_is_bootstrap, created_at, password_changed_at, last_login_at
		FROM admin_auth
		WHERE id = 1`

	var (
		authInfo          db.AdminAuth
		passwordChangedAt *time.Time
		lastLoginAt       *time.Time
	)

	err := s.pool.QueryRow(ctx, query).Scan(
		&authInfo.PasswordHash,
		&authInfo.PasswordIsBootstrap,
		&authInfo.CreatedAt,
		&passwordChangedAt,
		&lastLoginAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get admin auth: %w", err)
	}

	authInfo.PasswordChangedAt = passwordChangedAt
	authInfo.LastLoginAt = lastLoginAt
	return &authInfo, nil
}

func (s *Store) UpsertAdminAuth(ctx context.Context, passwordHash string, isBootstrap bool) error {
	return upsertAdminAuthTx(ctx, s.pool, passwordHash, isBootstrap)
}

const (
	lockAdminAuthForMutationSQL = `SELECT id FROM admin_auth WHERE id = 1 FOR UPDATE`
	changeAdminPasswordSQL      = `
		UPDATE admin_auth
		SET password_hash = $1,
			password_is_bootstrap = FALSE,
			password_changed_at = NOW()
		WHERE id = 1 AND password_hash = $2`
	insertAdminAuditLogLockSQL = `LOCK TABLE admin_audit_log IN SHARE ROW EXCLUSIVE MODE`
)

type adminAuthAuditMutationStep string

const (
	adminAuthAuditStepLockAuth    adminAuthAuditMutationStep = "lock_admin_auth"
	adminAuthAuditStepMutate      adminAuthAuditMutationStep = "mutate_admin_auth"
	adminAuthAuditStepInsertAudit adminAuthAuditMutationStep = "insert_admin_audit"
)

func adminAuthAuditMutationSteps() []adminAuthAuditMutationStep {
	return []adminAuthAuditMutationStep{
		adminAuthAuditStepLockAuth,
		adminAuthAuditStepMutate,
		adminAuthAuditStepInsertAudit,
	}
}

func (s *Store) UpsertAdminAuthWithAudit(ctx context.Context, passwordHash string, isBootstrap bool, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return runAdminAuthAuditMutationTx(ctx, tx, func() error {
			return upsertAdminAuthTx(ctx, tx, passwordHash, isBootstrap)
		}, audit)
	})
}

func (s *Store) ChangeAdminPasswordWithAudit(ctx context.Context, newHash, expectedOldHash string, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return runAdminAuthAuditMutationTx(ctx, tx, func() error {
			return changeAdminPasswordTx(ctx, tx, newHash, expectedOldHash)
		}, audit)
	})
}

func runAdminAuthAuditMutationTx(ctx context.Context, tx pgx.Tx, mutate func() error, audit *db.AdminAuditEntry) error {
	for _, step := range adminAuthAuditMutationSteps() {
		switch step {
		case adminAuthAuditStepLockAuth:
			if err := lockAdminAuthForMutationTx(ctx, tx); err != nil {
				return err
			}
		case adminAuthAuditStepMutate:
			if err := mutate(); err != nil {
				return err
			}
		case adminAuthAuditStepInsertAudit:
			if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
				return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
			}
		}
	}
	return nil
}

func lockAdminAuthForMutationTx(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, lockAdminAuthForMutationSQL); err != nil {
		return fmt.Errorf("postgres: lock admin auth: %w", err)
	}
	return nil
}

func changeAdminPasswordTx(ctx context.Context, execer postgresExecer, newHash, expectedOldHash string) error {
	tag, err := execer.Exec(ctx, changeAdminPasswordSQL, newHash, expectedOldHash)
	if err != nil {
		return fmt.Errorf("postgres: change admin password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return db.ErrAdminAuthConflict
	}
	return nil
}

func upsertAdminAuthTx(ctx context.Context, execer postgresExecer, passwordHash string, isBootstrap bool) error {
	const query = `
		INSERT INTO admin_auth (id, username, password_hash, password_is_bootstrap)
		VALUES (1, 'admin', $1, $2)
		ON CONFLICT (id) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			password_is_bootstrap = EXCLUDED.password_is_bootstrap,
			password_changed_at = NOW()`

	_, err := execer.Exec(ctx, query, passwordHash, isBootstrap)
	if err != nil {
		return fmt.Errorf("postgres: upsert admin auth: %w", err)
	}
	return nil
}

func (s *Store) InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return insertAdminAuditLogTx(ctx, tx, entry)
	})
}

func insertAdminAuditLogTx(ctx context.Context, tx pgx.Tx, entry *db.AdminAuditEntry) error {
	if entry.Action == "login_success" {
		if err := lockAdminAuthForMutationTx(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, insertAdminAuditLogLockSQL); err != nil {
		return fmt.Errorf("lock admin audit log: %w", err)
	}

	var id int
	if err := tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('admin_audit_log', 'id'))::int`).Scan(&id); err != nil {
		return fmt.Errorf("reserve admin audit id: %w", err)
	}

	previousDigest := ""
	err := tx.QueryRow(ctx, `
		SELECT row_digest
		FROM admin_audit_log
		ORDER BY id DESC
		LIMIT 1`).Scan(&previousDigest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read previous admin audit digest: %w", err)
	}

	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	var (
		detailsText   string
		ipText        string
		correlationID string
	)
	if err := tx.QueryRow(ctx,
		`INSERT INTO admin_audit_log (id, action, details, ip, correlation_id, created_at, previous_digest, row_digest)
		 VALUES ($1, $2, $3, NULLIF($4, '')::inet, $5, $6, $7, '')
		 RETURNING COALESCE(details::text, ''), COALESCE(ip::text, ''), COALESCE(correlation_id, ''), created_at`,
		id,
		entry.Action,
		normalizeJSON(entry.Details, nil),
		entry.IP,
		entry.CorrelationID,
		createdAt,
		previousDigest,
	).Scan(&detailsText, &ipText, &correlationID, &createdAt); err != nil {
		return fmt.Errorf("insert admin audit log: %w", err)
	}

	auditEntry := db.AdminAuditLogEntry{
		ID:             id,
		Action:         entry.Action,
		Details:        json.RawMessage(detailsText),
		IP:             ipText,
		CorrelationID:  correlationID,
		CreatedAt:      createdAt,
		PreviousDigest: previousDigest,
	}
	rowDigest := db.ComputeAdminAuditDigest(auditEntry)
	if _, err := tx.Exec(ctx, `UPDATE admin_audit_log SET row_digest = $1 WHERE id = $2`, rowDigest, id); err != nil {
		return fmt.Errorf("update admin audit digest: %w", err)
	}

	if entry.Action == "login_success" {
		if _, err := tx.Exec(ctx, `UPDATE admin_auth SET last_login_at = NOW() WHERE id = 1`); err != nil {
			return fmt.Errorf("update admin last_login_at: %w", err)
		}
	}
	return nil
}

func (s *Store) ListAdminAuditLog(ctx context.Context, limit int) ([]db.AdminAuditLogEntry, error) {
	return s.ListAdminAuditLogPage(ctx, limit, 0)
}

func (s *Store) ListAdminAuditLogPage(ctx context.Context, limit, offset int) ([]db.AdminAuditLogEntry, error) {
	limit = clampLimit(limit, 100, 200)
	if offset < 0 {
		offset = 0
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, action, details::text, COALESCE(ip::text, ''), COALESCE(correlation_id, ''), created_at, previous_digest, row_digest
		FROM admin_audit_log
		ORDER BY created_at DESC, id DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("postgres: list admin audit log: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make([]db.AdminAuditLogEntry, 0)
	for rows.Next() {
		var (
			item       db.AdminAuditLogEntry
			detailsRaw *string
		)
		if err := rows.Scan(&item.ID, &item.Action, &detailsRaw, &item.IP, &item.CorrelationID, &item.CreatedAt, &item.PreviousDigest, &item.RowDigest); err != nil {
			return nil, fmt.Errorf("postgres: scan admin audit row: %w", err)
		}
		if detailsRaw != nil {
			item.Details = []byte(*detailsRaw)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate admin audit log: %w", err)
	}
	db.AnnotateAdminAuditIntegrity(out)
	return out, nil
}

func (s *Store) PruneAdminAuditLogs(ctx context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-retention)
	tag, err := s.pool.Exec(ctx, `DELETE FROM admin_audit_log WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres: prune admin audit logs: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
