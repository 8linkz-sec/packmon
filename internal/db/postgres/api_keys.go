package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/jackc/pgx/v5"
)

func (s *Store) FindAPIKeyByHash(ctx context.Context, keyHash string) (*db.APIKey, error) {
	key, err := scanAPIKey(s.pool.QueryRow(ctx, `
		SELECT id, name, key_hash, created_at, revoked_at, last_used_at, expires_at, deleted_at
		FROM api_keys
		WHERE key_hash = $1
		  AND revoked_at IS NULL
		  AND deleted_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())`, keyHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find API key by hash: %w", err)
	}
	return key, nil
}

func (s *Store) TouchAPIKeyLastUsed(ctx context.Context, keyID int) error {
	_, err := s.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, keyID)
	if err != nil {
		return fmt.Errorf("postgres: touch API key last used: %w", err)
	}
	return nil
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]db.APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, key_hash, created_at, revoked_at, last_used_at, expires_at, deleted_at
		FROM api_keys
		ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list API keys: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make([]db.APIKey, 0)
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan API key row: %w", err)
		}
		out = append(out, *key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate API keys: %w", err)
	}
	return out, nil
}

func (s *Store) ListAPIKeysPage(ctx context.Context, limit, offset int) ([]db.APIKey, error) {
	if limit <= 0 {
		return nil, nil
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, name, key_hash, created_at, revoked_at, last_used_at, expires_at, deleted_at
		FROM api_keys
		ORDER BY created_at DESC, id DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("postgres: list API key page: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make([]db.APIKey, 0, limit)
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan API key page row: %w", err)
		}
		out = append(out, *key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate API key page: %w", err)
	}
	return out, nil
}

func (s *Store) CreateAPIKey(ctx context.Context, name, keyHash string, expiresAt *time.Time) (int, error) {
	return createAPIKeyTx(ctx, s.pool, name, keyHash, expiresAt)
}

func (s *Store) CreateAPIKeyWithAudit(ctx context.Context, name, keyHash string, expiresAt *time.Time, audit *db.AdminAuditEntry) (int, error) {
	var id int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		id, err = createAPIKeyTx(ctx, tx, name, keyHash, expiresAt)
		if err != nil {
			return err
		}
		if err := db.SetAdminAuditDetail(audit, "key_id", strconv.Itoa(id)); err != nil {
			return fmt.Errorf("postgres: encode API key create audit details: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
	return id, err
}

func createAPIKeyTx(ctx context.Context, q postgresQuerier, name, keyHash string, expiresAt *time.Time) (int, error) {
	var id int
	err := q.QueryRow(ctx,
		`INSERT INTO api_keys (name, key_hash, expires_at) VALUES ($1, $2, $3) RETURNING id`,
		name, keyHash, expiresAt,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("postgres: create API key: %w", err)
	}
	return id, nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, keyID int) error {
	return revokeAPIKeyTx(ctx, s.pool, keyID)
}

func (s *Store) RevokeAPIKeyWithAudit(ctx context.Context, keyID int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := revokeAPIKeyTx(ctx, tx, keyID); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func revokeAPIKeyTx(ctx context.Context, execer postgresExecer, keyID int) error {
	tag, err := execer.Exec(ctx,
		`UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL AND deleted_at IS NULL`,
		keyID,
	)
	if err != nil {
		return fmt.Errorf("postgres: revoke API key %d: %w", keyID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: revoke API key %d: key not found or already revoked", keyID)
	}
	return nil
}

func (s *Store) DeleteAPIKey(ctx context.Context, keyID int) error {
	return deleteAPIKeyTx(ctx, s.pool, keyID)
}

func (s *Store) DeleteAPIKeyWithAudit(ctx context.Context, keyID int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := deleteAPIKeyTx(ctx, tx, keyID); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

// deleteAPIKeyTx permanently removes a revoked API key row. scan_log rows
// referencing the key keep their history through ON DELETE SET NULL, and the
// caller-supplied admin audit entry records the deletion.
func deleteAPIKeyTx(ctx context.Context, execer postgresExecer, keyID int) error {
	tag, err := execer.Exec(ctx,
		`DELETE FROM api_keys WHERE id = $1 AND revoked_at IS NOT NULL`,
		keyID,
	)
	if err != nil {
		return fmt.Errorf("postgres: delete API key %d: %w", keyID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: delete API key %d: key not found or not revoked", keyID)
	}
	return nil
}
