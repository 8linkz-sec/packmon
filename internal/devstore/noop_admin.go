package devstore

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func (s *Store) FindAPIKeyByHash(_ context.Context, keyHash string) (*db.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, apiKey := range s.apiKeys {
		if apiKey.RevokedAt == nil &&
			apiKey.DeletedAt == nil &&
			!apiKey.IsExpired(time.Now().UTC()) &&
			subtle.ConstantTimeCompare([]byte(apiKey.KeyHash), []byte(keyHash)) == 1 {
			copyValue := cloneAPIKey(apiKey)
			return &copyValue, nil
		}
	}
	return nil, nil
}

func (s *Store) TouchAPIKeyLastUsed(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.apiKeys {
		if s.apiKeys[i].ID != keyID {
			continue
		}
		if s.apiKeys[i].DeletedAt != nil {
			return nil
		}
		now := time.Now().UTC()
		s.apiKeys[i].LastUsedAt = &now
		return nil
	}
	return nil
}

func (s *Store) ListAPIKeys(context.Context) ([]db.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]db.APIKey, 0, len(s.apiKeys))
	for _, apiKey := range s.apiKeys {
		out = append(out, cloneAPIKey(apiKey))
	}
	slices.Reverse(out)
	return out, nil
}

func (s *Store) CreateAPIKey(_ context.Context, name, keyHash string, expiresAt *time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.createAPIKeyLocked(name, keyHash, expiresAt), nil
}

func (s *Store) CreateAPIKeyWithAudit(_ context.Context, name, keyHash string, expiresAt *time.Time, audit *db.AdminAuditEntry) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextAPIKeyID + 1
	if err := db.SetAdminAuditDetail(audit, "key_id", fmt.Sprint(id)); err != nil {
		return 0, err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return 0, fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	return s.createAPIKeyLocked(name, keyHash, expiresAt), nil
}

func (s *Store) createAPIKeyLocked(name, keyHash string, expiresAt *time.Time) int {
	s.nextAPIKeyID++
	s.apiKeys = append(s.apiKeys, db.APIKey{
		ID:        s.nextAPIKeyID,
		Name:      name,
		KeyHash:   keyHash,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: cloneTimePtr(expiresAt),
	})
	return s.nextAPIKeyID
}

func (s *Store) RevokeAPIKey(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.revokeAPIKeyLocked(keyID)
}

func (s *Store) RevokeAPIKeyWithAudit(_ context.Context, keyID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.apiKeyIndexLocked(keyID)
	if err != nil {
		return err
	}
	if s.apiKeys[index].RevokedAt != nil {
		return fmt.Errorf("api key %d already revoked", keyID)
	}
	if s.apiKeys[index].DeletedAt != nil {
		return fmt.Errorf("api key %d not found", keyID)
	}
	if audit == nil {
		return fmt.Errorf("%w: missing API key revoke audit entry", db.ErrAdminAuditLog)
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	now := time.Now().UTC()
	s.apiKeys[index].RevokedAt = &now
	return nil
}

func (s *Store) revokeAPIKeyLocked(keyID int) error {
	for i := range s.apiKeys {
		if s.apiKeys[i].ID != keyID {
			continue
		}
		if s.apiKeys[i].RevokedAt != nil {
			return fmt.Errorf("api key %d already revoked", keyID)
		}
		if s.apiKeys[i].DeletedAt != nil {
			return fmt.Errorf("api key %d not found", keyID)
		}
		now := time.Now().UTC()
		s.apiKeys[i].RevokedAt = &now
		return nil
	}
	return fmt.Errorf("api key %d not found", keyID)
}

func (s *Store) DeleteAPIKey(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.deleteAPIKeyLocked(keyID)
}

func (s *Store) DeleteAPIKeyWithAudit(_ context.Context, keyID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.apiKeyIndexLocked(keyID)
	if err != nil {
		return err
	}
	if s.apiKeys[index].RevokedAt == nil {
		return fmt.Errorf("api key %d is not revoked", keyID)
	}
	if s.apiKeys[index].DeletedAt != nil {
		return fmt.Errorf("api key %d not found", keyID)
	}
	if audit == nil {
		return fmt.Errorf("%w: missing API key delete audit entry", db.ErrAdminAuditLog)
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	now := time.Now().UTC()
	s.apiKeys[index].DeletedAt = &now
	return nil
}

func (s *Store) deleteAPIKeyLocked(keyID int) error {
	for i := range s.apiKeys {
		if s.apiKeys[i].ID != keyID {
			continue
		}
		if s.apiKeys[i].RevokedAt == nil {
			return fmt.Errorf("api key %d is not revoked", keyID)
		}
		if s.apiKeys[i].DeletedAt != nil {
			return fmt.Errorf("api key %d not found", keyID)
		}
		now := time.Now().UTC()
		s.apiKeys[i].DeletedAt = &now
		return nil
	}
	return fmt.Errorf("api key %d not found", keyID)
}

func (s *Store) apiKeyIndexLocked(keyID int) (int, error) {
	for i := range s.apiKeys {
		if s.apiKeys[i].ID == keyID {
			return i, nil
		}
	}
	return -1, fmt.Errorf("api key %d not found", keyID)
}

func (s *Store) GetAdminAuth(context.Context) (*db.AdminAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.adminAuth == nil {
		return nil, nil
	}
	copyValue := *s.adminAuth
	return &copyValue, nil
}

func (s *Store) UpsertAdminAuth(_ context.Context, passwordHash string, isBootstrap bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.upsertAdminAuthLocked(passwordHash, isBootstrap)
	return nil
}

func (s *Store) UpsertAdminAuthWithAudit(_ context.Context, passwordHash string, isBootstrap bool, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	s.upsertAdminAuthLocked(passwordHash, isBootstrap)
	return nil
}

func (s *Store) ChangeAdminPasswordWithAudit(_ context.Context, newHash, expectedOldHash string, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.adminAuth == nil || s.adminAuth.PasswordHash != expectedOldHash {
		return db.ErrAdminAuthConflict
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	s.upsertAdminAuthLocked(newHash, false)
	return nil
}

func (s *Store) upsertAdminAuthLocked(passwordHash string, isBootstrap bool) {
	now := time.Now().UTC()
	if s.adminAuth == nil {
		s.adminAuth = &db.AdminAuth{
			PasswordHash:        passwordHash,
			PasswordIsBootstrap: isBootstrap,
			CreatedAt:           now,
			PasswordChangedAt:   nil,
			LastLoginAt:         nil,
		}
		return
	}

	s.adminAuth.PasswordHash = passwordHash
	s.adminAuth.PasswordIsBootstrap = isBootstrap
	if isBootstrap {
		s.adminAuth.PasswordChangedAt = nil
	} else {
		s.adminAuth.PasswordChangedAt = &now
	}
}

func (s *Store) InsertAdminAuditLog(_ context.Context, entry *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.insertAdminAuditLogLocked(entry)
}

func (s *Store) insertAdminAuditLogLocked(entry *db.AdminAuditEntry) error {
	if entry == nil {
		return nil
	}
	s.nextAuditID++
	now := time.Now().UTC().Truncate(time.Microsecond)
	previousDigest := ""
	if len(s.auditLog) > 0 {
		previousDigest = s.auditLog[len(s.auditLog)-1].RowDigest
	}
	auditEntry := db.AdminAuditLogEntry{
		ID:             s.nextAuditID,
		Action:         entry.Action,
		Details:        append(json.RawMessage(nil), entry.Details...),
		IP:             entry.IP,
		CreatedAt:      now,
		PreviousDigest: previousDigest,
	}
	auditEntry.RowDigest = db.ComputeAdminAuditDigest(auditEntry)
	auditEntry.IntegrityStatus = db.AdminAuditIntegrityStatus(auditEntry)
	s.auditLog = append(s.auditLog, auditEntry)

	if entry.Action == "login_success" && s.adminAuth != nil {
		s.adminAuth.LastLoginAt = &now
	}

	return nil
}

func (s *Store) ListAdminAuditLog(_ context.Context, limit int) ([]db.AdminAuditLogEntry, error) {
	return s.ListAdminAuditLogPage(context.Background(), limit, 0)
}

func (s *Store) ListAdminAuditLogPage(_ context.Context, limit, offset int) ([]db.AdminAuditLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || limit > len(s.auditLog) {
		limit = len(s.auditLog)
	}
	if offset < 0 {
		offset = 0
	}

	out := make([]db.AdminAuditLogEntry, 0, limit)
	for i, skipped := len(s.auditLog)-1, 0; i >= 0 && len(out) < limit; i-- {
		if skipped < offset {
			skipped++
			continue
		}
		out = append(out, cloneAdminAuditLogEntry(s.auditLog[i]))
	}
	db.AnnotateAdminAuditIntegrity(out)
	return out, nil
}

func (s *Store) PruneAdminAuditLogs(_ context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().Add(-retention)
	kept := s.auditLog[:0]
	pruned := 0
	for _, entry := range s.auditLog {
		if entry.CreatedAt.Before(cutoff) {
			pruned++
			continue
		}
		kept = append(kept, entry)
	}
	s.auditLog = kept
	return pruned, nil
}

func (s *Store) PruneDeletedAPIKeys(_ context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().Add(-retention)
	kept := s.apiKeys[:0]
	pruned := 0
	for _, apiKey := range s.apiKeys {
		if apiKey.DeletedAt != nil && apiKey.DeletedAt.Before(cutoff) {
			pruned++
			continue
		}
		kept = append(kept, apiKey)
	}
	s.apiKeys = kept
	return pruned, nil
}
