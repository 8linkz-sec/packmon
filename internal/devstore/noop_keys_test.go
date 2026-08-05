package devstore

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestNoopStoreDeleteAPIKeyRequiresRevocation(t *testing.T) {
	t.Parallel()

	store := newNoopStore()

	keyID, err := store.CreateAPIKey(context.Background(), "n8n", "hash", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	if err := store.DeleteAPIKey(context.Background(), keyID); err == nil {
		t.Fatal("DeleteAPIKey() error = nil, want error for active key")
	}

	if err := store.RevokeAPIKey(context.Background(), keyID); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}

	if err := store.DeleteAPIKey(context.Background(), keyID); err != nil {
		t.Fatalf("DeleteAPIKey() after revoke error = %v", err)
	}

	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("ListAPIKeys() = %+v, want key permanently removed", keys)
	}
	if found, err := store.FindAPIKeyByHash(context.Background(), "hash"); err != nil || found != nil {
		t.Fatalf("FindAPIKeyByHash(deleted) = %+v, %v; want nil nil", found, err)
	}
}

func TestNoopStoreRevokeAPIKeyRequiresStateChange(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	if err := store.RevokeAPIKey(context.Background(), 404); err == nil {
		t.Fatal("RevokeAPIKey(missing) error = nil, want not found")
	}

	keyID, err := store.CreateAPIKey(context.Background(), "ci", "hash", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if err := store.RevokeAPIKey(context.Background(), keyID); err != nil {
		t.Fatalf("RevokeAPIKey(first) error = %v", err)
	}
	if err := store.RevokeAPIKey(context.Background(), keyID); err == nil {
		t.Fatal("RevokeAPIKey(already revoked) error = nil, want failure")
	}
}

func TestNoopStoreRevokeAPIKeyWithAuditRequiresAuditBeforeMutation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	keyID, err := store.CreateAPIKey(ctx, "ci", "hash", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	err = store.RevokeAPIKeyWithAudit(ctx, keyID, nil)
	if !errors.Is(err, db.ErrAdminAuditLog) {
		t.Fatalf("RevokeAPIKeyWithAudit(nil audit) error = %v, want %v", err, db.ErrAdminAuditLog)
	}

	keys := mustNoopAPIKeys(t, store)
	if len(keys) != 1 || keys[0].RevokedAt != nil {
		t.Fatalf("ListAPIKeys() after nil audit revoke = %+v, want active key", keys)
	}
	if audit := mustNoopAuditLog(t, store, 10); len(audit) != 0 {
		t.Fatalf("ListAdminAuditLog() after nil audit revoke = %+v, want no audit rows", audit)
	}
}

func TestNoopStoreRevokeAPIKeyWithAuditRecordsStateAndAudit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	keyID, err := store.CreateAPIKey(ctx, "ci", "hash", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	audit := noopKeyAudit("api_key_revoke", keyID, "127.0.0.1")

	if err := store.RevokeAPIKeyWithAudit(ctx, keyID, audit); err != nil {
		t.Fatalf("RevokeAPIKeyWithAudit() error = %v", err)
	}

	keys := mustNoopAPIKeys(t, store)
	if len(keys) != 1 || keys[0].ID != keyID || keys[0].Name != "ci" || keys[0].KeyHash != "hash" || keys[0].RevokedAt == nil || keys[0].DeletedAt != nil {
		t.Fatalf("ListAPIKeys() after audited revoke = %+v, want revoked key with metadata retained", keys)
	}
	if found, err := store.FindAPIKeyByHash(ctx, "hash"); err != nil || found != nil {
		t.Fatalf("FindAPIKeyByHash(revoked) = %+v, %v; want nil nil", found, err)
	}

	auditLog := mustNoopAuditLog(t, store, 10)
	if len(auditLog) != 1 {
		t.Fatalf("ListAdminAuditLog() len = %d, want 1: %+v", len(auditLog), auditLog)
	}
	assertNoopKeyAudit(t, auditLog[0], "api_key_revoke", keyID, "127.0.0.1")
	if auditLog[0].CreatedAt.After(*keys[0].RevokedAt) {
		t.Fatalf("audit CreatedAt = %s after RevokedAt = %s, want audit recorded before mutation", auditLog[0].CreatedAt, keys[0].RevokedAt)
	}
}

func TestNoopStoreDeleteAPIKeyWithAuditRequiresRevokedKeyAndAudit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	keyID, err := store.CreateAPIKey(ctx, "ci", "hash", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if err := store.DeleteAPIKeyWithAudit(ctx, keyID, noopKeyAudit("api_key_delete", keyID, "127.0.0.1")); err == nil {
		t.Fatal("DeleteAPIKeyWithAudit(active key) error = nil, want failure")
	}
	keys := mustNoopAPIKeys(t, store)
	if len(keys) != 1 || keys[0].DeletedAt != nil {
		t.Fatalf("ListAPIKeys() after active delete = %+v, want not deleted", keys)
	}
	if audit := mustNoopAuditLog(t, store, 10); len(audit) != 0 {
		t.Fatalf("ListAdminAuditLog() after active delete = %+v, want no audit rows", audit)
	}

	if err := store.RevokeAPIKey(ctx, keyID); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}
	err = store.DeleteAPIKeyWithAudit(ctx, keyID, nil)
	if !errors.Is(err, db.ErrAdminAuditLog) {
		t.Fatalf("DeleteAPIKeyWithAudit(nil audit) error = %v, want %v", err, db.ErrAdminAuditLog)
	}
	keys = mustNoopAPIKeys(t, store)
	if len(keys) != 1 || keys[0].DeletedAt != nil {
		t.Fatalf("ListAPIKeys() after nil audit delete = %+v, want revoked but not deleted", keys)
	}
	if audit := mustNoopAuditLog(t, store, 10); len(audit) != 0 {
		t.Fatalf("ListAdminAuditLog() after nil audit delete = %+v, want no audit rows", audit)
	}
}

func TestNoopStoreDeleteAPIKeyWithAuditRecordsStateAndAudit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	keyID, err := store.CreateAPIKey(ctx, "n8n", "hash", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if err := store.RevokeAPIKey(ctx, keyID); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}
	audit := noopKeyAudit("api_key_delete", keyID, "127.0.0.1")

	if err := store.DeleteAPIKeyWithAudit(ctx, keyID, audit); err != nil {
		t.Fatalf("DeleteAPIKeyWithAudit() error = %v", err)
	}

	keys := mustNoopAPIKeys(t, store)
	if len(keys) != 0 {
		t.Fatalf("ListAPIKeys() after audited delete = %+v, want key permanently removed", keys)
	}
	if found, err := store.FindAPIKeyByHash(ctx, "hash"); err != nil || found != nil {
		t.Fatalf("FindAPIKeyByHash(deleted) = %+v, %v; want nil nil", found, err)
	}

	auditLog := mustNoopAuditLog(t, store, 10)
	if len(auditLog) != 1 {
		t.Fatalf("ListAdminAuditLog() len = %d, want 1: %+v", len(auditLog), auditLog)
	}
	assertNoopKeyAudit(t, auditLog[0], "api_key_delete", keyID, "127.0.0.1")
}

func TestNoopStoreAPIKeyAuditMutationsRejectTerminalStates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	revokedID, err := store.CreateAPIKey(ctx, "revoked", "hash-revoked", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(revoked) error = %v", err)
	}
	if err := store.RevokeAPIKeyWithAudit(ctx, revokedID, noopKeyAudit("api_key_revoke", revokedID, "127.0.0.1")); err != nil {
		t.Fatalf("RevokeAPIKeyWithAudit(first) error = %v", err)
	}
	if err := store.RevokeAPIKeyWithAudit(ctx, revokedID, noopKeyAudit("api_key_revoke_again", revokedID, "127.0.0.1")); err == nil {
		t.Fatal("RevokeAPIKeyWithAudit(already revoked) error = nil, want failure")
	}
	if audit := mustNoopAuditLog(t, store, 10); len(audit) != 1 {
		t.Fatalf("ListAdminAuditLog() after already revoked = %+v, want only first audit row", audit)
	}

	deletedID, err := store.CreateAPIKey(ctx, "deleted", "hash-deleted", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(deleted) error = %v", err)
	}
	if err := store.RevokeAPIKey(ctx, deletedID); err != nil {
		t.Fatalf("RevokeAPIKey(deleted setup) error = %v", err)
	}
	if err := store.DeleteAPIKeyWithAudit(ctx, deletedID, noopKeyAudit("api_key_delete", deletedID, "127.0.0.1")); err != nil {
		t.Fatalf("DeleteAPIKeyWithAudit(first) error = %v", err)
	}
	if err := store.DeleteAPIKeyWithAudit(ctx, deletedID, noopKeyAudit("api_key_delete_again", deletedID, "127.0.0.1")); err == nil {
		t.Fatal("DeleteAPIKeyWithAudit(already deleted) error = nil, want failure")
	}
	if err := store.RevokeAPIKeyWithAudit(ctx, deletedID, noopKeyAudit("api_key_revoke_deleted", deletedID, "127.0.0.1")); err == nil {
		t.Fatal("RevokeAPIKeyWithAudit(deleted) error = nil, want failure")
	}
	if audit := mustNoopAuditLog(t, store, 10); len(audit) != 2 {
		t.Fatalf("ListAdminAuditLog() after deleted-state failures = %+v, want only successful audit rows", audit)
	}
}

func TestNoopStoreAPIKeyIndexLockedFindsStoredLifecycleStates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()

	activeID, err := store.CreateAPIKey(ctx, "active", "hash-active", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(active) error = %v", err)
	}
	revokedID, err := store.CreateAPIKey(ctx, "revoked", "hash-revoked", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(revoked) error = %v", err)
	}
	if err := store.RevokeAPIKey(ctx, revokedID); err != nil {
		t.Fatalf("RevokeAPIKey(revoked) error = %v", err)
	}
	secondRevokedID, err := store.CreateAPIKey(ctx, "second-revoked", "hash-second-revoked", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(second-revoked) error = %v", err)
	}
	if err := store.RevokeAPIKey(ctx, secondRevokedID); err != nil {
		t.Fatalf("RevokeAPIKey(second-revoked setup) error = %v", err)
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	for _, keyID := range []int{activeID, revokedID, secondRevokedID} {
		index, err := store.apiKeyIndexLocked(keyID)
		if err != nil {
			t.Fatalf("apiKeyIndexLocked(%d) error = %v", keyID, err)
		}
		if index < 0 || index >= len(store.apiKeys) || store.apiKeys[index].ID != keyID {
			t.Fatalf("apiKeyIndexLocked(%d) = %d, keys = %+v", keyID, index, store.apiKeys)
		}
	}
	if _, err := store.apiKeyIndexLocked(404); err == nil {
		t.Fatal("apiKeyIndexLocked(missing) error = nil, want not found")
	}
}

func noopKeyAudit(action string, keyID int, ip string) *db.AdminAuditEntry {
	return &db.AdminAuditEntry{
		Action:  action,
		Details: json.RawMessage(`{"key_id":"` + strconv.Itoa(keyID) + `"}`),
		IP:      ip,
	}
}

func mustNoopAPIKeys(t *testing.T, store *Store) []db.APIKey {
	t.Helper()

	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	return keys
}

func mustNoopAuditLog(t *testing.T, store *Store, limit int) []db.AdminAuditLogEntry {
	t.Helper()

	auditLog, err := store.ListAdminAuditLog(context.Background(), limit)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	return auditLog
}

func assertNoopKeyAudit(t *testing.T, entry db.AdminAuditLogEntry, action string, keyID int, ip string) {
	t.Helper()

	if entry.Action != action || entry.IP != ip || entry.RowDigest == "" || entry.IntegrityStatus != db.AdminAuditIntegrityVerified {
		t.Fatalf("audit entry = %+v, want action %q, ip %q, digest, and verified integrity", entry, action, ip)
	}
	var details map[string]string
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("json.Unmarshal(audit details) error = %v", err)
	}
	if details["key_id"] != strconv.Itoa(keyID) {
		t.Fatalf("audit details = %v, want key_id %d", details, keyID)
	}
}
