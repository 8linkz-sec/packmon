package server

import (
	"context"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type apiKeyAuthDBStub struct {
	key        *db.APIKey
	lookupHash string
	touchedID  int
}

func (s *apiKeyAuthDBStub) FindAPIKeyByHash(_ context.Context, keyHash string) (*db.APIKey, error) {
	s.lookupHash = keyHash
	return s.key, nil
}

func (s *apiKeyAuthDBStub) TouchAPIKeyLastUsed(_ context.Context, keyID int) error {
	s.touchedID = keyID
	return nil
}

func TestAPIKeyAuthStoreMapsDatabaseKeyToCredentialView(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	dbStore := &apiKeyAuthDBStub{
		key: &db.APIKey{
			ID:        42,
			Name:      "ci-runner",
			KeyHash:   "stored-secret-hash",
			ExpiresAt: &expiresAt,
		},
	}
	store := apiKeyAuthStore{lookup: dbStore, lastUsed: dbStore}

	credential, err := store.FindAPIKeyCredentialByHash(context.Background(), "lookup-hash")
	if err != nil {
		t.Fatalf("FindAPIKeyCredentialByHash() error = %v", err)
	}
	if dbStore.lookupHash != "lookup-hash" {
		t.Fatalf("lookup hash = %q, want lookup-hash", dbStore.lookupHash)
	}
	if credential == nil {
		t.Fatal("credential = nil")
	}
	if credential.ID != 42 || credential.Name != "ci-runner" || credential.ExpiresAt != &expiresAt {
		t.Fatalf("credential = %+v, want id/name/expires only", credential)
	}

	if err := store.TouchAPIKeyLastUsed(context.Background(), credential.ID); err != nil {
		t.Fatalf("TouchAPIKeyLastUsed() error = %v", err)
	}
	if dbStore.touchedID != 42 {
		t.Fatalf("touched key ID = %d, want 42", dbStore.touchedID)
	}
}

func TestAPIKeyAuthStoreReturnsNilCredentialForMissingDatabaseKey(t *testing.T) {
	t.Parallel()

	dbStore := &apiKeyAuthDBStub{}
	store := apiKeyAuthStore{lookup: dbStore, lastUsed: dbStore}

	credential, err := store.FindAPIKeyCredentialByHash(context.Background(), "missing")
	if err != nil {
		t.Fatalf("FindAPIKeyCredentialByHash() error = %v", err)
	}
	if credential != nil {
		t.Fatalf("credential = %+v, want nil", credential)
	}
}
