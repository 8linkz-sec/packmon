package main

import (
	"context"
	"testing"
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
	if len(keys) != 1 || keys[0].ID != keyID || keys[0].DeletedAt == nil || keys[0].Name != "n8n" || keys[0].KeyHash != "hash" {
		t.Fatalf("ListAPIKeys() = %+v, want soft-deleted key metadata retained", keys)
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
