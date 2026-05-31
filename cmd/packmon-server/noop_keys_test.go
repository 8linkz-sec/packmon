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
	if len(keys) != 0 {
		t.Fatalf("ListAPIKeys() len = %d, want 0", len(keys))
	}
}
