package server

import (
	"context"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
)

type apiKeyAuthLookupStore interface {
	FindAPIKeyByHash(ctx context.Context, keyHash string) (*db.APIKey, error)
}

type apiKeyAuthLastUsedStore interface {
	TouchAPIKeyLastUsed(ctx context.Context, keyID int) error
}

type apiKeyAuthStore struct {
	lookup   apiKeyAuthLookupStore
	lastUsed apiKeyAuthLastUsedStore
}

func newAPIKeyAuthStore(store db.Store) apiKeyAuthStore {
	return apiKeyAuthStore{lookup: store, lastUsed: store}
}

func (s apiKeyAuthStore) FindAPIKeyCredentialByHash(ctx context.Context, keyHash string) (*auth.APIKeyCredential, error) {
	apiKey, err := s.lookup.FindAPIKeyByHash(ctx, keyHash)
	if err != nil || apiKey == nil {
		return nil, err
	}
	return &auth.APIKeyCredential{
		ID:        apiKey.ID,
		Name:      apiKey.Name,
		ExpiresAt: apiKey.ExpiresAt,
	}, nil
}

func (s apiKeyAuthStore) TouchAPIKeyLastUsed(ctx context.Context, keyID int) error {
	return s.lastUsed.TouchAPIKeyLastUsed(ctx, keyID)
}
