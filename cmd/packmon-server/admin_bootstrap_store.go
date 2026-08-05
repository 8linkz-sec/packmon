package main

import (
	"context"
	"encoding/json"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
)

type adminBootstrapDBStore interface {
	GetAdminAuth(ctx context.Context) (*db.AdminAuth, error)
	UpsertAdminAuthWithAudit(ctx context.Context, passwordHash string, isBootstrap bool, audit *db.AdminAuditEntry) error
}

type adminBootstrapStoreAdapter struct {
	store adminBootstrapDBStore
}

var _ auth.AdminBootstrapStore = adminBootstrapStoreAdapter{}

func newAdminBootstrapStore(store adminBootstrapDBStore) adminBootstrapStoreAdapter {
	return adminBootstrapStoreAdapter{store: store}
}

func (s adminBootstrapStoreAdapter) GetAdminBootstrapAuth(ctx context.Context) (*auth.AdminBootstrapAuth, error) {
	record, err := s.store.GetAdminAuth(ctx)
	if err != nil || record == nil {
		return nil, err
	}
	return &auth.AdminBootstrapAuth{
		PasswordHash:        record.PasswordHash,
		PasswordIsBootstrap: record.PasswordIsBootstrap,
	}, nil
}

func (s adminBootstrapStoreAdapter) UpsertAdminBootstrapAuthWithAudit(ctx context.Context, passwordHash string, isBootstrap bool, audit *auth.AdminBootstrapAuditEntry) error {
	return s.store.UpsertAdminAuthWithAudit(ctx, passwordHash, isBootstrap, dbAdminBootstrapAuditEntry(audit))
}

func dbAdminBootstrapAuditEntry(audit *auth.AdminBootstrapAuditEntry) *db.AdminAuditEntry {
	if audit == nil {
		return nil
	}
	return &db.AdminAuditEntry{
		Action:        audit.Action,
		Details:       json.RawMessage(append([]byte(nil), audit.Details...)),
		IP:            audit.IP,
		CorrelationID: audit.CorrelationID,
	}
}
