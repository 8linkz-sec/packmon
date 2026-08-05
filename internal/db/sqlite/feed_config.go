package sqlite

import (
	"context"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func (*Store) GetFeedConfig(context.Context, string) (*db.FeedConfig, error) {
	return nil, nil
}

func (*Store) UpsertFeedConfig(context.Context, *db.FeedConfig) error {
	return nil
}

func (*Store) UpsertFeedConfigWithAudit(context.Context, *db.FeedConfig, *db.AdminAuditEntry) error {
	return nil
}

func (*Store) DeleteFeedConfig(context.Context, string) error {
	return nil
}

func (*Store) DeleteFeedConfigWithAudit(context.Context, string, *time.Time, *db.AdminAuditEntry) error {
	return nil
}

func (*Store) ListFeedConfigs(context.Context) ([]db.FeedConfig, error) {
	return []db.FeedConfig{}, nil
}
