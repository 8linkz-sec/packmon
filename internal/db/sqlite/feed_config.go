package sqlite

import (
	"context"

	"github.com/8linkz/packmon/internal/db"
)

func (*Store) GetFeedConfig(context.Context, string) (*db.FeedConfig, error) {
	return nil, nil
}

func (*Store) UpsertFeedConfig(context.Context, *db.FeedConfig) error {
	return nil
}

func (*Store) DeleteFeedConfig(context.Context, string) error {
	return nil
}

func (*Store) ListFeedConfigs(context.Context) ([]db.FeedConfig, error) {
	return []db.FeedConfig{}, nil
}
