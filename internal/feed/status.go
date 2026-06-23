package feed

import (
	"context"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

const (
	// FeedStatusReadTimeout bounds feed_sync_status reads that are used for
	// runtime evidence rather than the core feed import transaction.
	FeedStatusReadTimeout = 10 * time.Second

	// FeedStatusWriteTimeout bounds feed_sync_status writes that are used for
	// runtime evidence rather than the core feed import transaction.
	FeedStatusWriteTimeout = 2 * time.Second
)

// GetFeedSyncStatusBounded reads a feed status row with the manager's bounded
// status context pattern instead of a long-lived sync context.
func GetFeedSyncStatusBounded(store db.Store, feedName string) (*db.FeedSyncStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), FeedStatusReadTimeout)
	defer cancel()
	return store.GetFeedSyncStatus(ctx, feedName)
}

// UpsertFeedSyncStatusBounded writes a feed status row with the manager's
// bounded status context pattern instead of a long-lived sync context.
func UpsertFeedSyncStatusBounded(store db.Store, status *db.FeedSyncStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), FeedStatusWriteTimeout)
	defer cancel()
	return store.UpsertFeedSyncStatus(ctx, status)
}

// PreserveFeedStatusData copies the last usable feed-data evidence from src
// into dst. It intentionally does not copy LastSyncStatus, LastError,
// LastSyncDuration, or UpdatedAt because callers are recording a new attempt or
// configuration heartbeat.
func PreserveFeedStatusData(dst, src *db.FeedSyncStatus) {
	if dst == nil || src == nil {
		return
	}
	if src.LastSyncAt != nil {
		lastSyncAt := src.LastSyncAt.UTC()
		dst.LastSyncAt = &lastSyncAt
	}
	dst.EntriesSynced = src.EntriesSynced
	dst.EntriesTotal = src.EntriesTotal
	dst.LastEtag = src.LastEtag
	dst.LastCommitHash = src.LastCommitHash
	if src.Metadata != nil {
		dst.Metadata = append([]byte(nil), src.Metadata...)
	}
}
