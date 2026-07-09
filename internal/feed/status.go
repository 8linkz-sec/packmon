package feed

import (
	"context"
	"encoding/json"
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

// FeedSyncStatusStore is the minimal store surface needed to preserve and
// write feed_sync_status rows without depending on the full database store.
type FeedSyncStatusStore interface {
	GetFeedSyncStatus(ctx context.Context, feedName string) (*db.FeedSyncStatus, error)
	UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error
}

// StatusMetadata stores optional operational details for a feed status row.
type StatusMetadata struct {
	RejectedCount   int    `json:"rejected_count,omitempty"`
	RejectionReason string `json:"rejection_reason,omitempty"`
	CorrelationID   string `json:"correlation_id,omitempty"`
	ClientIP        string `json:"client_ip,omitempty"`
	APIKeyID        int    `json:"api_key_id,omitempty"`
	APIKeyName      string `json:"api_key_name,omitempty"`
}

// GetFeedSyncStatusBounded reads a feed status row with the manager's bounded
// status context pattern instead of a long-lived sync context.
func GetFeedSyncStatusBounded(store FeedSyncStatusStore, feedName string) (*db.FeedSyncStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), FeedStatusReadTimeout)
	defer cancel()
	return store.GetFeedSyncStatus(ctx, feedName)
}

// UpsertFeedSyncStatusBounded writes a feed status row with the manager's
// bounded status context pattern instead of a long-lived sync context.
func UpsertFeedSyncStatusBounded(store FeedSyncStatusStore, status *db.FeedSyncStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), FeedStatusWriteTimeout)
	defer cancel()
	return store.UpsertFeedSyncStatus(ctx, status)
}

// UpsertFeedSyncStatusPreservingData loads the current row, copies the last
// usable sync evidence into status, and only then writes the replacement row.
// If the preservation read fails, no replacement status is written.
func UpsertFeedSyncStatusPreservingData(ctx context.Context, store FeedSyncStatusStore, status *db.FeedSyncStatus) error {
	current, err := store.GetFeedSyncStatus(ctx, status.FeedName)
	if err != nil {
		return err
	}
	PreserveFeedStatusData(status, current)
	return store.UpsertFeedSyncStatus(ctx, status)
}

// UpsertFeedSyncStatusPreservingDataBounded writes a preservation-safe status
// row with the manager's bounded status context pattern.
func UpsertFeedSyncStatusPreservingDataBounded(store FeedSyncStatusStore, status *db.FeedSyncStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), FeedStatusWriteTimeout)
	defer cancel()
	return UpsertFeedSyncStatusPreservingData(ctx, store, status)
}

// ParseStatusMetadata decodes optional feed status metadata. Invalid metadata
// is ignored because feed status rendering should stay available.
func ParseStatusMetadata(raw json.RawMessage) StatusMetadata {
	var metadata StatusMetadata
	if len(raw) == 0 {
		return metadata
	}
	_ = json.Unmarshal(raw, &metadata)
	return metadata
}

// RejectedRecordCount returns the rejected-record count for a feed status row.
func RejectedRecordCount(status db.FeedSyncStatus) int {
	metadata := ParseStatusMetadata(status.Metadata)
	if metadata.RejectedCount > 0 {
		return metadata.RejectedCount
	}
	if status.LastSyncStatus == db.FeedSyncStatusRejected {
		if status.EntriesTotal > 0 {
			return status.EntriesTotal
		}
		return 1
	}
	return 0
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
	dst.LastETag = src.LastETag
	dst.LastCommitHash = src.LastCommitHash
	if src.Metadata != nil {
		dst.Metadata = append([]byte(nil), src.Metadata...)
	}
}
