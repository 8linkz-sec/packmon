package db

import "strings"

const (
	FeedSyncStatusPending        = "pending"
	FeedSyncStatusRunning        = "running"
	FeedSyncStatusSuccess        = "success"
	FeedSyncStatusError          = "error"
	FeedSyncStatusSkipped        = "skipped"
	FeedSyncStatusDisabled       = "disabled"
	FeedSyncStatusExternal       = "external"
	FeedSyncStatusRejected       = "rejected"
	FeedSyncStatusPermanentError = "permanent_error"
)

var feedSyncStatusValues = []string{
	FeedSyncStatusPending,
	FeedSyncStatusRunning,
	FeedSyncStatusSuccess,
	FeedSyncStatusError,
	FeedSyncStatusSkipped,
	FeedSyncStatusDisabled,
	FeedSyncStatusExternal,
	FeedSyncStatusRejected,
	FeedSyncStatusPermanentError,
}

var importableFeedSyncStatusValues = []string{
	FeedSyncStatusSuccess,
	FeedSyncStatusError,
	FeedSyncStatusRunning,
	FeedSyncStatusSkipped,
	FeedSyncStatusDisabled,
	FeedSyncStatusPending,
	FeedSyncStatusRejected,
}

// FeedSyncStatusValues returns the complete persisted feed_sync_status status
// vocabulary. Values are wire and database values; do not rename them in place.
func FeedSyncStatusValues() []string {
	return append([]string(nil), feedSyncStatusValues...)
}

// ImportableFeedSyncStatusValues returns the feed import status values accepted
// from JSON payloads. This intentionally excludes internal-only runtime states.
func ImportableFeedSyncStatusValues() []string {
	return append([]string(nil), importableFeedSyncStatusValues...)
}

// NormalizeFeedSyncStatus canonicalizes values before persistence validation.
func NormalizeFeedSyncStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		return FeedSyncStatusPending
	}
	return status
}

// IsValidFeedSyncStatus reports whether status is in the persisted vocabulary.
func IsValidFeedSyncStatus(status string) bool {
	switch NormalizeFeedSyncStatus(status) {
	case FeedSyncStatusPending,
		FeedSyncStatusRunning,
		FeedSyncStatusSuccess,
		FeedSyncStatusError,
		FeedSyncStatusSkipped,
		FeedSyncStatusDisabled,
		FeedSyncStatusExternal,
		FeedSyncStatusRejected,
		FeedSyncStatusPermanentError:
		return true
	default:
		return false
	}
}

// IsImportableFeedSyncStatus reports whether a canonical status is accepted
// from external feed import JSON. Case sensitivity is preserved for imports.
func IsImportableFeedSyncStatus(status string) bool {
	status = strings.TrimSpace(status)
	switch status {
	case FeedSyncStatusSuccess,
		FeedSyncStatusError,
		FeedSyncStatusRunning,
		FeedSyncStatusSkipped,
		FeedSyncStatusDisabled,
		FeedSyncStatusPending,
		FeedSyncStatusRejected:
		return true
	default:
		return false
	}
}
