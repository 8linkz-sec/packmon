// Package feed defines the FeedSyncer interface and supporting types
// for the Packmon feed synchronisation pipeline. Each external data
// source (OSV, GHSA, OpenSSF, VulnCheck, etc.) implements FeedSyncer
// so the FeedManager can orchestrate them uniformly.
package feed

import (
	"context"
	"errors"

	"github.com/8linkz/packmon/internal/db"
)

// SyncResult is returned by a FeedSyncer after a successful sync.
// It carries counters that the manager persists in feed_sync_status.
type SyncResult struct {
	// EntriesSynced is the number of entries written/updated in this run.
	EntriesSynced int
	// EntriesTotal is the total number of entries the syncer is aware of
	// (may equal EntriesSynced for a full sync, or differ for deltas).
	EntriesTotal int
}

type permanentSyncError struct {
	err error
}

func (e *permanentSyncError) Error() string {
	return e.err.Error()
}

func (e *permanentSyncError) Unwrap() error {
	return e.err
}

// PermanentError marks a sync failure as non-retryable, for example when a
// required API key is missing or the feed is statically misconfigured.
func PermanentError(err error) error {
	if err == nil {
		return nil
	}
	return &permanentSyncError{err: err}
}

// IsPermanentError reports whether err should not be retried by the manager.
func IsPermanentError(err error) bool {
	var target *permanentSyncError
	return errors.As(err, &target)
}

// FeedSyncer is the interface every feed source must implement.
type FeedSyncer interface {
	// Name returns a short, stable identifier for the feed (e.g. "osv",
	// "ghsa", "malicious"). It is used as the key in feed_sync_status.
	Name() string

	// Sync fetches data from the upstream source and upserts it into the
	// store. The context carries a cancellation signal for graceful
	// shutdown. The returned SyncResult informs the manager about the
	// number of entries processed.
	//
	// Implementations must be safe for sequential calls (idempotent
	// upserts) and must respect context cancellation promptly.
	Sync(ctx context.Context, store db.Store) (*SyncResult, error)
}

// FeedMode controls whether the FeedManager runs a feed's syncer
// itself ("self") or expects an external system like N8N to push
// data via the import API ("external"). See DE-18.
type FeedMode string

const (
	// FeedModeSelf means the manager runs the syncer on its own schedule.
	FeedModeSelf FeedMode = "self"
	// FeedModeExternal means the feed is populated by an external system
	// (e.g. N8N) and the manager does not schedule syncs.
	FeedModeExternal FeedMode = "external"
)

// FeedConfig holds per-feed configuration used by the FeedManager.
type FeedConfig struct {
	// Syncer is the concrete feed syncer implementation.
	Syncer FeedSyncer
	// Mode determines whether the manager runs the syncer or an external
	// system is responsible. Default: FeedModeSelf.
	Mode FeedMode
	// Enabled controls whether the feed is active at all.
	Enabled bool
}
