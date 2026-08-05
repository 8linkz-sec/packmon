package feed

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type boundedFeedStatusStore struct {
	db.Store

	getCtx    context.Context
	getName   string
	getStatus *db.FeedSyncStatus
	getErr    error

	upsertCtx    context.Context
	upsertStatus *db.FeedSyncStatus
	upsertErr    error
}

func (s *boundedFeedStatusStore) GetFeedSyncStatus(ctx context.Context, feedName string) (*db.FeedSyncStatus, error) {
	s.getCtx = ctx
	s.getName = feedName
	return s.getStatus, s.getErr
}

func (s *boundedFeedStatusStore) UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error {
	s.upsertCtx = ctx
	s.upsertStatus = status
	return s.upsertErr
}

func TestGetFeedSyncStatusBoundedUsesReadDeadlineAndReturnsStoreResult(t *testing.T) {
	status := &db.FeedSyncStatus{FeedName: "osv", LastSyncStatus: db.FeedSyncStatusSuccess}
	storeErr := errors.New("read status")

	tests := []struct {
		name       string
		storeValue *db.FeedSyncStatus
		storeErr   error
	}{
		{name: "status", storeValue: status},
		{name: "error", storeValue: status, storeErr: storeErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &boundedFeedStatusStore{
				getStatus: tt.storeValue,
				getErr:    tt.storeErr,
			}

			started := time.Now()
			got, err := GetFeedSyncStatusBounded(store, "osv")
			finished := time.Now()

			if got != tt.storeValue {
				t.Fatalf("GetFeedSyncStatusBounded() status = %p, want %p", got, tt.storeValue)
			}
			if !errors.Is(err, tt.storeErr) {
				t.Fatalf("GetFeedSyncStatusBounded() error = %v, want %v", err, tt.storeErr)
			}
			if store.getName != "osv" {
				t.Fatalf("GetFeedSyncStatus() feedName = %q, want osv", store.getName)
			}
			requireStatusDeadline(t, store.getCtx, started, finished, FeedStatusReadTimeout)
			requireStatusContextCancelled(t, store.getCtx)
		})
	}
}

func TestUpsertFeedSyncStatusBoundedUsesWriteDeadlineAndReturnsStoreError(t *testing.T) {
	status := &db.FeedSyncStatus{FeedName: "ghsa", LastSyncStatus: db.FeedSyncStatusRunning}
	storeErr := errors.New("write status")

	tests := []struct {
		name     string
		storeErr error
	}{
		{name: "success"},
		{name: "error", storeErr: storeErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &boundedFeedStatusStore{upsertErr: tt.storeErr}

			started := time.Now()
			err := UpsertFeedSyncStatusBounded(store, status)
			finished := time.Now()

			if !errors.Is(err, tt.storeErr) {
				t.Fatalf("UpsertFeedSyncStatusBounded() error = %v, want %v", err, tt.storeErr)
			}
			if store.upsertStatus != status {
				t.Fatalf("UpsertFeedSyncStatus() status = %p, want %p", store.upsertStatus, status)
			}
			requireStatusDeadline(t, store.upsertCtx, started, finished, FeedStatusWriteTimeout)
			requireStatusContextCancelled(t, store.upsertCtx)
		})
	}
}

func TestUpsertFeedSyncStatusPreservingDataPreservesBeforeWrite(t *testing.T) {
	lastSuccessfulSync := time.Now().UTC().Add(-24 * time.Hour)
	metadata := []byte(`{"cursor":"old"}`)
	status := &db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncStatus: db.FeedSyncStatusRunning,
		UpdatedAt:      time.Now().UTC(),
	}
	store := &boundedFeedStatusStore{
		getStatus: &db.FeedSyncStatus{
			FeedName:       "osv",
			LastSyncAt:     &lastSuccessfulSync,
			LastSyncStatus: db.FeedSyncStatusSuccess,
			EntriesSynced:  17,
			EntriesTotal:   23,
			LastETag:       "etag-old",
			LastCommitHash: "commit-old",
			Metadata:       metadata,
		},
	}

	if err := UpsertFeedSyncStatusPreservingData(context.Background(), store, status); err != nil {
		t.Fatalf("UpsertFeedSyncStatusPreservingData() error = %v", err)
	}
	metadata[0] = '['

	if store.upsertStatus != status {
		t.Fatalf("UpsertFeedSyncStatus() status = %p, want original status %p", store.upsertStatus, status)
	}
	if status.LastSyncAt == nil || !status.LastSyncAt.Equal(lastSuccessfulSync) {
		t.Fatalf("LastSyncAt = %v, want preserved %v", status.LastSyncAt, lastSuccessfulSync)
	}
	if status.EntriesSynced != 17 || status.EntriesTotal != 23 {
		t.Fatalf("entries = %d/%d, want preserved 17/23", status.EntriesSynced, status.EntriesTotal)
	}
	if status.LastETag != "etag-old" || status.LastCommitHash != "commit-old" {
		t.Fatalf("cursor evidence = etag %q commit %q, want preserved", status.LastETag, status.LastCommitHash)
	}
	if string(status.Metadata) != `{"cursor":"old"}` {
		t.Fatalf("Metadata = %s, want copied old metadata", status.Metadata)
	}
}

func TestUpsertFeedSyncStatusPreservingDataAbortsWhenLoadFails(t *testing.T) {
	loadErr := errors.New("status read down")
	status := &db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncStatus: db.FeedSyncStatusRunning,
		UpdatedAt:      time.Now().UTC(),
	}
	store := &boundedFeedStatusStore{getErr: loadErr}

	err := UpsertFeedSyncStatusPreservingData(context.Background(), store, status)
	if !errors.Is(err, loadErr) {
		t.Fatalf("UpsertFeedSyncStatusPreservingData() error = %v, want %v", err, loadErr)
	}
	if store.upsertStatus != nil {
		t.Fatalf("UpsertFeedSyncStatus() status = %+v, want no write after failed preservation load", store.upsertStatus)
	}
	if status.LastSyncAt != nil || status.EntriesSynced != 0 || status.EntriesTotal != 0 || status.LastETag != "" || status.LastCommitHash != "" || len(status.Metadata) != 0 {
		t.Fatalf("status mutated after failed preservation load: %+v", status)
	}
}

func requireStatusDeadline(t *testing.T, ctx context.Context, started, finished time.Time, timeout time.Duration) {
	t.Helper()

	if ctx == nil {
		t.Fatal("store context is nil")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("store context has no deadline")
	}

	minDeadline := started.Add(timeout)
	maxDeadline := finished.Add(timeout)
	if deadline.Before(minDeadline) || deadline.After(maxDeadline) {
		t.Fatalf("store context deadline = %v, want between %v and %v", deadline, minDeadline, maxDeadline)
	}
}

func requireStatusContextCancelled(t *testing.T, ctx context.Context) {
	t.Helper()

	select {
	case <-ctx.Done():
	default:
		t.Fatal("store context was not cancelled after helper returned")
	}
}
