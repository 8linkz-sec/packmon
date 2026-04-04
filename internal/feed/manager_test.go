package feed

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

type managerStoreStub struct {
	db.Store
	status *db.FeedSyncStatus
}

func (s *managerStoreStub) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	copyValue := *status
	s.status = &copyValue
	return nil
}

type permanentSyncerStub struct {
	name  string
	calls int
}

func (s *permanentSyncerStub) Name() string { return s.name }

func (s *permanentSyncerStub) Sync(context.Context, db.Store) (*SyncResult, error) {
	s.calls++
	return nil, PermanentError(errors.New("missing api key"))
}

func TestManagerSyncOneRecordsSkippedWithoutRetry(t *testing.T) {
	t.Parallel()

	store := &managerStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewManager(store, logger, time.Hour)
	syncer := &permanentSyncerStub{name: "vulncheck"}
	manager.Register(FeedConfig{
		Syncer:  syncer,
		Mode:    FeedModeSelf,
		Enabled: true,
	})

	err := manager.SyncOne(context.Background(), "vulncheck")
	if err == nil {
		t.Fatal("SyncOne() error = nil, want permanent error")
	}
	if syncer.calls != 1 {
		t.Fatalf("syncer calls = %d, want 1", syncer.calls)
	}
	if store.status == nil {
		t.Fatal("UpsertFeedSyncStatus() was not called")
	}
	if store.status.LastSyncStatus != "skipped" {
		t.Fatalf("LastSyncStatus = %q, want skipped", store.status.LastSyncStatus)
	}
	if store.status.LastError != "missing api key" {
		t.Fatalf("LastError = %q, want %q", store.status.LastError, "missing api key")
	}
}
