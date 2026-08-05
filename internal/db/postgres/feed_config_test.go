package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5/pgconn"
)

type recordingFeedConfigExecer struct {
	called bool
}

func (e *recordingFeedConfigExecer) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	e.called = true
	return pgconn.CommandTag{}, errors.New("exec should not run for invalid feed config")
}

func TestUpsertFeedConfigRejectsUnsafeSyncIntervalBeforeExec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		interval time.Duration
	}{
		{name: "negative", interval: -time.Minute},
		{name: "below minimum", interval: config.FeedSyncMinInterval - time.Nanosecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			execer := &recordingFeedConfigExecer{}
			store := &Store{}
			err := store.upsertFeedConfigTx(context.Background(), execer, &db.FeedConfig{
				FeedName:     "osv",
				Enabled:      true,
				Mode:         "self",
				SyncInterval: &tt.interval,
			})
			if err == nil || !strings.Contains(err.Error(), "sync interval") {
				t.Fatalf("upsertFeedConfigTx() error = %v, want sync interval validation error", err)
			}
			if execer.called {
				t.Fatal("upsertFeedConfigTx executed SQL before rejecting unsafe sync interval")
			}
		})
	}
}
