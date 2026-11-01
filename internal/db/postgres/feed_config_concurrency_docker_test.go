//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5"
)

// raceRevisionedWrite forces the lost-update interleaving of two audited,
// revision-checked writes deterministically instead of relying on timing.
//
// The winner runs inside an explicit transaction that is held open after its
// write. The loser then runs through the public Store method on another pool
// connection. The barrier is PostgreSQL itself: the helper waits until the
// loser's backend is blocked on a lock (which it can only reach after any
// revision read it performs), commits the winner, and returns the loser's
// error. A loser that finishes without ever waiting fails the test, because
// then the interleaving under test did not happen.
func raceRevisionedWrite(t *testing.T, store *Store, dsn string, winner func(context.Context, pgx.Tx) error, loser func(context.Context) error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	monitor, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect monitor: %v", err)
	}
	defer func() { _ = monitor.Close(context.Background()) }()

	winnerTx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin winner tx: %v", err)
	}
	defer func() { _ = winnerTx.Rollback(context.Background()) }()

	var winnerPID int
	if err := winnerTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&winnerPID); err != nil {
		t.Fatalf("winner backend pid: %v", err)
	}
	if err := winner(ctx, winnerTx); err != nil {
		t.Fatalf("winner write error = %v", err)
	}

	loserDone := make(chan error, 1)
	go func() { loserDone <- loser(ctx) }()

	const blockedQuery = `
		SELECT count(*)
		FROM pg_stat_activity
		WHERE datname = current_database()
		  AND wait_event_type = 'Lock'
		  AND pid <> $1
		  AND pid <> pg_backend_pid()`
	for {
		var blocked int
		if err := monitor.QueryRow(ctx, blockedQuery, winnerPID).Scan(&blocked); err != nil {
			t.Fatalf("poll loser lock wait: %v", err)
		}
		if blocked > 0 {
			break
		}
		select {
		case loserErr := <-loserDone:
			t.Fatalf("loser finished without waiting for the winner's uncommitted write (err = %v); interleaving not reached", loserErr)
		case <-ctx.Done():
			t.Fatalf("loser never blocked on the winner's lock: %v", ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}

	if err := winnerTx.Commit(ctx); err != nil {
		t.Fatalf("commit winner tx: %v", err)
	}
	select {
	case loserErr := <-loserDone:
		return loserErr
	case <-ctx.Done():
		t.Fatalf("loser did not finish after the winner committed: %v", ctx.Err())
		return nil
	}
}

func raceAuditEntry(action, feedName string) *db.AdminAuditEntry {
	return &db.AdminAuditEntry{
		Action:  action,
		Details: json.RawMessage(`{"feed":"` + feedName + `"}`),
		IP:      "127.0.0.1",
	}
}

// requireSingleRaceAudit asserts that exactly one audit row carries the given
// action prefix and that it is the winner's.
func requireSingleRaceAudit(t *testing.T, store *Store, prefix, wantAction string) {
	t.Helper()
	entries, err := store.ListAdminAuditLog(context.Background(), 200)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	var got []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Action, prefix) {
			got = append(got, entry.Action)
		}
	}
	if len(got) != 1 || got[0] != wantAction {
		t.Fatalf("audit rows for %q = %v, want exactly [%s]", prefix, got, wantAction)
	}
}

func seedFeedConfigRevision(t *testing.T, store *Store, feedName string) time.Time {
	t.Helper()
	ctx := context.Background()
	if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{
		FeedName: feedName,
		Enabled:  true,
		Mode:     "self",
		APIKey:   "original-secret",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(seed %s) error = %v", feedName, err)
	}
	loaded, err := store.GetFeedConfig(ctx, feedName)
	if err != nil || loaded == nil || loaded.UpdatedAt.IsZero() {
		t.Fatalf("GetFeedConfig(seed %s) = %+v, %v; want revision", feedName, loaded, err)
	}
	return loaded.UpdatedAt
}

func TestFeedConfigConcurrentAuditedWritesWithSameRevisionOnlyOneWins(t *testing.T) {
	store, dsn := startDockerPostgresStore(t)

	winnerCfg := func(feedName string, expected time.Time) *db.FeedConfig {
		return &db.FeedConfig{FeedName: feedName, Enabled: false, Mode: "external", APIKey: "winner-secret", ExpectedUpdatedAt: &expected}
	}
	loserCfg := func(feedName string, expected time.Time) *db.FeedConfig {
		return &db.FeedConfig{FeedName: feedName, Enabled: true, Mode: "self", APIKey: "loser-secret", ExpectedUpdatedAt: &expected}
	}
	winnerSave := func(feedName string, expected time.Time) func(context.Context, pgx.Tx) error {
		return func(ctx context.Context, tx pgx.Tx) error {
			return store.upsertFeedConfigWithAuditTx(ctx, tx, winnerCfg(feedName, expected), raceAuditEntry(feedName+"_winner", feedName))
		}
	}
	winnerDelete := func(feedName string, expected time.Time) func(context.Context, pgx.Tx) error {
		return func(ctx context.Context, tx pgx.Tx) error {
			return deleteFeedConfigWithAuditTx(ctx, tx, feedName, &expected, raceAuditEntry(feedName+"_winner", feedName))
		}
	}
	loserSave := func(feedName string, expected time.Time) func(context.Context) error {
		return func(ctx context.Context) error {
			return store.UpsertFeedConfigWithAudit(ctx, loserCfg(feedName, expected), raceAuditEntry(feedName+"_loser", feedName))
		}
	}
	loserDelete := func(feedName string, expected time.Time) func(context.Context) error {
		return func(ctx context.Context) error {
			return store.DeleteFeedConfigWithAudit(ctx, feedName, &expected, raceAuditEntry(feedName+"_loser", feedName))
		}
	}
	requireWinnerConfig := func(t *testing.T, feedName string) {
		t.Helper()
		current, err := store.GetFeedConfig(context.Background(), feedName)
		if err != nil {
			t.Fatalf("GetFeedConfig(%s) error = %v", feedName, err)
		}
		if current == nil || current.Enabled || current.Mode != "external" || current.APIKey != "winner-secret" {
			t.Fatalf("GetFeedConfig(%s) = %+v, want the winner's config", feedName, current)
		}
	}
	requireDeleted := func(t *testing.T, feedName string) {
		t.Helper()
		current, err := store.GetFeedConfig(context.Background(), feedName)
		if err != nil {
			t.Fatalf("GetFeedConfig(%s) error = %v", feedName, err)
		}
		if current != nil {
			t.Fatalf("GetFeedConfig(%s) = %+v, want the winner's delete to stand", feedName, current)
		}
	}

	tests := []struct {
		name        string
		feedName    string
		firstSave   bool
		winner      func(string, time.Time) func(context.Context, pgx.Tx) error
		loser       func(string, time.Time) func(context.Context) error
		wantDeleted bool
	}{
		{name: "save vs save", feedName: "race-save-save", winner: winnerSave, loser: loserSave},
		{name: "save vs delete", feedName: "race-save-delete", winner: winnerSave, loser: loserDelete},
		{name: "delete vs save", feedName: "race-delete-save", winner: winnerDelete, loser: loserSave, wantDeleted: true},
		{name: "delete vs delete", feedName: "race-delete-delete", winner: winnerDelete, loser: loserDelete, wantDeleted: true},
		{name: "first save vs first save", feedName: "race-first-save", firstSave: true, winner: winnerSave, loser: loserSave},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var expected time.Time
			if !tt.firstSave {
				expected = seedFeedConfigRevision(t, store, tt.feedName)
			}

			err := raceRevisionedWrite(t, store, dsn, tt.winner(tt.feedName, expected), tt.loser(tt.feedName, expected))
			if !errors.Is(err, db.ErrConflict) {
				t.Fatalf("losing write error = %v, want ErrConflict", err)
			}
			if tt.wantDeleted {
				requireDeleted(t, tt.feedName)
			} else {
				requireWinnerConfig(t, tt.feedName)
			}
			requireSingleRaceAudit(t, store, tt.feedName+"_", tt.feedName+"_winner")
		})
	}
}

func TestSystemSettingsConcurrentAuditedSavesWithSameRevisionOnlyOneWins(t *testing.T) {
	tests := []struct {
		name      string
		firstSave bool
	}{
		{name: "save vs save"},
		{name: "first save vs first save", firstSave: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, dsn := startDockerPostgresStore(t)
			ctx := context.Background()

			var expected time.Time
			if !tt.firstSave {
				if err := store.UpsertSystemSettings(ctx, &db.SystemSettings{BlockThreshold: "CRITICAL", RateLimitPerMinute: 60, RateLimitBurst: 60}); err != nil {
					t.Fatalf("UpsertSystemSettings(seed) error = %v", err)
				}
				seeded, err := store.GetSystemSettings(ctx)
				if err != nil || seeded == nil {
					t.Fatalf("GetSystemSettings(seed) = %+v, %v", seeded, err)
				}
				expected = seeded.UpdatedAt
			} else if current, err := store.GetSystemSettings(ctx); err != nil || current != nil {
				t.Fatalf("GetSystemSettings(fresh) = %+v, %v; want no row", current, err)
			}

			winner := func(ctx context.Context, tx pgx.Tx) error {
				return upsertSystemSettingsWithAuditTx(ctx, tx,
					&db.SystemSettings{BlockThreshold: "HIGH", RateLimitPerMinute: 120, RateLimitBurst: 30, ExpectedUpdatedAt: &expected},
					raceAuditEntry("settings_race_winner", "settings"))
			}
			loser := func(ctx context.Context) error {
				return store.UpsertSystemSettingsWithAudit(ctx,
					&db.SystemSettings{BlockThreshold: "LOW", RateLimitPerMinute: 10, RateLimitBurst: 5, ExpectedUpdatedAt: &expected},
					raceAuditEntry("settings_race_loser", "settings"))
			}
			if err := raceRevisionedWrite(t, store, dsn, winner, loser); !errors.Is(err, db.ErrConflict) {
				t.Fatalf("losing save error = %v, want ErrConflict", err)
			}

			current, err := store.GetSystemSettings(ctx)
			if err != nil {
				t.Fatalf("GetSystemSettings() error = %v", err)
			}
			if current == nil || current.BlockThreshold != "HIGH" || current.RateLimitPerMinute != 120 || current.RateLimitBurst != 30 {
				t.Fatalf("GetSystemSettings() = %+v, want the winner's settings", current)
			}
			requireSingleRaceAudit(t, store, "settings_race_", "settings_race_winner")
		})
	}
}
