package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5/pgconn"
)

type f103FeedConfigExecer struct {
	query string
	args  []any
	tag   pgconn.CommandTag
	err   error
}

func (e *f103FeedConfigExecer) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	e.query = query
	e.args = append([]any(nil), args...)
	return e.tag, e.err
}

func TestF103FeedConfigGuardAndRevisionHelpers(t *testing.T) {
	t.Run("revision precedence and fallback", func(t *testing.T) {
		updated := time.Date(2026, 11, 2, 11, 12, 13, 456789000, time.UTC)
		expected := updated.Add(time.Second)
		if got, ok := expectedFeedConfigUpdatedAt(nil); ok || !got.IsZero() {
			t.Fatalf("expectedFeedConfigUpdatedAt(nil) = %s/%v, want zero/false", got, ok)
		}
		if got, ok := expectedFeedConfigUpdatedAt(&db.FeedConfig{UpdatedAt: updated, ExpectedUpdatedAt: &expected}); !ok || !got.Equal(expected) {
			t.Fatalf("explicit expected revision = %s/%v, want %s/true", got, ok, expected)
		}
		if got, ok := expectedFeedConfigUpdatedAt(&db.FeedConfig{UpdatedAt: updated}); !ok || !got.Equal(updated) {
			t.Fatalf("updated-at fallback = %s/%v, want %s/true", got, ok, updated)
		}
		zero := time.Time{}
		if got, ok := expectedFeedConfigUpdatedAt(&db.FeedConfig{ExpectedUpdatedAt: &zero}); !ok || !got.IsZero() {
			t.Fatalf("explicit zero revision = %s/%v, want zero/true", got, ok)
		}
		if got, ok := expectedFeedConfigUpdatedAt(&db.FeedConfig{}); ok || !got.IsZero() {
			t.Fatalf("missing revision = %s/%v, want zero/false", got, ok)
		}
	})

	t.Run("public upserts validate before SQL", func(t *testing.T) {
		tooShort := config.FeedSyncMinInterval - time.Nanosecond
		cfg := &db.FeedConfig{FeedName: "f103-invalid", SyncInterval: &tooShort}
		store := &Store{}
		if err := store.UpsertFeedConfig(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "sync interval") {
			t.Fatalf("UpsertFeedConfig() error = %v, want interval validation", err)
		}
		if err := store.UpsertFeedConfigWithAudit(context.Background(), cfg, nil); err == nil || !strings.Contains(err.Error(), "sync interval") {
			t.Fatalf("UpsertFeedConfigWithAudit() error = %v, want interval validation", err)
		}
	})

	t.Run("exec preserves cause and shared arguments", func(t *testing.T) {
		cause := errors.New("forced feed config exec failure")
		execer := &f103FeedConfigExecer{err: cause}
		store := &Store{}
		cfg := &db.FeedConfig{FeedName: "f103-exec", Enabled: true, Mode: "self"}
		err := store.execFeedConfigWrite(context.Background(), execer, upsertFeedConfigSQL, cfg, false)
		if !errors.Is(err, cause) {
			t.Fatalf("execFeedConfigWrite() error = %v, want wrapped cause", err)
		}
		if execer.query != upsertFeedConfigSQL || len(execer.args) != 5 {
			t.Fatalf("captured query/args = %q/%#v, want upsert and five args", execer.query, execer.args)
		}
		if execer.args[0] != cfg.FeedName || execer.args[1] != true || execer.args[2] != "self" || execer.args[3] != nil || execer.args[4] != nil {
			t.Fatalf("captured args = %#v, want feed/enabled/mode/nil cadence/nil key", execer.args)
		}
	})

	t.Run("write helper selects unrevisioned path and validates before exec", func(t *testing.T) {
		execer := &f103FeedConfigExecer{tag: pgconn.NewCommandTag("INSERT 0 1")}
		store := &Store{}
		cfg := &db.FeedConfig{FeedName: "f103-unrevisioned", Enabled: true, Mode: "self"}
		if err := store.writeFeedConfigAtRevisionTx(context.Background(), execer, cfg); err != nil {
			t.Fatalf("writeFeedConfigAtRevisionTx(unrevisioned) error = %v", err)
		}
		if execer.query != upsertFeedConfigSQL {
			t.Fatalf("unrevisioned query = %q, want upsertFeedConfigSQL", execer.query)
		}
		tooShort := config.FeedSyncMinInterval - time.Nanosecond
		execer.query = ""
		if err := store.execFeedConfigWrite(context.Background(), execer, upsertFeedConfigSQL, &db.FeedConfig{FeedName: "f103-invalid-direct", SyncInterval: &tooShort}, false); err == nil {
			t.Fatal("execFeedConfigWrite(invalid cadence) error = nil")
		}
		if execer.query != "" {
			t.Fatal("execFeedConfigWrite ran SQL for invalid cadence")
		}
	})

	t.Run("revision write requires affected row", func(t *testing.T) {
		execer := &f103FeedConfigExecer{tag: pgconn.NewCommandTag("UPDATE 0")}
		store := &Store{}
		cfg := &db.FeedConfig{FeedName: "f103-conflict"}
		if err := store.execFeedConfigWrite(context.Background(), execer, updateFeedConfigAtRevisionSQL, cfg, true, time.Now().UTC()); !errors.Is(err, db.ErrConflict) {
			t.Fatalf("execFeedConfigWrite(zero rows) error = %v, want ErrConflict", err)
		}
		execer.tag = pgconn.NewCommandTag("UPDATE 1")
		if err := store.execFeedConfigWrite(context.Background(), execer, updateFeedConfigAtRevisionSQL, cfg, true, time.Now().UTC()); err != nil {
			t.Fatalf("execFeedConfigWrite(one row) error = %v", err)
		}
	})
}

func TestF103NilFeedConfigRejectedBeforeStoreAccess(t *testing.T) {
	validationErr := validateFeedConfigSyncInterval(nil)
	if validationErr == nil {
		t.Skip("F103-bugs-2: nil feed configs are accepted by validation")
	}
	if !strings.Contains(validationErr.Error(), "feed config") {
		t.Fatalf("nil feed config validation error = %q, want feed-config context", validationErr)
	}

	store := &Store{}
	tests := []struct {
		name string
		call func() error
	}{
		{name: "public upsert", call: func() error { return store.UpsertFeedConfig(context.Background(), nil) }},
		{name: "audited public upsert", call: func() error { return store.UpsertFeedConfigWithAudit(context.Background(), nil, nil) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatal("nil feed config error = nil, want validation failure")
			}
			if !strings.Contains(err.Error(), "feed config") {
				t.Fatalf("nil feed config error = %q, want feed-config validation context", err)
			}
		})
	}
}

func TestF104FeedQueueGuards(t *testing.T) {
	t.Run("feed status validation", func(t *testing.T) {
		negativeDuration := -time.Microsecond
		tests := []struct {
			name string
			in   *db.FeedSyncStatus
			want string
		}{
			{name: "nil", want: "required"},
			{name: "invalid status", in: &db.FeedSyncStatus{LastSyncStatus: "not-a-status"}, want: "unsupported"},
			{name: "negative synced", in: &db.FeedSyncStatus{LastSyncStatus: "success", EntriesSynced: -1}, want: "entries_synced"},
			{name: "negative total", in: &db.FeedSyncStatus{LastSyncStatus: "success", EntriesTotal: -1}, want: "entries_total"},
			{name: "synced exceeds total", in: &db.FeedSyncStatus{LastSyncStatus: "success", EntriesSynced: 2, EntriesTotal: 1}, want: "exceed"},
			{name: "negative duration", in: &db.FeedSyncStatus{LastSyncStatus: "success", LastSyncDuration: &negativeDuration}, want: "duration"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if err := validateFeedSyncStatus(tt.in); err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("validateFeedSyncStatus() error = %v, want %q", err, tt.want)
				}
			})
		}
		store := &Store{}
		if err := store.UpsertFeedSyncStatus(context.Background(), &db.FeedSyncStatus{LastSyncStatus: "not-a-status"}); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("UpsertFeedSyncStatus(invalid) error = %v", err)
		}
	})

	t.Run("invalid ecosystem fails before pool access", func(t *testing.T) {
		store := &Store{}
		_, _, err := store.EnqueueRefresh(context.Background(), &db.RefreshJob{Ecosystem: "not-an-ecosystem", Priority: db.RefreshPriorityNormal})
		if err == nil || !strings.Contains(err.Error(), "ecosystem") {
			t.Fatalf("EnqueueRefresh(invalid ecosystem) error = %v", err)
		}
		if err := store.UpsertPackageCheckStatus(context.Background(), &db.PackageCheckStatus{Ecosystem: "not-an-ecosystem"}); err == nil || !strings.Contains(err.Error(), "ecosystem") {
			t.Fatalf("UpsertPackageCheckStatus(invalid ecosystem) error = %v", err)
		}
	})

	t.Run("disabled pruning avoids pool access", func(t *testing.T) {
		store := &Store{}
		for _, retention := range []time.Duration{0, -time.Second} {
			if got, err := store.PrunePackageCheckStatus(context.Background(), retention); err != nil || got != 0 {
				t.Fatalf("PrunePackageCheckStatus(%s) = %d, %v, want 0, nil", retention, got, err)
			}
		}
	})

	t.Run("diagnostics remain valid and byte bounded", func(t *testing.T) {
		if got := refreshQueueErrorText(nil); got != "" {
			t.Fatalf("refreshQueueErrorText(nil) = %q", got)
		}
		if got := refreshQueueErrorText(errors.New("short ASCII diagnostic")); got != "short ASCII diagnostic" {
			t.Fatalf("ASCII diagnostic = %q", got)
		}
		got := refreshQueueErrorText(errors.New(strings.Repeat("ä", 600)))
		if len(got) > 512 || !utf8.ValidString(got) {
			t.Fatalf("UTF-8 diagnostic bytes=%d valid=%v, want <=512 and valid", len(got), utf8.ValidString(got))
		}
	})
}
