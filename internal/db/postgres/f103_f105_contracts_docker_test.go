//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/secret"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const f103F105ContractTimeout = 30 * time.Second

func f103F105Context(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), f103F105ContractTimeout)
}

func f103F105Exec(t *testing.T, ctx context.Context, store *Store, query string, args ...any) pgconn.CommandTag {
	t.Helper()
	tag, err := store.pool.Exec(ctx, query, args...)
	if err != nil {
		t.Fatalf("exec fixture SQL: %v", err)
	}
	return tag
}

func f103F105QueueRow(t *testing.T, ctx context.Context, store *Store, id int) (status string, priority int, processedAt *time.Time, diagnostic *string) {
	t.Helper()
	if err := store.pool.QueryRow(ctx, `SELECT status, priority, processed_at, error FROM refresh_queue WHERE id=$1`, id).Scan(&status, &priority, &processedAt, &diagnostic); err != nil {
		t.Fatalf("read refresh queue row %d: %v", id, err)
	}
	return status, priority, processedAt, diagnostic
}

func f103F105DDLRestore(t *testing.T, dsn, cleanupSQL, verifySQL string) {
	t.Helper()
	ctx, cancel := f103F105Context(t)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect for DDL restore: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, cleanupSQL); err != nil {
		t.Fatalf("DDL restore: %v", err)
	}
	var clean bool
	if err := conn.QueryRow(ctx, verifySQL).Scan(&clean); err != nil || !clean {
		t.Fatalf("verify DDL restore = %v, %v", clean, err)
	}
}

func f103F105RegisterDDLRestore(t *testing.T, dsn, cleanupSQL, verifySQL string) {
	t.Helper()
	t.Cleanup(func() { f103F105DDLRestore(t, dsn, cleanupSQL, verifySQL) })
}

func TestF103F105PostgresContracts(t *testing.T) {
	store, dsn := startDockerPostgresStore(t)
	prefix := fmt.Sprintf("f103-f105-%d", time.Now().UnixNano())

	t.Run("F103 revision matrix", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		feed := prefix + "-revision"
		zero := time.Time{}
		cfg := &db.FeedConfig{FeedName: feed, Enabled: true, Mode: "self", ExpectedUpdatedAt: &zero}
		if err := store.UpsertFeedConfigWithAudit(ctx, cfg, &db.AdminAuditEntry{Action: prefix + "_first", IP: "127.0.0.1"}); err != nil {
			t.Fatalf("first revision save: %v", err)
		}
		if err := store.UpsertFeedConfigWithAudit(ctx, cfg, &db.AdminAuditEntry{Action: prefix + "_duplicate", IP: "127.0.0.1"}); !errors.Is(err, db.ErrConflict) {
			t.Fatalf("duplicate zero revision save = %v, want ErrConflict", err)
		}
		loaded, err := store.GetFeedConfig(ctx, feed)
		if err != nil || loaded == nil {
			t.Fatalf("GetFeedConfig = %+v, %v", loaded, err)
		}
		equivalent := loaded.UpdatedAt.In(time.FixedZone("offset", 5*60*60+30*60))
		loaded.ExpectedUpdatedAt = &equivalent
		loaded.Enabled = false
		loaded.Mode = "external"
		if err := store.UpsertFeedConfigWithAudit(ctx, loaded, &db.AdminAuditEntry{Action: prefix + "_matching", IP: "127.0.0.1"}); err != nil {
			t.Fatalf("matching equivalent-zone revision save: %v", err)
		}
		current, err := store.GetFeedConfig(ctx, feed)
		if err != nil || current == nil || current.Enabled || current.Mode != "external" {
			t.Fatalf("saved config = %+v, %v", current, err)
		}
		stale := loaded.UpdatedAt
		loaded.ExpectedUpdatedAt = &stale
		if err := store.UpsertFeedConfigWithAudit(ctx, loaded, &db.AdminAuditEntry{Action: prefix + "_stale", IP: "127.0.0.1"}); !errors.Is(err, db.ErrConflict) {
			t.Fatalf("stale revision save = %v, want ErrConflict", err)
		}
		if err := store.DeleteFeedConfigWithAudit(ctx, feed, &zero, &db.AdminAuditEntry{Action: prefix + "_zero_existing", IP: "127.0.0.1"}); !errors.Is(err, db.ErrConflict) {
			t.Fatalf("zero revision delete of existing row = %v, want ErrConflict", err)
		}
		if err := store.DeleteFeedConfigWithAudit(ctx, feed, &stale, &db.AdminAuditEntry{Action: prefix + "_stale_delete", IP: "127.0.0.1"}); !errors.Is(err, db.ErrConflict) {
			t.Fatalf("stale revision delete = %v, want ErrConflict", err)
		}
		deleteRevision := current.UpdatedAt.In(time.FixedZone("west", -7*60*60))
		if err := store.DeleteFeedConfigWithAudit(ctx, feed, &deleteRevision, &db.AdminAuditEntry{Action: prefix + "_delete", IP: "127.0.0.1"}); err != nil {
			t.Fatalf("matching equivalent-zone delete: %v", err)
		}
		if got, err := store.GetFeedConfig(ctx, feed); err != nil || got != nil {
			t.Fatalf("GetFeedConfig(after delete) = %+v, %v", got, err)
		}
		if err := store.DeleteFeedConfigWithAudit(ctx, feed, &zero, &db.AdminAuditEntry{Action: prefix + "_delete_absent", IP: "127.0.0.1"}); err != nil {
			t.Fatalf("zero revision delete of absent row: %v", err)
		}
		unconditional := prefix + "-unconditional-delete"
		if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: unconditional, Enabled: true, Mode: "self"}); err != nil {
			t.Fatalf("seed unconditional delete: %v", err)
		}
		tx, err := store.pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin unconditional delete: %v", err)
		}
		if err := deleteFeedConfigAtRevisionTx(ctx, tx, unconditional, nil); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("nil-revision delete: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit nil-revision delete: %v", err)
		}
	})

	t.Run("F103 audit rollback", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		feed := prefix + "-audit"
		if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: feed, Enabled: true, Mode: "self", APIKey: "before"}); err != nil {
			t.Fatalf("seed feed config: %v", err)
		}
		before, err := store.GetFeedConfig(ctx, feed)
		if err != nil || before == nil {
			t.Fatalf("read seed = %+v, %v", before, err)
		}
		before.ExpectedUpdatedAt = &before.UpdatedAt
		before.Enabled = false
		before.APIKey = "after"
		if err := store.UpsertFeedConfigWithAudit(ctx, before, failingAdminAuditEntry(prefix+"_bad_save")); !errors.Is(err, db.ErrAdminAuditLog) {
			t.Fatalf("audited save error = %v, want ErrAdminAuditLog", err)
		}
		got, err := store.GetFeedConfig(ctx, feed)
		if err != nil || got == nil || !got.Enabled || got.APIKey != "before" || !got.UpdatedAt.Equal(before.UpdatedAt) {
			t.Fatalf("config after failed audit = %+v, %v, want original", got, err)
		}
		if err := store.DeleteFeedConfigWithAudit(ctx, feed, &got.UpdatedAt, failingAdminAuditEntry(prefix+"_bad_delete")); !errors.Is(err, db.ErrAdminAuditLog) {
			t.Fatalf("audited delete error = %v, want ErrAdminAuditLog", err)
		}
		if got, err := store.GetFeedConfig(ctx, feed); err != nil || got == nil {
			t.Fatalf("config after failed audited delete = %+v, %v", got, err)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM feed_configs WHERE feed_name=$1`, feed)
	})

	t.Run("F103 encrypted round trip key clearing ordering and corruption", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		encryptor, err := secret.NewFieldEncryptor(prefix + "-key")
		if err != nil {
			t.Fatalf("NewFieldEncryptor: %v", err)
		}
		encryptedStore, err := New(ctx, dsn, encryptor, &PoolConfig{MaxConns: 2, MinConns: 1})
		if err != nil {
			t.Fatalf("New encrypted store: %v", err)
		}
		defer func() { _ = encryptedStore.Close() }()
		rows, err := encryptedStore.ListFeedConfigs(ctx)
		if err != nil || rows == nil {
			t.Fatalf("ListFeedConfigs(empty) = %#v, %v, want non-nil empty", rows, err)
		}
		names := []string{prefix + "-enc-b", prefix + "-enc-a"}
		cadence := 15*time.Minute + 123456*time.Microsecond
		if err := encryptedStore.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: names[0], Enabled: true, Mode: "self", SyncInterval: &cadence, APIKey: "top-secret"}); err != nil {
			t.Fatalf("encrypted upsert: %v", err)
		}
		if err := encryptedStore.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: names[1], Enabled: false, Mode: "external"}); err != nil {
			t.Fatalf("second upsert: %v", err)
		}
		var stored string
		if err := encryptedStore.pool.QueryRow(ctx, `SELECT api_key FROM feed_configs WHERE feed_name=$1`, names[0]).Scan(&stored); err != nil {
			t.Fatalf("read ciphertext: %v", err)
		}
		if !strings.HasPrefix(stored, secret.EncryptedPrefix) || strings.Contains(stored, "top-secret") {
			t.Fatalf("stored key = %q, want opaque encrypted value", stored)
		}
		loaded, err := encryptedStore.GetFeedConfig(ctx, names[0])
		if err != nil || loaded == nil || loaded.APIKey != "top-secret" || !loaded.APIKeyEncrypted || loaded.SyncInterval == nil || *loaded.SyncInterval != cadence {
			t.Fatalf("encrypted round trip = %+v, %v", loaded, err)
		}
		rows, err = encryptedStore.ListFeedConfigs(ctx)
		if err != nil || len(rows) != 2 || rows[0].FeedName != names[1] || rows[1].FeedName != names[0] {
			t.Fatalf("ordered feed configs = %+v, %v", rows, err)
		}
		if rows[0].SyncInterval != nil || rows[0].APIKey != "" || rows[0].APIKeyEncrypted {
			t.Fatalf("nullable feed config fields = %+v, want nil cadence and empty key", rows[0])
		}
		loaded.APIKey = ""
		loaded.ExpectedUpdatedAt = &loaded.UpdatedAt
		if err := encryptedStore.UpsertFeedConfig(ctx, loaded); err != nil {
			t.Fatalf("clear key: %v", err)
		}
		if err := encryptedStore.pool.QueryRow(ctx, `SELECT COALESCE(api_key,'') FROM feed_configs WHERE feed_name=$1`, names[0]).Scan(&stored); err != nil || stored != "" {
			t.Fatalf("stored cleared key = %q, %v", stored, err)
		}
		f103F105Exec(t, ctx, encryptedStore, `UPDATE feed_configs SET api_key=$2 WHERE feed_name=$1`, names[0], secret.EncryptedPrefix+"not-base64!")
		if _, err := encryptedStore.GetFeedConfig(ctx, names[0]); err == nil || !strings.Contains(err.Error(), "decrypt feed api key") {
			t.Fatalf("GetFeedConfig(corrupt key) error = %v", err)
		}
		if _, err := encryptedStore.ListFeedConfigs(ctx); err == nil || !strings.Contains(err.Error(), "decrypt feed api key") {
			t.Fatalf("ListFeedConfigs(corrupt key) error = %v", err)
		}
		f103F105Exec(t, ctx, encryptedStore, `DELETE FROM feed_configs WHERE feed_name = ANY($1)`, names)
		var remaining int
		if err := encryptedStore.pool.QueryRow(ctx, `SELECT count(*) FROM feed_configs WHERE feed_name = ANY($1)`, names).Scan(&remaining); err != nil || remaining != 0 {
			t.Fatalf("verified corrupt-row cleanup = %d, %v", remaining, err)
		}
		rows, err = encryptedStore.ListFeedConfigs(ctx)
		if err != nil || len(rows) != 0 {
			t.Fatalf("ListFeedConfigs(after cleanup) = %+v, %v", rows, err)
		}
	})

	t.Run("F104 feed status preservation replacement and ordering", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		firstName, secondName := prefix+"-status-b", prefix+"-status-a"
		at := time.Date(2026, 11, 2, 10, 9, 8, 654321000, time.FixedZone("east", 2*60*60))
		duration := 3*time.Second + 654321*time.Microsecond
		initial := &db.FeedSyncStatus{FeedName: firstName, LastSyncAt: &at, LastSyncDuration: &duration, LastSyncStatus: " SUCCESS ", LastError: "old", EntriesSynced: 4, EntriesTotal: 5, LastETag: "etag-1", LastCommitHash: "commit-1", Metadata: json.RawMessage(`{"phase":"one"}`)}
		if err := store.UpsertFeedSyncStatus(ctx, initial); err != nil {
			t.Fatalf("UpsertFeedSyncStatus(initial): %v", err)
		}
		if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{FeedName: firstName, LastSyncStatus: "running", EntriesSynced: 1, EntriesTotal: 5}); err != nil {
			t.Fatalf("UpsertFeedSyncStatus(preserve): %v", err)
		}
		got, err := store.GetFeedSyncStatus(ctx, firstName)
		if err != nil || got == nil {
			t.Fatalf("GetFeedSyncStatus = %+v, %v", got, err)
		}
		if got.LastSyncAt == nil || !got.LastSyncAt.Equal(at) || got.LastSyncDuration == nil || *got.LastSyncDuration != duration || got.LastETag != "etag-1" || got.LastCommitHash != "commit-1" || string(got.Metadata) != `{"phase": "one"}` {
			t.Fatalf("preserved status fields = %+v", got)
		}
		at2 := at.Add(time.Hour)
		duration2 := duration + time.Microsecond
		if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{FeedName: firstName, LastSyncAt: &at2, LastSyncDuration: &duration2, LastSyncStatus: "error", LastError: "new", EntriesSynced: 0, EntriesTotal: 5, LastETag: "etag-2", LastCommitHash: "commit-2", Metadata: json.RawMessage(`{"phase":"two"}`)}); err != nil {
			t.Fatalf("UpsertFeedSyncStatus(replace): %v", err)
		}
		if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{FeedName: secondName, LastSyncStatus: "pending"}); err != nil {
			t.Fatalf("UpsertFeedSyncStatus(second): %v", err)
		}
		statuses, err := store.ListFeedSyncStatuses(ctx)
		if err != nil || len(statuses) != 2 || statuses[0].FeedName != secondName || statuses[1].FeedName != firstName {
			t.Fatalf("ListFeedSyncStatuses = %+v, %v", statuses, err)
		}
		if statuses[0].LastSyncAt != nil || statuses[0].LastSyncDuration != nil || statuses[0].LastError != "" || statuses[0].LastETag != "" || statuses[0].LastCommitHash != "" || string(statuses[0].Metadata) != "{}" {
			t.Fatalf("nullable status fields = %+v, want nil pointers, empty strings, and empty metadata", statuses[0])
		}
		got, err = store.GetFeedSyncStatus(ctx, firstName)
		if err != nil || got == nil || got.LastSyncAt == nil || !got.LastSyncAt.Equal(at2) || got.LastSyncDuration == nil || *got.LastSyncDuration != duration2 || got.LastError != "new" || got.LastETag != "etag-2" || got.LastCommitHash != "commit-2" || string(got.Metadata) != `{"phase": "two"}` {
			t.Fatalf("replaced status = %+v, %v", got, err)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM feed_sync_status WHERE feed_name IN ($1,$2)`, firstName, secondName)
		if got, err := store.GetFeedSyncStatus(ctx, firstName); err != nil || got != nil {
			t.Fatalf("GetFeedSyncStatus(after cleanup) = %+v, %v", got, err)
		}
	})

	t.Run("F104 priority FIFO positions paused and improvement", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		source := prefix + "-order"
		base := time.Date(2026, 11, 2, 12, 0, 0, 123456000, time.UTC)
		type seeded struct {
			name      string
			priority  int
			requested time.Time
			status    string
		}
		fixtures := []seeded{
			{name: "normal-late", priority: 3, requested: base.Add(2 * time.Microsecond), status: db.RefreshStatusPending},
			{name: "high", priority: 1, requested: base.Add(3 * time.Microsecond), status: db.RefreshStatusPending},
			{name: "normal-early", priority: 3, requested: base, status: db.RefreshStatusPending},
			{name: "tie-first", priority: 2, requested: base.Add(5 * time.Microsecond), status: db.RefreshStatusPending},
			{name: "tie-second", priority: 2, requested: base.Add(5 * time.Microsecond), status: db.RefreshStatusPending},
			{name: "paused", priority: 0, requested: base, status: db.RefreshStatusPaused},
		}
		ids := map[string]int{}
		for _, item := range fixtures {
			var id int
			if err := store.pool.QueryRow(ctx, `INSERT INTO refresh_queue(ecosystem,name,source,priority,status,requested_at) VALUES('npm',$1,$2,$3,$4,$5) RETURNING id`, prefix+"-"+item.name, source, item.priority, item.status, item.requested).Scan(&id); err != nil {
				t.Fatalf("seed queue %s: %v", item.name, err)
			}
			ids[item.name] = id
		}
		if ids["tie-first"] >= ids["tie-second"] {
			t.Fatalf("equal-priority/equal-time IDs = %d/%d, want first ID lower", ids["tie-first"], ids["tie-second"])
		}
		created, pos, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-new", Source: source, Priority: 2})
		if err != nil || !created || pos != 4 {
			t.Fatalf("EnqueueRefresh(new) = %v/%d/%v, want true/4/nil", created, pos, err)
		}
		created, pos, err = store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-normal-late", Source: source, Priority: 0})
		if err != nil || created || pos != 1 {
			t.Fatalf("EnqueueRefresh(improve) = %v/%d/%v, want false/1/nil", created, pos, err)
		}
		_, priority, _, _ := f103F105QueueRow(t, ctx, store, ids["normal-late"])
		if priority != 0 {
			t.Fatalf("improved priority = %d, want 0", priority)
		}
		for _, tt := range []struct {
			name string
			want int
		}{
			{name: "tie-first", want: 3},
			{name: "tie-second", want: 4},
			{name: "new", want: 5},
		} {
			created, position, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-" + tt.name, Source: source, Priority: 2})
			if err != nil || created || position != tt.want {
				t.Fatalf("EnqueueRefresh(position %s) = %v/%d/%v, want false/%d/nil", tt.name, created, position, err, tt.want)
			}
		}
		_, _, err = store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-normal-late", Source: source, Priority: 3})
		if err != nil {
			t.Fatalf("EnqueueRefresh(worse duplicate): %v", err)
		}
		_, priority, _, _ = f103F105QueueRow(t, ctx, store, ids["normal-late"])
		if priority != 0 {
			t.Fatalf("worsened duplicate priority = %d, want preserved 0", priority)
		}
		created, _, err = store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-paused", Source: source, Priority: 0})
		if err != nil || created {
			t.Fatalf("EnqueueRefresh(paused) = %v/%v, want false/nil", created, err)
		}
		status, _, _, _ := f103F105QueueRow(t, ctx, store, ids["paused"])
		if status != db.RefreshStatusPaused {
			t.Fatalf("paused duplicate status = %s", status)
		}
		var dequeued []string
		for i := 0; i < 6; i++ {
			job, err := store.DequeueRefresh(ctx, source)
			if err != nil || job == nil {
				t.Fatalf("DequeueRefresh(%d) = %+v, %v", i, job, err)
			}
			dequeued = append(dequeued, job.Name)
			if err := store.CompleteClaimedRefresh(ctx, job.ID, job.ProcessedAt, nil); err != nil {
				t.Fatalf("complete dequeued job: %v", err)
			}
		}
		want := []string{prefix + "-normal-late", prefix + "-high", prefix + "-tie-first", prefix + "-tie-second", prefix + "-new", prefix + "-normal-early"}
		if fmt.Sprint(dequeued) != fmt.Sprint(want) {
			t.Fatalf("dequeue order = %v, want %v", dequeued, want)
		}
		if job, err := store.DequeueRefresh(ctx, source); err != nil || job != nil {
			t.Fatalf("DequeueRefresh(paused only) = %+v, %v", job, err)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM refresh_queue WHERE source=$1`, source)
	})

	t.Run("F104 concurrent deduplication", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		source, name := prefix+"-concurrent", prefix+"-same"
		start := make(chan struct{})
		ready := make(chan struct{}, 2)
		results := make(chan struct {
			created bool
			err     error
		}, 2)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ready <- struct{}{}
				<-start
				created, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: name, Source: source, Priority: db.RefreshPriorityNormal})
				results <- struct {
					created bool
					err     error
				}{created: created, err: err}
			}()
		}
		for i := 0; i < 2; i++ {
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatalf("concurrent enqueue worker %d did not reach rendezvous: %v", i, ctx.Err())
			}
		}
		close(start)
		wg.Wait()
		close(results)
		createdCount := 0
		for result := range results {
			if result.err != nil {
				t.Fatalf("concurrent enqueue: %v", result.err)
			}
			if result.created {
				createdCount++
			}
		}
		var rows int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM refresh_queue WHERE source=$1 AND name=$2 AND status IN ('pending','processing','paused')`, source, name).Scan(&rows); err != nil {
			t.Fatalf("count active dedup rows: %v", err)
		}
		if createdCount != 1 || rows != 1 {
			t.Fatalf("concurrent created/rows = %d/%d, want 1/1", createdCount, rows)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM refresh_queue WHERE source=$1`, source)
	})

	t.Run("F104 skip locked", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		source := prefix + "-skip-locked"
		first, second := prefix+"-locked", prefix+"-available"
		f103F105Exec(t, ctx, store, `INSERT INTO refresh_queue(ecosystem,name,source,priority,status,requested_at) VALUES ('npm',$1,$3,1,'pending',clock_timestamp()-interval '1 second'),('npm',$2,$3,1,'pending',clock_timestamp())`, first, second, source)
		tx, err := store.pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin lock tx: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		var lockedID int
		if err := tx.QueryRow(ctx, `SELECT id FROM refresh_queue WHERE source=$1 AND name=$2 FOR UPDATE`, source, first).Scan(&lockedID); err != nil {
			t.Fatalf("lock first row: %v", err)
		}
		job, err := store.DequeueRefresh(ctx, source)
		if err != nil || job == nil || job.Name != second {
			t.Fatalf("DequeueRefresh(skip locked) = %+v, %v, want %s", job, err, second)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatalf("rollback lock tx: %v", err)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM refresh_queue WHERE source=$1`, source)
	})

	t.Run("F104 retry after terminal conflict", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		cleanup := `DROP TRIGGER IF EXISTS f104_retry_insert ON refresh_queue; DROP FUNCTION IF EXISTS f104_retry_insert_fn(); DROP TABLE IF EXISTS f104_retry_counter`
		verify := `SELECT to_regclass('public.f104_retry_counter') IS NULL AND to_regprocedure('public.f104_retry_insert_fn()') IS NULL`
		f103F105RegisterDDLRestore(t, dsn, cleanup, verify)
		var oldID int
		if err := store.pool.QueryRow(ctx, `INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES('npm',$1,$2,3,'pending') RETURNING id`, prefix+"-retry-name", prefix+"-retry").Scan(&oldID); err != nil {
			t.Fatalf("seed retry row: %v", err)
		}
		f103F105Exec(t, ctx, store, `CREATE TABLE f104_retry_counter(n integer NOT NULL); INSERT INTO f104_retry_counter VALUES(0); CREATE FUNCTION f104_retry_insert_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE f104_retry_counter SET n=n+1; IF (SELECT n FROM f104_retry_counter)=1 THEN UPDATE refresh_queue SET status='done' WHERE source=TG_ARGV[0] AND name=TG_ARGV[1] AND status='pending'; END IF; RETURN NULL; END $$; CREATE TRIGGER f104_retry_insert AFTER INSERT ON refresh_queue FOR EACH STATEMENT EXECUTE FUNCTION f104_retry_insert_fn($$`+prefix+`-retry$$,$$`+prefix+`-retry-name$$)`)
		created, pos, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-retry-name", Source: prefix + "-retry", Priority: 1})
		if err != nil || !created || pos != 1 {
			t.Fatalf("retry enqueue = %v/%d/%v, want true/1/nil", created, pos, err)
		}
		var attempts, active, terminal int
		if err := store.pool.QueryRow(ctx, `SELECT n FROM f104_retry_counter`).Scan(&attempts); err != nil {
			t.Fatalf("retry counter: %v", err)
		}
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE status='pending'), count(*) FILTER(WHERE status='done') FROM refresh_queue WHERE source=$1 AND name=$2`, prefix+"-retry", prefix+"-retry-name").Scan(&active, &terminal); err != nil {
			t.Fatalf("retry rows: %v", err)
		}
		if attempts != 2 || active != 1 || terminal != 1 {
			t.Fatalf("retry attempts/pending/done = %d/%d/%d, want 2/1/1", attempts, active, terminal)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM refresh_queue WHERE source=$1`, prefix+"-retry")
		f103F105DDLRestore(t, dsn, cleanup, verify)
	})

	t.Run("F104 bounded retry exhaustion", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		cleanup := `DROP TRIGGER IF EXISTS f104_exhaust_insert ON refresh_queue; DROP TRIGGER IF EXISTS f104_exhaust_update ON refresh_queue; DROP FUNCTION IF EXISTS f104_exhaust_insert_fn(); DROP FUNCTION IF EXISTS f104_exhaust_update_fn(); DROP SEQUENCE IF EXISTS f104_exhaust_counter`
		verify := `SELECT to_regclass('public.f104_exhaust_counter') IS NULL AND to_regprocedure('public.f104_exhaust_insert_fn()') IS NULL AND to_regprocedure('public.f104_exhaust_update_fn()') IS NULL`
		f103F105RegisterDDLRestore(t, dsn, cleanup, verify)
		var oldID int
		if err := store.pool.QueryRow(ctx, `INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES('npm',$1,$2,3,'pending') RETURNING id`, prefix+"-exhaust-name", prefix+"-exhaust").Scan(&oldID); err != nil {
			t.Fatalf("seed exhaustion row: %v", err)
		}
		f103F105Exec(t, ctx, store, `CREATE SEQUENCE f104_exhaust_counter; CREATE FUNCTION f104_exhaust_insert_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('f104_exhaust_counter'); UPDATE refresh_queue SET status='done' WHERE source=TG_ARGV[0] AND name=TG_ARGV[1] AND status='pending'; RETURN NULL; END $$; CREATE FUNCTION f104_exhaust_update_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF pg_trigger_depth()=1 THEN UPDATE refresh_queue SET status='pending' WHERE source=TG_ARGV[0] AND name=TG_ARGV[1] AND status='done'; END IF; RETURN NULL; END $$; CREATE TRIGGER f104_exhaust_insert AFTER INSERT ON refresh_queue FOR EACH STATEMENT EXECUTE FUNCTION f104_exhaust_insert_fn($$`+prefix+`-exhaust$$,$$`+prefix+`-exhaust-name$$); CREATE TRIGGER f104_exhaust_update AFTER UPDATE ON refresh_queue FOR EACH STATEMENT EXECUTE FUNCTION f104_exhaust_update_fn($$`+prefix+`-exhaust$$,$$`+prefix+`-exhaust-name$$)`)
		created, pos, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-exhaust-name", Source: prefix + "-exhaust", Priority: 1})
		if err == nil || created || pos != 0 || !strings.Contains(err.Error(), "after 3 attempts") {
			t.Fatalf("exhausted enqueue = %v/%d/%v, want false/0/exhaustion", created, pos, err)
		}
		var attempts, rows int
		if err := store.pool.QueryRow(ctx, `SELECT last_value FROM f104_exhaust_counter`).Scan(&attempts); err != nil {
			t.Fatalf("exhaustion counter: %v", err)
		}
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM refresh_queue WHERE source=$1 AND name=$2 AND status='pending'`, prefix+"-exhaust", prefix+"-exhaust-name").Scan(&rows); err != nil {
			t.Fatalf("exhaustion rows: %v", err)
		}
		if attempts != 3 || rows != 1 {
			t.Fatalf("exhaustion attempts/pending rows = %d/%d, want 3/1", attempts, rows)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM refresh_queue WHERE source=$1`, prefix+"-exhaust")
		f103F105DDLRestore(t, dsn, cleanup, verify)
	})

	t.Run("F104 completion reset and reclaimed ownership", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		source := prefix + "-ownership"
		var now time.Time
		if err := store.pool.QueryRow(ctx, `SELECT date_trunc('microseconds', clock_timestamp())`).Scan(&now); err != nil {
			t.Fatalf("database clock: %v", err)
		}
		old, young := now.Add(-2*time.Hour), now.Add(-30*time.Minute)
		var oldID, youngID, nullID, otherID int
		seed := func(name, src string, processed *time.Time, diagnostic string) int {
			var id int
			if err := store.pool.QueryRow(ctx, `INSERT INTO refresh_queue(ecosystem,name,source,priority,status,processed_at,error) VALUES('npm',$1,$2,1,'processing',$3,$4) RETURNING id`, name, src, processed, diagnostic).Scan(&id); err != nil {
				t.Fatalf("seed ownership row: %v", err)
			}
			return id
		}
		oldID = seed(prefix+"-old", source, &old, "seed-error-old")
		youngID = seed(prefix+"-young", source, &young, "seed-error-young")
		nullID = seed(prefix+"-null", source, nil, "seed-error-null")
		otherID = seed(prefix+"-other", source+"-other", &old, "seed-error-other")
		reset, err := store.ResetStuckJobs(ctx, source, time.Hour)
		if err != nil || reset != 1 {
			t.Fatalf("ResetStuckJobs = %d, %v, want 1", reset, err)
		}
		type queueState struct {
			id          int
			status      string
			processedAt *time.Time
			diagnostic  *string
		}
		stringPtr := func(value string) *string { return &value }
		for _, want := range []queueState{
			{id: oldID, status: db.RefreshStatusPending},
			{id: youngID, status: db.RefreshStatusProcessing, processedAt: &young, diagnostic: stringPtr("seed-error-young")},
			{id: nullID, status: db.RefreshStatusProcessing, diagnostic: stringPtr("seed-error-null")},
			{id: otherID, status: db.RefreshStatusProcessing, processedAt: &old, diagnostic: stringPtr("seed-error-other")},
		} {
			status, _, processedAt, diagnostic := f103F105QueueRow(t, ctx, store, want.id)
			processedMatches := processedAt == nil && want.processedAt == nil || processedAt != nil && want.processedAt != nil && processedAt.Equal(*want.processedAt)
			diagnosticMatches := diagnostic == nil && want.diagnostic == nil || diagnostic != nil && want.diagnostic != nil && *diagnostic == *want.diagnostic
			if status != want.status || !processedMatches || !diagnosticMatches {
				t.Fatalf("row %d state=%s/%v/%v, want %s/%v/%v", want.id, status, processedAt, diagnostic, want.status, want.processedAt, want.diagnostic)
			}
		}
		if err := store.CompleteRefresh(ctx, youngID, errors.New("explicit completion error")); err != nil {
			t.Fatalf("CompleteRefresh(error): %v", err)
		}
		if status, _, _, diagnostic := f103F105QueueRow(t, ctx, store, youngID); status != db.RefreshStatusError || diagnostic == nil || *diagnostic != "explicit completion error" {
			t.Fatalf("CompleteRefresh(error) state = %s/%v", status, diagnostic)
		}
		if err := store.CompleteRefresh(ctx, nullID, nil); err != nil {
			t.Fatalf("CompleteRefresh(success): %v", err)
		}
		if status, _, _, diagnostic := f103F105QueueRow(t, ctx, store, nullID); status != db.RefreshStatusDone || diagnostic != nil {
			t.Fatalf("CompleteRefresh(success) state = %s/%v", status, diagnostic)
		}
		claimed, err := store.DequeueRefresh(ctx, source)
		if err != nil || claimed == nil || claimed.ID != oldID || claimed.ProcessedAt == nil {
			t.Fatalf("claim reset row = %+v, %v", claimed, err)
		}
		equivalent := claimed.ProcessedAt.In(time.FixedZone("offset", 9*60*60))
		longErr := errors.New(strings.Repeat("ä", 600))
		if err := store.CompleteClaimedRefresh(ctx, claimed.ID, &equivalent, longErr); err != nil {
			t.Fatalf("complete equivalent claim: %v", err)
		}
		status, _, completedAt, diagnostic := f103F105QueueRow(t, ctx, store, claimed.ID)
		wantDiagnostic := refreshQueueErrorText(longErr)
		if status != db.RefreshStatusError || completedAt == nil || completedAt.Before(*claimed.ProcessedAt) || diagnostic == nil || *diagnostic != wantDiagnostic || len(*diagnostic) > 512 || !utf8.ValidString(*diagnostic) {
			t.Fatalf("completed error row = %s/%v/%v", status, completedAt, diagnostic)
		}
		var reclaimID int
		if err := store.pool.QueryRow(ctx, `INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES('npm',$1,$2,0,'pending') RETURNING id`, prefix+"-reclaim", source).Scan(&reclaimID); err != nil {
			t.Fatalf("seed reclaim: %v", err)
		}
		first, err := store.DequeueRefresh(ctx, source)
		if err != nil || first == nil || first.ID != reclaimID {
			t.Fatalf("first reclaim claim = %+v, %v", first, err)
		}
		f103F105Exec(t, ctx, store, `UPDATE refresh_queue SET processed_at=$2,error='stale-claim-error' WHERE id=$1`, reclaimID, old)
		if n, err := store.ResetStuckJobs(ctx, source, time.Hour); err != nil || n != 1 {
			t.Fatalf("reset reclaimed = %d, %v", n, err)
		}
		if status, _, processedAt, diagnostic := f103F105QueueRow(t, ctx, store, reclaimID); status != db.RefreshStatusPending || processedAt != nil || diagnostic != nil {
			t.Fatalf("reset reclaimed state = %s/%v/%v, want pending/nil/nil", status, processedAt, diagnostic)
		}
		second, err := store.DequeueRefresh(ctx, source)
		if err != nil || second == nil || second.ID != reclaimID || second.ProcessedAt == nil {
			t.Fatalf("second reclaim claim = %+v, %v", second, err)
		}
		if err := store.CompleteClaimedRefresh(ctx, reclaimID, first.ProcessedAt, nil); err != nil {
			t.Fatalf("stale completion: %v", err)
		}
		status, _, staleProcessedAt, staleDiagnostic := f103F105QueueRow(t, ctx, store, reclaimID)
		if status != db.RefreshStatusProcessing || staleProcessedAt == nil || !staleProcessedAt.Equal(*second.ProcessedAt) || staleDiagnostic != nil {
			t.Fatalf("stale completion state = %s/%v/%v, want unchanged processing/%v/nil", status, staleProcessedAt, staleDiagnostic, second.ProcessedAt)
		}
		var beforeComplete, afterComplete time.Time
		if err := store.pool.QueryRow(ctx, `SELECT date_trunc('microseconds', clock_timestamp())`).Scan(&beforeComplete); err != nil {
			t.Fatalf("database clock before current completion: %v", err)
		}
		if err := store.CompleteClaimedRefresh(ctx, reclaimID, second.ProcessedAt, nil); err != nil {
			t.Fatalf("current completion: %v", err)
		}
		if err := store.pool.QueryRow(ctx, `SELECT date_trunc('microseconds', clock_timestamp())`).Scan(&afterComplete); err != nil {
			t.Fatalf("database clock after current completion: %v", err)
		}
		status, _, currentProcessedAt, currentDiagnostic := f103F105QueueRow(t, ctx, store, reclaimID)
		if status != db.RefreshStatusDone || currentProcessedAt == nil || currentProcessedAt.Before(beforeComplete) || currentProcessedAt.After(afterComplete) || currentDiagnostic != nil {
			t.Fatalf("current completion state = %s/%v/%v, want done within [%v,%v] with nil error", status, currentProcessedAt, currentDiagnostic, beforeComplete, afterComplete)
		}
		if err := store.CompleteClaimedRefresh(ctx, reclaimID, nil, nil); err == nil || !strings.Contains(err.Error(), "missing claim timestamp") {
			t.Fatalf("nil claim completion error = %v", err)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM refresh_queue WHERE source IN ($1,$2)`, source, source+"-other")
	})

	t.Run("F104 queue position permission rollback", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		const role = "f104_limited"
		cleanup := `DROP TRIGGER IF EXISTS f104_revoke_select ON refresh_queue; DROP FUNCTION IF EXISTS public.f104_revoke_select_fn(); DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='f104_limited') THEN REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM f104_limited; REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM f104_limited; REVOKE USAGE ON SCHEMA public FROM f104_limited; REVOKE CONNECT ON DATABASE packmon FROM f104_limited; END IF; END $$; DROP ROLE IF EXISTS f104_limited`
		verify := `SELECT to_regprocedure('public.f104_revoke_select_fn()') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='f104_limited')`
		f103F105RegisterDDLRestore(t, dsn, cleanup, verify)
		f103F105Exec(t, ctx, store, `CREATE ROLE f104_limited LOGIN PASSWORD 'f104-password'; GRANT CONNECT ON DATABASE packmon TO f104_limited; GRANT USAGE ON SCHEMA public TO f104_limited; GRANT SELECT,INSERT,UPDATE ON refresh_queue TO f104_limited; GRANT USAGE,SELECT ON SEQUENCE refresh_queue_id_seq TO f104_limited; CREATE FUNCTION public.f104_revoke_select_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ BEGIN EXECUTE 'REVOKE SELECT ON TABLE public.refresh_queue FROM f104_limited'; RETURN NULL; END $$; CREATE TRIGGER f104_revoke_select AFTER INSERT ON refresh_queue FOR EACH STATEMENT EXECUTE FUNCTION public.f104_revoke_select_fn()`)
		roleDSN := strings.Replace(dsn, "packmon:packmon@", role+":f104-password@", 1)
		roleStore, err := New(ctx, roleDSN, nil, &PoolConfig{MaxConns: 1, MinConns: 1})
		if err != nil {
			t.Fatalf("open limited-role store: %v", err)
		}
		defer func() { _ = roleStore.Close() }()
		source := prefix + "-permission"
		var auditBefore int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log`).Scan(&auditBefore); err != nil {
			t.Fatalf("audit baseline: %v", err)
		}
		created, position, err := roleStore.EnqueueRefreshWithAudit(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-permission-name", Source: source, Priority: 1}, func(created bool, position int) db.AdminAuditEntry {
			return db.AdminAuditEntry{Action: prefix + "_permission", IP: "127.0.0.1"}
		})
		var pgErr *pgconn.PgError
		if err == nil || created || position != 0 || !errors.As(err, &pgErr) || pgErr.Code != "42501" || ctx.Err() != nil {
			t.Fatalf("permission enqueue = %v/%d/%v pg=%+v ctx=%v", created, position, err, pgErr, ctx.Err())
		}
		var queueRows, auditAfter int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM refresh_queue WHERE source=$1`, source).Scan(&queueRows); err != nil {
			t.Fatalf("queue rollback count: %v", err)
		}
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log`).Scan(&auditAfter); err != nil {
			t.Fatalf("audit rollback count: %v", err)
		}
		if queueRows != 0 || auditAfter != auditBefore {
			t.Fatalf("rollback queue/audit = %d/%d, want 0/%d", queueRows, auditAfter, auditBefore)
		}
		var selectWorks int
		if err := roleStore.pool.QueryRow(ctx, `SELECT count(*) FROM refresh_queue`).Scan(&selectWorks); err != nil {
			t.Fatalf("transactional REVOKE was not rolled back: %v", err)
		}
		roleStore.Close()
		f103F105DDLRestore(t, dsn, cleanup, verify)
	})

	t.Run("F104 enqueue audit and deferred commit rollback", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		source := prefix + "-audit-queue"
		badBuilder := func(bool, int) db.AdminAuditEntry { return *failingAdminAuditEntry(prefix + "_queue_bad") }
		created, position, err := store.EnqueueRefreshWithAudit(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-audit-new", Source: source, Priority: 2}, badBuilder)
		if !errors.Is(err, db.ErrAdminAuditLog) || created || position != 0 {
			t.Fatalf("failed audited insert = %v/%d/%v", created, position, err)
		}
		var rows int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM refresh_queue WHERE source=$1`, source).Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("failed audited insert rows=%d err=%v", rows, err)
		}
		var id int
		if err := store.pool.QueryRow(ctx, `INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES('npm',$1,$2,3,'pending') RETURNING id`, prefix+"-audit-existing", source).Scan(&id); err != nil {
			t.Fatalf("seed audited update: %v", err)
		}
		created, _, err = store.EnqueueRefreshWithAudit(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-audit-existing", Source: source, Priority: 0}, badBuilder)
		if !errors.Is(err, db.ErrAdminAuditLog) || created {
			t.Fatalf("failed audited update = %v/%v", created, err)
		}
		_, priority, _, _ := f103F105QueueRow(t, ctx, store, id)
		if priority != 3 {
			t.Fatalf("priority after failed audited update=%d, want 3", priority)
		}

		cleanup := `DROP TRIGGER IF EXISTS f104_deferred_audit_failure ON admin_audit_log; DROP FUNCTION IF EXISTS f104_deferred_audit_failure_fn()`
		verify := `SELECT to_regprocedure('public.f104_deferred_audit_failure_fn()') IS NULL`
		f103F105RegisterDDLRestore(t, dsn, cleanup, verify)
		f103F105Exec(t, ctx, store, `CREATE FUNCTION f104_deferred_audit_failure_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced deferred audit failure' USING ERRCODE='23514'; END $$; CREATE CONSTRAINT TRIGGER f104_deferred_audit_failure AFTER INSERT ON admin_audit_log DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION f104_deferred_audit_failure_fn()`)
		created, _, err = store.EnqueueRefreshWithAudit(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-deferred", Source: source, Priority: 1}, func(bool, int) db.AdminAuditEntry {
			return db.AdminAuditEntry{Action: prefix + "_deferred", IP: "127.0.0.1"}
		})
		if err == nil || created || !strings.Contains(err.Error(), "commit enqueue refresh tx") {
			t.Fatalf("deferred commit enqueue = %v/%v", created, err)
		}
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM refresh_queue WHERE source=$1 AND name=$2`, source, prefix+"-deferred").Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("deferred commit rollback rows=%d err=%v", rows, err)
		}
		f103F105DDLRestore(t, dsn, cleanup, verify)
		f103F105Exec(t, ctx, store, `DELETE FROM refresh_queue WHERE source=$1`, source)
	})

	t.Run("F104 positionless query observation", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		var preload, track string
		if err := store.pool.QueryRow(ctx, `SHOW shared_preload_libraries`).Scan(&preload); err != nil {
			t.Fatalf("SHOW shared_preload_libraries: %v", err)
		}
		if err := store.pool.QueryRow(ctx, `SHOW pg_stat_statements.track`).Scan(&track); err != nil {
			t.Fatalf("SHOW pg_stat_statements.track: %v", err)
		}
		if !strings.Contains(preload, "pg_stat_statements") || track != "top" {
			t.Fatalf("pg_stat prerequisites preload=%q track=%q", preload, track)
		}
		positionCalls := func() int64 {
			var calls int64
			err := store.pool.QueryRow(ctx, `SELECT COALESCE(sum(calls),0)::bigint FROM pg_stat_statements WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND userid=(SELECT usesysid FROM pg_user WHERE usename=current_user) AND query LIKE '%WITH selected AS (%' AND query LIKE '%COUNT(*)::int%'`).Scan(&calls)
			if err != nil {
				t.Fatalf("query pg_stat_statements: %v", err)
			}
			return calls
		}
		if _, err := store.pool.Exec(ctx, `SELECT pg_stat_statements_reset()`); err != nil {
			t.Fatalf("reset pg_stat_statements: %v", err)
		}
		source := prefix + "-pgstat"
		if created, err := store.EnqueueRefreshNoPosition(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-no-position", Source: source, Priority: 1}); err != nil || !created {
			t.Fatalf("positionless enqueue=%v/%v", created, err)
		}
		if calls := positionCalls(); calls != 0 {
			t.Fatalf("positionless queue-position calls=%d, want 0", calls)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM refresh_queue WHERE source=$1`, source)
		if _, err := store.pool.Exec(ctx, `SELECT pg_stat_statements_reset()`); err != nil {
			t.Fatalf("second reset pg_stat_statements: %v", err)
		}
		if created, position, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: prefix + "-with-position", Source: source, Priority: 1}); err != nil || !created || position != 1 {
			t.Fatalf("normal enqueue=%v/%d/%v", created, position, err)
		}
		if calls := positionCalls(); calls != 1 {
			t.Fatalf("normal queue-position calls=%d, want 1", calls)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM refresh_queue WHERE source=$1`, source)
	})

	t.Run("F104 package check replacement increments and pruning", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		name := prefix + "-package"
		checked := time.Date(2026, 11, 2, 8, 0, 0, 123456000, time.FixedZone("east", 3*60*60))
		next := checked.Add(time.Hour)
		if err := store.UpsertPackageCheckStatus(ctx, &db.PackageCheckStatus{Ecosystem: "npm", Name: name, Source: "socket", LastCheckedAt: &checked, NextCheckAt: &next, CheckCount: 0, LastResult: json.RawMessage(`{"phase":1}`)}); err != nil {
			t.Fatalf("first package check upsert: %v", err)
		}
		checked2, next2 := checked.Add(time.Minute), next.Add(time.Minute)
		if err := store.UpsertPackageCheckStatus(ctx, &db.PackageCheckStatus{Ecosystem: "npm", Name: name, Source: "socket", LastCheckedAt: &checked2, NextCheckAt: &next2, CheckCount: 3, LastResult: json.RawMessage(`{"phase":2}`)}); err != nil {
			t.Fatalf("second package check upsert: %v", err)
		}
		got, err := store.GetPackageCheckStatus(ctx, "npm", name, "socket")
		if err != nil || got == nil || got.CheckCount != 4 || got.LastCheckedAt == nil || !got.LastCheckedAt.Equal(checked2) || got.NextCheckAt == nil || !got.NextCheckAt.Equal(next2) || string(got.LastResult) != `{"phase": 2}` {
			t.Fatalf("package check round trip = %+v, %v", got, err)
		}
		if _, err := store.pool.Exec(ctx, `UPDATE package_check_status SET last_result=$2::jsonb WHERE ecosystem='npm' AND name=$1 AND source='socket'`, name, `{`); err == nil {
			t.Fatal("PostgreSQL accepted malformed package-check JSON")
		}
		gotAfterMalformed, err := store.GetPackageCheckStatus(ctx, "npm", name, "socket")
		if err != nil || gotAfterMalformed == nil || string(gotAfterMalformed.LastResult) != `{"phase": 2}` || gotAfterMalformed.CheckCount != 4 {
			t.Fatalf("package check after malformed JSON = %+v, %v, want unchanged", gotAfterMalformed, err)
		}
		f103F105Exec(t, ctx, store, `UPDATE package_check_status SET updated_at=clock_timestamp()-interval '2 hours' WHERE ecosystem='npm' AND name=$1 AND source='socket'`, name)
		pruned, err := store.PrunePackageCheckStatus(ctx, time.Hour)
		if err != nil || pruned != 1 {
			t.Fatalf("PrunePackageCheckStatus = %d, %v, want 1", pruned, err)
		}
		if got, err := store.GetPackageCheckStatus(ctx, "npm", name, "socket"); err != nil || got != nil {
			t.Fatalf("package check after prune = %+v, %v", got, err)
		}
	})

	t.Run("F105 reconstruction canonicalization idempotence and delta", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		ids := []string{prefix + "-GHSA-valid", prefix + "-GHSA-canonical", prefix + "-GHSA-malformed"}
		for _, id := range ids {
			f103F105Exec(t, ctx, store, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES($1,'F105 fixture','HIGH',clock_timestamp(),clock_timestamp())`, id)
		}
		validRaw := json.RawMessage(`{"affected":[
			{"package":{"ecosystem":"npm","name":"f105-range"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}],"versions":["1.0.0","1.0.0"],"database_specific":{"last_known_affected_version_range":"<= 1.5.0"}},
			{"package":{"ecosystem":"npm","name":"f105-range"},"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"}]}],"versions":["2.1.0"],"database_specific":{"last_known_affected_version_range":"< 3.0.0"}},
			{"package":{"ecosystem":"npm","name":"f105-preserve"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"9.9.9"}]}],"database_specific":{"last_known_affected_version_range":"<= 10.0.0"}},
			{"package":{"ecosystem":"unsupported","name":"ignored"},"ranges":[],"versions":[]},
			{"package":{"ecosystem":"npm","name":""},"ranges":[],"versions":[]}
		]}`)
		canonicalRaw := json.RawMessage(`{"affected":[
			{"package":{"ecosystem":"PyPI","name":"Requests_Pkg"},"ranges":[],"versions":["1.0"]},
			{"package":{"ecosystem":"NuGet","name":"NewtonSoft.JSON"},"ranges":[],"versions":["13.0.1"]}
		]}`)
		malformedRaw := json.RawMessage(`{"affected":[
			{"package":{"ecosystem":"npm","name":"f105-good-sibling"},"ranges":[],"versions":["4.0.0"]},
			{"package":{"ecosystem":"npm","name":"f105-bad-events"},"ranges":[{"type":"SEMVER","events":{"introduced":"0"}}],"versions":[]}
		]}`)
		for i, raw := range []json.RawMessage{validRaw, canonicalRaw, malformedRaw} {
			f103F105Exec(t, ctx, store, `INSERT INTO vulnerability_sources(vulnerability_id,source,source_id,raw_json) VALUES($1,'ghsa',$1,$2)`, ids[i], raw)
		}
		f103F105Exec(t, ctx, store, `INSERT INTO affected_packages(vulnerability_id,ecosystem,name,version_ranges,versions_affected) VALUES($1,'pypi','requests-pkg','[]'::jsonb,'["0.1"]'::jsonb)`, ids[1])
		var since time.Time
		if err := store.pool.QueryRow(ctx, `SELECT date_trunc('microseconds', clock_timestamp())`).Scan(&since); err != nil {
			t.Fatalf("delta boundary: %v", err)
		}
		repaired, err := store.RepairGHSAAffectedPackages(ctx)
		if err != nil || repaired != 5 {
			t.Fatalf("RepairGHSAAffectedPackages = %d, %v, want 5", repaired, err)
		}
		var rangesRaw, versionsRaw []byte
		if err := store.pool.QueryRow(ctx, `SELECT version_ranges,versions_affected FROM affected_packages WHERE vulnerability_id=$1 AND ecosystem='npm' AND name='f105-range'`, ids[0]).Scan(&rangesRaw, &versionsRaw); err != nil {
			t.Fatalf("read reconstructed range: %v", err)
		}
		var ranges []struct {
			Events []map[string]string `json:"events"`
		}
		var versions []string
		if err := json.Unmarshal(rangesRaw, &ranges); err != nil {
			t.Fatalf("decode ranges: %v", err)
		}
		if err := json.Unmarshal(versionsRaw, &versions); err != nil {
			t.Fatalf("decode versions: %v", err)
		}
		if len(ranges) != 2 || len(ranges[0].Events) != 2 || ranges[0].Events[1]["last_affected"] != "1.5.0" || len(ranges[1].Events) != 2 || ranges[1].Events[1]["fixed"] != "3.0.0" {
			t.Fatalf("reconstructed <=/< ranges = %s", rangesRaw)
		}
		if len(versions) != 2 || !((versions[0] == "1.0.0" && versions[1] == "2.1.0") || (versions[1] == "1.0.0" && versions[0] == "2.1.0")) {
			t.Fatalf("deduped versions = %v", versions)
		}
		if err := store.pool.QueryRow(ctx, `SELECT version_ranges FROM affected_packages WHERE vulnerability_id=$1 AND name='f105-preserve'`, ids[0]).Scan(&rangesRaw); err != nil {
			t.Fatalf("read preserved range: %v", err)
		}
		if strings.Contains(string(rangesRaw), "10.0.0") || !strings.Contains(string(rangesRaw), "9.9.9") {
			t.Fatalf("existing terminal event not preserved: %s", rangesRaw)
		}
		var canonicalRows, ignoredRows, goodSibling int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM affected_packages WHERE vulnerability_id=$1 AND ((ecosystem='pypi' AND name='requests-pkg') OR (ecosystem='nuget' AND name='newtonsoft.json'))`, ids[1]).Scan(&canonicalRows); err != nil {
			t.Fatalf("canonical rows: %v", err)
		}
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM affected_packages WHERE vulnerability_id=$1 AND (name='' OR name='ignored')`, ids[0]).Scan(&ignoredRows); err != nil {
			t.Fatalf("ignored rows: %v", err)
		}
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM affected_packages WHERE vulnerability_id=$1 AND name='f105-good-sibling'`, ids[2]).Scan(&goodSibling); err != nil {
			t.Fatalf("good sibling: %v", err)
		}
		if canonicalRows != 2 || ignoredRows != 0 || goodSibling != 1 {
			t.Fatalf("canonical/ignored/good sibling = %d/%d/%d", canonicalRows, ignoredRows, goodSibling)
		}
		var updatedAt time.Time
		if err := store.pool.QueryRow(ctx, `SELECT updated_at FROM affected_packages WHERE vulnerability_id=$1 AND ecosystem='pypi'`, ids[1]).Scan(&updatedAt); err != nil {
			t.Fatalf("canonical updated_at: %v", err)
		}
		repaired, err = store.RepairGHSAAffectedPackages(ctx)
		if err != nil || repaired != 0 {
			t.Fatalf("idempotent repair = %d, %v", repaired, err)
		}
		var unchanged time.Time
		if err := store.pool.QueryRow(ctx, `SELECT updated_at FROM affected_packages WHERE vulnerability_id=$1 AND ecosystem='pypi'`, ids[1]).Scan(&unchanged); err != nil || !unchanged.Equal(updatedAt) {
			t.Fatalf("no-op updated_at = %s, %v, want %s", unchanged, err, updatedAt)
		}
		exported, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &since})
		if err != nil {
			t.Fatalf("ExportSync(delta): %v", err)
		}
		seenUpdatedPyPI := false
		seenInsertedNuGet := false
		for _, item := range exported.Vulnerabilities {
			if item.ID == ids[1] && item.Ecosystem == "pypi" && item.Name == "requests-pkg" {
				seenUpdatedPyPI = true
			}
			if item.ID == ids[1] && item.Ecosystem == "nuget" && item.Name == "newtonsoft.json" {
				seenInsertedNuGet = true
			}
		}
		if !seenUpdatedPyPI || !seenInsertedNuGet {
			t.Fatalf("delta export updated PyPI/inserted NuGet = %v/%v, want both; rows: %+v", seenUpdatedPyPI, seenInsertedNuGet, exported.Vulnerabilities)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM vulnerabilities WHERE id=ANY($1)`, ids)
		var remaining int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM vulnerabilities WHERE id=ANY($1)`, ids).Scan(&remaining); err != nil || remaining != 0 {
			t.Fatalf("verified F105 cleanup=%d, %v", remaining, err)
		}
	})

	t.Run("F105 empty range events preserve existing constraints", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		id := prefix + "-GHSA-empty-events"
		f103F105Exec(t, ctx, store, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES($1,'F105 empty events','HIGH',clock_timestamp(),clock_timestamp())`, id)
		f103F105Exec(t, ctx, store, `
			INSERT INTO vulnerability_sources(vulnerability_id,source,source_id,raw_json)
			VALUES($1,'ghsa',$1,'{"affected":[{"package":{"ecosystem":"npm","name":"f105-empty-events"},"ranges":[{"type":"SEMVER","events":[]}],"versions":[]}]}'::jsonb)`, id)
		f103F105Exec(t, ctx, store, `
			INSERT INTO affected_packages(vulnerability_id,ecosystem,name,version_ranges,versions_affected)
			VALUES($1,'npm','f105-empty-events','[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]'::jsonb,'["1.0.0"]'::jsonb)`, id)

		var beforeRanges, beforeVersions string
		if err := store.pool.QueryRow(ctx, `SELECT version_ranges::text,versions_affected::text FROM affected_packages WHERE vulnerability_id=$1`, id).Scan(&beforeRanges, &beforeVersions); err != nil {
			t.Fatalf("read constraints before repair: %v", err)
		}
		repaired, err := store.RepairGHSAAffectedPackages(ctx)
		if err != nil || repaired != 0 {
			t.Fatalf("RepairGHSAAffectedPackages(empty events) = %d, %v, want no repaired row", repaired, err)
		}
		var afterRanges, afterVersions string
		if err := store.pool.QueryRow(ctx, `SELECT version_ranges::text,versions_affected::text FROM affected_packages WHERE vulnerability_id=$1`, id).Scan(&afterRanges, &afterVersions); err != nil {
			t.Fatalf("read constraints after repair: %v", err)
		}
		if afterRanges != beforeRanges || afterVersions != beforeVersions {
			t.Fatalf("constraints after empty-events repair = %s / %s, want preserved %s / %s", afterRanges, afterVersions, beforeRanges, beforeVersions)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM vulnerabilities WHERE id=$1`, id)
	})

	t.Run("F105 malformed constraint shapes preserve existing constraints", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		id := prefix + "-GHSA-malformed-constraints"
		f103F105Exec(t, ctx, store, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES($1,'F105 malformed constraints','HIGH',clock_timestamp(),clock_timestamp())`, id)
		defer f103F105Exec(t, ctx, store, `DELETE FROM vulnerabilities WHERE id=$1`, id)

		raw := json.RawMessage(`{"affected":[
			{"package":{"ecosystem":"npm","name":"f105-malformed-ranges"},"ranges":{"not":"an array"},"versions":["2.0.0"]},
			{"package":{"ecosystem":"npm","name":"f105-malformed-versions"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.0.0"}]}],"versions":"not an array"},
			{"package":{"ecosystem":"npm","name":"f105-valid-sibling"},"ranges":[],"versions":["5.0.0"]}
		]}`)
		f103F105Exec(t, ctx, store, `INSERT INTO vulnerability_sources(vulnerability_id,source,source_id,raw_json) VALUES($1,'ghsa',$1,$2)`, id, raw)
		f103F105Exec(t, ctx, store, `
			INSERT INTO affected_packages(vulnerability_id,ecosystem,name,version_ranges,versions_affected)
			VALUES
				($1,'npm','f105-malformed-ranges','[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"3.0.0"}]}]'::jsonb,'["1.0.0"]'::jsonb),
				($1,'npm','f105-malformed-versions','[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"6.0.0"}]}]'::jsonb,'["3.0.0"]'::jsonb)`, id)

		type constraints struct {
			ranges   string
			versions string
		}
		readConstraints := func(name string) constraints {
			var got constraints
			if err := store.pool.QueryRow(ctx, `SELECT version_ranges::text,versions_affected::text FROM affected_packages WHERE vulnerability_id=$1 AND name=$2`, id, name).Scan(&got.ranges, &got.versions); err != nil {
				t.Fatalf("read %s constraints: %v", name, err)
			}
			return got
		}
		jsonEqual := func(got, want string) bool {
			var gotValue, wantValue any
			if json.Unmarshal([]byte(got), &gotValue) != nil || json.Unmarshal([]byte(want), &wantValue) != nil {
				return false
			}
			return reflect.DeepEqual(gotValue, wantValue)
		}
		beforeRanges := readConstraints("f105-malformed-ranges")
		beforeVersions := readConstraints("f105-malformed-versions")
		repaired, err := store.RepairGHSAAffectedPackages(ctx)
		if err != nil {
			t.Fatalf("RepairGHSAAffectedPackages(malformed constraints): %v", err)
		}
		afterRanges := readConstraints("f105-malformed-ranges")
		afterVersions := readConstraints("f105-malformed-versions")
		sibling := readConstraints("f105-valid-sibling")
		if afterRanges != beforeRanges || afterVersions != beforeVersions {
			knownRangesLoss := jsonEqual(afterRanges.ranges, `[]`) && jsonEqual(afterRanges.versions, `["2.0.0"]`)
			knownVersionsLoss := jsonEqual(afterVersions.ranges, `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.0.0"}]}]`) && jsonEqual(afterVersions.versions, `[]`)
			knownSibling := jsonEqual(sibling.ranges, `[]`) && jsonEqual(sibling.versions, `["5.0.0"]`)
			if repaired != 3 || !knownRangesLoss || !knownVersionsLoss || !knownSibling {
				t.Fatalf("unexpected malformed repair result: repaired=%d ranges=%+v versions=%+v sibling=%+v", repaired, afterRanges, afterVersions, sibling)
			}
			t.Skip("F105-bugs-3: independently non-array GHSA ranges or versions overwrite existing valid constraints")
		}
		if repaired != 1 || !jsonEqual(sibling.ranges, `[]`) || !jsonEqual(sibling.versions, `["5.0.0"]`) {
			t.Fatalf("malformed-preserving repair = %d ranges=%+v versions=%+v sibling=%+v, want both targets preserved and one exact valid sibling", repaired, afterRanges, afterVersions, sibling)
		}
	})

	t.Run("F105 cancellation atomic failure and source counts", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		cancelled, cancelNow := context.WithCancel(ctx)
		cancelNow()
		if _, err := store.RepairGHSAAffectedPackages(cancelled); !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-cancelled repair error=%v, want context.Canceled", err)
		}
		ids := []string{prefix + "-GHSA-atomic-a", prefix + "-GHSA-atomic-b", prefix + "-OSV-count"}
		for _, id := range ids {
			f103F105Exec(t, ctx, store, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES($1,'F105 atomic','HIGH',clock_timestamp(),clock_timestamp())`, id)
		}
		raw := json.RawMessage(`{"affected":[{"package":{"ecosystem":"npm","name":"atomic-package"},"ranges":[],"versions":["1.0.0"]}]}`)
		for _, id := range ids[:2] {
			f103F105Exec(t, ctx, store, `INSERT INTO vulnerability_sources(vulnerability_id,source,source_id,raw_json) VALUES($1,'ghsa',$1,$2)`, id, raw)
		}
		f103F105Exec(t, ctx, store, `INSERT INTO vulnerability_sources(vulnerability_id,source,source_id,raw_json) VALUES($1,'osv',$1,'{}')`, ids[2])
		cleanup := `DROP TRIGGER IF EXISTS f105_atomic_failure ON affected_packages; DROP FUNCTION IF EXISTS f105_atomic_failure_fn()`
		verify := `SELECT to_regprocedure('public.f105_atomic_failure_fn()') IS NULL`
		f103F105RegisterDDLRestore(t, dsn, cleanup, verify)
		f103F105Exec(t, ctx, store, `CREATE FUNCTION f105_atomic_failure_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.vulnerability_id='`+ids[1]+`' THEN RAISE EXCEPTION 'forced F105 atomic failure' USING ERRCODE='23514'; END IF; RETURN NEW; END $$; CREATE TRIGGER f105_atomic_failure BEFORE INSERT OR UPDATE ON affected_packages FOR EACH ROW EXECUTE FUNCTION f105_atomic_failure_fn()`)
		repaired, err := store.RepairGHSAAffectedPackages(ctx)
		var pgErr *pgconn.PgError
		if err == nil || repaired != 0 || !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("atomic repair=%d/%v pg=%+v", repaired, err, pgErr)
		}
		var rows int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM affected_packages WHERE vulnerability_id=ANY($1)`, ids[:2]).Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("atomic rollback rows=%d err=%v", rows, err)
		}
		f103F105DDLRestore(t, dsn, cleanup, verify)
		if count, err := store.CountVulnerabilitiesBySource(ctx, "ghsa"); err != nil || count != 2 {
			t.Fatalf("CountVulnerabilitiesBySource(ghsa)=%d/%v, want2", count, err)
		}
		if count, err := store.CountVulnerabilitiesBySource(ctx, "osv"); err != nil || count != 1 {
			t.Fatalf("CountVulnerabilitiesBySource(osv)=%d/%v, want1", count, err)
		}
		if count, err := store.CountVulnerabilitiesBySource(ctx, "missing"); err != nil || count != 0 {
			t.Fatalf("CountVulnerabilitiesBySource(missing)=%d/%v, want0", count, err)
		}
		f103F105Exec(t, ctx, store, `DELETE FROM vulnerabilities WHERE id=ANY($1)`, ids)
	})

	t.Run("closed pool errors remain wrapped", func(t *testing.T) {
		ctx, cancel := f103F105Context(t)
		defer cancel()
		closed, err := New(ctx, dsn, nil, &PoolConfig{MaxConns: 1, MinConns: 1})
		if err != nil {
			t.Fatalf("New closed-pool fixture: %v", err)
		}
		closed.Close()
		checks := []struct {
			name string
			call func() error
		}{
			{name: "get feed config", call: func() error { _, err := closed.GetFeedConfig(ctx, "missing"); return err }},
			{name: "upsert feed config", call: func() error {
				return closed.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: prefix + "-closed", Mode: "self"})
			}},
			{name: "delete feed config", call: func() error { return closed.DeleteFeedConfig(ctx, prefix+"-closed") }},
			{name: "list feed configs", call: func() error { _, err := closed.ListFeedConfigs(ctx); return err }},
			{name: "get status", call: func() error { _, err := closed.GetFeedSyncStatus(ctx, "missing"); return err }},
			{name: "upsert status", call: func() error {
				return closed.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{FeedName: "closed", LastSyncStatus: "pending"})
			}},
			{name: "list statuses", call: func() error { _, err := closed.ListFeedSyncStatuses(ctx); return err }},
			{name: "enqueue", call: func() error {
				_, _, err := closed.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "closed", Source: "closed", Priority: 1})
				return err
			}},
			{name: "dequeue", call: func() error { _, err := closed.DequeueRefresh(ctx, "closed"); return err }},
			{name: "complete", call: func() error { return closed.CompleteRefresh(ctx, 1, nil) }},
			{name: "complete claimed", call: func() error { now := time.Now(); return closed.CompleteClaimedRefresh(ctx, 1, &now, nil) }},
			{name: "reset", call: func() error { _, err := closed.ResetStuckJobs(ctx, "closed", time.Hour); return err }},
			{name: "get package", call: func() error { _, err := closed.GetPackageCheckStatus(ctx, "npm", "closed", "socket"); return err }},
			{name: "upsert package", call: func() error {
				return closed.UpsertPackageCheckStatus(ctx, &db.PackageCheckStatus{Ecosystem: "npm", Name: "closed", Source: "socket"})
			}},
			{name: "prune package", call: func() error { _, err := closed.PrunePackageCheckStatus(ctx, time.Hour); return err }},
			{name: "repair GHSA", call: func() error { _, err := closed.RepairGHSAAffectedPackages(ctx); return err }},
			{name: "count source", call: func() error { _, err := closed.CountVulnerabilitiesBySource(ctx, "ghsa"); return err }},
		}
		for _, check := range checks {
			if err := check.call(); err == nil {
				t.Fatalf("%s on closed pool returned nil", check.name)
			}
		}
	})
}
