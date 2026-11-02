//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	packmondb "github.com/8linkz-sec/packmon/internal/db"
	postgresstore "github.com/8linkz-sec/packmon/internal/db/postgres"
	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type f139F142Leaf struct {
	ctx  context.Context
	conn *sql.Conn
	dsn  string
}

type f139F142MigrationEvent struct {
	name     string
	checksum string
	success  bool
	dirty    bool
}

func TestF139F142MigrationContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	database, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(database)
	database.SetMaxOpenConns(4)

	t.Run("populated_forward_reverse_repeat_and_reapply", func(t *testing.T) {
		leaf := f139F142PrepareLeaf(t, database, instance.dsn)
		f139F142ApplyThrough(t, leaf, 15)
		f139F142SeedLegacyAudit(t, leaf)
		f139F142SeedQueue(t, leaf)
		auditBefore := f139F142AuditSnapshot(t, leaf, false)
		queueBefore := f139F142QueueSnapshot(t, leaf)

		up16 := f139F142Apply(t, leaf, 16, MigrationDirectionUp)
		f139F142AssertCleanMetadata(t, leaf, up16)
		f139F142AssertDigestColumns(t, leaf, true)
		f139F142AssertIndex(t, leaf, "idx_admin_audit_digest", "admin_audit_log", "row_digest")
		if got := f139F142AuditSnapshot(t, leaf, false); got != auditBefore {
			t.Fatalf("016 up changed legacy audit fields\ngot:  %s\nwant: %s", got, auditBefore)
		}
		var previousDigest, rowDigest string
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT previous_digest,row_digest FROM admin_audit_log WHERE id=1601`).Scan(&previousDigest, &rowDigest); err != nil {
			t.Fatalf("read legacy digest defaults: %v", err)
		}
		if previousDigest != "" || rowDigest != "" {
			t.Fatalf("legacy digest defaults = previous:%q row:%q, want empty strings", previousDigest, rowDigest)
		}
		_, err := leaf.conn.ExecContext(leaf.ctx, `UPDATE admin_audit_log SET row_digest=NULL WHERE id=1601`)
		f139F142ExpectSQLState(t, err, "23502")

		packmondb.ClearAdminAuditDigestHMACKey()
		t.Cleanup(packmondb.ClearAdminAuditDigestHMACKey)
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}
		packmondb.SetAdminAuditDigestHMACKey(key)
		clear(key)
		store := f139F142OpenStore(t, leaf)
		if err := store.InsertAdminAuditLog(leaf.ctx, &packmondb.AdminAuditEntry{Action: "f140.first", Details: json.RawMessage(`{"step":"first"}`), IP: "192.0.2.16", CorrelationID: "f140-correlation-1"}); err != nil {
			t.Fatalf("InsertAdminAuditLog(first) error = %v", err)
		}
		if err := store.InsertAdminAuditLog(leaf.ctx, &packmondb.AdminAuditEntry{Action: "f140.second", Details: json.RawMessage(`{"step":"second"}`), IP: "192.0.2.17", CorrelationID: "f140-correlation-2"}); err != nil {
			t.Fatalf("InsertAdminAuditLog(second) error = %v", err)
		}
		audits, err := store.ListAdminAuditLogPage(leaf.ctx, 10, 0)
		if err != nil {
			t.Fatalf("ListAdminAuditLogPage() error = %v", err)
		}
		if len(audits) != 3 || audits[0].ID != 1603 || audits[0].Action != "f140.second" || audits[1].ID != 1602 || audits[1].Action != "f140.first" || audits[2].ID != 1601 || audits[2].Action != "f140.legacy" {
			t.Fatalf("audit order/sequence = %+v, want IDs 1603,1602,1601 with second,first,legacy", audits)
		}
		if audits[0].IntegrityStatus != packmondb.AdminAuditIntegrityVerified || audits[1].IntegrityStatus != packmondb.AdminAuditIntegrityVerified || audits[2].IntegrityStatus != packmondb.AdminAuditIntegrityLegacy {
			t.Fatalf("audit integrity statuses = [%q %q %q], want verified,verified,legacy", audits[0].IntegrityStatus, audits[1].IntegrityStatus, audits[2].IntegrityStatus)
		}
		if !strings.HasPrefix(audits[0].RowDigest, "hmac-sha256:") || !strings.HasPrefix(audits[1].RowDigest, "hmac-sha256:") || audits[1].PreviousDigest != "" || audits[0].PreviousDigest != audits[1].RowDigest {
			t.Fatalf("audit HMAC chain = newest(previous=%q,row=%q) older(previous=%q,row=%q)", audits[0].PreviousDigest, audits[0].RowDigest, audits[1].PreviousDigest, audits[1].RowDigest)
		}
		if !audits[0].CreatedAt.After(audits[2].CreatedAt) || !audits[1].CreatedAt.After(audits[2].CreatedAt) || audits[0].CreatedAt.Before(audits[1].CreatedAt) {
			t.Fatalf("audit times = newest:%v older:%v legacy:%v, want chronological sequence", audits[0].CreatedAt, audits[1].CreatedAt, audits[2].CreatedAt)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close(audit store) error = %v", err)
		}

		up17 := f139F142Apply(t, leaf, 17, MigrationDirectionUp)
		f139F142AssertCleanMetadata(t, leaf, up17)
		f139F142AssertQueueIndexes(t, leaf, true)
		if got := f139F142QueueSnapshot(t, leaf); got != queueBefore {
			t.Fatalf("017 up changed queue rows\ngot:  %s\nwant: %s", got, queueBefore)
		}
		f139F142AssertQueueListing(t, leaf)
		f139F142AssertQueuePlans(t, leaf)

		f139F142ApplyDownAndDeleteVersion(t, leaf, 17)
		f139F142AssertQueueIndexes(t, leaf, false)
		f139F142AssertRelationExists(t, leaf, "idx_queue_priority")
		if got := f139F142QueueSnapshot(t, leaf); got != queueBefore {
			t.Fatalf("017 down changed queue rows\ngot:  %s\nwant: %s", got, queueBefore)
		}
		f139F142ApplyDownAndDeleteVersion(t, leaf, 17)
		f139F142AssertQueueIndexes(t, leaf, false)
		f139F142Apply(t, leaf, 17, MigrationDirectionUp)
		f139F142AssertQueueIndexes(t, leaf, true)

		auditWithDigests := f139F142AuditSnapshot(t, leaf, false)
		f139F142ApplyDownAndDeleteVersion(t, leaf, 17)
		f139F142ApplyDownAndDeleteVersion(t, leaf, 16)
		f139F142AssertDigestColumns(t, leaf, false)
		f139F142AssertRelationAbsent(t, leaf, "idx_admin_audit_digest")
		if got := f139F142AuditSnapshot(t, leaf, false); got != auditWithDigests {
			t.Fatalf("016 down changed surviving audit fields\ngot:  %s\nwant: %s", got, auditWithDigests)
		}
		f139F142ApplyDownAndDeleteVersion(t, leaf, 16)
		f139F142Apply(t, leaf, 16, MigrationDirectionUp)
		f139F142Apply(t, leaf, 17, MigrationDirectionUp)
		f139F142AssertDigestColumns(t, leaf, true)
		f139F142AssertQueueIndexes(t, leaf, true)
		var nonEmptyDigests int
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM admin_audit_log WHERE previous_digest<>'' OR row_digest<>''`).Scan(&nonEmptyDigests); err != nil {
			t.Fatalf("count digests after 016 reapply: %v", err)
		}
		if nonEmptyDigests != 0 {
			t.Fatalf("non-empty digests after 016 down/up = %d, want discarded chain values to remain discarded", nonEmptyDigests)
		}
		store = f139F142OpenStore(t, leaf)
		audits, err = store.ListAdminAuditLogPage(leaf.ctx, 10, 0)
		if err != nil {
			t.Fatalf("ListAdminAuditLogPage(after reapply) error = %v", err)
		}
		for _, audit := range audits {
			if audit.IntegrityStatus != packmondb.AdminAuditIntegrityLegacy {
				t.Fatalf("audit %d integrity after 016 down/up = %q, want legacy", audit.ID, audit.IntegrityStatus)
			}
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close(reapplied store) error = %v", err)
		}

		for version := 18; version <= 43; version++ {
			f139F142Apply(t, leaf, version, MigrationDirectionUp)
		}
		f139F142AssertRelationAbsent(t, leaf, "idx_admin_audit_digest")
		f139F142AssertDigestColumns(t, leaf, true)
		f139F142AssertQueueIndexes(t, leaf, true)
	})

	t.Run("migration_016_up_collision_is_atomic_dirty_and_recoverable", func(t *testing.T) {
		leaf := f139F142PrepareLeaf(t, database, instance.dsn)
		f139F142ApplyThrough(t, leaf, 15)
		f139F142SeedLegacyAudit(t, leaf)
		before := f139F142AuditSnapshot(t, leaf, false)
		f139F142Exec(t, leaf, `CREATE TABLE idx_admin_audit_digest(id integer)`)

		up := f139F142Embedded(t, 16, MigrationDirectionUp)
		err := applyMigration(leaf.ctx, leaf.conn, up)
		if err == nil || !strings.Contains(err.Error(), "idx_admin_audit_digest") {
			t.Fatalf("016 up collision error = %v, want idx_admin_audit_digest conflict", err)
		}
		f139F142AssertDigestColumns(t, leaf, false)
		f139F142AssertRelationKind(t, leaf, "idx_admin_audit_digest", "r")
		if got := f139F142AuditSnapshot(t, leaf, false); got != before {
			t.Fatalf("failed transactional 016 up changed audit rows\ngot:  %s\nwant: %s", got, before)
		}
		f139F142AssertDirtyMetadata(t, leaf, up)
		f139F142AssertEvents(t, leaf, 16, []f139F142MigrationEvent{{up.name, migrationChecksum(up.sql), false, true}})
		f139F142AssertRunRefusesDirty(t, leaf, 16)

		f139F142ClearDirty(t, leaf, 16)
		f139F142Exec(t, leaf, `DROP TABLE idx_admin_audit_digest`)
		f139F142Apply(t, leaf, 16, MigrationDirectionUp)
		f139F142AssertDigestColumns(t, leaf, true)
		f139F142AssertIndex(t, leaf, "idx_admin_audit_digest", "admin_audit_log", "row_digest")
		f139F142AssertEvents(t, leaf, 16, []f139F142MigrationEvent{
			{up.name, migrationChecksum(up.sql), false, true},
			{up.name, migrationChecksum(up.sql), true, false},
		})
	})

	t.Run("migration_016_down_dependency_is_atomic_dirty_and_recoverable", func(t *testing.T) {
		leaf := f139F142PrepareLeaf(t, database, instance.dsn)
		f139F142ApplyThrough(t, leaf, 16)
		f139F142SeedAuditAfter16(t, leaf)
		before := f139F142AuditSnapshot(t, leaf, true)
		f139F142Exec(t, leaf, `CREATE VIEW f139_f142_digest_dependency AS SELECT id,previous_digest,row_digest FROM admin_audit_log`)

		down := f139F142Embedded(t, 16, MigrationDirectionDown)
		err := applyMigration(leaf.ctx, leaf.conn, down)
		if err == nil || !strings.Contains(err.Error(), "depend") {
			t.Fatalf("016 down dependency error = %v, want dependent-view failure", err)
		}
		f139F142AssertDigestColumns(t, leaf, true)
		f139F142AssertIndex(t, leaf, "idx_admin_audit_digest", "admin_audit_log", "row_digest")
		if got := f139F142AuditSnapshot(t, leaf, true); got != before {
			t.Fatalf("failed transactional 016 down changed audit rows\ngot:  %s\nwant: %s", got, before)
		}
		f139F142AssertDirtyMetadata(t, leaf, down)
		up := f139F142Embedded(t, 16, MigrationDirectionUp)
		f139F142AssertEvents(t, leaf, 16, []f139F142MigrationEvent{
			{up.name, migrationChecksum(up.sql), true, false},
			{down.name, migrationChecksum(down.sql), false, true},
		})
		f139F142AssertRunRefusesDirty(t, leaf, 16)

		f139F142ClearDirty(t, leaf, 16)
		f139F142Exec(t, leaf, `DROP VIEW f139_f142_digest_dependency`)
		f139F142Apply(t, leaf, 16, MigrationDirectionDown)
		f139F142AssertDigestColumns(t, leaf, false)
		f139F142AssertRelationAbsent(t, leaf, "idx_admin_audit_digest")
		f139F142AssertEvents(t, leaf, 16, []f139F142MigrationEvent{
			{up.name, migrationChecksum(up.sql), true, false},
			{down.name, migrationChecksum(down.sql), false, true},
			{down.name, migrationChecksum(down.sql), true, false},
		})
		f139F142DeleteSuccessfulDownVersion(t, leaf, down)
		f139F142Apply(t, leaf, 16, MigrationDirectionUp)
		f139F142AssertDigestColumns(t, leaf, true)
	})

	t.Run("migration_017_up_collision_is_atomic_dirty_and_recoverable", func(t *testing.T) {
		leaf := f139F142PrepareLeaf(t, database, instance.dsn)
		f139F142ApplyThrough(t, leaf, 16)
		f139F142SeedQueue(t, leaf)
		before := f139F142QueueSnapshot(t, leaf)
		f139F142Exec(t, leaf, `CREATE TABLE idx_queue_listing_status_requested_at(id integer)`)

		up := f139F142Embedded(t, 17, MigrationDirectionUp)
		err := applyMigration(leaf.ctx, leaf.conn, up)
		if err == nil || !strings.Contains(err.Error(), "idx_queue_listing_status_requested_at") {
			t.Fatalf("017 up second-index collision error = %v, want status index conflict", err)
		}
		f139F142AssertRelationAbsent(t, leaf, "idx_queue_listing_requested_at")
		f139F142AssertRelationKind(t, leaf, "idx_queue_listing_status_requested_at", "r")
		if got := f139F142QueueSnapshot(t, leaf); got != before {
			t.Fatalf("failed transactional 017 up changed queue rows\ngot:  %s\nwant: %s", got, before)
		}
		f139F142AssertDirtyMetadata(t, leaf, up)
		f139F142AssertEvents(t, leaf, 17, []f139F142MigrationEvent{{up.name, migrationChecksum(up.sql), false, true}})
		f139F142AssertRunRefusesDirty(t, leaf, 17)

		f139F142ClearDirty(t, leaf, 17)
		f139F142Exec(t, leaf, `DROP TABLE idx_queue_listing_status_requested_at`)
		f139F142Apply(t, leaf, 17, MigrationDirectionUp)
		f139F142AssertQueueIndexes(t, leaf, true)
		f139F142AssertEvents(t, leaf, 17, []f139F142MigrationEvent{
			{up.name, migrationChecksum(up.sql), false, true},
			{up.name, migrationChecksum(up.sql), true, false},
		})
	})

	t.Run("migration_017_down_second_drop_collision_is_atomic_dirty_and_recoverable", func(t *testing.T) {
		leaf := f139F142PrepareLeaf(t, database, instance.dsn)
		f139F142ApplyThrough(t, leaf, 17)
		f139F142SeedQueue(t, leaf)
		before := f139F142QueueSnapshot(t, leaf)
		f139F142Exec(t, leaf, `DROP INDEX idx_queue_listing_requested_at`)
		f139F142Exec(t, leaf, `CREATE TABLE idx_queue_listing_requested_at(id integer)`)

		down := f139F142Embedded(t, 17, MigrationDirectionDown)
		err := applyMigration(leaf.ctx, leaf.conn, down)
		if err == nil || !strings.Contains(err.Error(), "idx_queue_listing_requested_at") {
			t.Fatalf("017 down second-drop collision error = %v, want requested index conflict", err)
		}
		f139F142AssertIndex(t, leaf, "idx_queue_listing_status_requested_at", "refresh_queue", "status,requested_at DESC,id DESC")
		f139F142AssertRelationKind(t, leaf, "idx_queue_listing_requested_at", "r")
		if got := f139F142QueueSnapshot(t, leaf); got != before {
			t.Fatalf("failed transactional 017 down changed queue rows\ngot:  %s\nwant: %s", got, before)
		}
		f139F142AssertDirtyMetadata(t, leaf, down)
		up := f139F142Embedded(t, 17, MigrationDirectionUp)
		f139F142AssertEvents(t, leaf, 17, []f139F142MigrationEvent{
			{up.name, migrationChecksum(up.sql), true, false},
			{down.name, migrationChecksum(down.sql), false, true},
		})
		f139F142AssertRunRefusesDirty(t, leaf, 17)

		f139F142ClearDirty(t, leaf, 17)
		f139F142Exec(t, leaf, `DROP TABLE idx_queue_listing_requested_at`)
		f139F142Exec(t, leaf, `CREATE INDEX idx_queue_listing_requested_at ON refresh_queue(requested_at DESC,id DESC)`)
		f139F142Apply(t, leaf, 17, MigrationDirectionDown)
		f139F142AssertQueueIndexes(t, leaf, false)
		f139F142AssertEvents(t, leaf, 17, []f139F142MigrationEvent{
			{up.name, migrationChecksum(up.sql), true, false},
			{down.name, migrationChecksum(down.sql), false, true},
			{down.name, migrationChecksum(down.sql), true, false},
		})
		f139F142DeleteSuccessfulDownVersion(t, leaf, down)
		f139F142Apply(t, leaf, 17, MigrationDirectionUp)
		f139F142AssertQueueIndexes(t, leaf, true)
	})
}

func f139F142PrepareLeaf(t *testing.T, database *sql.DB, dsn string) f139F142Leaf {
	t.Helper()
	resetCtx, resetCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer resetCancel()
	if _, err := database.ExecContext(resetCtx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public AUTHORIZATION packmon`); err != nil {
		t.Fatalf("reset public schema before migration leaf: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	conn, err := database.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire migration leaf connection: %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(conn) })
	leaf := f139F142Leaf{ctx: ctx, conn: conn, dsn: dsn}
	if err := ensureVersionTable(ctx, conn); err != nil {
		t.Fatalf("ensure migration metadata tables: %v", err)
	}
	return leaf
}

func f139F142ApplyThrough(t *testing.T, leaf f139F142Leaf, target int) {
	t.Helper()
	for version := 1; version <= target; version++ {
		f139F142Apply(t, leaf, version, MigrationDirectionUp)
	}
}

func f139F142Embedded(t *testing.T, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	embedded, err := ReadEmbeddedMigration(version, direction)
	if err != nil {
		t.Fatalf("ReadEmbeddedMigration(%03d, %s) error = %v", version, direction, err)
	}
	return migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
}

func f139F142Apply(t *testing.T, leaf f139F142Leaf, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	migration := f139F142Embedded(t, version, direction)
	if err := applyMigration(leaf.ctx, leaf.conn, migration); err != nil {
		t.Fatalf("apply %s: %v", migration.name, err)
	}
	return migration
}

func f139F142ApplyDownAndDeleteVersion(t *testing.T, leaf f139F142Leaf, version int) {
	t.Helper()
	down := f139F142Apply(t, leaf, version, MigrationDirectionDown)
	f139F142DeleteSuccessfulDownVersion(t, leaf, down)
}

func f139F142DeleteSuccessfulDownVersion(t *testing.T, leaf f139F142Leaf, down migrationFile) {
	t.Helper()
	f139F142AssertCleanMetadata(t, leaf, down)
	version, dirty, ok, err := currentVersion(leaf.ctx, leaf.conn)
	if err != nil {
		t.Fatalf("currentVersion() after %s: %v", down.name, err)
	}
	if !ok || dirty || version != down.version {
		t.Fatalf("currentVersion() after %s = version:%d dirty:%t ok:%t, want version %d clean before explicit down-row deletion", down.name, version, dirty, ok, down.version)
	}
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND name=$2 AND checksum=$3 AND NOT dirty`, down.version, down.name, migrationChecksum(down.sql))
	if err != nil {
		t.Fatalf("delete inspected successful down metadata for %s: %v", down.name, err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		t.Fatalf("delete successful down metadata for %s affected=%d error=%v, want 1", down.name, affected, err)
	}
}

func f139F142OpenStore(t *testing.T, leaf f139F142Leaf) *postgresstore.Store {
	t.Helper()
	store, err := postgresstore.New(leaf.ctx, leaf.dsn, nil, &postgresstore.PoolConfig{MaxConns: 1, MinConns: 1})
	if err != nil {
		t.Fatalf("postgres.New() error = %v", err)
	}
	return store
}

func f139F142Exec(t *testing.T, leaf f139F142Leaf, statement string, args ...any) {
	t.Helper()
	if _, err := leaf.conn.ExecContext(leaf.ctx, statement, args...); err != nil {
		t.Fatalf("execute migration fixture SQL: %v\nSQL:\n%s", err, statement)
	}
}

func f139F142SeedLegacyAudit(t *testing.T, leaf f139F142Leaf) {
	t.Helper()
	f139F142Exec(t, leaf, `INSERT INTO admin_audit_log(id,action,details,ip,correlation_id,created_at) VALUES(1601,'f140.legacy','{"kind":"legacy"}','192.0.2.15','f140-legacy-correlation','2020-01-02T03:04:05.123456Z')`)
	f139F142Exec(t, leaf, `SELECT setval(pg_get_serial_sequence('admin_audit_log','id'),1601,true)`)
}

func f139F142SeedAuditAfter16(t *testing.T, leaf f139F142Leaf) {
	t.Helper()
	f139F142Exec(t, leaf, `INSERT INTO admin_audit_log(id,action,details,ip,correlation_id,created_at,previous_digest,row_digest) VALUES(1601,'f139.down','{"keep":"all"}','192.0.2.18','f139-down-correlation','2021-02-03T04:05:06.654321Z','hmac-sha256:previous','hmac-sha256:row')`)
	f139F142Exec(t, leaf, `SELECT setval(pg_get_serial_sequence('admin_audit_log','id'),1601,true)`)
}

func f139F142SeedQueue(t *testing.T, leaf f139F142Leaf) {
	t.Helper()
	f139F142Exec(t, leaf, `
		INSERT INTO refresh_queue(id,ecosystem,name,source,priority,status,requested_at,processed_at,error) VALUES
		(1701,'npm','pending-low-id','osv',1,'pending','2026-06-02T00:00:00Z',NULL,NULL),
		(1702,'pypi','done-tie','ghsa',2,'done','2026-06-02T00:00:00Z','2026-06-02T01:00:00Z',NULL),
		(1703,'go','pending-high-id','osv',0,'pending','2026-06-02T00:00:00Z',NULL,NULL),
		(1704,'maven','pending-older','osv',3,'pending','2026-06-01T00:00:00Z',NULL,NULL),
		(1705,'cargo','error-newest','ghsa',2,'error','2026-06-03T00:00:00Z','2026-06-03T01:00:00Z','fixture error')`)
	f139F142Exec(t, leaf, `SELECT setval(pg_get_serial_sequence('refresh_queue','id'),1705,true)`)
}

func f139F142AuditSnapshot(t *testing.T, leaf f139F142Leaf, includeDigests bool) string {
	t.Helper()
	columns := "id,action,details,ip::text AS ip,correlation_id,created_at"
	if includeDigests {
		columns += ",previous_digest,row_digest"
	}
	var snapshot string
	query := `SELECT COALESCE(jsonb_agg(to_jsonb(snapshot) ORDER BY id)::text,'[]') FROM (SELECT ` + columns + ` FROM admin_audit_log ORDER BY id) snapshot`
	if err := leaf.conn.QueryRowContext(leaf.ctx, query).Scan(&snapshot); err != nil {
		t.Fatalf("snapshot admin audit rows: %v", err)
	}
	return snapshot
}

func f139F142QueueSnapshot(t *testing.T, leaf f139F142Leaf) string {
	t.Helper()
	var snapshot string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(snapshot) ORDER BY id)::text,'[]') FROM (SELECT id,ecosystem,name,source,priority,status,requested_at,processed_at,error FROM refresh_queue ORDER BY id) snapshot`).Scan(&snapshot); err != nil {
		t.Fatalf("snapshot refresh queue rows: %v", err)
	}
	return snapshot
}

func f139F142AssertDigestColumns(t *testing.T, leaf f139F142Leaf, want bool) {
	t.Helper()
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT column_name,data_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema='public' AND table_name='admin_audit_log' AND column_name IN ('previous_digest','row_digest') ORDER BY column_name`)
	if err != nil {
		t.Fatalf("inspect digest columns: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	type column struct{ name, dataType, nullable, defaultSQL string }
	var got []column
	for rows.Next() {
		var value column
		if err := rows.Scan(&value.name, &value.dataType, &value.nullable, &value.defaultSQL); err != nil {
			t.Fatalf("scan digest column: %v", err)
		}
		got = append(got, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate digest columns: %v", err)
	}
	wantColumns := []column(nil)
	if want {
		wantColumns = []column{{"previous_digest", "text", "NO", "''::text"}, {"row_digest", "text", "NO", "''::text"}}
	}
	if !reflect.DeepEqual(got, wantColumns) {
		t.Fatalf("digest columns = %#v, want %#v", got, wantColumns)
	}
}

func f139F142AssertQueueIndexes(t *testing.T, leaf f139F142Leaf, want bool) {
	t.Helper()
	for _, index := range []struct{ name, keys string }{
		{"idx_queue_listing_requested_at", "requested_at DESC,id DESC"},
		{"idx_queue_listing_status_requested_at", "status,requested_at DESC,id DESC"},
	} {
		if want {
			f139F142AssertIndex(t, leaf, index.name, "refresh_queue", index.keys)
		} else {
			f139F142AssertRelationAbsent(t, leaf, index.name)
		}
	}
}

func f139F142AssertIndex(t *testing.T, leaf f139F142Leaf, name, table, keys string) {
	t.Helper()
	var gotTable, accessMethod, gotKeys, definition string
	var unique, valid, ready bool
	err := leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT tbl.relname,am.amname,i.indisunique,
		       string_agg(pg_get_indexdef(i.indexrelid,n,true),',' ORDER BY n),
		       pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready
		FROM pg_index i
		JOIN pg_class idx ON idx.oid=i.indexrelid
		JOIN pg_class tbl ON tbl.oid=i.indrelid
		JOIN pg_am am ON am.oid=idx.relam
		CROSS JOIN LATERAL generate_series(1,i.indnkeyatts) n
		WHERE idx.oid=to_regclass($1)
		GROUP BY i.indexrelid,tbl.relname,am.amname,i.indisunique,i.indisvalid,i.indisready`, name).Scan(&gotTable, &accessMethod, &unique, &gotKeys, &definition, &valid, &ready)
	if err != nil {
		t.Fatalf("inspect index %s: %v", name, err)
	}
	wantColumns := strings.ReplaceAll(keys, " DESC", "")
	wantDefinition := "CREATE INDEX " + name + " ON public." + table + " USING btree (" + strings.ReplaceAll(keys, ",", ", ") + ")"
	if gotTable != table || accessMethod != "btree" || unique || gotKeys != wantColumns || definition != wantDefinition || !valid || !ready {
		t.Fatalf("index %s = table:%q method:%q unique:%t keys:%q definition:%q valid:%t ready:%t, want %s btree nonunique keys %q definition %q valid/ready", name, gotTable, accessMethod, unique, gotKeys, definition, valid, ready, table, wantColumns, wantDefinition)
	}
}

func f139F142AssertQueueListing(t *testing.T, leaf f139F142Leaf) {
	t.Helper()
	store := f139F142OpenStore(t, leaf)
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close(queue listing store) error = %v", err)
		}
	}()
	assertIDs := func(label string, jobs []packmondb.RefreshJob, err error, want []int) {
		t.Helper()
		if err != nil {
			t.Fatalf("ListQueueJobsPage(%s) error = %v", label, err)
		}
		got := make([]int, len(jobs))
		for i := range jobs {
			got[i] = jobs[i].ID
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ListQueueJobsPage(%s) IDs = %v, want %v", label, got, want)
		}
	}
	jobs, err := store.ListQueueJobsPage(leaf.ctx, "", 2, 0)
	assertIDs("all page 1", jobs, err, []int{1705, 1703})
	jobs, err = store.ListQueueJobsPage(leaf.ctx, "", 2, 2)
	assertIDs("all page 2", jobs, err, []int{1702, 1701})
	jobs, err = store.ListQueueJobsPage(leaf.ctx, packmondb.RefreshStatusPending, 2, 0)
	assertIDs("pending page 1", jobs, err, []int{1703, 1701})
	jobs, err = store.ListQueueJobsPage(leaf.ctx, packmondb.RefreshStatusPending, 2, 2)
	assertIDs("pending page 2", jobs, err, []int{1704})
}

func f139F142AssertQueuePlans(t *testing.T, leaf f139F142Leaf) {
	t.Helper()
	f139F142Exec(t, leaf, `SET enable_seqscan=off`)
	t.Cleanup(func() {
		resetCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = leaf.conn.ExecContext(resetCtx, `RESET enable_seqscan`)
	})
	tests := []struct {
		name, query, index string
		args               []any
	}{
		{
			name:  "unfiltered",
			query: `EXPLAIN (FORMAT JSON, COSTS OFF) SELECT id,ecosystem,name,source,priority,status,requested_at,processed_at,error FROM refresh_queue ORDER BY requested_at DESC,id DESC LIMIT $1 OFFSET $2`,
			index: "idx_queue_listing_requested_at",
			args:  []any{2, 0},
		},
		{
			name:  "filtered",
			query: `EXPLAIN (FORMAT JSON, COSTS OFF) SELECT id,ecosystem,name,source,priority,status,requested_at,processed_at,error FROM refresh_queue WHERE status=$1 ORDER BY requested_at DESC,id DESC LIMIT $2 OFFSET $3`,
			index: "idx_queue_listing_status_requested_at",
			args:  []any{packmondb.RefreshStatusPending, 2, 0},
		},
	}
	for _, tt := range tests {
		var raw []byte
		if err := leaf.conn.QueryRowContext(leaf.ctx, tt.query, tt.args...).Scan(&raw); err != nil {
			t.Fatalf("EXPLAIN %s queue listing: %v", tt.name, err)
		}
		var plan any
		if err := json.Unmarshal(raw, &plan); err != nil {
			t.Fatalf("decode %s queue EXPLAIN: %v\n%s", tt.name, err, raw)
		}
		if !f139F142JSONPlanContainsIndex(plan, tt.index) {
			t.Fatalf("%s queue EXPLAIN does not use %s: %s", tt.name, tt.index, raw)
		}
		if f139F142JSONPlanContainsNode(plan, "Sort") {
			t.Fatalf("%s queue EXPLAIN contains Sort despite ordered index: %s", tt.name, raw)
		}
	}
}

func f139F142JSONPlanContainsIndex(value any, index string) bool {
	switch value := value.(type) {
	case map[string]any:
		if value["Index Name"] == index {
			return true
		}
		for _, child := range value {
			if f139F142JSONPlanContainsIndex(child, index) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if f139F142JSONPlanContainsIndex(child, index) {
				return true
			}
		}
	}
	return false
}

func f139F142JSONPlanContainsNode(value any, node string) bool {
	switch value := value.(type) {
	case map[string]any:
		if value["Node Type"] == node {
			return true
		}
		for _, child := range value {
			if f139F142JSONPlanContainsNode(child, node) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if f139F142JSONPlanContainsNode(child, node) {
				return true
			}
		}
	}
	return false
}

func f139F142AssertRelationAbsent(t *testing.T, leaf f139F142Leaf, name string) {
	t.Helper()
	var exists bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatalf("inspect absent relation %s: %v", name, err)
	}
	if exists {
		t.Fatalf("relation %s exists, want absent", name)
	}
}

func f139F142AssertRelationExists(t *testing.T, leaf f139F142Leaf, name string) {
	t.Helper()
	var exists bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatalf("inspect relation %s: %v", name, err)
	}
	if !exists {
		t.Fatalf("relation %s absent, want present", name)
	}
}

func f139F142AssertRelationKind(t *testing.T, leaf f139F142Leaf, name, want string) {
	t.Helper()
	var kind string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT relkind::text FROM pg_class WHERE oid=to_regclass($1)`, name).Scan(&kind); err != nil {
		t.Fatalf("inspect relation kind %s: %v", name, err)
	}
	if kind != want {
		t.Fatalf("relation %s kind = %q, want %q", name, kind, want)
	}
}

func f139F142AssertCleanMetadata(t *testing.T, leaf f139F142Leaf, migration migrationFile) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read clean metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != migrationChecksum(migration.sql) || dirty || appliedAt.IsZero() {
		t.Fatalf("clean metadata for %s = name:%q checksum:%q dirty:%t applied:%v", migration.name, name, checksum, dirty, appliedAt)
	}
}

func f139F142AssertDirtyMetadata(t *testing.T, leaf f139F142Leaf, migration migrationFile) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt sql.NullTime
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read dirty metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != migrationChecksum(migration.sql) || !dirty || appliedAt.Valid {
		t.Fatalf("dirty metadata for %s = name:%q checksum:%q dirty:%t applied:%v", migration.name, name, checksum, dirty, appliedAt)
	}
}

func f139F142AssertEvents(t *testing.T, leaf f139F142Leaf, version int, want []f139F142MigrationEvent) {
	t.Helper()
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT name,checksum,success,dirty,finished_at IS NOT NULL FROM schema_migration_events WHERE version=$1 ORDER BY id`, version)
	if err != nil {
		t.Fatalf("read migration %03d events: %v", version, err)
	}
	defer ioutils.CloseSilently(rows)
	var got []f139F142MigrationEvent
	for rows.Next() {
		var event f139F142MigrationEvent
		var finished bool
		if err := rows.Scan(&event.name, &event.checksum, &event.success, &event.dirty, &finished); err != nil {
			t.Fatalf("scan migration %03d event: %v", version, err)
		}
		if !finished {
			t.Fatalf("migration %03d event %d has no finished_at", version, len(got)+1)
		}
		got = append(got, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migration %03d events: %v", version, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("migration %03d events = %#v, want %#v", version, got, want)
	}
}

func f139F142AssertRunRefusesDirty(t *testing.T, leaf f139F142Leaf, version int) {
	t.Helper()
	err := RunContext(leaf.ctx, leaf.dsn)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("dirty at version %d", version)) {
		t.Fatalf("RunContext() on dirty version %d error = %v, want dirty refusal", version, err)
	}
}

func f139F142ClearDirty(t *testing.T, leaf f139F142Leaf, version int) {
	t.Helper()
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND dirty`, version)
	if err != nil {
		t.Fatalf("fixture-only dirty cleanup for version %d: %v", version, err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		t.Fatalf("fixture-only dirty cleanup for version %d affected=%d error=%v, want 1", version, affected, err)
	}
}

func f139F142ExpectSQLState(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("PostgreSQL error = nil, want SQLSTATE %s", want)
	}
	var state interface{ SQLState() string }
	if !errors.As(err, &state) || state.SQLState() != want {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, want)
	}
}
