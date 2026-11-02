//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type f119F122MigrationEventExpectation struct {
	name     string
	checksum string
	success  bool
	dirty    bool
}

type f119F122APIKeySnapshot struct {
	id         int
	name       string
	keyHash    string
	createdAt  time.Time
	revokedAt  sql.NullTime
	lastUsedAt sql.NullTime
}

func TestAPIKeyExpirationMigration006ContractsAgainstPostgres(t *testing.T) {
	up := f119F122ReadMigration(t, 6, MigrationDirectionUp)
	down := f119F122ReadMigration(t, 6, MigrationDirectionDown)
	f119F122AssertStatementOrder(t, up.sql, []string{
		"ALTER TABLE api_keys\n    ADD COLUMN expires_at TIMESTAMPTZ",
		"CREATE INDEX idx_api_keys_expires_at\n    ON api_keys(expires_at)\n    WHERE expires_at IS NOT NULL",
	})
	f119F122AssertStatementOrder(t, down.sql, []string{
		"DROP INDEX IF EXISTS idx_api_keys_expires_at",
		"ALTER TABLE api_keys\n    DROP COLUMN IF EXISTS expires_at",
	})

	instance := startMigrationPostgresInstance(t, false)
	db, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	applyEmbeddedMigrationsRangeForTest(t, ctx, db, 1, 5)
	f119F122SeedLegacyAPIKeys(t, ctx, db)
	wantLegacy := f119F122ReadAPIKeySnapshots(t, ctx, db)
	var events []f119F122MigrationEventExpectation

	t.Run("failed_up_rolls_back_and_records_dirty_event", func(t *testing.T) {
		injected := f119F122InjectFinalFailure(up)
		err := applyMigration(ctx, db, injected)
		expectSQLState(t, "42P01", err)
		events = append(events, f119F122EventExpectation(injected, false, true))
		f119F122AssertFailedMigrationState(t, ctx, db, injected)
		f119F122AssertAPIKeyObjects(t, ctx, db, false)
		if got := f119F122ReadAPIKeySnapshots(t, ctx, db); !reflect.DeepEqual(got, wantLegacy) {
			t.Fatalf("legacy API keys after failed 006 up = %#v, want %#v", got, wantLegacy)
		}
	})

	t.Run("upgrade_preserves_legacy_rows_catalog_and_expiration_semantics", func(t *testing.T) {
		if err := applyMigration(ctx, db, up); err != nil {
			t.Fatalf("apply migration %s: %v", up.name, err)
		}
		events = append(events, f119F122EventExpectation(up, true, false))
		assertCleanMigration(t, ctx, db, up)
		f119F122AssertAPIKeyObjects(t, ctx, db, true)
		if got := f119F122ReadAPIKeySnapshots(t, ctx, db); !reflect.DeepEqual(got, wantLegacy) {
			t.Fatalf("legacy API keys after 006 up = %#v, want %#v", got, wantLegacy)
		}
		f119F122AssertAllExpirationsNull(t, ctx, db, []int{41, 42, 43})
		f119F122AssertAPIKeyEligibility(t, ctx, db, map[int]bool{41: true, 42: false, 43: true})

		expiresAt := time.Date(2027, time.January, 2, 3, 4, 5, 678000000, time.UTC)
		execOK(t, ctx, db, `UPDATE api_keys SET expires_at = $1 WHERE id = 41`, expiresAt)
		execOK(t, ctx, db, `UPDATE api_keys SET expires_at = '2026-04-05T06:07:08Z' WHERE id = 43`)
		execOK(t, ctx, db, `INSERT INTO api_keys(id, name, key_hash, created_at, expires_at) VALUES(44, 'explicit-expiry', 'hash-explicit-expiry', '2026-04-05T06:07:08.123Z', $1)`, expiresAt)
		var got time.Time
		if err := db.QueryRowContext(ctx, `SELECT expires_at FROM api_keys WHERE id = 44`).Scan(&got); err != nil {
			t.Fatalf("read explicit API key expiration: %v", err)
		}
		if !got.Equal(expiresAt) {
			t.Fatalf("explicit API key expiration = %s, want %s", got, expiresAt)
		}
		f119F122AssertAPIKeyEligibility(t, ctx, db, map[int]bool{41: true, 42: false, 43: false, 44: true})
	})

	t.Run("failed_down_rolls_back_and_records_dirty_event", func(t *testing.T) {
		wantRows := f119F122ReadAPIKeySnapshots(t, ctx, db)
		wantExpirations := f119F122ReadExpirations(t, ctx, db)
		injected := f119F122InjectFinalFailure(down)
		err := applyMigration(ctx, db, injected)
		expectSQLState(t, "42P01", err)
		events = append(events, f119F122EventExpectation(injected, false, true))
		f119F122AssertFailedMigrationState(t, ctx, db, injected)
		f119F122AssertAPIKeyObjects(t, ctx, db, true)
		if got := f119F122ReadAPIKeySnapshots(t, ctx, db); !reflect.DeepEqual(got, wantRows) {
			t.Fatalf("API keys after failed 006 down = %#v, want %#v", got, wantRows)
		}
		if got := f119F122ReadExpirations(t, ctx, db); !reflect.DeepEqual(got, wantExpirations) {
			t.Fatalf("API key expirations after failed 006 down = %#v, want %#v", got, wantExpirations)
		}
	})

	t.Run("downgrade_preserves_legacy_fields_and_removes_objects", func(t *testing.T) {
		wantRows := f119F122ReadAPIKeySnapshots(t, ctx, db)
		if err := applyMigration(ctx, db, down); err != nil {
			t.Fatalf("apply migration %s: %v", down.name, err)
		}
		events = append(events, f119F122EventExpectation(down, true, false))
		assertCleanMigrationAndDelete(t, ctx, db, down)
		assertCurrentMigration(t, ctx, db, 5)
		f119F122AssertAPIKeyObjects(t, ctx, db, false)
		if got := f119F122ReadAPIKeySnapshots(t, ctx, db); !reflect.DeepEqual(got, wantRows) {
			t.Fatalf("API keys after 006 down = %#v, want %#v", got, wantRows)
		}
	})

	t.Run("missing_index_repeated_down_and_reapply", func(t *testing.T) {
		if err := applyMigration(ctx, db, up); err != nil {
			t.Fatalf("first reapply migration %s: %v", up.name, err)
		}
		events = append(events, f119F122EventExpectation(up, true, false))
		f119F122AssertAllExpirationsNull(t, ctx, db, []int{41, 42, 43, 44})
		execOK(t, ctx, db, `DROP INDEX idx_api_keys_expires_at`)

		if err := applyMigration(ctx, db, down); err != nil {
			t.Fatalf("apply 006 down with missing index: %v", err)
		}
		events = append(events, f119F122EventExpectation(down, true, false))
		assertCleanMigrationAndDelete(t, ctx, db, down)
		if err := applyMigration(ctx, db, down); err != nil {
			t.Fatalf("repeat 006 down: %v", err)
		}
		events = append(events, f119F122EventExpectation(down, true, false))
		assertCleanMigrationAndDelete(t, ctx, db, down)
		assertCurrentMigration(t, ctx, db, 5)

		if err := applyMigration(ctx, db, up); err != nil {
			t.Fatalf("final reapply migration %s: %v", up.name, err)
		}
		events = append(events, f119F122EventExpectation(up, true, false))
		assertCleanMigration(t, ctx, db, up)
		assertCurrentMigration(t, ctx, db, 6)
		f119F122AssertAPIKeyObjects(t, ctx, db, true)
		f119F122AssertAllExpirationsNull(t, ctx, db, []int{41, 42, 43, 44})
		f119F122AssertMigrationEvents(t, ctx, db, 6, events, 8)
	})
}

func f119F122ReadMigration(t *testing.T, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	embedded, err := ReadEmbeddedMigration(version, direction)
	if err != nil {
		t.Fatalf("read migration %03d %s: %v", version, direction, err)
	}
	return migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
}

func f119F122AssertStatementOrder(t *testing.T, migrationSQL string, want []string) {
	t.Helper()
	statements, err := splitSQLStatements(migrationSQL)
	if err != nil {
		t.Fatalf("splitSQLStatements() error = %v", err)
	}
	if len(statements) != len(want) {
		t.Fatalf("splitSQLStatements() count = %d, want %d: %#v", len(statements), len(want), statements)
	}
	for i := range want {
		got := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(statements[i]), ";"))
		if got != want[i] {
			t.Fatalf("statement %d = %q, want %q", i+1, got, want[i])
		}
	}
}

func f119F122InjectFinalFailure(migration migrationFile) migrationFile {
	migration.sql += `

DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '42P01', MESSAGE = 'injected final migration failure';
END $$;
`
	return migration
}

func f119F122EventExpectation(migration migrationFile, success, dirty bool) f119F122MigrationEventExpectation {
	return f119F122MigrationEventExpectation{
		name:     migration.name,
		checksum: migrationChecksum(migration.sql),
		success:  success,
		dirty:    dirty,
	}
}

func f119F122AssertFailedMigrationState(t *testing.T, ctx context.Context, db *sql.DB, migration migrationFile) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT name, checksum, dirty, applied_at FROM schema_migrations WHERE version = $1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read failed migration metadata: %v", err)
	}
	wantChecksum := migrationChecksum(migration.sql)
	if name != migration.name || checksum != wantChecksum || !dirty || appliedAt.Valid {
		t.Fatalf("failed metadata = name:%q checksum:%q dirty:%v applied:%v, want %q %q true false", name, checksum, dirty, appliedAt.Valid, migration.name, wantChecksum)
	}
	version, currentDirty, ok, err := currentVersion(ctx, db)
	if err != nil {
		t.Fatalf("currentVersion() error = %v", err)
	}
	if !ok || version != migration.version || !currentDirty {
		t.Fatalf("currentVersion() = version:%d dirty:%v ok:%v, want %d dirty", version, currentDirty, ok, migration.version)
	}

	var eventName, eventChecksum string
	var finishedAt sql.NullTime
	var success, eventDirty bool
	if err := db.QueryRowContext(ctx, `
		SELECT name, checksum, finished_at, success, dirty
		FROM schema_migration_events WHERE version = $1 ORDER BY id DESC LIMIT 1`, migration.version).Scan(&eventName, &eventChecksum, &finishedAt, &success, &eventDirty); err != nil {
		t.Fatalf("read failed migration event: %v", err)
	}
	if eventName != migration.name || eventChecksum != wantChecksum || !finishedAt.Valid || success || !eventDirty {
		t.Fatalf("failed event = name:%q checksum:%q finished:%v success:%v dirty:%v", eventName, eventChecksum, finishedAt.Valid, success, eventDirty)
	}
}

func f119F122AssertMigrationEvents(t *testing.T, ctx context.Context, db *sql.DB, version int, want []f119F122MigrationEventExpectation, wantCount int) {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		SELECT name, checksum, finished_at, success, dirty
		FROM schema_migration_events WHERE version = $1 ORDER BY id`, version)
	if err != nil {
		t.Fatalf("read migration %03d events: %v", version, err)
	}
	defer ioutils.CloseSilently(rows)
	var got []f119F122MigrationEventExpectation
	for rows.Next() {
		var event f119F122MigrationEventExpectation
		var finishedAt sql.NullTime
		if err := rows.Scan(&event.name, &event.checksum, &finishedAt, &event.success, &event.dirty); err != nil {
			t.Fatalf("scan migration %03d event: %v", version, err)
		}
		if !finishedAt.Valid {
			t.Fatalf("migration %03d event %d has NULL finished_at", version, len(got)+1)
		}
		got = append(got, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migration %03d events: %v", version, err)
	}
	if len(got) != wantCount || wantCount != len(want) || !reflect.DeepEqual(got, want) {
		t.Fatalf("migration %03d events = %#v (count %d), want %#v (count %d)", version, got, len(got), want, wantCount)
	}
}

func f119F122SeedLegacyAPIKeys(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	execOK(t, ctx, db, `
		INSERT INTO api_keys(id, name, key_hash, created_at, revoked_at, last_used_at)
		VALUES
			(41, 'legacy-active', 'hash-legacy-active', '2026-01-02T03:04:05.123Z', NULL, NULL),
			(42, 'legacy-revoked', 'hash-legacy-revoked', '2026-02-03T04:05:06.234Z', '2026-02-04T04:05:06.234Z', '2026-02-05T04:05:06.234Z'),
			(43, 'legacy-used', 'hash-legacy-used', '2026-03-04T05:06:07.345Z', NULL, '2026-03-05T05:06:07.345Z')`)
}

func f119F122ReadAPIKeySnapshots(t *testing.T, ctx context.Context, db *sql.DB) []f119F122APIKeySnapshot {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT id, name, key_hash, created_at, revoked_at, last_used_at FROM api_keys ORDER BY id`)
	if err != nil {
		t.Fatalf("read API key snapshots: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	var snapshots []f119F122APIKeySnapshot
	for rows.Next() {
		var row f119F122APIKeySnapshot
		if err := rows.Scan(&row.id, &row.name, &row.keyHash, &row.createdAt, &row.revokedAt, &row.lastUsedAt); err != nil {
			t.Fatalf("scan API key snapshot: %v", err)
		}
		row.createdAt = row.createdAt.UTC()
		if row.revokedAt.Valid {
			row.revokedAt.Time = row.revokedAt.Time.UTC()
		}
		if row.lastUsedAt.Valid {
			row.lastUsedAt.Time = row.lastUsedAt.Time.UTC()
		}
		snapshots = append(snapshots, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate API key snapshots: %v", err)
	}
	return snapshots
}

func f119F122AssertAPIKeyObjects(t *testing.T, ctx context.Context, db *sql.DB, wantPresent bool) {
	t.Helper()
	var dataType, nullable string
	var columnDefault sql.NullString
	err := db.QueryRowContext(ctx, `
		SELECT data_type, is_nullable, column_default
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'api_keys' AND column_name = 'expires_at'`).Scan(&dataType, &nullable, &columnDefault)
	if !wantPresent {
		if err != sql.ErrNoRows {
			t.Fatalf("expires_at catalog error = %v, want no row", err)
		}
		var indexExists bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.idx_api_keys_expires_at') IS NOT NULL`).Scan(&indexExists); err != nil {
			t.Fatalf("inspect removed expiration index: %v", err)
		}
		if indexExists {
			t.Fatal("idx_api_keys_expires_at exists, want absent")
		}
		return
	}
	if err != nil {
		t.Fatalf("inspect expires_at column: %v", err)
	}
	if dataType != "timestamp with time zone" || nullable != "YES" || columnDefault.Valid {
		t.Fatalf("expires_at catalog = type:%q nullable:%q default:%q, want timestamptz nullable without default", dataType, nullable, columnDefault.String)
	}

	var table, keys, predicate string
	var unique, valid, ready bool
	if err := db.QueryRowContext(ctx, `
		SELECT tbl.relname, idx.indisunique,
			(SELECT string_agg(pg_get_indexdef(idx.indexrelid, key_no, true), '|' ORDER BY key_no)
			 FROM generate_series(1, idx.indnkeyatts) key_no),
			COALESCE(pg_get_expr(idx.indpred, idx.indrelid), ''), idx.indisvalid, idx.indisready
		FROM pg_index idx
		JOIN pg_class index_class ON index_class.oid = idx.indexrelid
		JOIN pg_class tbl ON tbl.oid = idx.indrelid
		WHERE index_class.oid = to_regclass('public.idx_api_keys_expires_at')`).Scan(&table, &unique, &keys, &predicate, &valid, &ready); err != nil {
		t.Fatalf("inspect idx_api_keys_expires_at: %v", err)
	}
	if table != "api_keys" || unique || keys != "expires_at" || normalizeCatalogPredicate(predicate) != "expires_atisnotnull" || !valid || !ready {
		t.Fatalf("idx_api_keys_expires_at = table:%q unique:%v keys:%q predicate:%q valid:%v ready:%v", table, unique, keys, predicate, valid, ready)
	}
}

func f119F122ReadExpirations(t *testing.T, ctx context.Context, db *sql.DB) map[int]sql.NullTime {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT id, expires_at FROM api_keys ORDER BY id`)
	if err != nil {
		t.Fatalf("read API key expirations: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	result := make(map[int]sql.NullTime)
	for rows.Next() {
		var id int
		var expiresAt sql.NullTime
		if err := rows.Scan(&id, &expiresAt); err != nil {
			t.Fatalf("scan API key expiration: %v", err)
		}
		if expiresAt.Valid {
			expiresAt.Time = expiresAt.Time.UTC()
		}
		result[id] = expiresAt
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate API key expirations: %v", err)
	}
	return result
}

func f119F122AssertAllExpirationsNull(t *testing.T, ctx context.Context, db *sql.DB, ids []int) {
	t.Helper()
	got := f119F122ReadExpirations(t, ctx, db)
	if len(got) != len(ids) {
		t.Fatalf("API key expiration row count = %d, want %d: %#v", len(got), len(ids), got)
	}
	for _, id := range ids {
		expiresAt, ok := got[id]
		if !ok || expiresAt.Valid {
			t.Fatalf("API key %d expiration = %#v present:%v, want NULL", id, expiresAt, ok)
		}
	}
}

func f119F122AssertAPIKeyEligibility(t *testing.T, ctx context.Context, db *sql.DB, want map[int]bool) {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		SELECT id, revoked_at IS NULL AND (expires_at IS NULL OR expires_at > '2026-06-01T00:00:00Z'::timestamptz)
		FROM api_keys ORDER BY id`)
	if err != nil {
		t.Fatalf("read API key eligibility: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	got := make(map[int]bool)
	for rows.Next() {
		var id int
		var eligible bool
		if err := rows.Scan(&id, &eligible); err != nil {
			t.Fatalf("scan API key eligibility: %v", err)
		}
		got[id] = eligible
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate API key eligibility: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("API key eligibility = %v, want %v", got, want)
	}
}
