//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

func TestF203MigratorMetadataAndLifecycleAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	ctx := context.Background()

	migrations, err := embeddedUpMigrations()
	if err != nil {
		t.Fatalf("embeddedUpMigrations() error = %v", err)
	}
	if len(migrations) < 10 {
		t.Fatalf("embedded migration count = %d, want at least 10", len(migrations))
	}

	t.Run("advisory lock lifecycle reports cancellation and missing ownership", func(t *testing.T) {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("db.Conn() error = %v", err)
		}
		defer ioutils.CloseSilently(conn)

		if err := acquireMigrationLock(ctx, conn); err != nil {
			t.Fatalf("acquireMigrationLock() error = %v", err)
		}
		if err := releaseMigrationLock(ctx, conn); err != nil {
			t.Fatalf("releaseMigrationLock() error = %v", err)
		}
		if err := releaseMigrationLock(ctx, conn); err == nil || !strings.Contains(err.Error(), "lock was not held") {
			t.Fatalf("releaseMigrationLock(without ownership) error = %v, want lock-not-held error", err)
		}

		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := acquireMigrationLock(canceled, conn); err == nil || !strings.Contains(err.Error(), "acquire advisory lock") {
			t.Fatalf("acquireMigrationLock(canceled) error = %v, want wrapped cancellation", err)
		}
	})

	t.Run("legacy version table is extended idempotently", func(t *testing.T) {
		f203DropMigratorTables(t, ctx, db)
		if _, err := db.ExecContext(ctx, `
			CREATE TABLE schema_migrations (
				version bigint not null primary key,
				dirty boolean not null
			)`); err != nil {
			t.Fatalf("create legacy schema_migrations: %v", err)
		}
		if err := ensureVersionTable(ctx, db); err != nil {
			t.Fatalf("ensureVersionTable() first call error = %v", err)
		}
		if err := ensureVersionTable(ctx, db); err != nil {
			t.Fatalf("ensureVersionTable() second call error = %v", err)
		}

		var columns, indexes int
		if err := db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM information_schema.columns
			WHERE table_schema = 'public'
				AND table_name = 'schema_migrations'
				AND column_name IN ('name', 'checksum', 'applied_at')`).Scan(&columns); err != nil {
			t.Fatalf("query extended columns: %v", err)
		}
		if columns != 3 {
			t.Fatalf("extended metadata columns = %d, want 3", columns)
		}
		if err := db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM pg_indexes
			WHERE schemaname = 'public'
				AND tablename = 'schema_migration_events'
				AND indexname IN (
					'idx_schema_migration_events_version',
					'idx_schema_migration_events_started_at'
				)`).Scan(&indexes); err != nil {
			t.Fatalf("query event indexes: %v", err)
		}
		if indexes != 2 {
			t.Fatalf("event indexes = %d, want 2", indexes)
		}

		if _, _, err := VersionContext(ctx, dsn); err == nil || !strings.Contains(err.Error(), "no schema version found") {
			t.Fatalf("VersionContext(empty table) error = %v, want no-version error", err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations(version, dirty) VALUES(7, true)`); err != nil {
			t.Fatalf("insert dirty version: %v", err)
		}
		version, dirty, err := VersionContext(ctx, dsn)
		if err != nil {
			t.Fatalf("VersionContext(dirty) error = %v", err)
		}
		if version != 7 || !dirty {
			t.Fatalf("VersionContext(dirty) = %d, %v; want 7, true", version, dirty)
		}
	})

	t.Run("metadata backfill completes only missing fields", func(t *testing.T) {
		f203ResetMigratorTables(t, ctx, db)
		fixedAppliedAt := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
		if _, err := db.ExecContext(ctx, `
			INSERT INTO schema_migrations(version, name, checksum, applied_at, dirty)
			VALUES
				($1, $2, NULL, NULL, false),
				($3, NULL, $4, $5, false)`,
			migrations[0].version, migrations[0].name,
			migrations[1].version, migrationChecksum(migrations[1].sql), fixedAppliedAt); err != nil {
			t.Fatalf("insert partial migration metadata: %v", err)
		}
		if err := backfillAppliedMigrationMetadata(ctx, db, migrations[:2], 2); err != nil {
			t.Fatalf("backfillAppliedMigrationMetadata() error = %v", err)
		}
		if err := validateAppliedMigrationMetadata(ctx, db, migrations[:2], 2); err != nil {
			t.Fatalf("validateAppliedMigrationMetadata() error = %v", err)
		}

		var name, checksum string
		var appliedAt time.Time
		if err := db.QueryRowContext(ctx, `
			SELECT name, checksum, applied_at
			FROM schema_migrations
			WHERE version = $1`, migrations[1].version).Scan(&name, &checksum, &appliedAt); err != nil {
			t.Fatalf("query backfilled metadata: %v", err)
		}
		if name != migrations[1].name || checksum != migrationChecksum(migrations[1].sql) || !appliedAt.Equal(fixedAppliedAt) {
			t.Fatalf("backfilled metadata = name %q checksum %q applied_at %s; want existing checksum/time and name %q", name, checksum, appliedAt, migrations[1].name)
		}
	})

	t.Run("metadata validation rejects every corrupt field", func(t *testing.T) {
		migration := migrations[0]
		tests := []struct {
			name     string
			rowName  any
			checksum any
			dirty    bool
			insert   bool
			want     string
		}{
			{name: "missing row", insert: false, want: "missing metadata"},
			{name: "dirty row", rowName: migration.name, checksum: migrationChecksum(migration.sql), dirty: true, insert: true, want: "database is dirty"},
			{name: "null name", rowName: nil, checksum: migrationChecksum(migration.sql), insert: true, want: "missing name"},
			{name: "blank name", rowName: "  ", checksum: migrationChecksum(migration.sql), insert: true, want: "missing name"},
			{name: "wrong name", rowName: "001_other.up.sql", checksum: migrationChecksum(migration.sql), insert: true, want: "name mismatch"},
			{name: "null checksum", rowName: migration.name, checksum: nil, insert: true, want: "missing checksum"},
			{name: "blank checksum", rowName: migration.name, checksum: "  ", insert: true, want: "missing checksum"},
			{name: "wrong checksum", rowName: migration.name, checksum: strings.Repeat("0", 64), insert: true, want: "checksum mismatch"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f203ResetMigratorTables(t, ctx, db)
				if tt.insert {
					if _, err := db.ExecContext(ctx, `
						INSERT INTO schema_migrations(version, name, checksum, applied_at, dirty)
						VALUES($1, $2, $3, now(), $4)`, migration.version, tt.rowName, tt.checksum, tt.dirty); err != nil {
						t.Fatalf("insert corrupt metadata: %v", err)
					}
				}
				err := validateAppliedMigrationMetadata(ctx, db, []migrationFile{migration}, migration.version)
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("validateAppliedMigrationMetadata() error = %v, want %q", err, tt.want)
				}
			})
		}
	})

	t.Run("historical checksum remains accepted", func(t *testing.T) {
		f203ResetMigratorTables(t, ctx, db)
		migration := migrations[9]
		historical := "db8f58df8d5022eb21bad847c61bcaf7453c4f96ba1cafe12d719498b0974f30"
		if migration.name != "010_affected_packages_updated_at.up.sql" {
			t.Fatalf("migration 10 name = %q", migration.name)
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO schema_migrations(version, name, checksum, applied_at, dirty)
			VALUES($1, $2, $3, now(), false)`, migration.version, migration.name, historical); err != nil {
			t.Fatalf("insert historical metadata: %v", err)
		}
		if err := validateAppliedMigrationMetadata(ctx, db, []migrationFile{migration}, migration.version); err != nil {
			t.Fatalf("validate historical checksum: %v", err)
		}
	})

	t.Run("metadata storage failures are reported and rolled back", func(t *testing.T) {
		f203ResetMigratorTables(t, ctx, db)
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := backfillAppliedMigrationMetadata(canceled, db, migrations[:1], 1); err == nil || !strings.Contains(err.Error(), "backfill migration metadata") {
			t.Fatalf("backfillAppliedMigrationMetadata(canceled) error = %v, want wrapped begin failure", err)
		}

		if _, err := db.ExecContext(ctx, `DROP TABLE schema_migrations`); err != nil {
			t.Fatalf("drop schema_migrations: %v", err)
		}
		if err := backfillAppliedMigrationMetadata(ctx, db, migrations[:1], 1); err == nil || !strings.Contains(err.Error(), "backfill metadata for") {
			t.Fatalf("backfillAppliedMigrationMetadata(missing table) error = %v, want named write failure", err)
		}
		if err := validateAppliedMigrationMetadata(ctx, db, migrations[:1], 1); err == nil || !strings.Contains(err.Error(), "read metadata for") {
			t.Fatalf("validateAppliedMigrationMetadata(missing table) error = %v, want named read failure", err)
		}
		if _, _, _, err := currentVersion(ctx, db); err == nil || !strings.Contains(err.Error(), "read version") {
			t.Fatalf("currentVersion(missing table) error = %v, want read-version failure", err)
		}
	})

	t.Run("successful lifecycle records clean metadata and event", func(t *testing.T) {
		f203ResetMigratorTables(t, ctx, db)
		migration := migrationFile{version: 901, name: "901_lifecycle.up.sql", sql: "CREATE TABLE f203_lifecycle(id integer)"}
		eventID, err := startMigrationEventAndMarkDirty(ctx, db, migration)
		if err != nil {
			t.Fatalf("startMigrationEventAndMarkDirty() error = %v", err)
		}
		if err := finishSuccessfulMigrationEvent(ctx, db, eventID, migration); err != nil {
			t.Fatalf("finishSuccessfulMigrationEvent() error = %v", err)
		}
		var rowDirty, eventSuccess, eventDirty bool
		var applied, finished bool
		if err := db.QueryRowContext(ctx, `
			SELECT migration.dirty,
				migration.applied_at IS NOT NULL,
				event.success,
				event.dirty,
				event.finished_at IS NOT NULL
			FROM schema_migrations migration
			JOIN schema_migration_events event ON event.id = $1
			WHERE migration.version = $2`, eventID, migration.version).Scan(&rowDirty, &applied, &eventSuccess, &eventDirty, &finished); err != nil {
			t.Fatalf("query completed lifecycle: %v", err)
		}
		if rowDirty || !applied || !eventSuccess || eventDirty || !finished {
			t.Fatalf("completed lifecycle = rowDirty %v applied %v eventSuccess %v eventDirty %v finished %v", rowDirty, applied, eventSuccess, eventDirty, finished)
		}
	})

	t.Run("start lifecycle failures are atomic", func(t *testing.T) {
		migration := migrationFile{version: 902, name: "902_start.up.sql", sql: "SELECT 1"}

		f203ResetMigratorTables(t, ctx, db)
		if _, err := db.ExecContext(ctx, `DROP TABLE schema_migration_events`); err != nil {
			t.Fatalf("drop schema_migration_events: %v", err)
		}
		if _, err := startMigrationEventAndMarkDirty(ctx, db, migration); err == nil || !strings.Contains(err.Error(), "record start event") {
			t.Fatalf("startMigrationEventAndMarkDirty(missing events table) error = %v, want event error", err)
		}
		var versionRows int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = $1`, migration.version).Scan(&versionRows); err != nil {
			t.Fatalf("query version rows after event failure: %v", err)
		}
		if versionRows != 0 {
			t.Fatalf("version rows after event failure = %d, want 0", versionRows)
		}

		f203ResetMigratorTables(t, ctx, db)
		if _, err := db.ExecContext(ctx, `DROP TABLE schema_migrations`); err != nil {
			t.Fatalf("drop schema_migrations: %v", err)
		}
		if _, err := startMigrationEventAndMarkDirty(ctx, db, migration); err == nil || !strings.Contains(err.Error(), "mark 902_start.up.sql dirty") {
			t.Fatalf("startMigrationEventAndMarkDirty(missing version table) error = %v, want dirty error", err)
		}
		var eventRows int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migration_events WHERE version = $1`, migration.version).Scan(&eventRows); err != nil {
			t.Fatalf("query event rows after dirty failure: %v", err)
		}
		if eventRows != 0 {
			t.Fatalf("event rows after dirty failure = %d, want transaction rollback", eventRows)
		}
	})

	t.Run("finish lifecycle failures are atomic", func(t *testing.T) {
		migration := migrationFile{version: 903, name: "903_finish.up.sql", sql: "SELECT 1"}

		f203ResetMigratorTables(t, ctx, db)
		eventID, err := startMigrationEventAndMarkDirty(ctx, db, migration)
		if err != nil {
			t.Fatalf("start lifecycle for missing-version-table case: %v", err)
		}
		if _, err := db.ExecContext(ctx, `DROP TABLE schema_migrations`); err != nil {
			t.Fatalf("drop schema_migrations: %v", err)
		}
		if err := finishSuccessfulMigrationEvent(ctx, db, eventID, migration); err == nil || !strings.Contains(err.Error(), "mark 903_finish.up.sql clean") {
			t.Fatalf("finishSuccessfulMigrationEvent(missing version table) error = %v, want mark-clean error", err)
		}
		f203AssertEventStillDirty(t, ctx, db, eventID)

		f203ResetMigratorTables(t, ctx, db)
		eventID, err = startMigrationEventAndMarkDirty(ctx, db, migration)
		if err != nil {
			t.Fatalf("start lifecycle for missing-event-table case: %v", err)
		}
		if _, err := db.ExecContext(ctx, `DROP TABLE schema_migration_events`); err != nil {
			t.Fatalf("drop schema_migration_events: %v", err)
		}
		if err := finishSuccessfulMigrationEvent(ctx, db, eventID, migration); err == nil || !strings.Contains(err.Error(), "record finish event") {
			t.Fatalf("finishSuccessfulMigrationEvent(missing event table) error = %v, want finish-event error", err)
		}
		var dirty bool
		var appliedAt sql.NullTime
		if err := db.QueryRowContext(ctx, `SELECT dirty, applied_at FROM schema_migrations WHERE version = $1`, migration.version).Scan(&dirty, &appliedAt); err != nil {
			t.Fatalf("query version row after rolled-back finish: %v", err)
		}
		if !dirty || appliedAt.Valid {
			t.Fatalf("version row after rolled-back finish = dirty %v applied_at %v, want dirty with null applied_at", dirty, appliedAt)
		}
		if err := finishMigrationEvent(ctx, db, eventID, false, true); err == nil || !strings.Contains(err.Error(), "record finish event") {
			t.Fatalf("finishMigrationEvent(missing event table) error = %v, want wrapped failure", err)
		}
	})

	t.Run("mark dirty records optional checksum and reports failures", func(t *testing.T) {
		f203ResetMigratorTables(t, ctx, db)
		if err := markDirtyWithChecksum(ctx, db, 904, "904_retry.up.sql", "known-checksum"); err != nil {
			t.Fatalf("markDirtyWithChecksum() error = %v", err)
		}
		var checksum string
		var dirty bool
		if err := db.QueryRowContext(ctx, `SELECT checksum, dirty FROM schema_migrations WHERE version = 904`).Scan(&checksum, &dirty); err != nil {
			t.Fatalf("query marked-dirty row: %v", err)
		}
		if checksum != "known-checksum" || !dirty {
			t.Fatalf("marked-dirty row = checksum %q dirty %v", checksum, dirty)
		}

		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := markDirtyWithChecksum(canceled, db, 905, "905_canceled.up.sql", ""); err == nil || !strings.Contains(err.Error(), "mark 905_canceled.up.sql dirty") {
			t.Fatalf("markDirtyWithChecksum(canceled) error = %v, want wrapped begin failure", err)
		}
		if _, err := db.ExecContext(ctx, `DROP TABLE schema_migrations`); err != nil {
			t.Fatalf("drop schema_migrations: %v", err)
		}
		if err := markDirtyWithChecksum(ctx, db, 906, "906_missing.up.sql", ""); err == nil || !strings.Contains(err.Error(), "mark 906_missing.up.sql dirty") {
			t.Fatalf("markDirtyWithChecksum(missing table) error = %v, want wrapped write failure", err)
		}
	})
}

func f203DropMigratorTables(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `
		DROP TABLE IF EXISTS schema_migration_events;
		DROP TABLE IF EXISTS schema_migrations;`); err != nil {
		t.Fatalf("drop migrator tables: %v", err)
	}
}

func f203ResetMigratorTables(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	f203DropMigratorTables(t, ctx, db)
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
}

func f203AssertEventStillDirty(t *testing.T, ctx context.Context, db *sql.DB, eventID int64) {
	t.Helper()
	var success, dirty, finished bool
	if err := db.QueryRowContext(ctx, `
		SELECT success, dirty, finished_at IS NOT NULL
		FROM schema_migration_events
		WHERE id = $1`, eventID).Scan(&success, &dirty, &finished); err != nil {
		t.Fatalf("query unfinished migration event: %v", err)
	}
	if success || !dirty || finished {
		t.Fatalf("unfinished migration event = success %v dirty %v finished %v", success, dirty, finished)
	}
}
