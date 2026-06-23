// Package migrations embeds SQL migration files and provides a helper to run
// them against a PostgreSQL database.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	iofs "io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // register "pgx" driver
)

//go:embed *.sql
var fs embed.FS

// ExpectedVersion is the schema version that this binary expects.
// It must match the highest migration number embedded in the binary.
const ExpectedVersion = 26

const migrationAdvisoryLockKey int64 = 0x7061636b6d6f6e // ASCII "packmon"

type migrationFile struct {
	version int
	name    string
	sql     string
}

type migrationConn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

// Run applies all pending migrations to the database at the given DSN.
// The DSN must be a valid PostgreSQL connection string
// (e.g. "postgres://user:pass@host:5432/dbname?sslmode=prefer").
//
// Run is safe to call as an explicit migration step: if the database is
// already at the latest version, it returns nil without changes.
func Run(dsn string) (err error) {
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("migrations: open db: %w", err)
	}
	defer closeSilently(db)

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrations: connect db: %w", err)
	}
	defer closeSilently(conn)

	if err := acquireMigrationLock(ctx, conn); err != nil {
		return err
	}
	defer func() {
		if unlockErr := releaseMigrationLock(ctx, conn); unlockErr != nil && err == nil {
			err = unlockErr
		}
	}()

	if err := ensureVersionTable(ctx, conn); err != nil {
		return err
	}

	current, dirty, hasVersion, err := currentVersion(ctx, conn)
	if err != nil {
		return err
	}
	if dirty {
		return fmt.Errorf("migrations: database is dirty at version %d", current)
	}
	if hasVersion && current > ExpectedVersion {
		return fmt.Errorf("migrations: database schema version %d is newer than binary expected version %d", current, ExpectedVersion)
	}

	migrations, err := embeddedUpMigrations()
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		if hasVersion && migration.version <= current {
			continue
		}
		if err := applyMigration(ctx, conn, migration); err != nil {
			return err
		}
	}

	return nil
}

// Version returns the current schema version of the database, or an
// error if the version cannot be determined. If dirty is true, the
// database is in a partially-applied migration state and should not
// be used.
func Version(dsn string) (version uint, dirty bool, err error) {
	return VersionContext(context.Background(), dsn)
}

// VersionContext is Version with caller-controlled cancellation.
func VersionContext(ctx context.Context, dsn string) (version uint, dirty bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return 0, false, fmt.Errorf("migrations: open db: %w", err)
	}
	defer closeSilently(db)

	hasTable, err := versionTableExists(ctx, db)
	if err != nil {
		return 0, false, err
	}
	if !hasTable {
		return 0, false, fmt.Errorf("migrations: no schema version found (database has not been migrated)")
	}
	current, dirty, hasVersion, err := currentVersion(ctx, db)
	if err != nil {
		return 0, false, err
	}
	if !hasVersion {
		return 0, false, fmt.Errorf("migrations: no schema version found (database has not been migrated)")
	}
	if current < 0 {
		return 0, dirty, fmt.Errorf("migrations: invalid negative schema version %d", current)
	}

	return uint(current), dirty, nil
}

func ensureVersionTable(ctx context.Context, db migrationConn) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version bigint not null primary key,
			dirty boolean not null
		)`)
	if err != nil {
		return fmt.Errorf("migrations: ensure version table: %w", err)
	}
	return nil
}

func acquireMigrationLock(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLockKey); err != nil {
		return fmt.Errorf("migrations: acquire advisory lock: %w", err)
	}
	return nil
}

func releaseMigrationLock(ctx context.Context, conn *sql.Conn) error {
	var unlocked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLockKey).Scan(&unlocked); err != nil {
		return fmt.Errorf("migrations: release advisory lock: %w", err)
	}
	if !unlocked {
		return fmt.Errorf("migrations: release advisory lock: lock was not held")
	}
	return nil
}

func versionTableExists(ctx context.Context, db *sql.DB) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("migrations: check version table: %w", err)
	}
	return exists, nil
}

func currentVersion(ctx context.Context, db migrationConn) (version int, dirty, ok bool, err error) {
	err = db.QueryRowContext(ctx, `
		SELECT version, dirty
		FROM schema_migrations
		ORDER BY version DESC
		LIMIT 1`).Scan(&version, &dirty)
	if err == sql.ErrNoRows {
		return 0, false, false, nil
	}
	if err != nil {
		return 0, false, false, fmt.Errorf("migrations: read version: %w", err)
	}
	return version, dirty, true, nil
}

func embeddedUpMigrations() ([]migrationFile, error) {
	entries, err := iofs.ReadDir(fs, ".")
	if err != nil {
		return nil, fmt.Errorf("migrations: read embedded migrations: %w", err)
	}

	migrations := make([]migrationFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		version, err := parseMigrationVersion(name)
		if err != nil {
			return nil, err
		}
		data, err := fs.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("migrations: read %s: %w", name, err)
		}
		migrations = append(migrations, migrationFile{
			version: version,
			name:    name,
			sql:     string(data),
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})
	return migrations, nil
}

func parseMigrationVersion(name string) (int, error) {
	base := filepath.Base(name)
	if len(base) < 3 {
		return 0, fmt.Errorf("migrations: migration filename %q is too short", base)
	}
	version, err := strconv.Atoi(base[:3])
	if err != nil {
		return 0, fmt.Errorf("migrations: migration filename %q does not start with a numeric version: %w", base, err)
	}
	return version, nil
}

func applyMigration(ctx context.Context, db migrationConn, migration migrationFile) error {
	if err := markDirty(ctx, db, migration.version, migration.name); err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrations: begin %s: %w", migration.name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, migration.sql); err != nil {
		return fmt.Errorf("migrations: apply %s: %w", migration.name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrations: commit %s: %w", migration.name, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE schema_migrations SET dirty = false WHERE version = $1`, migration.version); err != nil {
		return fmt.Errorf("migrations: mark %s clean: %w", migration.name, err)
	}
	return nil
}

func markDirty(ctx context.Context, db migrationConn, version int, name string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrations: mark %s dirty: %w", name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM schema_migrations`); err != nil {
		return fmt.Errorf("migrations: mark %s dirty: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, dirty) VALUES($1, true)`, version); err != nil {
		return fmt.Errorf("migrations: mark %s dirty: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrations: mark %s dirty: %w", name, err)
	}
	return nil
}
