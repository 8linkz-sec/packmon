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
const ExpectedVersion = 9

type migrationFile struct {
	version int
	name    string
	sql     string
}

// Run applies all pending migrations to the database at the given DSN.
// The DSN must be a valid PostgreSQL connection string
// (e.g. "postgres://user:pass@host:5432/dbname?sslmode=prefer").
//
// Run is safe to call on every application start: if the database is
// already at the latest version, it returns nil without changes.
func Run(dsn string) error {
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("migrations: open db: %w", err)
	}
	defer closeSilently(db)

	if err := ensureVersionTable(ctx, db); err != nil {
		return err
	}

	current, dirty, hasVersion, err := currentVersion(ctx, db)
	if err != nil {
		return err
	}
	if dirty {
		return fmt.Errorf("migrations: database is dirty at version %d", current)
	}

	migrations, err := embeddedUpMigrations()
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		if hasVersion && migration.version <= current {
			continue
		}
		if err := applyMigration(ctx, db, migration); err != nil {
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
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return 0, false, fmt.Errorf("migrations: open db: %w", err)
	}
	defer closeSilently(db)

	if err := ensureVersionTable(ctx, db); err != nil {
		return 0, false, err
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

func ensureVersionTable(ctx context.Context, db *sql.DB) error {
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

func currentVersion(ctx context.Context, db *sql.DB) (version int, dirty, ok bool, err error) {
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

func applyMigration(ctx context.Context, db *sql.DB, migration migrationFile) error {
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

func markDirty(ctx context.Context, db *sql.DB, version int, name string) error {
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
