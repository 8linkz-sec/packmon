// Package migrations embeds SQL migration files and provides
// a helper to run them against a PostgreSQL database using golang-migrate.
package migrations

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib" // register "pgx" driver
)

//go:embed *.sql
var fs embed.FS

// ExpectedVersion is the schema version that this binary expects.
// It must match the highest migration number embedded in the binary.
const ExpectedVersion = 1

// Run applies all pending migrations to the database at the given DSN.
// The DSN must be a valid PostgreSQL connection string
// (e.g. "postgres://user:pass@host:5432/dbname?sslmode=prefer").
//
// Run is safe to call on every application start: if the database is
// already at the latest version, it returns nil without changes.
func Run(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("migrations: open db: %w", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("migrations: create driver: %w", err)
	}

	source, err := iofs.New(fs, ".")
	if err != nil {
		return fmt.Errorf("migrations: create source: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return fmt.Errorf("migrations: init migrate: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrations: apply: %w", err)
	}

	return nil
}

// Version returns the current schema version of the database, or an
// error if the version cannot be determined. If dirty is true, the
// database is in a partially-applied migration state and should not
// be used.
func Version(dsn string) (version uint, dirty bool, err error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return 0, false, fmt.Errorf("migrations: open db: %w", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return 0, false, fmt.Errorf("migrations: create driver: %w", err)
	}

	source, err := iofs.New(fs, ".")
	if err != nil {
		return 0, false, fmt.Errorf("migrations: create source: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return 0, false, fmt.Errorf("migrations: init migrate: %w", err)
	}

	ver, dirty, err := m.Version()
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			return 0, false, fmt.Errorf("migrations: no schema version found (database has not been migrated)")
		}
		return 0, false, fmt.Errorf("migrations: version: %w", err)
	}

	return ver, dirty, nil
}
