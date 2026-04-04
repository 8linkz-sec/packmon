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
