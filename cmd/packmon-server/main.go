package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	pgstore "github.com/8linkz/packmon/internal/db/postgres"
	migrations "github.com/8linkz/packmon/internal/db/postgres/migrations"
	"github.com/8linkz/packmon/internal/health"
	"github.com/8linkz/packmon/internal/server"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("packmon-server %s (%s) built %s %s/%s\n",
				version, commit, date, runtime.GOOS, runtime.GOARCH)
			return
		case "migrate":
			if err := runMigrate(); err != nil {
				fmt.Fprintf(os.Stderr, "packmon-server migrate: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "packmon-server: %v\n", err)
		os.Exit(1)
	}
}

// runMigrate loads config, runs all pending migrations, and exits.
func runMigrate() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := newLogger(cfg.Log)
	dsn := cfg.DB.DSN()

	logger.Info("running database migrations",
		slog.Int("expected_version", int(migrations.ExpectedVersion)),
	)

	if err := migrations.Run(dsn); err != nil {
		return fmt.Errorf("migrations failed: %w", err)
	}

	ver, dirty, err := migrations.Version(dsn)
	if err != nil {
		return fmt.Errorf("failed to read schema version after migration: %w", err)
	}

	if dirty {
		return fmt.Errorf("schema is in dirty state after migration (version %d)", ver)
	}

	logger.Info("migrations completed successfully",
		slog.Int("schema_version", int(ver)),
	)

	return nil
}

func run() error {
	// Load configuration from environment.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Set up structured logger.
	logger := newLogger(cfg.Log)

	devMode := cfg.IsDevelopment()
	ver := uint(migrations.ExpectedVersion)
	if !devMode {
		// Verify database schema version before starting the server.
		// Migrations must be run separately via "packmon-server migrate" (DE-27).
		dsn := cfg.DB.DSN()
		ver, dirty, err := migrations.Version(dsn)
		if err != nil {
			logger.Error("failed to read database schema version -- run 'packmon-server migrate' first",
				slog.String("error", err.Error()),
			)
			return fmt.Errorf("schema version check failed: %w", err)
		}
		if dirty {
			logger.Error("database schema is in dirty state -- manual intervention required",
				slog.Int("schema_version", int(ver)),
			)
			return fmt.Errorf("database schema is dirty at version %d", ver)
		}
		if ver != uint(migrations.ExpectedVersion) {
			logger.Error("database schema version mismatch -- run 'packmon-server migrate'",
				slog.Int("current_version", int(ver)),
				slog.Int("expected_version", int(migrations.ExpectedVersion)),
			)
			return fmt.Errorf("schema version mismatch: database is at %d, binary expects %d", ver, migrations.ExpectedVersion)
		}
	}

	logger.Info("packmon-server starting",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("mode", string(cfg.Server.Mode)),
		slog.Int("schema_version", int(ver)),
	)

	var (
		store  db.Store
		pinger health.Pinger
	)

	if devMode {
		store = newNoopStore()
		pinger = &noopPinger{}
	} else {
		pg, err := pgstore.New(context.Background(), cfg.DB.DSN())
		if err != nil {
			return fmt.Errorf("open postgres store: %w", err)
		}
		store = pg
		pinger = pg
	}
	defer store.Close()

	if err := auth.BootstrapAdmin(context.Background(), store, cfg.Admin.InitialPassword, logger); err != nil {
		return fmt.Errorf("bootstrap admin auth: %w", err)
	}

	build := server.BuildInfo{
		Version:       version,
		Commit:        commit,
		Date:          date,
		SchemaVersion: ver,
	}

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	background := startBackgroundServices(rootCtx, cfg, store, logger)

	srv := server.New(cfg, store, pinger, logger, build)
	err = srv.Run(rootCtx)
	cancel()
	background.Wait()
	return err
}

// newLogger creates an slog.Logger based on the log configuration.
func newLogger(lc config.LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(lc.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if strings.ToLower(lc.Format) == "console" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
