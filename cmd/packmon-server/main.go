package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/server"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("packmon-server %s (%s) built %s %s/%s\n",
			version, commit, date, runtime.GOOS, runtime.GOARCH)
		return
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "packmon-server: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration from environment.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Set up structured logger.
	logger := newLogger(cfg.Log)

	logger.Info("packmon-server starting",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("mode", string(cfg.Server.Mode)),
	)

	// For now we use a no-op store and pinger since the PostgreSQL
	// implementation is not wired up yet. This lets the server
	// compile, start, and serve health/version endpoints.
	store := &noopStore{}
	pinger := &noopPinger{}

	build := server.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	srv := server.New(cfg, store, pinger, logger, build)
	return srv.Run(context.Background())
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
