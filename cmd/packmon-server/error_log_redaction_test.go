package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
)

// errSecretBearingDatabase mimics a driver error that echoes the connection
// URL, a libpq secret assignment, and a local filesystem path.
var errSecretBearingDatabase = errors.New(`dial postgres://packmon:dsn-secret-pass@db.internal:5432/packmon failed; password=kv-secret-pass while reading /var/lib/postgresql/data/pg_hba.conf`)

var secretBearingFragments = []string{
	"dsn-secret-pass",
	"kv-secret-pass",
	"/var/lib/postgresql/data/pg_hba.conf",
}

// syncBuffer is a log sink that tolerates writes from background goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newCapturingLogger() (*slog.Logger, *syncBuffer) {
	sink := &syncBuffer{}
	return slog.New(slog.NewJSONHandler(sink, nil)), sink
}

func assertLogRedacted(t *testing.T, logs, wantMessage string) {
	t.Helper()

	if !strings.Contains(logs, wantMessage) {
		t.Fatalf("log = %s, want message %q", logs, wantMessage)
	}
	for _, leaked := range secretBearingFragments {
		if strings.Contains(logs, leaked) {
			t.Fatalf("log leaked %q: %s", leaked, logs)
		}
	}
}

type secretErrorFeedStatusStore struct {
	*noopStore
	failRead bool
}

func (s *secretErrorFeedStatusStore) GetFeedSyncStatus(ctx context.Context, feedName string) (*db.FeedSyncStatus, error) {
	if s.failRead {
		return nil, errSecretBearingDatabase
	}
	return s.noopStore.GetFeedSyncStatus(ctx, feedName)
}

func (s *secretErrorFeedStatusStore) UpsertFeedSyncStatus(context.Context, *db.FeedSyncStatus) error {
	return errSecretBearingDatabase
}

type secretFeedModeStore struct {
	*noopStore
}

func (s *secretFeedModeStore) ListFeedConfigs(context.Context) ([]db.FeedConfig, error) {
	return []db.FeedConfig{{FeedName: "osv", Enabled: true, Mode: "self password=kv-secret-pass /var/lib/postgresql/data/pg_hba.conf"}}, nil
}

// TestServerErrorLogsRedactDatabaseDiagnostics routes every background and
// startup error log through the shared redact-and-bound helper, the same bug
// class as the schema-check log: database errors can echo the DSN password,
// secret assignments, or local paths.
func TestServerErrorLogsRedactDatabaseDiagnostics(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		message string
		run     func(t *testing.T, logger *slog.Logger)
	}{
		{
			name:    "startup package-name repair",
			message: "startup repair: failed to normalize package names",
			run: func(_ *testing.T, logger *slog.Logger) {
				runPackageNameStartupRepair(context.Background(), time.Second, logger, func(context.Context) (int, error) {
					return 0, errSecretBearingDatabase
				})
			},
		},
		{
			name:    "background startup task",
			message: "background startup task failed",
			run: func(_ *testing.T, logger *slog.Logger) {
				b := &backgroundServices{logger: logger, rootCtx: context.Background()}
				b.startBackgroundTask("repair", func(context.Context) error { return errSecretBearingDatabase })
				b.backgroundTasks.Wait()
			},
		},
		{
			name:    "queue worker status read",
			message: "failed to load current queue worker feed status",
			run: func(_ *testing.T, logger *slog.Logger) {
				store := &secretErrorFeedStatusStore{noopStore: newNoopStore(), failRead: true}
				_ = recordQueueWorkerSkipped(context.Background(), store, logger, "socket", "Socket.dev API key not configured")
			},
		},
		{
			name:    "queue worker status write",
			message: "failed to record queue worker skipped status",
			run: func(_ *testing.T, logger *slog.Logger) {
				store := &secretErrorFeedStatusStore{noopStore: newNoopStore()}
				_ = recordQueueWorkerSkipped(context.Background(), store, logger, "socket", "Socket.dev API key not configured")
			},
		},
		{
			name:    "audit retention prune",
			message: "audit retention prune failed",
			run: func(_ *testing.T, logger *slog.Logger) {
				logAuditRetentionResult(logger, "scan_log", time.Hour, 0, errSecretBearingDatabase)
			},
		},
		{
			name:    "queue processor restart wait",
			message: "queue processor stopped with error",
			run: func(_ *testing.T, logger *slog.Logger) {
				done := make(chan error, 1)
				done <- errSecretBearingDatabase
				b := &backgroundServices{logger: logger, shutdownWait: time.Second}
				b.waitForQueueProcessor(done, "restart")
			},
		},
		{
			name:    "queue processor shutdown wait",
			message: "queue processor stopped with error",
			run: func(_ *testing.T, logger *slog.Logger) {
				done := make(chan error, 1)
				done <- errSecretBearingDatabase
				b := &backgroundServices{logger: logger, queueDones: []chan error{done}}
				b.stopAndWaitQueueProcessors(time.Now())
			},
		},
		{
			name:    "audit retention worker shutdown wait",
			message: "audit retention worker stopped with error",
			run: func(_ *testing.T, logger *slog.Logger) {
				done := make(chan error, 1)
				done <- errSecretBearingDatabase
				b := &backgroundServices{logger: logger, retentionDone: done}
				b.waitRetentionWorker(time.Now())
			},
		},
		{
			name:    "persisted feed mode",
			message: "ignoring invalid persisted feed mode",
			run: func(t *testing.T, logger *slog.Logger) {
				cfg := &config.Config{Server: config.ServerConfig{Mode: config.ModeDevelopment}}
				if err := applyStoredFeedConfigOverrides(context.Background(), cfg, &secretFeedModeStore{noopStore: newNoopStore()}, logger); err != nil {
					t.Fatalf("applyStoredFeedConfigOverrides() error = %v", err)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger, sink := newCapturingLogger()
			tt.run(t, logger)
			assertLogRedacted(t, sink.String(), tt.message)
		})
	}
}

// TestDeferredQueueRestartRedactsOldGenerationError covers the continuation
// that logs the delayed old generation's exit error.
func TestDeferredQueueRestartRedactsOldGenerationError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rootCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, oldCancel := context.WithCancel(context.Background())
		defer oldCancel()
		oldDone := make(chan error, 1)
		services := newDelayedQueueRestartServices(rootCtx, oldCancel, oldDone)
		logger, sink := newCapturingLogger()
		services.logger = logger

		if err := services.restartQueueProcessor(); err != nil {
			t.Fatalf("restartQueueProcessor() error = %v", err)
		}
		oldDone <- errSecretBearingDatabase
		synctest.Wait()
		cancel()
		services.Wait()

		assertLogRedacted(t, sink.String(), "queue processor stopped with error")
	})
}

// TestLogFatalErrorRedactsStderrFallback covers the plain-stderr fatal path
// used before a configured logger exists.
func TestLogFatalErrorRedactsStderrFallback(t *testing.T) {
	original := os.Stderr
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = writePipe
	t.Cleanup(func() { os.Stderr = original })

	logFatalError("packmon-server", "packmon-server startup failed", errSecretBearingDatabase)
	_ = writePipe.Close()
	os.Stderr = original
	output, err := io.ReadAll(readPipe)
	_ = readPipe.Close()
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}

	assertLogRedacted(t, string(output), "packmon-server: dial")
}
