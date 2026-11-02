package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/feed/reversinglabs"
)

type f014NVDUpdate struct {
	cveID    string
	severity string
	score    float64
}

type f014NVDStore struct {
	db.Store
	cveIDs  []string
	updates []f014NVDUpdate
}

func (s *f014NVDStore) FindUnknownSeverityCVEIDs(context.Context, string, int) ([]string, error) {
	return slices.Clone(s.cveIDs), nil
}

func (s *f014NVDStore) UpdateSeverityByCVE(_ context.Context, cveID, severity string, score float64) error {
	s.updates = append(s.updates, f014NVDUpdate{cveID: cveID, severity: severity, score: score})
	return nil
}

type f014FeedSyncer struct {
	name string
}

func (s f014FeedSyncer) Name() string { return s.name }

func (f014FeedSyncer) Sync(context.Context, db.Store) (*feed.SyncResult, error) {
	return &feed.SyncResult{}, nil
}

func TestFeedRuntimeDescriptorSyncerWithoutConstructorReturnsNil(t *testing.T) {
	t.Parallel()

	descriptor := feedRuntimeDescriptor{name: "synthetic"}
	if got := descriptor.syncer(feedRuntime{}); got != nil {
		t.Fatalf("syncer() = %T, want nil without constructor", got)
	}
}

func TestAsyncWorkerDescriptorWiresConfiguredReversingLabsOptions(t *testing.T) {
	t.Parallel()

	descriptor, ok := asyncWorkerDescriptorForFeed("reversinglabs")
	if !ok {
		t.Fatal("reversinglabs async worker descriptor not found")
	}
	limiter := reversinglabs.NewRateLimiter(17)
	runtime := asyncWorkerRuntime{
		store:  newNoopStore(),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		feeds: config.FeedsConfig{
			ReversingLabsAPIKey:             "rl-fixture-key",
			ReversingLabsBaseURL:            "https://rl.example.test/community",
			ReversingLabsLookupTTL:          13 * time.Hour,
			ReversingLabsBatchSize:          4,
			ReversingLabsCacheRetention:     72 * time.Hour,
			ReversingLabsExcludedNamespaces: []string{" NPM/@Private/ ", "", "npm/@private/", "Maven/Com.Acme:"},
		},
		rateLimiters: asyncWorkerRateLimiters{reversingLabs: limiter},
	}

	worker, ok := descriptor.newWorker(runtime).(*reversinglabs.Worker)
	if !ok {
		t.Fatalf("descriptor worker = %T, want *reversinglabs.Worker", descriptor.newWorker(runtime))
	}
	value := reflect.Indirect(reflect.ValueOf(worker))
	checks := []struct {
		field string
		want  any
	}{
		{field: "apiKey", want: runtime.feeds.ReversingLabsAPIKey},
		{field: "baseURL", want: runtime.feeds.ReversingLabsBaseURL},
		{field: "lookupTTL", want: runtime.feeds.ReversingLabsLookupTTL},
		{field: "batchSize", want: runtime.feeds.ReversingLabsBatchSize},
		{field: "cacheRetention", want: runtime.feeds.ReversingLabsCacheRetention},
	}
	for _, check := range checks {
		field := value.FieldByName(check.field)
		switch want := check.want.(type) {
		case string:
			if got := field.String(); got != want {
				t.Errorf("worker.%s = %q, want %q", check.field, got, want)
			}
		case time.Duration:
			if got := time.Duration(field.Int()); got != want {
				t.Errorf("worker.%s = %s, want %s", check.field, got, want)
			}
		case int:
			if got := int(field.Int()); got != want {
				t.Errorf("worker.%s = %d, want %d", check.field, got, want)
			}
		}
	}
	excludedField := value.FieldByName("excluded")
	excluded := make([]string, excludedField.Len())
	for i := range excluded {
		excluded[i] = excludedField.Index(i).String()
	}
	if want := []string{"npm/@private/", "maven/com.acme:"}; !slices.Equal(excluded, want) {
		t.Errorf("worker exclusions = %v, want normalized %v", excluded, want)
	}
	if worker.RateLimiter != limiter {
		t.Fatal("worker did not reuse the shared ReversingLabs rate limiter")
	}
}

func TestRuntimeFeedConfigSignatureTracksReversingLabsOptions(t *testing.T) {
	t.Parallel()

	settings := config.FeedSettings{
		Name:    "reversinglabs",
		Enabled: true,
		Mode:    config.FeedModeSelf,
		APIKey:  "fixture-key",
	}
	feeds := config.FeedsConfig{
		ReversingLabsBaseURL:            "https://rl.example.test/community",
		ReversingLabsLookupTTL:          12 * time.Hour,
		ReversingLabsBatchSize:          3,
		ReversingLabsCacheRetention:     48 * time.Hour,
		ReversingLabsExcludedNamespaces: []string{"npm/@private/"},
	}
	cfg := &config.Config{FeedSync: config.FeedSyncConfig{Interval: time.Hour}}
	baseline := runtimeFeedConfigSignature(cfg, feeds, settings)
	if duplicate := runtimeFeedConfigSignature(cfg, feeds, settings); !baseline.equal(duplicate) {
		t.Fatal("identical ReversingLabs runtime inputs produced unequal signatures")
	}

	tests := []struct {
		name   string
		mutate func(*config.FeedsConfig)
	}{
		{name: "base URL", mutate: func(f *config.FeedsConfig) { f.ReversingLabsBaseURL += "/v2" }},
		{name: "lookup TTL", mutate: func(f *config.FeedsConfig) { f.ReversingLabsLookupTTL++ }},
		{name: "batch size", mutate: func(f *config.FeedsConfig) { f.ReversingLabsBatchSize++ }},
		{name: "cache retention", mutate: func(f *config.FeedsConfig) { f.ReversingLabsCacheRetention++ }},
		{name: "excluded namespaces", mutate: func(f *config.FeedsConfig) { f.ReversingLabsExcludedNamespaces = []string{"npm/@other/"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := feeds
			changed.ReversingLabsExcludedNamespaces = slices.Clone(feeds.ReversingLabsExcludedNamespaces)
			tt.mutate(&changed)
			if baseline.equal(runtimeFeedConfigSignature(cfg, changed, settings)) {
				t.Fatalf("changing %s did not change the runtime signature", tt.name)
			}
		})
	}
}

func TestApplyFeedConfigSkipsUnchangedReversingLabsWorkerConfig(t *testing.T) {
	t.Parallel()

	oldCtx, oldCancel := context.WithCancel(context.Background())
	defer oldCancel()
	oldDone := make(chan error, 1)
	cfg := f014ReversingLabsConfig("fixture-key")
	settings, ok := cfg.FeedSettings("reversinglabs")
	if !ok {
		t.Fatal("reversinglabs settings not found")
	}
	services := &backgroundServices{
		cfg:         cfg,
		rootCtx:     context.Background(),
		queueCancel: oldCancel,
		queueDone:   oldDone,
		queueDones:  []chan error{oldDone},
	}

	if err := services.ApplyFeedConfig(context.Background(), settings); err != nil {
		t.Fatalf("ApplyFeedConfig(unchanged reversinglabs) error = %v", err)
	}
	if oldCtx.Err() != nil {
		t.Fatal("unchanged ReversingLabs config cancelled the current queue generation")
	}
	if services.queueDone != oldDone || len(services.queueDones) != 1 {
		t.Fatal("unchanged ReversingLabs config replaced the current queue generation")
	}
}

func TestApplyFeedConfigRestartsQueueForAPIKeyChange(t *testing.T) {
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()
	oldCtx, oldCancel := context.WithCancel(context.Background())
	oldDone := make(chan error, 1)
	oldDone <- context.Canceled
	cfg := f014ReversingLabsConfig("old-fixture-key")
	services := &backgroundServices{
		logger:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:                      cfg,
		store:                    newNoopStore(),
		rootCtx:                  rootCtx,
		shutdownWait:             time.Second,
		queueCancel:              oldCancel,
		queueDone:                oldDone,
		queueDones:               []chan error{oldDone},
		reversingLabsRateLimiter: reversinglabs.NewRateLimiter(0),
	}
	settings, _ := cfg.FeedSettings("reversinglabs")
	settings.APIKey = "new-fixture-key"

	if err := services.ApplyFeedConfig(context.Background(), settings); err != nil {
		t.Fatalf("ApplyFeedConfig(changed key) error = %v", err)
	}
	if oldCtx.Err() == nil {
		t.Fatal("changed ReversingLabs key did not cancel the old queue generation")
	}
	services.queueMu.Lock()
	replacement := services.queueDone
	services.queueMu.Unlock()
	if replacement == nil || replacement == oldDone {
		t.Fatal("changed ReversingLabs key did not install a replacement queue generation")
	}

	if err := services.ApplyFeedConfig(context.Background(), settings); err != nil {
		t.Fatalf("ApplyFeedConfig(identical replacement settings) error = %v", err)
	}
	services.queueMu.Lock()
	unchanged := services.queueDone
	services.queueMu.Unlock()
	if unchanged != replacement {
		t.Fatal("identical ReversingLabs signature restarted the replacement generation")
	}

	rootCancel()
	if !services.Wait() {
		t.Fatal("Wait() = false after cancelling replacement queue generation")
	}
}

func f014ReversingLabsConfig(apiKey string) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		Feeds: config.FeedsConfig{
			ReversingLabsEnabled:        true,
			ReversingLabsMode:           config.FeedModeSelf,
			ReversingLabsAPIKey:         apiKey,
			ReversingLabsBaseURL:        "https://rl.example.test/community",
			ReversingLabsLookupTTL:      12 * time.Hour,
			ReversingLabsBatchSize:      3,
			ReversingLabsCacheRetention: 48 * time.Hour,
		},
	}
}

func TestRunManualFeedSyncGuardsAndFallbackManager(t *testing.T) {
	t.Parallel()

	var nilServices *backgroundServices
	if err := nilServices.RunManualFeedSync(context.Background(), "nvd"); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil RunManualFeedSync() error = %v, want context.Canceled", err)
	}
	closed := &backgroundServices{manualClosed: true}
	if err := closed.RunManualFeedSync(context.Background(), "nvd"); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed RunManualFeedSync() error = %v, want context.Canceled", err)
	}

	cfg := &config.Config{
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
		Feeds: config.FeedsConfig{
			DataDir:    t.TempDir(),
			NVDEnabled: true,
			NVDMode:    config.FeedModeSelf,
		},
	}
	services := &backgroundServices{
		cfg:    cfg,
		store:  newNoopStore(),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := services.RunManualFeedSync(context.Background(), "nvd"); err != nil {
		t.Fatalf("RunManualFeedSync(fallback manager) error = %v", err)
	}
	if services.manager != nil || services.manualRunning != 0 {
		t.Fatalf("fallback manual sync published manager/running state: manager=%v running=%d", services.manager, services.manualRunning)
	}
}

func TestStartBackgroundTaskLifecycleAndCancellationLogging(t *testing.T) {
	t.Parallel()

	var nilServices *backgroundServices
	nilServices.startBackgroundTask("ignored", func(context.Context) error { return errors.New("must not run") })

	logger, logs := newCapturingLogger()
	services := &backgroundServices{logger: logger}
	services.startBackgroundTask("nil-function", nil)
	services.backgroundTasks.Wait()

	contextSeen := make(chan context.Context, 1)
	services.startBackgroundTask("successful-task", func(ctx context.Context) error {
		contextSeen <- ctx
		return nil
	})
	services.backgroundTasks.Wait()
	if ctx := <-contextSeen; ctx == nil || ctx.Err() != nil {
		t.Fatalf("nil-root fallback context = %v, want active background context", ctx)
	}

	services.startBackgroundTask("failed-task", func(context.Context) error { return errors.New("startup failed") })
	services.backgroundTasks.Wait()
	services.startBackgroundTask("cancelled-task", func(context.Context) error { return context.Canceled })
	services.backgroundTasks.Wait()

	output := logs.String()
	for _, want := range []string{
		`"msg":"background startup task completed"`,
		`"task":"successful-task"`,
		`"msg":"background startup task failed"`,
		`"task":"failed-task"`,
		`"error":"startup failed"`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("logs = %s, want %s", output, want)
		}
	}
	if strings.Contains(output, `"task":"cancelled-task"`) || strings.Contains(output, `"task":"nil-function"`) {
		t.Fatalf("canceled or nil background task produced a log: %s", output)
	}
}

func TestStartQueueProcessorLockedSkipsInactiveRoot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "nil root"},
		{name: "cancelled root", ctx: f014CanceledContext()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			services := &backgroundServices{rootCtx: tt.ctx}
			if err := services.startQueueProcessorLocked(); err != nil {
				t.Fatalf("startQueueProcessorLocked() error = %v", err)
			}
			if services.queueCancel != nil || services.queueDone != nil || len(services.queueDones) != 0 {
				t.Fatalf("inactive root started queue state: %+v", services)
			}
			if services.socketRateLimiter != nil || services.reversingLabsRateLimiter != nil {
				t.Fatal("inactive root constructed provider rate limiters")
			}
		})
	}
}

func f014CanceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestNewQueueProcessorUsesDefaultSkippedRecorder(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	cfg := &config.Config{Feeds: config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
	}}
	processor, err := newQueueProcessorWithRateLimitersAndRecorder(
		cfg,
		store,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		nil,
		nil,
	)
	if err != nil || processor != nil {
		t.Fatalf("newQueueProcessorWithRateLimitersAndRecorder() = %T, %v; want nil, nil", processor, err)
	}
	status, err := store.GetFeedSyncStatus(context.Background(), "socket")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(socket) error = %v", err)
	}
	if status == nil || status.LastSyncStatus != db.FeedSyncStatusSkipped || status.LastError != "Socket.dev API key not configured" {
		t.Fatalf("default recorder status = %+v, want missing-key skipped status", status)
	}
}

func TestWaitForQueueProcessorDiagnostics(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			logger, logs := newCapturingLogger()
			done := make(chan error, 1)
			done <- errors.New("queue failed")
			services := &backgroundServices{logger: logger, shutdownWait: time.Hour}
			if !services.waitForQueueProcessor(done, "restart") {
				t.Fatal("waitForQueueProcessor(error) = false, want completed")
			}
			output := logs.String()
			for _, want := range []string{`"level":"ERROR"`, `"msg":"queue processor stopped with error"`, `"reason":"restart"`, `"error":"queue failed"`} {
				if !strings.Contains(output, want) {
					t.Fatalf("error logs = %s, want %s", output, want)
				}
			}
		})
	})

	t.Run("cancellation", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			logger, logs := newCapturingLogger()
			done := make(chan error, 1)
			done <- context.Canceled
			services := &backgroundServices{logger: logger, shutdownWait: time.Hour}
			if !services.waitForQueueProcessor(done, "shutdown") {
				t.Fatal("waitForQueueProcessor(cancellation) = false, want completed")
			}
			output := logs.String()
			if strings.Contains(output, `"level":"ERROR"`) || !strings.Contains(output, `"msg":"queue processor stopped"`) {
				t.Fatalf("cancellation logs = %s, want informational stop only", output)
			}
		})
	})

	t.Run("timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			logger, logs := newCapturingLogger()
			services := &backgroundServices{logger: logger, shutdownWait: 2 * time.Second}
			if services.waitForQueueProcessor(make(chan error), "reload") {
				t.Fatal("waitForQueueProcessor(timeout) = true, want false")
			}
			output := logs.String()
			for _, want := range []string{`"level":"WARN"`, `"msg":"queue processor did not stop before deadline; replacement deferred until it exits"`, `"reason":"reload"`, `"timeout":2000000000`} {
				if !strings.Contains(output, want) {
					t.Fatalf("timeout logs = %s, want %s", output, want)
				}
			}
		})
	})
}

func TestBackgroundServicesWaitPreservesShutdownOrder(t *testing.T) {
	t.Parallel()

	logger, logs := newCapturingLogger()
	queueDone := make(chan error, 1)
	queueDone <- context.Canceled
	retentionDone := make(chan error, 1)
	retentionDone <- context.Canceled
	services := &backgroundServices{
		logger:        logger,
		shutdownWait:  time.Second,
		queueDone:     queueDone,
		queueDones:    []chan error{queueDone},
		retentionDone: retentionDone,
	}
	if !services.Wait() {
		t.Fatal("Wait() = false with buffered completions")
	}

	output := logs.String()
	ordered := []string{
		"shutdown: queue processor stopped",
		"shutdown: waiting for audit retention worker",
		"shutdown: audit retention worker stopped",
		"shutdown: waiting for manual feed syncs",
		"shutdown: manual feed syncs stopped",
		"shutdown: waiting for background startup tasks",
		"shutdown: background startup tasks stopped",
	}
	previous := -1
	for _, message := range ordered {
		index := strings.Index(output, message)
		if index < 0 || index <= previous {
			t.Fatalf("shutdown log order = %s, want %q after prior marker", output, message)
		}
		previous = index
	}
}

func TestRegisterFeedSyncerLogsRegistrationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		feedSync   time.Duration
		feedPeriod time.Duration
	}{
		{name: "RegisterWithInterval", feedSync: time.Hour, feedPeriod: 2 * time.Hour},
		{name: "Register"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := feed.NewManager(newNoopStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			manager.Start(ctx)

			cfg := &config.Config{
				FeedSync: config.FeedSyncConfig{Interval: tt.feedSync},
				Feeds: config.FeedsConfig{
					OSVEnabled:  true,
					OSVMode:     config.FeedModeSelf,
					OSVInterval: tt.feedPeriod,
				},
			}
			logger, logs := newCapturingLogger()
			registerFeedSyncer(manager, cfg, logger, feedRuntimeDescriptor{
				name:  "osv",
				phase: feed.FeedPhaseVulnerability,
				newSyncer: func(feedRuntime) feed.FeedSyncer {
					return f014FeedSyncer{name: "osv"}
				},
			})

			line := strings.TrimSpace(logs.String())
			var record map[string]any
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatalf("decode registration log %q: %v", line, err)
			}
			if record["level"] != "ERROR" || record["msg"] != "failed to register feed syncer" || record["feed"] != "osv" || record["error"] != feed.ErrManagerStarted.Error() {
				t.Fatalf("registration log = %#v, want exact structured failure fields", record)
			}
			manager.Wait()
		})
	}
}
