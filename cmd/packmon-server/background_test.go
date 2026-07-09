package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

func TestFeedPhaseForNameSeparatesEnrichmentFeeds(t *testing.T) {
	t.Parallel()

	tests := map[string]feed.FeedPhase{
		"osv":       feed.FeedPhaseVulnerability,
		"ghsa":      feed.FeedPhaseVulnerability,
		"openssf":   feed.FeedPhaseVulnerability,
		"malicious": feed.FeedPhaseVulnerability,
		"vulncheck": feed.FeedPhaseEnrichment,
		"cisakev":   feed.FeedPhaseEnrichment,
		"epss":      feed.FeedPhaseEnrichment,
		"nvd":       feed.FeedPhaseEnrichment,
		"endoflife": feed.FeedPhaseEnrichment,
	}
	for name, want := range tests {
		if got := feedPhaseForName(name); got != want {
			t.Fatalf("feedPhaseForName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestNewFeedManagerHonorsSyncOnStartupConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		FeedSync: config.FeedSyncConfig{
			Interval:  time.Hour,
			OnStartup: false,
		},
		Feeds: config.FeedsConfig{
			DataDir: t.TempDir(),
		},
	}
	manager := newFeedManager(cfg, newNoopStore(), slog.New(slog.NewTextHandler(os.Stdout, nil)))
	if manager.SyncOnStartup() {
		t.Fatal("manager SyncOnStartup = true, want false from config")
	}
}

func TestNewFeedSyncerRecognizesKnownFeeds(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Feeds: config.FeedsConfig{DataDir: t.TempDir()}}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	for _, name := range []string{"osv", "ghsa", "openssf", "vulncheck", "cisakev", "epss", "nvd", "endoflife"} {
		if syncer := newFeedSyncer(name, cfg, logger); syncer == nil {
			t.Fatalf("newFeedSyncer(%q) = nil", name)
		}
	}
	if syncer := newFeedSyncer("unknown", cfg, logger); syncer != nil {
		t.Fatalf("newFeedSyncer(unknown) = %T, want nil", syncer)
	}
}

func TestFeedRuntimeDescriptorTableOwnsSelfManagedFeedWiring(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("background.go")
	if err != nil {
		t.Fatalf("ReadFile(background.go) error = %v", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "background.go", source, 0)
	if err != nil {
		t.Fatalf("ParseFile(background.go) error = %v", err)
	}

	hasRuntimeDescriptor := false
	var descriptorViolations []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			switch spec := spec.(type) {
			case *ast.TypeSpec:
				if spec.Name.Name == "feedRuntimeDescriptor" {
					hasRuntimeDescriptor = true
				}
			case *ast.ValueSpec:
				for _, name := range spec.Names {
					if slices.Contains([]string{"phaseTwoFeeds", "enrichmentFeeds"}, name.Name) {
						descriptorViolations = append(descriptorViolations, "top-level "+name.Name)
					}
				}
			}
		}
	}
	if !hasRuntimeDescriptor {
		descriptorViolations = append(descriptorViolations, "missing feedRuntimeDescriptor type")
	}

	guardedFunctions := map[string]bool{
		"newFeedManager":   true,
		"newFeedSyncer":    true,
		"feedPhaseForName": true,
	}
	disallowedFeedNameLiterals := []string{"osv", "ghsa", "openssf", "vulncheck", "cisakev", "epss", "nvd", "endoflife"}
	disallowedConstructorCalls := []string{"NewSyncer", "NewSyncerWithOptions", "newNVDSyncer"}

	violations := map[string][]string{}
	ast.Inspect(file, func(node ast.Node) bool {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		if !guardedFunctions[fn.Name.Name] {
			return false
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch expr := node.(type) {
			case *ast.BasicLit:
				if expr.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(expr.Value)
				if err == nil && slices.Contains(disallowedFeedNameLiterals, value) {
					violations[fn.Name.Name] = append(violations[fn.Name.Name], "literal "+expr.Value)
				}
			case *ast.CallExpr:
				switch call := expr.Fun.(type) {
				case *ast.Ident:
					if slices.Contains(disallowedConstructorCalls, call.Name) {
						violations[fn.Name.Name] = append(violations[fn.Name.Name], "call "+call.Name)
					}
				case *ast.SelectorExpr:
					if slices.Contains(disallowedConstructorCalls, call.Sel.Name) {
						violations[fn.Name.Name] = append(violations[fn.Name.Name], "call "+call.Sel.Name)
					}
				}
			}
			return true
		})
		return false
	})

	if len(descriptorViolations) > 0 {
		t.Fatalf("self-managed feed runtime metadata must live in feedRuntimeDescriptor table: %v", descriptorViolations)
	}
	for _, functionName := range []string{"newFeedManager", "newFeedSyncer", "feedPhaseForName"} {
		if got := violations[functionName]; len(got) > 0 {
			t.Fatalf("%s has self-managed feed wiring outside feedRuntimeDescriptor: %v", functionName, got)
		}
	}
}

func TestNewFeedSyncerWiresConfiguredMirrorURLs(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Feeds: config.FeedsConfig{
		DataDir:           t.TempDir(),
		OSVBaseURL:        "https://mirror.example/osv",
		GHSARepoURL:       "https://mirror.example/github/advisory-database.git",
		OpenSSFRepoURL:    "https://mirror.example/ossf/malicious-packages.git",
		CISAKEVCatalogURL: "https://mirror.example/cisa/kev.json",
		EPSSScoresURL:     "https://mirror.example/epss/current.csv.gz",
		NVDAPIURL:         "https://mirror.example/nvd/rest/json/cves/2.0",
		VulnCheckBaseURL:  "https://mirror.example/vulncheck",
	}}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tests := []struct {
		feed  string
		field string
		want  string
	}{
		{"osv", "baseURL", cfg.Feeds.OSVBaseURL},
		{"ghsa", "repoURL", cfg.Feeds.GHSARepoURL},
		{"openssf", "repoURL", cfg.Feeds.OpenSSFRepoURL},
		{"cisakev", "catalogURL", cfg.Feeds.CISAKEVCatalogURL},
		{"epss", "scoresURL", cfg.Feeds.EPSSScoresURL},
		{"nvd", "apiURL", cfg.Feeds.NVDAPIURL},
		{"vulncheck", "baseURL", cfg.Feeds.VulnCheckBaseURL},
	}
	for _, tt := range tests {
		t.Run(tt.feed, func(t *testing.T) {
			syncer := newFeedSyncer(tt.feed, cfg, logger)
			if syncer == nil {
				t.Fatalf("newFeedSyncer(%q) = nil", tt.feed)
			}
			got := reflect.Indirect(reflect.ValueOf(syncer)).FieldByName(tt.field).String()
			if got != tt.want {
				t.Fatalf("%s.%s = %q, want %q", tt.feed, tt.field, got, tt.want)
			}
		})
	}
}

func TestAsyncWorkerDescriptorWiresConfiguredSocketBaseURL(t *testing.T) {
	t.Parallel()

	descriptor, ok := asyncWorkerDescriptorForFeed("socket")
	if !ok {
		t.Fatal("socket async worker descriptor not found")
	}
	runtime := asyncWorkerRuntime{
		store:  newNoopStore(),
		logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
		feeds: config.FeedsConfig{
			SocketAPIKey:  "socket-secret",
			SocketBaseURL: "https://mirror.example/socket/api/v1",
		},
	}

	worker := descriptor.newWorker(runtime)
	if worker == nil {
		t.Fatal("socket descriptor returned nil worker")
	}
	got := reflect.Indirect(reflect.ValueOf(worker)).FieldByName("baseURL").String()
	if got != runtime.feeds.SocketBaseURL {
		t.Fatalf("socket worker baseURL = %q, want %q", got, runtime.feeds.SocketBaseURL)
	}
}

func TestNewQueueProcessorHonorsFeedEnablementAndMode(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	store := newNoopStore()

	disabled := &config.Config{Feeds: config.FeedsConfig{
		SocketMode:        config.FeedModeSelf,
		ReversingLabsMode: config.FeedModeSelf,
	}}
	if processor, err := newQueueProcessorWithRateLimiters(disabled, store, logger, nil, nil); err != nil || processor != nil {
		t.Fatalf("newQueueProcessorWithRateLimiters(disabled) = %T, want nil", processor)
	}

	external := &config.Config{Feeds: config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeExternal,
	}}
	if processor, err := newQueueProcessorWithRateLimiters(external, store, logger, nil, nil); err != nil || processor != nil {
		t.Fatalf("newQueueProcessorWithRateLimiters(external socket) = %T, want nil", processor)
	}

	enabled := &config.Config{Feeds: config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-secret",
	}}
	if processor, err := newQueueProcessorWithRateLimiters(enabled, store, logger, nil, nil); err != nil || processor == nil {
		t.Fatal("newQueueProcessorWithRateLimiters(enabled socket) = nil, want processor")
	}
}

func TestNewQueueProcessorRecordsMissingKeyStatus(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	store := newNoopStore()
	cfg := &config.Config{Feeds: config.FeedsConfig{
		SocketEnabled:        true,
		SocketMode:           config.FeedModeSelf,
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeSelf,
	}}

	if processor, err := newQueueProcessorWithRateLimiters(cfg, store, logger, nil, nil); err != nil || processor != nil {
		t.Fatalf("newQueueProcessorWithRateLimiters(missing keys) = %T, want nil", processor)
	}
	socketStatus, err := store.GetFeedSyncStatus(context.Background(), "socket")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(socket) error = %v", err)
	}
	if socketStatus == nil || socketStatus.LastSyncStatus != "skipped" || socketStatus.LastError != "Socket.dev API key not configured" {
		t.Fatalf("socket status = %+v, want skipped missing-key row", socketStatus)
	}
	rlStatus, err := store.GetFeedSyncStatus(context.Background(), "reversinglabs")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(reversinglabs) error = %v", err)
	}
	if rlStatus == nil || rlStatus.LastSyncStatus != "skipped" || rlStatus.LastError != "ReversingLabs API key not configured" {
		t.Fatalf("reversinglabs status = %+v, want skipped missing-key row", rlStatus)
	}
}

type queueStatusFailStore struct {
	db.Store
	err error
}

func (s *queueStatusFailStore) UpsertFeedSyncStatus(context.Context, *db.FeedSyncStatus) error {
	return s.err
}

func TestNewQueueProcessorFailsWhenMissingKeyStatusCannotBeRecorded(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	store := &queueStatusFailStore{Store: newNoopStore(), err: errors.New("status db down")}
	cfg := &config.Config{Feeds: config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
	}}

	processor, err := newQueueProcessorWithRateLimiters(cfg, store, logger, nil, nil)
	if err == nil {
		t.Fatal("newQueueProcessorWithRateLimiters() error = nil, want skipped-status persistence failure")
	}
	if processor != nil {
		t.Fatalf("newQueueProcessorWithRateLimiters() processor = %T, want nil on status failure", processor)
	}
}

func TestAsyncWorkerDescriptorTableOwnsQueueWorkerProviderBranches(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("background.go")
	if err != nil {
		t.Fatalf("ReadFile(background.go) error = %v", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "background.go", source, 0)
	if err != nil {
		t.Fatalf("ParseFile(background.go) error = %v", err)
	}

	guardedFunctions := map[string]bool{
		"ApplyFeedConfig": true,
		"newQueueProcessorWithRateLimitersAndRecorder": true,
	}
	disallowedSelectors := []string{
		"SocketEnabled",
		"SocketMode",
		"SocketAPIKey",
		"ReversingLabsEnabled",
		"ReversingLabsMode",
		"ReversingLabsAPIKey",
		"NewWorker",
	}
	disallowedStringLiterals := []string{"socket", "reversinglabs"}

	violations := map[string][]string{}
	ast.Inspect(file, func(node ast.Node) bool {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		if !guardedFunctions[fn.Name.Name] {
			return false
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch expr := node.(type) {
			case *ast.BasicLit:
				if expr.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(expr.Value)
				if err == nil && slices.Contains(disallowedStringLiterals, value) {
					violations[fn.Name.Name] = append(violations[fn.Name.Name], "literal "+expr.Value)
				}
			case *ast.SelectorExpr:
				if slices.Contains(disallowedSelectors, expr.Sel.Name) {
					violations[fn.Name.Name] = append(violations[fn.Name.Name], "selector "+expr.Sel.Name)
				}
			}
			return true
		})
		return false
	})

	for _, functionName := range []string{"ApplyFeedConfig", "newQueueProcessorWithRateLimitersAndRecorder"} {
		if got := violations[functionName]; len(got) > 0 {
			t.Fatalf("%s has provider-specific async worker wiring outside asyncWorkerDescriptor: %v", functionName, got)
		}
	}
}

func TestRecordQueueWorkerSkippedPreservesExistingFeedData(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	store := newNoopStore()
	lastSuccessfulSync := time.Now().UTC().Add(-6 * time.Hour)
	if err := store.UpsertFeedSyncStatus(context.Background(), &db.FeedSyncStatus{
		FeedName:       "socket",
		LastSyncAt:     &lastSuccessfulSync,
		LastSyncStatus: "success",
		EntriesSynced:  11,
		EntriesTotal:   13,
		LastETag:       "etag-old",
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus() error = %v", err)
	}

	if err := recordQueueWorkerSkipped(context.Background(), store, logger, "socket", "Socket.dev API key not configured"); err != nil {
		t.Fatalf("recordQueueWorkerSkipped() error = %v", err)
	}

	status, err := store.GetFeedSyncStatus(context.Background(), "socket")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(socket) error = %v", err)
	}
	if status == nil || status.LastSyncStatus != "skipped" {
		t.Fatalf("socket status = %+v, want skipped", status)
	}
	if status.LastSyncAt == nil || !status.LastSyncAt.Equal(lastSuccessfulSync) {
		t.Fatalf("LastSyncAt = %v, want preserved %v", status.LastSyncAt, lastSuccessfulSync)
	}
	if status.EntriesSynced != 11 || status.EntriesTotal != 13 || status.LastETag != "etag-old" {
		t.Fatalf("status lost feed data: %+v", status)
	}
}

func TestStartBackgroundServicesSkipsWorkersInDevelopment(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Server: config.ServerConfig{Mode: config.ModeDevelopment}}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	services, err := startBackgroundServices(context.Background(), cfg, config.NewRuntimeSettingsFromConfig(cfg), cfg.Feeds, newNoopStore(), logger)
	if err != nil {
		t.Fatalf("startBackgroundServices() error = %v", err)
	}
	if services == nil {
		t.Fatal("startBackgroundServices returned nil")
	}
	if services.manager != nil || services.queueCancel != nil || services.queueDone != nil {
		t.Fatalf("development services unexpectedly started workers: %+v", services)
	}
	services.Wait()
}

func TestStartBackgroundServicesDefersBestEffortFeedStatusWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &slowStartupFeedStatusStore{
		noopStore: newNoopStore(),
		delay:     250 * time.Millisecond,
		delayOnce: make(chan struct{}, 1),
		calls:     make(chan string, 16),
	}
	store.delayOnce <- struct{}{}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:            config.ModeProduction,
			ShutdownTimeout: time.Second,
		},
		FeedSync: config.FeedSyncConfig{
			Interval:  time.Hour,
			OnStartup: false,
		},
		Feeds: config.FeedsConfig{
			DataDir:       t.TempDir(),
			SocketEnabled: true,
			SocketMode:    config.FeedModeSelf,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	start := time.Now()
	services, err := startBackgroundServices(ctx, cfg, config.NewRuntimeSettingsFromConfig(cfg), cfg.Feeds, store, logger)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("startBackgroundServices() error = %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("startBackgroundServices() took %s, want best-effort feed status writes deferred", elapsed)
	}

	select {
	case <-store.calls:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("background feed status write was not attempted")
	}

	cancel()
	if !services.Wait() {
		t.Fatal("background services did not stop after root context cancellation")
	}
}

type slowStartupFeedStatusStore struct {
	*noopStore
	delay     time.Duration
	delayOnce chan struct{}
	calls     chan string
}

func (s *slowStartupFeedStatusStore) GetFeedSyncStatus(ctx context.Context, feedName string) (*db.FeedSyncStatus, error) {
	s.noteCall("get:" + feedName)
	if err := s.maybeDelay(ctx); err != nil {
		return nil, err
	}
	return s.noopStore.GetFeedSyncStatus(ctx, feedName)
}

func (s *slowStartupFeedStatusStore) UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error {
	if status != nil {
		s.noteCall("upsert:" + status.FeedName)
	}
	if err := s.maybeDelay(ctx); err != nil {
		return err
	}
	return s.noopStore.UpsertFeedSyncStatus(ctx, status)
}

func (s *slowStartupFeedStatusStore) noteCall(call string) {
	select {
	case s.calls <- call:
	default:
	}
}

func (s *slowStartupFeedStatusStore) maybeDelay(ctx context.Context) error {
	select {
	case <-s.delayOnce:
	default:
		return nil
	}

	timer := time.NewTimer(s.delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestBackgroundServicesWaitReportsStopped(t *testing.T) {
	t.Parallel()

	services := &backgroundServices{shutdownWait: time.Second}
	if !services.Wait() {
		t.Fatal("Wait() = false, want true when no background work is running")
	}
}

func TestBackgroundServicesWaitReportsAbandonedOnTimeout(t *testing.T) {
	t.Parallel()

	services := &backgroundServices{shutdownWait: 10 * time.Millisecond}
	if !services.beginManualSyncTask() {
		t.Fatal("beginManualSyncTask() = false, want running manual task")
	}

	if services.Wait() {
		t.Fatal("Wait() = true, want false while manual task is still running after deadline")
	}

	services.endManualSyncTask()
}

func TestRunAuditRetentionOncePrunesConfiguredLogs(t *testing.T) {
	t.Parallel()

	store := &auditRetentionTestStore{}
	retention := config.RetentionConfig{
		ScanLog:            48 * time.Hour,
		AdminAuditLog:      72 * time.Hour,
		RefreshQueue:       96 * time.Hour,
		PackageCheckStatus: 120 * time.Hour,
		DeletedAPIKeys:     144 * time.Hour,
	}

	runAuditRetentionOnce(context.Background(), retention, config.FeedsConfig{}, store, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	if store.scanCalls != 1 || store.scanRetention != 48*time.Hour {
		t.Fatalf("scan retention calls = %d/%s, want 1/48h", store.scanCalls, store.scanRetention)
	}
	if store.adminCalls != 1 || store.adminRetention != 72*time.Hour {
		t.Fatalf("admin retention calls = %d/%s, want 1/72h", store.adminCalls, store.adminRetention)
	}
	if store.queueCalls != 1 || store.queueRetention != 96*time.Hour {
		t.Fatalf("queue retention calls = %d/%s, want 1/96h", store.queueCalls, store.queueRetention)
	}
	if store.packageCheckStatusCalls != 1 || store.packageCheckStatusRetention != 120*time.Hour {
		t.Fatalf("package check status retention calls = %d/%s, want 1/120h", store.packageCheckStatusCalls, store.packageCheckStatusRetention)
	}
	if store.deletedAPIKeyCalls != 1 || store.deletedAPIKeyRetention != 144*time.Hour {
		t.Fatalf("deleted API key retention calls = %d/%s, want 1/144h", store.deletedAPIKeyCalls, store.deletedAPIKeyRetention)
	}
}

func TestRunAuditRetentionOncePrunesReversingLabsReputationCache(t *testing.T) {
	t.Parallel()

	store := &auditRetentionTestStore{}
	feeds := config.FeedsConfig{
		ReversingLabsCacheRetention: 168 * time.Hour,
	}

	runAuditRetentionOnce(context.Background(), config.RetentionConfig{}, feeds, store, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	if store.reputationCalls != 1 {
		t.Fatalf("reputation retention calls = %d, want 1", store.reputationCalls)
	}
	if store.reputationSource != db.ReputationSourceReversingLabs {
		t.Fatalf("reputation source = %q, want %q", store.reputationSource, db.ReputationSourceReversingLabs)
	}
	if store.reputationRetention != 168*time.Hour {
		t.Fatalf("reputation retention = %s, want 168h", store.reputationRetention)
	}
}

func TestRunAuditRetentionOnceSkipsDisabledDurations(t *testing.T) {
	t.Parallel()

	store := &auditRetentionTestStore{}
	runAuditRetentionOnce(context.Background(), config.RetentionConfig{}, config.FeedsConfig{}, store, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	if store.scanCalls != 0 || store.adminCalls != 0 || store.queueCalls != 0 || store.packageCheckStatusCalls != 0 || store.deletedAPIKeyCalls != 0 || store.reputationCalls != 0 {
		t.Fatalf("retention calls = scan:%d admin:%d queue:%d package_check_status:%d deleted_api_keys:%d reputation:%d, want none when durations are disabled", store.scanCalls, store.adminCalls, store.queueCalls, store.packageCheckStatusCalls, store.deletedAPIKeyCalls, store.reputationCalls)
	}
}

func TestApplyAndResetFeedConfigMutateRuntimeConfig(t *testing.T) {
	t.Parallel()

	defaultFeeds := config.FeedsConfig{
		OSVEnabled: true,
		OSVMode:    config.FeedModeSelf,
	}
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeDevelopment},
		Feeds:  defaultFeeds,
	}
	services := &backgroundServices{cfg: cfg, defaultFeeds: defaultFeeds}

	if err := services.ApplyFeedConfig(context.Background(), config.FeedSettings{
		Name:                 "osv",
		Enabled:              false,
		Mode:                 config.FeedModeExternal,
		SyncInterval:         5 * time.Minute,
		SupportsSyncInterval: true,
	}); err != nil {
		t.Fatalf("ApplyFeedConfig: %v", err)
	}
	settings, _ := cfg.FeedSettings("osv")
	if settings.Enabled || settings.Mode != config.FeedModeExternal || settings.SyncInterval != 5*time.Minute {
		t.Fatalf("settings after apply = %+v", settings)
	}

	if _, _, err := services.ResetFeedConfig(context.Background(), "osv"); err != nil {
		t.Fatalf("ResetFeedConfig: %v", err)
	}
	settings, _ = cfg.FeedSettings("osv")
	if !settings.Enabled || settings.Mode != config.FeedModeSelf || settings.SyncInterval != 0 {
		t.Fatalf("settings after reset = %+v", settings)
	}
}

func TestApplyFeedConfigSkipsUnchangedRuntimeConfig(t *testing.T) {
	t.Parallel()

	store := &feedStatusCountingStore{Store: newNoopStore()}
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		FeedSync: config.FeedSyncConfig{
			Interval: time.Hour,
		},
		Feeds: config.FeedsConfig{
			DataDir:    t.TempDir(),
			OSVEnabled: true,
			OSVMode:    config.FeedModeExternal,
		},
	}
	services := &backgroundServices{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:     cfg,
		store:   store,
		manager: newFeedManager(cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil))),
	}

	if err := services.ApplyFeedConfig(context.Background(), config.FeedSettings{
		Name:                 "osv",
		Enabled:              true,
		Mode:                 config.FeedModeExternal,
		SupportsSyncInterval: true,
	}); err != nil {
		t.Fatalf("ApplyFeedConfig(unchanged osv) error = %v", err)
	}

	if store.upsertFeedSyncStatusCalls != 0 {
		t.Fatalf("feed sync status writes = %d, want no manager reload for unchanged runtime config", store.upsertFeedSyncStatusCalls)
	}
}

func TestApplyFeedConfigSkipsUnchangedQueueWorkerConfig(t *testing.T) {
	oldCtx, oldCancel := context.WithCancel(context.Background())
	oldDone := make(chan error, 1)
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		Feeds: config.FeedsConfig{
			SocketEnabled: true,
			SocketMode:    config.FeedModeSelf,
			SocketAPIKey:  "socket-secret",
		},
	}
	services := &backgroundServices{
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:          cfg,
		store:        newNoopStore(),
		rootCtx:      context.Background(),
		shutdownWait: 10 * time.Millisecond,
		queueCancel:  oldCancel,
		queueDone:    oldDone,
		queueDones:   []chan error{oldDone},
	}

	if err := services.ApplyFeedConfig(context.Background(), config.FeedSettings{
		Name:    "socket",
		Enabled: true,
		Mode:    config.FeedModeSelf,
		APIKey:  "socket-secret",
	}); err != nil {
		t.Fatalf("ApplyFeedConfig(unchanged socket) error = %v", err)
	}

	if oldCtx.Err() != nil {
		t.Fatal("unchanged queue runtime config cancelled the existing worker")
	}
	if services.queueDone != oldDone {
		t.Fatal("queueDone changed, want existing queue worker to remain tracked")
	}
}

type feedStatusCountingStore struct {
	db.Store

	upsertFeedSyncStatusCalls int
}

func (s *feedStatusCountingStore) UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error {
	s.upsertFeedSyncStatusCalls++
	return s.Store.UpsertFeedSyncStatus(ctx, status)
}

func TestStartAuditRetentionWorkerDefersFirstPruneUntilInitialInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &delayedAuditRetentionStore{
		noopStore: newNoopStore(),
		called:    make(chan struct{}, 1),
	}
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:            config.ModeProduction,
			ShutdownTimeout: time.Second,
		},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
		Retention: config.RetentionConfig{
			ScanLog:  time.Hour,
			Interval: 500 * time.Millisecond,
		},
		Feeds: config.FeedsConfig{DataDir: t.TempDir()},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	services, err := startBackgroundServices(ctx, cfg, config.NewRuntimeSettingsFromConfig(cfg), cfg.Feeds, store, logger)
	if err != nil {
		t.Fatalf("startBackgroundServices() error = %v", err)
	}
	select {
	case <-store.called:
		t.Fatal("audit retention pruned during background service startup")
	case <-time.After(100 * time.Millisecond):
	}

	select {
	case <-store.called:
	case <-time.After(2 * time.Second):
		t.Fatal("audit retention worker did not run after initial interval")
	}

	cancel()
	if !services.Wait() {
		t.Fatal("Wait() = false, want retention worker to stop after root context cancellation")
	}
}

type auditRetentionTestStore struct {
	scanCalls                   int
	scanRetention               time.Duration
	adminCalls                  int
	adminRetention              time.Duration
	queueCalls                  int
	queueRetention              time.Duration
	packageCheckStatusCalls     int
	packageCheckStatusRetention time.Duration
	deletedAPIKeyCalls          int
	deletedAPIKeyRetention      time.Duration
	reputationCalls             int
	reputationSource            string
	reputationRetention         time.Duration
}

func (s *auditRetentionTestStore) PruneScanLogs(_ context.Context, retention time.Duration) (int, error) {
	s.scanCalls++
	s.scanRetention = retention
	return 3, nil
}

func (s *auditRetentionTestStore) PruneAdminAuditLogs(_ context.Context, retention time.Duration) (int, error) {
	s.adminCalls++
	s.adminRetention = retention
	return 4, nil
}

func (s *auditRetentionTestStore) PruneRefreshQueue(_ context.Context, retention time.Duration) (int, error) {
	s.queueCalls++
	s.queueRetention = retention
	return 5, nil
}

func (s *auditRetentionTestStore) PrunePackageCheckStatus(_ context.Context, retention time.Duration) (int, error) {
	s.packageCheckStatusCalls++
	s.packageCheckStatusRetention = retention
	return 6, nil
}

func (s *auditRetentionTestStore) PruneDeletedAPIKeys(_ context.Context, retention time.Duration) (int, error) {
	s.deletedAPIKeyCalls++
	s.deletedAPIKeyRetention = retention
	return 8, nil
}

func (s *auditRetentionTestStore) PrunePackageReputation(_ context.Context, source string, retention time.Duration) (int, error) {
	s.reputationCalls++
	s.reputationSource = source
	s.reputationRetention = retention
	return 7, nil
}

type delayedAuditRetentionStore struct {
	*noopStore
	called chan struct{}
}

func (s *delayedAuditRetentionStore) PruneScanLogs(ctx context.Context, _ time.Duration) (int, error) {
	select {
	case s.called <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestBackgroundServicesApplyProductionConfigRestartsQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defaultFeeds := config.FeedsConfig{
		OSVEnabled:        true,
		OSVMode:           config.FeedModeSelf,
		OSVInterval:       time.Hour,
		SocketMode:        config.FeedModeExternal,
		ReversingLabsMode: config.FeedModeSelf,
		DataDir:           t.TempDir(),
	}
	cfg := &config.Config{
		Server:   config.ServerConfig{Mode: config.ModeProduction},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
		Feeds:    defaultFeeds,
	}
	services, err := startBackgroundServices(ctx, cfg, config.NewRuntimeSettingsFromConfig(cfg), defaultFeeds, newNoopStore(), slog.Default())
	if err != nil {
		t.Fatalf("startBackgroundServices() error = %v", err)
	}
	if services.manager == nil {
		t.Fatal("manager = nil, want production manager")
	}

	if err := services.ApplyFeedConfig(ctx, config.FeedSettings{
		Name:                 "osv",
		Enabled:              true,
		Mode:                 config.FeedModeSelf,
		SyncInterval:         30 * time.Minute,
		SupportsSyncInterval: true,
	}); err != nil {
		t.Fatalf("ApplyFeedConfig(osv) error = %v", err)
	}
	if err := services.ApplyFeedConfig(ctx, config.FeedSettings{
		Name:    "socket",
		Enabled: true,
		Mode:    config.FeedModeSelf,
		APIKey:  "socket-secret",
	}); err != nil {
		t.Fatalf("ApplyFeedConfig(socket) error = %v", err)
	}
	if services.queueDone == nil {
		t.Fatal("queueDone = nil, want queue processor after socket self config")
	}
	if _, _, err := services.ResetFeedConfig(ctx, "unknown"); err != nil {
		t.Fatalf("ResetFeedConfig(unknown) error = %v", err)
	}

	cancel()
	services.Wait()
}

func TestRestartQueueProcessorDoesNotOverlapGenerations(t *testing.T) {
	oldCtx, oldCancel := context.WithCancel(context.Background())
	oldDone := make(chan error, 1)
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		Feeds: config.FeedsConfig{
			SocketEnabled: true,
			SocketMode:    config.FeedModeSelf,
			SocketAPIKey:  "socket-secret",
		},
	}
	services := &backgroundServices{
		logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
		cfg:          cfg,
		store:        newNoopStore(),
		rootCtx:      context.Background(),
		shutdownWait: 10 * time.Millisecond,
		queueCancel:  oldCancel,
		queueDone:    oldDone,
		queueDones:   []chan error{oldDone},
	}

	if err := services.restartQueueProcessor(); err != nil {
		t.Fatalf("restartQueueProcessor() error = %v", err)
	}

	if oldCtx.Err() == nil {
		t.Fatal("old queue context was not cancelled")
	}
	if services.queueDone != oldDone {
		t.Fatal("queueDone changed, want old generation retained while it is still running")
	}
	if len(services.queueDones) != 1 || services.queueDones[0] != oldDone {
		t.Fatalf("queueDones = %+v, want old generation retained while it is still running", services.queueDones)
	}
}

func TestRestartQueueProcessorStartsReplacementAfterOldStops(t *testing.T) {
	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oldDone := make(chan error, 1)
	oldDone <- context.Canceled
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		Feeds: config.FeedsConfig{
			SocketEnabled: true,
			SocketMode:    config.FeedModeSelf,
			SocketAPIKey:  "socket-secret",
		},
	}
	services := &backgroundServices{
		logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
		cfg:          cfg,
		store:        newNoopStore(),
		rootCtx:      rootCtx,
		shutdownWait: time.Second,
		queueCancel:  func() {},
		queueDone:    oldDone,
		queueDones:   []chan error{oldDone},
	}

	if err := services.restartQueueProcessor(); err != nil {
		t.Fatalf("restartQueueProcessor() error = %v", err)
	}

	if services.queueDone == nil {
		t.Fatal("queueDone = nil, want replacement queue processor")
	}
	if services.queueDone == oldDone {
		t.Fatal("queueDone still points at old generation")
	}
	cancel()
	services.Wait()
}
