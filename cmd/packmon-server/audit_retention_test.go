package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/config"
)

func TestF091AuditRetentionWorkerUsesRuntimeUpdatesBetweenTicks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cfg := &config.Config{
			Retention: config.RetentionConfig{
				Interval:           time.Hour,
				ScanLog:            24 * time.Hour,
				AdminAuditLog:      48 * time.Hour,
				RefreshQueue:       72 * time.Hour,
				PackageCheckStatus: 96 * time.Hour,
			},
			Feeds: config.FeedsConfig{ReversingLabsCacheRetention: 120 * time.Hour},
		}
		runtime := config.NewRuntimeSettingsFromConfig(cfg)
		store := &runtimeUpdatingAuditRetentionStore{noopStore: newNoopStore()}
		services := &backgroundServices{cfg: cfg, runtime: runtime, rootCtx: ctx, store: store}
		services.startAuditRetentionWorker()

		time.Sleep(time.Hour)
		synctest.Wait()
		runtime.UpdateRetention(168*time.Hour, 336*time.Hour)
		time.Sleep(time.Hour)
		synctest.Wait()

		cancel()
		synctest.Wait()
		if err := <-services.retentionDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("retention worker error = %v, want context canceled", err)
		}

		got := store.snapshot()
		want := []runtimeUpdatingAuditRetentionCall{
			{name: "scan_log", retention: 24 * time.Hour},
			{name: "admin_audit_log", retention: 48 * time.Hour},
			{name: "refresh_queue", retention: 72 * time.Hour},
			{name: "package_check_status", retention: 96 * time.Hour},
			{name: "package_reputation_cache", retention: 120 * time.Hour},
			{name: "scan_log", retention: 168 * time.Hour},
			{name: "admin_audit_log", retention: 336 * time.Hour},
			{name: "refresh_queue", retention: 72 * time.Hour},
			{name: "package_check_status", retention: 96 * time.Hour},
			{name: "package_reputation_cache", retention: 120 * time.Hour},
		}
		if len(got) != len(want) {
			t.Fatalf("prune calls = %d, want exact %d: %+v", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("prune call %d = %+v, want %+v", i, got[i], want[i])
			}
		}
	})
}

func TestStartAuditRetentionWorkerRejectsIncompleteConfiguration(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("startAuditRetentionWorker() panicked: %v", recovered)
			}
		}()

		var services *backgroundServices
		services.startAuditRetentionWorker()
	})

	validConfig := func() *config.Config {
		return &config.Config{Retention: config.RetentionConfig{
			Interval: time.Hour,
			ScanLog:  time.Hour,
		}}
	}
	for _, tt := range []struct {
		name  string
		build func(*auditRetentionWorkerStore) *backgroundServices
	}{
		{
			name: "nil config",
			build: func(store *auditRetentionWorkerStore) *backgroundServices {
				return &backgroundServices{rootCtx: context.Background(), store: store}
			},
		},
		{
			name: "nil root context",
			build: func(store *auditRetentionWorkerStore) *backgroundServices {
				return &backgroundServices{cfg: validConfig(), store: store}
			},
		},
		{
			name: "nil store",
			build: func(_ *auditRetentionWorkerStore) *backgroundServices {
				return &backgroundServices{cfg: validConfig(), rootCtx: context.Background()}
			},
		},
		{
			name: "zero interval",
			build: func(store *auditRetentionWorkerStore) *backgroundServices {
				cfg := validConfig()
				cfg.Retention.Interval = 0
				return &backgroundServices{cfg: cfg, rootCtx: context.Background(), store: store}
			},
		},
		{
			name: "negative interval",
			build: func(store *auditRetentionWorkerStore) *backgroundServices {
				cfg := validConfig()
				cfg.Retention.Interval = -time.Second
				return &backgroundServices{cfg: cfg, rootCtx: context.Background(), store: store}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := &auditRetentionWorkerStore{noopStore: newNoopStore()}
			services := tt.build(store)

			services.startAuditRetentionWorker()

			if services.retentionDone != nil {
				t.Fatal("retentionDone initialized for incomplete configuration")
			}
			if store.scanCalls != 0 {
				t.Fatalf("scan prune calls = %d, want 0", store.scanCalls)
			}
		})
	}
}

func TestBackgroundServicesRetentionSnapshotHandlesMissingConfiguration(t *testing.T) {
	t.Parallel()

	var nilServices *backgroundServices
	if got := nilServices.retentionSnapshot(); got != (config.RetentionConfig{}) {
		t.Fatalf("nil receiver snapshot = %+v, want zero value", got)
	}
	if got := (&backgroundServices{}).retentionSnapshot(); got != (config.RetentionConfig{}) {
		t.Fatalf("missing config snapshot = %+v, want zero value", got)
	}
}

func TestBackgroundServicesRetentionSnapshotAppliesZeroLiveOverrides(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Retention: config.RetentionConfig{
		Interval:           15 * time.Minute,
		ScanLog:            24 * time.Hour,
		AdminAuditLog:      48 * time.Hour,
		RefreshQueue:       72 * time.Hour,
		PackageCheckStatus: 96 * time.Hour,
	}}
	runtime := config.NewRuntimeSettingsFromConfig(cfg)
	runtime.UpdateRetention(0, 0)

	got := (&backgroundServices{cfg: cfg, runtime: runtime}).retentionSnapshot()
	if got.ScanLog != 0 || got.AdminAuditLog != 0 {
		t.Fatalf("live retention = scan:%s admin:%s, want both disabled", got.ScanLog, got.AdminAuditLog)
	}
	if got.Interval != cfg.Retention.Interval || got.RefreshQueue != cfg.Retention.RefreshQueue || got.PackageCheckStatus != cfg.Retention.PackageCheckStatus {
		t.Fatalf("static retention changed: got %+v, want config %+v", got, cfg.Retention)
	}
}

func TestRunAuditRetentionOnceStopsAfterCancellation(t *testing.T) {
	retention := config.RetentionConfig{
		ScanLog:            24 * time.Hour,
		AdminAuditLog:      48 * time.Hour,
		RefreshQueue:       72 * time.Hour,
		PackageCheckStatus: 96 * time.Hour,
	}
	feeds := config.FeedsConfig{ReversingLabsCacheRetention: 120 * time.Hour}
	for _, tt := range []struct {
		cancelAt string
		want     string
	}{
		{cancelAt: "scan_log", want: "scan_log"},
		{cancelAt: "admin_audit_log", want: "scan_log,admin_audit_log"},
		{cancelAt: "refresh_queue", want: "scan_log,admin_audit_log,refresh_queue"},
		{cancelAt: "package_check_status", want: "scan_log,admin_audit_log,refresh_queue,package_check_status"},
	} {
		t.Run(tt.cancelAt, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			store := &auditRetentionLifecycleStore{cancel: cancel, cancelAt: tt.cancelAt}

			runAuditRetentionOnce(ctx, retention, feeds, store, nil)

			if got := strings.Join(store.calls, ","); got != tt.want {
				t.Fatalf("prune calls = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunAuditRetentionOnceContinuesAfterPruneErrorAndSuppressesZeroRows(t *testing.T) {
	t.Parallel()

	const secret = "audit-retention-secret-token"
	scanErr := errors.New("scan prune failed with Bearer " + secret + " " + strings.Repeat("x", 600))
	store := &auditRetentionLifecycleStore{results: map[string]auditRetentionResult{
		"scan_log":      {err: scanErr},
		"refresh_queue": {rows: 2},
	}}
	retention := config.RetentionConfig{
		ScanLog:            24 * time.Hour,
		AdminAuditLog:      48 * time.Hour,
		RefreshQueue:       72 * time.Hour,
		PackageCheckStatus: 96 * time.Hour,
	}
	feeds := config.FeedsConfig{ReversingLabsCacheRetention: 120 * time.Hour}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	runAuditRetentionOnce(context.Background(), retention, feeds, store, logger)

	if got, want := strings.Join(store.calls, ","), "scan_log,admin_audit_log,refresh_queue,package_check_status,package_reputation_cache"; got != want {
		t.Fatalf("prune calls = %q, want %q", got, want)
	}
	entries := decodeAuditRetentionJSONLogs(t, logs.Bytes())
	if len(entries) != 2 {
		t.Fatalf("log records = %d, want 2; logs=%s", len(entries), logs.String())
	}

	byTable := make(map[string]map[string]any, len(entries))
	for _, entry := range entries {
		table, _ := entry["table"].(string)
		byTable[table] = entry
	}
	warn := byTable["scan_log"]
	if warn == nil || warn["level"] != "WARN" || warn["msg"] != "audit retention prune failed" {
		t.Fatalf("scan warning = %#v", warn)
	}
	if got, want := warn["retention"], float64((24 * time.Hour).Nanoseconds()); got != want {
		t.Fatalf("scan warning retention = %#v, want %v", got, want)
	}
	diagnostic, _ := warn["error"].(string)
	if len(diagnostic) > errorLogMaxBytes || !utf8.ValidString(diagnostic) || !strings.Contains(diagnostic, "[redacted]") || !strings.Contains(diagnostic, "[truncated]") || strings.Contains(diagnostic, secret) {
		t.Fatalf("scan warning diagnostic is not safely bounded/redacted: %q", diagnostic)
	}

	info := byTable["refresh_queue"]
	if info == nil || info["level"] != "INFO" || info["msg"] != "audit retention pruned rows" || info["rows"] != float64(2) {
		t.Fatalf("refresh info = %#v", info)
	}
	if got, want := info["retention"], float64((72 * time.Hour).Nanoseconds()); got != want {
		t.Fatalf("refresh info retention = %#v, want %v", got, want)
	}
}

func TestRunAuditRetentionPruneHonorsCallerDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		started := time.Now()
		var callbackErr error
		var elapsed time.Duration
		var logs bytes.Buffer

		runAuditRetentionPrune(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), "scan_log", time.Hour, func(pruneCtx context.Context) (int, error) {
			<-pruneCtx.Done()
			callbackErr = pruneCtx.Err()
			elapsed = time.Since(started)
			return 0, callbackErr
		})

		if !errors.Is(callbackErr, context.DeadlineExceeded) {
			t.Fatalf("callback error = %v, want context deadline exceeded", callbackErr)
		}
		if elapsed != 5*time.Second {
			t.Fatalf("callback elapsed = %s, want 5s parent deadline", elapsed)
		}
		entries := decodeAuditRetentionJSONLogs(t, logs.Bytes())
		if len(entries) != 1 || entries[0]["level"] != "WARN" || entries[0]["table"] != "scan_log" || entries[0]["error"] != context.DeadlineExceeded.Error() {
			t.Fatalf("deadline warning = %#v", entries)
		}
	})
}

func TestAuditRetentionLoggingAllowsNilLogger(t *testing.T) {
	t.Parallel()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("nil logger path panicked: %v", recovered)
		}
	}()

	logAuditRetentionPanic(nil, "scan_log", time.Hour, "panic diagnostic")
	logAuditRetentionResult(nil, "scan_log", time.Hour, 0, errors.New("prune failed"))
	runAuditRetentionPrune(context.Background(), nil, "scan_log", time.Hour, func(context.Context) (int, error) {
		panic("prune panic")
	})
}

func TestLogAuditRetentionPanicRedactsAndBoundsDiagnostic(t *testing.T) {
	t.Parallel()

	const secret = "panic-secret-token-value"
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	panicValue := "panic\nwith\tBearer " + secret + " " + strings.Repeat("é", 600)

	runAuditRetentionPrune(context.Background(), logger, "scan_log", 2*time.Hour, func(context.Context) (int, error) {
		panic(panicValue)
	})

	entries := decodeAuditRetentionJSONLogs(t, logs.Bytes())
	if len(entries) != 1 {
		t.Fatalf("panic log records = %d, want 1; logs=%s", len(entries), logs.String())
	}
	entry := entries[0]
	if entry["level"] != "WARN" || entry["msg"] != "audit retention prune panicked" || entry["table"] != "scan_log" {
		t.Fatalf("panic warning = %#v", entry)
	}
	if got, want := entry["retention"], float64((2 * time.Hour).Nanoseconds()); got != want {
		t.Fatalf("panic warning retention = %#v, want %v", got, want)
	}
	diagnostic, _ := entry["panic"].(string)
	if len(diagnostic) > errorLogMaxBytes || !utf8.ValidString(diagnostic) {
		t.Fatalf("panic diagnostic length/UTF-8 invalid: len=%d value=%q", len(diagnostic), diagnostic)
	}
	if strings.ContainsAny(diagnostic, "\n\r\t") || strings.Contains(diagnostic, secret) || !strings.Contains(diagnostic, "[redacted]") || !strings.Contains(diagnostic, "[truncated]") {
		t.Fatalf("panic diagnostic is not safely normalized/redacted/truncated: %q", diagnostic)
	}
}

func TestRunAuditRetentionOnceRecoversPrunePanicAndContinues(t *testing.T) {
	t.Parallel()

	store := &panickingScanAuditRetentionStore{}
	retention := config.RetentionConfig{
		ScanLog:       48 * time.Hour,
		AdminAuditLog: 72 * time.Hour,
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("runAuditRetentionOnce panicked: %v", recovered)
		}
	}()

	runAuditRetentionOnce(context.Background(), retention, config.FeedsConfig{}, store, logger)

	if store.scanCalls != 1 {
		t.Fatalf("scan retention calls = %d, want 1", store.scanCalls)
	}
	if store.adminCalls != 1 || store.adminRetention != 72*time.Hour {
		t.Fatalf("admin retention calls = %d/%s, want 1/72h", store.adminCalls, store.adminRetention)
	}
	logOutput := logs.String()
	for _, want := range []string{"audit retention prune panicked", "table=scan_log", "scan retention panic"} {
		if !strings.Contains(logOutput, want) {
			t.Fatalf("panic log missing %q\nlogs=%s", want, logOutput)
		}
	}
}

func TestRunAuditRetentionOnceUsesDeadlineContextForEachPrune(t *testing.T) {
	t.Parallel()

	store := &deadlineCapturingAuditRetentionStore{}
	retention := config.RetentionConfig{
		ScanLog:            48 * time.Hour,
		AdminAuditLog:      72 * time.Hour,
		RefreshQueue:       96 * time.Hour,
		PackageCheckStatus: 120 * time.Hour,
	}
	feeds := config.FeedsConfig{
		ReversingLabsCacheRetention: 168 * time.Hour,
	}
	started := time.Now()

	runAuditRetentionOnce(context.Background(), retention, feeds, store, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	finished := time.Now()
	if len(store.calls) != 5 {
		t.Fatalf("prune calls = %d, want 5", len(store.calls))
	}
	for _, call := range store.calls {
		deadline, ok := call.ctx.Deadline()
		if !ok {
			t.Fatalf("%s prune context has no deadline", call.name)
		}
		minDeadline := started.Add(auditRetentionPruneTimeout)
		maxDeadline := finished.Add(auditRetentionPruneTimeout)
		if deadline.Before(minDeadline) || deadline.After(maxDeadline) {
			t.Fatalf("%s prune deadline = %v, want between %v and %v", call.name, deadline, minDeadline, maxDeadline)
		}
		if err := call.ctx.Err(); err == nil {
			t.Fatalf("%s prune context was not canceled after prune returned", call.name)
		}
	}
}

func TestLogAuditRetentionResultUsesNumericJSONDuration(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	logAuditRetentionResult(logger, "scan_log", 2*time.Second, 1, nil)

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
		t.Fatalf("audit retention log is not JSON: %v; log=%q", err, logs.String())
	}

	got, ok := entry["retention"].(float64)
	if !ok {
		t.Fatalf("retention log field type = %T (%v), want numeric duration", entry["retention"], entry["retention"])
	}
	if want := float64((2 * time.Second).Nanoseconds()); got != want {
		t.Fatalf("retention = %v, want %v", got, want)
	}
}

func TestBackgroundServicesRetentionSnapshotUsesLiveAdminRetention(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Retention: config.RetentionConfig{
			Interval:           15 * time.Minute,
			ScanLog:            24 * time.Hour,
			AdminAuditLog:      48 * time.Hour,
			RefreshQueue:       72 * time.Hour,
			PackageCheckStatus: 96 * time.Hour,
		},
	}
	runtime := config.NewRuntimeSettingsFromConfig(cfg)
	runtime.UpdateRetention(7*24*time.Hour, 14*24*time.Hour)

	got := (&backgroundServices{cfg: cfg, runtime: runtime}).retentionSnapshot()
	if got.ScanLog != 7*24*time.Hour || got.AdminAuditLog != 14*24*time.Hour {
		t.Fatalf("live retention = scan:%s admin:%s, want 168h/336h", got.ScanLog, got.AdminAuditLog)
	}
	if got.Interval != cfg.Retention.Interval || got.RefreshQueue != cfg.Retention.RefreshQueue || got.PackageCheckStatus != cfg.Retention.PackageCheckStatus {
		t.Fatalf("non-admin retention changed: got %+v, want config %+v", got, cfg.Retention)
	}
}

func TestRunAuditRetentionOnceUsesBackgroundForNilContext(t *testing.T) {
	t.Parallel()

	store := &deadlineCapturingAuditRetentionStore{}
	runAuditRetentionOnce(nil, config.RetentionConfig{ScanLog: time.Hour}, config.FeedsConfig{}, store, nil) //nolint:staticcheck // SA1012: the nil-context fallback is under test.

	if len(store.calls) != 1 {
		t.Fatalf("prune calls = %d, want 1", len(store.calls))
	}
	if store.calls[0].name != "scan_log" {
		t.Fatalf("prune table = %q, want scan_log", store.calls[0].name)
	}
	if _, ok := store.calls[0].ctx.Deadline(); !ok {
		t.Fatal("nil caller context did not receive the bounded prune deadline")
	}
}

type auditRetentionWorkerStore struct {
	*noopStore
	scanCalls int
}

type runtimeUpdatingAuditRetentionCall struct {
	name      string
	retention time.Duration
}

type runtimeUpdatingAuditRetentionStore struct {
	*noopStore
	mu    sync.Mutex
	calls []runtimeUpdatingAuditRetentionCall
}

func (s *runtimeUpdatingAuditRetentionStore) record(name string, retention time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, runtimeUpdatingAuditRetentionCall{name: name, retention: retention})
	return 0, nil
}

func (s *runtimeUpdatingAuditRetentionStore) snapshot() []runtimeUpdatingAuditRetentionCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]runtimeUpdatingAuditRetentionCall(nil), s.calls...)
}

func (s *runtimeUpdatingAuditRetentionStore) PruneScanLogs(_ context.Context, retention time.Duration) (int, error) {
	return s.record("scan_log", retention)
}

func (s *runtimeUpdatingAuditRetentionStore) PruneAdminAuditLogs(_ context.Context, retention time.Duration) (int, error) {
	return s.record("admin_audit_log", retention)
}

func (s *runtimeUpdatingAuditRetentionStore) PruneRefreshQueue(_ context.Context, retention time.Duration) (int, error) {
	return s.record("refresh_queue", retention)
}

func (s *runtimeUpdatingAuditRetentionStore) PrunePackageCheckStatus(_ context.Context, retention time.Duration) (int, error) {
	return s.record("package_check_status", retention)
}

func (s *runtimeUpdatingAuditRetentionStore) PrunePackageReputation(_ context.Context, _ string, retention time.Duration) (int, error) {
	return s.record("package_reputation_cache", retention)
}

func (s *auditRetentionWorkerStore) PruneScanLogs(ctx context.Context, retention time.Duration) (int, error) {
	s.scanCalls++
	return s.noopStore.PruneScanLogs(ctx, retention)
}

type auditRetentionResult struct {
	rows int
	err  error
}

type auditRetentionLifecycleStore struct {
	calls    []string
	cancel   context.CancelFunc
	cancelAt string
	results  map[string]auditRetentionResult
}

func (s *auditRetentionLifecycleStore) prune(name string) (int, error) {
	s.calls = append(s.calls, name)
	if s.cancel != nil && s.cancelAt == name {
		s.cancel()
	}
	result := s.results[name]
	return result.rows, result.err
}

func (s *auditRetentionLifecycleStore) PruneScanLogs(context.Context, time.Duration) (int, error) {
	return s.prune("scan_log")
}

func (s *auditRetentionLifecycleStore) PruneAdminAuditLogs(context.Context, time.Duration) (int, error) {
	return s.prune("admin_audit_log")
}

func (s *auditRetentionLifecycleStore) PruneRefreshQueue(context.Context, time.Duration) (int, error) {
	return s.prune("refresh_queue")
}

func (s *auditRetentionLifecycleStore) PrunePackageCheckStatus(context.Context, time.Duration) (int, error) {
	return s.prune("package_check_status")
}

func (s *auditRetentionLifecycleStore) PrunePackageReputation(context.Context, string, time.Duration) (int, error) {
	return s.prune("package_reputation_cache")
}

func decodeAuditRetentionJSONLogs(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}

	lines := bytes.Split(trimmed, []byte{'\n'})
	entries := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("audit retention log is not JSON: %v; log=%q", err, line)
		}
		entries = append(entries, entry)
	}
	return entries
}

type panickingScanAuditRetentionStore struct {
	auditRetentionTestStore
}

func (s *panickingScanAuditRetentionStore) PruneScanLogs(context.Context, time.Duration) (int, error) {
	s.scanCalls++
	panic("scan retention panic")
}

type deadlineCapturingAuditRetentionStore struct {
	calls []deadlineCapturingAuditRetentionCall
}

type deadlineCapturingAuditRetentionCall struct {
	name string
	ctx  context.Context
}

func (s *deadlineCapturingAuditRetentionStore) record(name string, ctx context.Context) (int, error) {
	s.calls = append(s.calls, deadlineCapturingAuditRetentionCall{name: name, ctx: ctx})
	return 0, nil
}

func (s *deadlineCapturingAuditRetentionStore) PruneScanLogs(ctx context.Context, _ time.Duration) (int, error) {
	return s.record("scan_log", ctx)
}

func (s *deadlineCapturingAuditRetentionStore) PruneAdminAuditLogs(ctx context.Context, _ time.Duration) (int, error) {
	return s.record("admin_audit_log", ctx)
}

func (s *deadlineCapturingAuditRetentionStore) PruneRefreshQueue(ctx context.Context, _ time.Duration) (int, error) {
	return s.record("refresh_queue", ctx)
}

func (s *deadlineCapturingAuditRetentionStore) PrunePackageCheckStatus(ctx context.Context, _ time.Duration) (int, error) {
	return s.record("package_check_status", ctx)
}

func (s *deadlineCapturingAuditRetentionStore) PrunePackageReputation(ctx context.Context, _ string, _ time.Duration) (int, error) {
	return s.record("package_reputation_cache", ctx)
}
