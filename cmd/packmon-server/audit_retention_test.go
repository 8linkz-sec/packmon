package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
)

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
