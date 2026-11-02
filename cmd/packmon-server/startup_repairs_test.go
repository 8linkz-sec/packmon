package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type startupAuditRepairStub struct {
	auditedCalled   bool
	unauditedCalled bool
	auditedCalls    int
	unauditedCalls  int
	audit           *db.AdminAuditEntry
	auditedErr      error
}

func (s *startupAuditRepairStub) RepairCaseInsensitivePackageNames(context.Context) (int, error) {
	s.unauditedCalled = true
	s.unauditedCalls++
	return 0, nil
}

func (s *startupAuditRepairStub) RepairCaseInsensitivePackageNamesWithAudit(_ context.Context, audit *db.AdminAuditEntry) (int, error) {
	s.auditedCalled = true
	s.auditedCalls++
	s.audit = audit
	return 7, s.auditedErr
}

func TestRunStartupRepairs_UsesAuditedPackageNameRepairWhenSupported(t *testing.T) {
	t.Parallel()

	store := &startupAuditRepairStub{}

	runStartupRepairs(context.Background(), store, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	if !store.auditedCalled {
		t.Fatal("expected audited package-name normalization repair to run")
	}
	if store.unauditedCalled {
		t.Fatal("unaudited package-name normalization repair should not run when audited repair is supported")
	}
	if store.audit == nil {
		t.Fatal("expected startup repair audit entry")
	}
	if store.audit.Action != "startup_package_name_repair" {
		t.Fatalf("audit action = %q, want startup_package_name_repair", store.audit.Action)
	}
	var details map[string]string
	if err := json.Unmarshal(store.audit.Details, &details); err != nil {
		t.Fatalf("audit details are invalid JSON: %v", err)
	}
	if details["repair"] != "case_insensitive_package_names" {
		t.Fatalf("audit repair detail = %q, want case_insensitive_package_names", details["repair"])
	}
}

type startupRepairStub struct {
	repaired           int
	err                error
	called             bool
	packetStormRemoved int
	packetStormErr     error
	packetStormCalled  bool
	namesRepaired      int
	namesErr           error
	namesCalled        bool
	namesCalls         int
}

func (s *startupRepairStub) RepairGHSAAffectedPackages(context.Context) (int, error) {
	s.called = true
	return s.repaired, s.err
}

func (s *startupRepairStub) RemovePacketStormReferences(context.Context) (int, error) {
	s.packetStormCalled = true
	return s.packetStormRemoved, s.packetStormErr
}

func (s *startupRepairStub) RepairCaseInsensitivePackageNames(context.Context) (int, error) {
	s.namesCalled = true
	s.namesCalls++
	return s.namesRepaired, s.namesErr
}

func TestRunStartupRepairsSkipsGHSAAffectedPackageRepair(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := &startupRepairStub{repaired: 3, namesRepaired: 4}

	runStartupRepairs(context.Background(), store, logger)

	if store.called {
		t.Fatal("GHSA affected-package repair should not run during startup repairs")
	}
	if store.packetStormCalled {
		t.Fatal("Packet Storm cleanup should not run during startup repairs")
	}
	if !store.namesCalled {
		t.Fatal("expected package-name normalization repair to run")
	}
	if strings.Contains(logs.String(), "backfilled GHSA affected packages") {
		t.Fatalf("expected no GHSA backfill log, got %q", logs.String())
	}
}

func TestRunStartupRepairsSkipsGHSAAffectedPackageRepairFailures(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := &startupRepairStub{err: errors.New("boom")}

	runStartupRepairs(context.Background(), store, logger)

	if store.called {
		t.Fatal("GHSA affected-package repair should not run during startup repairs")
	}
	if strings.Contains(logs.String(), "failed to backfill GHSA affected packages") {
		t.Fatalf("expected no GHSA repair warning log, got %q", logs.String())
	}
}

func TestRunStartupRepairs_SkipsPacketStormReferencesWhenSupported(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := &startupRepairStub{packetStormRemoved: 5}

	runStartupRepairs(context.Background(), store, logger)

	if store.packetStormCalled {
		t.Fatal("Packet Storm cleanup should not run during startup repairs")
	}
	if strings.Contains(logs.String(), "removed Packet Storm references") {
		t.Fatalf("unexpected Packet Storm cleanup log, got %q", logs.String())
	}
}

func TestRunStartupRepairs_SkipsUnsupportedStore(t *testing.T) {
	t.Parallel()

	runStartupRepairs(context.Background(), struct{}{}, nil)
}

func TestRunStartupRepairs_NormalizesPackageNamesWhenSupported(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := &startupRepairStub{namesRepaired: 4}

	runStartupRepairs(context.Background(), store, logger)

	if !store.namesCalled {
		t.Fatal("expected package-name normalization repair to run")
	}
	if !strings.Contains(logs.String(), "normalized package names") {
		t.Fatalf("expected package-name repair log, got %q", logs.String())
	}
}

func TestRunStartupRepairs_LogsWarningOnPackageNameRepairFailure(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := &startupRepairStub{namesErr: errors.New("boom")}

	runStartupRepairs(context.Background(), store, logger)

	if !store.namesCalled {
		t.Fatal("expected package-name normalization repair to run")
	}
	if !strings.Contains(logs.String(), "failed to normalize package names") {
		t.Fatalf("expected package-name repair warning, got %q", logs.String())
	}
}

type blockingStartupRepairStore struct {
	hadDeadline bool
	ctxErr      error
}

func (s *blockingStartupRepairStore) RepairCaseInsensitivePackageNames(ctx context.Context) (int, error) {
	_, s.hadDeadline = ctx.Deadline()
	<-ctx.Done()
	s.ctxErr = ctx.Err()
	return 0, ctx.Err()
}

func TestRunStartupRepairsBoundsRepairContext(t *testing.T) {
	store := &blockingStartupRepairStore{}
	runStartupRepairsWithTimeout(context.Background(), store, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), 25*time.Millisecond)

	if !store.hadDeadline {
		t.Fatal("repair context had no deadline")
	}
	if err := store.ctxErr; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("repair context error = %v, want deadline exceeded", err)
	}
}

type startupRepairContextCapture struct {
	ctx context.Context
}

func (s *startupRepairContextCapture) RepairCaseInsensitivePackageNames(ctx context.Context) (int, error) {
	s.ctx = ctx
	return 0, nil
}

func TestRunStartupRepairsWithTimeoutNormalizesNilContextAndDefaultTimeout(t *testing.T) {
	t.Parallel()

	store := &startupRepairContextCapture{}
	before := time.Now()
	runStartupRepairsWithTimeout(nil, store, nil, 0) //nolint:staticcheck // SA1012: the nil-context fallback is under test.

	if store.ctx == nil {
		t.Fatal("repair received a nil context")
	}
	deadline, ok := store.ctx.Deadline()
	if !ok {
		t.Fatal("repair context had no deadline")
	}
	if remaining := deadline.Sub(before); remaining < startupRepairTimeout-time.Second || remaining > startupRepairTimeout+time.Second {
		t.Fatalf("repair deadline remaining = %v, want approximately %v", remaining, startupRepairTimeout)
	}
}

func TestRunStartupRepairsWithTimeoutDefaultsNegativeTimeout(t *testing.T) {
	t.Parallel()

	store := &startupRepairContextCapture{}
	before := time.Now().Add(startupRepairTimeout)
	runStartupRepairsWithTimeout(context.Background(), store, nil, -time.Second)
	after := time.Now().Add(startupRepairTimeout)

	if store.ctx == nil {
		t.Fatal("repair received a nil context")
	}
	deadline, ok := store.ctx.Deadline()
	if !ok {
		t.Fatal("repair context had no deadline")
	}
	if deadline.Before(before) || deadline.After(after) {
		t.Fatalf("repair deadline = %v, want within [%v, %v]", deadline, before, after)
	}
}

func TestRunPackageNameStartupRepairStructuredLogs(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))
		runPackageNameStartupRepair(context.Background(), time.Second, logger, func(context.Context) (int, error) {
			return 4, nil
		})

		var record map[string]any
		if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
			t.Fatalf("decode success log: %v; log = %q", err, logs.String())
		}
		if record["level"] != "INFO" {
			t.Fatalf("level = %v, want INFO", record["level"])
		}
		if record["msg"] != "startup repair: normalized package names" {
			t.Fatalf("msg = %v, want normalized-package success message", record["msg"])
		}
		if record["repaired"] != float64(4) {
			t.Fatalf("repaired = %v, want 4", record["repaired"])
		}
		if _, ok := record["error"]; ok {
			t.Fatalf("success log unexpectedly has error field: %v", record["error"])
		}
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))
		longError := errors.New(strings.Repeat("x", errorLogMaxBytes*2))
		runPackageNameStartupRepair(context.Background(), time.Second, logger, func(context.Context) (int, error) {
			return 9, longError
		})

		var record map[string]any
		if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
			t.Fatalf("decode failure log: %v; log = %q", err, logs.String())
		}
		if record["level"] != "WARN" {
			t.Fatalf("level = %v, want WARN", record["level"])
		}
		if record["msg"] != "startup repair: failed to normalize package names" {
			t.Fatalf("msg = %v, want package-name failure message", record["msg"])
		}
		if _, ok := record["repaired"]; ok {
			t.Fatalf("failure log unexpectedly has repaired field: %v", record["repaired"])
		}
		loggedError, ok := record["error"].(string)
		if !ok {
			t.Fatalf("error = %T(%v), want string", record["error"], record["error"])
		}
		if len(loggedError) > errorLogMaxBytes {
			t.Fatalf("logged error length = %d, want at most %d bytes", len(loggedError), errorLogMaxBytes)
		}
		if !strings.HasSuffix(loggedError, "...[truncated]") {
			t.Fatalf("logged error = %q, want truncation marker", loggedError)
		}
	})
}

func TestRunStartupRepairsWithNilLogger(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "failure", err: errors.New("repair failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &startupRepairStub{namesErr: tc.err}
			runStartupRepairs(context.Background(), store, nil)
			if store.namesCalls != 1 {
				t.Fatalf("repair callbacks = %d, want exactly one", store.namesCalls)
			}
		})
	}
}

func TestRunStartupRepairsAuditedFailureDoesNotFallback(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	store := &startupAuditRepairStub{auditedErr: errors.New("audited repair failed")}
	runStartupRepairs(context.Background(), store, slog.New(slog.NewJSONHandler(&logs, nil)))

	if store.auditedCalls != 1 {
		t.Fatalf("audited repair callbacks = %d, want exactly one", store.auditedCalls)
	}
	if store.unauditedCalls != 0 {
		t.Fatalf("unaudited repair callbacks = %d, want none", store.unauditedCalls)
	}
	if store.audit == nil {
		t.Fatal("audited repair received no audit entry")
	}
	if store.audit.Action != "startup_package_name_repair" {
		t.Fatalf("audit action = %q, want startup_package_name_repair", store.audit.Action)
	}
	var details map[string]string
	if err := json.Unmarshal(store.audit.Details, &details); err != nil {
		t.Fatalf("audit details are invalid JSON: %v", err)
	}
	if details["repair"] != "case_insensitive_package_names" {
		t.Fatalf("audit repair detail = %q, want case_insensitive_package_names", details["repair"])
	}

	var record map[string]any
	if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
		t.Fatalf("decode failure log: %v; log = %q", err, logs.String())
	}
	if record["level"] != "WARN" {
		t.Fatalf("level = %v, want WARN", record["level"])
	}
}
