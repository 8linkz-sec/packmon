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
	audit           *db.AdminAuditEntry
}

func (s *startupAuditRepairStub) RepairCaseInsensitivePackageNames(context.Context) (int, error) {
	s.unauditedCalled = true
	return 0, nil
}

func (s *startupAuditRepairStub) RepairCaseInsensitivePackageNamesWithAudit(_ context.Context, audit *db.AdminAuditEntry) (int, error) {
	s.auditedCalled = true
	s.audit = audit
	return 7, nil
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
