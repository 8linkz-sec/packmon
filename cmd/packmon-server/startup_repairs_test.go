package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type startupRepairStub struct {
	repaired           int
	err                error
	called             bool
	packetStormRemoved int
	packetStormErr     error
	packetStormCalled  bool
}

func (s *startupRepairStub) RepairGHSAAffectedPackages(context.Context) (int, error) {
	s.called = true
	return s.repaired, s.err
}

func (s *startupRepairStub) RemovePacketStormReferences(context.Context) (int, error) {
	s.packetStormCalled = true
	return s.packetStormRemoved, s.packetStormErr
}

func TestRunStartupRepairs_BackfillsWhenSupported(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := &startupRepairStub{repaired: 3}

	runStartupRepairs(context.Background(), store, logger)

	if !store.called {
		t.Fatal("expected startup repair to run")
	}
	if !store.packetStormCalled {
		t.Fatal("expected Packet Storm cleanup to run")
	}
	if !strings.Contains(logs.String(), "backfilled GHSA affected packages") {
		t.Fatalf("expected backfill log, got %q", logs.String())
	}
}

func TestRunStartupRepairs_LogsWarningOnFailure(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := &startupRepairStub{err: errors.New("boom")}

	runStartupRepairs(context.Background(), store, logger)

	if !store.called {
		t.Fatal("expected startup repair to run")
	}
	if !strings.Contains(logs.String(), "failed to backfill GHSA affected packages") {
		t.Fatalf("expected warning log, got %q", logs.String())
	}
}

func TestRunStartupRepairs_RemovesPacketStormReferencesWhenSupported(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := &startupRepairStub{packetStormRemoved: 5}

	runStartupRepairs(context.Background(), store, logger)

	if !store.packetStormCalled {
		t.Fatal("expected Packet Storm cleanup to run")
	}
	if !strings.Contains(logs.String(), "removed Packet Storm references") {
		t.Fatalf("expected cleanup log, got %q", logs.String())
	}
}

func TestRunStartupRepairs_SkipsUnsupportedStore(t *testing.T) {
	t.Parallel()

	runStartupRepairs(context.Background(), struct{}{}, nil)
}
