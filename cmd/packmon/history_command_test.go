package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db/sqlite"
)

func TestHistoryClearCommandFiltersByRepoAndDate(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)

	insertHistoryEntry(t, store, "app", time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC))
	insertHistoryEntry(t, store, "app", time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC))
	insertHistoryEntry(t, store, "other", time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC))
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	cmd := newHistoryClearCmd()
	cmd.SetArgs([]string{"--repo", "app", "--before", "2026-01-01"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("history clear: %v", err)
		}
	})
	if !strings.Contains(output, `Cleared 1 scan history entry for repo "app" before 2026-01-01.`) {
		t.Fatalf("history clear output = %q", output)
	}

	verifyStore, _ := newTestSQLiteStore(t, dbDir)
	var count int
	if err := verifyStore.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM scan_history`).Scan(&count); err != nil {
		t.Fatalf("count history rows: %v", err)
	}
	if count != 2 {
		t.Fatalf("remaining history rows = %d, want 2", count)
	}
}

func TestHistoryClearCommandRejectsInvalidBeforeDate(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	cmd := newHistoryClearCmd()
	cmd.SetArgs([]string{"--before", "30-05-2026"})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	if err == nil {
		t.Fatal("history clear invalid --before error = nil")
	}
	if !strings.Contains(err.Error(), "parse --before") {
		t.Fatalf("history clear error = %v", err)
	}
}

func insertHistoryEntry(t *testing.T, store *sqlite.Store, repo string, scannedAt time.Time) {
	t.Helper()

	err := store.InsertScan(context.Background(), sqlite.ScanEntry{
		RepoName:      repo,
		ScannedAt:     scannedAt,
		PackagesCount: 1,
		FindingsCount: 1,
		FindingIDs:    []string{"GHSA-test"},
	})
	if err != nil {
		t.Fatalf("insert history entry: %v", err)
	}
}
