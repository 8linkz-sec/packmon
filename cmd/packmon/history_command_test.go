package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
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
	if !strings.Contains(output, `Cleared 1 scan history entry for repo "app" before 2026-01-01 UTC.`) {
		t.Fatalf("history clear output = %q", output)
	}

	verifyStore, _ := newTestSQLiteStore(t, dbDir)
	entries, err := verifyStore.GetRecentScans(context.Background(), "", -1)
	if err != nil {
		t.Fatalf("get remaining history: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("remaining history rows = %d, want 2", len(entries))
	}
	for _, entry := range entries {
		if entry.RepoName == "app" && entry.ScannedAt.Equal(time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)) {
			t.Fatalf("deleted app entry remains: %+v", entry)
		}
	}
	if entries[0].RepoName != "app" || !entries[0].ScannedAt.Equal(time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("first remaining entry = %+v, want newer app entry", entries[0])
	}
	if entries[1].RepoName != "other" || !entries[1].ScannedAt.Equal(time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("second remaining entry = %+v, want other repo entry", entries[1])
	}
}

func TestHistoryClearCommandRequiresForceForUnfilteredDelete(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	insertHistoryEntry(t, store, "app", time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC))
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	cmd := newHistoryClearCmd()
	cmd.SetArgs([]string{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	if err == nil {
		t.Fatal("history clear without filters/force error = nil")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Fatalf("history clear unfiltered error = %v, want --force guidance", err)
	}

	verifyStore, _ := newTestSQLiteStore(t, dbDir)
	var count int
	if err := verifyStore.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM scan_history`).Scan(&count); err != nil {
		t.Fatalf("count history rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("remaining history rows = %d, want 1", count)
	}
}

func TestHistoryClearCommandForceAllowsUnfilteredDelete(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	insertHistoryEntry(t, store, "app", time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC))
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	cmd := newHistoryClearCmd()
	cmd.SetArgs([]string{"--force"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("history clear --force: %v", err)
		}
	})
	if !strings.Contains(output, "Cleared 1 scan history entry.") {
		t.Fatalf("history clear --force output = %q", output)
	}

	verifyStore, _ := newTestSQLiteStore(t, dbDir)
	var count int
	if err := verifyStore.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM scan_history`).Scan(&count); err != nil {
		t.Fatalf("count history rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("remaining history rows after --force = %d, want 0", count)
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

func TestHistoryClearCommandSanitizesRepoFilter(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	cmd := newHistoryClearCmd()
	cmd.SetArgs([]string{"--repo", "repo\x1b\n::warning::spoof"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("history clear: %v", err)
		}
	})

	if strings.Contains(output, "\x1b") || strings.Contains(output, "\n::warning::") {
		t.Fatalf("history clear output contains raw terminal controls:\n%s", output)
	}
	if !strings.Contains(output, `\x1B`) || !strings.Contains(output, `\n::warning::spoof`) {
		t.Fatalf("history clear output missing sanitized repo:\n%s", output)
	}
}

func TestHistoryClearCommandConfigErrorDoesNotDeleteHistory(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	insertHistoryEntry(t, store, "app", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	t.Setenv("PACKMON_DB_PATH", "")
	if err := os.WriteFile(defaultCLIConfigFile, []byte("db: ["), 0o600); err != nil {
		t.Fatalf("write malformed project config: %v", err)
	}
	cmd := newHistoryClearCmd()
	cmd.SetArgs([]string{"--repo", "app"})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var commandErr error
	output := captureStdout(t, func() { commandErr = cmd.Execute() })
	if commandErr == nil || !strings.Contains(commandErr.Error(), "parse "+defaultCLIConfigFile) {
		t.Fatalf("history clear config error = %v, want parse context", commandErr)
	}
	if strings.Contains(output, "Cleared") {
		t.Fatalf("history clear config error output = %q, want no success message", output)
	}

	verifyStore, _ := newTestSQLiteStore(t, dbDir)
	entries, err := verifyStore.GetRecentScans(context.Background(), "", -1)
	if err != nil {
		t.Fatalf("get history after config error: %v", err)
	}
	if len(entries) != 1 || entries[0].RepoName != "app" {
		t.Fatalf("history after config error = %+v, want original app entry", entries)
	}
}

func TestHistoryClearCommandReportsDatabaseOpenError(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	notADirectory := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notADirectory, []byte("file"), 0o600); err != nil {
		t.Fatalf("write database-path file: %v", err)
	}
	t.Setenv("PACKMON_DB_PATH", notADirectory)

	cmd := newHistoryClearCmd()
	cmd.SetArgs([]string{"--repo", "app"})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var commandErr error
	output := captureStdout(t, func() { commandErr = cmd.Execute() })
	if commandErr == nil || !strings.Contains(commandErr.Error(), "open local database") {
		t.Fatalf("history clear database-open error = %v, want open local database context", commandErr)
	}
	if strings.Contains(output, "Cleared") {
		t.Fatalf("history clear database-open output = %q, want no success message", output)
	}
}

func TestHistoryClearCommandCancellationDoesNotDeleteHistory(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	insertHistoryEntry(t, store, "app", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := newHistoryClearCmd()
	cmd.SetArgs([]string{"--repo", "app"})
	cmd.SetContext(ctx)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var commandErr error
	output := captureStdout(t, func() { commandErr = cmd.Execute() })
	if commandErr == nil || !strings.Contains(commandErr.Error(), "clear scan history") {
		t.Fatalf("history clear cancellation error = %v, want clear scan history context", commandErr)
	}
	if strings.Contains(output, "Cleared") {
		t.Fatalf("history clear cancellation output = %q, want no success message", output)
	}

	verifyStore, _ := newTestSQLiteStore(t, dbDir)
	entries, err := verifyStore.GetRecentScans(context.Background(), "", -1)
	if err != nil {
		t.Fatalf("get history after cancellation: %v", err)
	}
	if len(entries) != 1 || entries[0].RepoName != "app" {
		t.Fatalf("history after cancellation = %+v, want original app entry", entries)
	}
}

func TestHistoryClearCommandKeepsExactUTCCutoff(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	insertHistoryEntry(t, store, "older", time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC))
	insertHistoryEntry(t, store, "cutoff", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	cmd := newHistoryClearCmd()
	cmd.SetArgs([]string{"--before", "2026-01-01"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("history clear before cutoff: %v", err)
		}
	})
	if !strings.Contains(output, "Cleared 1 scan history entry before 2026-01-01 UTC.") {
		t.Fatalf("history clear cutoff output = %q", output)
	}

	verifyStore, _ := newTestSQLiteStore(t, dbDir)
	entries, err := verifyStore.GetRecentScans(context.Background(), "", -1)
	if err != nil {
		t.Fatalf("get history after cutoff: %v", err)
	}
	if len(entries) != 1 || entries[0].RepoName != "cutoff" || !entries[0].ScannedAt.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("history after cutoff = %+v, want exact-cutoff row", entries)
	}
}

func TestHistoryClearCommandReportsZeroAndPluralCounts(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	insertHistoryEntry(t, store, "app", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	insertHistoryEntry(t, store, "app", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	zeroCmd := newHistoryClearCmd()
	zeroCmd.SetArgs([]string{"--repo", "missing"})
	zeroOutput := captureStdout(t, func() {
		if err := zeroCmd.Execute(); err != nil {
			t.Fatalf("history clear zero count: %v", err)
		}
	})
	if !strings.Contains(zeroOutput, `Cleared 0 scan history entries for repo "missing".`) {
		t.Fatalf("history clear zero output = %q", zeroOutput)
	}

	pluralCmd := newHistoryClearCmd()
	pluralCmd.SetArgs([]string{"--repo", "app"})
	pluralOutput := captureStdout(t, func() {
		if err := pluralCmd.Execute(); err != nil {
			t.Fatalf("history clear plural count: %v", err)
		}
	})
	if !strings.Contains(pluralOutput, `Cleared 2 scan history entries for repo "app".`) {
		t.Fatalf("history clear plural output = %q", pluralOutput)
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
