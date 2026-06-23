package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
)

func TestReportCommandEmptyHistory(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close empty store: %v", err)
	}

	cmd := newReportCmd()
	cmd.SetArgs([]string{"--repo", "app"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("report command: %v", err)
		}
	})
	if !strings.Contains(output, "No scan history found.") || !strings.Contains(output, "filtered by repo: app") {
		t.Fatalf("empty report output = %q", output)
	}
}

func TestFormatReportTimestampUsesUTC(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 5, 30, 14, 15, 0, 0, time.FixedZone("CEST", 2*60*60))
	if got := formatReportTimestamp(ts); got != "2026-05-30 12:15 UTC" {
		t.Fatalf("formatReportTimestamp() = %q, want explicit UTC timestamp", got)
	}
	if got := formatReportTimestamp(time.Time{}); got != "" {
		t.Fatalf("formatReportTimestamp(zero) = %q, want empty", got)
	}
}

func TestReportCommandPrintsSummaryAndTrend(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)

	insertReportEntry(t, store, sqlite.ScanEntry{
		RepoName:          "app",
		ScannedAt:         time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
		PackagesCount:     5,
		FindingsCount:     3,
		FindingSeverities: []string{"CRITICAL", "HIGH", "HIGH"},
	})
	insertReportEntry(t, store, sqlite.ScanEntry{
		RepoName:          "app",
		ScannedAt:         time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
		PackagesCount:     4,
		FindingsCount:     1,
		FindingSeverities: []string{"LOW"},
	})
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	cmd := newReportCmd()
	cmd.SetArgs([]string{"--repo", "app", "--limit", "2"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("report command: %v", err)
		}
	})

	for _, want := range []string{
		"Packmon Security Report -- app",
		"Scans:     2",
		"Packages:  9",
		"Findings:  4",
		"CRITICAL",
		"HIGH",
		"LOW",
		"2026-05-30 12:00 UTC",
		"^ +2",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("report output missing %q:\n%s", want, output)
		}
	}
}

func TestReportCommandSanitizesRepoNames(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)

	insertReportEntry(t, store, sqlite.ScanEntry{
		RepoName:      "repo\x1b\n::warning::spoof",
		ScannedAt:     time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
		PackagesCount: 1,
		FindingsCount: 0,
	})
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	cmd := newReportCmd()
	cmd.SetArgs([]string{"--limit", "1"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("report command: %v", err)
		}
	})

	if strings.Contains(output, "\x1b") || strings.Contains(output, "\n::warning::") {
		t.Fatalf("report output contains raw terminal controls:\n%s", output)
	}
	if !strings.Contains(output, `repo\x1B\n::warning::spoof`) {
		t.Fatalf("report output missing sanitized repo:\n%s", output)
	}
}

func insertReportEntry(t *testing.T, store *sqlite.Store, entry sqlite.ScanEntry) {
	t.Helper()

	if err := store.InsertScan(context.Background(), entry); err != nil {
		t.Fatalf("insert report entry: %v", err)
	}
}
