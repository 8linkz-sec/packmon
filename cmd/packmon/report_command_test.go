package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db/sqlite"
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
		"^ +2",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("report output missing %q:\n%s", want, output)
		}
	}
}

func insertReportEntry(t *testing.T, store *sqlite.Store, entry sqlite.ScanEntry) {
	t.Helper()

	if err := store.InsertScan(context.Background(), entry); err != nil {
		t.Fatalf("insert report entry: %v", err)
	}
}
