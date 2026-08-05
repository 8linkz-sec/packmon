package main

import (
	"bytes"
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

func TestSummarizeReportEntriesCountsReturnedScans(t *testing.T) {
	t.Parallel()

	summary := summarizeReportEntries([]sqlite.ScanEntry{
		{
			PackagesCount:     5,
			FindingsCount:     3,
			FindingSeverities: []string{"CRITICAL", "HIGH", "HIGH"},
		},
		{
			PackagesCount:     4,
			FindingsCount:     1,
			FindingSeverities: []string{"LOW"},
		},
		{
			PackagesCount:     2,
			FindingsCount:     1,
			FindingSeverities: []string{"UNKNOWN"},
		},
	})

	if summary.TotalScans != 3 || summary.TotalPackages != 11 || summary.TotalFindings != 5 {
		t.Fatalf("summary totals = scans %d packages %d findings %d, want 3, 11, 5",
			summary.TotalScans, summary.TotalPackages, summary.TotalFindings)
	}
	for sev, want := range map[string]int{
		"CRITICAL": 1,
		"HIGH":     2,
		"MEDIUM":   0,
		"LOW":      1,
		"UNKNOWN":  1,
	} {
		if got := summary.SeverityCounts[sev]; got != want {
			t.Fatalf("SeverityCounts[%q] = %d, want %d", sev, got, want)
		}
	}
}

func TestWriteReportTableRendersTrendAndSanitizesRepo(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := writeReportTable(&buf, []sqlite.ScanEntry{
		{
			RepoName:      "repo\x1b\n::warning::spoof",
			ScannedAt:     time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
			PackagesCount: 5,
			FindingsCount: 3,
		},
		{
			RepoName:      "repo",
			ScannedAt:     time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
			PackagesCount: 4,
			FindingsCount: 1,
		},
	})
	if err != nil {
		t.Fatalf("writeReportTable() error = %v", err)
	}

	output := buf.String()
	for _, want := range []string{
		"DATE",
		"REPO",
		"PACKAGES",
		"FINDINGS",
		"TREND",
		"2026-05-30 12:00 UTC",
		`repo\x1B\n::warning::spoof`,
		"^ +2",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("report table missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "\x1b") || strings.Contains(output, "\n::warning::") {
		t.Fatalf("report table contains raw terminal controls:\n%s", output)
	}
}

func TestRunReportCommandUsesInjectedDependenciesAndClosesStore(t *testing.T) {
	t.Parallel()

	store := &reportCommandTestStore{
		entries: []sqlite.ScanEntry{{
			RepoName:      "app",
			ScannedAt:     time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
			PackagesCount: 2,
			FindingsCount: 1,
		}},
	}
	var (
		openedPath string
		buf        bytes.Buffer
	)

	err := runReportCommand(context.Background(), reportCommandOptions{
		repo:  "app",
		limit: 2,
	}, reportCommandDeps{
		resolveDBPath: func() (string, error) {
			return "local.db", nil
		},
		openStore: func(path string) (reportScanStore, error) {
			openedPath = path
			return store, nil
		},
		output: &buf,
	})
	if err != nil {
		t.Fatalf("runReportCommand() error = %v", err)
	}

	if openedPath != "local.db" {
		t.Fatalf("opened path = %q, want local.db", openedPath)
	}
	if store.repo != "app" || store.limit != 2 {
		t.Fatalf("GetRecentScans(repo, limit) = %q, %d; want app, 2", store.repo, store.limit)
	}
	if !store.closed {
		t.Fatal("store was not closed")
	}
	if output := buf.String(); !strings.Contains(output, "Packmon Security Report -- app") {
		t.Fatalf("report output missing filtered header:\n%s", output)
	}
}

type reportCommandTestStore struct {
	entries []sqlite.ScanEntry
	repo    string
	limit   int
	closed  bool
}

func (s *reportCommandTestStore) GetRecentScans(_ context.Context, repo string, limit int) ([]sqlite.ScanEntry, error) {
	s.repo = repo
	s.limit = limit
	return s.entries, nil
}

func (s *reportCommandTestStore) Close() error {
	s.closed = true
	return nil
}

func insertReportEntry(t *testing.T, store *sqlite.Store, entry sqlite.ScanEntry) {
	t.Helper()

	if err := store.InsertScan(context.Background(), entry); err != nil {
		t.Fatalf("insert report entry: %v", err)
	}
}
