package main

import (
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
)

// TestNormalizeDockerRegistryMirrorSourceHostAcceptsOnlyKnownRegistries pins the
// allowlist for mirror source hosts. The mirror map redirects digest lookups, so
// an arbitrary host here would let a config file silently reroute image checks.
func TestNormalizeDockerRegistryMirrorSourceHostAcceptsOnlyKnownRegistries(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"ghcr.io", "GHCR.IO", "  ghcr.io.  ", "registry-1.docker.io:443",
		"gcr.io", "quay.io", "public.ecr.aws", "mcr.microsoft.com",
		"registry.k8s.io", "registry.gitlab.com", "eu.gcr.io", "us.gcr.io", "asia.gcr.io",
	} {
		host, err := normalizeDockerRegistryMirrorSourceHost("mirror", raw)
		if err != nil {
			t.Errorf("normalizeDockerRegistryMirrorSourceHost(%q) error = %v", raw, err)
			continue
		}
		if host == "" {
			t.Errorf("normalizeDockerRegistryMirrorSourceHost(%q) returned an empty host", raw)
		}
		if host != strings.ToLower(host) {
			t.Errorf("normalizeDockerRegistryMirrorSourceHost(%q) = %q, want a lower-cased host", raw, host)
		}
	}
}

// TestNormalizeDockerRegistryMirrorSourceHostRejectsUnknownHosts is the security
// half: anything outside the allowlist, including an empty value, must be an
// error that names the offending input.
func TestNormalizeDockerRegistryMirrorSourceHostRejectsUnknownHosts(t *testing.T) {
	t.Parallel()

	if _, err := normalizeDockerRegistryMirrorSourceHost("mirror", "   "); err == nil {
		t.Error("an empty source host was accepted")
	}
	for _, raw := range []string{"evil.example", "localhost", "169.254.169.254", "docker.io.evil.example"} {
		if _, err := normalizeDockerRegistryMirrorSourceHost("mirror", raw); err == nil {
			t.Errorf("normalizeDockerRegistryMirrorSourceHost(%q) = nil error, want a rejection", raw)
		}
	}
}

// TestNormalizeDockerRegistryMirrorBaseURLBlocksNonRoutableTargets covers the
// SSRF guard on the mirror target. A mirror pointing at a link-local address is
// how a cloud metadata endpoint gets reached from a config file.
func TestNormalizeDockerRegistryMirrorBaseURLBlocksNonRoutableTargets(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://169.254.169.254",
		"https://[fe80::1]",
		"https://0.0.0.0",
		"https://[::]",
		"https://224.0.0.1",
	} {
		if _, err := normalizeDockerRegistryMirrorBaseURL("mirror", raw); err == nil {
			t.Errorf("normalizeDockerRegistryMirrorBaseURL(%q) = nil error, want a rejection", raw)
		}
	}
}

// TestNormalizeDockerRegistryMirrorBaseURLAcceptsRoutableHTTPS is the positive
// counterpart, and also pins the inherited URL rules: https is required off
// loopback, and a trailing slash is normalised away so joins stay predictable.
func TestNormalizeDockerRegistryMirrorBaseURLAcceptsRoutableHTTPS(t *testing.T) {
	t.Parallel()

	got, err := normalizeDockerRegistryMirrorBaseURL("mirror", "https://mirror.internal/v2/")
	if err != nil {
		t.Fatalf("normalizeDockerRegistryMirrorBaseURL: %v", err)
	}
	if got != "https://mirror.internal/v2" {
		t.Fatalf("normalized = %q, want the trailing slash removed", got)
	}

	if _, err := normalizeDockerRegistryMirrorBaseURL("mirror", "http://mirror.internal"); err == nil {
		t.Error("plain http to a non-loopback host was accepted")
	}
	// A public IP literal is routable and must pass the IP guard.
	if _, err := normalizeDockerRegistryMirrorBaseURL("mirror", "https://93.184.216.34"); err != nil {
		t.Errorf("a routable IP mirror was rejected: %v", err)
	}
}

// TestWriteReportTableRendersEveryScanRow covers the local history table. The
// repo column falls back to a placeholder for path-only scans, because an empty
// cell would misalign the table and hide which scan a row belongs to.
func TestWriteReportTableRendersEveryScanRow(t *testing.T) {
	t.Parallel()

	scannedAt := time.Date(2026, 8, 4, 9, 30, 0, 0, time.UTC)
	var buf strings.Builder
	if err := writeReportTable(&buf, []sqlite.ScanEntry{
		{RepoName: "packmon", ScannedAt: scannedAt, PackagesCount: 120, FindingsCount: 5},
		{RepoName: "", ScannedAt: scannedAt.Add(-24 * time.Hour), PackagesCount: 118, FindingsCount: 3},
	}); err != nil {
		t.Fatalf("writeReportTable: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"DATE", "REPO", "PACKAGES", "FINDINGS", "TREND", "packmon", "(local)", "120", "118"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
}

// TestWriteReportTableRendersTheTrendColumn pins the trend marker, which is the
// only part of the row that compares against the previous scan. A wrong sign
// would tell the user findings fell when they rose.
func TestWriteReportTableRendersTheTrendColumn(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 4, 9, 30, 0, 0, time.UTC)
	entries := []sqlite.ScanEntry{
		{RepoName: "up", ScannedAt: now, FindingsCount: 9},
		{RepoName: "down", ScannedAt: now.Add(-time.Hour), FindingsCount: 4},
		{RepoName: "flat", ScannedAt: now.Add(-2 * time.Hour), FindingsCount: 7},
		{RepoName: "oldest", ScannedAt: now.Add(-3 * time.Hour), FindingsCount: 7},
	}

	// Entries are newest-first, so each row compares against the one below it.
	if got := reportEntryTrend(entries, 0); got != "^ +5" {
		t.Errorf("rising trend = %q, want ^ +5", got)
	}
	if got := reportEntryTrend(entries, 1); got != "v 3" {
		t.Errorf("falling trend = %q, want v 3", got)
	}
	if got := reportEntryTrend(entries, 2); got != "= 0" {
		t.Errorf("unchanged trend = %q, want = 0", got)
	}
	// The oldest row has nothing to compare against.
	if got := reportEntryTrend(entries, 3); strings.TrimSpace(got) != "" {
		t.Errorf("oldest row trend = %q, want blank", got)
	}

	var buf strings.Builder
	if err := writeReportTable(&buf, entries); err != nil {
		t.Fatalf("writeReportTable: %v", err)
	}
	if !strings.Contains(buf.String(), "^ +5") {
		t.Errorf("rendered table lost the trend marker:\n%s", buf.String())
	}
}

// TestWriteReportTableHandlesAnEmptyHistory keeps the header on screen when there
// is nothing to show, so the output reads as "no scans yet" rather than blank.
func TestWriteReportTableHandlesAnEmptyHistory(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	if err := writeReportTable(&buf, nil); err != nil {
		t.Fatalf("writeReportTable(nil): %v", err)
	}
	if !strings.Contains(buf.String(), "DATE") {
		t.Fatalf("empty history produced %q, want the header row", buf.String())
	}
}
