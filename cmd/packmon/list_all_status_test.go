package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// TestWriteListAllTerminalFindingStatusMessagesWarnsAboutAStaleLocalDB covers the
// banner that tells the user their offline results may be incomplete. Losing it
// would let a stale local database look like a clean scan.
func TestWriteListAllTerminalFindingStatusMessagesWarnsAboutAStaleLocalDB(t *testing.T) {
	t.Parallel()

	ageDays := 12
	var buf bytes.Buffer
	if err := writeListAllTerminalFindingStatusMessages(&buf, &domain.ScanResult{
		Mode:      domain.ScanModeLocal,
		DBStale:   true,
		DBAgeDays: &ageDays,
	}); err != nil {
		t.Fatalf("writeListAllTerminalFindingStatusMessages: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "ATTENTION") {
		t.Fatalf("output = %q, want the stale-database attention banner", out)
	}
	if !strings.Contains(out, "12 days") {
		t.Fatalf("output = %q, want the database age named", out)
	}
	if !strings.Contains(out, "packmon db sync") {
		t.Fatalf("output = %q, want the remediation command", out)
	}
}

// TestWriteListAllTerminalFindingStatusMessagesPrefersTheScanError covers the
// precedence rule: a scan that failed reports its own error rather than the
// generic degraded-feed wording, which would understate the problem.
func TestWriteListAllTerminalFindingStatusMessagesPrefersTheScanError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := writeListAllTerminalFindingStatusMessages(&buf, &domain.ScanResult{
		ScanError:  "  server rejected the API key  ",
		FeedStatus: string(domain.ScanFeedStatusDegraded),
	}); err != nil {
		t.Fatalf("writeListAllTerminalFindingStatusMessages: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "server rejected the API key") {
		t.Fatalf("output = %q, want the scan error surfaced", out)
	}
	if strings.Contains(out, "degraded") {
		t.Fatalf("output = %q, want the scan error to win over the feed status", out)
	}
}

// TestWriteListAllTerminalFindingStatusMessagesReportsDegradedFeeds covers the
// fallback: without a scan error, a degraded feed status still has to reach the
// user, because it means the findings were matched against incomplete data.
func TestWriteListAllTerminalFindingStatusMessagesReportsDegradedFeeds(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := writeListAllTerminalFindingStatusMessages(&buf, &domain.ScanResult{
		Mode:       domain.ScanModeRemote,
		FeedStatus: string(domain.ScanFeedStatusDegraded),
	}); err != nil {
		t.Fatalf("writeListAllTerminalFindingStatusMessages: %v", err)
	}
	if !strings.Contains(buf.String(), "WARN") {
		t.Fatalf("output = %q, want a degraded-feed warning", buf.String())
	}
}

// TestWriteListAllTerminalFindingStatusMessagesStaysSilentOnAHealthyScan keeps
// the report free of banners when there is nothing to report -- a permanent
// warning trains users to ignore all of them.
func TestWriteListAllTerminalFindingStatusMessagesStaysSilentOnAHealthyScan(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := writeListAllTerminalFindingStatusMessages(&buf, &domain.ScanResult{
		Mode:       domain.ScanModeRemote,
		FeedStatus: string(domain.ScanFeedStatusHealthy),
	}); err != nil {
		t.Fatalf("writeListAllTerminalFindingStatusMessages: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("healthy scan produced %q, want no status output", buf.String())
	}

	// A missing result is not an error either; there is simply nothing to say.
	buf.Reset()
	if err := writeListAllTerminalFindingStatusMessages(&buf, nil); err != nil {
		t.Fatalf("writeListAllTerminalFindingStatusMessages(nil) = %v, want no error", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("nil result produced %q, want no status output", buf.String())
	}
}

// TestWriteListAllSecurityFindingsReportsAnIncompleteScan covers the branch where
// the scan never produced a result. The section must say so explicitly rather
// than render an empty finding table, which reads as "nothing found".
func TestWriteListAllSecurityFindingsReportsAnIncompleteScan(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := writeListAllSecurityFindings(&buf, nil, domain.SeverityHigh, listAllPackageReport{}, true); err != nil {
		t.Fatalf("writeListAllSecurityFindings: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Security Findings") {
		t.Fatalf("output = %q, want the section heading", out)
	}
	if !strings.Contains(out, "did not complete") {
		t.Fatalf("output = %q, want the incomplete scan stated explicitly", out)
	}
}

// TestWriteListAllSecurityFindingsGroupsFindingsIntoSections covers the normal
// path: findings are grouped under their category heading with a count, so a
// malicious package cannot be lost among vulnerabilities.
func TestWriteListAllSecurityFindingsGroupsFindingsIntoSections(t *testing.T) {
	t.Parallel()

	result := &domain.ScanResult{
		Mode:       domain.ScanModeRemote,
		FeedStatus: string(domain.ScanFeedStatusHealthy),
		Findings: []domain.Finding{
			{
				Name:       "evil-pkg",
				Version:    "1.0.0",
				Ecosystem:  domain.Ecosystem("npm"),
				Type:       domain.FindingTypeMalicious,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "MAL-1",
				Title:      "malicious package",
				Source:     "socket",
			},
			{
				Name:       "left-pad",
				Version:    "1.0.0",
				Ecosystem:  domain.Ecosystem("npm"),
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "GHSA-1",
				Title:      "regex denial of service",
				Source:     "osv",
			},
		},
	}

	var buf bytes.Buffer
	if err := writeListAllSecurityFindings(&buf, result, domain.SeverityHigh, listAllPackageReport{}, true); err != nil {
		t.Fatalf("writeListAllSecurityFindings: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Malicious (1)", "Vulnerabilities (1)", "evil-pkg", "left-pad", "MAL-1", "GHSA-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// No-colour output must carry no escape sequences.
	if strings.Contains(out, "\033") {
		t.Errorf("no-colour output still contains escape codes:\n%q", out)
	}
}

// TestSleepWithContextReturnsEarlyOnCancellation covers the wait used between
// registry requests. A cancelled scan must stop waiting immediately, otherwise
// Ctrl-C would appear to hang for the length of the throttle interval.
func TestSleepWithContextReturnsEarlyOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if sleepWithContext(ctx, time.Hour) {
		t.Fatal("sleepWithContext(cancelled) = true, want false")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancelled sleep took %v, want an immediate return", elapsed)
	}
}

// TestSleepWithContextCompletesAShortWait is the positive counterpart: an
// uncancelled wait has to run to completion and report success.
func TestSleepWithContextCompletesAShortWait(t *testing.T) {
	t.Parallel()

	if !sleepWithContext(context.Background(), time.Millisecond) {
		t.Fatal("sleepWithContext(1ms) = false, want a completed wait")
	}
}

// TestRegistryThrottleSleepWithContextSkipsNonPositiveDurations keeps the
// throttle from arming a timer when there is nothing to wait for, and honours an
// injected sleep so tests never wait on the real clock.
func TestRegistryThrottleSleepWithContextSkipsNonPositiveDurations(t *testing.T) {
	t.Parallel()

	called := false
	throttle := &registryThrottle{sleep: func(context.Context, time.Duration) bool {
		called = true
		return true
	}}

	for _, d := range []time.Duration{0, -time.Second} {
		if !throttle.sleepWithContext(context.Background(), d) {
			t.Fatalf("sleepWithContext(%v) = false, want an immediate success", d)
		}
	}
	if called {
		t.Fatal("a non-positive duration still invoked the sleep function")
	}

	if !throttle.sleepWithContext(context.Background(), time.Millisecond) {
		t.Fatal("sleepWithContext(1ms) = false, want the injected sleep's result")
	}
	if !called {
		t.Fatal("a positive duration did not reach the injected sleep function")
	}
}
