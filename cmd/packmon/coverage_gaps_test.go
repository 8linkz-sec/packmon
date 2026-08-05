package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/spf13/cobra"
)

// TestDockerRegistryMirrorIPBlockedRejectsNonRoutableTargets guards the mirror
// allowlist: an operator-supplied Docker registry mirror must not be able to
// point the digest lookup at a link-local or unspecified address, which is how
// cloud metadata endpoints get reached.
func TestDockerRegistryMirrorIPBlockedRejectsNonRoutableTargets(t *testing.T) {
	t.Parallel()

	blocked := map[string]net.IP{
		"nil":                  nil,
		"link-local unicast":   net.ParseIP("169.254.169.254"),
		"link-local v6":        net.ParseIP("fe80::1"),
		"link-local multicast": net.ParseIP("224.0.0.1"),
		"multicast":            net.ParseIP("239.1.2.3"),
		"unspecified":          net.ParseIP("0.0.0.0"),
		"unspecified v6":       net.ParseIP("::"),
	}
	for name, ip := range blocked {
		if !dockerRegistryMirrorIPBlocked(ip) {
			t.Errorf("dockerRegistryMirrorIPBlocked(%s = %v) = false, want blocked", name, ip)
		}
	}

	allowed := map[string]net.IP{
		"public v4":  net.ParseIP("93.184.216.34"),
		"public v6":  net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
		"private v4": net.ParseIP("10.0.0.5"),
		"loopback":   net.ParseIP("127.0.0.1"),
	}
	for name, ip := range allowed {
		if dockerRegistryMirrorIPBlocked(ip) {
			t.Errorf("dockerRegistryMirrorIPBlocked(%s = %v) = true, want allowed", name, ip)
		}
	}
}

// TestLazyLocalCheckerReportsUnavailableAdvisoryData covers the lookup methods
// that only run in local mode. With no usable local database they must report
// the sentinel rather than a nil checker, so the scanner can degrade instead of
// panicking mid-scan.
func TestLazyLocalCheckerReportsUnavailableAdvisoryData(t *testing.T) {
	// Point the local database at an empty home so no advisory data is found.
	t.Setenv("PACKMON_DB_PATH", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	checker := &lazyLocalChecker{}
	// ensure() opens the SQLite file even when it holds no advisory data, so the
	// handle has to be released before the temp directory is removed.
	t.Cleanup(checker.close)
	ctx := context.Background()

	if _, err := checker.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0"); err == nil {
		t.Fatal("FindVulnerabilities error = nil, want unavailable advisory data")
	}
	if _, err := checker.FindMalicious(ctx, "npm", "evil", "1.0.0"); err == nil {
		t.Fatal("FindMalicious error = nil, want unavailable advisory data")
	}
	// The failure must be sticky: a second call returns the cached sentinel
	// rather than reopening the database on every package.
	if _, err := checker.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0"); !errors.Is(err, errLocalAdvisoryDataUnavailable) {
		t.Fatalf("second FindVulnerabilities error = %v, want the cached sentinel", err)
	}
	// The batch variants share the same lazy initialisation.
	if _, err := checker.FindVulnerabilitiesBatch(ctx, nil); !errors.Is(err, errLocalAdvisoryDataUnavailable) {
		t.Fatalf("FindVulnerabilitiesBatch error = %v, want the cached sentinel", err)
	}
	if _, err := checker.FindMaliciousBatch(ctx, nil); !errors.Is(err, errLocalAdvisoryDataUnavailable) {
		t.Fatalf("FindMaliciousBatch error = %v, want the cached sentinel", err)
	}
}

// TestScanHistoryRecordErrorUnwraps keeps the wrapper transparent to errors.Is
// and errors.As, and nil-safe: history recording is best-effort and its error
// travels alongside a successful scan.
func TestScanHistoryRecordErrorUnwraps(t *testing.T) {
	t.Parallel()

	inner := errors.New("history write failed")
	wrapped := &scanHistoryRecordError{err: inner}

	if !errors.Is(wrapped, inner) {
		t.Fatal("errors.Is could not see through scanHistoryRecordError")
	}
	if got := wrapped.Unwrap(); !errors.Is(got, inner) {
		t.Fatalf("Unwrap() = %v, want the wrapped error", got)
	}

	var nilErr *scanHistoryRecordError
	if got := nilErr.Unwrap(); got != nil {
		t.Fatalf("(*scanHistoryRecordError)(nil).Unwrap() = %v, want nil", got)
	}
	if got := nilErr.Error(); got != "" {
		t.Fatalf("(*scanHistoryRecordError)(nil).Error() = %q, want empty", got)
	}
}

// TestListAllTerminalSeverityColoursEverySeverity covers the colour mapping for
// all severities plus the no-colour path, so a new severity cannot silently
// render without its marker.
func TestListAllTerminalSeverityColoursEverySeverity(t *testing.T) {
	t.Parallel()

	for _, severity := range []domain.Severity{
		domain.SeverityCritical,
		domain.SeverityHigh,
		domain.SeverityMedium,
		domain.SeverityLow,
		domain.Severity("UNKNOWN"),
	} {
		coloured := listAllTerminalSeverity(severity, false)
		if !strings.Contains(coloured, string(severity)) {
			t.Errorf("listAllTerminalSeverity(%s) = %q, want the severity text retained", severity, coloured)
		}
		plain := listAllTerminalSeverity(severity, true)
		if plain != string(severity) {
			t.Errorf("listAllTerminalSeverity(%s, noColor) = %q, want the bare text", severity, plain)
		}
		if strings.Contains(plain, "\033") {
			t.Errorf("listAllTerminalSeverity(%s, noColor) = %q, want no escape codes", severity, plain)
		}
	}
}

// TestDBSyncFlagHelpersFallBackWithoutFlag covers the three flag readers used by
// `packmon db sync`. They must tolerate both a nil command and a command that
// never declared the flag, because the same helpers serve several subcommands.
func TestDBSyncFlagHelpersFallBackWithoutFlag(t *testing.T) {
	t.Parallel()

	if got, err := dbSyncStringFlag(nil, "server", "fallback"); err != nil || got != "fallback" {
		t.Fatalf("dbSyncStringFlag(nil) = %q, %v; want fallback", got, err)
	}
	if got, err := dbSyncBoolFlag(nil, "full", true); err != nil || !got {
		t.Fatalf("dbSyncBoolFlag(nil) = %v, %v; want true", got, err)
	}
	if got, err := dbSyncIntFlag(nil, "timeout", 42); err != nil || got != 42 {
		t.Fatalf("dbSyncIntFlag(nil) = %d, %v; want 42", got, err)
	}

	bare := &cobra.Command{Use: "bare"}
	if got, err := dbSyncStringFlag(bare, "server", "fallback"); err != nil || got != "fallback" {
		t.Fatalf("dbSyncStringFlag(undeclared) = %q, %v; want fallback", got, err)
	}
	if got, err := dbSyncBoolFlag(bare, "full", true); err != nil || !got {
		t.Fatalf("dbSyncBoolFlag(undeclared) = %v, %v; want true", got, err)
	}
	if got, err := dbSyncIntFlag(bare, "timeout", 42); err != nil || got != 42 {
		t.Fatalf("dbSyncIntFlag(undeclared) = %d, %v; want 42", got, err)
	}
}

// TestDBSyncFlagHelpersReadDeclaredValues is the positive counterpart: a
// declared flag must win over the fallback.
func TestDBSyncFlagHelpersReadDeclaredValues(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{Use: "sync"}
	cmd.Flags().String("server", "", "")
	cmd.Flags().Bool("full", false, "")
	cmd.Flags().Int("timeout", 0, "")
	if err := cmd.Flags().Set("server", "https://packmon.internal"); err != nil {
		t.Fatalf("set server: %v", err)
	}
	if err := cmd.Flags().Set("full", "true"); err != nil {
		t.Fatalf("set full: %v", err)
	}
	if err := cmd.Flags().Set("timeout", "90"); err != nil {
		t.Fatalf("set timeout: %v", err)
	}

	if got, err := dbSyncStringFlag(cmd, "server", "fallback"); err != nil || got != "https://packmon.internal" {
		t.Fatalf("dbSyncStringFlag = %q, %v; want the declared value", got, err)
	}
	if got, err := dbSyncBoolFlag(cmd, "full", false); err != nil || !got {
		t.Fatalf("dbSyncBoolFlag = %v, %v; want true", got, err)
	}
	if got, err := dbSyncIntFlag(cmd, "timeout", 30); err != nil || got != 90 {
		t.Fatalf("dbSyncIntFlag = %d, %v; want 90", got, err)
	}
}

// TestDBSyncFlagHelpersReportTypeMismatch covers the error path: asking for the
// wrong type must surface an error rather than a zero value that looks valid.
func TestDBSyncFlagHelpersReportTypeMismatch(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{Use: "sync"}
	cmd.Flags().String("full", "", "")
	cmd.Flags().String("timeout", "", "")
	cmd.Flags().Bool("server", false, "")

	if _, err := dbSyncBoolFlag(cmd, "full", true); err == nil {
		t.Fatal("dbSyncBoolFlag on a string flag error = nil, want a type mismatch")
	}
	if _, err := dbSyncIntFlag(cmd, "timeout", 30); err == nil {
		t.Fatal("dbSyncIntFlag on a string flag error = nil, want a type mismatch")
	}
	if _, err := dbSyncStringFlag(cmd, "server", "fallback"); err == nil {
		t.Fatal("dbSyncStringFlag on a bool flag error = nil, want a type mismatch")
	}
}
