package scanner

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestScanArtifactDiagnosticsWarnsWhenLocalDBFreshnessUnknown(t *testing.T) {
	t.Parallel()

	result := &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 1,
		DBStale:         true,
		FeedStatus:      "healthy",
	}

	diagnostics := scanArtifactDiagnostics(result)
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(diagnostics))
	}
	if diagnostics[0].Level != "warning" {
		t.Fatalf("diagnostic level = %q, want warning", diagnostics[0].Level)
	}
	if !strings.Contains(diagnostics[0].Message, "Local database freshness could not be verified") {
		t.Fatalf("diagnostic message = %q, want unknown freshness warning", diagnostics[0].Message)
	}
}

func TestReportWarningsIncludesSharedWarningsAndParseErrors(t *testing.T) {
	t.Parallel()

	result := &domain.ScanResult{
		Mode:            domain.ScanModeLocal,
		FeedStatus:      "degraded",
		PackagesScanned: 1,
		DBStale:         true,
		ParseErrors:     []string{" ", "bad lockfile"},
	}

	warnings := ReportWarnings(result)
	want := []string{
		DegradedFeedStatusWarning(domain.ScanModeLocal),
		"Local database freshness could not be verified. Results may be incomplete. Update with: packmon db sync.",
		"Some dependency inventory could not be evaluated: bad lockfile",
	}
	if len(warnings) != len(want) {
		t.Fatalf("warnings = %#v, want %#v", warnings, want)
	}
	for i := range want {
		if warnings[i] != want[i] {
			t.Fatalf("warnings[%d] = %q, want %q\nall warnings: %#v", i, warnings[i], want[i], warnings)
		}
	}
}

func TestReportWarningsKeepsOperationalStatusSeparate(t *testing.T) {
	t.Parallel()

	warnings := ReportWarnings(&domain.ScanResult{
		Mode:            domain.ScanModeRemote,
		PackagesScanned: 1,
		FeedStatus:      "error",
		ScanError:       "remote check failed",
	})
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none because operational status is rendered separately", warnings)
	}
}
