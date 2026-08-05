package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// TestListAllRiskTypeLabelCoversEveryKnownRisk pins the label for every risk
// type the report can render. An unlabelled risk would surface as a raw enum
// token in a user-facing HTML table.
func TestListAllRiskTypeLabelCoversEveryKnownRisk(t *testing.T) {
	t.Parallel()

	for risk, want := range map[string]string{
		"":                            "-",
		"known_vulnerability":         "Known vulnerability",
		"malware":                     "Malware",
		domain.RiskTypeMalwareHistory: "Malware history",
		"removed_package":             "Removed package",
		"supply_chain":                "Supply-chain risk",
		"lifecycle":                   "Lifecycle",
		"eol":                         "End-of-life",
		"eol_soon":                    "End-of-life soon",
		"security_support_only":       "Security support only",
		"security_support_ended":      "Security support ended",
		"protestware":                 "Protestware",
		"typosquatting":               "Typosquatting",
		"other":                       "Other",
	} {
		if got := listAllRiskTypeLabel(risk); got != want {
			t.Errorf("listAllRiskTypeLabel(%q) = %q, want %q", risk, got, want)
		}
	}

	// Casing and padding must not defeat the lookup.
	if got := listAllRiskTypeLabel("  SUPPLY_CHAIN  "); got != "Supply-chain risk" {
		t.Errorf("listAllRiskTypeLabel(padded upper case) = %q, want the normalised label", got)
	}

	// An unknown token still has to render as something readable rather than
	// leaking the raw enum spelling.
	got := listAllRiskTypeLabel("brand_new_risk")
	if got == "" || strings.Contains(got, "_") {
		t.Errorf("listAllRiskTypeLabel(unknown) = %q, want a humanised fallback", got)
	}
}

// TestScanOutputConfigRequestsArtifact covers the decision that turns a config
// file's output block into an artifact write. Both halves have to hold: a path
// without a usable format writes nothing, and a format without a path likewise.
func TestScanOutputConfigRequestsArtifact(t *testing.T) {
	t.Parallel()

	if scanOutputConfigRequestsArtifact(cliOutputConfig{Format: "json", File: ""}) {
		t.Error("format without a file path requested an artifact")
	}
	if scanOutputConfigRequestsArtifact(cliOutputConfig{Format: "json", File: "   "}) {
		t.Error("blank file path requested an artifact")
	}
	if scanOutputConfigRequestsArtifact(cliOutputConfig{Format: "not-a-format", File: "out.txt"}) {
		t.Error("unknown format requested an artifact")
	}

	for _, format := range scanOutputArtifactFormats() {
		if !scanOutputConfigRequestsArtifact(cliOutputConfig{Format: format, File: "out." + format}) {
			t.Errorf("format %q with a path did not request an artifact", format)
		}
		if !scanOutputConfigRequestsArtifact(cliOutputConfig{Format: strings.ToUpper(format), File: "out"}) {
			t.Errorf("upper-case format %q did not request an artifact", format)
		}
	}
}

// TestLocalDashboardDBWarningStaysSilentOnFreshData covers the freshness banner
// the local dashboard renders. A database that was just created is not stale, so
// the dashboard must show no warning at all -- a permanent banner would train
// users to ignore it.
func TestLocalDashboardDBWarningStaysSilentOnFreshData(t *testing.T) {
	t.Parallel()

	store, _ := newTestSQLiteStore(t, t.TempDir())
	if got := localDashboardDBWarning(context.Background(), store, slog.New(slog.DiscardHandler)); got != "" {
		t.Fatalf("localDashboardDBWarning(fresh) = %q, want no warning", got)
	}
	// A nil logger must not turn the check into a panic.
	if got := localDashboardDBWarning(context.Background(), store, nil); got != "" {
		t.Fatalf("localDashboardDBWarning(nil logger) = %q, want no warning", got)
	}
}
