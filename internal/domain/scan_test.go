package domain

import "testing"

func TestBuildScanSummary(t *testing.T) {
	t.Parallel()

	findings := []Finding{
		{Severity: SeverityCritical, Type: FindingTypeVulnerability, Source: "osv"},
		{Severity: SeverityHigh, Type: FindingTypeVulnerability, Source: "osv"},
		{Severity: SeverityHigh, Type: FindingTypeVulnerability, Source: "ghsa"},
		{Severity: SeverityCritical, Type: FindingTypeMalicious, Source: "openssf"},
		{Severity: SeverityHigh, Type: FindingTypeSupplyChainRisk, RiskType: RiskTypeMalwareHistory, Source: "reversinglabs"},
	}

	summary := BuildScanSummary(findings)

	if summary.BySeverity["CRITICAL"] != 2 {
		t.Fatalf("BySeverity[CRITICAL] = %d, want 2", summary.BySeverity["CRITICAL"])
	}
	if summary.BySeverity["HIGH"] != 2 {
		t.Fatalf("BySeverity[HIGH] = %d, want 2", summary.BySeverity["HIGH"])
	}
	if summary.BySeverity["LOW"] != 1 {
		t.Fatalf("BySeverity[LOW] = %d, want 1", summary.BySeverity["LOW"])
	}
	if summary.ByType["vulnerability"] != 3 {
		t.Fatalf("ByType[vulnerability] = %d, want 3", summary.ByType["vulnerability"])
	}
	if summary.ByType["malicious"] != 1 {
		t.Fatalf("ByType[malicious] = %d, want 1", summary.ByType["malicious"])
	}
	if summary.ByType["supply_chain_risk"] != 1 {
		t.Fatalf("ByType[supply_chain_risk] = %d, want 1", summary.ByType["supply_chain_risk"])
	}
	if summary.BySource["osv"] != 2 {
		t.Fatalf("BySource[osv] = %d, want 2", summary.BySource["osv"])
	}
	if summary.BySource["ghsa"] != 1 {
		t.Fatalf("BySource[ghsa] = %d, want 1", summary.BySource["ghsa"])
	}
	if summary.BySource["openssf"] != 1 {
		t.Fatalf("BySource[openssf] = %d, want 1", summary.BySource["openssf"])
	}
	if summary.BySource["reversinglabs"] != 1 {
		t.Fatalf("BySource[reversinglabs] = %d, want 1", summary.BySource["reversinglabs"])
	}
}

func TestBuildScanSummaryEmpty(t *testing.T) {
	t.Parallel()

	summary := BuildScanSummary(nil)

	if len(summary.BySeverity) != 0 {
		t.Fatalf("BySeverity should be empty, got %v", summary.BySeverity)
	}
	if len(summary.ByType) != 0 {
		t.Fatalf("ByType should be empty, got %v", summary.ByType)
	}
	if len(summary.BySource) != 0 {
		t.Fatalf("BySource should be empty, got %v", summary.BySource)
	}
}

func TestScanFeedStatusValues(t *testing.T) {
	t.Parallel()

	want := []ScanFeedStatus{
		ScanFeedStatusHealthy,
		ScanFeedStatusDegraded,
		ScanFeedStatusError,
	}
	if got := ScanFeedStatusValues(); len(got) != len(want) {
		t.Fatalf("ScanFeedStatusValues() = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("ScanFeedStatusValues()[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	}

	if string(ScanFeedStatusHealthy) != "healthy" || string(ScanFeedStatusDegraded) != "degraded" || string(ScanFeedStatusError) != "error" {
		t.Fatalf("scan feed status constants changed: healthy=%q degraded=%q error=%q", ScanFeedStatusHealthy, ScanFeedStatusDegraded, ScanFeedStatusError)
	}
}

func TestFeedModeValues(t *testing.T) {
	t.Parallel()

	want := []FeedMode{FeedModeSelf, FeedModeExternal}
	if got := FeedModeValues(); len(got) != len(want) {
		t.Fatalf("FeedModeValues() = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("FeedModeValues()[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	}

	if string(FeedModeSelf) != "self" || string(FeedModeExternal) != "external" {
		t.Fatalf("feed mode constants changed: self=%q external=%q", FeedModeSelf, FeedModeExternal)
	}
}

func TestParseFeedMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want FeedMode
		ok   bool
	}{
		{"self", FeedModeSelf, true},
		{" SELF ", FeedModeSelf, true},
		{"external", FeedModeExternal, true},
		{"EXTERNAL", FeedModeExternal, true},
		{"", "", false},
		{"managed", "", false},
	}

	for _, tt := range tests {
		got, ok := ParseFeedMode(tt.raw)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("ParseFeedMode(%q) = %q/%v, want %q/%v", tt.raw, got, ok, tt.want, tt.ok)
		}
	}
}

func TestFindingBlocksPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		finding   Finding
		threshold Severity
		want      bool
	}{
		{
			name:      "malware always blocks",
			finding:   Finding{Type: FindingTypeMalicious, Severity: SeverityLow},
			threshold: SeverityNone,
			want:      true,
		},
		{
			name:      "supply chain risk always blocks",
			finding:   Finding{Type: FindingTypeSupplyChainRisk, Severity: SeverityLow},
			threshold: SeverityNone,
			want:      true,
		},
		{
			name:      "malware history is informational",
			finding:   Finding{Type: FindingTypeSupplyChainRisk, RiskType: RiskTypeMalwareHistory, Severity: SeverityHigh},
			threshold: SeverityNone,
			want:      false,
		},
		{
			name:      "malware history stays informational even at severity threshold",
			finding:   Finding{Type: FindingTypeSupplyChainRisk, RiskType: " " + RiskTypeMalwareHistory + " ", Severity: SeverityHigh},
			threshold: SeverityHigh,
			want:      false,
		},
		{
			name:      "none disables vulnerability blocking",
			finding:   Finding{Type: FindingTypeVulnerability, Severity: SeverityCritical},
			threshold: SeverityNone,
			want:      false,
		},
		{
			name:      "severity at threshold blocks",
			finding:   Finding{Type: FindingTypeVulnerability, Severity: SeverityHigh},
			threshold: SeverityHigh,
			want:      true,
		},
		{
			name:      "severity below threshold does not block",
			finding:   Finding{Type: FindingTypeVulnerability, Severity: SeverityMedium},
			threshold: SeverityHigh,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FindingBlocks(tt.finding, tt.threshold); got != tt.want {
				t.Fatalf("FindingBlocks() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindingsBlock(t *testing.T) {
	t.Parallel()

	findings := []Finding{
		{Type: FindingTypeVulnerability, Severity: SeverityLow},
		{Type: FindingTypeSupplyChainRisk, Severity: SeverityLow},
	}
	if !FindingsBlock(findings, SeverityNone) {
		t.Fatal("FindingsBlock() = false, want true when any finding blocks")
	}
	if FindingsBlock([]Finding{{Type: FindingTypeVulnerability, Severity: SeverityLow}}, SeverityHigh) {
		t.Fatal("FindingsBlock() = true, want false when no finding blocks")
	}
}

func TestCountManualAdvisoryFindings(t *testing.T) {
	t.Parallel()

	findings := []Finding{
		{Source: ManualAdvisorySource},
		{Source: "osv"},
		{Source: ManualAdvisorySource},
		{Source: "openssf"},
	}

	if got := CountManualAdvisoryFindings(findings); got != 2 {
		t.Fatalf("CountManualAdvisoryFindings() = %d, want 2", got)
	}
}
