package domain

import "testing"

func TestParseManualAdvisoryFindingType(t *testing.T) {
	tests := []struct {
		raw  string
		want FindingType
		ok   bool
	}{
		{"", FindingTypeVulnerability, true},
		{" vulnerability ", FindingTypeVulnerability, true},
		{"MALICIOUS", FindingTypeMalicious, true},
		{"supply_chain_risk", "", false},
		{"typo", "", false},
	}

	for _, tt := range tests {
		got, ok := ParseManualAdvisoryFindingType(tt.raw)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("ParseManualAdvisoryFindingType(%q) = %q/%v, want %q/%v", tt.raw, got, ok, tt.want, tt.ok)
		}
	}
}

func TestManualAdvisoryNamespace(t *testing.T) {
	if ManualAdvisorySource != "manual" {
		t.Fatalf("ManualAdvisorySource = %q, want manual", ManualAdvisorySource)
	}
	if ManualAdvisoryIDPrefix != "manual:" {
		t.Fatalf("ManualAdvisoryIDPrefix = %q, want manual:", ManualAdvisoryIDPrefix)
	}

	tests := []struct {
		raw        string
		want       string
		wantManual bool
	}{
		{" manual:operator-1 ", "manual:operator-1", true},
		{" Manual:operator-1 ", "Manual:operator-1", true},
		{"CVE-2026-0001", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		got, ok := NormalizeManualAdvisoryID(tt.raw)
		if got != tt.want || ok != tt.wantManual {
			t.Fatalf("NormalizeManualAdvisoryID(%q) = %q/%v, want %q/%v", tt.raw, got, ok, tt.want, tt.wantManual)
		}
		if gotManual := IsManualAdvisoryID(tt.raw); gotManual != tt.wantManual {
			t.Fatalf("IsManualAdvisoryID(%q) = %v, want %v", tt.raw, gotManual, tt.wantManual)
		}
	}
}

func TestRiskTypeMalwareHistoryPublicValue(t *testing.T) {
	if RiskTypeMalwareHistory != "malware_history" {
		t.Fatalf("RiskTypeMalwareHistory = %q, want malware_history", RiskTypeMalwareHistory)
	}
}
