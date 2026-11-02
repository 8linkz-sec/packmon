package db

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestManualAdvisoryConverters(t *testing.T) {
	t.Parallel()

	advisory := &ManualAdvisory{
		ID:          " manual-1 ",
		Ecosystem:   " NPM ",
		Name:        " left-pad ",
		Severity:    " high ",
		RiskType:    "",
		Summary:     " summary ",
		Description: " details ",
	}
	vuln := ManualAdvisoryToVulnerability(advisory)
	if vuln.ID != "manual-1" || vuln.Severity != "HIGH" || vuln.Summary != "summary" || vuln.Details != "details" {
		t.Fatalf("ManualAdvisoryToVulnerability = %+v", vuln)
	}
	if len(vuln.AffectedPackages) != 1 || vuln.AffectedPackages[0].Ecosystem != "npm" || vuln.AffectedPackages[0].Name != "left-pad" {
		t.Fatalf("affected packages = %+v", vuln.AffectedPackages)
	}
	var raw map[string]string
	if err := json.Unmarshal(vuln.Sources[0].RawJSON, &raw); err != nil || raw["finding_type"] != "vulnerability" || raw["created_by"] != "admin" {
		t.Fatalf("vulnerability raw JSON = %s, %v", vuln.Sources[0].RawJSON, err)
	}

	malicious := ManualAdvisoryToMaliciousFinding(advisory)
	if malicious.ID != "manual-1" || malicious.Severity != "HIGH" || malicious.RiskType != "malware" || malicious.CreatedBy != "admin" {
		t.Fatalf("ManualAdvisoryToMaliciousFinding = %+v", malicious)
	}
	defaults := ManualAdvisoryToMaliciousFinding(&ManualAdvisory{ID: "id"})
	if defaults.Severity != "CRITICAL" || defaults.RiskType != "malware" {
		t.Fatalf("manual malicious defaults = %+v", defaults)
	}
	supplyChain := ManualAdvisoryToMaliciousFinding(&ManualAdvisory{ID: "id", RiskType: "supply-chain"})
	if supplyChain.RiskType != "supply_chain" {
		t.Fatalf("supply-chain risk type = %q, want supply_chain", supplyChain.RiskType)
	}
}

func TestManualAdvisoryToVulnerabilityDefaultsAndMetadata(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC()
	input := &ManualAdvisory{
		ID:          " manual:test-1 ",
		Ecosystem:   " NPM ",
		Name:        " left-pad ",
		Summary:     " summary ",
		Description: " description ",
	}
	original := *input
	vuln := ManualAdvisoryToVulnerability(input)
	after := time.Now().UTC()
	if !reflect.DeepEqual(*input, original) {
		t.Fatalf("ManualAdvisoryToVulnerability mutated input from %+v to %+v", original, *input)
	}
	if vuln.ID != "manual:test-1" || vuln.Severity != "UNKNOWN" || vuln.Summary != "summary" || vuln.Details != "description" {
		t.Fatalf("converted vulnerability = %+v", vuln)
	}
	if vuln.Published.Before(before) || vuln.Published.After(after) || !vuln.Published.Equal(vuln.Modified) {
		t.Fatalf("published/modified = %s/%s, want equal within [%s,%s]", vuln.Published, vuln.Modified, before, after)
	}
	if !reflect.DeepEqual(vuln.Aliases, []VulnerabilityAlias{{AliasID: "manual:test-1"}}) {
		t.Fatalf("aliases = %#v", vuln.Aliases)
	}
	if len(vuln.Sources) != 1 || vuln.Sources[0].Source != domain.ManualAdvisorySource || vuln.Sources[0].SourceID != "manual:test-1" || vuln.Sources[0].URL != "" {
		t.Fatalf("sources = %#v", vuln.Sources)
	}
	var metadata map[string]string
	if err := json.Unmarshal(vuln.Sources[0].RawJSON, &metadata); err != nil {
		t.Fatalf("metadata = %s: %v", vuln.Sources[0].RawJSON, err)
	}
	if !reflect.DeepEqual(metadata, map[string]string{"finding_type": "vulnerability", "created_by": "admin"}) {
		t.Fatalf("metadata = %#v", metadata)
	}
	if len(vuln.AffectedPackages) != 1 {
		t.Fatalf("affected packages = %#v", vuln.AffectedPackages)
	}
	affected := vuln.AffectedPackages[0]
	if affected.Ecosystem != "npm" || affected.Name != "left-pad" || string(affected.VersionRanges) != "[]" || string(affected.VersionsAffected) != "[]" {
		t.Fatalf("affected package = %+v", affected)
	}
	vuln.Aliases[0].AliasID = "changed"
	vuln.Sources[0].RawJSON[0] = '['
	vuln.AffectedPackages[0].Name = "changed"
	second := ManualAdvisoryToVulnerability(input)
	if !reflect.DeepEqual(*input, original) || second.ID != "manual:test-1" || second.Aliases[0].AliasID != "manual:test-1" || second.AffectedPackages[0].Name != "left-pad" || !json.Valid(second.Sources[0].RawJSON) {
		t.Fatalf("vulnerability conversion retained mutable output state: input=%+v second=%+v", *input, second)
	}

	fallback := ManualAdvisoryToVulnerability(&ManualAdvisory{Ecosystem: " Unsupported ", Severity: " low "})
	if fallback.Severity != "LOW" || fallback.AffectedPackages[0].Ecosystem != "Unsupported" {
		t.Fatalf("invalid-ecosystem fallback = %+v", fallback)
	}
}

func TestManualAdvisoryToMaliciousFindingAliasesAndFallbacks(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		input string
		want  string
	}{
		{input: "", want: "malware"},
		{input: " malware ", want: "malware"},
		{input: "supply_chain", want: "supply_chain"},
		{input: "supply-chain", want: "supply_chain"},
		{input: "supply chain", want: "supply_chain"},
		{input: "typosquatting", want: "typosquatting"},
		{input: "typosquat", want: "typosquatting"},
		{input: "typo-squatting", want: "typosquatting"},
	} {
		got := ManualAdvisoryToMaliciousFinding(&ManualAdvisory{RiskType: tt.input})
		if got.RiskType != tt.want {
			t.Errorf("risk type for %q = %q, want %q", tt.input, got.RiskType, tt.want)
		}
	}

	input := &ManualAdvisory{
		ID:          " manual:malicious-1 ",
		Ecosystem:   " PyPI ",
		Name:        " Demo_Package ",
		Severity:    " ",
		RiskType:    " unsupported-risk ",
		Summary:     " summary ",
		Description: " description ",
	}
	original := *input
	got := ManualAdvisoryToMaliciousFinding(input)
	if !reflect.DeepEqual(*input, original) {
		t.Fatalf("ManualAdvisoryToMaliciousFinding mutated input from %+v to %+v", original, *input)
	}
	if got.ID != "manual:malicious-1" || got.Ecosystem != "pypi" || got.Name != "Demo_Package" || got.Severity != "CRITICAL" || got.RiskType != "unsupported-risk" || got.Summary != "summary" || got.Description != "description" || got.Source != domain.ManualAdvisorySource || got.CreatedBy != "admin" {
		t.Fatalf("converted malicious finding = %+v", got)
	}
	got.Name = "changed"
	second := ManualAdvisoryToMaliciousFinding(input)
	if !reflect.DeepEqual(*input, original) || second.Name != "Demo_Package" {
		t.Fatalf("malicious conversion retained mutable output state: input=%+v second=%+v", *input, second)
	}

	invalidEcosystem := ManualAdvisoryToMaliciousFinding(&ManualAdvisory{Ecosystem: " Invalid Ecosystem "})
	if invalidEcosystem.Ecosystem != "Invalid Ecosystem" {
		t.Fatalf("invalid ecosystem fallback = %q", invalidEcosystem.Ecosystem)
	}
}

func TestNormalizeManualAdvisoryRiskTypeAliasesAndErrors(t *testing.T) {
	t.Parallel()

	valid := map[string]string{
		"": "malware", "   ": "malware", "MALWARE": "malware",
		" SUPPLY_CHAIN ": "supply_chain", "supply-chain": "supply_chain", "Supply Chain": "supply_chain",
		"TYPOSQUATTING": "typosquatting", "typosquat": "typosquatting", "typo-squatting": "typosquatting",
	}
	for input, want := range valid {
		got, err := normalizeManualAdvisoryRiskType(input)
		if err != nil || got != want {
			t.Errorf("normalizeManualAdvisoryRiskType(%q) = %q, %v; want %q, nil", input, got, err, want)
		}
	}
	for _, input := range []string{"unknown", "supplychain", "typo squatting", "malware\x00"} {
		got, err := normalizeManualAdvisoryRiskType(input)
		if err == nil || got != "" || !strings.Contains(err.Error(), "unsupported malicious risk type") {
			t.Errorf("normalizeManualAdvisoryRiskType(%q) = %q, %v; want empty and descriptive error", input, got, err)
		}
	}
}
