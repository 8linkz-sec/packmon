package db

import (
	"encoding/json"
	"testing"
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
