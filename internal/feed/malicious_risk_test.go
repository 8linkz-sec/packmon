package feed

import (
	"encoding/json"
	"testing"
)

func TestMaliciousRiskTypeHelpersNormalizeSharedFeedMetadata(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		`{"risk_type":"typosquat"}`:                           "typosquatting",
		`{"type":"supply-chain"}`:                             "supply_chain",
		`{"classification":"typo-squatting"}`:                 "typosquatting",
		`{"categories":["malicious","dependency_confusion"]}`: "supply_chain",
		`{"categories":["dependency confusion"]}`:             "supply_chain",
		`{"categories":["cryptomining"]}`:                     "malware",
	}
	for raw, want := range tests {
		if got := MaliciousRiskTypeFromJSON(json.RawMessage(raw)); got != want {
			t.Fatalf("MaliciousRiskTypeFromJSON(%s) = %q, want %q", raw, got, want)
		}
	}

	for raw, want := range map[string]string{
		" typo-squatting ": "typosquatting",
		"protestware":      "malware",
		"unknown":          "",
	} {
		if got := NormalizeMaliciousRiskType(raw); got != want {
			t.Fatalf("NormalizeMaliciousRiskType(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestClassifyMaliciousRiskTypeUsesExplicitMetadataBeforeHeuristics(t *testing.T) {
	t.Parallel()

	if got := ClassifyMaliciousRiskType(json.RawMessage(`{"risk_type":"supply_chain"}`), "typosquat", ""); got != "supply_chain" {
		t.Fatalf("ClassifyMaliciousRiskType(explicit) = %q, want supply_chain", got)
	}

	tests := []struct {
		name    string
		summary string
		details string
		want    string
	}{
		{name: "typosquat", summary: "typosquat steals tokens", want: "typosquatting"},
		{name: "supply chain", details: "supply chain attack", want: "supply_chain"},
		{name: "supply-chain", details: "supply-chain compromise", want: "supply_chain"},
		{name: "dependency confusion", details: "dependency confusion attack", want: "supply_chain"},
		{name: "trojan", summary: "trojan downloader", want: "malware"},
		{name: "backdoor", summary: "backdoor payload", want: "malware"},
		{name: "cryptominer", summary: "cryptominer in install script", want: "malware"},
		{name: "exfiltration", details: "credential exfiltration payload", want: "malware"},
		{name: "default", summary: "generic malicious package", want: "malware"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := ClassifyMaliciousRiskType(nil, tt.summary, tt.details); got != tt.want {
				t.Fatalf("ClassifyMaliciousRiskType(%q,%q) = %q, want %q", tt.summary, tt.details, got, tt.want)
			}
		})
	}
}
