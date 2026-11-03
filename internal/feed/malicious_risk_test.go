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

func TestMaliciousRiskTypeFromJSONRejectsInvalidMetadataAndUsesCandidateOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "malformed JSON", raw: `{"risk_type":`, want: ""},
		{name: "empty metadata", raw: `{}`, want: ""},
		{
			name: "unrecognized metadata",
			raw:  `{"risk_type":"unknown","type":"other","classification":"noise","categories":["benign",""]}`,
			want: "",
		},
		{
			name: "risk type precedes later candidates",
			raw:  `{"risk_type":"typosquat","type":"supply-chain","classification":"malware","categories":["malware"]}`,
			want: "typosquatting",
		},
		{
			name: "type follows unrecognized risk type",
			raw:  `{"risk_type":"unknown","type":"supply-chain","classification":"typosquat","categories":["malware"]}`,
			want: "supply_chain",
		},
		{
			name: "classification follows unrecognized fields",
			raw:  `{"risk_type":"unknown","type":"other","classification":"typosquat","categories":["malware"]}`,
			want: "typosquatting",
		},
		{
			name: "first recognized category wins",
			raw:  `{"categories":["unknown","typosquat","malware"]}`,
			want: "typosquatting",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := MaliciousRiskTypeFromJSON(json.RawMessage(tt.raw)); got != tt.want {
				t.Fatalf("MaliciousRiskTypeFromJSON(%s) = %q, want %q", tt.raw, got, tt.want)
			}
		})
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
