package feed

import (
	"encoding/json"
	"strings"
)

// ClassifyMaliciousRiskType normalizes explicit malicious-feed metadata first,
// then falls back to legacy summary/details heuristics used by feed syncers.
func ClassifyMaliciousRiskType(raw json.RawMessage, summary, details string) string {
	if riskType := MaliciousRiskTypeFromJSON(raw); riskType != "" {
		return riskType
	}

	lower := strings.ToLower(summary + " " + details)
	switch {
	case strings.Contains(lower, "typosquat"):
		return "typosquatting"
	case strings.Contains(lower, "supply chain") || strings.Contains(lower, "supply-chain"):
		return "supply_chain"
	case strings.Contains(lower, "dependency confusion"):
		return "supply_chain"
	case strings.Contains(lower, "trojan") || strings.Contains(lower, "backdoor"):
		return "malware"
	case strings.Contains(lower, "cryptomin"):
		return "malware"
	case strings.Contains(lower, "exfiltrat"):
		return "malware"
	default:
		return "malware"
	}
}

// MaliciousRiskTypeFromJSON returns the first recognized risk type from the
// metadata fields used by OpenSSF malicious packages and OSV category entries.
func MaliciousRiskTypeFromJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var spec struct {
		RiskType       string   `json:"risk_type"`
		Type           string   `json:"type"`
		Classification string   `json:"classification"`
		Categories     []string `json:"categories"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		return ""
	}
	for _, candidate := range append([]string{spec.RiskType, spec.Type, spec.Classification}, spec.Categories...) {
		if normalized := NormalizeMaliciousRiskType(candidate); normalized != "" {
			return normalized
		}
	}
	return ""
}

// NormalizeMaliciousRiskType maps feed-specific malicious risk labels to
// Packmon's stored risk_type values.
func NormalizeMaliciousRiskType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "malware", "trojan", "backdoor", "cryptominer", "cryptomining", "exfiltration", "protestware":
		return "malware"
	case "typosquat", "typosquatting", "typo-squatting":
		return "typosquatting"
	case "supply_chain", "supply-chain", "supply chain", "dependency_confusion", "dependency confusion":
		return "supply_chain"
	default:
		return ""
	}
}
