package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// ManualAdvisoryToVulnerability converts an operator-managed advisory to the
// normalized vulnerability persistence model used by all stores.
func ManualAdvisoryToVulnerability(advisory *ManualAdvisory) *Vulnerability {
	now := time.Now().UTC()
	severity := strings.ToUpper(strings.TrimSpace(advisory.Severity))
	if severity == "" {
		severity = "UNKNOWN"
	}
	ecosystem, err := normalizeManualAdvisoryEcosystem(advisory.Ecosystem)
	if err != nil {
		ecosystem = strings.TrimSpace(advisory.Ecosystem)
	}
	raw, _ := json.Marshal(map[string]string{
		"finding_type": "vulnerability",
		"created_by":   "admin",
	})

	id := strings.TrimSpace(advisory.ID)
	return &Vulnerability{
		ID:        id,
		Summary:   strings.TrimSpace(advisory.Summary),
		Details:   strings.TrimSpace(advisory.Description),
		Severity:  severity,
		Published: now,
		Modified:  now,
		Aliases: []VulnerabilityAlias{
			{AliasID: id},
		},
		Sources: []VulnerabilitySource{
			{
				Source:   domain.ManualAdvisorySource,
				SourceID: id,
				RawJSON:  raw,
			},
		},
		AffectedPackages: []AffectedPackage{
			{
				Ecosystem:        ecosystem,
				Name:             strings.TrimSpace(advisory.Name),
				VersionRanges:    json.RawMessage("[]"),
				VersionsAffected: json.RawMessage("[]"),
			},
		},
	}
}

// ManualAdvisoryToMaliciousFinding converts an operator-managed advisory to the
// normalized malicious-finding persistence model used by all stores.
func ManualAdvisoryToMaliciousFinding(advisory *ManualAdvisory) *MaliciousFinding {
	riskType, err := normalizeManualAdvisoryRiskType(advisory.RiskType)
	if err != nil {
		riskType = strings.TrimSpace(advisory.RiskType)
	}
	severity := strings.ToUpper(strings.TrimSpace(advisory.Severity))
	if severity == "" {
		severity = "CRITICAL"
	}
	ecosystem, err := normalizeManualAdvisoryEcosystem(advisory.Ecosystem)
	if err != nil {
		ecosystem = strings.TrimSpace(advisory.Ecosystem)
	}
	return &MaliciousFinding{
		ID:          strings.TrimSpace(advisory.ID),
		Ecosystem:   ecosystem,
		Name:        strings.TrimSpace(advisory.Name),
		Source:      domain.ManualAdvisorySource,
		RiskType:    riskType,
		Severity:    severity,
		Summary:     strings.TrimSpace(advisory.Summary),
		Description: strings.TrimSpace(advisory.Description),
		CreatedBy:   "admin",
	}
}

func normalizeManualAdvisoryEcosystem(ecosystem string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(ecosystem))
	if !domain.Ecosystem(normalized).Valid() {
		return "", fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
	return normalized, nil
}

func normalizeManualAdvisoryRiskType(riskType string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(riskType)) {
	case "":
		return "malware", nil
	case "malware":
		return "malware", nil
	case "supply_chain", "supply-chain", "supply chain":
		return "supply_chain", nil
	case "typosquatting", "typosquat", "typo-squatting":
		return "typosquatting", nil
	default:
		return "", fmt.Errorf("unsupported malicious risk type %q", riskType)
	}
}
