package db

import (
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// FindingTypeForMaliciousRiskType maps rows stored in the malicious findings
// table to their public finding type. Some async reputation providers use that
// table for blocking supply-chain signals that are not malware.
func FindingTypeForMaliciousRiskType(riskType string) domain.FindingType {
	switch strings.ToLower(strings.TrimSpace(riskType)) {
	case "supply_chain", "typosquatting":
		return domain.FindingTypeSupplyChainRisk
	default:
		return domain.FindingTypeMalicious
	}
}
