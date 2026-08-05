package db

import (
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestFindingTypeForMaliciousRiskType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		riskType string
		want     domain.FindingType
	}{
		{riskType: "malware", want: domain.FindingTypeMalicious},
		{riskType: "protestware", want: domain.FindingTypeMalicious},
		{riskType: "supply_chain", want: domain.FindingTypeSupplyChainRisk},
		{riskType: "typosquatting", want: domain.FindingTypeSupplyChainRisk},
		{riskType: " SUPPLY_CHAIN ", want: domain.FindingTypeSupplyChainRisk},
		{riskType: "unknown", want: domain.FindingTypeMalicious},
	}

	for _, tt := range tests {
		t.Run(tt.riskType, func(t *testing.T) {
			t.Parallel()
			if got := FindingTypeForMaliciousRiskType(tt.riskType); got != tt.want {
				t.Fatalf("FindingTypeForMaliciousRiskType(%q) = %q, want %q", tt.riskType, got, tt.want)
			}
		})
	}
}
