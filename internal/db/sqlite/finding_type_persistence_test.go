package sqlite

import (
	"context"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestPersistedMaliciousRiskTypesRemainSupplyChainFindings(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity, summary, source)
		VALUES
			('RISK-SUPPLY', 'npm', 'supply-pkg', '["1.2.3"]', 'supply_chain', 'HIGH', 'supply-chain risk', 'socket'),
			('RISK-TYPO', 'npm', 'typo-pkg', NULL, 'typosquatting', 'MEDIUM', 'typosquatting risk', 'socket')`); err != nil {
		t.Fatalf("insert malicious_local rows: %v", err)
	}

	requireSupplyChain := func(label string, findings []domain.Finding, wantID, wantRisk, wantVersion string) {
		t.Helper()
		if len(findings) != 1 {
			t.Fatalf("%s findings = %+v, want one", label, findings)
		}
		finding := findings[0]
		if finding.AdvisoryID != wantID || finding.Type != domain.FindingTypeSupplyChainRisk || finding.RiskType != wantRisk || finding.Version != wantVersion {
			t.Fatalf("%s finding = %+v, want ID=%q type=%q risk=%q version=%q", label, finding, wantID, domain.FindingTypeSupplyChainRisk, wantRisk, wantVersion)
		}
	}

	single, err := store.FindMalicious(ctx, "npm", "supply-pkg", "1.2.3")
	if err != nil {
		t.Fatalf("FindMalicious(supply_chain) error = %v", err)
	}
	requireSupplyChain("single supply_chain", single, "RISK-SUPPLY", "supply_chain", "1.2.3")

	single, err = store.FindMalicious(ctx, "npm", "typo-pkg", "9.9.9")
	if err != nil {
		t.Fatalf("FindMalicious(typosquatting) error = %v", err)
	}
	requireSupplyChain("single typosquatting", single, "RISK-TYPO", "typosquatting", "9.9.9")

	batch, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "supply-pkg", Version: "1.2.3"},
		{Ecosystem: "npm", Name: "typo-pkg", Version: "2.0.0"},
	})
	if err != nil {
		t.Fatalf("FindMaliciousBatch(versioned) error = %v", err)
	}
	if len(batch) != 2 {
		t.Fatalf("versioned batch = %+v, want two findings", batch)
	}
	byID := make(map[string]domain.Finding, len(batch))
	for _, finding := range batch {
		byID[finding.AdvisoryID] = finding
	}
	for id, wantRisk := range map[string]string{"RISK-SUPPLY": "supply_chain", "RISK-TYPO": "typosquatting"} {
		finding, ok := byID[id]
		if !ok || finding.Type != domain.FindingTypeSupplyChainRisk || finding.RiskType != wantRisk {
			t.Errorf("versioned batch[%q] = %+v, present=%t", id, finding, ok)
		}
	}

	versionless, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "supply-pkg"},
		{Ecosystem: "npm", Name: "typo-pkg"},
	})
	if err != nil {
		t.Fatalf("FindMaliciousBatch(versionless) error = %v", err)
	}
	if len(versionless) != 2 {
		t.Fatalf("versionless batch = %+v, want two findings", versionless)
	}
	for _, finding := range versionless {
		if finding.Type != domain.FindingTypeSupplyChainRisk || finding.Version != "" {
			t.Errorf("versionless finding = %+v, want supply_chain_risk with empty version", finding)
		}
	}
}
