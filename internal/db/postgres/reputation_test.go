package postgres

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestReputationToFindingMapsRemoved(t *testing.T) {
	rep := db.PackageReputation{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
		Source:    db.ReputationSourceReversingLabs,
		Status:    "removed",
		Severity:  "CRITICAL",
		Summary:   "ReversingLabs: package version was removed",
	}

	finding, ok := reputationToFinding(rep)
	if !ok {
		t.Fatal("reputationToFinding returned !ok for removed reputation")
	}
	if finding.Type != domain.FindingTypeSupplyChainRisk {
		t.Fatalf("Type = %q, want supply_chain_risk", finding.Type)
	}
	if finding.RiskType != "removed_package" {
		t.Fatalf("RiskType = %q, want removed_package", finding.RiskType)
	}
	if finding.Source != db.ReputationSourceReversingLabs {
		t.Fatalf("Source = %q, want reversinglabs", finding.Source)
	}
}

func TestReversingLabsReputationStatusMapping(t *testing.T) {
	cases := []struct {
		name         string
		status       string
		severity     string
		wantOK       bool
		wantType     domain.FindingType
		wantRiskType string
		wantSeverity domain.Severity
		wantTitle    string
	}{
		{
			name:         "malicious",
			status:       reputationStatusMalicious,
			severity:     "UNKNOWN",
			wantOK:       true,
			wantType:     domain.FindingTypeMalicious,
			wantRiskType: "malware",
			wantSeverity: domain.SeverityCritical,
			wantTitle:    "ReversingLabs: malware detected",
		},
		{
			name:         "removed",
			status:       reputationStatusRemoved,
			severity:     "MEDIUM",
			wantOK:       true,
			wantType:     domain.FindingTypeSupplyChainRisk,
			wantRiskType: "removed_package",
			wantSeverity: domain.SeverityMedium,
			wantTitle:    "ReversingLabs: package version was removed",
		},
		{
			name:         "historical risk",
			status:       reputationStatusRisk,
			severity:     "HIGH",
			wantOK:       true,
			wantType:     domain.FindingTypeSupplyChainRisk,
			wantRiskType: domain.RiskTypeMalwareHistory,
			wantSeverity: domain.SeverityLow,
			wantTitle:    "ReversingLabs: malware incident history",
		},
		{
			name:   "clean",
			status: "clean",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := reversingLabsReputationStatusMapping(tc.status, tc.severity)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if got.findingType != tc.wantType || got.riskType != tc.wantRiskType || got.severity != tc.wantSeverity || got.title != tc.wantTitle {
				t.Fatalf("mapping = %+v, want type=%q risk=%q severity=%q title=%q",
					got, tc.wantType, tc.wantRiskType, tc.wantSeverity, tc.wantTitle)
			}
		})
	}
}

func TestListDuePackageReputationsUsesPartialIndexPredicate(t *testing.T) {
	t.Parallel()

	const duePredicate = "status IN ('pending', 'error', 'malicious', 'removed', 'risk', 'clean', 'not_found')"
	if packageReputationDueStatusPredicateSQL != duePredicate {
		t.Fatalf("packageReputationDueStatusPredicateSQL = %q, want %q", packageReputationDueStatusPredicateSQL, duePredicate)
	}
	if !strings.Contains(listDuePackageReputationsSQL, packageReputationDueStatusPredicateSQL) {
		t.Fatalf("ListDuePackageReputations must use idx_reputation_due predicate %q", duePredicate)
	}
	if strings.Contains(listDuePackageReputationsSQL, "AND status <> 'unsupported'") {
		t.Fatal("ListDuePackageReputations must not use status <> 'unsupported'; it bypasses the partial due index predicate")
	}
}

func TestUpsertPackageReputationSkipsIdenticalConflictUpdates(t *testing.T) {
	required := []string{
		"ON CONFLICT (ecosystem, name, version, source) DO UPDATE SET",
		"updated_at = NOW()",
		"WHERE package_reputation_cache.status IS DISTINCT FROM EXCLUDED.status",
		"package_reputation_cache.severity IS DISTINCT FROM EXCLUDED.severity",
		"package_reputation_cache.next_check_at IS DISTINCT FROM EXCLUDED.next_check_at",
		"package_reputation_cache.last_error IS DISTINCT FROM EXCLUDED.last_error",
	}
	for _, want := range required {
		if !strings.Contains(upsertPackageReputationSQL, want) {
			t.Fatalf("upsertPackageReputationSQL missing %q", want)
		}
	}
}

func TestReputationToFindingMapsMalicious(t *testing.T) {
	rep := db.PackageReputation{
		Ecosystem: "pypi",
		Name:      "evilpkg",
		Version:   "2.0.0",
		Source:    db.ReputationSourceReversingLabs,
		Status:    "malicious",
		Severity:  "CRITICAL",
		Summary:   "ReversingLabs: malware detected",
	}

	finding, ok := reputationToFinding(rep)
	if !ok {
		t.Fatal("reputationToFinding returned !ok for malicious reputation")
	}
	if finding.Type != domain.FindingTypeMalicious {
		t.Fatalf("Type = %q, want malicious", finding.Type)
	}
	if finding.RiskType != "malware" {
		t.Fatalf("RiskType = %q, want malware", finding.RiskType)
	}
}

func TestReputationToFindingMapsHistoricalRisk(t *testing.T) {
	rep := db.PackageReputation{
		Ecosystem: "pypi",
		Name:      "polars-runtime-32",
		Version:   "1.40.1",
		Source:    db.ReputationSourceReversingLabs,
		Status:    "risk",
		Severity:  "HIGH",
		Summary:   "ReversingLabs: malware incident history",
	}

	finding, ok := reputationToFinding(rep)
	if !ok {
		t.Fatal("reputationToFinding returned !ok for historical risk reputation")
	}
	if finding.Type != domain.FindingTypeSupplyChainRisk {
		t.Fatalf("Type = %q, want supply_chain_risk", finding.Type)
	}
	if finding.RiskType != domain.RiskTypeMalwareHistory {
		t.Fatalf("RiskType = %q, want malware_history", finding.RiskType)
	}
	if finding.Severity != domain.SeverityLow {
		t.Fatalf("Severity = %q, want LOW for historical reputation context", finding.Severity)
	}
}

func TestReputationToFindingSkipsClean(t *testing.T) {
	rep := db.PackageReputation{
		Ecosystem: "nuget",
		Name:      "Safe.Package",
		Version:   "1.0.0",
		Source:    db.ReputationSourceReversingLabs,
		Status:    "clean",
		Severity:  "CRITICAL",
		Summary:   "ReversingLabs: no malicious signals",
	}

	if finding, ok := reputationToFinding(rep); ok {
		t.Fatalf("reputationToFinding(%+v) = %+v, true; want false", rep, finding)
	}
}

func TestReputationSyncFindingMapsRowsAndTombstones(t *testing.T) {
	removed := db.PackageReputation{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
		Status:    "removed",
		Severity:  "CRITICAL",
		Summary:   "ReversingLabs: package version was removed",
	}

	got := reputationSyncFinding(removed)
	if got.ID != "reversinglabs:npm/left-pad@1.3.0" {
		t.Fatalf("ID = %q", got.ID)
	}
	if got.Type != "supply_chain_risk" || got.RiskType != "removed_package" || got.Withdrawn {
		t.Fatalf("removed sync row = %+v", got)
	}

	risk := removed
	risk.Name = "polars-runtime-32"
	risk.Version = "1.40.1"
	risk.Status = "risk"
	risk.Severity = "HIGH"
	risk.Summary = "ReversingLabs: malware incident history"
	got = reputationSyncFinding(risk)
	if got.Withdrawn || got.Type != "supply_chain_risk" || got.RiskType != domain.RiskTypeMalwareHistory || got.Severity != "LOW" {
		t.Fatalf("historical risk sync row = %+v, want non-withdrawn LOW malware_history reputation row", got)
	}

	clean := removed
	clean.Status = "clean"
	got = reputationSyncFinding(clean)
	if !got.Withdrawn {
		t.Fatalf("clean sync row = %+v, want withdrawn tombstone", got)
	}
	if got.Type != "" || got.RiskType != "" {
		t.Fatalf("clean tombstone should not carry finding fields: %+v", got)
	}
}
