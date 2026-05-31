package postgres

import (
	"testing"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
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
