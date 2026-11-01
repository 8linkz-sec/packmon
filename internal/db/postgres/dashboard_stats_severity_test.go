package postgres

import (
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// TestDashboardReputationSeverityMatchesFindingContract pins the dashboard
// severity bucket of a cached reputation row to the severity of the finding
// reputationToFinding emits for it, so a historical malware_history row stored
// as HIGH is counted as LOW, exactly as TestReputationToFindingMapsHistoricalRisk
// requires for the finding itself.
func TestDashboardReputationSeverityMatchesFindingContract(t *testing.T) {
	t.Parallel()

	statuses := []string{reputationStatusMalicious, reputationStatusRemoved, reputationStatusRisk}
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "", "unknown", " high "}
	for _, status := range statuses {
		for _, severity := range severities {
			finding, ok := reputationToFinding(db.PackageReputation{
				Ecosystem: "pypi",
				Name:      "polars-runtime-32",
				Version:   "1.40.1",
				Source:    db.ReputationSourceReversingLabs,
				Status:    status,
				Severity:  severity,
			})
			if !ok {
				t.Fatalf("reputationToFinding(status=%q) returned !ok", status)
			}
			if got := dashboardReputationSeverity(status, severity); got != string(finding.Severity) {
				t.Fatalf("dashboardReputationSeverity(%q, %q) = %q, want finding severity %q", status, severity, got, finding.Severity)
			}
		}
	}

	if got := dashboardReputationSeverity(reputationStatusRisk, "HIGH"); got != string(domain.SeverityLow) {
		t.Fatalf("dashboardReputationSeverity(risk, HIGH) = %q, want LOW for informational malware_history", got)
	}
}

func TestDashboardReputationSeverityKeepsUnmappedStatusRaw(t *testing.T) {
	t.Parallel()

	if got := dashboardReputationSeverity("clean", "high"); got != "HIGH" {
		t.Fatalf("dashboardReputationSeverity(clean, high) = %q, want normalized raw severity HIGH", got)
	}
}
