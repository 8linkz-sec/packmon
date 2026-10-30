//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestRepairCaseInsensitivePackageNamesRollsBackBothRepairPhases(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:        "GHSA-package-name-repair-rollback",
		Summary:   "repair rollback",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "pypi",
			Name:             "repair-package",
			VersionRanges:    json.RawMessage(`[]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:            "dbperf-package-name-repair-rollback",
		Ecosystem:     "pypi",
		Name:          "repair-package",
		Source:        "openssf",
		RiskType:      "malware",
		Severity:      "CRITICAL",
		Summary:       "repair rollback",
		ReferenceURLs: json.RawMessage(`[]`),
	}); err != nil {
		t.Fatalf("seed malicious finding: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		UPDATE affected_packages
		SET name = 'Repair_Package'
		WHERE vulnerability_id = 'GHSA-package-name-repair-rollback';

		UPDATE malicious_findings
		SET name = 'Repair_Package'
		WHERE id = 'dbperf-package-name-repair-rollback';

		CREATE FUNCTION packmon_test_reject_malicious_name_repair() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'malicious repair rejected by test fixture';
		END
		$$;

		CREATE TRIGGER packmon_test_reject_malicious_name_repair
		BEFORE UPDATE OF name ON malicious_findings
		FOR EACH ROW
		WHEN (OLD.id = 'dbperf-package-name-repair-rollback')
		EXECUTE FUNCTION packmon_test_reject_malicious_name_repair()`); err != nil {
		t.Fatalf("prepare repair rollback fixture: %v", err)
	}

	generation := dashboardStatsCacheGeneration(store)
	if repaired, err := store.RepairCaseInsensitivePackageNames(ctx); err == nil {
		t.Fatalf("RepairCaseInsensitivePackageNames() = %d, nil; want malicious phase failure", repaired)
	}
	if got := dashboardStatsCacheGeneration(store); got != generation {
		t.Fatalf("cache generation after rolled-back repair = %d, want %d", got, generation)
	}

	var affectedName, maliciousName string
	if err := store.pool.QueryRow(ctx, `
		SELECT ap.name, mf.name
		FROM affected_packages ap
		CROSS JOIN malicious_findings mf
		WHERE ap.vulnerability_id = 'GHSA-package-name-repair-rollback'
		  AND mf.id = 'dbperf-package-name-repair-rollback'`).Scan(&affectedName, &maliciousName); err != nil {
		t.Fatalf("read package names after rolled-back repair: %v", err)
	}
	if affectedName != "Repair_Package" || maliciousName != "Repair_Package" {
		t.Fatalf("package names after rolled-back repair = (%q, %q), want both original names", affectedName, maliciousName)
	}
}
