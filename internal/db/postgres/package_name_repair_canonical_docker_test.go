//go:build integration

package postgres

import (
	"context"
	"slices"
	"testing"
)

// testPackageNameRepairUsesCanonicalNames seeds legacy rows the write
// boundaries no longer produce: mixed-case GitHub Actions names and names with
// surrounding whitespace, including the lower-cased but untrimmed names an
// earlier pypi/nuget-only repair left behind. The repair must fold them into
// the canonical packageid.NormalizeName identity every lookup uses, merging
// colliding affected_packages rows like the pypi/nuget repair always did.
func testPackageNameRepairUsesCanonicalNames(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified)
		VALUES
			('GHSA-name-repair-actions', 'actions repair', 'HIGH', NOW(), NOW()),
			('PYSEC-name-repair-trim', 'pypi trim repair', 'HIGH', NOW(), NOW()),
			('GHSA-name-repair-nuget-trim', 'nuget trim repair', 'HIGH', NOW(), NOW()),
			('GHSA-name-repair-npm-trim', 'npm trim repair', 'HIGH', NOW(), NOW());
		INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected)
		VALUES
			('GHSA-name-repair-actions', 'actions', 'Name-Repair/Checkout', '[]'::jsonb, '["4.0.0"]'::jsonb),
			('GHSA-name-repair-actions', 'actions', 'name-repair/checkout', '[]'::jsonb, '["4.1.0"]'::jsonb),
			('PYSEC-name-repair-trim', 'pypi', ' Name_Repair.Requests ', '[]'::jsonb, '["2.0.0"]'::jsonb),
			('PYSEC-name-repair-trim', 'pypi', 'name-repair-requests'||chr(9), '[]'::jsonb, '["2.1.0"]'::jsonb),
			('GHSA-name-repair-nuget-trim', 'nuget', ' name.repair.json', '[]'::jsonb, '["13.0.3"]'::jsonb),
			('GHSA-name-repair-npm-trim', 'npm', 'name-repair-left-pad ', '[]'::jsonb, '["1.3.0"]'::jsonb);
		INSERT INTO malicious_findings(
			id, ecosystem, name, version_ranges, versions, source, risk_type, severity, summary, reference_urls, created_by
		)
		VALUES
			('MAL-name-repair-actions', 'actions', 'Name-Repair/Evil-Action', '[]'::jsonb, '["1.0.0"]'::jsonb,
				'openssf', 'malware', 'CRITICAL', 'mixed case action', '[]'::jsonb, 'feed'),
			('MAL-name-repair-pypi-trim', 'pypi', ' name-repair-bad ', '[]'::jsonb, '["1.0.0"]'::jsonb,
				'openssf', 'malware', 'CRITICAL', 'untrimmed pypi', '[]'::jsonb, 'feed'),
			('MAL-name-repair-npm-trim', 'npm', 'name-repair-evil ', '[]'::jsonb, '["1.0.0"]'::jsonb,
				'openssf', 'malware', 'CRITICAL', 'untrimmed npm', '[]'::jsonb, 'feed');
	`); err != nil {
		t.Fatalf("insert legacy package-name rows: %v", err)
	}

	if _, err := store.RepairCaseInsensitivePackageNames(ctx); err != nil {
		t.Fatalf("RepairCaseInsensitivePackageNames() error = %v", err)
	}

	affected := []struct {
		id, ecosystem, name string
		versions            []string
	}{
		{"GHSA-name-repair-actions", "actions", "name-repair/checkout", []string{"4.0.0", "4.1.0"}},
		{"PYSEC-name-repair-trim", "pypi", "name-repair-requests", []string{"2.0.0", "2.1.0"}},
		{"GHSA-name-repair-nuget-trim", "nuget", "name.repair.json", []string{"13.0.3"}},
		{"GHSA-name-repair-npm-trim", "npm", "name-repair-left-pad", []string{"1.3.0"}},
	}
	for _, want := range affected {
		if got := affectedPackageNames(ctx, t, store, want.id, want.ecosystem); !slices.Equal(got, []string{want.name}) {
			t.Fatalf("affected packages for %s = %q, want only canonical %q", want.id, got, want.name)
		}
		for _, version := range want.versions {
			findings, err := store.FindVulnerabilities(ctx, want.ecosystem, want.name, version)
			if err != nil {
				t.Fatalf("FindVulnerabilities(%s %s@%s) error = %v", want.ecosystem, want.name, version, err)
			}
			if !findingsContainAdvisory(findings, want.id) {
				t.Fatalf("FindVulnerabilities(%s %s@%s) = %+v, want merged canonical advisory %s", want.ecosystem, want.name, version, findings, want.id)
			}
		}
	}

	malicious := []struct{ id, ecosystem, name string }{
		{"MAL-name-repair-actions", "actions", "name-repair/evil-action"},
		{"MAL-name-repair-pypi-trim", "pypi", "name-repair-bad"},
		{"MAL-name-repair-npm-trim", "npm", "name-repair-evil"},
	}
	for _, want := range malicious {
		findings, err := store.FindMalicious(ctx, want.ecosystem, want.name, "1.0.0")
		if err != nil {
			t.Fatalf("FindMalicious(%s %s) error = %v", want.ecosystem, want.name, err)
		}
		if !findingsContainAdvisory(findings, want.id) {
			t.Fatalf("FindMalicious(%s %s) = %+v, want repaired finding %s", want.ecosystem, want.name, findings, want.id)
		}
	}

	again, err := store.RepairCaseInsensitivePackageNames(ctx)
	if err != nil {
		t.Fatalf("second RepairCaseInsensitivePackageNames() error = %v", err)
	}
	if again != 0 {
		t.Fatalf("second RepairCaseInsensitivePackageNames() = %d, want 0 (idempotent)", again)
	}
}
