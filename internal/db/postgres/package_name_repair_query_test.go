package postgres

import (
	"strings"
	"testing"
)

// TestPackageNameRepairUsesCanonicalPackageNameSQL guards the startup
// package-name repair against its own ecosystem list: it must fold names with
// canonicalPackageNameSQL (the SQL form of packageid.NormalizeName), so legacy
// GitHub Actions names and untrimmed names merge into the identity lookups use.
func TestPackageNameRepairUsesCanonicalPackageNameSQL(t *testing.T) {
	t.Parallel()

	for name, query := range map[string]string{
		"affected_packages":  repairAffectedPackageNamesSQL,
		"malicious_findings": repairMaliciousPackageNamesSQL,
	} {
		if !strings.Contains(query, canonicalPackageNameSQL) {
			t.Fatalf("%s package-name repair must derive names from canonicalPackageNameSQL", name)
		}
		if strings.Contains(query, "IN ('pypi', 'nuget')") {
			t.Fatalf("%s package-name repair is still limited to pypi/nuget", name)
		}
	}
}
