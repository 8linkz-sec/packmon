package postgres

import (
	"strings"
	"testing"
)

// TestRepairGHSAAffectedPackagesCanonicalizesNames guards the repair against
// copying raw GHSA package names: rows it writes must use the canonical
// package identity (packageid.NormalizeName) that every lookup uses.
func TestRepairGHSAAffectedPackagesCanonicalizesNames(t *testing.T) {
	t.Parallel()

	if strings.Contains(repairGHSAAffectedPackagesSQL, "aff.item->'package'->>'name' AS name") {
		t.Fatal("GHSA repair copies the raw package name into affected_packages.name")
	}
	if !strings.Contains(repairGHSAAffectedPackagesSQL, canonicalPackageNameSQL) {
		t.Fatal("GHSA repair must derive affected_packages.name from canonicalPackageNameSQL")
	}
}
