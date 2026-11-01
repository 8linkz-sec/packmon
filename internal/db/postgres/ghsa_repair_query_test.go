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

// TestRepairGHSAAffectedPackagesGuardsJSONArrayFunctions guards the repair
// against JSON null, objects, and scalars where it expects arrays: COALESCE
// does not replace a JSON null, and jsonb_array_elements/jsonb_array_length
// raise on non-arrays, which would abort the repair for every candidate.
func TestRepairGHSAAffectedPackagesGuardsJSONArrayFunctions(t *testing.T) {
	t.Parallel()

	for _, unguarded := range []string{
		"jsonb_array_elements(COALESCE(",
		"jsonb_array_length(COALESCE(",
		"COALESCE(r.item->'events'",
	} {
		if strings.Contains(repairGHSAAffectedPackagesSQL, unguarded) {
			t.Fatalf("GHSA repair applies an array function without a jsonb_typeof guard: %q", unguarded)
		}
	}
	for _, guard := range []string{
		"jsonb_typeof(vs.raw_json->'affected') = 'array'",
		"jsonb_typeof(r.item->'events') = 'array'",
		"WHERE packmon_jsonb_version_ranges_valid(version_ranges)",
		"AND packmon_jsonb_string_array_valid(versions_affected)",
	} {
		if !strings.Contains(repairGHSAAffectedPackagesSQL, guard) {
			t.Fatalf("GHSA repair is missing array guard %q", guard)
		}
	}
}
