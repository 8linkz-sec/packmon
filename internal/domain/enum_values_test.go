package domain

import "testing"

// TestEcosystemValidAcceptsEverySupportedEcosystem pins the allowlist behind
// `Ecosystem.Valid`. A supported ecosystem missing here would have its packages
// rejected before they ever reach the scanner.
func TestEcosystemValidAcceptsEverySupportedEcosystem(t *testing.T) {
	t.Parallel()

	for _, ecosystem := range []Ecosystem{
		EcosystemNPM, EcosystemPyPI, EcosystemGo, EcosystemMaven, EcosystemCargo,
		EcosystemNuGet, EcosystemComposer, EcosystemGem, EcosystemPub,
		EcosystemGitHubActions, EcosystemCocoaPods, EcosystemSwiftPM, EcosystemHex,
		EcosystemCRAN, EcosystemDocker, EcosystemChocolatey,
	} {
		if !ecosystem.Valid() {
			t.Errorf("Ecosystem(%q).Valid() = false, want it supported", ecosystem)
		}
	}
}

// TestEcosystemValidRejectsAnythingElse is the other half: the check is
// case-sensitive and exact, because the value is used as a database key and a
// near-miss would silently create a second, unmatched ecosystem.
func TestEcosystemValidRejectsAnythingElse(t *testing.T) {
	t.Parallel()

	for _, ecosystem := range []Ecosystem{
		"", "   ", "NPM", "Npm", " npm ", "npmjs", "unknown", "rubygems",
	} {
		if ecosystem.Valid() {
			t.Errorf("Ecosystem(%q).Valid() = true, want it rejected", ecosystem)
		}
	}
}

// TestScanModeValuesListsTheWholePublicEnum covers the exported enum listing.
// It backs the CLI help text and the API's documented vocabulary, so a missing
// value is a documented mode users cannot discover.
func TestScanModeValuesListsTheWholePublicEnum(t *testing.T) {
	t.Parallel()

	values := ScanModeValues()
	if len(values) != 3 {
		t.Fatalf("ScanModeValues() = %v, want three modes", values)
	}

	seen := map[ScanMode]bool{}
	for _, mode := range values {
		if seen[mode] {
			t.Errorf("ScanModeValues() lists %q twice", mode)
		}
		seen[mode] = true
	}
	for _, mode := range []ScanMode{ScanModeRemote, ScanModeLocal, ScanModeAuto} {
		if !seen[mode] {
			t.Errorf("ScanModeValues() is missing %q", mode)
		}
	}

	// The caller receives a fresh slice: mutating it must not corrupt the enum
	// for the next caller.
	values[0] = "mutated"
	if again := ScanModeValues(); again[0] == "mutated" {
		t.Fatal("ScanModeValues() returns a shared backing array")
	}
}

// TestEcosystemInventoryOnly pins the metadata-only ecosystems: they appear in
// CLI inventory reports but are never scan inputs for /api/v1/check, feed
// matching, or manual advisories.
func TestEcosystemInventoryOnly(t *testing.T) {
	t.Parallel()

	for _, ecosystem := range []Ecosystem{EcosystemDocker, EcosystemChocolatey} {
		if !ecosystem.Valid() {
			t.Errorf("Ecosystem(%q).Valid() = false, want valid", ecosystem)
		}
		if !ecosystem.InventoryOnly() {
			t.Errorf("Ecosystem(%q).InventoryOnly() = false, want true", ecosystem)
		}
		if ecosystem.ScanInput() {
			t.Errorf("Ecosystem(%q).ScanInput() = true, want false", ecosystem)
		}
	}
	for _, ecosystem := range []Ecosystem{EcosystemNPM, EcosystemNuGet, EcosystemGitHubActions} {
		if ecosystem.InventoryOnly() {
			t.Errorf("Ecosystem(%q).InventoryOnly() = true, want false", ecosystem)
		}
		if !ecosystem.ScanInput() {
			t.Errorf("Ecosystem(%q).ScanInput() = false, want true", ecosystem)
		}
	}
	if Ecosystem("bogus").ScanInput() {
		t.Errorf("invalid ecosystem must not be a scan input")
	}
}
