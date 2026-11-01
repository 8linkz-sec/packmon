package postgres

import (
	"slices"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

// TestNormalizedManualAdvisoryUsesNormalizedID pins the manual advisory write
// path to the normalized ID: the persisted rows use the trimmed ID, so the
// counterpart cleanup and the lock must use it too.
func TestNormalizedManualAdvisoryUsesNormalizedID(t *testing.T) {
	t.Parallel()

	input := &db.ManualAdvisory{ID: "  manual:padded \t", FindingType: "vulnerability", Ecosystem: "npm", Name: "left-pad"}
	got, err := normalizedManualAdvisory(input)
	if err != nil {
		t.Fatalf("normalizedManualAdvisory() error = %v", err)
	}
	if got.ID != "manual:padded" {
		t.Fatalf("normalizedManualAdvisory().ID = %q, want manual:padded", got.ID)
	}
	if input.ID != "  manual:padded \t" {
		t.Fatalf("normalizedManualAdvisory() mutated the caller's advisory ID to %q", input.ID)
	}

	if _, err := normalizedManualAdvisory(&db.ManualAdvisory{ID: "GHSA-feed-owned", FindingType: "vulnerability"}); err == nil {
		t.Fatal("normalizedManualAdvisory(feed-owned ID) error = nil, want manual namespace rejection")
	}
	if _, err := normalizedManualAdvisory(&db.ManualAdvisory{ID: "manual:x", FindingType: "lifecycle"}); err == nil {
		t.Fatal("normalizedManualAdvisory(unsupported type) error = nil, want rejection")
	}
}

// TestManualVulnerabilityPackageKeysUseStoredIdentity pins the affected
// package set a manual edit keeps to the canonical identity upsertVulnerabilityTx
// stores, so the replace step never deletes the row the edit just wrote.
func TestManualVulnerabilityPackageKeysUseStoredIdentity(t *testing.T) {
	t.Parallel()

	ecosystems, names, err := manualVulnerabilityPackageKeys(db.ManualAdvisoryToVulnerability(&db.ManualAdvisory{
		ID: "manual:keys", FindingType: "vulnerability", Ecosystem: " PyPI ", Name: " My.Pkg_Name ",
	}))
	if err != nil {
		t.Fatalf("manualVulnerabilityPackageKeys() error = %v", err)
	}
	if !slices.Equal(ecosystems, []string{"pypi"}) || !slices.Equal(names, []string{"my-pkg-name"}) {
		t.Fatalf("manualVulnerabilityPackageKeys() = %q, %q; want [pypi] [my-pkg-name]", ecosystems, names)
	}

	if _, _, err := manualVulnerabilityPackageKeys(&db.Vulnerability{
		ID:               "manual:bad-ecosystem",
		AffectedPackages: []db.AffectedPackage{{Ecosystem: "not-an-ecosystem", Name: "x"}},
	}); err == nil {
		t.Fatal("manualVulnerabilityPackageKeys(unsupported ecosystem) error = nil, want rejection")
	}
}
