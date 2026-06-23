package db

import "testing"

func TestFormatSearchVulnerabilityIDPreviewCapsAndCountsRemainder(t *testing.T) {
	got := FormatSearchVulnerabilityIDPreview("GHSA-001, GHSA-002, GHSA-003, GHSA-004, GHSA-005, GHSA-006, GHSA-007", 7)
	want := "GHSA-001, GHSA-002, GHSA-003, GHSA-004, GHSA-005, +2 more"
	if got != want {
		t.Fatalf("FormatSearchVulnerabilityIDPreview() = %q, want %q", got, want)
	}
}

func TestFormatSearchVulnerabilityIDPreviewKeepsShortLists(t *testing.T) {
	got := FormatSearchVulnerabilityIDPreview("GHSA-002, GHSA-001", 2)
	want := "GHSA-002, GHSA-001"
	if got != want {
		t.Fatalf("FormatSearchVulnerabilityIDPreview() = %q, want %q", got, want)
	}
}
