package postgres

import "testing"

func TestNormalizeSeverityUsesLowForUnresolvedVulnerabilitySeverity(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", " ", "UNKNOWN", "unknown"} {
		if got := normalizeVulnerabilitySeverity(raw); got != "LOW" {
			t.Fatalf("normalizeVulnerabilitySeverity(%q) = %q, want LOW", raw, got)
		}
	}
}
