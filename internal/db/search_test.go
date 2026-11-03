package db

import "testing"

func TestFormatSearchVulnerabilityIDPreviewBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		ids   string
		total int
		want  string
	}{
		{name: "empty", want: ""},
		{name: "only ASCII and Unicode whitespace segments", ids: " \t,\n,\u2003,\u00a0 ", total: 4, want: ""},
		{
			name:  "caps and counts remainder",
			ids:   "GHSA-001, GHSA-002, GHSA-003, GHSA-004, GHSA-005, GHSA-006, GHSA-007",
			total: 7,
			want:  "GHSA-001, GHSA-002, GHSA-003, GHSA-004, GHSA-005, +2 more",
		},
		{
			name:  "exact limit has no remainder",
			ids:   "GHSA-001,GHSA-002,GHSA-003,GHSA-004,GHSA-005",
			total: SearchVulnerabilityIDPreviewLimit,
			want:  "GHSA-001, GHSA-002, GHSA-003, GHSA-004, GHSA-005",
		},
		{
			name:  "short already deduplicated list preserves source order",
			ids:   "GHSA-002, GHSA-001",
			total: 2,
			want:  "GHSA-002, GHSA-001",
		},
		{
			name:  "Unicode IDs and surrounding whitespace are preserved and trimmed",
			ids:   "\u2003GHSA-\u03b2\u00a0,\tCVE-2026-0001\n",
			total: 2,
			want:  "GHSA-\u03b2, CVE-2026-0001",
		},
		{
			name:  "reported total can exceed supplied preview IDs",
			ids:   "GHSA-001, GHSA-002",
			total: 4,
			want:  "GHSA-001, GHSA-002, +2 more",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := FormatSearchVulnerabilityIDPreview(tt.ids, tt.total); got != tt.want {
				t.Fatalf("FormatSearchVulnerabilityIDPreview(%q, %d) = %q, want %q", tt.ids, tt.total, got, tt.want)
			}
		})
	}
}
