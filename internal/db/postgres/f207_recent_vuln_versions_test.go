package postgres

import "testing"

func TestF207RecentVulnerabilityVersionEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		versionRanges string
		versions      string
		want          string
	}{
		{
			name:          "blank legacy range falls back to explicit versions",
			versionRanges: `[{"introduced":"","fixed":"","last_affected":""}]`,
			versions:      `[" 1.0.0 ","","  ","2.0.0"]`,
			want:          "1.0.0, 2.0.0",
		},
		{
			name:          "malformed ranges fall back to explicit versions",
			versionRanges: `{not-json`,
			versions:      `["3.0.0"]`,
			want:          "3.0.0",
		},
		{
			name:          "fixed event without introduction formats an upper bound",
			versionRanges: `[{"events":[{"fixed":"4.0.0"}]}]`,
			want:          "< 4.0.0",
		},
		{
			name:          "last affected event without introduction formats an inclusive upper bound",
			versionRanges: `[{"events":[{"last_affected":"5.0.0"}]}]`,
			want:          "<= 5.0.0",
		},
		{
			name:          "open legacy range formats a lower bound",
			versionRanges: `[{"introduced":"6.0.0"}]`,
			want:          ">= 6.0.0",
		},
		{
			name:     "three explicit versions are not abbreviated",
			versions: `["7.0.0","7.1.0","7.2.0"]`,
			want:     "7.0.0, 7.1.0, 7.2.0",
		},
		{
			name:     "malformed explicit versions return no summary",
			versions: `{not-json`,
		},
		{
			name:     "blank explicit versions return no summary",
			versions: `["","  "]`,
		},
		{
			name:     "null explicit versions return no summary",
			versions: ` null `,
		},
		{
			name:          "range summary wins over explicit versions",
			versionRanges: `[{"events":[{"introduced":"8.0.0"},{"fixed":"9.0.0"}]}]`,
			versions:      `["8.5.0"]`,
			want:          ">= 8.0.0, < 9.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := summarizeAffectedVersions(tt.versionRanges, tt.versions); got != tt.want {
				t.Fatalf("summarizeAffectedVersions(%q, %q) = %q, want %q", tt.versionRanges, tt.versions, got, tt.want)
			}
		})
	}
}

func TestF207RangeHelpersRejectEmptyBoundaries(t *testing.T) {
	t.Parallel()

	if got := recentRangeEvents(recentRange{}); got != nil {
		t.Fatalf("recentRangeEvents(empty) = %#v, want nil", got)
	}
	if got := formatAffectedClause("", "", "", false); got != "" {
		t.Fatalf("formatAffectedClause(empty) = %q, want empty", got)
	}
}
