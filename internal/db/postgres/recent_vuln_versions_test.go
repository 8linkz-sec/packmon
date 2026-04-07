package postgres

import "testing"

func TestSummarizeAffectedVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		versionRanges string
		versions      string
		want          string
	}{
		{
			name:          "range with fixed version only",
			versionRanges: `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.1.0"}]}]`,
			want:          "< 2.1.0",
		},
		{
			name:          "range with introduced and fixed",
			versionRanges: `[{"type":"SEMVER","events":[{"introduced":"1.4.0"},{"fixed":"1.8.2"}]}]`,
			want:          ">= 1.4.0, < 1.8.2",
		},
		{
			name:          "range with last affected",
			versionRanges: `[{"type":"SEMVER","events":[{"introduced":"3.0.0"},{"last_affected":"3.2.5"}]}]`,
			want:          ">= 3.0.0, <= 3.2.5",
		},
		{
			name:     "fallback to explicit versions",
			versions: `["1.0.0","1.1.0","1.2.0","1.3.0"]`,
			want:     "1.0.0, 1.1.0, 1.2.0 (+1 more)",
		},
		{
			name:          "flat shorthand range",
			versionRanges: `[{"introduced":"0","fixed":"5.0.0"}]`,
			want:          "< 5.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summarizeAffectedVersions(tt.versionRanges, tt.versions)
			if got != tt.want {
				t.Fatalf("summarizeAffectedVersions() = %q, want %q", got, tt.want)
			}
		})
	}
}
