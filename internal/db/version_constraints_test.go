package db

import "testing"

func TestNormalizeVersionConstraintJSONDefaultsBlankAndNullToEmptyArrays(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		ranges       string
		versions     string
		wantRanges   string
		wantVersions string
	}{
		{name: "blank", wantRanges: "[]", wantVersions: "[]"},
		{name: "null", ranges: " null ", versions: "\tnull\n", wantRanges: "[]", wantVersions: "[]"},
		{name: "preserves json", ranges: ` [{"events":[{"introduced":"0"}]}] `, versions: ` ["1.0.0"] `, wantRanges: `[{"events":[{"introduced":"0"}]}]`, wantVersions: `["1.0.0"]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotRanges, gotVersions := NormalizeVersionConstraintJSON(tt.ranges, tt.versions)
			if gotRanges != tt.wantRanges || gotVersions != tt.wantVersions {
				t.Fatalf("NormalizeVersionConstraintJSON() = %q, %q; want %q, %q", gotRanges, gotVersions, tt.wantRanges, tt.wantVersions)
			}
		})
	}
}
