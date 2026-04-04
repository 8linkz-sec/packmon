package postgres

import "testing"

func TestVersionAffected(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"},{"introduced":"2.0.0"},{"last_affected":"2.1.0"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "zero introduced includes older", version: "0.9.0", want: true},
		{name: "inside first range", version: "1.2.2", want: true},
		{name: "fixed boundary excluded", version: "1.2.3", want: false},
		{name: "inside second range", version: "2.1.0", want: true},
		{name: "after last affected", version: "2.1.1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := versionAffected(tt.version, ranges, `[]`)
			if err != nil {
				t.Fatalf("versionAffected() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("versionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestExtractFixedVersion(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.5.0"},{"introduced":"5.0.0"},{"fixed":"5.1.0"}]}]`
	if got := extractFixedVersion(ranges); got != "4.5.0" {
		t.Fatalf("extractFixedVersion() = %q, want %q", got, "4.5.0")
	}
}
