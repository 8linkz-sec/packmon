package main

import "testing"

func TestSelectLatestNuGetVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		versions []string
		want     string
	}{
		{
			name:     "empty",
			versions: nil,
			want:     "",
		},
		{
			name:     "unsorted stable versions",
			versions: []string{"1.2.0", "1.10.0", "1.3.0"},
			want:     "1.10.0",
		},
		{
			name:     "release wins over prerelease",
			versions: []string{"2.0.0-rc1", "1.9.9", "2.0.0"},
			want:     "2.0.0",
		},
		{
			name:     "highest can appear first",
			versions: []string{"3.1.0", "2.9.0", "3.0.5"},
			want:     "3.1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectLatestNuGetVersion(tt.versions)
			if got != tt.want {
				t.Fatalf("selectLatestNuGetVersion(%v) = %q, want %q", tt.versions, got, tt.want)
			}
		})
	}
}
