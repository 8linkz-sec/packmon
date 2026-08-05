package parser

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestCRANParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewCRANParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"renv.lock", true},
		{"Renv.lock", false},
		{"renv.json", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestCRANParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewCRANParser().Ecosystem(); got != domain.EcosystemCRAN {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemCRAN)
	}
}

func TestCRANParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "valid renv.lock",
			input: `{
				"R": {"Version": "4.3.1"},
				"Packages": {
					"dplyr": {
						"Package": "dplyr",
						"Version": "1.1.4",
						"Source": "Repository",
						"Repository": "CRAN"
					},
					"ggplot2": {
						"Package": "ggplot2",
						"Version": "3.4.4",
						"Source": "Repository",
						"Repository": "CRAN"
					},
					"tidyr": {
						"Package": "tidyr",
						"Version": "1.3.1",
						"Source": "Repository",
						"Repository": "CRAN"
					}
				}
			}`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"dplyr":   "1.1.4",
				"ggplot2": "3.4.4",
				"tidyr":   "1.3.1",
			},
		},
		{
			name:      "no packages key",
			input:     `{"R": {"Version": "4.3.1"}}`,
			wantCount: 0,
		},
		{
			name:      "empty packages",
			input:     `{"Packages": {}}`,
			wantCount: 0,
		},
		{
			name:    "invalid json",
			input:   `not json`,
			wantErr: true,
		},
		{
			name: "package with empty version",
			input: `{
				"Packages": {
					"dplyr": {"Package": "dplyr", "Version": "1.1.4"},
					"bad": {"Package": "bad", "Version": ""}
				}
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"dplyr": "1.1.4"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewCRANParser().Parse(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pkgs) != tt.wantCount {
				if tt.wantErr {
					t.Fatalf("got %d packages, want %d (with error)", len(pkgs), tt.wantCount)
				}
				t.Fatalf("got %d packages, want %d", len(pkgs), tt.wantCount)
			}
			assertParsedPackages(t, pkgs, tt.wantPkgs, domain.EcosystemCRAN)
		})
	}
}
