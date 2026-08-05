package parser

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestNuGetParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewNuGetParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"packages.lock.json", true},
		{"Packages.Lock.Json", true}, // case-insensitive
		{"PACKAGES.LOCK.JSON", true},
		{"package-lock.json", false},
		{"composer.lock", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestNuGetParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewNuGetParser().Ecosystem(); got != domain.EcosystemNuGet {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemNuGet)
	}
}

func TestNuGetParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "multiple frameworks",
			input: `{
				"version": 2,
				"dependencies": {
					"net8.0": {
						"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"},
						"Serilog": {"type": "Direct", "resolved": "3.1.1"}
					},
					"net6.0": {
						"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}
					}
				}
			}`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"newtonsoft.json": "13.0.3",
				"serilog":         "3.1.1",
			},
		},
		{
			name: "mixed case package IDs are canonicalized",
			input: `{
				"version": 2,
				"dependencies": {
					"net8.0": {
						"Microsoft.Extensions.Logging": {"type": "Direct", "resolved": "8.0.0"}
					}
				}
			}`,
			wantCount: 1,
			wantPkgs: map[string]string{
				"microsoft.extensions.logging": "8.0.0",
			},
		},
		{
			name:      "empty dependencies",
			input:     `{"version": 2, "dependencies": {}}`,
			wantCount: 0,
		},
		{
			name:    "invalid json",
			input:   `not json`,
			wantErr: true,
		},
		{
			name: "missing resolved version",
			input: `{
				"version": 2,
				"dependencies": {
					"net8.0": {
						"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"},
						"BadPkg": {"type": "Direct", "resolved": ""}
					}
				}
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"newtonsoft.json": "13.0.3"},
			wantErr:   true,
		},
		{
			name: "project references are ignored",
			input: `{
				"version": 2,
				"dependencies": {
					"net8.0": {
						"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"},
						"Local.Project": {"type": "Project", "resolved": ""}
					}
				}
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"newtonsoft.json": "13.0.3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewNuGetParser().Parse(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pkgs) != tt.wantCount {
				t.Fatalf("got %d packages, want %d", len(pkgs), tt.wantCount)
			}

			assertPackages(t, pkgs, tt.wantPkgs, domain.EcosystemNuGet)
		})
	}
}
