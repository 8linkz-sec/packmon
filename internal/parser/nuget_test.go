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
				"Newtonsoft.Json": "13.0.3",
				"Serilog":         "3.1.1",
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
			wantPkgs:  map[string]string{"Newtonsoft.Json": "13.0.3"},
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
			wantPkgs:  map[string]string{"Newtonsoft.Json": "13.0.3"},
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
				if len(pkgs) != tt.wantCount {
					t.Fatalf("got %d packages, want %d (with error)", len(pkgs), tt.wantCount)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pkgs) != tt.wantCount {
				t.Fatalf("got %d packages, want %d", len(pkgs), tt.wantCount)
			}
			for _, pkg := range pkgs {
				if pkg.Ecosystem != domain.EcosystemNuGet {
					t.Errorf("package %q ecosystem = %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemNuGet)
				}
				if wantVer, ok := tt.wantPkgs[pkg.Name]; ok {
					if pkg.Version != wantVer {
						t.Errorf("package %q version = %q, want %q", pkg.Name, pkg.Version, wantVer)
					}
				}
			}
		})
	}
}
