package parser

import (
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestGemParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewGemParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"Gemfile.lock", true},
		{"gemfile.lock", true}, // case-insensitive
		{"GEMFILE.LOCK", true},
		{"Gemfile", false},
		{"yarn.lock", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestGemParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewGemParser().Ecosystem(); got != domain.EcosystemGem {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemGem)
	}
}

func TestGemParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "valid Gemfile.lock",
			input: `GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.1.3)
      actionpack (= 7.1.3)
    actionpack (7.1.3)
      rack (>= 2.2.4)
    nokogiri (1.16.5)
    rack (3.0.9)

PLATFORMS
  ruby

DEPENDENCIES
  rails

BUNDLED WITH
   2.5.6
`,
			wantCount: 4,
			wantPkgs: map[string]string{
				"actioncable": "7.1.3",
				"actionpack":  "7.1.3",
				"nokogiri":    "1.16.5",
				"rack":        "3.0.9",
			},
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name: "no GEM section",
			input: `PATH
  remote: .
  specs:
    myapp (1.0.0)

PLATFORMS
  ruby
`,
			wantCount: 0,
		},
		{
			name: "sub-dependencies not extracted",
			input: `GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.5)
      racc (~> 1.4)
    racc (1.7.3)
`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"nokogiri": "1.16.5",
				"racc":     "1.7.3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewGemParser().Parse(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
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
				if pkg.Ecosystem != domain.EcosystemGem {
					t.Errorf("package %q ecosystem = %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemGem)
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
