package parser

import (
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestHexParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewHexParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"mix.lock", true},
		{"Mix.lock", false},
		{"mix.exs", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestHexParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewHexParser().Ecosystem(); got != domain.EcosystemHex {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemHex)
	}
}

func TestHexParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "valid mix.lock",
			input: `%{
  "jason": {:hex, :jason, "1.4.1", "af1c63c72f3135dd2cba27fdb80cdcfb824e9710e22cbd0b046ecf1200913034", [:mix], [], "hexpm", "fba22f9b4ba3b6cd7ca80b2bbd63e429d3241de8d99cd3de4aebe7d46b03bd09"},
  "phoenix": {:hex, :phoenix, "1.7.12", "abc123", [:mix], [{:jason, "~> 1.0", [hex: :jason, repo: "hexpm", optional: false]}], "hexpm", "def456"},
  "plug": {:hex, :plug, "1.15.3", "ghi789", [:mix], [], "hexpm", "jkl012"},
}
`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"jason":   "1.4.1",
				"phoenix": "1.7.12",
				"plug":    "1.15.3",
			},
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name:      "only map delimiters",
			input:     "%{\n}\n",
			wantCount: 0,
		},
		{
			name: "non-hex entries skipped",
			input: `%{
  "jason": {:hex, :jason, "1.4.1", "hash", [:mix], [], "hexpm", "hash"},
  "local_dep": {:path, "../local_dep"},
}
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"jason": "1.4.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewHexParser().Parse(strings.NewReader(tt.input))
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
				if pkg.Ecosystem != domain.EcosystemHex {
					t.Errorf("package %q ecosystem = %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemHex)
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
