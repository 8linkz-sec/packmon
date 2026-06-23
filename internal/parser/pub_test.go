package parser

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestPubParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewPubParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"pubspec.lock", true},
		{"Pubspec.lock", false},
		{"pubspec.yaml", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestPubParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewPubParser().Ecosystem(); got != domain.EcosystemPub {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemPub)
	}
}

func TestPubParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "valid pubspec.lock",
			input: `packages:
  http:
    version: "1.2.1"
  path:
    version: "1.9.0"
  collection:
    version: "1.18.0"
`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"http":       "1.2.1",
				"path":       "1.9.0",
				"collection": "1.18.0",
			},
		},
		{
			name:      "empty packages map",
			input:     `packages:`,
			wantCount: 0,
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name:    "invalid yaml",
			input:   `{{{not yaml`,
			wantErr: true,
		},
		{
			name: "package with empty version",
			input: `packages:
  http:
    version: "1.2.1"
  bad:
    version: ""
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"http": "1.2.1"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewPubParser().Parse(strings.NewReader(tt.input))
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
				if pkg.Ecosystem != domain.EcosystemPub {
					t.Errorf("package %q ecosystem = %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemPub)
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
