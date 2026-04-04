package parser

import (
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestCocoaPodsParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewCocoaPodsParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"Podfile.lock", true},
		{"podfile.lock", false},
		{"Gemfile.lock", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestCocoaPodsParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewCocoaPodsParser().Ecosystem(); got != domain.EcosystemCocoaPods {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemCocoaPods)
	}
}

func TestCocoaPodsParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "valid Podfile.lock",
			input: `PODS:
  - Alamofire (5.9.0)
  - Firebase/Core (10.22.0):
    - FirebaseAnalytics (~> 10.22.0)
  - SDWebImage (5.19.1)

DEPENDENCIES:
  - Alamofire
  - Firebase/Core
  - SDWebImage

SPEC REPOS:
  trunk:
    - Alamofire
`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"Alamofire":  "5.9.0",
				"Firebase":   "10.22.0",
				"SDWebImage": "5.19.1",
			},
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
			wantErr:   true, // "no PODS section found"
		},
		{
			name: "no PODS section",
			input: `DEPENDENCIES:
  - Alamofire
`,
			wantCount: 0,
			wantErr:   true,
		},
		{
			name: "subspecs collapsed to root pod",
			input: `PODS:
  - Firebase/Core (10.22.0)
  - Firebase/Messaging (10.22.0)
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"Firebase": "10.22.0"},
		},
		{
			name: "sub-dependencies not extracted",
			input: `PODS:
  - Alamofire (5.9.0):
    - AlamofireImage (~> 4.0)
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"Alamofire": "5.9.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewCocoaPodsParser().Parse(strings.NewReader(tt.input))
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
				if pkg.Ecosystem != domain.EcosystemCocoaPods {
					t.Errorf("package %q ecosystem = %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemCocoaPods)
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
