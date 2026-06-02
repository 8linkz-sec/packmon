package parser

import (
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestSwiftPMParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewSwiftPMParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"Package.resolved", true},
		{"package.resolved", false},
		{"Podfile.lock", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestSwiftPMParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewSwiftPMParser().Ecosystem(); got != domain.EcosystemSwiftPM {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemSwiftPM)
	}
}

func TestSwiftPMParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "v2 format",
			input: `{
				"version": 2,
				"pins": [
					{
						"identity": "alamofire",
						"location": "https://github.com/Alamofire/Alamofire.git",
						"state": {"version": "5.9.0", "revision": "abc123"}
					},
					{
						"identity": "swift-argument-parser",
						"location": "https://github.com/apple/swift-argument-parser.git",
						"state": {"version": "1.3.0", "revision": "def456"}
					}
				]
			}`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"github.com/Alamofire/Alamofire":         "5.9.0",
				"github.com/apple/swift-argument-parser": "1.3.0",
			},
		},
		{
			name: "v1 format",
			input: `{
				"version": 1,
				"object": {
					"pins": [
						{
							"package": "Alamofire",
							"repositoryURL": "https://github.com/Alamofire/Alamofire.git",
							"state": {"version": "5.9.0", "revision": "abc123", "branch": null}
						},
						{
							"package": "Kingfisher",
							"repositoryURL": "https://github.com/onevcat/Kingfisher.git",
							"state": {"version": "7.11.0", "revision": "def456", "branch": null}
						}
					]
				}
			}`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"github.com/Alamofire/Alamofire": "5.9.0",
				"github.com/onevcat/Kingfisher":  "7.11.0",
			},
		},
		{
			name: "v3 format (same as v2)",
			input: `{
				"version": 3,
				"pins": [
					{
						"identity": "swift-nio",
						"location": "https://github.com/apple/swift-nio.git",
						"state": {"version": "2.65.0", "revision": "abc"}
					}
				]
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"github.com/apple/swift-nio": "2.65.0"},
		},
		{
			name: "branch pin skipped (no version)",
			input: `{
				"version": 2,
				"pins": [
					{
						"identity": "branch-dep",
						"location": "https://example.com/repo.git",
						"state": {"version": "", "revision": "abc", "branch": "main"}
					},
					{
						"identity": "versioned-dep",
						"location": "https://example.com/other.git",
						"state": {"version": "1.0.0", "revision": "def"}
					}
				]
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"example.com/other": "1.0.0"},
		},
		{
			name:      "empty pins",
			input:     `{"version": 2, "pins": []}`,
			wantCount: 0,
		},
		{
			name:    "invalid json",
			input:   `{broken`,
			wantErr: true,
		},
		{
			name: "v2 pin with empty identity and location",
			input: `{
				"version": 2,
				"pins": [
					{
						"identity": "",
						"location": "https://example.com/repo.git",
						"state": {"version": "1.0.0", "revision": "abc"}
					}
				]
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"example.com/repo": "1.0.0"},
		},
		{
			name: "scp-style location canonicalized",
			input: `{
				"version": 2,
				"pins": [
					{
						"identity": "swift-nio",
						"location": "git@github.com:apple/swift-nio.git",
						"state": {"version": "2.65.0", "revision": "abc"}
					}
				]
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"github.com/apple/swift-nio": "2.65.0"},
		},
		{
			name: "v2 pin with empty identity and location",
			input: `{
				"version": 2,
				"pins": [
					{
						"identity": "",
						"location": "",
						"state": {"version": "1.0.0", "revision": "abc"}
					}
				]
			}`,
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewSwiftPMParser().Parse(strings.NewReader(tt.input))
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
			seen := make(map[string]struct{}, len(pkgs))
			for _, pkg := range pkgs {
				if pkg.Ecosystem != domain.EcosystemSwiftPM {
					t.Errorf("package %q ecosystem = %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemSwiftPM)
				}
				if wantVer, ok := tt.wantPkgs[pkg.Name]; ok {
					if pkg.Version != wantVer {
						t.Errorf("package %q version = %q, want %q", pkg.Name, pkg.Version, wantVer)
					}
				} else if len(tt.wantPkgs) > 0 {
					t.Errorf("unexpected package %q@%s", pkg.Name, pkg.Version)
				}
				seen[pkg.Name] = struct{}{}
			}
			for wantName := range tt.wantPkgs {
				if _, ok := seen[wantName]; !ok {
					t.Errorf("missing package %q", wantName)
				}
			}
		})
	}
}
