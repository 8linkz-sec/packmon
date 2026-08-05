package parser

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
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
			name: "v1 branch-only pin skipped",
			input: `{
				"version": 1,
				"object": {
					"pins": [
						{
							"package": "BranchDep",
							"repositoryURL": "https://example.com/branch-dep.git",
							"state": {"revision": "abc123", "branch": "main"}
						},
						{
							"package": "VersionedDep",
							"repositoryURL": "https://example.com/versioned-dep.git",
							"state": {"version": "1.2.3", "revision": "def456", "branch": null}
						}
					]
				}
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"example.com/versioned-dep": "1.2.3"},
		},
		{
			name: "v1 revision-only pin skipped",
			input: `{
				"version": 1,
				"object": {
					"pins": [
						{
							"package": "RevisionDep",
							"repositoryURL": "https://example.com/revision-dep.git",
							"state": {"revision": "abc123"}
						},
						{
							"package": "VersionedDep",
							"repositoryURL": "https://example.com/versioned-dep.git",
							"state": {"version": "1.2.3", "revision": "def456", "branch": null}
						}
					]
				}
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"example.com/versioned-dep": "1.2.3"},
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
			name: "url userinfo is discarded from canonical identity",
			input: `{
				"version": 2,
				"pins": [
					{
						"identity": "private-lib",
						"location": "https://user:token@example.com/org/private-lib.git",
						"state": {"version": "1.2.3", "revision": "abc"}
					}
				]
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"example.com/org/private-lib": "1.2.3"},
		},
		{
			name: "non-http URL scheme falls back to identity",
			input: `{
				"version": 2,
				"pins": [
					{
						"identity": "private-lib",
						"location": "ssh://internal-host/org/private-lib.git",
						"state": {"version": "1.2.3", "revision": "abc"}
					}
				]
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"private-lib": "1.2.3"},
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

func TestSwiftPMParserRedactsRepositoryURLsInErrors(t *testing.T) {
	//nolint:gosec // fake credential-bearing URL verifies redaction.
	input := `{
		"version": 2,
		"pins": [
			{
				"identity": "",
				"location": "ssh://user:token@internal-host/org/private-lib.git",
				"state": {"version": "1.2.3", "revision": "abc"}
			}
		]
	}`

	_, err := NewSwiftPMParser().Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("Parse() error = nil, want redacted skipped-entry error")
	}
	msg := err.Error()
	for _, leaked := range []string{"user:token", "internal-host/org/private-lib", "private-lib.git"} {
		if strings.Contains(msg, leaked) {
			t.Fatalf("SwiftPM parse error leaked %q in %q", leaked, msg)
		}
	}
	if !strings.Contains(msg, "ssh://internal-host/...") {
		t.Fatalf("SwiftPM parse error = %q, want redacted URL host", msg)
	}
}

func TestSwiftPMParserV1RedactsRepositoryURLsInErrors(t *testing.T) {
	//nolint:gosec // fake credential-bearing URL verifies redaction.
	input := `{
		"version": 1,
		"object": {
			"pins": [
				{
					"package": "",
					"repositoryURL": "ssh://user:token@internal-host/org/private-lib.git",
					"state": {"version": "1.2.3", "revision": "abc", "branch": null}
				}
			]
		}
	}`

	pkgs, err := NewSwiftPMParser().Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("Parse() error = nil, want redacted skipped-entry error")
	}
	if len(pkgs) != 0 {
		t.Fatalf("Parse() returned %d packages, want 0", len(pkgs))
	}
	msg := err.Error()
	for _, want := range []string{"swiftpm v1", "empty package name", "ssh://internal-host/..."} {
		if !strings.Contains(msg, want) {
			t.Fatalf("SwiftPM parse error = %q, want %q", msg, want)
		}
	}
	for _, leaked := range []string{"user:token", "internal-host/org/private-lib", "private-lib.git"} {
		if strings.Contains(msg, leaked) {
			t.Fatalf("SwiftPM parse error leaked %q in %q", leaked, msg)
		}
	}
}

func TestSwiftPMParserLocalPathsUseFallbackIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		wantName string
		wantVer  string
	}{
		{
			name: "v2 relative local path",
			input: `{
				"version": 2,
				"pins": [
					{
						"identity": "local-helper",
						"location": "../Private/LocalHelper",
						"state": {"version": "1.2.3", "revision": "abc"}
					}
				]
			}`,
			wantName: "local-helper",
			wantVer:  "1.2.3",
		},
		{
			name: "v1 absolute local path",
			input: `{
				"version": 1,
				"object": {
					"pins": [
						{
							"package": "LocalHelper",
							"repositoryURL": "/Users/alice/Private/LocalHelper",
							"state": {"version": "2.3.4", "revision": "def", "branch": null}
						}
					]
				}
			}`,
			wantName: "LocalHelper",
			wantVer:  "2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkgs, err := NewSwiftPMParser().Parse(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(pkgs) != 1 {
				t.Fatalf("Parse() returned %d packages, want 1", len(pkgs))
			}
			if pkgs[0].Name != tt.wantName {
				t.Fatalf("Parse() package name = %q, want %q", pkgs[0].Name, tt.wantName)
			}
			if pkgs[0].Version != tt.wantVer {
				t.Fatalf("Parse() package version = %q, want %q", pkgs[0].Version, tt.wantVer)
			}
		})
	}
}

func TestSwiftPMParserLocalPathsRedactedInErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		leaked   []string
		wantHint string
	}{
		{
			name: "v2 relative local path",
			input: `{
				"version": 2,
				"pins": [
					{
						"identity": "",
						"location": "../Private/LocalHelper",
						"state": {"version": "1.2.3", "revision": "abc"}
					}
				]
			}`,
			leaked:   []string{"../Private/LocalHelper", "Private", "LocalHelper"},
			wantHint: "<redacted>",
		},
		{
			name: "v1 absolute local path",
			input: `{
				"version": 1,
				"object": {
					"pins": [
						{
							"package": "",
							"repositoryURL": "/Users/alice/Private/LocalHelper",
							"state": {"version": "2.3.4", "revision": "def", "branch": null}
						}
					]
				}
			}`,
			leaked:   []string{"/Users/alice/Private/LocalHelper", "alice", "Private", "LocalHelper"},
			wantHint: "<redacted>",
		},
		{
			name: "v2 file URL with path-like identity",
			input: `{
				"version": 2,
				"pins": [
					{
						"identity": "../Private/LocalHelper",
						"location": "file:///Users/alice/Private/LocalHelper",
						"state": {"version": "3.4.5", "revision": "ghi"}
					}
				]
			}`,
			leaked:   []string{"/Users/alice/Private/LocalHelper", "alice", "Private", "LocalHelper"},
			wantHint: "file://...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkgs, err := NewSwiftPMParser().Parse(strings.NewReader(tt.input))
			if err == nil {
				t.Fatal("Parse() error = nil, want redacted skipped-entry error")
			}
			if len(pkgs) != 0 {
				t.Fatalf("Parse() returned %d packages, want 0", len(pkgs))
			}
			msg := err.Error()
			if !strings.Contains(msg, tt.wantHint) {
				t.Fatalf("SwiftPM parse error = %q, want %q", msg, tt.wantHint)
			}
			for _, leaked := range tt.leaked {
				if strings.Contains(msg, leaked) {
					t.Fatalf("SwiftPM parse error leaked %q in %q", leaked, msg)
				}
			}
		})
	}
}
