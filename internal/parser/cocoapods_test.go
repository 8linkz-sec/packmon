package parser

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
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

func TestCocoaPodsParseStateAdvance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		state     cocoaPodsParseState
		line      string
		wantState cocoaPodsParseState
		wantOK    bool
	}{
		{
			name:      "enter pods section",
			line:      "PODS:",
			wantState: cocoaPodsParseState{section: cocoaPodsSectionPods},
			wantOK:    true,
		},
		{
			name:      "dependency section exits pods",
			state:     cocoaPodsParseState{section: cocoaPodsSectionPods},
			line:      "DEPENDENCIES:",
			wantState: cocoaPodsParseState{section: cocoaPodsSectionOther},
			wantOK:    true,
		},
		{
			name:      "spec checksums section exits pods",
			state:     cocoaPodsParseState{section: cocoaPodsSectionPods},
			line:      "SPEC CHECKSUMS:",
			wantState: cocoaPodsParseState{section: cocoaPodsSectionOther},
			wantOK:    true,
		},
		{
			name:      "external sources section exits pods",
			state:     cocoaPodsParseState{section: cocoaPodsSectionPods},
			line:      "EXTERNAL SOURCES:",
			wantState: cocoaPodsParseState{section: cocoaPodsSectionOther},
			wantOK:    true,
		},
		{
			name:      "enter spec repos section",
			line:      "SPEC REPOS:",
			wantState: cocoaPodsParseState{section: cocoaPodsSectionSpecRepos},
			wantOK:    true,
		},
		{
			name:      "record current spec repo",
			state:     cocoaPodsParseState{section: cocoaPodsSectionSpecRepos},
			line:      "  https://pods.internal.example/specs.git:",
			wantState: cocoaPodsParseState{section: cocoaPodsSectionSpecRepos, currentSpecRepo: "https://pods.internal.example/specs.git"},
			wantOK:    true,
		},
		{
			name:      "spec repo package line is left to parser",
			state:     cocoaPodsParseState{section: cocoaPodsSectionSpecRepos, currentSpecRepo: "trunk"},
			line:      "    - Firebase/Core",
			wantState: cocoaPodsParseState{section: cocoaPodsSectionSpecRepos, currentSpecRepo: "trunk"},
			wantOK:    false,
		},
		{
			name:      "pod line is left to parser",
			state:     cocoaPodsParseState{section: cocoaPodsSectionPods},
			line:      "  - Alamofire (5.9.0)",
			wantState: cocoaPodsParseState{section: cocoaPodsSectionPods},
			wantOK:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotState, gotOK := advanceCocoaPodsParseState(tt.state, tt.line)
			if gotOK != tt.wantOK {
				t.Fatalf("advanceCocoaPodsParseState() handled = %v, want %v", gotOK, tt.wantOK)
			}
			if gotState != tt.wantState {
				t.Fatalf("advanceCocoaPodsParseState() state = %+v, want %+v", gotState, tt.wantState)
			}
		})
	}
}

func TestParseCocoaPodsPodLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		line        string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{
			name:        "top level pod",
			line:        "  - Alamofire (5.9.0)",
			wantName:    "Alamofire",
			wantVersion: "5.9.0",
			wantOK:      true,
		},
		{
			name:        "top level subspec collapses to root",
			line:        "  - Firebase/Core (10.22.0):",
			wantName:    "Firebase",
			wantVersion: "10.22.0",
			wantOK:      true,
		},
		{
			name:   "sub dependency is ignored",
			line:   "    - FirebaseAnalytics (~> 10.22.0)",
			wantOK: false,
		},
		{
			name:   "dependency section entry without version is ignored",
			line:   "  - Firebase/Core",
			wantOK: false,
		},
		{
			name:   "unindented pod is ignored",
			line:   "- Alamofire (5.9.0)",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotName, gotVersion, gotOK := parseCocoaPodsPodLine(tt.line)
			if gotOK != tt.wantOK {
				t.Fatalf("parseCocoaPodsPodLine() ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Fatalf("parseCocoaPodsPodLine() = (%q, %q), want (%q, %q)", gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}

func TestParseCocoaPodsSpecRepoPackageLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		repo     string
		line     string
		wantName string
		wantOK   bool
	}{
		{
			name:     "spec repo pod",
			repo:     "trunk",
			line:     "    - Alamofire",
			wantName: "Alamofire",
			wantOK:   true,
		},
		{
			name:     "spec repo subspec collapses to root",
			repo:     "https://pods.internal.example/specs.git",
			line:     "    - Firebase/Core",
			wantName: "Firebase",
			wantOK:   true,
		},
		{
			name:   "missing current repo is ignored",
			line:   "    - Alamofire",
			wantOK: false,
		},
		{
			name:   "repo header is ignored",
			repo:   "trunk",
			line:   "  trunk:",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotName, gotOK := parseCocoaPodsSpecRepoPackageLine(tt.repo, tt.line)
			if gotOK != tt.wantOK {
				t.Fatalf("parseCocoaPodsSpecRepoPackageLine() ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotName != tt.wantName {
				t.Fatalf("parseCocoaPodsSpecRepoPackageLine() name = %q, want %q", gotName, tt.wantName)
			}
		})
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
		{
			name: "dependency checksums and external source sections not extracted",
			input: `PODS:
  - Alamofire (5.9.0)

DEPENDENCIES:
  - DependencyOnly (1.0.0)

SPEC CHECKSUMS:
  ChecksumOnly: 42

EXTERNAL SOURCES:
  - ExternalOnly (2.0.0)

SPEC REPOS:
  trunk:
    - Alamofire
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
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pkgs) != tt.wantCount {
				if tt.wantErr {
					t.Fatalf("got %d packages, want %d (with error)", len(pkgs), tt.wantCount)
				}
				t.Fatalf("got %d packages, want %d", len(pkgs), tt.wantCount)
			}
			assertParsedPackages(t, pkgs, tt.wantPkgs, domain.EcosystemCocoaPods)
		})
	}
}
