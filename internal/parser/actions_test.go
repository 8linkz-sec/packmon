package parser

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestActionsParserCanParseOnlyWorkflowFiles(t *testing.T) {
	t.Parallel()

	p := NewActionsParser()
	for _, path := range []string{
		".github/workflows/ci.yml",
		".github/workflows/release.yaml",
		`C:\repo\.github\workflows\build.yml`,
	} {
		if !p.CanParse(path) {
			t.Fatalf("CanParse(%q) = false, want true", path)
		}
	}

	for _, path := range []string{
		"ci.yml",
		".github/dependabot.yml",
		".gitlab-ci.yml",
		".github/workflows/readme.md",
	} {
		if p.CanParse(path) {
			t.Fatalf("CanParse(%q) = true, want false", path)
		}
	}
}

func TestActionsParserParseUsesReferences(t *testing.T) {
	t.Parallel()

	input := `
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: Actions/Checkout@v4
      - uses: docker/login-action@v3.1.0
      - uses: github/codeql-action/init@v3
      - uses: actions/checkout@v4
      - uses: ./local-action
      - uses: docker://alpine:3
  reuse:
    uses: octo-org/reusable/.github/workflows/build.yml@v2
`

	pkgs, err := NewActionsParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	want := map[string]string{
		"actions/checkout":     "v4",
		"docker/login-action":  "v3.1.0",
		"github/codeql-action": "v3",
		"octo-org/reusable":    "v2",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("Parse() returned %d packages, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for _, pkg := range pkgs {
		if pkg.Ecosystem != domain.EcosystemGitHubActions {
			t.Fatalf("package ecosystem = %q, want %q", pkg.Ecosystem, domain.EcosystemGitHubActions)
		}
		if got := pkg.Version; got != want[pkg.Name] {
			t.Fatalf("package %q version = %q, want %q", pkg.Name, got, want[pkg.Name])
		}
	}
}

func TestActionsParserInvalidYAMLReturnsError(t *testing.T) {
	t.Parallel()

	if _, err := NewActionsParser().Parse(strings.NewReader("jobs: [")); err == nil {
		t.Fatal("Parse(invalid YAML) error = nil")
	}
}

func TestActionsParserRecordsDeclaredVersionCommentForSHAPins(t *testing.T) {
	t.Parallel()

	const (
		shaCheckout = "11bd71901bbe5b1630ceea73d27597364c9af683"
		shaUpload   = "81c65b7cd4de9b2570615ce3aad67a41de5b1a13"
		shaSetupGo  = "4a3601121dd01d1626a1e23e37211e3254c1c06c"
		shaCache    = "5a3ec84eff668545956fd18022155c47e93e2684"
		shaQuoted   = "0ad4b8fadaa221de15dcec353f45205ec38ea70b"
		shaUpper    = "AB6EEBB4C0F1FBBDDCC1E9B77CBEC0AB2AB4D8F1"
		shaReusable = "3f5df9d5a2b0f7d3f4c9e2b1a6d7c8e9f0a1b2c3"
		shaNoHint   = "cafebabecafebabecafebabecafebabecafebabe"
		shaMajor    = "1234567890abcdef1234567890abcdef12345678"
	)
	input := "name: CI\r\non: [push]\r\njobs:\r\n" +
		"  build:\r\n    runs-on: ubuntu-latest\r\n    steps:\r\n" +
		"      - uses: actions/checkout@" + shaCheckout + " # v4.2.2\r\n" +
		"      - uses: svenstaro/upload-release-action@" + shaUpload + "  #  tag=v2.11.2\r\n" +
		"      - uses: actions/setup-go@" + shaSetupGo + " # 6.4.0 (renovate)\r\n" +
		"      - uses: actions/cache@" + shaCache + " # see docs\r\n" +
		"      - uses: \"docker/login-action@" + shaQuoted + "\" # v3.1.0-beta.1\r\n" +
		"      - uses: 'github/codeql-action/init@" + shaUpper + "' # v3\r\n" +
		"      - uses: actions/setup-node@v4 # v4.0.2\r\n" +
		"      - uses: actions/labeler@" + shaMajor + " # pin@v5\r\n" +
		"      - name: shell\r\n        run: |\r\n          echo \"uses: actions/upload-artifact@" + shaNoHint + " # v9.9.9\"\r\n" +
		"      - uses: actions/upload-artifact@" + shaNoHint + "\r\n" +
		"  reuse:\r\n    uses: octo-org/reusable/.github/workflows/build.yml@" + shaReusable + " # v1.4.0\r\n"

	pkgs, err := NewActionsParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	want := map[string]struct{ version, declared string }{
		"actions/checkout":                {shaCheckout, "v4.2.2"},
		"svenstaro/upload-release-action": {shaUpload, "v2.11.2"},
		"actions/setup-go":                {shaSetupGo, "6.4.0"},
		"actions/cache":                   {shaCache, ""},
		"docker/login-action":             {shaQuoted, "v3.1.0-beta.1"},
		"github/codeql-action":            {shaUpper, "v3"},
		"actions/setup-node":              {"v4", ""},
		"actions/labeler":                 {shaMajor, ""},
		"actions/upload-artifact":         {shaNoHint, ""},
		"octo-org/reusable":               {shaReusable, "v1.4.0"},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("Parse() returned %d packages, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for _, pkg := range pkgs {
		w, ok := want[pkg.Name]
		if !ok {
			t.Fatalf("unexpected package %q", pkg.Name)
		}
		if pkg.Version != w.version {
			t.Errorf("package %q version = %q, want %q", pkg.Name, pkg.Version, w.version)
		}
		if pkg.DeclaredVersion != w.declared {
			t.Errorf("package %q declared version = %q, want %q", pkg.Name, pkg.DeclaredVersion, w.declared)
		}
	}
}

func TestActionsParserFirstDeclaredVersionWinsForDuplicatePins(t *testing.T) {
	t.Parallel()

	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	input := "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@" + sha + "\n" +
		"  b:\n    steps:\n      - uses: actions/checkout@" + sha + " # v4.2.2\n"
	pkgs, err := NewActionsParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("Parse() returned %d packages, want 1: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].DeclaredVersion != "v4.2.2" {
		t.Fatalf("declared version = %q, want the hint from any occurrence of the same pin", pkgs[0].DeclaredVersion)
	}
}

func TestParseActionsVersionComment(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		comment string
		want    string
	}{
		{"# v4.2.2", "v4.2.2"},
		{"#v4.2.2", "v4.2.2"},
		{"# tag=v1.2.3", "v1.2.3"},
		{"# 4.2.2 trailing words", "4.2.2"},
		{"# v3", "v3"},
		{"# v1.0.0-rc.1+build.5", "v1.0.0-rc.1+build.5"},
		{"# V4.2.2", ""},
		{"# pin@v5", ""},
		{"# ratchet:actions/checkout@v4", ""},
		{"# see docs", ""},
		{"# v", ""},
		{"# 4.", ""},
		{"", ""},
	} {
		if got := parseActionsVersionComment(tt.comment); got != tt.want {
			t.Errorf("parseActionsVersionComment(%q) = %q, want %q", tt.comment, got, tt.want)
		}
	}
}
