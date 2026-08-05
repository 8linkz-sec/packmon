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
