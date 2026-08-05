package parser

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestParsersRecordPackageSourceRefsForRegistryEgressGating(t *testing.T) {
	tests := []struct {
		name      string
		parse     func() ([]domain.Package, error)
		pkgName   string
		wantRefs  []string
		wantError bool
	}{
		{
			name: "npm package-lock resolved URL",
			parse: func() ([]domain.Package, error) {
				return parseSourceRefPackages(NewNPMParser(), `{
  "lockfileVersion": 3,
  "packages": {
    "": {"version": "1.0.0"},
    "node_modules/@acme/private": {
      "version": "1.0.0",
      "resolved": "https://npm.internal.example/@acme/private/-/private-1.0.0.tgz"
    }
  }
}`)
			},
			pkgName:  "@acme/private",
			wantRefs: []string{"https://npm.internal.example/@acme/private/-/private-1.0.0.tgz"},
		},
		{
			name: "requirements private index",
			parse: func() ([]domain.Package, error) {
				return parseSourceRefPackages(NewRequirementsParser(), `--index-url https://pypi.internal.example/simple
private-pkg==1.0.0
`)
			},
			pkgName:  "private-pkg",
			wantRefs: []string{"https://pypi.internal.example/simple"},
		},
		{
			name: "cargo alternate registry",
			parse: func() ([]domain.Package, error) {
				return parseSourceRefPackages(NewCargoParser(), `[[package]]
name = "private-crate"
version = "1.0.0"
source = "registry+https://cargo.internal.example/index"
`)
			},
			pkgName:  "private-crate",
			wantRefs: []string{"registry+https://cargo.internal.example/index"},
		},
		{
			name: "bundler private remote",
			parse: func() ([]domain.Package, error) {
				return parseSourceRefPackages(NewGemParser(), `GEM
  remote: https://gems.internal.example/
  specs:
    private-gem (1.0.0)
`)
			},
			pkgName:  "private-gem",
			wantRefs: []string{"https://gems.internal.example/"},
		},
		{
			name: "cocoapods private spec repo",
			parse: func() ([]domain.Package, error) {
				return parseSourceRefPackages(NewCocoaPodsParser(), `PODS:
  - AcmePayrollSDK (1.0.0)

DEPENDENCIES:
  - AcmePayrollSDK

SPEC REPOS:
  https://pods.internal.example/specs.git:
    - AcmePayrollSDK
`)
			},
			pkgName:  "AcmePayrollSDK",
			wantRefs: []string{"https://pods.internal.example/specs.git"},
		},
		{
			name: "composer private source and dist URLs",
			parse: func() ([]domain.Package, error) {
				return parseSourceRefPackages(NewComposerParser(), `{
  "packages": [{
    "name": "acme/payroll-sdk",
    "version": "1.0.0",
    "source": {"type": "git", "url": "ssh://git.internal.example/acme/payroll-sdk.git"},
    "dist": {"type": "zip", "url": "https://composer.internal.example/dist/acme/payroll-sdk.zip"}
  }]
}`)
			},
			pkgName: "acme/payroll-sdk",
			wantRefs: []string{
				"https://composer.internal.example/dist/acme/payroll-sdk.zip",
				"ssh://git.internal.example/acme/payroll-sdk.git",
			},
		},
		{
			name: "cran non-cran source",
			parse: func() ([]domain.Package, error) {
				return parseSourceRefPackages(NewCRANParser(), `{
  "Packages": {
    "privateR": {
      "Package": "privateR",
      "Version": "1.0.0",
      "Source": "GitHub",
      "Repository": "internal"
    }
  }
}`)
			},
			pkgName:  "privateR",
			wantRefs: []string{"repository=internal", "source=GitHub"},
		},
		{
			name: "pub private hosted URL",
			parse: func() ([]domain.Package, error) {
				return parseSourceRefPackages(NewPubParser(), `packages:
  private_dart:
    version: "1.0.0"
    source: hosted
    description:
      name: private_dart
      url: "https://pub.internal.example"
`)
			},
			pkgName:  "private_dart",
			wantRefs: []string{"source=hosted", "url=https://pub.internal.example"},
		},
		{
			name: "maven private repository URL",
			parse: func() ([]domain.Package, error) {
				return parseSourceRefPackages(NewMavenParser(), `<project>
  <repositories>
    <repository>
      <id>internal</id>
      <url>https://maven.internal.example/repository/releases</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme.payroll</groupId>
      <artifactId>risk-model</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>`)
			},
			pkgName:  "com.acme.payroll:risk-model",
			wantRefs: []string{"https://maven.internal.example/repository/releases"},
		},
		{
			name: "hex private repository",
			parse: func() ([]domain.Package, error) {
				return parseSourceRefPackages(NewHexParser(), `%{
  "payroll": {:hex, :payroll, "1.0.0", "hash", [:mix], [], "internal_hex", "hash"}
}
`)
			},
			pkgName:  "payroll",
			wantRefs: []string{"repo=internal_hex"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, err := tt.parse()
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got, ok := sourceRefPackageByName(pkgs, tt.pkgName)
			if !ok {
				t.Fatalf("package %q not found in %+v", tt.pkgName, pkgs)
			}
			if !reflect.DeepEqual(got.SourceRefs, tt.wantRefs) {
				t.Fatalf("%s SourceRefs = %#v, want %#v", tt.pkgName, got.SourceRefs, tt.wantRefs)
			}
		})
	}
}

func TestUpdateRequirementSourceRefsOptionVariants(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		current []string
		want    []string
	}{
		{
			name:    "extra index appends space separated value",
			line:    "--extra-index-url https://extra.pypi.example/simple",
			current: []string{"https://primary.pypi.example/simple"},
			want: []string{
				"https://extra.pypi.example/simple",
				"https://primary.pypi.example/simple",
			},
		},
		{
			name:    "find links appends space separated value",
			line:    "--find-links https://wheels.pypi.example/simple",
			current: []string{"https://primary.pypi.example/simple"},
			want: []string{
				"https://primary.pypi.example/simple",
				"https://wheels.pypi.example/simple",
			},
		},
		{
			name:    "no index replaces active refs",
			line:    "--no-index",
			current: []string{"https://primary.pypi.example/simple"},
			want:    []string{"no-index"},
		},
		{
			name:    "index url equals replaces active refs",
			line:    "--index-url=https://replacement.pypi.example/simple",
			current: []string{"https://primary.pypi.example/simple", "https://extra.pypi.example/simple"},
			want:    []string{"https://replacement.pypi.example/simple"},
		},
		{
			name:    "short index equals replaces active refs",
			line:    "-i=https://short.pypi.example/simple",
			current: []string{"https://primary.pypi.example/simple", "https://extra.pypi.example/simple"},
			want:    []string{"https://short.pypi.example/simple"},
		},
		{
			name:    "extra index equals appends active refs",
			line:    "--extra-index-url=https://extra.pypi.example/simple",
			current: []string{"https://primary.pypi.example/simple"},
			want: []string{
				"https://extra.pypi.example/simple",
				"https://primary.pypi.example/simple",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := updateRequirementSourceRefs(tt.line, tt.current)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("updateRequirementSourceRefs(%q, %#v) = %#v, want %#v", tt.line, tt.current, got, tt.want)
			}
		})
	}
}

func TestRequirementsParserSourceRefsOptionVariants(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		pkgName  string
		wantRefs []string
	}{
		{
			name: "extra index appends space separated value",
			input: `--index-url https://primary.pypi.example/simple
--extra-index-url https://extra.pypi.example/simple
extra-pkg==1.0.0
`,
			pkgName: "extra-pkg",
			wantRefs: []string{
				"https://extra.pypi.example/simple",
				"https://primary.pypi.example/simple",
			},
		},
		{
			name: "find links appends space separated value",
			input: `--index-url https://primary.pypi.example/simple
--find-links https://wheels.pypi.example/simple
wheel-pkg==2.0.0
`,
			pkgName: "wheel-pkg",
			wantRefs: []string{
				"https://primary.pypi.example/simple",
				"https://wheels.pypi.example/simple",
			},
		},
		{
			name: "no index replaces active refs",
			input: `--index-url https://primary.pypi.example/simple
--extra-index-url https://extra.pypi.example/simple
--no-index
offline-pkg==3.0.0
`,
			pkgName:  "offline-pkg",
			wantRefs: []string{"no-index"},
		},
		{
			name: "index url equals replaces active refs",
			input: `--extra-index-url https://extra.pypi.example/simple
--index-url=https://replacement.pypi.example/simple
replace-pkg==4.0.0
`,
			pkgName:  "replace-pkg",
			wantRefs: []string{"https://replacement.pypi.example/simple"},
		},
		{
			name: "short index equals replaces active refs",
			input: `--index-url https://primary.pypi.example/simple
--extra-index-url https://extra.pypi.example/simple
-i=https://short.pypi.example/simple
short-pkg==5.0.0
`,
			pkgName:  "short-pkg",
			wantRefs: []string{"https://short.pypi.example/simple"},
		},
		{
			name: "extra index equals appends active refs",
			input: `--index-url https://primary.pypi.example/simple
--extra-index-url=https://extra.pypi.example/simple
eq-extra-pkg==6.0.0
`,
			pkgName: "eq-extra-pkg",
			wantRefs: []string{
				"https://extra.pypi.example/simple",
				"https://primary.pypi.example/simple",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, err := parseSourceRefPackages(NewRequirementsParser(), tt.input)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got, ok := sourceRefPackageByName(pkgs, tt.pkgName)
			if !ok {
				t.Fatalf("package %q not found in %+v", tt.pkgName, pkgs)
			}
			if !reflect.DeepEqual(got.SourceRefs, tt.wantRefs) {
				t.Fatalf("%s SourceRefs = %#v, want %#v", tt.pkgName, got.SourceRefs, tt.wantRefs)
			}
		})
	}
}

type sourceRefParser interface {
	Parse(io.Reader) ([]domain.Package, error)
}

func parseSourceRefPackages(parser sourceRefParser, input string) ([]domain.Package, error) {
	return parser.Parse(strings.NewReader(input))
}

func sourceRefPackageByName(pkgs []domain.Package, name string) (domain.Package, bool) {
	for _, pkg := range pkgs {
		if pkg.Name == name {
			return pkg, true
		}
	}
	return domain.Package{}, false
}
