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
