package parser

import (
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestGradleParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewGradleParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"gradle.lockfile", true},
		{"GRADLE.LOCKFILE", true}, // case-insensitive
		{"Gradle.Lockfile", true}, // case-insensitive
		{"build.gradle", false},
		{"settings.gradle", false},
		{"package-lock.json", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestGradleParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewGradleParser().Ecosystem(); got != domain.EcosystemMaven {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemMaven)
	}
}

func TestGradleParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "normal gradle.lockfile",
			input: `# This is a Gradle generated file for dependency locking.
# Manual edits can mess up your build.
# This file is expected to be part of source control.
com.google.guava:guava:33.0.0-jre=compileClasspath,runtimeClasspath
org.apache.commons:commons-lang3:3.14.0=compileClasspath,runtimeClasspath
io.netty:netty-all:4.1.107.Final=runtimeClasspath
empty=
`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"com.google.guava:guava":           "33.0.0-jre",
				"org.apache.commons:commons-lang3": "3.14.0",
				"io.netty:netty-all":               "4.1.107.Final",
			},
		},
		{
			name: "comments and empty lines only",
			input: `# This is a Gradle generated file for dependency locking.
# Manual edits can mess up your build.

empty=
`,
			wantCount: 0,
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name: "empty configurations only",
			input: `# This is a Gradle generated file for dependency locking.
empty=
`,
			wantCount: 0,
		},
		{
			name: "malformed line mixed with valid",
			input: `# Header
com.google.guava:guava:33.0.0-jre=compileClasspath
this-is-not-valid
org.apache.commons:commons-lang3:3.14.0=compileClasspath
`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"com.google.guava:guava":           "33.0.0-jre",
				"org.apache.commons:commons-lang3": "3.14.0",
			},
			wantErr: true,
		},
		{
			name: "duplicate entries are deduplicated",
			input: `com.google.guava:guava:33.0.0-jre=compileClasspath
com.google.guava:guava:33.0.0-jre=runtimeClasspath
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"com.google.guava:guava": "33.0.0-jre"},
		},
		{
			name: "entry without equals sign",
			input: `com.google.guava:guava:33.0.0-jre
org.apache.commons:commons-lang3:3.14.0=compileClasspath
`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"com.google.guava:guava":           "33.0.0-jre",
				"org.apache.commons:commons-lang3": "3.14.0",
			},
		},
		{
			name: "entry with empty version",
			input: `com.google.guava:guava:=compileClasspath
org.apache.commons:commons-lang3:3.14.0=compileClasspath
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"org.apache.commons:commons-lang3": "3.14.0"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewGradleParser().Parse(strings.NewReader(tt.input))
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
				if pkg.Ecosystem != domain.EcosystemMaven {
					t.Errorf("package %q ecosystem = %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemMaven)
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

func TestGradleParserMarksTestConfigurationsAsDev(t *testing.T) {
	t.Parallel()

	input := `com.example:runtime:1.0.0=compileClasspath,runtimeClasspath
com.example:test-helper:2.0.0=testRuntimeClasspath,testCompileClasspath
com.example:both:3.0.0=testRuntimeClasspath
com.example:both:3.0.0=runtimeClasspath
`
	pkgs, err := NewGradleParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dev := make(map[string]bool, len(pkgs))
	for _, pkg := range pkgs {
		dev[pkg.Name] = pkg.Dev
	}
	if dev["com.example:runtime"] {
		t.Fatalf("runtime dependency marked dev")
	}
	if !dev["com.example:test-helper"] {
		t.Fatalf("test-helper not marked dev")
	}
	if dev["com.example:both"] {
		t.Fatalf("package present in runtime and test configurations should be runtime")
	}
}
