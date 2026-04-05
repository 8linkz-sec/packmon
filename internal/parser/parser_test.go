package parser

import (
	"fmt"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestNewRegistry_AllParsersRegistered(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	parsers := r.AllParsers()

	// There are 20 built-in parsers according to the Registry constructor.
	const expectedCount = 20
	if len(parsers) != expectedCount {
		t.Fatalf("AllParsers() returned %d parsers, want %d", len(parsers), expectedCount)
	}
}

func TestRegistry_ParserFor(t *testing.T) {
	t.Parallel()
	r := NewRegistry()

	tests := []struct {
		path          string
		wantEcosystem domain.Ecosystem
		wantNil       bool
	}{
		{"package-lock.json", domain.EcosystemNPM, false},
		{"yarn.lock", domain.EcosystemNPM, false},
		{"pnpm-lock.yaml", domain.EcosystemNPM, false},
		{"Pipfile.lock", domain.EcosystemPyPI, false},
		{"poetry.lock", domain.EcosystemPyPI, false},
		{"uv.lock", domain.EcosystemPyPI, false},
		{"requirements.txt", domain.EcosystemPyPI, false},
		{"go.sum", domain.EcosystemGo, false},
		{"go.mod", domain.EcosystemGo, false},
		{"Cargo.lock", domain.EcosystemCargo, false},
		{"packages.lock.json", domain.EcosystemNuGet, false},
		{"composer.lock", domain.EcosystemComposer, false},
		{"Gemfile.lock", domain.EcosystemGem, false},
		{"pubspec.lock", domain.EcosystemPub, false},
		{"Podfile.lock", domain.EcosystemCocoaPods, false},
		{"Package.resolved", domain.EcosystemSwiftPM, false},
		{"mix.lock", domain.EcosystemHex, false},
		{"renv.lock", domain.EcosystemCRAN, false},
		{"pom.xml", domain.EcosystemMaven, false},
		{"gradle.lockfile", domain.EcosystemMaven, false},
		// Negative cases.
		{"unknown.file", "", true},
		{"README.md", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			p := r.ParserFor(tt.path)
			if tt.wantNil {
				if p != nil {
					t.Errorf("ParserFor(%q) = %T, want nil", tt.path, p)
				}
				return
			}
			if p == nil {
				t.Fatalf("ParserFor(%q) = nil, want parser for %q", tt.path, tt.wantEcosystem)
			}
			if got := p.Ecosystem(); got != tt.wantEcosystem {
				t.Errorf("ParserFor(%q).Ecosystem() = %q, want %q", tt.path, got, tt.wantEcosystem)
			}
		})
	}
}

func TestRegistry_ParserFor_WithSubdirectory(t *testing.T) {
	t.Parallel()
	r := NewRegistry()

	// ParserFor should extract the base name from a path with directories.
	tests := []struct {
		path          string
		wantEcosystem domain.Ecosystem
	}{
		{"some/dir/package-lock.json", domain.EcosystemNPM},
		{"deep/nested/path/go.sum", domain.EcosystemGo},
		{"./Cargo.lock", domain.EcosystemCargo},
	}

	for _, tt := range tests {
		p := r.ParserFor(tt.path)
		if p == nil {
			t.Fatalf("ParserFor(%q) = nil, want parser for %q", tt.path, tt.wantEcosystem)
		}
		if got := p.Ecosystem(); got != tt.wantEcosystem {
			t.Errorf("ParserFor(%q).Ecosystem() = %q, want %q", tt.path, got, tt.wantEcosystem)
		}
	}
}

func TestRegistry_SupportedFiles(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	files := r.SupportedFiles()

	if len(files) == 0 {
		t.Fatal("SupportedFiles() returned empty slice")
	}

	// Verify all expected file names are present.
	expected := map[string]bool{
		"package-lock.json":  false,
		"yarn.lock":          false,
		"pnpm-lock.yaml":     false,
		"Pipfile.lock":       false,
		"poetry.lock":        false,
		"uv.lock":            false,
		"requirements.txt":   false,
		"go.sum":             false,
		"go.mod":             false,
		"Cargo.lock":         false,
		"packages.lock.json": false,
		"composer.lock":      false,
		"Gemfile.lock":       false,
		"pubspec.lock":       false,
		"Podfile.lock":       false,
		"Package.resolved":   false,
		"mix.lock":           false,
		"renv.lock":          false,
		"pom.xml":            false,
		"gradle.lockfile":    false,
	}

	for _, f := range files {
		if _, ok := expected[f]; ok {
			expected[f] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("SupportedFiles() missing %q", name)
		}
	}
}

func TestRegistry_Register_CustomParser(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	before := len(r.AllParsers())

	// Register a dummy parser; use an existing type for convenience.
	r.Register(NewNPMParser())

	after := len(r.AllParsers())
	if after != before+1 {
		t.Errorf("after Register, AllParsers() returned %d, want %d", after, before+1)
	}
}

func TestDedup(t *testing.T) {
	t.Parallel()

	pkgs := []domain.Package{
		{Name: "a", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "b", Version: "2.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "a", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}, // duplicate
		{Name: "a", Version: "2.0.0", Ecosystem: domain.EcosystemNPM}, // different version, not duplicate
		{Name: "a", Version: "1.0.0", Ecosystem: domain.EcosystemGo},  // different ecosystem, not duplicate
	}

	result := dedup(pkgs)
	if len(result) != 4 {
		t.Fatalf("dedup returned %d packages, want 4", len(result))
	}
}

func TestJoinErrors(t *testing.T) {
	t.Parallel()

	if err := joinErrors(nil); err != nil {
		t.Errorf("joinErrors(nil) = %v, want nil", err)
	}

	if err := joinErrors([]error{}); err != nil {
		t.Errorf("joinErrors([]) = %v, want nil", err)
	}

	errs := []error{
		fmt.Errorf("error 1"),
		fmt.Errorf("error 2"),
	}
	err := joinErrors(errs)
	if err == nil {
		t.Fatal("joinErrors with errors returned nil")
	}
	msg := err.Error()
	if !contains(msg, "error 1") || !contains(msg, "error 2") {
		t.Errorf("joinErrors message = %q, want to contain both errors", msg)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchStr(s, sub)
}

func searchStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
