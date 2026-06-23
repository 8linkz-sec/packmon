package parser

import (
	"fmt"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

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
		{".github/workflows/ci.yml", domain.EcosystemGitHubActions, false},
		{".github/workflows/release.yaml", domain.EcosystemGitHubActions, false},
		// Negative cases.
		{"unknown.file", "", true},
		{"README.md", "", true},
		{".github/dependabot.yml", "", true},
		{"ci.yml", "", true},
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

func TestDedupProductionWins(t *testing.T) {
	t.Parallel()

	// The same name+version+ecosystem seen as both a dev and a production
	// dependency must collapse to a single production entry, regardless of the
	// order in which they appear.
	devThenProd := dedup([]domain.Package{
		{Name: "a", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Dev: true},
		{Name: "a", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Dev: false},
	})
	if len(devThenProd) != 1 || devThenProd[0].Dev {
		t.Fatalf("dev-then-prod = %+v, want a single non-dev entry", devThenProd)
	}

	prodThenDev := dedup([]domain.Package{
		{Name: "a", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Dev: false},
		{Name: "a", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Dev: true},
	})
	if len(prodThenDev) != 1 || prodThenDev[0].Dev {
		t.Fatalf("prod-then-dev = %+v, want a single non-dev entry", prodThenDev)
	}

	// A package that is only ever dev stays dev.
	devOnly := dedup([]domain.Package{
		{Name: "a", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Dev: true},
		{Name: "a", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Dev: true},
	})
	if len(devOnly) != 1 || !devOnly[0].Dev {
		t.Fatalf("dev-only = %+v, want a single dev entry", devOnly)
	}
}

func TestDedupMergesPackageMetadata(t *testing.T) {
	t.Parallel()

	result := dedup([]domain.Package{
		{
			Name:      "postcss",
			Version:   "8.5.8",
			Ecosystem: domain.EcosystemNPM,
			Dev:       true,
			Indirect:  true,
			Peer:      true,
			Via:       []string{"tailwindcss"},
		},
		{
			Name:      "postcss",
			Version:   "8.5.8",
			Ecosystem: domain.EcosystemNPM,
			Direct:    true,
			Optional:  true,
			Via:       []string{"other"},
		},
	})

	if len(result) != 1 {
		t.Fatalf("dedup returned %d packages, want 1", len(result))
	}
	pkg := result[0]
	if pkg.Dev || !pkg.Direct || !pkg.Indirect || !pkg.Optional || !pkg.Peer {
		t.Fatalf("merged metadata = %+v, want production direct+indirect optional peer", pkg)
	}
	if len(pkg.Via) != 2 || pkg.Via[0] != "other" || pkg.Via[1] != "tailwindcss" {
		t.Fatalf("Via = %#v, want sorted merged roots", pkg.Via)
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
