package parser

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestGemParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewGemParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"Gemfile.lock", true},
		{"gemfile.lock", true}, // case-insensitive
		{"GEMFILE.LOCK", true},
		{"Gemfile", false},
		{"yarn.lock", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestGemParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewGemParser().Ecosystem(); got != domain.EcosystemGem {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemGem)
	}
}

func TestGemParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "valid Gemfile.lock",
			input: `GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.1.3)
      actionpack (= 7.1.3)
    actionpack (7.1.3)
      rack (>= 2.2.4)
    nokogiri (1.16.5)
    rack (3.0.9)

PLATFORMS
  ruby

DEPENDENCIES
  rails

BUNDLED WITH
   2.5.6
`,
			wantCount: 4,
			wantPkgs: map[string]string{
				"actioncable": "7.1.3",
				"actionpack":  "7.1.3",
				"nokogiri":    "1.16.5",
				"rack":        "3.0.9",
			},
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name: "no GEM section",
			input: `PATH
  remote: .
  specs:
    myapp (1.0.0)

PLATFORMS
  ruby
`,
			wantCount: 0,
		},
		{
			name: "sub-dependencies not extracted",
			input: `GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.5)
      racc (~> 1.4)
    racc (1.7.3)
`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"nokogiri": "1.16.5",
				"racc":     "1.7.3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewGemParser().Parse(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pkgs) != tt.wantCount {
				t.Fatalf("got %d packages, want %d", len(pkgs), tt.wantCount)
			}
			assertParsedPackages(t, pkgs, tt.wantPkgs, domain.EcosystemGem)
		})
	}
}

func TestGemParserParsePreservesCleanRemoteProvenance(t *testing.T) {
	t.Parallel()

	input := "GEM\n" +
		"  remote: https://rubygems.org/\n" +
		"  remote:  https://private.example/gems/ \n" +
		"  remote: https://rubygems.org/\n" +
		"  specs:\n" +
		"    private_gem (1.2.3)\n\n" +
		"DEPENDENCIES\n" +
		"  private_gem\n"
	pkgs, err := NewGemParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("package count = %d, want 1", len(pkgs))
	}
	if got, want := pkgs[0].SourceRefs, []string{"https://private.example/gems/", "https://rubygems.org/"}; !equalStrings(got, want) {
		t.Fatalf("source refs = %q, want %q", got, want)
	}
}

func TestGemParserParseReturnsReadErrorWithPartialPackages(t *testing.T) {
	t.Parallel()

	input := "GEM\n  specs:\n    rack (3.0.9)\n"
	pkgs, err := NewGemParser().Parse(&readThenError{data: []byte(input), err: errors.New("forced read error")})
	if err == nil || !strings.Contains(err.Error(), "gem: reading input: forced read error") {
		t.Fatalf("Parse(read error) = %v, want contextual read error", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "rack" || pkgs[0].Version != "3.0.9" {
		t.Fatalf("partial packages = %#v, want rack 3.0.9", pkgs)
	}
}

func TestGemParserParseReturnsReadErrorWithoutPackages(t *testing.T) {
	t.Parallel()

	pkgs, err := NewGemParser().Parse(errorReader{})
	if err == nil || !strings.Contains(err.Error(), "gem: reading input: forced read error") {
		t.Fatalf("Parse(read error) = %v, want contextual read error", err)
	}
	if pkgs != nil {
		t.Fatalf("packages = %#v, want nil without a completed entry", pkgs)
	}
}

type readThenError struct {
	data []byte
	err  error
	read bool
}

func (r *readThenError) Read(p []byte) (int, error) {
	if r.read {
		return 0, r.err
	}
	r.read = true
	return copy(p, r.data), nil
}

var _ io.Reader = (*readThenError)(nil)

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func assertParsedPackages(t *testing.T, pkgs []domain.Package, wantPkgs map[string]string, wantEco domain.Ecosystem) {
	t.Helper()

	gotPkgs := make(map[string]string, len(pkgs))
	for _, pkg := range pkgs {
		if pkg.Ecosystem != wantEco {
			t.Errorf("package %q ecosystem = %q, want %q", pkg.Name, pkg.Ecosystem, wantEco)
		}
		if wantPkgs == nil {
			continue
		}
		if _, ok := gotPkgs[pkg.Name]; ok {
			t.Errorf("duplicate package %q", pkg.Name)
			continue
		}
		gotPkgs[pkg.Name] = pkg.Version
	}
	if wantPkgs == nil {
		return
	}

	for name, version := range gotPkgs {
		if _, ok := wantPkgs[name]; !ok {
			t.Errorf("unexpected package %q version %q", name, version)
		}
	}
	for name, wantVersion := range wantPkgs {
		gotVersion, ok := gotPkgs[name]
		if !ok {
			t.Errorf("missing package %q version %q", name, wantVersion)
			continue
		}
		if gotVersion != wantVersion {
			t.Errorf("package %q version = %q, want %q", name, gotVersion, wantVersion)
		}
	}
}
