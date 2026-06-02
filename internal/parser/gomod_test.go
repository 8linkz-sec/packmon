package parser

import (
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

// ---------------------------------------------------------------------------
// GoSumParser
// ---------------------------------------------------------------------------

func TestGoSumParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewGoSumParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"go.sum", true},
		{"Go.sum", false},
		{"go.mod", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestGoSumParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewGoSumParser().Ecosystem(); got != domain.EcosystemGo {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemGo)
	}
}

func TestGoSumParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "valid go.sum with go.mod entries",
			input: `golang.org/x/text v0.3.7 h1:abc=
golang.org/x/text v0.3.7/go.mod h1:def=
golang.org/x/net v0.15.0 h1:ghi=
golang.org/x/net v0.15.0/go.mod h1:jkl=
github.com/stretchr/testify v1.8.4 h1:mno=
github.com/stretchr/testify v1.8.4/go.mod h1:pqr=
`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"golang.org/x/text":           "v0.3.7",
				"golang.org/x/net":            "v0.15.0",
				"github.com/stretchr/testify": "v1.8.4",
			},
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name:      "only comments",
			input:     "// this is a comment\n",
			wantCount: 0,
		},
		{
			name: "malformed line produces error with partial results",
			input: `golang.org/x/text v0.3.7 h1:abc=
badline
golang.org/x/net v0.15.0 h1:ghi=
`,
			wantCount: 2,
			wantErr:   true,
		},
		{
			name: "incompatible suffix stripped",
			input: `github.com/example/mod v2.0.0+incompatible h1:abc=
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"github.com/example/mod": "v2.0.0"},
		},
		{
			name: "deduplication",
			input: `golang.org/x/text v0.3.7 h1:abc=
golang.org/x/text v0.3.7 h1:abc=
`,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewGoSumParser().Parse(strings.NewReader(tt.input))
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
			assertPackagesEco(t, pkgs, tt.wantPkgs, domain.EcosystemGo)
		})
	}
}

// ---------------------------------------------------------------------------
// GoModParser
// ---------------------------------------------------------------------------

func TestGoModParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewGoModParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"go.mod", true},
		{"Go.mod", false},
		{"go.sum", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestGoModParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewGoModParser().Ecosystem(); got != domain.EcosystemGo {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemGo)
	}
}

func TestGoModParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "block require",
			input: `module example.com/mymodule

go 1.22

require (
	golang.org/x/text v0.3.7
	golang.org/x/net v0.15.0
	github.com/stretchr/testify v1.8.4 // indirect
)
`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"golang.org/x/text":           "v0.3.7",
				"golang.org/x/net":            "v0.15.0",
				"github.com/stretchr/testify": "v1.8.4",
			},
		},
		{
			name: "single-line require",
			input: `module example.com/mymodule

go 1.22

require golang.org/x/text v0.3.7
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"golang.org/x/text": "v0.3.7"},
		},
		{
			name:      "no require block",
			input:     "module example.com/mymodule\n\ngo 1.22\n",
			wantCount: 0,
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name: "incompatible suffix",
			input: `module example.com/mymodule

require github.com/example/v2 v2.0.0+incompatible
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"github.com/example/v2": "v2.0.0"},
		},
		{
			name: "malformed require line in block",
			input: `module example.com/mymodule

require (
	justname
	golang.org/x/text v0.3.7
)
`,
			wantCount: 1,
			wantErr:   true,
		},
		{
			name: "multiple require blocks",
			input: `module example.com/mymodule

require (
	golang.org/x/text v0.3.7
)

require (
	golang.org/x/net v0.15.0
)
`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"golang.org/x/text": "v0.3.7",
				"golang.org/x/net":  "v0.15.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewGoModParser().Parse(strings.NewReader(tt.input))
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
			assertPackagesEco(t, pkgs, tt.wantPkgs, domain.EcosystemGo)
		})
	}
}

func TestGoModParser_MarksDirectAndIndirectRequires(t *testing.T) {
	t.Parallel()

	input := `module example.com/mymodule

go 1.26

require (
	github.com/direct/pkg v1.2.3
	github.com/indirect/pkg v0.4.5 // indirect
)
`
	pkgs, err := NewGoModParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	byName := make(map[string]domain.Package, len(pkgs))
	for _, pkg := range pkgs {
		byName[pkg.Name] = pkg
	}
	if direct := byName["github.com/direct/pkg"]; !direct.Direct || direct.Indirect {
		t.Fatalf("direct package metadata = %+v, want direct only", direct)
	}
	if indirect := byName["github.com/indirect/pkg"]; indirect.Direct || !indirect.Indirect {
		t.Fatalf("indirect package metadata = %+v, want indirect only", indirect)
	}
}

// assertPackagesEco verifies ecosystem and version for each package.
func assertPackagesEco(t *testing.T, pkgs []domain.Package, wantPkgs map[string]string, eco domain.Ecosystem) {
	t.Helper()
	for _, pkg := range pkgs {
		if pkg.Ecosystem != eco {
			t.Errorf("package %q has ecosystem %q, want %q", pkg.Name, pkg.Ecosystem, eco)
		}
		if wantVer, ok := wantPkgs[pkg.Name]; ok {
			if pkg.Version != wantVer {
				t.Errorf("package %q version = %q, want %q", pkg.Name, pkg.Version, wantVer)
			}
		}
	}
}

// Regression: a '(' or ')' inside a require-block comment must not be treated
// as a block boundary, otherwise that line and every following require would be
// silently dropped from the scan.
func TestGoModParserKeepsRequiresWithParenInComment(t *testing.T) {
	t.Parallel()

	input := "module x\n\ngo 1.26\n\nrequire (\n\tgithub.com/a/one v1.0.0 // kept (legacy)\n\tgithub.com/b/two v2.0.0\n)\n"

	pkgs, err := NewGoModParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	by := packagesByName(pkgs)

	if len(pkgs) != 2 {
		t.Fatalf("got %d packages %v, want 2 (')' in a comment closed the block early)", len(pkgs), pkgs)
	}
	if _, ok := by["github.com/a/one"]; !ok {
		t.Errorf("missing github.com/a/one (line with paren comment was dropped)")
	}
	if _, ok := by["github.com/b/two"]; !ok {
		t.Errorf("missing github.com/b/two (block closed early)")
	}
}
