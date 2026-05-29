package parser

import (
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

// ---------------------------------------------------------------------------
// PipfileParser
// ---------------------------------------------------------------------------

func TestPipfileParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewPipfileParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"Pipfile.lock", true},
		{"pipfile.lock", false},
		{"requirements.txt", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestPipfileParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewPipfileParser().Ecosystem(); got != domain.EcosystemPyPI {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemPyPI)
	}
}

func TestPipfileParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "default and develop deps",
			input: `{
				"_meta": {},
				"default": {
					"requests": {"version": "==2.31.0"},
					"flask": {"version": "==3.0.0"}
				},
				"develop": {
					"pytest": {"version": "==8.0.0"}
				}
			}`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"requests": "2.31.0",
				"flask":    "3.0.0",
				"pytest":   "8.0.0",
			},
		},
		{
			name:      "empty default and develop",
			input:     `{"default": {}, "develop": {}}`,
			wantCount: 0,
		},
		{
			name:    "invalid json",
			input:   `not json`,
			wantErr: true,
		},
		{
			name: "name normalization",
			input: `{
				"default": {
					"My_Package.Name": {"version": "==1.0.0"}
				}
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"my-package-name": "1.0.0"},
		},
		{
			name: "skip entry without version",
			input: `{
				"default": {
					"requests": {"version": "==2.31.0"},
					"noversion": {"version": ""}
				}
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"requests": "2.31.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewPipfileParser().Parse(strings.NewReader(tt.input))
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
			assertPackages(t, pkgs, tt.wantPkgs, domain.EcosystemPyPI)
		})
	}
}

func TestPipfileParser_ParseMarksDevDependencies(t *testing.T) {
	t.Parallel()

	input := `{
		"default": {"requests": {"version": "==2.31.0"}},
		"develop": {"pytest": {"version": "==8.0.0"}}
	}`
	pkgs, err := NewPipfileParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	dev := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		dev[p.Name] = p.Dev
	}
	if dev["requests"] {
		t.Errorf("default dependency wrongly marked dev")
	}
	if !dev["pytest"] {
		t.Errorf("develop dependency not marked dev")
	}
}

// ---------------------------------------------------------------------------
// PoetryParser
// ---------------------------------------------------------------------------

func TestPoetryParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewPoetryParser()

	pos := []string{"poetry.lock"}
	neg := []string{"Poetry.lock", "Pipfile.lock", ""}

	for _, f := range pos {
		if !p.CanParse(f) {
			t.Errorf("CanParse(%q) = false, want true", f)
		}
	}
	for _, f := range neg {
		if p.CanParse(f) {
			t.Errorf("CanParse(%q) = true, want false", f)
		}
	}
}

func TestPoetryParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewPoetryParser().Ecosystem(); got != domain.EcosystemPyPI {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemPyPI)
	}
}

func TestPoetryParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "multiple packages",
			input: `[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "Flask"
version = "3.0.0"

[[package]]
name = "click"
version = "8.1.7"
`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"requests": "2.31.0",
				"flask":    "3.0.0",
				"click":    "8.1.7",
			},
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name:    "invalid toml",
			input:   `[[[broken`,
			wantErr: true,
		},
		{
			name: "skip package without name",
			input: `[[package]]
name = ""
version = "1.0.0"

[[package]]
name = "good"
version = "2.0.0"
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"good": "2.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewPoetryParser().Parse(strings.NewReader(tt.input))
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
			assertPackages(t, pkgs, tt.wantPkgs, domain.EcosystemPyPI)
		})
	}
}

// ---------------------------------------------------------------------------
// UVParser
// ---------------------------------------------------------------------------

func TestUVParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewUVParser()

	if !p.CanParse("uv.lock") {
		t.Error("CanParse(uv.lock) = false, want true")
	}
	for _, f := range []string{"UV.lock", "poetry.lock", ""} {
		if p.CanParse(f) {
			t.Errorf("CanParse(%q) = true, want false", f)
		}
	}
}

func TestUVParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewUVParser().Ecosystem(); got != domain.EcosystemPyPI {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemPyPI)
	}
}

func TestUVParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "valid uv.lock",
			input: `[[package]]
name = "httpx"
version = "0.27.0"

[[package]]
name = "anyio"
version = "4.3.0"
`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"httpx": "0.27.0",
				"anyio": "4.3.0",
			},
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name:    "invalid toml",
			input:   `not valid toml {{{`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewUVParser().Parse(strings.NewReader(tt.input))
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
			assertPackages(t, pkgs, tt.wantPkgs, domain.EcosystemPyPI)
		})
	}
}

// ---------------------------------------------------------------------------
// RequirementsParser
// ---------------------------------------------------------------------------

func TestRequirementsParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewRequirementsParser()

	if !p.CanParse("requirements.txt") {
		t.Error("CanParse(requirements.txt) = false, want true")
	}
	for _, f := range []string{"Requirements.txt", "Pipfile.lock", ""} {
		if p.CanParse(f) {
			t.Errorf("CanParse(%q) = true, want false", f)
		}
	}
}

func TestRequirementsParser_Ecosystem(t *testing.T) {
	t.Parallel()
	if got := NewRequirementsParser().Ecosystem(); got != domain.EcosystemPyPI {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemPyPI)
	}
}

func TestRequirementsParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "pinned versions",
			input: `# This is a comment
requests==2.31.0
flask==3.0.0
click==8.1.7
`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"requests": "2.31.0",
				"flask":    "3.0.0",
				"click":    "8.1.7",
			},
		},
		{
			name:      "empty file",
			input:     "",
			wantCount: 0,
		},
		{
			name:      "only comments",
			input:     "# just a comment\n# another",
			wantCount: 0,
		},
		{
			name: "unpinned versions produce error",
			input: `requests>=2.28.0
flask==3.0.0
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"flask": "3.0.0"},
			wantErr:   true,
		},
		{
			name: "inline comments and environment markers",
			input: `requests==2.31.0 # some comment
flask==3.0.0 ; python_version >= "3.8"
`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"requests": "2.31.0",
				"flask":    "3.0.0",
			},
		},
		{
			name:      "extras stripped",
			input:     `requests[security]==2.31.0`,
			wantCount: 1,
			wantPkgs:  map[string]string{"requests": "2.31.0"},
		},
		{
			name:      "pip options skipped",
			input:     "-i https://pypi.org/simple\n--extra-index-url https://other.pypi.org\nrequests==2.31.0\n",
			wantCount: 1,
			wantPkgs:  map[string]string{"requests": "2.31.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, err := NewRequirementsParser().Parse(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				// Even when there is an error, partial results may be returned.
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
			assertPackages(t, pkgs, tt.wantPkgs, domain.EcosystemPyPI)
		})
	}
}

// ---------------------------------------------------------------------------
// helper
// ---------------------------------------------------------------------------

func assertPackages(t *testing.T, pkgs []domain.Package, wantPkgs map[string]string, eco domain.Ecosystem) {
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
