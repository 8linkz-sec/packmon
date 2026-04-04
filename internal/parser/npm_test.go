package parser

import (
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

// ---------------------------------------------------------------------------
// NPMParser
// ---------------------------------------------------------------------------

func TestNPMParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewNPMParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"package-lock.json", true},
		{"Package-Lock.json", false},
		{"package.json", false},
		{"yarn.lock", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestNPMParser_Ecosystem(t *testing.T) {
	t.Parallel()
	p := NewNPMParser()
	if got := p.Ecosystem(); got != domain.EcosystemNPM {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemNPM)
	}
}

func TestNPMParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string // name -> version
		wantErr   bool
	}{
		{
			name: "v3 packages map",
			input: `{
				"lockfileVersion": 3,
				"packages": {
					"": {"version": "1.0.0"},
					"node_modules/lodash": {"version": "4.17.21"},
					"node_modules/@babel/core": {"version": "7.24.0"},
					"node_modules/express": {"version": "4.18.2"}
				}
			}`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"lodash":      "4.17.21",
				"@babel/core": "7.24.0",
				"express":     "4.18.2",
			},
			wantErr: false,
		},
		{
			name: "v1 dependencies map",
			input: `{
				"lockfileVersion": 1,
				"dependencies": {
					"lodash": {"version": "4.17.21"},
					"express": {"version": "4.18.2"}
				}
			}`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"lodash":  "4.17.21",
				"express": "4.18.2",
			},
			wantErr: false,
		},
		{
			name:      "empty packages",
			input:     `{"lockfileVersion": 3, "packages": {}}`,
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:      "empty json object",
			input:     `{}`,
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:    "malformed json",
			input:   `{not valid json`,
			wantErr: true,
		},
		{
			name: "nested node_modules",
			input: `{
				"lockfileVersion": 3,
				"packages": {
					"node_modules/a": {"version": "1.0.0"},
					"node_modules/a/node_modules/b": {"version": "2.0.0"}
				}
			}`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"a": "1.0.0",
				"b": "2.0.0",
			},
			wantErr: false,
		},
		{
			name: "skip entries with empty version",
			input: `{
				"lockfileVersion": 3,
				"packages": {
					"node_modules/good": {"version": "1.0.0"},
					"node_modules/bad": {"version": ""}
				}
			}`,
			wantCount: 1,
			wantPkgs:  map[string]string{"good": "1.0.0"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := NewNPMParser()
			pkgs, err := p.Parse(strings.NewReader(tt.input))

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

			for _, pkg := range pkgs {
				if pkg.Ecosystem != domain.EcosystemNPM {
					t.Errorf("package %q has ecosystem %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemNPM)
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

// ---------------------------------------------------------------------------
// YarnParser
// ---------------------------------------------------------------------------

func TestYarnParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewYarnParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"yarn.lock", true},
		{"Yarn.lock", false},
		{"package-lock.json", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestYarnParser_Ecosystem(t *testing.T) {
	t.Parallel()
	p := NewYarnParser()
	if got := p.Ecosystem(); got != domain.EcosystemNPM {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemNPM)
	}
}

func TestYarnParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "valid yarn.lock",
			input: `# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@babel/core@^7.0.0":
  version "7.24.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz"

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
`,
			wantCount: 3,
			wantPkgs: map[string]string{
				"lodash":      "4.17.21",
				"@babel/core": "7.24.0",
				"express":     "4.18.2",
			},
			wantErr: false,
		},
		{
			name:      "empty file",
			input:     `# yarn lockfile v1`,
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:      "blank input",
			input:     "",
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "header without version line",
			input: `lodash@^4.17.0:
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
`,
			wantCount: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := NewYarnParser()
			pkgs, err := p.Parse(strings.NewReader(tt.input))

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

			for _, pkg := range pkgs {
				if pkg.Ecosystem != domain.EcosystemNPM {
					t.Errorf("package %q has ecosystem %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemNPM)
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

// ---------------------------------------------------------------------------
// PnpmParser
// ---------------------------------------------------------------------------

func TestPnpmParser_CanParse(t *testing.T) {
	t.Parallel()
	p := NewPnpmParser()

	tests := []struct {
		filename string
		want     bool
	}{
		{"pnpm-lock.yaml", true},
		{"Pnpm-lock.yaml", false},
		{"yarn.lock", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := p.CanParse(tt.filename); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.filename, got, tt.want)
		}
	}
}

func TestPnpmParser_Ecosystem(t *testing.T) {
	t.Parallel()
	p := NewPnpmParser()
	if got := p.Ecosystem(); got != domain.EcosystemNPM {
		t.Errorf("Ecosystem() = %q, want %q", got, domain.EcosystemNPM)
	}
}

func TestPnpmParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantPkgs  map[string]string
		wantErr   bool
	}{
		{
			name: "v6 format with at sign",
			input: `lockfileVersion: '6.0'
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}
  /@babel/core@7.24.0:
    resolution: {integrity: sha512-def}
`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"lodash":      "4.17.21",
				"@babel/core": "7.24.0",
			},
			wantErr: false,
		},
		{
			name: "v5 format with slash separator",
			input: `lockfileVersion: 5
packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-abc}
`,
			wantCount: 1,
			wantPkgs:  map[string]string{"lodash": "4.17.21"},
			wantErr:   false,
		},
		{
			name:      "empty packages",
			input:     `lockfileVersion: '6.0'`,
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:    "invalid yaml",
			input:   `{{{not yaml`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := NewPnpmParser()
			pkgs, err := p.Parse(strings.NewReader(tt.input))

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

			for _, pkg := range pkgs {
				if pkg.Ecosystem != domain.EcosystemNPM {
					t.Errorf("package %q has ecosystem %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemNPM)
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
