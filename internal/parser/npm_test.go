package parser

import (
	"errors"
	"fmt"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
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
			name:    "trailing json document",
			input:   `{"lockfileVersion":3,"packages":{}}{"ignored":true}`,
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

			seen := make(map[string]string, len(pkgs))
			for _, pkg := range pkgs {
				if pkg.Ecosystem != domain.EcosystemNPM {
					t.Errorf("package %q has ecosystem %q, want %q", pkg.Name, pkg.Ecosystem, domain.EcosystemNPM)
				}
				seen[pkg.Name] = pkg.Version
				if wantVer, ok := tt.wantPkgs[pkg.Name]; ok {
					if pkg.Version != wantVer {
						t.Errorf("package %q version = %q, want %q", pkg.Name, pkg.Version, wantVer)
					}
				} else if tt.wantPkgs != nil {
					t.Errorf("unexpected package parsed from pnpm lock: %s@%s", pkg.Name, pkg.Version)
				}
			}
			for wantName, wantVersion := range tt.wantPkgs {
				if gotVersion, ok := seen[wantName]; !ok {
					t.Errorf("missing package %s@%s", wantName, wantVersion)
				} else if gotVersion != wantVersion {
					t.Errorf("package %q version = %q, want %q", wantName, gotVersion, wantVersion)
				}
			}
		})
	}
}

func TestNPMParser_ParseMarksDevDependencies(t *testing.T) {
	t.Parallel()

	input := `{
		"lockfileVersion": 3,
		"packages": {
			"": {"version": "1.0.0"},
			"node_modules/prod": {"version": "1.0.0"},
			"node_modules/dev-tool": {"version": "2.0.0", "dev": true}
		}
	}`
	pkgs, err := NewNPMParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	dev := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		dev[p.Name] = p.Dev
	}
	if dev["prod"] {
		t.Errorf("prod dependency wrongly marked dev")
	}
	if !dev["dev-tool"] {
		t.Errorf("dev dependency not marked dev")
	}
}

func TestNPMRootDependencyScopeCallsitesUseNamedFlags(t *testing.T) {
	source, err := os.ReadFile("npm.go")
	if err != nil {
		t.Fatalf("read npm.go: %v", err)
	}
	body := string(source)
	for _, blocked := range []string{
		`add := func(deps map[string]string, dev, optional, peer bool)`,
		`add(root.Dependencies, false, false, false)`,
		`add(root.DevDependencies, true, false, false)`,
		`add(root.OptionalDependencies, false, true, false)`,
		`add(root.PeerDependencies, false, false, true)`,
	} {
		if strings.Contains(body, blocked) {
			t.Fatalf("npm root dependency scope still uses ambiguous boolean tuple %q", blocked)
		}
	}
}

func TestNPMParser_ParsePackageLockV3Metadata(t *testing.T) {
	t.Parallel()

	input := `{
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "app",
				"version": "1.0.0",
				"dependencies": {"runtime": "^1.0.0"},
				"devDependencies": {"tailwindcss": "^3.4.17"},
				"optionalDependencies": {"optional-root": "^1.0.0"}
			},
			"node_modules/runtime": {"version": "1.0.0"},
			"node_modules/tailwindcss": {
				"version": "3.4.17",
				"dev": true,
				"dependencies": {"postcss": "^8.4.47"}
			},
			"node_modules/postcss": {
				"version": "8.5.8",
				"dev": true,
				"peer": true
			},
			"node_modules/optional-root": {
				"version": "1.0.0",
				"optional": true
			}
		}
	}`

	pkgs, err := NewNPMParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := packagesByName(pkgs)

	runtime := byName["runtime"]
	if !runtime.Direct || runtime.Indirect || runtime.Dev || runtime.Optional || runtime.Peer || len(runtime.Via) != 0 {
		t.Fatalf("runtime metadata = %+v, want direct runtime package", runtime)
	}

	tailwind := byName["tailwindcss"]
	if !tailwind.Direct || tailwind.Indirect || !tailwind.Dev || len(tailwind.Via) != 0 {
		t.Fatalf("tailwindcss metadata = %+v, want direct dev package", tailwind)
	}

	postcss := byName["postcss"]
	if postcss.Direct || !postcss.Indirect || !postcss.Dev || !postcss.Peer || postcss.Optional {
		t.Fatalf("postcss metadata = %+v, want dev peer transitive package", postcss)
	}
	if len(postcss.Via) != 1 || postcss.Via[0] != "tailwindcss" {
		t.Fatalf("postcss Via = %#v, want tailwindcss", postcss.Via)
	}
	if len(postcss.Parents) != 1 || postcss.Parents[0] != (domain.PackageParent{Name: "tailwindcss", Version: "3.4.17", Ecosystem: domain.EcosystemNPM}) {
		t.Fatalf("postcss Parents = %#v, want tailwindcss@3.4.17", postcss.Parents)
	}

	optionalRoot := byName["optional-root"]
	if !optionalRoot.Direct || !optionalRoot.Optional {
		t.Fatalf("optional-root metadata = %+v, want direct optional package", optionalRoot)
	}
}

func TestNPMParser_DoesNotMarkNestedDuplicateNameAsDirect(t *testing.T) {
	t.Parallel()

	input := `{
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "app",
				"version": "1.0.0",
				"dependencies": {
					"left-pad": "^1.0.0",
					"other": "^1.0.0"
				}
			},
			"node_modules/left-pad": {"version": "1.0.0"},
			"node_modules/other": {
				"version": "1.0.0",
				"dependencies": {"left-pad": "^2.0.0"}
			},
			"node_modules/other/node_modules/left-pad": {"version": "2.0.0"}
		}
	}`

	pkgs, err := NewNPMParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byKey := make(map[string]domain.Package, len(pkgs))
	for _, pkg := range pkgs {
		byKey[pkg.Name+"@"+pkg.Version] = pkg
	}

	root := byKey["left-pad@1.0.0"]
	if !root.Direct || root.Indirect {
		t.Fatalf("root left-pad metadata = %+v, want direct only", root)
	}
	nested := byKey["left-pad@2.0.0"]
	if nested.Direct || !nested.Indirect {
		t.Fatalf("nested left-pad metadata = %+v, want transitive only", nested)
	}
	if len(nested.Via) != 1 || nested.Via[0] != "other" {
		t.Fatalf("nested left-pad Via = %#v, want other", nested.Via)
	}
	if len(nested.Parents) != 1 || nested.Parents[0] != (domain.PackageParent{Name: "other", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}) {
		t.Fatalf("nested left-pad Parents = %#v, want other@1.0.0", nested.Parents)
	}
}

func TestNPMDirectDependencyMetadataPassPreservesScopeFlags(t *testing.T) {
	t.Parallel()

	packages := map[string]packageLockPkg{
		"": {
			Dependencies:         map[string]string{"runtime": "^1.0.0"},
			DevDependencies:      map[string]string{"dev-tool": "^2.0.0"},
			OptionalDependencies: map[string]string{"optional-root": "^3.0.0"},
			PeerDependencies:     map[string]string{"peer-root": "^4.0.0"},
		},
		"node_modules/runtime": {
			Version: "1.0.0",
		},
		"node_modules/dev-tool": {
			Version: "2.0.0",
		},
		"node_modules/optional-root": {
			Version: "3.0.0",
		},
		"node_modules/peer-root": {
			Version: "4.0.0",
		},
		"node_modules/transitive-flagged": {
			Version:  "5.0.0",
			Optional: true,
			Peer:     true,
		},
		"node_modules/runtime/node_modules/dev-tool": {
			Version: "2.1.0",
		},
	}

	resolver := newNPMPackageResolver(packages)
	metadata := npmDirectDependencyMetadata(packages, resolver, npmRootDependencies(packages[""]))

	assertNPMPackageMeta(t, metadata["node_modules/runtime"], npmPackageMeta{direct: true})
	assertNPMPackageMeta(t, metadata["node_modules/dev-tool"], npmPackageMeta{direct: true, dev: true})
	assertNPMPackageMeta(t, metadata["node_modules/optional-root"], npmPackageMeta{direct: true, optional: true})
	assertNPMPackageMeta(t, metadata["node_modules/peer-root"], npmPackageMeta{direct: true, peer: true})
	assertNPMPackageMeta(t, metadata["node_modules/transitive-flagged"], npmPackageMeta{indirect: true, optional: true, peer: true})
	assertNPMPackageMeta(t, metadata["node_modules/runtime/node_modules/dev-tool"], npmPackageMeta{indirect: true})
	if _, ok := metadata[""]; ok {
		t.Fatalf("root package metadata present")
	}
}

func TestNPMViaRootPropagationPassAddsOnlyIndirectRoots(t *testing.T) {
	t.Parallel()

	packages := map[string]packageLockPkg{
		"": {
			Dependencies: map[string]string{
				"alpha": "^1.0.0",
				"beta":  "^1.0.0",
			},
		},
		"node_modules/alpha": {
			Version: "1.0.0",
			Dependencies: map[string]string{
				"beta":   "^1.0.0",
				"shared": "^1.0.0",
			},
		},
		"node_modules/beta": {
			Version:      "1.0.0",
			Dependencies: map[string]string{"shared": "^1.0.0"},
		},
		"node_modules/shared": {
			Version: "1.0.0",
		},
	}

	resolver := newNPMPackageResolver(packages)
	directDeps := npmRootDependencies(packages[""])
	metadata := npmDirectDependencyMetadata(packages, resolver, directDeps)
	npmPropagateViaRoots(metadata, resolver, directDeps)

	assertNPMPackageMeta(t, metadata["node_modules/shared"], npmPackageMeta{indirect: true, via: []string{"alpha", "beta"}})
	assertNPMPackageMeta(t, metadata["node_modules/beta"], npmPackageMeta{direct: true})
}

func TestNPMViaRootPropagationSharedGraphHasStableVia(t *testing.T) {
	const (
		rootCount = 40
		depth     = 40
	)
	packages, wantVia, leafKey := sharedNPMViaGraph(rootCount, depth)

	metadata := npmPackageMetadata(packages)
	leaf := metadata[leafKey]
	if leaf.direct || !leaf.indirect || !reflect.DeepEqual(leaf.via, wantVia) {
		t.Fatalf("leaf metadata = %+v, want indirect via %v", leaf, wantVia)
	}
	assertNPMPackageMeta(t, metadata["node_modules/root-39"], npmPackageMeta{direct: true, dev: true})

	allocs := testing.AllocsPerRun(10, func() {
		metadata = npmPackageMetadata(packages)
	})
	if allocs > 6000 {
		t.Fatalf("npmPackageMetadata shared graph allocations = %.0f, want <= 6000", allocs)
	}
}

func TestNPMViaRootPropagationDoesNotUsePerRootReachability(t *testing.T) {
	source, err := os.ReadFile("npm.go")
	if err != nil {
		t.Fatalf("read npm.go: %v", err)
	}
	file, err := goparser.ParseFile(token.NewFileSet(), "npm.go", source, 0)
	if err != nil {
		t.Fatalf("parse npm.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		candidate, ok := decl.(*ast.FuncDecl)
		if ok && candidate.Name.Name == "npmPropagateViaRoots" {
			fn = candidate
			break
		}
	}
	if fn == nil {
		t.Fatalf("npmPropagateViaRoots not found")
	}

	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "reachableDependencyKeys" {
			t.Fatalf("npmPropagateViaRoots still calls reachableDependencyKeys")
		}
		return true
	})
}

func TestNPMParentEdgeCollectionPassUsesDependencyKinds(t *testing.T) {
	t.Parallel()

	packages := map[string]packageLockPkg{
		"node_modules/parent": {
			Version: "1.0.0",
			Dependencies: map[string]string{
				"child": "^1.0.0",
			},
			OptionalDependencies: map[string]string{
				"optional-child": "^1.0.0",
			},
		},
		"node_modules/peer-parent": {
			Version:          "2.0.0",
			PeerDependencies: map[string]string{"child": "^1.0.0"},
		},
		"node_modules/no-version-parent": {
			Dependencies: map[string]string{"child": "^1.0.0"},
		},
		"node_modules/child": {
			Version: "1.0.0",
		},
		"node_modules/optional-child": {
			Version: "1.0.0",
		},
	}

	resolver := newNPMPackageResolver(packages)
	metadata := npmDirectDependencyMetadata(packages, resolver, npmRootDependencies(packages[""]))
	npmCollectParentEdges(metadata, packages, resolver)

	if want := []domain.PackageParent{
		{Name: "parent", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "peer-parent", Version: "2.0.0", Ecosystem: domain.EcosystemNPM},
	}; !reflect.DeepEqual(metadata["node_modules/child"].parents, want) {
		t.Fatalf("child parents = %#v, want %#v", metadata["node_modules/child"].parents, want)
	}
	if want := []domain.PackageParent{{Name: "parent", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}}; !reflect.DeepEqual(metadata["node_modules/optional-child"].parents, want) {
		t.Fatalf("optional-child parents = %#v, want %#v", metadata["node_modules/optional-child"].parents, want)
	}
}

func TestNPMParserNameHelperRejectsNonNodeModulePath(t *testing.T) {
	t.Parallel()

	if got := npmNameFromKey("packages/lodash"); got != "" {
		t.Fatalf("npmNameFromKey(non-node_modules) = %q, want empty", got)
	}
}

func TestNPMPackageResolverUsesIndexedDependencyKeys(t *testing.T) {
	t.Parallel()

	packages := map[string]packageLockPkg{
		"": {
			Dependencies: map[string]string{"app": "^1.0.0"},
		},
		"node_modules/app": {
			Version:      "1.0.0",
			Dependencies: map[string]string{"left-pad": "^2.0.0"},
		},
		"node_modules/app/node_modules/left-pad": {
			Version: "2.0.0",
		},
		"node_modules/left-pad": {
			Version: "1.0.0",
		},
	}

	resolver := newNPMPackageResolver(packages)
	if got := resolver.rootPackageKey("app"); got != "node_modules/app" {
		t.Fatalf("rootPackageKey(app) = %q", got)
	}
	if got := resolver.dependencyKey("node_modules/app", "left-pad"); got != "node_modules/app/node_modules/left-pad" {
		t.Fatalf("dependencyKey(nested left-pad) = %q", got)
	}
	if got := resolver.dependencyKey("", "left-pad"); got != "node_modules/left-pad" {
		t.Fatalf("dependencyKey(fallback left-pad) = %q", got)
	}
	if got := strings.Join(resolver.resolvedDependencyKeys("node_modules/app"), ","); got != "node_modules/app/node_modules/left-pad" {
		t.Fatalf("resolvedDependencyKeys(app) = %q", got)
	}
}

func assertNPMPackageMeta(t *testing.T, got, want npmPackageMeta) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata = %+v, want %+v", got, want)
	}
}

func sharedNPMViaGraph(rootCount, depth int) (map[string]packageLockPkg, []string, string) {
	packages := make(map[string]packageLockPkg, rootCount+depth+1)
	root := packageLockPkg{
		Dependencies:    make(map[string]string, rootCount-1),
		DevDependencies: make(map[string]string, 1),
	}
	wantVia := make([]string, 0, rootCount)
	for i := 0; i < rootCount; i++ {
		name := fmt.Sprintf("root-%02d", i)
		if i == rootCount-1 {
			root.DevDependencies[name] = "^1.0.0"
		} else {
			root.Dependencies[name] = "^1.0.0"
		}
		wantVia = append(wantVia, name)
		packages["node_modules/"+name] = packageLockPkg{
			Version:      "1.0.0",
			Dev:          i == rootCount-1,
			Dependencies: map[string]string{"shared-00": "^1.0.0"},
		}
	}
	packages[""] = root

	for i := 0; i < depth; i++ {
		name := fmt.Sprintf("shared-%02d", i)
		entry := packageLockPkg{Version: "1.0.0"}
		if i < depth-1 {
			nextName := fmt.Sprintf("shared-%02d", i+1)
			entry.Dependencies = map[string]string{nextName: "^1.0.0"}
		}
		packages["node_modules/"+name] = entry
	}

	return packages, wantVia, fmt.Sprintf("node_modules/shared-%02d", depth-1)
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

func TestYarnParserReportsUnsupportedFormatAndReadErrors(t *testing.T) {
	t.Parallel()

	if _, err := NewYarnParser().Parse(strings.NewReader(`__metadata:
  version: 6
`)); err == nil || !strings.Contains(err.Error(), "format not recognized") {
		t.Fatalf("YarnParser.Parse(berry) error = %v", err)
	}

	if _, err := NewYarnParser().Parse(errorReader{}); err == nil || !strings.Contains(err.Error(), "read error") {
		t.Fatalf("YarnParser.Parse(read error) error = %v", err)
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
			name: "v9 package keys with peer suffix",
			input: `lockfileVersion: '9.0'
packages:
  vue@3.4.0(typescript@5.4.0):
    resolution: {integrity: sha512-abc}
  '@scope/pkg@1.2.3(@types/node@20.0.0)':
    resolution: {integrity: sha512-def}
`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"vue":        "3.4.0",
				"@scope/pkg": "1.2.3",
			},
			wantErr: false,
		},
		{
			name: "v9 snapshots only",
			input: `lockfileVersion: '9.0'
snapshots:
  vue@3.4.0(typescript@5.4.0): {}
  '@scope/pkg@1.2.3(@types/node@20.0.0)': {}
`,
			wantCount: 2,
			wantPkgs: map[string]string{
				"vue":        "3.4.0",
				"@scope/pkg": "1.2.3",
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

func TestPnpmParserMarksDevEntries(t *testing.T) {
	t.Parallel()

	input := `lockfileVersion: '9.0'
packages:
  prod@1.0.0: {}
  dev-tool@2.0.0:
    dev: true
snapshots:
  snapshot-dev@3.0.0:
    dev: true
`
	pkgs, err := NewPnpmParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := packagesByName(pkgs)
	if byName["prod"].Dev {
		t.Fatalf("prod package marked dev: %+v", byName["prod"])
	}
	if !byName["dev-tool"].Dev {
		t.Fatalf("dev-tool package not marked dev: %+v", byName["dev-tool"])
	}
	if !byName["snapshot-dev"].Dev {
		t.Fatalf("snapshot-dev package not marked dev: %+v", byName["snapshot-dev"])
	}
}

func TestPnpmParserFallbackKeysAndReadError(t *testing.T) {
	t.Parallel()

	name, version := parsePnpmKey("left-pad", "1.3.0")
	if name != "left-pad" || version != "1.3.0" {
		t.Fatalf("parsePnpmKey(fallback) = %q %q, want left-pad 1.3.0", name, version)
	}
	name, version = parsePnpmKey("@scope", "")
	if name != "@scope" || version != "" {
		t.Fatalf("parsePnpmKey(scoped without slash) = %q %q, want name without version", name, version)
	}
	name, version = parsePnpmKey("", "1.0.0")
	if name != "" || version != "" {
		t.Fatalf("parsePnpmKey(empty) = %q %q, want empty", name, version)
	}

	if _, err := NewPnpmParser().Parse(errorReader{}); err == nil || !strings.Contains(err.Error(), "read error") {
		t.Fatalf("PnpmParser.Parse(read error) error = %v", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("forced read error")
}

func packagesByName(pkgs []domain.Package) map[string]domain.Package {
	out := make(map[string]domain.Package, len(pkgs))
	for _, pkg := range pkgs {
		out[pkg.Name] = pkg
	}
	return out
}

func TestNPMParserParsePackageLockProvenance(t *testing.T) {
	t.Parallel()

	input := `{
		"lockfileVersion": 3,
		"packages": {
			"": {
				"version": "1.0.0",
				"dependencies": {"runtime-lib": "^1.0.0"},
				"devDependencies": {"tailwindcss": "3.4.17"},
				"optionalDependencies": {"optional-root": "1.0.0"}
			},
			"node_modules/runtime-lib": {"version": "1.0.0"},
			"node_modules/optional-root": {"version": "1.0.0", "optional": true},
			"node_modules/tailwindcss": {
				"version": "3.4.17",
				"dev": true,
				"dependencies": {"postcss": "^8.4.47", "postcss-import": "^15.1.0"}
			},
			"node_modules/postcss": {"version": "8.5.8", "dev": true, "peer": true},
			"node_modules/postcss-import": {
				"version": "15.1.0",
				"dev": true,
				"peerDependencies": {"postcss": "^8.0.0"}
			}
		}
	}`

	pkgs, err := NewNPMParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	by := packagesByName(pkgs)

	if r := by["runtime-lib"]; !r.Direct || r.Dev || r.Indirect || r.Peer || r.Optional || len(r.Via) != 0 {
		t.Fatalf("runtime-lib = %+v, want direct runtime only", r)
	}
	if tw := by["tailwindcss"]; !tw.Direct || !tw.Dev || tw.Indirect || len(tw.Via) != 0 {
		t.Fatalf("tailwindcss = %+v, want direct dev root", tw)
	}
	if o := by["optional-root"]; !o.Direct || !o.Optional {
		t.Fatalf("optional-root = %+v, want direct optional root", o)
	}
	if pc := by["postcss"]; pc.Direct || !pc.Dev || !pc.Indirect || !pc.Peer || len(pc.Via) != 1 || pc.Via[0] != "tailwindcss" {
		t.Fatalf("postcss = %+v, want dev peer transitive via tailwindcss", pc)
	}
	if pi := by["postcss-import"]; pi.Direct || !pi.Dev || !pi.Indirect || len(pi.Via) != 1 || pi.Via[0] != "tailwindcss" {
		t.Fatalf("postcss-import = %+v, want dev transitive via tailwindcss", pi)
	}
}
