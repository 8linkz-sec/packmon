# Package Scope Provenance Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show whether reported packages and findings are runtime, dev, CI, SBOM, direct, transitive, peer, optional, or indirect, including npm "via" roots such as `postcss@8.5.8 via tailwindcss`.

**Architecture:** Extend `domain.Package` with optional provenance metadata, populate it in parsers and `CollectPackages`, then render it in `--list-all` and `--outdated` terminal/HTML reports. Keep vulnerability matching unchanged and keep canonical API scan result findings unchanged; CLI reports annotate findings by joining them back to collected package rows.

**Tech Stack:** Go 1.26, existing parser/scanner/domain packages, Cobra CLI, Go `html/template`, npm lockfile metadata.

---

## File Structure

- Modify `internal/domain/models.go`: add optional metadata fields to `domain.Package`.
- Modify `internal/parser/npm.go`: parse npm `dev`, `peer`, `optional`, direct root deps, and nearest direct `Via` roots.
- Modify `internal/parser/gomod.go`: preserve `// indirect` from `go.mod`.
- Modify `internal/parser/parser.go`: merge metadata in parser-level dedup.
- Modify `internal/scanner/package_collector.go`: merge metadata across lockfiles/SBOMs.
- Modify `cmd/packmon/list_all.go`: add `SCOPE`, `RELATION`, `VIA`, and `FLAGS` columns in terminal and HTML; annotate finding rows.
- Modify `cmd/packmon/outdated.go`: add the same metadata columns to outdated terminal and HTML output.
- Test files: `internal/parser/npm_test.go`, `internal/parser/gomod_test.go`, `internal/parser/parser_test.go`, `internal/scanner/package_collector_test.go`, `cmd/packmon/list_all_test.go`, `cmd/packmon/outdated_fetch_test.go`, and `internal/sbom/purl_test.go` (compat fix: `domain.Package` becomes non-comparable).

---

### Task 1: Extend Package Metadata Model

**Files:**
- Modify: `internal/domain/models.go`
- Test: `internal/domain/package_metadata_test.go`
- Modify (compat): `internal/sbom/purl_test.go`

- [ ] **Step 1: Write the failing metadata zero-value test**

Create `internal/domain/package_metadata_test.go`:

```go
package domain

import "testing"

func TestPackageMetadataZeroValueIsEmpty(t *testing.T) {
	pkg := Package{Name: "postcss", Version: "8.5.8", Ecosystem: EcosystemNPM}
	if pkg.Direct || pkg.Indirect || pkg.Optional || pkg.Peer {
		t.Fatalf("zero-value metadata flags = direct:%v indirect:%v optional:%v peer:%v, want all false",
			pkg.Direct, pkg.Indirect, pkg.Optional, pkg.Peer)
	}
	if len(pkg.Via) != 0 {
		t.Fatalf("Via = %#v, want empty", pkg.Via)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
$env:GOTMPDIR = Join-Path $env:TEMP 'packmon-gotmp'
New-Item -ItemType Directory -Force $env:GOTMPDIR | Out-Null
go test -count=1 .\internal\domain -run TestPackageMetadataZeroValueIsEmpty
```

Expected: FAIL because `Package.Direct`, `Package.Indirect`, `Package.Optional`, `Package.Peer`, and `Package.Via` do not exist.

- [ ] **Step 3: Add optional metadata fields**

In `internal/domain/models.go`, change `Package` to:

```go
type Package struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Ecosystem Ecosystem `json:"ecosystem"`
	Dev       bool      `json:"dev,omitempty"`
	Direct    bool      `json:"direct,omitempty"`
	Indirect  bool      `json:"indirect,omitempty"`
	Optional  bool      `json:"optional,omitempty"`
	Peer      bool      `json:"peer,omitempty"`
	Via       []string  `json:"via,omitempty"`
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run:

```powershell
go test -count=1 .\internal\domain -run TestPackageMetadataZeroValueIsEmpty
```

Expected: PASS.

- [ ] **Step 5: Fix call sites that compare `domain.Package` with `==`/`!=`**

Adding the `Via []string` slice makes `domain.Package` **non-comparable**, so any
`==`/`!=` on a `Package` value no longer compiles. The only such call sites in
the repo are in `internal/sbom/purl_test.go` (verified: there is no
`map[domain.Package]` and `parser.dedup` keys a local struct; the
`internal/sbom` cyclonedx/spdx tests already use `reflect.DeepEqual`).

In `internal/sbom/purl_test.go`, add `"reflect"` to the imports and replace the
three comparisons:

```go
// was: if ok != tt.ok || got != tt.want {
if ok != tt.ok || !reflect.DeepEqual(got, tt.want) {

// was: if !ok || got != want {
if !ok || !reflect.DeepEqual(got, want) {

// was: if got, ok := PackageFromPURL("pkg:pypi/django"); ok || got != (domain.Package{}) {
if got, ok := PackageFromPURL("pkg:pypi/django"); ok || !reflect.DeepEqual(got, domain.Package{}) {
```

Run:

```powershell
go build ./...
go test -count=1 .\internal\sbom
```

Expected: compiles and PASS.

---

### Task 2: Parse npm Direct/Transitive/Peer/Optional/Via Metadata

**Files:**
- Modify: `internal/parser/npm.go`
- Test: `internal/parser/npm_test.go`

- [ ] **Step 1: Write the failing npm provenance test**

Append to `internal/parser/npm_test.go`:

```go
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
			"node_modules/runtime-lib": {
				"version": "1.0.0"
			},
			"node_modules/optional-root": {
				"version": "1.0.0",
				"optional": true
			},
			"node_modules/tailwindcss": {
				"version": "3.4.17",
				"dev": true,
				"dependencies": {
					"postcss": "^8.4.47",
					"postcss-import": "^15.1.0"
				}
			},
			"node_modules/postcss": {
				"version": "8.5.8",
				"dev": true,
				"peer": true
			},
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

	byName := map[string]domain.Package{}
	for _, pkg := range pkgs {
		byName[pkg.Name] = pkg
	}

	runtime := byName["runtime-lib"]
	if !runtime.Direct || runtime.Dev || runtime.Indirect || runtime.Peer || runtime.Optional || len(runtime.Via) != 0 {
		t.Fatalf("runtime-lib metadata = %+v, want direct runtime only", runtime)
	}

	tailwind := byName["tailwindcss"]
	if !tailwind.Direct || !tailwind.Dev || tailwind.Indirect || len(tailwind.Via) != 0 {
		t.Fatalf("tailwindcss metadata = %+v, want direct dev root", tailwind)
	}

	optional := byName["optional-root"]
	if !optional.Direct || !optional.Optional {
		t.Fatalf("optional-root metadata = %+v, want direct optional root", optional)
	}

	postcss := byName["postcss"]
	if postcss.Direct || !postcss.Dev || !postcss.Indirect || !postcss.Peer || len(postcss.Via) != 1 || postcss.Via[0] != "tailwindcss" {
		t.Fatalf("postcss metadata = %+v, want dev peer transitive via tailwindcss", postcss)
	}

	postcssImport := byName["postcss-import"]
	if postcssImport.Direct || !postcssImport.Dev || !postcssImport.Indirect || len(postcssImport.Via) != 1 || postcssImport.Via[0] != "tailwindcss" {
		t.Fatalf("postcss-import metadata = %+v, want dev transitive via tailwindcss", postcssImport)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
go test -count=1 .\internal\parser -run TestNPMParserParsePackageLockProvenance
```

Expected: FAIL because npm parser does not populate `Direct`, `Indirect`, `Optional`, `Peer`, or `Via`.

- [ ] **Step 3: Extend npm lock structs**

In `internal/parser/npm.go`, replace `packageLockPkg` with:

```go
type packageLockPkg struct {
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	Peer                 bool              `json:"peer"`
	Optional             bool              `json:"optional"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}
```

Also replace `packageLockDep` with:

```go
type packageLockDep struct {
	Version  string `json:"version"`
	Dev      bool   `json:"dev"`
	Optional bool   `json:"optional"`
	Peer     bool   `json:"peer"`
}
```

- [ ] **Step 4: Add npm provenance helpers**

Add these helpers near `npmNameFromKey`:

```go
type npmPackageMeta struct {
	direct   bool
	indirect bool
	dev      bool
	optional bool
	peer     bool
	via      []string
}

func npmPackageMetadata(lock packageLock) map[string]npmPackageMeta {
	metadata := map[string]npmPackageMeta{}
	root := lock.Packages[""]
	directRoots := map[string]bool{}

	addDirect := func(name string, dev, optional, peer bool) {
		if name == "" {
			return
		}
		meta := metadata[name]
		meta.direct = true
		meta.dev = meta.dev || dev
		meta.optional = meta.optional || optional
		meta.peer = meta.peer || peer
		metadata[name] = meta
		directRoots[name] = true
	}

	for name := range root.Dependencies {
		addDirect(name, false, false, false)
	}
	for name := range root.DevDependencies {
		addDirect(name, true, false, false)
	}
	for name := range root.OptionalDependencies {
		addDirect(name, false, true, false)
	}
	for name := range root.PeerDependencies {
		addDirect(name, false, false, true)
	}

	type edge struct {
		from string
		to   string
	}
	var edges []edge
	for key, entry := range lock.Packages {
		if key == "" {
			continue
		}
		from := npmNameFromKey(key)
		if from == "" {
			continue
		}
		for dep := range entry.Dependencies {
			edges = append(edges, edge{from: from, to: dep})
		}
		for dep := range entry.OptionalDependencies {
			edges = append(edges, edge{from: from, to: dep})
		}
		for dep := range entry.PeerDependencies {
			edges = append(edges, edge{from: from, to: dep})
			meta := metadata[dep]
			meta.peer = true
			metadata[dep] = meta
		}
	}

	for rootName := range directRoots {
		seen := map[string]bool{rootName: true}
		queue := []string{rootName}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, e := range edges {
				if e.from != cur || seen[e.to] {
					continue
				}
				seen[e.to] = true
				queue = append(queue, e.to)
				if e.to == rootName {
					continue
				}
				meta := metadata[e.to]
				if !meta.direct {
					meta.indirect = true
					meta.via = appendUniqueSorted(meta.via, rootName)
				}
				metadata[e.to] = meta
			}
		}
	}

	return metadata
}

func appendUniqueSorted(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	values = append(values, value)
	sort.Strings(values)
	return values
}
```

Add `sort` to the import list.

- [ ] **Step 5: Apply metadata in `NPMParser.Parse`**

Inside `Parse`, before iterating `lock.Packages`, add:

```go
metadata := npmPackageMetadata(lock)
```

When appending each package from `lock.Packages`, replace the current `domain.Package{...}` with:

```go
meta := metadata[name]
pkgs = append(pkgs, domain.Package{
	Name:      name,
	Version:   entry.Version,
	Ecosystem: domain.EcosystemNPM,
	Dev:       entry.Dev || meta.dev,
	Direct:    meta.direct,
	Indirect:  meta.indirect,
	Optional:  entry.Optional || meta.optional,
	Peer:      entry.Peer || meta.peer,
	Via:       meta.via,
})
```

For the v1 `Dependencies` fallback, use:

```go
pkgs = append(pkgs, domain.Package{
	Name:      name,
	Version:   entry.Version,
	Ecosystem: domain.EcosystemNPM,
	Dev:       entry.Dev,
	Optional:  entry.Optional,
	Peer:      entry.Peer,
})
```

- [ ] **Step 6: Run npm parser tests**

Run:

```powershell
go test -count=1 .\internal\parser -run "TestNPMParser"
```

Expected: PASS.

---

### Task 3: Preserve Go Direct vs Indirect Requires

**Files:**
- Modify: `internal/parser/gomod.go`
- Test: `internal/parser/gomod_test.go`

- [ ] **Step 1: Write the failing Go metadata test**

Append this test function to `internal/parser/gomod_test.go` (it already declares `package parser`; ensure `strings`, `testing`, and `github.com/8linkz/packmon/internal/domain` are imported):

```go
func TestGoModParserMarksIndirectRequires(t *testing.T) {
	t.Parallel()

	input := `module example.com/app

go 1.26

require (
	github.com/direct/pkg v1.2.3
	github.com/indirect/pkg v0.9.0 // indirect
)
`

	pkgs, err := NewGoModParser().Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	byName := map[string]domain.Package{}
	for _, pkg := range pkgs {
		byName[pkg.Name] = pkg
	}

	if !byName["github.com/direct/pkg"].Direct || byName["github.com/direct/pkg"].Indirect {
		t.Fatalf("direct package metadata = %+v, want direct only", byName["github.com/direct/pkg"])
	}
	if byName["github.com/indirect/pkg"].Direct || !byName["github.com/indirect/pkg"].Indirect {
		t.Fatalf("indirect package metadata = %+v, want indirect only", byName["github.com/indirect/pkg"])
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
go test -count=1 .\internal\parser -run TestGoModParserMarksIndirectRequires
```

Expected: FAIL because Go parser currently strips comments before it can detect `// indirect`.

- [ ] **Step 3: Capture `// indirect` before stripping, then record it**

Do **not** remove the global comment-strip in `GoModParser.Parse`. The require
block terminator check immediately below it (`if inBlock && strings.Contains(line, ")")`)
relies on comments already being gone — otherwise a require line whose inline
comment contains `)` (e.g. `foo v1.0.0 // needed by (x)`) would close the block
early and silently drop that and all following requires. Instead, capture the
`// indirect` marker from the raw line first and thread it through.

In `GoModParser.Parse`, just below `line := strings.TrimSpace(scanner.Text())`
and ABOVE the existing `// Strip inline comments.` block, add:

```go
indirect := strings.Contains(line, "// indirect")
```

Pass `indirect` to all three `parseGoRequireLine` call sites (the same-line
`require (` case, the in-block case, and the single-line `require ` case):

```go
pkg, err := parseGoRequireLine(rest, indirect, lineNo)  // same-line require (
// ...
pkg, err := parseGoRequireLine(line, indirect, lineNo)  // in-block line
// ...
pkg, err := parseGoRequireLine(rest, indirect, lineNo)  // single-line require
```

Then change `parseGoRequireLine` to accept the flag and record it. Keep the
internal `//` strip as a defensive no-op (the line is already stripped):

```go
func parseGoRequireLine(line string, indirect bool, lineNo int) (domain.Package, error) {
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}

	fields := strings.Fields(line)
	if len(fields) < 2 {
		return domain.Package{}, fmt.Errorf("go.mod:%d: malformed require line: %q", lineNo, line)
	}

	module := fields[0]
	version := strings.TrimSuffix(fields[1], "+incompatible")

	return domain.Package{
		Name:      module,
		Version:   version,
		Ecosystem: domain.EcosystemGo,
		Direct:    !indirect,
		Indirect:  indirect,
	}, nil
}
```

- [ ] **Step 4: Run Go parser tests**

Run:

```powershell
go test -count=1 .\internal\parser -run "TestGo"
```

Expected: PASS.

---

### Task 4: Merge Metadata During Deduplication and Collection

**Files:**
- Modify: `internal/parser/parser.go`
- Modify: `internal/scanner/package_collector.go`
- Test: `internal/parser/parser_test.go`
- Test: `internal/scanner/package_collector_test.go`

- [ ] **Step 1: Write parser dedup merge test**

Append to `internal/parser/parser_test.go`:

```go
func TestDedupMergesPackageMetadata(t *testing.T) {
	input := []domain.Package{
		{Name: "postcss", Version: "8.5.8", Ecosystem: domain.EcosystemNPM, Dev: true, Indirect: true, Peer: true, Via: []string{"tailwindcss"}},
		{Name: "postcss", Version: "8.5.8", Ecosystem: domain.EcosystemNPM, Dev: false, Direct: true, Optional: true, Via: []string{"other"}},
	}

	got := dedup(input)
	if len(got) != 1 {
		t.Fatalf("dedup len = %d, want 1", len(got))
	}
	pkg := got[0]
	if pkg.Dev {
		t.Fatalf("Dev = true, want false when any duplicate is runtime")
	}
	if !pkg.Direct || !pkg.Indirect || !pkg.Peer || !pkg.Optional {
		t.Fatalf("metadata flags = %+v, want all merged except Dev=false", pkg)
	}
	if len(pkg.Via) != 2 || pkg.Via[0] != "other" || pkg.Via[1] != "tailwindcss" {
		t.Fatalf("Via = %#v, want sorted merged roots", pkg.Via)
	}
}
```

- [ ] **Step 2: Write collector merge test**

Append to `internal/scanner/package_collector_test.go`:

```go
func TestPackageCollectionAddMergesPackageMetadata(t *testing.T) {
	var c PackageCollection
	c.add(domain.Package{
		Name:      "postcss",
		Version:   "8.5.8",
		Ecosystem: domain.EcosystemNPM,
		Dev:       true,
		Indirect:  true,
		Peer:      true,
		Via:       []string{"tailwindcss"},
	}, "package-lock.json", "lockfile")
	c.add(domain.Package{
		Name:      "postcss",
		Version:   "8.5.8",
		Ecosystem: domain.EcosystemNPM,
		Direct:    true,
		Optional:  true,
		Via:       []string{"other"},
	}, "sbom.json", "sbom")

	if len(c.Entries) != 1 {
		t.Fatalf("Entries len = %d, want 1", len(c.Entries))
	}
	pkg := c.Entries[0].Package
	if pkg.Dev {
		t.Fatalf("Dev = true, want false when any source says runtime")
	}
	if !pkg.Direct || !pkg.Indirect || !pkg.Peer || !pkg.Optional {
		t.Fatalf("metadata flags = %+v, want merged metadata", pkg)
	}
	if len(pkg.Via) != 2 || pkg.Via[0] != "other" || pkg.Via[1] != "tailwindcss" {
		t.Fatalf("Via = %#v, want sorted merged roots", pkg.Via)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run:

```powershell
go test -count=1 .\internal\parser .\internal\scanner -run "TestDedupMergesPackageMetadata|TestPackageCollectionAddMergesPackageMetadata"
```

Expected: FAIL because metadata is not merged.

- [ ] **Step 4: Add metadata merge helper**

In `internal/parser/parser.go`, add:

```go
func mergePackageMetadata(dst, src domain.Package) domain.Package {
	if dst.Dev && !src.Dev {
		dst.Dev = false
	}
	dst.Direct = dst.Direct || src.Direct
	dst.Indirect = dst.Indirect || src.Indirect
	dst.Optional = dst.Optional || src.Optional
	dst.Peer = dst.Peer || src.Peer
	dst.Via = mergeStringSet(dst.Via, src.Via)
	return dst
}

func mergeStringSet(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	var out []string
	for _, value := range append(a, b...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
```

Add `sort` to imports.

- [ ] **Step 5: Use merge helper in parser dedup**

In `dedup`, replace:

```go
if out[idx].Dev && !p.Dev {
	out[idx].Dev = false
}
```

with:

```go
out[idx] = mergePackageMetadata(out[idx], p)
```

- [ ] **Step 6: Add scanner-local merge helper**

In `internal/scanner/package_collector.go`, add scanner-local helpers rather than importing parser internals:

```go
func mergeCollectedPackageMetadata(dst, src domain.Package) domain.Package {
	if dst.Dev && !src.Dev {
		dst.Dev = false
	}
	dst.Direct = dst.Direct || src.Direct
	dst.Indirect = dst.Indirect || src.Indirect
	dst.Optional = dst.Optional || src.Optional
	dst.Peer = dst.Peer || src.Peer
	dst.Via = mergeCollectedStringSet(dst.Via, src.Via)
	return dst
}

func mergeCollectedStringSet(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	var out []string
	for _, value := range append(a, b...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
```

Add `sort` to imports.

- [ ] **Step 7: Use merge helper in collection add**

In `PackageCollection.add`, replace:

```go
if c.Entries[i].Package.Dev && !pkg.Dev {
	c.Entries[i].Package.Dev = false
}
```

with:

```go
c.Entries[i].Package = mergeCollectedPackageMetadata(c.Entries[i].Package, pkg)
```

- [ ] **Step 8: Run merge tests**

Run:

```powershell
go test -count=1 .\internal\parser .\internal\scanner -run "TestDedupMergesPackageMetadata|TestPackageCollectionAddMergesPackageMetadata"
```

Expected: PASS.

---

### Task 5: Render Scope, Relation, Via, and Flags in `--list-all`

**Files:**
- Modify: `cmd/packmon/list_all.go`
- Test: `cmd/packmon/list_all_test.go`

- [ ] **Step 1: Write failing terminal output test**

Add to `cmd/packmon/list_all_test.go`:

```go
func TestRunListAll_RendersScopeRelationViaAndFlags(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "devDependencies": {"tailwindcss": "3.4.17"}
    },
    "node_modules/tailwindcss": {
      "version": "3.4.17",
      "dev": true,
      "dependencies": {"postcss": "^8.4.47"}
    },
    "node_modules/postcss": {
      "version": "8.5.8",
      "dev": true,
      "peer": true
    }
  }
}`)

	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		if name == "postcss" {
			return "8.5.15"
		}
		return "3.4.17"
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettings(dir, false)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	for _, want := range []string{"SCOPE", "RELATION", "VIA", "FLAGS"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all output missing column %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "postcss") || !strings.Contains(out, "dev") || !strings.Contains(out, "transitive") || !strings.Contains(out, "tailwindcss") || !strings.Contains(out, "peer") {
		t.Fatalf("postcss row missing dev/transitive/via/peer context:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```powershell
go test -count=1 .\cmd\packmon -run TestRunListAll_RendersScopeRelationViaAndFlags
```

Expected: FAIL because the columns do not exist.

- [ ] **Step 3: Extend list-all structs**

In `cmd/packmon/list_all.go`, change `listAllPackage`:

```go
type listAllPackage struct {
	Name       string
	Version    string
	Ecosystem  domain.Ecosystem
	LockFile   string
	SourceType string
	Dev        bool
	Direct     bool
	Indirect   bool
	Optional   bool
	Peer       bool
	Via        []string
}
```

Change `listAllRow`:

```go
type listAllRow struct {
	Name       string
	Installed  string
	Latest     string
	Update     string
	Ecosystem  string
	Vuln       string
	Scope      string
	Relation   string
	Via        string
	Flags      string
	LockFile   string
}
```

Change `listAllFindingRow`:

```go
type listAllFindingRow struct {
	Severity     string
	Package      string
	Ecosystem    string
	Advisory     string
	FixedVersion string
	Source       string
	Scope        string
	Relation     string
	Via          string
	Flags        string
}
```

- [ ] **Step 4: Copy metadata from collected entries**

In `collectAllPackages`, replace the append block with:

```go
packages = append(packages, listAllPackage{
	Name:       p.Name,
	Version:    p.Version,
	Ecosystem:  p.Ecosystem,
	LockFile:   entry.SourceFile,
	SourceType: entry.SourceType,
	Dev:        p.Dev,
	Direct:     p.Direct,
	Indirect:   p.Indirect,
	Optional:   p.Optional,
	Peer:       p.Peer,
	Via:        append([]string(nil), p.Via...),
})
```

- [ ] **Step 5: Add display helpers**

Add to `cmd/packmon/list_all.go`:

```go
func packageScope(eco domain.Ecosystem, sourceType string, dev bool) string {
	switch {
	case sourceType == "sbom":
		return "sbom"
	case eco == domain.EcosystemGitHubActions:
		return "ci"
	case dev:
		return "dev"
	default:
		return "runtime"
	}
}

func packageRelation(pkg listAllPackage) string {
	switch {
	case pkg.SourceType == "sbom":
		return "declared"
	case pkg.Direct:
		return "direct"
	case pkg.Indirect:
		return "transitive"
	case pkg.Ecosystem == domain.EcosystemGo:
		return "module"
	case pkg.Ecosystem == domain.EcosystemGitHubActions:
		return "workflow"
	default:
		return "-"
	}
}

func packageVia(via []string) string {
	if len(via) == 0 {
		return "-"
	}
	if len(via) <= 3 {
		return strings.Join(via, ",")
	}
	return strings.Join(via[:3], ",") + fmt.Sprintf(",+%d", len(via)-3)
}

func packageFlags(optional, peer bool) string {
	var flags []string
	if optional {
		flags = append(flags, "optional")
	}
	if peer {
		flags = append(flags, "peer")
	}
	if len(flags) == 0 {
		return "-"
	}
	return strings.Join(flags, ",")
}
```

- [ ] **Step 6: Populate row metadata and finding metadata**

In `buildListAllPackageReport`, when appending a row, include:

```go
Scope:     packageScope(p.Ecosystem, p.SourceType, p.Dev),
Relation:  packageRelation(p),
Via:       packageVia(p.Via),
Flags:     packageFlags(p.Optional, p.Peer),
```

In `writeListAllHTML`, build an index before iterating findings:

```go
rowByPackage := make(map[string]listAllRow, len(packages.Rows))
for _, row := range packages.Rows {
	rowByPackage[row.Ecosystem+"/"+row.Name+"@"+row.Installed] = row
}
```

When appending `listAllFindingRow`, look up metadata:

```go
meta := rowByPackage[string(f.Ecosystem)+"/"+f.Name+"@"+f.Version]
rep.Findings = append(rep.Findings, listAllFindingRow{
	Severity:     string(f.Severity),
	Package:      fmt.Sprintf("%s@%s", f.Name, f.Version),
	Ecosystem:    string(f.Ecosystem),
	Advisory:     listAllAdvisoryLabel(f),
	FixedVersion: f.FixedVersion,
	Source:       f.Source,
	Scope:        meta.Scope,
	Relation:     meta.Relation,
	Via:          meta.Via,
	Flags:        meta.Flags,
})
```

- [ ] **Step 7: Update terminal column widths and print format**

In `printListAllPackageReport`, add `maxScope`, `maxRelation`, `maxVia`, `maxFlags` and include the columns:

```go
fmtStr := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
	maxName, gap, maxInst, gap, maxLat, gap, maxUpd, gap, maxEco, gap, maxVuln, gap,
	maxScope, gap, maxRelation, gap, maxVia, gap, maxFlags, gap)

fmt.Printf(fmtStr, "PACKAGE", "INSTALLED", "LATEST", "UPDATE", "ECOSYSTEM", "VULN", "SCOPE", "RELATION", "VIA", "FLAGS", "LOCK FILE")
for _, r := range report.Rows {
	fmt.Printf(fmtStr, r.Name, r.Installed, r.Latest, r.Update, r.Ecosystem, r.Vuln, r.Scope, r.Relation, r.Via, r.Flags, r.LockFile)
}
```

- [ ] **Step 8: Update list-all HTML columns**

In the findings table header, use:

```html
<thead><tr><th class="short">Severity</th><th class="finding-package">Package</th><th class="short">Ecosystem</th><th>Advisory</th><th>Fix Version</th><th>Source</th><th class="short">Scope</th><th class="short">Relation</th><th>Via</th><th class="short">Flags</th></tr></thead>
```

In the findings row template, use:

```html
{{range .Findings}}<tr><td class="short">{{.Severity}}</td><td class="finding-package">{{.Package}}</td><td class="short">{{.Ecosystem}}</td><td>{{.Advisory}}</td><td>{{.FixedVersion}}</td><td>{{.Source}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td><td>{{.Via}}</td><td class="short">{{.Flags}}</td></tr>{{end}}
```

In the package table header, use:

```html
<thead><tr><th class="name">Package</th><th class="version">Installed</th><th class="version">Latest</th><th class="short">Update</th><th class="short">Ecosystem</th><th class="short">Vuln</th><th class="short">Scope</th><th class="short">Relation</th><th>Via</th><th class="short">Flags</th><th class="lockfile">Lock File</th></tr></thead>
```

In the package row template, use:

```html
{{range .PackageRows}}<tr><td class="name">{{.Name}}</td><td class="version">{{.Installed}}</td><td class="version">{{.Latest}}</td><td class="short">{{.Update}}</td><td class="short">{{.Ecosystem}}</td><td class="short">{{.Vuln}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td><td>{{.Via}}</td><td class="short">{{.Flags}}</td><td class="lockfile">{{.LockFile}}</td></tr>{{end}}
```

- [ ] **Step 9: Run list-all tests**

Run:

```powershell
go test -count=1 .\cmd\packmon -run "TestRunListAll_RendersScopeRelationViaAndFlags|TestRunListAll_WritesHTMLReportWithFullPackageList|TestScanCommandListAllHTMLFlagWritesFullReport"
```

Expected: PASS.

---

### Task 6: Render Scope Metadata in `--outdated`

**Files:**
- Modify: `cmd/packmon/outdated.go`
- Test: `cmd/packmon/outdated_fetch_test.go`

- [ ] **Step 1: Write failing outdated terminal/HTML test**

Append to `cmd/packmon/outdated_fetch_test.go`:

```go
func TestScanCommandOutdatedRendersScopeRelationViaAndFlags(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		if name == "postcss" {
			return "8.5.15"
		}
		return "3.4.17"
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"devDependencies": {"tailwindcss": "3.4.17"}},
			"node_modules/tailwindcss": {"version": "3.4.17", "dev": true, "dependencies": {"postcss": "^8.4.47"}},
			"node_modules/postcss": {"version": "8.5.8", "dev": true, "peer": true}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")

	output := captureStdout(t, func() {
		cmd := newScanCmd()
		cmd.SetArgs([]string{"--outdated", "--html", htmlPath, dir})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("scan command execute: %v", err)
		}
	})

	for _, want := range []string{"SCOPE", "RELATION", "VIA", "FLAGS", "postcss", "dev", "transitive", "tailwindcss", "peer"} {
		if !strings.Contains(output, want) {
			t.Fatalf("outdated terminal output missing %q:\n%s", want, output)
		}
	}

	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read outdated HTML report: %v", err)
	}
	html := string(data)
	for _, want := range []string{"Scope", "Relation", "Via", "Flags", "postcss", "dev", "transitive", "tailwindcss", "peer"} {
		if !strings.Contains(html, want) {
			t.Fatalf("outdated HTML missing %q:\n%s", want, html)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```powershell
go test -count=1 .\cmd\packmon -run TestScanCommandOutdatedRendersScopeRelationViaAndFlags
```

Expected: FAIL because outdated output lacks metadata columns.

- [ ] **Step 3: Extend outdated structs**

In `cmd/packmon/outdated.go`, change `outdatedPackage`:

```go
type outdatedPackage struct {
	Name       string
	Version    string
	Ecosystem  domain.Ecosystem
	LockFile   string
	SourceType string
	Dev        bool
	Direct     bool
	Indirect   bool
	Optional   bool
	Peer       bool
	Via        []string
}
```

Change `outdatedRow`:

```go
type outdatedRow struct {
	Name      string
	Installed string
	Latest    string
	Ecosystem string
	Scope     string
	Relation  string
	Via       string
	Flags     string
	LockFile  string
}
```

- [ ] **Step 4: Copy metadata from collected entries**

In `runOutdatedWithOptions`, when appending `outdatedPackage`, use:

```go
packages = append(packages, outdatedPackage{
	Name:       p.Name,
	Version:    p.Version,
	Ecosystem:  p.Ecosystem,
	LockFile:   entry.SourceFile,
	SourceType: entry.SourceType,
	Dev:        p.Dev,
	Direct:     p.Direct,
	Indirect:   p.Indirect,
	Optional:   p.Optional,
	Peer:       p.Peer,
	Via:        append([]string(nil), p.Via...),
})
```

- [ ] **Step 5: Add adapter helper for existing display functions**

In `cmd/packmon/outdated.go`, add:

```go
func outdatedListAllPackage(p outdatedPackage) listAllPackage {
	return listAllPackage{
		Name:       p.Name,
		Version:    p.Version,
		Ecosystem:  p.Ecosystem,
		LockFile:   p.LockFile,
		SourceType: p.SourceType,
		Dev:        p.Dev,
		Direct:     p.Direct,
		Indirect:   p.Indirect,
		Optional:   p.Optional,
		Peer:       p.Peer,
		Via:        p.Via,
	}
}
```

- [ ] **Step 6: Populate outdated row metadata**

When appending `outdatedRow`, include:

```go
displayPkg := outdatedListAllPackage(pkg)
report.Outdated = append(report.Outdated, outdatedRow{
	Name:      pkg.Name,
	Installed: pkg.Version,
	Latest:    latest,
	Ecosystem: string(pkg.Ecosystem),
	Scope:     packageScope(pkg.Ecosystem, pkg.SourceType, pkg.Dev),
	Relation:  packageRelation(displayPkg),
	Via:       packageVia(pkg.Via),
	Flags:     packageFlags(pkg.Optional, pkg.Peer),
	LockFile:  pkg.LockFile,
})
```

- [ ] **Step 7: Update outdated terminal output columns**

In `printOutdatedReport`, include `SCOPE`, `RELATION`, `VIA`, and `FLAGS` before `LOCK FILE`, mirroring `printListAllPackageReport`.

- [ ] **Step 8: Update outdated HTML columns**

In `outdatedHTML`, update the table header:

```html
<thead><tr><th class="name">Package</th><th class="version">Installed</th><th class="version">Latest</th><th class="ecosystem">Ecosystem</th><th class="short">Scope</th><th class="short">Relation</th><th>Via</th><th class="short">Flags</th><th class="lockfile">Lock File</th></tr></thead>
```

Update the row template:

```html
{{range .Outdated}}<tr><td class="name">{{.Name}}</td><td class="version">{{.Installed}}</td><td class="version">{{.Latest}}</td><td class="ecosystem">{{.Ecosystem}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td><td>{{.Via}}</td><td class="short">{{.Flags}}</td><td class="lockfile">{{.LockFile}}</td></tr>{{end}}
```

- [ ] **Step 9: Run outdated tests**

Run:

```powershell
go test -count=1 .\cmd\packmon -run "TestScanCommandOutdatedRendersScopeRelationViaAndFlags|TestScanCommandOutdatedHTMLFlagWritesReport|TestScanCommandOutdatedIncludesDevByDefault"
```

Expected: PASS.

---

### Task 7: Adjust Scanner Findings Basis for `--list-all`

**Files:**
- Modify: `cmd/packmon/list_all.go`
- Test: `cmd/packmon/list_all_test.go`

- [ ] **Step 1: Write failing test for list-all default scan scope**

Add to `cmd/packmon/list_all_test.go`:

```go
func TestRunListAll_FindingScanRespectsIncludeDevButPackageListShowsAll(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "": {"devDependencies": {"postcss": "8.5.8"}},
    "node_modules/postcss": {"version": "8.5.8", "dev": true}
  }
}`)

	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		if name == "postcss" {
			return "8.5.15"
		}
		return ""
	})

	settings := listAllSettings(dir, false)
	settings.IncludeDev = false
	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), settings); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	if !strings.Contains(out, "postcss") || !strings.Contains(out, "dev") {
		t.Fatalf("package list should include dev postcss:\n%s", out)
	}
	if strings.Contains(out, "VULN  yes") {
		t.Fatalf("dev-only package should not be marked vulnerable when scan IncludeDev=false:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails if current code scans all dev findings**

Run:

```powershell
go test -count=1 .\cmd\packmon -run TestRunListAll_FindingScanRespectsIncludeDevButPackageListShowsAll
```

Expected: With current code this may pass if no advisory is seeded. If it passes immediately, keep it and add a seeded advisory variant in Step 3.

- [ ] **Step 3: Seed advisory in the test when needed**

If Step 2 passed immediately, add this before writing the package-lock:

```go
dbDir := os.Getenv("PACKMON_DB_PATH")
store, _ := newTestSQLiteStore(t, dbDir)
ctx := context.Background()
if _, err := store.DB().ExecContext(ctx, `
	INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, summary)
	VALUES('GHSA-postcss-test|npm|postcss', 'GHSA-postcss-test', 'npm', 'postcss', '[{"introduced":"0.0.0"},{"fixed":"8.5.10"}]', 'MEDIUM', 'postcss test advisory')`); err != nil {
	t.Fatalf("insert vulnerability: %v", err)
}
```

Then assert:

```go
if strings.Contains(out, "GHSA-postcss-test") {
	t.Fatalf("findings section should not include dev-only postcss when IncludeDev=false:\n%s", out)
}
```

- [ ] **Step 4: Implement separate scan vs inventory include-dev settings**

In `runListAll`, remove:

```go
settings.IncludeDev = true
```

Before collecting all packages, create:

```go
inventorySettings := settings
inventorySettings.IncludeDev = true
packages, err := collectAllPackages(inventorySettings)
```

Keep `runScanPipeline(ctx, settings)` unchanged so `--include-dev` controls findings, while the inventory section still lists everything.

- [ ] **Step 5: Run list-all scope tests**

Run:

```powershell
go test -count=1 .\cmd\packmon -run "TestRunListAll_FindingScanRespectsIncludeDevButPackageListShowsAll|TestRunListAll_IncludesDevPackagesByDefault|TestRunListAll_RendersScopeRelationViaAndFlags"
```

Expected: PASS. If `TestRunListAll_IncludesDevPackagesByDefault` now asserts findings behavior, adjust it to assert only inventory behavior.

---

### Task 8: Summary Counts by Scope in HTML

**Files:**
- Modify: `cmd/packmon/list_all.go`
- Test: `cmd/packmon/list_all_test.go`

- [ ] **Step 1: Write failing HTML summary test**

Add to `cmd/packmon/list_all_test.go`:

```go
func TestRunListAllHTMLShowsScopeSummary(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"prod": "1.0.0"}, "devDependencies": {"dev-tool": "1.0.0"}},
    "node_modules/prod": {"version": "1.0.0"},
    "node_modules/dev-tool": {"version": "1.0.0", "dev": true}
  }
}`)
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, _ string) string { return "1.0.0" })

	settings := listAllSettings(dir, false)
	settings.OutputHTML = htmlPath
	if _, err := runListAll(context.Background(), settings); err != nil {
		t.Fatalf("runListAll: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	html := string(data)
	for _, want := range []string{"1 runtime", "1 dev"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML summary missing %q:\n%s", want, html)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```powershell
go test -count=1 .\cmd\packmon -run TestRunListAllHTMLShowsScopeSummary
```

Expected: FAIL because summary lacks scope counts.

- [ ] **Step 3: Add summary counts to report**

Add to `listAllPackageReport`:

```go
ByScope map[string]int
```

Initialize in `buildListAllPackageReport`:

```go
ByScope: make(map[string]int),
```

After computing `scope := packageScope(...)`, increment:

```go
report.ByScope[scope]++
```

Use `scope` in the row append.

- [ ] **Step 4: Add stable summary badge view model**

In `writeListAllHTML`, add:

```go
ScopeBadges []struct {
	Label string
	Count int
}
```

Build it in stable order:

```go
for _, label := range []string{"runtime", "dev", "ci", "sbom"} {
	if n := packages.ByScope[label]; n > 0 {
		rep.ScopeBadges = append(rep.ScopeBadges, struct {
			Label string
			Count int
		}{Label: label, Count: n})
	}
}
```

- [ ] **Step 5: Render scope badges**

In `listAllHTML`, inside `.summary`, add:

```html
{{range .ScopeBadges}}<span class="badge">{{.Count}} {{.Label}}</span>{{end}}
```

- [ ] **Step 6: Run summary test**

Run:

```powershell
go test -count=1 .\cmd\packmon -run TestRunListAllHTMLShowsScopeSummary
```

Expected: PASS.

---

### Task 9: Full Verification and Manual Smoke

**Files:**
- No source changes beyond previous tasks.

- [ ] **Step 1: Format Go files**

Run:

```powershell
gofmt -w .\internal\domain\models.go .\internal\parser\npm.go .\internal\parser\gomod.go .\internal\parser\parser.go .\internal\scanner\package_collector.go .\cmd\packmon\list_all.go .\cmd\packmon\outdated.go .\internal\domain\package_metadata_test.go .\internal\sbom\purl_test.go .\internal\parser\npm_test.go .\internal\parser\gomod_test.go .\internal\parser\parser_test.go .\internal\scanner\package_collector_test.go .\cmd\packmon\list_all_test.go .\cmd\packmon\outdated_fetch_test.go
```

Expected: command exits 0.

- [ ] **Step 2: Run focused tests**

Run:

```powershell
$env:GOTMPDIR = Join-Path $env:TEMP 'packmon-gotmp'
New-Item -ItemType Directory -Force $env:GOTMPDIR | Out-Null
go test -count=1 .\internal\domain .\internal\parser .\internal\scanner .\cmd\packmon
```

Expected: PASS.

- [ ] **Step 3: Run full test suite**

Run:

```powershell
go test -count=1 ./...
```

Expected: PASS.

- [ ] **Step 4: Build binaries in repo root**

Run:

```powershell
go build -o .\packmon.exe .\cmd\packmon
go build -o .\packmon-server.exe .\cmd\packmon-server
```

Expected: both commands exit 0.

- [ ] **Step 5: Manual list-all smoke**

Run:

```powershell
.\packmon.exe scan . --mode local --list-all --html 1.html
```

Expected terminal output contains:

```text
SCOPE
RELATION
VIA
FLAGS
postcss
dev
transitive
tailwindcss
peer
HTML report written to: 1.html
```

Expected `1.html` contains:

```text
Packmon List-All Report
All Packages
Scope
Relation
Via
Flags
postcss
tailwindcss
```

- [ ] **Step 6: Manual outdated smoke**

Run:

```powershell
.\packmon.exe scan . --outdated --html 1.html
```

Expected terminal output contains metadata columns and, if `postcss` remains outdated/vulnerable in the current lockfile, its row contains:

```text
postcss
dev
transitive
tailwindcss
peer
```

Expected `1.html` is an Outdated Packages report with metadata columns.

---

## Self-Review Notes

- Spec coverage: Scope (`runtime/dev/ci/sbom`), relation (`direct/transitive/module/workflow/declared`), optional/peer flags, and npm `via tailwindcss` are covered by Tasks 1-8.
- Type consistency: `domain.Package` metadata fields are defined before parser/scanner/CLI tasks use them.
- Comparability: adding `Via []string` makes `domain.Package` non-comparable; Task 1 Step 5 migrates the only affected call sites (`internal/sbom/purl_test.go`) to `reflect.DeepEqual`. No `map[domain.Package]` exists and `parser.dedup` keys a local struct, so nothing else breaks.
- Go parser file is `internal/parser/gomod.go` (not `go.go`); `// indirect` is captured before the existing comment strip so the `require (` block terminator is unaffected.
- Blast radius: canonical vulnerability matching and API finding shape remain unchanged; only `Package` input metadata and CLI reports expand.
- Known limitation: `via` roots are implemented for npm package-lock v2/v3 only in this plan. Other ecosystems still show the best available metadata (`dev`, `ci`, `sbom`, Go `indirect`) without inventing a dependency path.
