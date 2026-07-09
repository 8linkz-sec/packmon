package sbom

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestParseCycloneDXJSONPackages(t *testing.T) {
	input := []byte(`{
		"bomFormat":"CycloneDX",
		"specVersion":"1.5",
		"components":[
			{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"},
			{"type":"framework","name":"django","version":"4.2.11","purl":"pkg:pypi/django@4.2.11"},
			{"type":"file","name":"README.md","version":"1.0.0","purl":"pkg:npm/readme@1.0.0"},
			{"type":"library","name":"noversion","purl":"pkg:npm/noversion"}
		]
	}`)

	got, err := Parse(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	want := []domain.Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: domain.EcosystemNPM},
		{Name: "django", Version: "4.2.11", Ecosystem: domain.EcosystemPyPI},
	}
	if !reflect.DeepEqual(domainPackages(got.Packages), want) {
		t.Fatalf("packages = %+v, want %+v", domainPackages(got.Packages), want)
	}
	if len(got.Skipped) != 2 {
		t.Fatalf("skipped = %d, want 2: %+v", len(got.Skipped), got.Skipped)
	}
}

func TestParseCycloneDXJSONDependencyGraphMetadata(t *testing.T) {
	input := []byte(`{
		"bomFormat":"CycloneDX",
		"metadata":{
			"component":{"type":"application","name":"app","bom-ref":"app","purl":"pkg:npm/app@1.0.0"}
		},
		"components":[
			{"type":"library","name":"cli","version":"4.3.0","bom-ref":"app|@tailwindcss/cli@4.3.0","purl":"pkg:npm/%40tailwindcss/cli@4.3.0"},
			{"type":"library","name":"watcher","version":"2.5.6","bom-ref":"app|@parcel/watcher@2.5.6","purl":"pkg:npm/%40parcel/watcher@2.5.6"},
			{"type":"library","name":"node-addon-api","version":"7.1.1","bom-ref":"app|node-addon-api@7.1.1","purl":"pkg:npm/node-addon-api@7.1.1"}
		],
		"dependencies":[
			{"ref":"app","dependsOn":["app|@tailwindcss/cli@4.3.0"]},
			{"ref":"app|@tailwindcss/cli@4.3.0","dependsOn":["app|@parcel/watcher@2.5.6"]},
			{"ref":"app|@parcel/watcher@2.5.6","dependsOn":["app|node-addon-api@7.1.1"]}
		]
	}`)

	got, err := Parse(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	byName := make(map[string]domain.Package)
	for _, item := range got.Packages {
		byName[item.Package.Name] = item.Package
	}

	cli := byName["@tailwindcss/cli"]
	if !cli.Direct || cli.Indirect {
		t.Fatalf("cli direct=%v indirect=%v, want direct root dependency", cli.Direct, cli.Indirect)
	}

	watcher := byName["@parcel/watcher"]
	if watcher.Direct || !watcher.Indirect || len(watcher.Via) != 1 || watcher.Via[0] != "@tailwindcss/cli" {
		t.Fatalf("watcher metadata = %+v, want indirect via @tailwindcss/cli", watcher)
	}
	if len(watcher.Parents) != 1 || watcher.Parents[0].Name != "@tailwindcss/cli" || watcher.Parents[0].Version != "4.3.0" {
		t.Fatalf("watcher parents = %+v, want @tailwindcss/cli@4.3.0", watcher.Parents)
	}

	nodeAddon := byName["node-addon-api"]
	if nodeAddon.Direct || !nodeAddon.Indirect || len(nodeAddon.Via) != 1 || nodeAddon.Via[0] != "@tailwindcss/cli" {
		t.Fatalf("node-addon-api metadata = %+v, want indirect via @tailwindcss/cli", nodeAddon)
	}
	if len(nodeAddon.Parents) != 1 || nodeAddon.Parents[0].Name != "@parcel/watcher" || nodeAddon.Parents[0].Version != "2.5.6" {
		t.Fatalf("node-addon-api parents = %+v, want @parcel/watcher@2.5.6", nodeAddon.Parents)
	}
}

func TestParseCycloneDXJSONDependencyGraphPropagatesSharedVia(t *testing.T) {
	input := []byte(`{
		"bomFormat":"CycloneDX",
		"metadata":{
			"component":{"type":"application","name":"app","bom-ref":"app","purl":"pkg:npm/app@1.0.0"}
		},
		"components":[
			{"type":"library","name":"cli","version":"4.3.0","bom-ref":"cli","purl":"pkg:npm/%40tailwindcss/cli@4.3.0"},
			{"type":"library","name":"plugin","version":"1.0.0","bom-ref":"plugin","purl":"pkg:npm/plugin@1.0.0"},
			{"type":"library","name":"shared","version":"2.0.0","bom-ref":"shared","purl":"pkg:npm/shared@2.0.0"},
			{"type":"library","name":"leaf","version":"3.0.0","bom-ref":"leaf","purl":"pkg:npm/leaf@3.0.0"}
		],
		"dependencies":[
			{"ref":"app","dependsOn":["cli","plugin"]},
			{"ref":"cli","dependsOn":["shared"]},
			{"ref":"plugin","dependsOn":["shared"]},
			{"ref":"shared","dependsOn":["leaf"]}
		]
	}`)

	got, err := Parse(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	byName := make(map[string]domain.Package)
	for _, item := range got.Packages {
		byName[item.Package.Name] = item.Package
	}

	shared := byName["shared"]
	if shared.Direct || !shared.Indirect || !reflect.DeepEqual(shared.Via, []string{"@tailwindcss/cli", "plugin"}) {
		t.Fatalf("shared metadata = %+v, want indirect via cli and plugin", shared)
	}
	leaf := byName["leaf"]
	if leaf.Direct || !leaf.Indirect || !reflect.DeepEqual(leaf.Via, []string{"@tailwindcss/cli", "plugin"}) {
		t.Fatalf("leaf metadata = %+v, want indirect via cli and plugin", leaf)
	}
}

func TestAttachCycloneDXRootViaCapsDenseSharedGraphViaNames(t *testing.T) {
	const (
		rootCount   = 96
		sharedCount = 96
		wantCap     = 32
	)

	packages := make([]Package, 0, rootCount+sharedCount+1)
	edges := map[string][]string{"root": make([]string, 0, rootCount)}
	for i := rootCount - 1; i >= 0; i-- {
		ref := fmt.Sprintf("direct-%02d", i)
		name := fmt.Sprintf("root-%02d", i)
		packages = append(packages, cycloneDXTestPackage(ref, name, "1.0.0"))
		edges["root"] = append(edges["root"], ref)
		for child := 0; child < sharedCount; child++ {
			edges[ref] = append(edges[ref], fmt.Sprintf("shared-%02d", child))
		}
	}
	for child := 0; child < sharedCount; child++ {
		ref := fmt.Sprintf("shared-%02d", child)
		packages = append(packages, cycloneDXTestPackage(ref, ref, "1.0.0"))
		edges[ref] = []string{"leaf"}
	}
	packages = append(packages, cycloneDXTestPackage("leaf", "leaf", "1.0.0"))

	if err := attachCycloneDXRootVia(packages, buildCycloneDXRefIndex(packages), edges, "root"); err != nil {
		t.Fatalf("attachCycloneDXRootVia() error = %v", err)
	}

	wantVia := make([]string, 0, wantCap)
	for i := 0; i < wantCap; i++ {
		wantVia = append(wantVia, fmt.Sprintf("root-%02d", i))
	}
	for _, idx := range []int{rootCount, len(packages) - 1} {
		pkg := packages[idx].Package
		if !reflect.DeepEqual(pkg.Via, wantVia) {
			t.Fatalf("%s Via = %#v, want capped stable roots %#v", pkg.Name, pkg.Via, wantVia)
		}
	}
}

func TestCycloneDXUsesDomainPackageMergeHelpers(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "cyclonedx.go", nil, 0)
	if err != nil {
		t.Fatalf("parse cyclonedx.go: %v", err)
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		switch fn.Name.Name {
		case "mergeSBOMStringSet", "mergeSBOMPackageParents":
			t.Fatalf("local SBOM merge helper %s still exists; use domain package merge helpers", fn.Name.Name)
		}
	}
}

func TestAttachCycloneDXPackageParentsAccumulatesBeforeMerging(t *testing.T) {
	packages := []Package{
		cycloneDXTestPackage("child", "child", "1.0.0"),
		cycloneDXTestPackage("z-parent", "z-parent", "1.0.0"),
		cycloneDXTestPackage("a-parent", "a-parent", "1.0.0"),
		cycloneDXTestPackage("a-parent-dupe", "a-parent", "1.0.0"),
	}
	refToIndex := buildCycloneDXRefIndex(packages)
	edges := map[string][]string{
		"z-parent":      {"child"},
		"a-parent":      {"child"},
		"a-parent-dupe": {"child"},
	}

	attachCycloneDXPackageParents(packages, refToIndex, edges)

	wantParents := []domain.PackageParent{
		{Name: "a-parent", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "z-parent", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
	}
	if !reflect.DeepEqual(packages[0].Package.Parents, wantParents) {
		t.Fatalf("child parents = %+v, want %+v", packages[0].Package.Parents, wantParents)
	}
	if !packages[0].Package.Indirect {
		t.Fatalf("child Indirect = false, want true")
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "cyclonedx.go", nil, 0)
	if err != nil {
		t.Fatalf("parse cyclonedx.go: %v", err)
	}
	fn := findCycloneDXFunc(file, "attachCycloneDXPackageParents")
	if fn == nil {
		t.Fatal("attachCycloneDXPackageParents not found")
	}
	if cycloneDXEdgeLoopMergesParents(fn) {
		t.Fatal("attachCycloneDXPackageParents merges parents inside the child edge loop; want accumulation before a single merge per child")
	}
}

func TestBuildCycloneDXRefIndexTrimsRefsAndKeepsLastDuplicate(t *testing.T) {
	packages := []Package{
		{BOMRef: " first "},
		{BOMRef: ""},
		{BOMRef: "second"},
		{BOMRef: "first"},
	}

	got := buildCycloneDXRefIndex(packages)
	want := map[string]int{
		"first":  3,
		"second": 2,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildCycloneDXRefIndex() = %#v, want %#v", got, want)
	}
}

func TestBuildCycloneDXDependencyEdgesTrimsRefsAndSkipsBlanks(t *testing.T) {
	dependencies := []cyclonedxDependency{
		{Ref: " root ", DependsOn: []string{" first ", "", "second"}},
		{Ref: "", DependsOn: []string{"ignored"}},
		{Ref: "root", DependsOn: []string{" third "}},
		{Ref: "empty", DependsOn: []string{" "}},
	}

	got := buildCycloneDXDependencyEdges(dependencies)
	want := map[string][]string{
		"root": {"first", "second", "third"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildCycloneDXDependencyEdges() = %#v, want %#v", got, want)
	}
}

func TestMarkCycloneDXDirectDependenciesUsesTrimmedRootRef(t *testing.T) {
	packages := []Package{
		cycloneDXTestPackage("cli", "@tailwindcss/cli", "4.3.0"),
		cycloneDXTestPackage("plugin", "plugin", "1.0.0"),
	}
	refToIndex := buildCycloneDXRefIndex(packages)
	edges := map[string][]string{
		"root": {"cli", "missing"},
	}

	markCycloneDXDirectDependencies(packages, refToIndex, edges, " root ")

	if !packages[0].Package.Direct {
		t.Fatalf("cli Direct = false, want true")
	}
	if packages[1].Package.Direct {
		t.Fatalf("plugin Direct = true, want false")
	}
}

func TestAttachCycloneDXDependencyMetadataAddsParentsAndVia(t *testing.T) {
	packages := []Package{
		cycloneDXTestPackage("cli", "@tailwindcss/cli", "4.3.0"),
		cycloneDXTestPackage("plugin", "plugin", "1.0.0"),
		cycloneDXTestPackage("shared", "shared", "2.0.0"),
		cycloneDXTestPackage("leaf", "leaf", "3.0.0"),
	}
	refToIndex := buildCycloneDXRefIndex(packages)
	edges := map[string][]string{
		"root":   {"cli", "plugin"},
		"cli":    {"shared"},
		"plugin": {"shared"},
		"shared": {"leaf"},
	}

	if err := attachCycloneDXDependencyMetadata(packages, refToIndex, edges, " root "); err != nil {
		t.Fatalf("attachCycloneDXDependencyMetadata() error = %v", err)
	}

	shared := packages[2].Package
	if shared.Direct || !shared.Indirect || !reflect.DeepEqual(shared.Via, []string{"@tailwindcss/cli", "plugin"}) {
		t.Fatalf("shared metadata = %+v, want indirect via cli and plugin", shared)
	}
	wantSharedParents := []domain.PackageParent{
		{Name: "@tailwindcss/cli", Version: "4.3.0", Ecosystem: domain.EcosystemNPM},
		{Name: "plugin", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
	}
	if !reflect.DeepEqual(shared.Parents, wantSharedParents) {
		t.Fatalf("shared parents = %+v, want %+v", shared.Parents, wantSharedParents)
	}

	leaf := packages[3].Package
	if leaf.Direct || !leaf.Indirect || !reflect.DeepEqual(leaf.Via, []string{"@tailwindcss/cli", "plugin"}) {
		t.Fatalf("leaf metadata = %+v, want indirect via cli and plugin", leaf)
	}
	wantLeafParents := []domain.PackageParent{
		{Name: "shared", Version: "2.0.0", Ecosystem: domain.EcosystemNPM},
	}
	if !reflect.DeepEqual(leaf.Parents, wantLeafParents) {
		t.Fatalf("leaf parents = %+v, want %+v", leaf.Parents, wantLeafParents)
	}
}

func TestParseCycloneDXRejectsRootDependencyFanoutOverWorkLimit(t *testing.T) {
	var deps strings.Builder
	for i := 0; i <= maxCycloneDXRootDependencies; i++ {
		if i > 0 {
			deps.WriteByte(',')
		}
		fmt.Fprintf(&deps, "%q", fmt.Sprintf("dep-%d", i))
	}
	input := []byte(`{
		"bomFormat":"CycloneDX",
		"metadata":{"component":{"bom-ref":"app"}},
		"components":[],
		"dependencies":[{"ref":"app","dependsOn":[` + deps.String() + `]}]
	}`)

	_, err := Parse(bytes.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "root dependency count") {
		t.Fatalf("Parse() error = %v, want root dependency work-limit error", err)
	}
}

func TestParseCycloneDXRejectsDependencyEdgesOverWorkLimit(t *testing.T) {
	var deps strings.Builder
	for i := 0; i <= maxCycloneDXDependencyEdges; i++ {
		if i > 0 {
			deps.WriteByte(',')
		}
		fmt.Fprintf(&deps, "%q", fmt.Sprintf("dep-%d", i))
	}
	input := []byte(`{
		"bomFormat":"CycloneDX",
		"components":[],
		"dependencies":[{"ref":"not-root","dependsOn":[` + deps.String() + `]}]
	}`)

	_, err := Parse(bytes.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "dependency edge count") {
		t.Fatalf("Parse() error = %v, want dependency edge work-limit error", err)
	}
}

func TestAttachCycloneDXRootViaCapsBeforeViaStateLimit(t *testing.T) {
	rootCount := 225
	childCount := 225
	packages := make([]Package, 0, rootCount+childCount)
	edges := map[string][]string{"root": make([]string, 0, rootCount)}

	for i := 0; i < rootCount; i++ {
		ref := fmt.Sprintf("direct-%d", i)
		packages = append(packages, cycloneDXTestPackage(ref, ref, "1.0.0"))
		edges["root"] = append(edges["root"], ref)
		for child := 0; child < childCount; child++ {
			edges[ref] = append(edges[ref], fmt.Sprintf("child-%d", child))
		}
	}
	for child := 0; child < childCount; child++ {
		ref := fmt.Sprintf("child-%d", child)
		packages = append(packages, cycloneDXTestPackage(ref, ref, "1.0.0"))
	}

	if err := attachCycloneDXRootVia(packages, buildCycloneDXRefIndex(packages), edges, "root"); err != nil {
		t.Fatalf("attachCycloneDXRootVia() error = %v", err)
	}

	gotVia := packages[rootCount].Package.Via
	if len(gotVia) != maxCycloneDXViaRootsPerComponent {
		t.Fatalf("child-0 Via length = %d, want cap %d: %#v", len(gotVia), maxCycloneDXViaRootsPerComponent, gotVia)
	}
}

func TestParseCycloneDXXMLPackages(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5">
  <components>
    <component type="library">
      <name>left-pad</name>
      <version>1.3.0</version>
      <purl>pkg:npm/left-pad@1.3.0</purl>
    </component>
    <component type="application">
      <name>rails</name>
      <version>7.1.3</version>
      <purl>pkg:gem/rails@7.1.3</purl>
    </component>
  </components>
</bom>`)

	got, err := Parse(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("Parse(xml) error = %v", err)
	}

	want := []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
		{Name: "rails", Version: "7.1.3", Ecosystem: domain.EcosystemGem},
	}
	if !reflect.DeepEqual(domainPackages(got.Packages), want) {
		t.Fatalf("packages = %+v, want %+v", domainPackages(got.Packages), want)
	}
}

func TestParseCycloneDXXMLDependencyGraphMetadata(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5">
  <metadata>
    <component type="application" bom-ref="app">
      <name>app</name>
      <version>1.0.0</version>
      <purl>pkg:npm/app@1.0.0</purl>
    </component>
  </metadata>
  <components>
    <component type="library" bom-ref="app|@tailwindcss/cli@4.3.0">
      <name>cli</name>
      <version>4.3.0</version>
      <purl>pkg:npm/%40tailwindcss/cli@4.3.0</purl>
    </component>
    <component type="library" bom-ref="app|@parcel/watcher@2.5.6">
      <name>watcher</name>
      <version>2.5.6</version>
      <purl>pkg:npm/%40parcel/watcher@2.5.6</purl>
    </component>
    <component type="library" bom-ref="app|node-addon-api@7.1.1">
      <name>node-addon-api</name>
      <version>7.1.1</version>
      <purl>pkg:npm/node-addon-api@7.1.1</purl>
    </component>
  </components>
  <dependencies>
    <dependency ref="app">
      <dependency ref="app|@tailwindcss/cli@4.3.0"/>
    </dependency>
    <dependency ref="app|@tailwindcss/cli@4.3.0">
      <dependency ref="app|@parcel/watcher@2.5.6"/>
    </dependency>
    <dependency ref="app|@parcel/watcher@2.5.6">
      <dependency ref="app|node-addon-api@7.1.1"/>
    </dependency>
  </dependencies>
</bom>`)

	got, err := Parse(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("Parse(xml) error = %v", err)
	}

	byName := make(map[string]domain.Package)
	for _, item := range got.Packages {
		byName[item.Package.Name] = item.Package
	}

	cli := byName["@tailwindcss/cli"]
	if !cli.Direct || cli.Indirect {
		t.Fatalf("cli direct=%v indirect=%v, want direct root dependency", cli.Direct, cli.Indirect)
	}

	watcher := byName["@parcel/watcher"]
	if watcher.Direct || !watcher.Indirect || len(watcher.Via) != 1 || watcher.Via[0] != "@tailwindcss/cli" {
		t.Fatalf("watcher metadata = %+v, want indirect via @tailwindcss/cli", watcher)
	}
	if len(watcher.Parents) != 1 || watcher.Parents[0].Name != "@tailwindcss/cli" || watcher.Parents[0].Version != "4.3.0" {
		t.Fatalf("watcher parents = %+v, want @tailwindcss/cli@4.3.0", watcher.Parents)
	}

	nodeAddon := byName["node-addon-api"]
	if nodeAddon.Direct || !nodeAddon.Indirect || len(nodeAddon.Via) != 1 || nodeAddon.Via[0] != "@tailwindcss/cli" {
		t.Fatalf("node-addon-api metadata = %+v, want indirect via @tailwindcss/cli", nodeAddon)
	}
	if len(nodeAddon.Parents) != 1 || nodeAddon.Parents[0].Name != "@parcel/watcher" || nodeAddon.Parents[0].Version != "2.5.6" {
		t.Fatalf("node-addon-api parents = %+v, want @parcel/watcher@2.5.6", nodeAddon.Parents)
	}
}

func TestParseRejectsUnknownJSONFormat(t *testing.T) {
	_, err := Parse(strings.NewReader(`{"format":"unknown"}`))
	if err == nil {
		t.Fatal("Parse(unknown) error = nil")
	}
}

func domainPackages(pkgs []Package) []domain.Package {
	out := make([]domain.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		out = append(out, pkg.Package)
	}
	return out
}

func cycloneDXTestPackage(ref, name, version string) Package {
	return Package{
		BOMRef: ref,
		Package: domain.Package{
			Name:      name,
			Version:   version,
			Ecosystem: domain.EcosystemNPM,
		},
	}
}

func findCycloneDXFunc(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func cycloneDXEdgeLoopMergesParents(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(node ast.Node) bool {
		rangeStmt, ok := node.(*ast.RangeStmt)
		if !ok || !cycloneDXIdentName(rangeStmt.X, "childRefs") {
			return true
		}
		ast.Inspect(rangeStmt.Body, func(inner ast.Node) bool {
			if cycloneDXCallsDomainMergePackageParents(inner) {
				found = true
				return false
			}
			return true
		})
		return !found
	})
	return found
}

func cycloneDXCallsDomainMergePackageParents(node ast.Node) bool {
	call, ok := node.(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "MergePackageParents" {
		return false
	}
	return cycloneDXIdentName(selector.X, "domain")
}

func cycloneDXIdentName(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}
