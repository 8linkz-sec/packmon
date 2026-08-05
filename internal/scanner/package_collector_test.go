package scanner

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/parser"
	"github.com/8linkz-sec/packmon/internal/sbom"
)

func TestCollectPackagesIncludesExplicitSBOM(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion":3,
		"packages":{"node_modules/lodash":{"version":"4.17.21"}}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sbomPath := filepath.Join(dir, "bom.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{
		"bomFormat":"CycloneDX",
		"components":[{"type":"library","name":"django","version":"4.2.11","purl":"pkg:pypi/django@4.2.11"}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := CollectPackages(CollectConfig{
		Registry:  parser.NewRegistry(),
		Root:      dir,
		MaxDepth:  2,
		SBOMFiles: []string{sbomPath},
	})
	if err != nil {
		t.Fatalf("CollectPackages() error = %v", err)
	}
	if got.LockFiles != 1 || got.SBOMFiles != 1 {
		t.Fatalf("sources lock=%d sbom=%d, want 1/1", got.LockFiles, got.SBOMFiles)
	}
	want := map[string]domain.Ecosystem{
		"lodash@4.17.21": domain.EcosystemNPM,
		"django@4.2.11":  domain.EcosystemPyPI,
	}
	if len(got.Packages) != len(want) {
		t.Fatalf("packages = %+v, want %d", got.Packages, len(want))
	}
	for _, pkg := range got.Packages {
		key := pkg.Name + "@" + pkg.Version
		if want[key] != pkg.Ecosystem {
			t.Fatalf("package %+v not in expected set %#v", pkg, want)
		}
	}
}

func symlinkOrSkip(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
}

func TestCollectPackagesRejectsLockfileSymlinkOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	outsideLock := filepath.Join(outside, "package-lock.json")
	if err := os.WriteFile(outsideLock, []byte(`{
		"lockfileVersion": 3,
		"packages": {"node_modules/external": {"version":"9.9.9"}}
	}`), 0o600); err != nil {
		t.Fatalf("write outside lockfile: %v", err)
	}
	symlinkOrSkip(t, outsideLock, filepath.Join(root, "package-lock.json"))

	got, err := CollectPackages(CollectConfig{
		Registry: parser.NewRegistry(),
		Root:     root,
		MaxDepth: 2,
	})
	if err != nil {
		t.Fatalf("CollectPackages() error = %v", err)
	}
	if len(got.Packages) != 0 {
		t.Fatalf("Packages = %+v, want no packages from external symlink target", got.Packages)
	}
	if len(got.ParseErrors) != 1 || !strings.Contains(got.ParseErrors[0], "package-lock.json") {
		t.Fatalf("ParseErrors = %#v, want symlinked lockfile rejection", got.ParseErrors)
	}
}

func TestParseCollectedLockFileUnderRootRejectsRelativeEscape(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	outsideLock := filepath.Join(outside, "package-lock.json")
	if err := os.WriteFile(outsideLock, []byte(`{
		"lockfileVersion": 3,
		"packages": {"node_modules/external": {"version":"9.9.9"}}
	}`), 0o600); err != nil {
		t.Fatalf("write outside lockfile: %v", err)
	}
	p := parser.NewRegistry().ParserFor(outsideLock)
	if p == nil {
		t.Fatal("package-lock parser not registered")
	}

	_, err := parseCollectedLockFileUnderRoot(root, LockFile{
		Path:    outsideLock,
		RelPath: filepath.ToSlash(filepath.Join("..", "outside", "package-lock.json")),
		Parser:  p,
	})
	if err == nil {
		t.Fatal("parseCollectedLockFileUnderRoot() error = nil, want root escape rejection")
	}
}

func TestCollectLockfilePackagesRecordsParseErrorsAsNonFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(`{{{not yaml`), 0o600); err != nil {
		t.Fatal(err)
	}

	result := &PackageCollection{}
	err := collectLockfilePackages(result, parser.NewRegistry(), dir, 2, nil, ecosystemFilter(nil))
	if err != nil {
		t.Fatalf("collectLockfilePackages() error = %v", err)
	}
	if result.LockFiles != 2 {
		t.Fatalf("LockFiles = %d, want 2", result.LockFiles)
	}
	if len(result.ParseErrors) != 1 || !strings.Contains(result.ParseErrors[0], "pnpm-lock.yaml") {
		t.Fatalf("ParseErrors = %#v, want pnpm parse warning", result.ParseErrors)
	}
	if len(result.FatalParseErrors) != 0 {
		t.Fatalf("FatalParseErrors = %#v, want none for lockfile parse errors", result.FatalParseErrors)
	}
	if len(result.Entries) != 1 || result.Entries[0].Package.Name != "prod" {
		t.Fatalf("Entries = %+v, want parsed lockfile package", result.Entries)
	}
}

func TestCollectExplicitSBOMPackagesRecordsParseErrorsAsFatal(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.cdx.json")
	if err := os.WriteFile(badPath, []byte(`{"bomFormat":"CycloneDX",`), 0o600); err != nil {
		t.Fatal(err)
	}
	goodPath := filepath.Join(dir, "good.cdx.json")
	if err := os.WriteFile(goodPath, []byte(`{
		"bomFormat":"CycloneDX",
		"components":[{"type":"library","name":"django","version":"4.2.11","purl":"pkg:pypi/django@4.2.11"}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	result := &PackageCollection{}
	err := collectExplicitSBOMPackages(result, dir, []string{badPath, goodPath}, ecosystemFilter(nil))
	if err != nil {
		t.Fatalf("collectExplicitSBOMPackages() error = %v", err)
	}
	if result.SBOMFiles != 2 {
		t.Fatalf("SBOMFiles = %d, want 2", result.SBOMFiles)
	}
	if len(result.ParseErrors) != 1 || !strings.Contains(result.ParseErrors[0], "bad.cdx.json") {
		t.Fatalf("ParseErrors = %#v, want malformed SBOM error", result.ParseErrors)
	}
	if len(result.FatalParseErrors) != 1 || result.FatalParseErrors[0] != result.ParseErrors[0] {
		t.Fatalf("FatalParseErrors = %#v, want malformed SBOM marked fatal", result.FatalParseErrors)
	}
	if len(result.Entries) != 1 || result.Entries[0].Package.Name != "django" || result.Entries[0].SourceType != "sbom" {
		t.Fatalf("Entries = %+v, want imported SBOM package", result.Entries)
	}
}

func TestFinalizePackageCollectionKeepsExistingFilters(t *testing.T) {
	collection := &PackageCollection{}
	collection.add(domain.Package{Name: "github.com/klauspost/compress", Version: "v1.18.6", Ecosystem: domain.EcosystemGo}, "go.mod", "lockfile")
	collection.add(domain.Package{Name: "github.com/klauspost/compress", Version: "v1.18.0", Ecosystem: domain.EcosystemGo}, "go.sum", "lockfile")
	collection.add(domain.Package{Name: "dev-only", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Dev: true}, "package-lock.json", "lockfile")

	finalizePackageCollection(collection, false)

	if len(collection.Packages) != 1 {
		t.Fatalf("Packages = %+v, want only selected Go module", collection.Packages)
	}
	pkg := collection.Packages[0]
	if pkg.Name != "github.com/klauspost/compress" || pkg.Version != "v1.18.6" {
		t.Fatalf("remaining package = %+v, want selected Go module", pkg)
	}
	if len(collection.Entries) != 1 ||
		collection.Entries[0].Package.Name != pkg.Name ||
		collection.Entries[0].Package.Version != pkg.Version ||
		collection.Entries[0].Package.Ecosystem != pkg.Ecosystem {
		t.Fatalf("Entries = %+v, want rebuilt entries matching Packages", collection.Entries)
	}
}

func TestParseCollectedLockFileRejectsOversizedRegularFileBeforeParser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxLockfileSize+1); err != nil {
		t.Fatal(err)
	}

	parser := &rejectCalledParser{}
	_, err := parseCollectedLockFile(LockFile{
		Path:    path,
		RelPath: "package-lock.json",
		Parser:  parser,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum lockfile size") {
		t.Fatalf("parseCollectedLockFile() error = %v, want size-limit error", err)
	}
	if parser.called {
		t.Fatal("parser was called for an oversized regular lockfile")
	}
}

type rejectCalledParser struct {
	called bool
}

func (p *rejectCalledParser) CanParse(string) bool {
	return true
}

func (p *rejectCalledParser) Parse(io.Reader) ([]domain.Package, error) {
	p.called = true
	return nil, errors.New("parser should not be called")
}

func (p *rejectCalledParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemNPM
}

func TestCollectPackagesDropsStaleGoSumVersionWhenGoModSelectsModule(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(`module example.com/app

go 1.26

require github.com/klauspost/compress v1.18.6
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(`github.com/klauspost/compress v1.18.0 h1:old
github.com/klauspost/compress v1.18.0/go.mod h1:oldmod
github.com/klauspost/compress v1.18.6 h1:new
github.com/klauspost/compress v1.18.6/go.mod h1:newmod
`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := CollectPackages(CollectConfig{
		Registry: parser.NewRegistry(),
		Root:     dir,
		MaxDepth: 2,
	})
	if err != nil {
		t.Fatalf("CollectPackages() error = %v", err)
	}

	versions := []string{}
	for _, entry := range got.Entries {
		if entry.Package.Ecosystem == domain.EcosystemGo && entry.Package.Name == "github.com/klauspost/compress" {
			versions = append(versions, entry.Package.Version)
		}
	}
	if len(versions) != 1 || versions[0] != "v1.18.6" {
		t.Fatalf("github.com/klauspost/compress versions = %v, want only selected go.mod version v1.18.6", versions)
	}
}

func TestCollectPackagesReportsSBOMParseErrors(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX",`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := CollectPackages(CollectConfig{
		Registry:  parser.NewRegistry(),
		Root:      dir,
		MaxDepth:  2,
		SBOMFiles: []string{sbomPath},
	})
	if err != nil {
		t.Fatalf("CollectPackages() error = %v", err)
	}
	if len(got.Packages) != 0 || len(got.ParseErrors) != 1 {
		t.Fatalf("packages=%d parseErrors=%d, want 0/1", len(got.Packages), len(got.ParseErrors))
	}
}

func TestCollectPackagesRedactsExternalSBOMPathInParseErrors(t *testing.T) {
	root := t.TempDir()
	externalDir := t.TempDir()
	sbomPath := filepath.Join(externalDir, "student-project-bom.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX",`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := CollectPackages(CollectConfig{
		Registry:  parser.NewRegistry(),
		Root:      root,
		MaxDepth:  2,
		SBOMFiles: []string{sbomPath},
	})
	if err != nil {
		t.Fatalf("CollectPackages() error = %v", err)
	}
	if len(got.ParseErrors) != 1 {
		t.Fatalf("parse errors = %#v, want one external SBOM parse error", got.ParseErrors)
	}
	parseErr := got.ParseErrors[0]
	if !strings.Contains(parseErr, "student-project-bom.cdx.json") {
		t.Fatalf("parse error = %q, want SBOM basename", parseErr)
	}
	for _, leaked := range []string{externalDir, filepath.Dir(sbomPath), sbomPath} {
		if strings.Contains(parseErr, leaked) {
			t.Fatalf("parse error leaked external path %q: %q", leaked, parseErr)
		}
	}
}

func TestCollectPackagesReportsSkippedSBOMComponentsWithoutPrivateNames(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "bom.cdx.json")
	privateName := "corp-internal-auth-service"
	if err := os.WriteFile(sbomPath, []byte(`{
		"bomFormat":"CycloneDX",
		"components":[
			{"type":"library","name":"django","version":"4.2.11","purl":"pkg:pypi/django@4.2.11"},
			{"type":"library","name":"corp-internal-auth-service","version":"1.0.0"}
		]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := CollectPackages(CollectConfig{
		Registry:  parser.NewRegistry(),
		Root:      dir,
		MaxDepth:  2,
		SBOMFiles: []string{sbomPath},
	})
	if err != nil {
		t.Fatalf("CollectPackages() error = %v", err)
	}
	if len(got.Packages) != 1 {
		t.Fatalf("packages = %+v, want one imported package", got.Packages)
	}
	if len(got.ParseErrors) != 1 {
		t.Fatalf("parse errors = %#v, want one skipped component warning", got.ParseErrors)
	}
	parseErr := got.ParseErrors[0]
	if strings.Contains(parseErr, privateName) {
		t.Fatalf("parse error leaked private SBOM component name %q: %q", privateName, parseErr)
	}
	if !strings.Contains(parseErr, `skipped SBOM component #1: missing purl`) {
		t.Fatalf("parse error = %q, want generic skipped component warning with ordinal and reason", parseErr)
	}
}

func TestPackageCollectionAddMergesPackageMetadata(t *testing.T) {
	c := &PackageCollection{}
	c.add(domain.Package{
		Name:      "postcss",
		Version:   "8.5.8",
		Ecosystem: domain.EcosystemNPM,
		Dev:       true,
		Indirect:  true,
		Peer:      true,
		Via:       []string{"tailwindcss"},
		Parents: []domain.PackageParent{
			{Name: " tailwindcss ", Version: "3.4.17", Ecosystem: domain.EcosystemNPM},
			{Name: "", Version: "ignored", Ecosystem: domain.EcosystemNPM},
		},
	}, "package-lock.json", "lockfile")
	c.add(domain.Package{
		Name:      "postcss",
		Version:   "8.5.8",
		Ecosystem: domain.EcosystemNPM,
		Direct:    true,
		Optional:  true,
		Via:       []string{"other"},
		Parents: []domain.PackageParent{
			{Name: "other", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
			{Name: "tailwindcss", Version: "3.4.17", Ecosystem: domain.EcosystemNPM},
		},
	}, "bom.json", "sbom")

	if len(c.Entries) != 1 {
		t.Fatalf("Entries = %d, want 1", len(c.Entries))
	}
	pkg := c.Entries[0].Package
	if pkg.Dev || !pkg.Direct || !pkg.Indirect || !pkg.Optional || !pkg.Peer {
		t.Fatalf("merged metadata = %+v, want production direct+indirect optional peer", pkg)
	}
	if len(pkg.Via) != 2 || pkg.Via[0] != "other" || pkg.Via[1] != "tailwindcss" {
		t.Fatalf("Via = %#v, want sorted merged roots", pkg.Via)
	}
	wantParents := []domain.PackageParent{
		{Name: "other", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "tailwindcss", Version: "3.4.17", Ecosystem: domain.EcosystemNPM},
	}
	if len(pkg.Parents) != len(wantParents) {
		t.Fatalf("Parents = %#v, want %#v", pkg.Parents, wantParents)
	}
	for i := range wantParents {
		if pkg.Parents[i] != wantParents[i] {
			t.Fatalf("Parents = %#v, want %#v", pkg.Parents, wantParents)
		}
	}
}

func TestPackageCollectionIndexRebuildsAfterDevFilter(t *testing.T) {
	t.Parallel()

	c := &PackageCollection{}
	c.add(domain.Package{Name: "dev-only", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Dev: true}, "package-lock.json", "lockfile")
	c.filterDev()
	c.add(domain.Package{Name: "dev-only", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}, "bom.json", "sbom")

	if len(c.Entries) != 1 || c.Entries[0].Package.Dev {
		t.Fatalf("entries after filter/add = %+v, want one production package", c.Entries)
	}
}

func TestPackageCollectorHelperBranches(t *testing.T) {
	t.Parallel()

	baseErr := errors.New("open failed")
	inputErr := &sbomInputError{err: baseErr}
	if inputErr.Error() != "open failed" {
		t.Fatalf("sbomInputError.Error() = %q", inputErr.Error())
	}
	if !errors.Is(inputErr, baseErr) {
		t.Fatal("sbomInputError should unwrap base error")
	}

	for _, item := range []struct {
		component string
		reason    string
		ordinal   int
		want      string
	}{
		{component: "private-pkg", reason: "", ordinal: 0, want: "skipped SBOM component #1: component could not be imported"},
		{component: "", reason: "missing purl", ordinal: 2, want: "skipped SBOM component #2: missing purl"},
		{component: "", reason: "pkg:npm/@corp/private@1.0.0", ordinal: 3, want: "skipped SBOM component #3: component could not be imported"},
	} {
		got := formatSBOMSkippedComponent("bom.json", item.ordinal, sbom.SkippedComponent{Name: item.component, Reason: item.reason})
		if !strings.Contains(got, item.want) {
			t.Fatalf("formatSBOMSkippedComponent() = %q, want %q", got, item.want)
		}
		if item.component != "" && strings.Contains(got, item.component) {
			t.Fatalf("formatSBOMSkippedComponent() leaked component name %q: %q", item.component, got)
		}
		if strings.Contains(got, "pkg:npm/@corp/private@1.0.0") {
			t.Fatalf("formatSBOMSkippedComponent() leaked raw reason coordinate: %q", got)
		}
	}

	filter := ecosystemFilter([]string{" npm ", "", "Go"})
	if !filter.allows(domain.EcosystemNPM) || !filter.allows(domain.EcosystemGo) {
		t.Fatalf("filter should allow npm and go: %#v", filter)
	}
	if filter.allows(domain.EcosystemPyPI) {
		t.Fatal("filter should reject pypi")
	}
	if !ecosystemFilter(nil).allows(domain.EcosystemPyPI) {
		t.Fatal("empty filter should allow all ecosystems")
	}
	if got := domain.MergePackageStringSet([]string{" b ", "", "a"}, []string{"a", "c"}); strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("MergePackageStringSet() = %#v", got)
	}
	if got := domain.MergePackageStringSet(nil, nil); got != nil {
		t.Fatalf("MergePackageStringSet(nil,nil) = %#v, want nil", got)
	}
}
