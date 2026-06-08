package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/parser"
	"github.com/8linkz/packmon/internal/sbom"
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

func TestCollectPackagesReportsSkippedSBOMComponents(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "bom.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{
		"bomFormat":"CycloneDX",
		"components":[
			{"type":"library","name":"django","version":"4.2.11","purl":"pkg:pypi/django@4.2.11"},
			{"type":"library","name":"no-purl","version":"1.0.0"}
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
	if len(got.ParseErrors) != 1 || !strings.Contains(got.ParseErrors[0], `skipped SBOM component "no-purl": missing purl`) {
		t.Fatalf("parse errors = %#v, want skipped component warning", got.ParseErrors)
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
	}, "package-lock.json", "lockfile")
	c.add(domain.Package{
		Name:      "postcss",
		Version:   "8.5.8",
		Ecosystem: domain.EcosystemNPM,
		Direct:    true,
		Optional:  true,
		Via:       []string{"other"},
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
		want      string
	}{
		{component: "pkg", reason: "", want: `skipped SBOM component "pkg"`},
		{component: "", reason: "missing purl", want: "skipped SBOM component: missing purl"},
		{component: "", reason: "", want: "skipped SBOM component"},
	} {
		got := formatSBOMSkippedComponent("bom.json", sbom.SkippedComponent{Name: item.component, Reason: item.reason})
		if !strings.Contains(got, item.want) {
			t.Fatalf("formatSBOMSkippedComponent() = %q, want %q", got, item.want)
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
	if got := mergeCollectedStringSet([]string{" b ", "", "a"}, []string{"a", "c"}); strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("mergeCollectedStringSet() = %#v", got)
	}
	if got := mergeCollectedStringSet(nil, nil); got != nil {
		t.Fatalf("mergeCollectedStringSet(nil,nil) = %#v, want nil", got)
	}
}
