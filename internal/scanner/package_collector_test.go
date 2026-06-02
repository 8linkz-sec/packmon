package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/parser"
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
