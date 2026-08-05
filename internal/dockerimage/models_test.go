package dockerimage

import (
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestImagePackageConvertsToDockerDomainPackage(t *testing.T) {
	ref, ok := ParseRef("postgres:18-alpine")
	if !ok {
		t.Fatal("ParseRef(postgres:18-alpine) failed")
	}
	img := Image{
		Ref:        ref,
		SourceFile: "docker-compose.yml",
		SourceType: SourceCompose,
		Scope:      "runtime",
		Relation:   "compose",
		Direct:     true,
		Flags:      []string{"service=postgres"},
	}

	pkg := img.Package()
	if pkg.Name != "docker.io/library/postgres" || pkg.Version != "18-alpine" || pkg.Ecosystem != domain.EcosystemDocker {
		t.Fatalf("Package() = %#v", pkg)
	}
	if !pkg.Direct || pkg.Indirect || len(pkg.Via) != 0 {
		t.Fatalf("Package provenance = %#v, want direct docker row", pkg)
	}
}
