package sbom

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestF327CycloneDXReachableGuardBranches(t *testing.T) {
	t.Parallel()

	if _, err := parseCycloneDX([]byte("{\"bomFormat\":\"CycloneDX\",\"components\":{}}")); err == nil || !strings.Contains(err.Error(), "parse CycloneDX JSON") {
		t.Fatalf("malformed CycloneDX JSON error = %v", err)
	}
	if _, err := parseCycloneDX([]byte("{\"bomFormat\":\"other\"}")); err == nil || err.Error() != "unsupported CycloneDX format" {
		t.Fatalf("unsupported CycloneDX error = %v", err)
	}

	result := importCycloneDXComponents([]cyclonedxComponent{
		{Type: "library", Name: "missing"},
		{Type: "library", Name: "versionless", PURL: "pkg:npm/versionless"},
	})
	if len(result.Packages) != 0 || len(result.Skipped) != 2 {
		t.Fatalf("component import = %#v, want two skipped components", result)
	}
	if result.Skipped[0].Reason != "missing purl" || result.Skipped[1].Reason != "unsupported or versionless purl" {
		t.Fatalf("skip reasons = %#v", result.Skipped)
	}

	tooManyEntries := make([]cyclonedxDependency, maxCycloneDXDependencyEntries+1)
	if err := validateCycloneDXWorkLimits(0, "", tooManyEntries); err == nil || !strings.Contains(err.Error(), "dependency entry count") {
		t.Fatalf("dependency-entry limit error = %v", err)
	}
	if err := validateCycloneDXWorkLimits(0, "root", []cyclonedxDependency{{Ref: "root", DependsOn: []string{"  "}}}); err != nil {
		t.Fatalf("blank dependency edge: %v", err)
	}
}

func TestF327CycloneDXMetadataHelperBoundaries(t *testing.T) {
	t.Parallel()

	packages := []Package{{Package: domain.Package{Name: "root", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}, BOMRef: "root"}}
	markCycloneDXDirectDependencies(packages, map[string]int{"root": 0}, map[string][]string{"root": {"root"}}, "  ")
	if packages[0].Package.Direct {
		t.Fatal("blank root reference must not mark a direct dependency")
	}
	attachCycloneDXPackageParents(packages, map[string]int{"root": 0}, map[string][]string{
		"root": {"root", "missing"},
	})
	if len(packages[0].Package.Parents) != 0 {
		t.Fatalf("self and unknown parent edges produced parents: %#v", packages[0].Package.Parents)
	}

	rootPackages := []Package{
		{Package: domain.Package{Name: "", Version: "1.0.0"}},
		{Package: domain.Package{Name: "usable", Version: "1.0.0"}},
	}
	roots := cycloneDXDirectViaRoots(rootPackages, map[string]int{"blank": 0, "usable": 1}, []string{"missing", "blank", "usable", " usable "})
	if len(roots) != 1 || roots[0] != (cycloneDXViaRoot{name: "usable", directRef: "usable"}) {
		t.Fatalf("direct via roots = %#v", roots)
	}

	via := make(map[string]map[cycloneDXViaRoot]struct{})
	if changed, err := addCycloneDXViaRoot(via, " ", cycloneDXViaRoot{name: "root", directRef: "root"}, nil); err != nil || changed {
		t.Fatalf("blank via target = (%v, %v)", changed, err)
	}
	exhausted := &cycloneDXViaBudget{states: maxCycloneDXViaStates}
	if changed, err := addCycloneDXViaRoot(via, "child", cycloneDXViaRoot{name: "root", directRef: "root"}, exhausted); err == nil || changed {
		t.Fatalf("exhausted via budget = (%v, %v)", changed, err)
	}
	if changed, err := mergeCycloneDXViaRoots(via, "other", map[cycloneDXViaRoot]struct{}{{name: "root", directRef: "root"}: {}}, exhausted); err == nil || changed {
		t.Fatalf("exhausted merge budget = (%v, %v)", changed, err)
	}
	if !cycloneDXViaRootLess(cycloneDXViaRoot{name: "same", directRef: "a"}, cycloneDXViaRoot{name: "same", directRef: "b"}) {
		t.Fatal("equal-name via roots must sort by direct reference")
	}
}

func TestF330SPDXParserReachableErrors(t *testing.T) {
	t.Parallel()

	if _, err := parseSPDXJSON([]byte("{\"spdxVersion\":\"other\"}")); err == nil || err.Error() != "unsupported SPDX JSON format" {
		t.Fatalf("unsupported SPDX error = %v", err)
	}
	if _, err := parseSPDXJSON([]byte("{\"spdxVersion\":\"SPDX-2.3\",\"packages\":{}}")); err == nil || !strings.Contains(err.Error(), "parse SPDX JSON") {
		t.Fatalf("malformed SPDX packages error = %v", err)
	}
}
