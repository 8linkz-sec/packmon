package sbomgen

import (
	"strings"
	"testing"
)

func TestDefaultRegistryHasAllV1Ecosystems(t *testing.T) {
	reg := DefaultRegistry()
	for _, eco := range []string{"go", "npm", "pypi", "maven"} {
		g, ok := reg[eco]
		if !ok {
			t.Fatalf("registry missing %q", eco)
		}
		if g.Ecosystem() != eco {
			t.Errorf("%q generator reports Ecosystem()=%q", eco, g.Ecosystem())
		}
		if g.Tool() == "" {
			t.Errorf("%q generator has empty Tool()", eco)
		}
	}
}

func TestInstallSpecPinsVersions(t *testing.T) {
	reg := DefaultRegistry()
	cases := map[string]string{
		"npm":  "@cyclonedx/cyclonedx-npm@" + npmGeneratorVersion,
		"pypi": "cyclonedx-bom==" + pypiGeneratorVersion,
		"go":   "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@" + goGeneratorVersion,
	}
	for eco, wantPkg := range cases {
		spec := reg[eco].InstallSpec()
		if !spec.CanAutoInstall {
			t.Errorf("%q should be auto-installable", eco)
		}
		if !strings.Contains(strings.Join(spec.Args, " "), wantPkg) {
			t.Errorf("%q install args %v do not contain pinned %q", eco, spec.Args, wantPkg)
		}
	}
	if reg["maven"].InstallSpec().CanAutoInstall {
		t.Errorf("maven must not be auto-installable")
	}
}
