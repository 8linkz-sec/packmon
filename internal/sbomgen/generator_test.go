package sbomgen

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestDefaultRegistryHasAllV1Ecosystems(t *testing.T) {
	reg := DefaultRegistry()
	for _, eco := range []domain.Ecosystem{
		domain.EcosystemGo,
		domain.EcosystemNPM,
		domain.EcosystemPyPI,
		domain.EcosystemMaven,
	} {
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
	cases := map[domain.Ecosystem]string{
		domain.EcosystemNPM:  "@cyclonedx/cyclonedx-npm@" + npmGeneratorVersion,
		domain.EcosystemPyPI: "cyclonedx-bom==" + pypiGeneratorVersion,
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
	if reg[domain.EcosystemMaven].InstallSpec().CanAutoInstall {
		t.Errorf("maven must not be auto-installable")
	}
	if reg[domain.EcosystemGo].InstallSpec().CanAutoInstall {
		t.Errorf("go must use the local Go toolchain and not be auto-installable")
	}
}
