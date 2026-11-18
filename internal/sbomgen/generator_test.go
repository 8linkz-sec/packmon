package sbomgen

import (
	"context"
	"os"
	"path/filepath"
	"slices"
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

// The generators Packmon auto-installs are the same tools the bootstrap
// requirements pin; both must name one version so an auto-SBOM run and a
// bootstrapped developer machine generate with the same release.
func TestAutoInstalledGeneratorPinsMatchRequirementsToolPins(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "requirements", "packmon-tools.tsv"))
	if err != nil {
		t.Fatalf("read requirements/packmon-tools.tsv: %v", err)
	}
	rows := map[string][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "|")
		if len(fields) >= 6 && !strings.HasPrefix(fields[0], "#") {
			rows[fields[0]] = fields
		}
	}
	reg := DefaultRegistry()
	for _, tc := range []struct {
		id        string
		eco       domain.Ecosystem
		installer string
	}{
		{id: "cyclonedx-npm", eco: domain.EcosystemNPM, installer: "npm-global:@cyclonedx/cyclonedx-npm@"},
		{id: "cyclonedx-py", eco: domain.EcosystemPyPI, installer: "pip-user:cyclonedx-bom=="},
	} {
		row, ok := rows[tc.id]
		if !ok {
			t.Fatalf("requirements/packmon-tools.tsv has no %s row", tc.id)
		}
		spec := reg[tc.eco].InstallSpec()
		if row[4] != spec.ExpectedVersion || row[5] != tc.installer+spec.ExpectedVersion {
			t.Errorf("%s requirements pin %q (%s) does not match the auto-install pin %q", tc.id, row[4], row[5], spec.ExpectedVersion)
		}
	}
}

// Every generator Packmon drives writes the same CycloneDX spec version, so a
// generator major that moves its default (cyclonedx-npm 7 defaults to 1.7)
// does not change the format of a generated or kept SBOM.
func TestGeneratorsPinTheCycloneDXSpecVersion(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	writeFile(t, root, "requirements.txt", "requests==2.32.3\n")
	writeFile(t, root, "pyproject.toml", "[tool.poetry.dependencies]\nrequests = \"2.32.3\"\n")
	for _, tc := range []struct {
		name string
		gen  Generator
		d    Detection
	}{
		{name: "npm", gen: npmGenerator{}, d: Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root}},
		{name: "pypi requirements", gen: pypiGenerator{}, d: Detection{InputKind: "requirements", ManifestPath: filepath.Join(root, "requirements.txt"), ProjectDir: root}},
		{name: "pypi poetry", gen: pypiGenerator{}, d: Detection{InputKind: "poetry", ManifestPath: filepath.Join(root, "pyproject.toml"), ProjectDir: root}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got RunOptions
			err := tc.gen.Generate(context.Background(), tc.d, filepath.Join(root, "bom.json"), GenerateOptions{}, func(_ context.Context, opts RunOptions) ([]byte, error) {
				got = opts
				return nil, nil
			})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			index := slices.Index(got.Args, "--spec-version")
			if index < 0 || index+1 >= len(got.Args) || got.Args[index+1] != cycloneDXSpecVersion {
				t.Fatalf("%s args = %v, want --spec-version %s", got.Name, got.Args, cycloneDXSpecVersion)
			}
		})
	}
	if cycloneDXSpecVersion != "1.6" {
		t.Fatalf("cycloneDXSpecVersion = %q; moving the generated spec version is a deliberate change", cycloneDXSpecVersion)
	}
}
