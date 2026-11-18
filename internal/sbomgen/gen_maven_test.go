package sbomgen

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMavenGeneratorGenerateCopiesStagedBOM(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pom.xml", `<project><dependencies></dependencies></project>`)
	outPath := filepath.Join(root, "bom.json")
	d := Detection{ManifestPath: filepath.Join(root, "pom.xml"), ProjectDir: root}
	var got RunOptions
	err := (mavenGenerator{}).Generate(context.Background(), d, outPath, GenerateOptions{IncludeDev: true}, func(_ context.Context, opts RunOptions) ([]byte, error) {
		got = opts
		var outDir string
		for _, arg := range opts.Args {
			if strings.HasPrefix(arg, "-DoutputDirectory=") {
				outDir = strings.TrimPrefix(arg, "-DoutputDirectory=")
			}
		}
		if outDir == "" {
			t.Fatalf("missing output directory in args: %+v", opts)
		}
		if err := os.MkdirAll(outDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outDir, "bom.json"), []byte(validCycloneDXWithPackage()), 0o600); err != nil {
			t.Fatal(err)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// The plugin release is spelled out: the pin is the latest release, and a
	// bump is a deliberate edit here as for the npm and PyPI generator pins.
	if got.Name != "mvn" || !slices.Contains(got.Args, "org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom") || !slices.Contains(got.Args, "-DincludeTestScope=true") {
		t.Fatalf("RunOptions = %+v", got)
	}
	// Like the npm and PyPI generators, Maven gets the spec version explicitly
	// so a plugin release that moves its default cannot change the format.
	if !slices.Contains(got.Args, "-DschemaVersion="+cycloneDXSpecVersion) {
		t.Fatalf("mvn args = %v, want -DschemaVersion=%s", got.Args, cycloneDXSpecVersion)
	}
	// #nosec G304 -- test reads the generated output path it passed to the generator.
	if data, err := os.ReadFile(outPath); err != nil || !strings.Contains(string(data), "CycloneDX") {
		t.Fatalf("copied BOM = %q, %v", data, err)
	}
}

func TestMavenGeneratorDeclaresDirectAndModuleDependencies(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pom.xml", `<project><modules><module>app</module></modules></project>`)
	writeFile(t, root, "app/pom.xml", `<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency></dependencies></project>`)
	declares, err := (mavenGenerator{}).DeclaresDependencies(Detection{ManifestPath: filepath.Join(root, "pom.xml"), ProjectDir: root}, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies: %v", err)
	}
	if !declares {
		t.Fatalf("module dependency should count")
	}
}
