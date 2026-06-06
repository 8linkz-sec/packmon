package sbomgen

import (
	"context"
	"os"
	"path/filepath"
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
	joined := strings.Join(got.Args, " ")
	if got.Name != "mvn" || !strings.Contains(joined, "org.cyclonedx:cyclonedx-maven-plugin:"+mavenPluginVersion+":makeAggregateBom") || !strings.Contains(joined, "-DincludeTestScope=true") {
		t.Fatalf("RunOptions = %+v", got)
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
