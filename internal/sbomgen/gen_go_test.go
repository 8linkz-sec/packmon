package sbomgen

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/sbom"
)

func TestGoGeneratorGenerateUsesNativeGoList(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.test\n\ngo 1.26\n\nrequire golang.org/x/text v0.3.7\n")
	d := Detection{ProjectDir: root, ManifestPath: filepath.Join(root, "go.mod")}
	var got RunOptions
	outPath := filepath.Join(root, "bom.json")
	err := (goGenerator{}).Generate(context.Background(), d, outPath, GenerateOptions{IncludeDev: true}, func(_ context.Context, opts RunOptions) ([]byte, error) {
		got = opts
		return []byte(strings.Join([]string{
			`{"Path":"example.test","Main":true}`,
			`{"Path":"golang.org/x/text","Version":"v0.3.7","Indirect":false}`,
			`{"Path":"golang.org/x/sys","Version":"v0.1.0","Indirect":true}`,
		}, "\n")), nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	joined := strings.Join(got.Args, " ")
	if got.Name != "go" || got.Dir != root || !strings.Contains(joined, "list") || !strings.Contains(joined, "-mod=readonly") || !strings.Contains(joined, "-m") || !strings.Contains(joined, "-json") || !strings.Contains(joined, "all") {
		t.Fatalf("RunOptions = %+v", got)
	}
	if !containsString(got.Env, "GOWORK=off") {
		t.Fatalf("RunOptions.Env = %v, want GOWORK=off", got.Env)
	}

	file, err := os.Open(outPath) // #nosec G304 -- test opens the SBOM path generated in its own temp directory.
	if err != nil {
		t.Fatalf("open generated SBOM: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close generated SBOM: %v", err)
		}
	}()
	parsed, err := sbom.Parse(file)
	if err != nil {
		t.Fatalf("parse generated SBOM: %v", err)
	}
	if len(parsed.Packages) != 2 {
		t.Fatalf("packages = %d, want 2", len(parsed.Packages))
	}
	if parsed.Packages[0].Package.Name != "golang.org/x/text" || parsed.Packages[0].Package.Version != "v0.3.7" {
		t.Fatalf("first package = %+v", parsed.Packages[0].Package)
	}
}

func TestGoListCycloneDXUsesVersionedModuleReplacementIdentity(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "bom.json")
	data := []byte(strings.Join([]string{
		`{"Path":"example.test/app","Main":true}`,
		`{"Path":"example.test/original","Version":"v1.0.0","Replace":{"Path":"example.test/fork","Version":"v1.2.3"}}`,
	}, "\n"))
	if err := writeGoListCycloneDX(outPath, data); err != nil {
		t.Fatalf("writeGoListCycloneDX: %v", err)
	}

	bom := readGoCycloneDXBOM(t, outPath)
	if len(bom.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(bom.Components))
	}
	component := bom.Components[0]
	if component.Name != "example.test/fork" || component.Version != "v1.2.3" {
		t.Fatalf("component identity = %s@%s, want replacement example.test/fork@v1.2.3", component.Name, component.Version)
	}
	if component.PURL != "pkg:golang/example.test/fork@v1.2.3" {
		t.Fatalf("component PURL = %q", component.PURL)
	}
	if got := propertyValue(component.Properties, "packmon:go:original_path"); got != "example.test/original" {
		t.Fatalf("original_path property = %q", got)
	}
	if got := propertyValue(component.Properties, "packmon:go:original_version"); got != "v1.0.0" {
		t.Fatalf("original_version property = %q", got)
	}
}

func TestGoListCycloneDXRecordsLocalModuleReplacement(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "bom.json")
	data := []byte(strings.Join([]string{
		`{"Path":"example.test/app","Main":true}`,
		`{"Path":"example.test/dep","Version":"v0.0.0","Replace":{"Path":"./dep"}}`,
	}, "\n"))
	if err := writeGoListCycloneDX(outPath, data); err != nil {
		t.Fatalf("writeGoListCycloneDX: %v", err)
	}

	bom := readGoCycloneDXBOM(t, outPath)
	if len(bom.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(bom.Components))
	}
	component := bom.Components[0]
	if component.Name != "example.test/dep" || component.Version != "v0.0.0" {
		t.Fatalf("component identity = %s@%s, want original identity for local replacement", component.Name, component.Version)
	}
	if got := propertyValue(component.Properties, "packmon:go:replace_path"); got != "./dep" {
		t.Fatalf("replace_path property = %q", got)
	}
	if got := propertyValue(component.Properties, "packmon:go:replacement_kind"); got != "local" {
		t.Fatalf("replacement_kind property = %q", got)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestGoGeneratorDeclaresDependencies(t *testing.T) {
	root := t.TempDir()
	mod := "module example.test\n\ngo 1.26\n\nrequire golang.org/x/text v0.3.7\n"
	writeFile(t, root, "go.mod", mod)
	declares, err := (goGenerator{}).DeclaresDependencies(Detection{ManifestPath: filepath.Join(root, "go.mod")}, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies: %v", err)
	}
	if !declares {
		t.Fatalf("go.mod require should declare dependencies")
	}
}

func readGoCycloneDXBOM(t *testing.T, path string) goCycloneDXBOM {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test reads generated SBOM from t.TempDir.
	if err != nil {
		t.Fatalf("read generated BOM: %v", err)
	}
	var bom goCycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("unmarshal generated BOM: %v", err)
	}
	return bom
}

func propertyValue(properties []goCycloneDXProperty, name string) string {
	for _, property := range properties {
		if property.Name == name {
			return property.Value
		}
	}
	return ""
}
