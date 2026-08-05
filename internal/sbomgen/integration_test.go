package sbomgen

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGoGeneratorRealToolSmoke(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not installed")
	}
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.test\n\ngo 1.21\n\nrequire example.test/dep v0.0.0\n\nreplace example.test/dep => ./dep\n")
	writeFile(t, root, "dep/go.mod", "module example.test/dep\n\ngo 1.21\n")
	out := filepath.Join(t.TempDir(), "bom.json")
	d := Detection{ProjectDir: root, ManifestPath: filepath.Join(root, "go.mod"), InputKind: "go.mod"}
	err := (goGenerator{}).Generate(context.Background(), d, out, GenerateOptions{}, defaultRunner)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	packages, _, err := validateGeneratedSBOM(out)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if packages == 0 {
		t.Fatalf("expected generated SBOM to import packages")
	}
	if err := os.Remove(out); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove: %v", err)
	}
}
