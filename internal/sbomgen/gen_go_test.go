package sbomgen

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoGeneratorGenerateArgs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.test\n\ngo 1.26\n")
	d := Detection{ProjectDir: root, ManifestPath: filepath.Join(root, "go.mod")}
	var got RunOptions
	err := (goGenerator{}).Generate(context.Background(), d, filepath.Join(root, "bom.json"), GenerateOptions{IncludeDev: true}, func(_ context.Context, opts RunOptions) ([]byte, error) {
		got = opts
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	joined := strings.Join(got.Args, " ")
	if got.Name != "cyclonedx-gomod" || !strings.Contains(joined, "mod") || !strings.Contains(joined, "-json") || !strings.Contains(joined, "-test") || !strings.Contains(joined, root) {
		t.Fatalf("RunOptions = %+v", got)
	}
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
