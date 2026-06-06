package sbomgen

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestNpmGeneratorGenerateArgsOmitDevByDefault(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	d := Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root}
	var got RunOptions
	err := (npmGenerator{}).Generate(context.Background(), d, filepath.Join(root, "bom.json"), GenerateOptions{}, func(_ context.Context, opts RunOptions) ([]byte, error) {
		got = opts
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	joined := strings.Join(got.Args, " ")
	if got.Name != "cyclonedx-npm" || !strings.Contains(joined, "--omit dev") || !strings.Contains(joined, d.ManifestPath) {
		t.Fatalf("RunOptions = %+v", got)
	}
}

func TestNpmGeneratorGenerateArgsIncludeDevDoesNotOmitDev(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"devDependencies":{"vitest":"1.0.0"}}`)
	d := Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root}
	var got RunOptions
	err := (npmGenerator{}).Generate(context.Background(), d, filepath.Join(root, "bom.json"), GenerateOptions{IncludeDev: true}, func(_ context.Context, opts RunOptions) ([]byte, error) {
		got = opts
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(strings.Join(got.Args, " "), "--omit dev") {
		t.Fatalf("include-dev args unexpectedly omit dev: %+v", got)
	}
}

func TestNpmGeneratorDeclaresWorkspaceChildDependencies(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"workspaces":{"packages":["packages/*"]}}`)
	writeFile(t, root, "packages/a/package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	declares, err := (npmGenerator{}).DeclaresDependencies(Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root}, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies: %v", err)
	}
	if !declares {
		t.Fatalf("workspace child dependency should count")
	}
}

func TestNpmGeneratorDeclaresDevOnlyOnlyWhenIncluded(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"devDependencies":{"vitest":"1.0.0"}}`)
	d := Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root}
	declares, err := (npmGenerator{}).DeclaresDependencies(d, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies without dev: %v", err)
	}
	if declares {
		t.Fatalf("dev-only package should not declare scanned dependencies when IncludeDev=false")
	}
	declares, err = (npmGenerator{}).DeclaresDependencies(d, GenerateOptions{IncludeDev: true})
	if err != nil {
		t.Fatalf("DeclaresDependencies with dev: %v", err)
	}
	if !declares {
		t.Fatalf("dev-only package should declare dependencies when IncludeDev=true")
	}
}
