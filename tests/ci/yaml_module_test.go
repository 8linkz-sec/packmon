package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

const maintainedYAMLModule = "go.yaml.in/yaml/v3"

func TestYAMLImportsUseMaintainedModulePath(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join("..", "..")
	forbiddenModule := "gopkg.in/" + "yaml.v3"
	cmd := exec.Command("git", "ls-files")
	cmd.Dir = repoRoot
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("list tracked files: %v", err)
	}

	for _, rel := range strings.Fields(string(output)) {
		if !strings.HasSuffix(rel, ".go") && rel != "go.mod" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel))) //nolint:gosec // tracked repository file.
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", rel, err)
		}
		if strings.Contains(string(data), forbiddenModule) {
			t.Fatalf("%s uses archived %s; use %s", rel, forbiddenModule, maintainedYAMLModule)
		}
	}

	mod, err := os.ReadFile(filepath.Join(repoRoot, "go.mod")) //nolint:gosec // tracked repository file.
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	parsed, err := modfile.Parse("go.mod", mod, nil)
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	var selected *modfile.Require
	for _, requirement := range parsed.Require {
		if requirement.Mod.Path == maintainedYAMLModule {
			selected = requirement
			break
		}
	}
	if selected == nil {
		t.Fatalf("go.mod must require maintained YAML module %s", maintainedYAMLModule)
	}
	if selected.Indirect {
		t.Fatalf("go.mod must keep %s as a direct dependency", maintainedYAMLModule)
	}
	if selected.Mod.Version == "" {
		t.Fatalf("go.mod requirement for %s must select a version", maintainedYAMLModule)
	}
}
