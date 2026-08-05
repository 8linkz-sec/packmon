package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestYAMLImportsUseMaintainedModulePath(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join("..", "..")
	forbiddenModule := "gopkg.in/" + "yaml.v3"
	maintainedModule := "go.yaml.in/yaml/v3"
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
			t.Fatalf("%s uses archived %s; use %s", rel, forbiddenModule, maintainedModule)
		}
	}

	mod, err := os.ReadFile(filepath.Join(repoRoot, "go.mod")) //nolint:gosec // tracked repository file.
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if !strings.Contains(string(mod), maintainedModule) {
		t.Fatalf("go.mod must require maintained YAML module %s", maintainedModule)
	}
	sum, err := os.ReadFile(filepath.Join(repoRoot, "go.sum")) //nolint:gosec // tracked repository file.
	if err != nil {
		t.Fatalf("read go.sum: %v", err)
	}
	if !strings.Contains(string(sum), maintainedModule+" v3.0.4") {
		t.Fatal("go.sum must include the maintained YAML module checksum")
	}
}
