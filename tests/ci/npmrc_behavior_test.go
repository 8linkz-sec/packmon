package ci

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestTailwindWASMBundledDependenciesAreLocked(t *testing.T) {
	t.Parallel()

	var lockfile struct {
		Packages map[string]struct {
			BundleDependencies []string `json:"bundleDependencies"`
			InBundle           bool     `json:"inBundle"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, "package-lock.json")), &lockfile); err != nil {
		t.Fatalf("parse package-lock.json: %v", err)
	}

	const parent = "node_modules/@tailwindcss/oxide-wasm32-wasi"
	for _, name := range []string{"@emnapi/core", "@emnapi/runtime"} {
		if !slices.Contains(lockfile.Packages[parent].BundleDependencies, name) {
			t.Errorf("%s bundleDependencies does not contain %q", parent, name)
		}

		path := parent + "/node_modules/" + name
		entry, ok := lockfile.Packages[path]
		if !ok {
			t.Errorf("package-lock.json does not contain bundled package entry %q", path)
			continue
		}
		if !entry.InBundle {
			t.Errorf("package-lock.json entry %q does not set inBundle", path)
		}
	}
}

func TestNPMRCEnforcesNodeEngineAndDisablesLifecycleScripts(t *testing.T) {
	t.Parallel()

	t.Run("unsupported node engine is rejected", func(t *testing.T) {
		dir := writeNPMFixture(t, `{
  "name": "engine-fixture",
  "version": "1.0.0",
  "engines": {"node": ">=999.0.0"}
}`)

		output, err := runNPMInstall(t, dir)
		if err == nil {
			t.Fatalf("npm install accepted an unsupported Node engine:\n%s", output)
		}
		if !strings.Contains(output, "EBADENGINE") {
			t.Fatalf("npm install error did not report the engine violation:\n%s", output)
		}
	})

	t.Run("project lifecycle script does not run", func(t *testing.T) {
		dir := writeNPMFixture(t, `{
  "name": "lifecycle-fixture",
  "version": "1.0.0",
  "scripts": {"preinstall": "node -e \"require('fs').writeFileSync('lifecycle-ran', 'yes')\""}
}`)

		output, err := runNPMInstall(t, dir)
		if err != nil {
			t.Fatalf("npm install: %v:\n%s", err, output)
		}
		if _, err := os.Stat(filepath.Join(dir, "lifecycle-ran")); !os.IsNotExist(err) {
			t.Fatalf("npm executed the fixture lifecycle script (stat error = %v)", err)
		}
	})

	t.Run("lifecycle probe runs when config is explicitly overridden", func(t *testing.T) {
		dir := writeNPMFixture(t, `{
  "name": "lifecycle-override-fixture",
  "version": "1.0.0",
  "scripts": {"preinstall": "node -e \"require('fs').writeFileSync('lifecycle-ran', 'yes')\""}
}`)

		output, err := runNPMInstall(t, dir, "--ignore-scripts=false")
		if err != nil {
			t.Fatalf("npm install with ignore-scripts override: %v:\n%s", err, output)
		}
		if _, err := os.Stat(filepath.Join(dir, "lifecycle-ran")); err != nil {
			t.Fatalf("lifecycle probe did not run after ignore-scripts override: %v", err)
		}
	})
}

func writeNPMFixture(t *testing.T, packageJSON string) string {
	t.Helper()

	dir := t.TempDir()
	for name, content := range map[string]string{
		"package.json": packageJSON,
		".npmrc":       readRepoFile(t, ".npmrc"),
		"user.npmrc":   "",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func runNPMInstall(t *testing.T, dir string, extraArgs ...string) (string, error) {
	t.Helper()

	args := []string{"install", "--userconfig", filepath.Join(dir, "user.npmrc")}
	args = append(args, extraArgs...)
	cmd := exec.Command("npm", args...) // #nosec G204 -- fixed npm arguments and t.TempDir paths.
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	return string(output), err
}
