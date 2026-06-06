package sbomgen

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func detectionKeys(ds []Detection) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Ecosystem+":"+filepath.ToSlash(d.DisplayPath))
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDetectSingleEcosystems(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module x\n\ngo 1.26\n")
	writeFile(t, root, "svc/pom.xml", "<project><dependencies></dependencies></project>")

	got, err := Detect(root, 10)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := []string{"go:go.mod", "maven:svc/pom.xml"}
	if g := detectionKeys(got); !equalStrings(g, want) {
		t.Fatalf("keys = %v, want %v", g, want)
	}
}

func TestDetectSkipsVendorAndNodeModules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"name":"root"}`)
	writeFile(t, root, "node_modules/dep/package.json", `{"name":"dep"}`)
	writeFile(t, root, "vendor/x/go.mod", "module v\n")

	got, err := Detect(root, 10)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if g := detectionKeys(got); !equalStrings(g, []string{"npm:package.json"}) {
		t.Fatalf("keys = %v, want [npm:package.json]", g)
	}
}

func TestDetectNpmWorkspaceSuppressesChild(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"name":"root","workspaces":["packages/*"]}`)
	writeFile(t, root, "packages/a/package.json", `{"name":"a"}`)
	writeFile(t, root, "tools/standalone/package.json", `{"name":"standalone"}`)

	got, err := Detect(root, 10)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := []string{"npm:package.json", "npm:tools/standalone/package.json"}
	if g := detectionKeys(got); !equalStrings(g, want) {
		t.Fatalf("keys = %v, want %v", g, want)
	}
}

func TestDetectSuppressionIsEcosystemScoped(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"name":"root","workspaces":["packages/*"]}`)
	writeFile(t, root, "packages/a/package.json", `{"name":"a"}`)
	writeFile(t, root, "packages/a/go.mod", "module a\n\ngo 1.26\n")

	got, err := Detect(root, 10)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := []string{"go:packages/a/go.mod", "npm:package.json"}
	if g := detectionKeys(got); !equalStrings(g, want) {
		t.Fatalf("keys = %v, want %v", g, want)
	}
}

func TestDetectMavenModulesSuppressChildren(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pom.xml", `<project><modules><module>app</module></modules></project>`)
	writeFile(t, root, "app/pom.xml", `<project><dependencies></dependencies></project>`)
	writeFile(t, root, "standalone/pom.xml", `<project><dependencies></dependencies></project>`)

	got, err := Detect(root, 10)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := []string{"maven:pom.xml", "maven:standalone/pom.xml"}
	if g := detectionKeys(got); !equalStrings(g, want) {
		t.Fatalf("keys = %v, want %v", g, want)
	}
}

func TestDetectOnlyPoetryPyproject(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pyproject.toml", `[build-system]`+"\n")
	writeFile(t, root, "poetry/pyproject.toml", `[tool.poetry]`+"\nname = \"demo\"\n")

	got, err := Detect(root, 10)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if g := detectionKeys(got); !equalStrings(g, []string{"pypi:poetry/pyproject.toml"}) {
		t.Fatalf("keys = %v", g)
	}
}
