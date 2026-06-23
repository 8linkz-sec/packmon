package sbomgen

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
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

func TestDetectSingleEcosystems(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module x\n\ngo 1.26\n")
	writeFile(t, root, "svc/pom.xml", "<project><dependencies></dependencies></project>")

	got, err := Detect(root, 10)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := []string{"go:go.mod", "maven:svc/pom.xml"}
	if g := detectionKeys(got); !slices.Equal(g, want) {
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
	if g := detectionKeys(got); !slices.Equal(g, []string{"npm:package.json"}) {
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
	if g := detectionKeys(got); !slices.Equal(g, want) {
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
	if g := detectionKeys(got); !slices.Equal(g, want) {
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
	if g := detectionKeys(got); !slices.Equal(g, want) {
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
	if g := detectionKeys(got); !slices.Equal(g, []string{"pypi:poetry/pyproject.toml"}) {
		t.Fatalf("keys = %v", g)
	}
}

func TestDetectReportsWalkErrors(t *testing.T) {
	root := t.TempDir()
	originalWalkDir := walkDir
	t.Cleanup(func() { walkDir = originalWalkDir })

	denied := filepath.Join(root, "private")
	walkDir = func(_ string, fn fs.WalkDirFunc) error {
		return fn(denied, fakeDirEntry{name: "private", dir: true}, fs.ErrPermission)
	}

	_, err := Detect(root, 10)
	if err == nil {
		t.Fatalf("Detect should report walk errors")
	}
	if !errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), "private") {
		t.Fatalf("Detect err = %v, want path and permission error", err)
	}
}

func TestDetectRejectsOversizedManifestReads(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", strings.Repeat("x", maxAutoSBOMManifestBytes+1))

	_, err := Detect(root, 10)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum auto-SBOM manifest size") {
		t.Fatalf("Detect err = %v, want manifest size cap", err)
	}
}

type fakeDirEntry struct {
	name string
	dir  bool
}

func (d fakeDirEntry) Name() string               { return d.name }
func (d fakeDirEntry) IsDir() bool                { return d.dir }
func (d fakeDirEntry) Type() fs.FileMode          { return 0 }
func (d fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }
