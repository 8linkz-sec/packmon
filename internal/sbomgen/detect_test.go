package sbomgen

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
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

func symlinkOrSkip(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
}

func detectionKeys(ds []Detection) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, string(d.Ecosystem)+":"+filepath.ToSlash(d.DisplayPath))
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

func TestDetectRejectsSymlinkedManifestOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "package.json", `{"dependencies":{"external":"1.0.0"}}`)
	symlinkOrSkip(t, filepath.Join(outside, "package.json"), filepath.Join(root, "package.json"))

	_, err := Detect(root, 10)
	if err == nil || !strings.Contains(err.Error(), "escapes scan root") {
		t.Fatalf("Detect err = %v, want root escape rejection", err)
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

func TestDetectRejectsNPMWorkspaceOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	writeFile(t, root, "package.json", `{"name":"root","workspaces":["../outside/*"]}`)
	writeFile(t, parent, "outside/pkg/package.json", `{"name":"external"}`)

	_, err := Detect(root, 10)
	if err == nil || !strings.Contains(err.Error(), "escapes scan root") {
		t.Fatalf("Detect err = %v, want workspace root escape rejection", err)
	}
}

func TestDetectSkipsYarnAndPnpmProjectsWithoutNpmLockfile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "yarn-app/package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	writeFile(t, root, "yarn-app/yarn.lock", "# yarn lockfile v1\n")
	writeFile(t, root, "pnpm-app/package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	writeFile(t, root, "pnpm-app/pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	writeFile(t, root, "npm-app/package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	writeFile(t, root, "npm-app/package-lock.json", `{"lockfileVersion":3,"packages":{}}`)

	got, err := Detect(root, 10)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := []string{"npm:npm-app/package.json"}
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

func TestDetectRejectsMavenModuleOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	writeFile(t, root, "pom.xml", `<project><modules><module>../outside</module></modules></project>`)
	writeFile(t, parent, "outside/pom.xml", `<project><dependencies></dependencies></project>`)

	_, err := Detect(root, 10)
	if err == nil || !strings.Contains(err.Error(), "escapes scan root") {
		t.Fatalf("Detect err = %v, want Maven module root escape rejection", err)
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

func TestDetectPythonManifestsMirrorAutoSBOMSupportDescriptors(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "requirements.txt", "Django==5.0.0\n")
	writeFile(t, root, "poetry/pyproject.toml", `[tool.poetry]`+"\nname = \"demo\"\n")
	writeFile(t, root, "plain/pyproject.toml", `[build-system]`+"\n")
	writeFile(t, root, "lock-only/poetry.lock", "[[package]]\nname = \"Django\"\nversion = \"5.0.0\"\n")
	writeFile(t, root, "pipenv/Pipfile", "[packages]\ndjango = \"*\"\n")
	writeFile(t, root, "pipenv/Pipfile.lock", `{"default":{"django":{"version":"==5.0.0"}}}`+"\n")

	got, err := Detect(root, 10)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := []string{"pypi:poetry/pyproject.toml", "pypi:requirements.txt"}
	if g := detectionKeys(got); !slices.Equal(g, want) {
		t.Fatalf("keys = %v, want %v", g, want)
	}
}

func TestDetectRejectsRequirementsIncludeOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	writeFile(t, root, "requirements.txt", "-r ../outside/requirements.txt\n")
	writeFile(t, parent, "outside/requirements.txt", "django==4.2.11\n")

	_, err := Detect(root, 10)
	if err == nil || !strings.Contains(err.Error(), "escapes scan root") {
		t.Fatalf("Detect err = %v, want requirements include root escape rejection", err)
	}
}

func TestDetectReportsInvalidPyprojectTOML(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pyproject.toml", "[tool.poetry\n")

	_, err := Detect(root, 10)
	if err == nil {
		t.Fatalf("Detect should report invalid pyproject TOML")
	}
	if !strings.Contains(err.Error(), "pyproject.toml") || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("Detect err = %v, want parse error with pyproject.toml", err)
	}
}

func TestRunAutoSBOMPoetryLockReadErrorFailsBeforeZeroPackageValidation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pyproject.toml", `[tool.poetry]`+"\nname = \"demo\"\n[tool.poetry.dependencies]\npython = \"^3.12\"\n")
	if err := os.Mkdir(filepath.Join(root, "poetry.lock"), 0o700); err != nil {
		t.Fatalf("mkdir poetry.lock: %v", err)
	}

	runner := func(_ context.Context, opts RunOptions) ([]byte, error) {
		if len(opts.Args) == 1 && opts.Args[0] == "--version" {
			return []byte("cyclonedx-py 7.3.0\n"), nil
		}
		for i, arg := range opts.Args {
			if arg == "--output-file" && i+1 < len(opts.Args) {
				return nil, os.WriteFile(opts.Args[i+1], []byte(validCycloneDXNoPackages()), 0o600)
			}
		}
		return nil, errors.New("missing --output-file")
	}

	_, err := Run(context.Background(), Config{
		Target:   root,
		Registry: map[domain.Ecosystem]Generator{"pypi": pypiGenerator{}},
		LookPath: func(string) (string, error) { return "cyclonedx-py", nil },
		Runner:   runner,
	})
	if err == nil {
		t.Fatalf("Run should fail on unreadable poetry.lock before allowing an empty SBOM")
	}
	if !strings.Contains(err.Error(), "poetry.lock") {
		t.Fatalf("Run err = %v, want poetry.lock read error", err)
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
