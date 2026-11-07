package sbomgen

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestDetectHelperFallbacksStayBounded(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	bounds, err := newScanRootBounds(root)
	if err != nil {
		t.Fatalf("newScanRootBounds() error = %v", err)
	}
	if detection, ok, err := classifyManifest(bounds, filepath.Join(root, "unknown.manifest")); err != nil || ok || detection != (Detection{}) {
		t.Fatalf("classifyManifest(unknown) = %+v, %t, %v", detection, ok, err)
	}

	missingRoot := filepath.Join(root, "missing-root")
	if _, err := npmHasUnsupportedLockfileScoped(missingRoot, root); err == nil {
		t.Fatal("npmHasUnsupportedLockfileScoped(missing root) error = nil")
	}
	if _, err := parsePoetryProject(root, filepath.Join(root, "missing.toml"), true); err == nil {
		t.Fatal("parsePoetryProject(missing) error = nil")
	}
	writeFile(t, root, "poetry.lock", "[[package]]\nname='demo'\n")
	if err := checkPoetryLockReadable(root, root); err != nil {
		t.Fatalf("checkPoetryLockReadable(existing) error = %v", err)
	}

	writeFile(t, root, "package.json", `{"workspaces":["  ","packages/*"]}`)
	if err := os.MkdirAll(filepath.Join(root, "packages", "one"), 0o750); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	children, err := npmWorkspaceChildren(Detection{
		ScanRoot: root, ProjectDir: root, ManifestPath: filepath.Join(root, "package.json"),
	})
	if err != nil || len(children) != 1 || filepath.Base(children[0]) != "one" {
		t.Fatalf("npmWorkspaceChildren() = %v, %v; want packages/one only", children, err)
	}

	writeFile(t, root, "malformed/pom.xml", "<project><modules>")
	children, err = mavenModulesWalk(root, filepath.Join(root, "malformed"), map[string]struct{}{})
	if err != nil || children != nil {
		t.Fatalf("mavenModulesWalk(malformed) = %v, %v; want nil, nil", children, err)
	}
	writeFile(t, root, "blank/pom.xml", `<project><modules><module> </module></modules></project>`)
	children, err = mavenModulesWalk(root, filepath.Join(root, "blank"), map[string]struct{}{})
	if err != nil || len(children) != 0 {
		t.Fatalf("mavenModulesWalk(blank module) = %v, %v", children, err)
	}
	writeFile(t, root, "missing-child/pom.xml", `<project><modules><module>child</module></modules></project>`)
	children, err = mavenModulesWalk(root, filepath.Join(root, "missing-child"), map[string]struct{}{})
	if err == nil || len(children) != 0 {
		t.Fatalf("mavenModulesWalk(missing child) = %v, %v; want read error", children, err)
	}
}

func TestGoGeneratorRejectsMalformedAndAmbiguousModuleLists(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "bad.mod", "module example.test/root\nunknown-directive value\n")
	if _, err := (goGenerator{}).DeclaresDependencies(Detection{
		ScanRoot: root, ManifestPath: filepath.Join(root, "bad.mod"),
	}, GenerateOptions{}); err == nil {
		t.Fatal("DeclaresDependencies(invalid go.mod) error = nil")
	}
	if _, err := parseGoListModules(nil); err == nil || !strings.Contains(err.Error(), "no modules") {
		t.Fatalf("parseGoListModules(empty) error = %v", err)
	}
	if err := writeGoListCycloneDX(filepath.Join(root, "bad.json"), []byte(`{"Path":`)); err == nil || !strings.Contains(err.Error(), "parse go list") {
		t.Fatalf("writeGoListCycloneDX(malformed) error = %v", err)
	}
	if err := writeGoListCycloneDX(filepath.Join(root, "empty-root.json"), []byte(`{"Path":"","Main":true}`)); err == nil || !strings.Contains(err.Error(), "main module path is empty") {
		t.Fatalf("writeGoListCycloneDX(empty root) error = %v", err)
	}
	valid := []byte("{\"Path\":\"example.test/root\",\"Main\":true}\n{\"Path\":\"example.test/dep\",\"Version\":\"v1.0.0\"}\n")
	if err := writeGoListCycloneDX(filepath.Join(root, "missing", "bom.json"), valid); err == nil || !strings.Contains(err.Error(), "write Go CycloneDX") {
		t.Fatalf("writeGoListCycloneDX(unwritable target) error = %v", err)
	}

	bom, err := buildGoListCycloneDX([]goListModule{
		{Path: "example.test/root", Main: true},
		{Path: "", Version: "v1.0.0"},
		{Path: "example.test/dep", Version: "v1.0.0"},
		{Path: "example.test/dep", Version: "v1.0.0"},
	})
	if err != nil {
		t.Fatalf("buildGoListCycloneDX() error = %v", err)
	}
	if len(bom.Components) != 1 || bom.Components[0].Name != "example.test/dep" {
		t.Fatalf("buildGoListCycloneDX() components = %+v; want one de-duplicated dependency", bom.Components)
	}
	path, version, properties := goModuleCycloneDXIdentity(goListModule{
		Path: "example.test/original", Version: "v1.2.3", Replace: &struct {
			Path    string `json:"Path"`
			Version string `json:"Version"`
		}{},
	})
	if path != "example.test/original" || version != "v1.2.3" || properties != nil {
		t.Fatalf("goModuleCycloneDXIdentity(empty replacement) = %q, %q, %+v", path, version, properties)
	}
}

func TestMavenDependencyWalkValidatesModulesAndScopes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "pom.xml", `<project>
		<dependencies>
			<dependency><groupId></groupId><artifactId>invalid</artifactId></dependency>
			<dependency><groupId>test.group</groupId><artifactId>test-only</artifactId><scope>test</scope></dependency>
		</dependencies>
		<modules><module> </module><module>child</module></modules>
	</project>`)
	writeFile(t, root, "child/pom.xml", `<project><dependencies><dependency><groupId>prod.group</groupId><artifactId>prod</artifactId></dependency></dependencies></project>`)
	declares, err := mavenProjectDeclaresDependencies(root, root, GenerateOptions{}, map[string]struct{}{})
	if err != nil || !declares {
		t.Fatalf("mavenProjectDeclaresDependencies(scoped child) = %t, %v; want true", declares, err)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("filepath.Abs() error = %v", err)
	}
	declares, err = mavenProjectDeclaresDependencies(root, root, GenerateOptions{}, map[string]struct{}{absRoot: {}})
	if err != nil || declares {
		t.Fatalf("mavenProjectDeclaresDependencies(visited) = %t, %v; want false", declares, err)
	}
	if _, err := mavenProjectDeclaresDependencies(root, filepath.Join(root, "missing"), GenerateOptions{}, map[string]struct{}{}); err == nil {
		t.Fatal("mavenProjectDeclaresDependencies(missing) error = nil")
	}

	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	writeFile(t, repo, "pom.xml", `<project><modules><module>../outside</module></modules></project>`)
	writeFile(t, parent, "outside/pom.xml", `<project/>`)
	if _, err := mavenProjectDeclaresDependencies(repo, repo, GenerateOptions{}, map[string]struct{}{}); !errors.Is(err, errScanRootEscape) {
		t.Fatalf("mavenProjectDeclaresDependencies(escape) error = %v, want scan-root sentinel", err)
	}
}

func TestMavenGeneratorReportsStagingAndDestinationFailures(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pom.xml", `<project/>`)
	detection := Detection{ScanRoot: root, ProjectDir: root, ManifestPath: filepath.Join(root, "pom.xml")}
	runner := func(_ context.Context, opts RunOptions) ([]byte, error) {
		for _, arg := range opts.Args {
			if dir, ok := strings.CutPrefix(arg, "-DoutputDirectory="); ok {
				if err := os.WriteFile(filepath.Join(dir, "bom.json"), []byte(validCycloneDXNoPackages()), 0o600); err != nil {
					return nil, err
				}
			}
		}
		return nil, nil
	}
	if err := (mavenGenerator{}).Generate(context.Background(), detection, filepath.Join(root, "missing", "bom.json"), GenerateOptions{}, runner); err == nil || !strings.Contains(err.Error(), "write Maven SBOM") {
		t.Fatalf("Maven Generate(unwritable destination) error = %v", err)
	}

	notDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed invalid temp root: %v", err)
	}
	t.Setenv("TMPDIR", notDir)
	t.Setenv("TMP", notDir)
	t.Setenv("TEMP", notDir)
	if err := (mavenGenerator{}).Generate(context.Background(), detection, filepath.Join(root, "bom.json"), GenerateOptions{}, runner); err == nil || !strings.Contains(err.Error(), "staging dir") {
		t.Fatalf("Maven Generate(invalid temp root) error = %v", err)
	}
}

func TestNPMGeneratorLockfileAndWorkspaceFallbacks(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "package.json", `{"workspaces":["packages/*"]}`)
	if err := os.MkdirAll(filepath.Join(root, "packages", "missing-manifest"), 0o750); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	detection := Detection{ScanRoot: root, ProjectDir: root, ManifestPath: filepath.Join(root, "package.json")}
	declares, err := (npmGenerator{}).DeclaresDependencies(detection, GenerateOptions{})
	if err != nil || declares {
		t.Fatalf("DeclaresDependencies(workspace without package.json) = %t, %v; want false", declares, err)
	}
	if _, err := packageJSONDeclaresDependenciesScoped(root, filepath.Join(root, "missing.json"), GenerateOptions{}); err == nil {
		t.Fatal("packageJSONDeclaresDependenciesScoped(missing) error = nil")
	}

	writeFile(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{}}`)
	data, err := readNpmLockfile(Detection{ProjectDir: root})
	if err != nil || !strings.Contains(string(data), "lockfileVersion") {
		t.Fatalf("readNpmLockfile(unscoped) = %q, %v", data, err)
	}
	if err := os.Remove(filepath.Join(root, "package-lock.json")); err != nil {
		t.Fatalf("remove lockfile: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "package-lock.json"), 0o750); err != nil {
		t.Fatalf("create lockfile directory: %v", err)
	}
	if _, err := readNpmLockfile(Detection{ProjectDir: root}); err == nil || !strings.Contains(err.Error(), "no npm lockfile") {
		t.Fatalf("readNpmLockfile(no file) error = %v", err)
	}
	if _, err := npmLockfileOptionalPackages(Detection{ProjectDir: t.TempDir()}); err == nil {
		t.Fatal("npmLockfileOptionalPackages(no lockfile) error = nil")
	}
	if problems, ok := toleratedNpmLSProblems(detection, []byte("npm error code ELSPROBLEMS\nno parsable problem\n")); ok || problems != nil {
		t.Fatalf("toleratedNpmLSProblems(no matches) = %v, %t", problems, ok)
	}
	if _, err := npmHasLockfileScoped(filepath.Join(root, "missing-root"), root); err == nil {
		t.Fatal("npmHasLockfileScoped(missing root) error = nil")
	}
	if err := (npmGenerator{}).Generate(context.Background(), Detection{
		ScanRoot: filepath.Join(root, "missing-root"), ProjectDir: root, ManifestPath: filepath.Join(root, "package.json"),
	}, filepath.Join(root, "bom.json"), GenerateOptions{}, func(context.Context, RunOptions) ([]byte, error) {
		t.Fatal("runner called after lockfile scope failure")
		return nil, nil
	}); err == nil {
		t.Fatal("npm Generate(missing scan root) error = nil")
	}
}

func TestPyPIDependencyFallbacksAndCycles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	requirements := filepath.Join(root, "requirements.txt")
	writeFile(t, root, "requirements.txt", "Django==5.0 # pinned\n")
	declares, err := requirementsDeclareDependencies(requirements)
	if err != nil || !declares {
		t.Fatalf("requirementsDeclareDependencies(inline comment) = %t, %v", declares, err)
	}
	writeFile(t, root, "requirements.txt", "-r missing.txt\n")
	declares, err = requirementsDeclareDependencies(requirements)
	if err != nil || !declares {
		t.Fatalf("requirementsDeclareDependencies(missing include) = %t, %v; want conservative true", declares, err)
	}
	writeFile(t, root, "a.txt", "-r b.txt\n")
	writeFile(t, root, "b.txt", "-r a.txt\n")
	declares, err = requirementsDeclareDependencies(filepath.Join(root, "a.txt"))
	if err != nil || declares {
		t.Fatalf("requirementsDeclareDependencies(cycle) = %t, %v; want false", declares, err)
	}
	writeFile(t, root, "oversized-line.txt", strings.Repeat("x", 70<<10))
	if _, err := requirementsDeclareDependencies(filepath.Join(root, "oversized-line.txt")); err == nil {
		t.Fatal("requirementsDeclareDependencies(oversized scanner token) error = nil")
	}

	detection := Detection{InputKind: "requirements", ManifestPath: requirements, ProjectDir: root}
	err = (pypiGenerator{}).Generate(context.Background(), detection, filepath.Join(root, "bom.json"), GenerateOptions{}, func(context.Context, RunOptions) ([]byte, error) {
		return []byte("generator diagnostic"), errors.New("exit 2")
	})
	if err == nil || !strings.Contains(err.Error(), "generator diagnostic") {
		t.Fatalf("PyPI Generate(runner failure) error = %v", err)
	}

	poetryPath := filepath.Join(root, "pyproject.toml")
	writeFile(t, root, "pyproject.toml", "[tool.poetry.dependencies]\npython='^3.12'\nDjango='^5'\n")
	declares, err = poetryDeclaresDependencies(Detection{ScanRoot: root, ProjectDir: root, ManifestPath: poetryPath}, GenerateOptions{})
	if err != nil || !declares {
		t.Fatalf("poetryDeclaresDependencies(runtime) = %t, %v", declares, err)
	}
	writeFile(t, root, "pyproject.toml", "[tool.poetry.dev-dependencies]\npytest='^8'\n")
	declares, err = poetryDeclaresDependencies(Detection{ScanRoot: root, ProjectDir: root, ManifestPath: poetryPath}, GenerateOptions{IncludeDev: true})
	if err != nil || !declares {
		t.Fatalf("poetryDeclaresDependencies(legacy dev) = %t, %v", declares, err)
	}
	writeFile(t, root, "pyproject.toml", "[tool.poetry\n")
	if _, err := poetryDeclaresDependencies(Detection{ScanRoot: root, ProjectDir: root, ManifestPath: poetryPath}, GenerateOptions{}); err == nil {
		t.Fatal("poetryDeclaresDependencies(invalid TOML) error = nil")
	}
	if _, err := poetryDeclaresDependencies(Detection{ScanRoot: root, ProjectDir: root, ManifestPath: filepath.Join(root, "missing.toml")}, GenerateOptions{}); err == nil {
		t.Fatal("poetryDeclaresDependencies(missing manifest) error = nil")
	}
	lock := []byte("[[package]]\nname='   '\ncategory='main'\n[[package]]\nname='Django'\ncategory='main'\n")
	if !poetryLockDeclaresDependencies(lock, false) {
		t.Fatal("poetryLockDeclaresDependencies skipped valid package after blank name")
	}
}

func TestReadOpenedFileLimitedReportsClosedHandle(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "manifest")
	writeFile(t, filepath.Dir(path), filepath.Base(path), "content")
	file, err := os.Open(path) //nolint:gosec // Test-owned path.
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	if _, err := readOpenedFileLimited(file, path, 100, "manifest"); err == nil {
		t.Fatal("readOpenedFileLimited(closed file) error = nil")
	}
}

func TestManifestSupportRejectsMalformedRows(t *testing.T) {
	t.Parallel()

	for name, data := range map[string]string{
		"field count": "package.json|detect|npm",
		"ecosystem":   "package.json|detect|unsupported|npm-package|req",
		"empty name":  " |detect|npm|npm-package|req",
	} {
		t.Run(name, func(t *testing.T) {
			if descriptors, err := parseAutoSBOMManifestDescriptors(data); err == nil || descriptors != nil {
				t.Fatalf("parseAutoSBOMManifestDescriptors(%s) = %+v, %v", name, descriptors, err)
			}
		})
	}
	if ecosystem, err := parseAutoSBOMManifestEcosystem("unknown"); err == nil || ecosystem != "" {
		t.Fatalf("parseAutoSBOMManifestEcosystem(unknown) = %q, %v", ecosystem, err)
	}
	if descriptor, ok := autoSBOMDetectManifestDescriptor("not-supported.lock"); ok || descriptor.Name != "" || descriptor.Kind != "" || descriptor.Ecosystem != "" || descriptor.InputKind != "" || descriptor.RequirementIDs != nil {
		t.Fatalf("autoSBOMDetectManifestDescriptor(missing) = %+v, %t", descriptor, ok)
	}
}

// TestScopedReadFailureBoundaries covers every deterministic scoped-read error.
// The remaining path_scope.go blocks require filepath.Abs/Rel to fail after the
// same paths already passed an absolute bounds check, a file to disappear
// between requireExisting and Root.Open, or a supported filesystem symlink.
// Those are structural races/platform capabilities, not stable unit-test seams.
func TestScopedReadFailureBoundaries(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	inside := filepath.Join(root, "inside.json")
	writeFile(t, root, "inside.json", "{}")
	if _, err := readFileLimitedScoped(filepath.Join(root, "missing-root"), inside, 100, "manifest"); err == nil {
		t.Fatal("readFileLimitedScoped(missing root) error = nil")
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	writeFile(t, filepath.Dir(outside), filepath.Base(outside), "{}")
	if _, err := readFileLimitedScoped(root, outside, 100, "manifest"); !errors.Is(err, errScanRootEscape) {
		t.Fatalf("readFileLimitedScoped(outside) error = %v, want scan-root sentinel", err)
	}

	rootFile := filepath.Join(t.TempDir(), "root-file")
	writeFile(t, filepath.Dir(rootFile), filepath.Base(rootFile), "{}")
	if _, err := readFileLimitedScoped(rootFile, rootFile, 100, "manifest"); err == nil {
		t.Fatal("readFileLimitedScoped(file as root) error = nil")
	}

	if runtime.GOOS == "windows" && pathWithinRoot(`C:\repo`, `D:\elsewhere\file`) {
		t.Fatal("pathWithinRoot accepted a path on another Windows volume")
	}

	link := filepath.Join(root, "outside-link.json")
	if err := os.Symlink(outside, link); err == nil {
		bounds, err := newScanRootBounds(root)
		if err != nil {
			t.Fatalf("newScanRootBounds() error = %v", err)
		}
		if err := bounds.requireExisting(link); !errors.Is(err, errScanRootEscape) {
			t.Fatalf("requireExisting(outside symlink) error = %v, want scan-root sentinel", err)
		}
	}
}

func TestRunHelperErrorAndInstallContracts(t *testing.T) {
	ctx := context.Background()
	detection := Detection{Ecosystem: domain.EcosystemNPM, DisplayPath: "package.json"}
	if _, err := reserveUniqueOutputPath(filepath.Join(t.TempDir(), "missing"), detection, map[string]int{}, ""); err == nil {
		t.Fatal("reserveUniqueOutputPath(missing parent) error = nil")
	}

	collisionDir := t.TempDir()
	for i := 1; i <= 1000; i++ {
		name := "package.cdx.json"
		if i > 1 {
			name = "package-" + strconv.Itoa(i) + ".cdx.json"
		}
		writeFile(t, collisionDir, name, "occupied")
	}
	if _, err := reserveUniqueOutputPath(collisionDir, detection, map[string]int{}, ""); err == nil || !strings.Contains(err.Error(), "too many filename collisions") {
		t.Fatalf("reserveUniqueOutputPath(collisions) error = %v", err)
	}
	if err := normalizeGeneratedSBOMFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("normalizeGeneratedSBOMFile(missing) error = nil")
	}

	defaultVenv, err := pythonToolVenvDir(Config{}, InstallSpec{Package: "cyclonedx-bom", ExpectedVersion: "7.3.0"})
	if err != nil || !strings.Contains(defaultVenv, filepath.Join("packmon", "tools", "python", "cyclonedx-bom", "7.3.0")) {
		t.Fatalf("pythonToolVenvDir(default cache) = %q, %v", defaultVenv, err)
	}
	missing := func(string) (string, error) { return "", errors.New("missing") }
	if _, err := resolveInstaller(Config{LookPath: missing}, InstallSpec{Package: "cyclonedx-bom", Args: []string{"python"}}); err == nil || !strings.Contains(err.Error(), "python") {
		t.Fatalf("resolveInstaller(no python) error = %v", err)
	}

	versioned := &fakeGenerator{tool: "cyclonedx-npm", install: InstallSpec{ExpectedVersion: "5.0.0", VersionArgs: []string{"--version"}}}
	cfg := normalizeConfig(Config{Timeout: time.Second, Runner: func(context.Context, RunOptions) ([]byte, error) {
		return []byte("cannot execute"), errors.New("exit")
	}})
	if err := verifyToolVersion(ctx, cfg, versioned, "tool"); err == nil || !strings.Contains(err.Error(), "cannot execute") {
		t.Fatalf("verifyToolVersion(runner error) = %v", err)
	}
	cfg.Runner = func(context.Context, RunOptions) ([]byte, error) { return []byte("cyclonedx-npm v5.0.0"), nil }
	if err := verifyToolVersion(ctx, cfg, versioned, "tool"); err != nil {
		t.Fatalf("verifyToolVersion(match) error = %v", err)
	}
	if !versionOutputContainsVersion("tool version v5.0.0 (build)", "v5.0.0") {
		t.Fatal("versionOutputContainsVersion() missed an exact token")
	}

	cacheParent := t.TempDir()
	cacheFile := filepath.Join(cacheParent, "cache-file")
	writeFile(t, cacheParent, "cache-file", "x")
	pythonSpec := InstallSpec{Package: "cyclonedx-bom", ExpectedVersion: "7.3.0", PythonPackage: true}
	if err := installPythonPackageTool(ctx, Config{ToolCacheDir: filepath.Join(cacheFile, "child")}, pythonSpec, "python"); err == nil || !strings.Contains(err.Error(), "tool cache") {
		t.Fatalf("installPythonPackageTool(cache failure) error = %v", err)
	}
	if err := installPythonPackageTool(ctx, Config{
		ToolCacheDir: t.TempDir(), Timeout: time.Second,
		Runner: func(context.Context, RunOptions) ([]byte, error) { return []byte("venv failed"), errors.New("exit") },
	}, pythonSpec, "python"); err == nil || !strings.Contains(err.Error(), "venv failed") {
		t.Fatalf("installPythonPackageTool(venv failure) error = %v", err)
	}
	runs := 0
	if err := installPythonPackageTool(ctx, Config{
		ToolCacheDir: t.TempDir(), Timeout: time.Second,
		Runner: func(context.Context, RunOptions) ([]byte, error) {
			runs++
			if runs == 2 {
				return []byte("pip failed"), errors.New("exit")
			}
			return nil, nil
		},
	}, pythonSpec, "python"); err == nil || !strings.Contains(err.Error(), "pip failed") {
		t.Fatalf("installPythonPackageTool(pip failure) error = %v", err)
	}
}

func TestRunEnvironmentAndPostInstallChecks(t *testing.T) {
	originalPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", originalPath) })
	if err := os.Setenv("PATH", ""); err != nil {
		t.Fatalf("clear PATH: %v", err)
	}
	cache := t.TempDir()
	spec := InstallSpec{Package: "cyclonedx-bom", ExpectedVersion: "7.3.0"}
	if err := prependPythonToolPath(Config{ToolCacheDir: cache}, spec); err != nil {
		t.Fatalf("prependPythonToolPath(empty PATH) error = %v", err)
	}
	wantBin := pythonToolBinDir(filepath.Join(cache, "python", "cyclonedx-bom", "7.3.0"))
	if got := os.Getenv("PATH"); filepath.Clean(got) != filepath.Clean(wantBin) {
		t.Fatalf("PATH = %q, want %q", got, wantBin)
	}
	if err := prependPythonToolPath(Config{ToolCacheDir: cache}, spec); err != nil || os.Getenv("PATH") != wantBin {
		t.Fatalf("prependPythonToolPath(existing) changed PATH to %q, err %v", os.Getenv("PATH"), err)
	}

	installGen := &fakeGenerator{
		tool:    "cyclonedx-npm",
		install: InstallSpec{Package: "pkg", Source: "registry", Args: []string{"npm", "install", "pkg"}, CanAutoInstall: true},
	}
	if err := ensureTool(context.Background(), Config{
		InstallTools: true,
		LookPath: func(name string) (string, error) {
			if name == "npm" {
				return "npm", nil
			}
			return "", errors.New("missing")
		},
		Runner:  func(context.Context, RunOptions) ([]byte, error) { return nil, nil },
		Timeout: time.Second,
	}, installGen); err == nil || !strings.Contains(err.Error(), "still not on PATH") {
		t.Fatalf("ensureTool(post-install lookup failure) error = %v", err)
	}

	installed := false
	versionGen := &fakeGenerator{
		tool: "cyclonedx-npm",
		install: InstallSpec{
			Package: "pkg", Source: "registry", Args: []string{"npm", "install", "pkg"},
			ExpectedVersion: "5.0.0", VersionArgs: []string{"--version"}, CanAutoInstall: true,
		},
	}
	if err := ensureTool(context.Background(), Config{
		InstallTools: true,
		LookPath: func(name string) (string, error) {
			if name == "npm" {
				return "npm", nil
			}
			if name == "cyclonedx-npm" && installed {
				return "cyclonedx-npm", nil
			}
			return "", errors.New("missing")
		},
		Runner: func(_ context.Context, opts RunOptions) ([]byte, error) {
			if opts.Name == "npm" {
				installed = true
				return nil, nil
			}
			return []byte("9.9.9"), nil
		},
		Timeout: time.Second,
	}, versionGen); err == nil || !strings.Contains(err.Error(), "required SBOM generator") {
		t.Fatalf("ensureTool(post-install version mismatch) error = %v", err)
	}

	pythonCacheFile := filepath.Join(t.TempDir(), "python-cache-file")
	writeFile(t, filepath.Dir(pythonCacheFile), filepath.Base(pythonCacheFile), "x")
	pythonGen := &fakeGenerator{
		tool: "cyclonedx-py",
		install: InstallSpec{
			Package: "cyclonedx-bom", Args: []string{"python"}, ExpectedVersion: "7.3.0",
			CanAutoInstall: true, PythonPackage: true,
		},
	}
	if err := ensureTool(context.Background(), Config{
		InstallTools: true, ToolCacheDir: filepath.Join(pythonCacheFile, "child"), Timeout: time.Second,
		LookPath: func(name string) (string, error) {
			if name == "python" {
				return "python", nil
			}
			return "", errors.New("missing")
		},
	}, pythonGen); err == nil || !strings.Contains(err.Error(), "tool cache") {
		t.Fatalf("ensureTool(Python install failure) error = %v", err)
	}

	env := sanitizedCommandEnv([]string{"PATH=first", "Path=second", "invalid-without-equals"})
	var pathValues []string
	for _, kv := range env {
		key, value, ok := strings.Cut(kv, "=")
		if ok && strings.EqualFold(key, "PATH") {
			pathValues = append(pathValues, value)
		}
	}
	if len(pathValues) != 1 || pathValues[0] != "second" {
		t.Fatalf("sanitizedCommandEnv duplicate PATH values = %v, want [second]", pathValues)
	}
	if allowToolEnvKey("   ") {
		t.Fatal("allowToolEnvKey(blank) = true")
	}
}
