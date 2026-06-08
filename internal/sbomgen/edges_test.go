package sbomgen

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilterDetectionsByEcosystem(t *testing.T) {
	ds := []Detection{
		{Ecosystem: "go", DisplayPath: "go.mod"},
		{Ecosystem: "npm", DisplayPath: "package.json"},
	}
	got := filterDetections(ds, []string{" NPM "})
	if len(got) != 1 || got[0].Ecosystem != "npm" {
		t.Fatalf("filterDetections = %+v, want npm only", got)
	}
	if got = filterDetections(ds, []string{" "}); len(got) != 2 {
		t.Fatalf("blank ecosystem filter should leave detections unchanged: %+v", got)
	}
}

func TestRunAppliesEcosystemFilter(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.test\n\ngo 1.26\n")
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	gen := &fakeGenerator{ecosystem: "npm", tool: "cyclonedx-npm", declares: true}
	result, err := Run(context.Background(), Config{
		Target:     root,
		Ecosystems: []string{"npm"},
		Registry:   map[string]Generator{"npm": gen},
		LookPath:   func(string) (string, error) { return "found", nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer func() { _ = result.Cleanup() }()
	if len(result.SBOMPaths) != 1 || !strings.Contains(filepath.Base(result.SBOMPaths[0]), "package") {
		t.Fatalf("SBOMPaths = %v, want only npm package SBOM", result.SBOMPaths)
	}
}

func TestEnsureToolInstallFailureBranches(t *testing.T) {
	ctx := context.Background()
	missing := func(string) (string, error) { return "", errors.New("missing") }

	manual := &fakeGenerator{ecosystem: "maven", tool: "mvn", install: InstallSpec{Package: "mvn"}}
	if err := ensureTool(ctx, Config{LookPath: missing}, manual); err == nil || !strings.Contains(err.Error(), "install mvn manually") {
		t.Fatalf("manual install err = %v", err)
	}

	noArgs := &fakeGenerator{ecosystem: "npm", tool: "cyclonedx-npm", install: InstallSpec{CanAutoInstall: true}}
	if err := ensureTool(ctx, Config{InstallTools: true, LookPath: missing}, noArgs); err == nil || !strings.Contains(err.Error(), "no install command") {
		t.Fatalf("no args err = %v", err)
	}

	installerMissing := &fakeGenerator{
		ecosystem: "npm",
		tool:      "cyclonedx-npm",
		install:   InstallSpec{Package: "pkg", Args: []string{"npm", "install", "pkg"}, CanAutoInstall: true},
	}
	if err := ensureTool(ctx, Config{InstallTools: true, LookPath: missing}, installerMissing); err == nil || !strings.Contains(err.Error(), "installer") {
		t.Fatalf("installer missing err = %v", err)
	}

	lookups := 0
	installFails := func(name string) (string, error) {
		lookups++
		if name == "npm" {
			return "npm", nil
		}
		return "", errors.New("missing")
	}
	err := ensureTool(ctx, Config{
		InstallTools: true,
		LookPath:     installFails,
		Runner: func(context.Context, RunOptions) ([]byte, error) {
			return []byte("boom"), errors.New("exit")
		},
		Timeout: defaultGenerationTimeout,
	}, installerMissing)
	if err == nil || !strings.Contains(err.Error(), "boom") || lookups < 2 {
		t.Fatalf("install failure err/lookups = %v/%d", err, lookups)
	}
}

func TestDefaultRunnerRunsCommand(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go command not on PATH")
	}
	out, err := defaultRunner(context.Background(), RunOptions{Name: "go", Args: []string{"version"}, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("defaultRunner: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "go version") {
		t.Fatalf("go version output = %q", out)
	}
}

func TestValidateGeneratedSBOMErrors(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := validateGeneratedSBOM(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatalf("missing SBOM should error")
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateGeneratedSBOM(empty); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty SBOM err = %v", err)
	}
}

func TestRunKeepModeFailureRemovesCreatedSBOM(t *testing.T) {
	root := t.TempDir()
	keep := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	gen := &fakeGenerator{
		ecosystem:      "npm",
		tool:           "cyclonedx-npm",
		generateOutput: `{"bomFormat":"CycloneDX","components":`,
	}
	_, err := Run(context.Background(), Config{
		Target:      root,
		KeepSBOMDir: keep,
		Registry:    map[string]Generator{"npm": gen},
		LookPath:    func(string) (string, error) { return "found", nil },
	})
	if err == nil {
		t.Fatalf("Run should fail on invalid generated SBOM")
	}
	leftovers, globErr := filepath.Glob(filepath.Join(keep, "*.cdx.json"))
	if globErr != nil {
		t.Fatalf("glob generated SBOMs: %v", globErr)
	}
	if len(leftovers) != 0 {
		t.Fatalf("created SBOM should be removed on failure, leftovers = %v", leftovers)
	}
}

func TestGeneratorErrorBranches(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.test\n\ngo 1.26\n")
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	writeFile(t, root, "requirements.txt", "Django==5.0.0\n")
	writeFile(t, root, "pom.xml", `<project><dependencies></dependencies></project>`)
	failRun := func(context.Context, RunOptions) ([]byte, error) {
		return []byte("tool failed"), errors.New("exit")
	}
	if err := (goGenerator{}).Generate(context.Background(), Detection{ProjectDir: root, ManifestPath: filepath.Join(root, "go.mod")}, filepath.Join(root, "go.json"), GenerateOptions{}, failRun); err == nil || !strings.Contains(err.Error(), "tool failed") {
		t.Fatalf("go Generate err = %v", err)
	}
	if err := (npmGenerator{}).Generate(context.Background(), Detection{ProjectDir: root, ManifestPath: filepath.Join(root, "package.json")}, filepath.Join(root, "npm.json"), GenerateOptions{}, failRun); err == nil || !strings.Contains(err.Error(), "tool failed") {
		t.Fatalf("npm Generate err = %v", err)
	}
	if err := (pypiGenerator{}).Generate(context.Background(), Detection{InputKind: "unsupported", ProjectDir: root}, filepath.Join(root, "pypi.json"), GenerateOptions{}, failRun); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("pypi unsupported Generate err = %v", err)
	}
	if err := (mavenGenerator{}).Generate(context.Background(), Detection{ProjectDir: root, ManifestPath: filepath.Join(root, "pom.xml")}, filepath.Join(root, "maven.json"), GenerateOptions{}, failRun); err == nil || !strings.Contains(err.Error(), "tool failed") {
		t.Fatalf("maven Generate err = %v", err)
	}
}

func TestPyPIPoetryDevDependenciesRespectIncludeDev(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pyproject.toml", `[tool.poetry]`+"\nname = \"demo\"\n[tool.poetry.dependencies]\npython = \"^3.12\"\n[tool.poetry.group.dev.dependencies]\npytest = \"^8.0\"\n")
	d := Detection{InputKind: "poetry", ManifestPath: filepath.Join(root, "pyproject.toml"), ProjectDir: root}
	declares, err := (pypiGenerator{}).DeclaresDependencies(d, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies without dev: %v", err)
	}
	if declares {
		t.Fatalf("dev-only poetry dependencies should not count when IncludeDev=false")
	}
	declares, err = (pypiGenerator{}).DeclaresDependencies(d, GenerateOptions{IncludeDev: true})
	if err != nil {
		t.Fatalf("DeclaresDependencies with dev: %v", err)
	}
	if !declares {
		t.Fatalf("dev poetry dependencies should count when IncludeDev=true")
	}
}

func TestMavenTestScopeRespectsIncludeDev(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pom.xml", `<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version><scope>test</scope></dependency></dependencies></project>`)
	d := Detection{ManifestPath: filepath.Join(root, "pom.xml"), ProjectDir: root}
	declares, err := (mavenGenerator{}).DeclaresDependencies(d, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies without dev: %v", err)
	}
	if declares {
		t.Fatalf("test-scope dependency should not count when IncludeDev=false")
	}
	declares, err = (mavenGenerator{}).DeclaresDependencies(d, GenerateOptions{IncludeDev: true})
	if err != nil {
		t.Fatalf("DeclaresDependencies with dev: %v", err)
	}
	if !declares {
		t.Fatalf("test-scope dependency should count when IncludeDev=true")
	}
}

func TestRunAdditionalErrorBranches(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)

	_, err := Run(context.Background(), Config{
		Target:   root,
		Registry: map[string]Generator{},
		LookPath: func(string) (string, error) { return "found", nil },
	})
	if err == nil || !strings.Contains(err.Error(), "no SBOM generator") {
		t.Fatalf("missing registry err = %v", err)
	}

	genErr := &fakeGenerator{ecosystem: "npm", tool: "cyclonedx-npm", generateErr: errors.New("generate boom")}
	_, err = Run(context.Background(), Config{
		Target:   root,
		Registry: map[string]Generator{"npm": genErr},
		LookPath: func(string) (string, error) { return "found", nil },
	})
	if err == nil || !strings.Contains(err.Error(), "generate boom") {
		t.Fatalf("generate err = %v", err)
	}

	declaresErr := &fakeGenerator{
		ecosystem:      "npm",
		tool:           "cyclonedx-npm",
		generateOutput: validCycloneDXNoPackages(),
		declaresErr:    errors.New("declares boom"),
	}
	_, err = Run(context.Background(), Config{
		Target:   root,
		Registry: map[string]Generator{"npm": declaresErr},
		LookPath: func(string) (string, error) { return "found", nil },
	})
	if err == nil || !strings.Contains(err.Error(), "declares boom") {
		t.Fatalf("declares err = %v", err)
	}

	noDeps := &fakeGenerator{ecosystem: "npm", tool: "cyclonedx-npm", generateOutput: validCycloneDXNoPackages()}
	result, err := Run(context.Background(), Config{
		Target:   root,
		Registry: map[string]Generator{"npm": noDeps},
		LookPath: func(string) (string, error) { return "found", nil },
	})
	if err != nil {
		t.Fatalf("zero packages with no declared deps should pass: %v", err)
	}
	if err := result.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

func TestOutputAndCleanupHelpers(t *testing.T) {
	if got := outputFileName(Detection{Ecosystem: "npm"}); got != "npm.cdx.json" {
		t.Fatalf("outputFileName fallback = %q", got)
	}
	relKeep := filepath.Join(t.TempDir(), "relative-keep")
	if err := os.MkdirAll(relKeep, 0o700); err != nil {
		t.Fatal(err)
	}
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(filepath.Dir(relKeep)); err != nil {
		t.Fatal(err)
	}
	outDir, successCleanup, failureCleanup, err := prepareOutputDir(filepath.Base(relKeep))
	if chdirErr := os.Chdir(oldwd); chdirErr != nil {
		t.Fatal(chdirErr)
	}
	if err != nil {
		t.Fatalf("prepareOutputDir relative keep: %v", err)
	}
	if !filepath.IsAbs(outDir) {
		t.Fatalf("prepareOutputDir relative keep = %q, want absolute path", outDir)
	}
	if filepath.Clean(outDir) != filepath.Clean(relKeep) {
		t.Fatalf("prepareOutputDir relative keep = %q, want %q", outDir, relKeep)
	}
	if err := successCleanup(); err != nil {
		t.Fatalf("success cleanup: %v", err)
	}
	if err := failureCleanup(); err != nil {
		t.Fatalf("failure cleanup: %v", err)
	}
	if err := reserveOutputPath(filepath.Join(t.TempDir(), "missing", "bom.json")); err == nil {
		t.Fatalf("reserveOutputPath should fail when parent dir is missing")
	}
	fileAsDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := prepareOutputDir(fileAsDir); err == nil {
		t.Fatalf("prepareOutputDir should fail when keep dir path is an existing file")
	}
	nonEmptyDir := t.TempDir()
	writeFile(t, nonEmptyDir, "child.txt", "x")
	if err := removeFiles([]string{nonEmptyDir}); err == nil {
		t.Fatalf("removeFiles should report non-empty directory removal error")
	}
}

func TestDeclaresDependencyErrorBranches(t *testing.T) {
	root := t.TempDir()
	if _, err := (goGenerator{}).DeclaresDependencies(Detection{ManifestPath: filepath.Join(root, "missing-go.mod")}, GenerateOptions{}); err == nil {
		t.Fatalf("missing go.mod should error")
	}
	writeFile(t, root, "package.json", "{")
	if _, err := (npmGenerator{}).DeclaresDependencies(Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root}, GenerateOptions{}); err == nil {
		t.Fatalf("invalid package.json should error")
	}
	if _, err := (pypiGenerator{}).DeclaresDependencies(Detection{InputKind: "unsupported"}, GenerateOptions{}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported PyPI declares err = %v", err)
	}
	if _, err := requirementsDeclareDependencies(filepath.Join(root, "missing-requirements.txt")); err == nil {
		t.Fatalf("missing requirements.txt should error")
	}
	writeFile(t, root, "pom.xml", "<project>")
	if _, err := (mavenGenerator{}).DeclaresDependencies(Detection{ManifestPath: filepath.Join(root, "pom.xml"), ProjectDir: root}, GenerateOptions{}); err == nil {
		t.Fatalf("invalid pom.xml should error")
	}
}

func TestMavenGeneratorMissingStagedBOM(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pom.xml", `<project><dependencies></dependencies></project>`)
	err := (mavenGenerator{}).Generate(context.Background(), Detection{ProjectDir: root, ManifestPath: filepath.Join(root, "pom.xml")}, filepath.Join(root, "bom.json"), GenerateOptions{}, func(context.Context, RunOptions) ([]byte, error) {
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "bom.json") {
		t.Fatalf("missing staged BOM err = %v", err)
	}
}

func TestDetectorHelperEdgeBranches(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	if depthExceeded(root, nested, -1) {
		t.Fatalf("negative maxDepth should not limit traversal")
	}
	if !depthExceeded(root, nested, 1) {
		t.Fatalf("nested dir should exceed maxDepth=1")
	}
	writeFile(t, root, "bad-pyproject.toml", "[tool.poetry\n")
	if isPoetryProject(filepath.Join(root, "bad-pyproject.toml")) {
		t.Fatalf("malformed pyproject should not classify as poetry")
	}
	writeFile(t, root, "bad-workspaces.json", `{"workspaces": 123}`)
	if globs, err := npmWorkspaceGlobs(filepath.Join(root, "bad-workspaces.json")); err == nil || globs != nil {
		t.Fatalf("bad workspaces globs = %v, err = %v", globs, err)
	}
	writeFile(t, root, "pom.xml", `<project><modules><module>.</module></modules></project>`)
	if children := mavenModulesWalk(root, map[string]struct{}{}); len(children) != 1 || filepath.Clean(children[0]) != filepath.Clean(root) {
		t.Fatalf("cyclic module children = %v", children)
	}
}
