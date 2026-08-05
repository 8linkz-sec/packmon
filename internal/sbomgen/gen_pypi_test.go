package sbomgen

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestPyPIGeneratorRequirementsArgs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "requirements.txt", "Django==5.0.0\n")
	d := Detection{InputKind: "requirements", ManifestPath: filepath.Join(root, "requirements.txt"), ProjectDir: root}
	var got RunOptions
	err := (pypiGenerator{}).Generate(context.Background(), d, filepath.Join(root, "bom.json"), GenerateOptions{}, func(_ context.Context, opts RunOptions) ([]byte, error) {
		got = opts
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	joined := strings.Join(got.Args, " ")
	if got.Name != "cyclonedx-py" || !strings.Contains(joined, "requirements") || !strings.Contains(joined, d.ManifestPath) || got.Dir != "" {
		t.Fatalf("RunOptions = %+v", got)
	}
}

func TestPyPIGeneratorPoetryRunsInProjectDir(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pyproject.toml", `[tool.poetry]`+"\nname = \"demo\"\n[tool.poetry.dependencies]\npython = \"^3.12\"\nDjango = \"^5.0\"\n")
	d := Detection{InputKind: "poetry", ManifestPath: filepath.Join(root, "pyproject.toml"), ProjectDir: root}
	var got RunOptions
	err := (pypiGenerator{}).Generate(context.Background(), d, filepath.Join(root, "bom.json"), GenerateOptions{}, func(_ context.Context, opts RunOptions) ([]byte, error) {
		got = opts
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got.Name != "cyclonedx-py" || got.Dir != root || !strings.Contains(strings.Join(got.Args, " "), "poetry") {
		t.Fatalf("RunOptions = %+v", got)
	}
	if !strings.Contains(strings.Join(got.Args, " "), "--no-dev") {
		t.Fatalf("Poetry generation without IncludeDev should pass --no-dev, args = %+v", got.Args)
	}
}

func TestPyPIGeneratorPoetryIncludeDevDoesNotPassNoDev(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pyproject.toml", `[tool.poetry]`+"\nname = \"demo\"\n[tool.poetry.dependencies]\npython = \"^3.12\"\nDjango = \"^5.0\"\n")
	d := Detection{InputKind: "poetry", ManifestPath: filepath.Join(root, "pyproject.toml"), ProjectDir: root}
	var got RunOptions
	err := (pypiGenerator{}).Generate(context.Background(), d, filepath.Join(root, "bom.json"), GenerateOptions{IncludeDev: true}, func(_ context.Context, opts RunOptions) ([]byte, error) {
		got = opts
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(strings.Join(got.Args, " "), "--no-dev") {
		t.Fatalf("Poetry generation with IncludeDev should not pass --no-dev, args = %+v", got.Args)
	}
}

func TestPyPIGeneratorRequirementsDeclaresOnlyDependencyLines(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "requirements.txt", "# comment\n--index-url https://example.invalid/simple\n--pre\n")
	declares, err := (pypiGenerator{}).DeclaresDependencies(Detection{InputKind: "requirements", ManifestPath: filepath.Join(root, "requirements.txt")}, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies option-only: %v", err)
	}
	if declares {
		t.Fatalf("option-only requirements should not declare dependencies")
	}
	writeFile(t, root, "requirements.txt", "--editable git+https://example.invalid/repo.git#egg=demo\n")
	declares, err = (pypiGenerator{}).DeclaresDependencies(Detection{InputKind: "requirements", ManifestPath: filepath.Join(root, "requirements.txt")}, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies editable: %v", err)
	}
	if !declares {
		t.Fatalf("--editable requirement should declare a dependency")
	}
}

func TestPyPIGeneratorRequirementsIncludeDeclaresNestedDependency(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "requirements.txt", "-r common.txt\n")
	writeFile(t, root, "common.txt", "# shared deps\nDjango==5.0.0\n")
	declares, err := (pypiGenerator{}).DeclaresDependencies(Detection{InputKind: "requirements", ManifestPath: filepath.Join(root, "requirements.txt")}, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies include: %v", err)
	}
	if !declares {
		t.Fatalf("requirements include with nested package should declare dependencies")
	}
}

func TestPyPIGeneratorRequirementsEmptyIncludeDoesNotDeclareDependencies(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "requirements.txt", "--requirement common.txt\n")
	writeFile(t, root, "common.txt", "# intentionally empty\n")
	declares, err := (pypiGenerator{}).DeclaresDependencies(Detection{InputKind: "requirements", ManifestPath: filepath.Join(root, "requirements.txt")}, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies include: %v", err)
	}
	if declares {
		t.Fatalf("empty requirements include should not declare dependencies")
	}
}

func TestRequirementsIncludePathForms(t *testing.T) {
	cases := map[string]string{
		"-r common.txt":                  "common.txt",
		"-rcommon.txt":                   "common.txt",
		"--requirement common.txt":       "common.txt",
		"--requirement=common.txt":       "common.txt",
		"--requirement common.txt # dev": "common.txt",
	}
	for line, want := range cases {
		got, ok := requirementsIncludePath(line)
		if !ok || got != want {
			t.Fatalf("requirementsIncludePath(%q) = %q/%v, want %q/true", line, got, ok, want)
		}
	}
	if got, ok := requirementsIncludePath("--pre"); ok || got != "" {
		t.Fatalf("requirementsIncludePath option = %q/%v, want empty/false", got, ok)
	}
	if got, ok := firstRequirementArg("   "); ok || got != "" {
		t.Fatalf("firstRequirementArg blank = %q/%v, want empty/false", got, ok)
	}
}

func TestPyPIGeneratorPoetryLockDeclaresDependencies(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pyproject.toml", `[tool.poetry]`+"\nname = \"demo\"\n[tool.poetry.dependencies]\npython = \"^3.12\"\n")
	writeFile(t, root, "poetry.lock", "[[package]]\nname = \"Django\"\nversion = \"5.0.0\"\n")
	declares, err := (pypiGenerator{}).DeclaresDependencies(Detection{InputKind: "poetry", ManifestPath: filepath.Join(root, "pyproject.toml"), ProjectDir: root}, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies: %v", err)
	}
	if !declares {
		t.Fatalf("non-empty poetry.lock should declare dependencies")
	}
}

func TestPyPIGeneratorPoetryDevOnlyLockRespectsIncludeDev(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pyproject.toml", `[tool.poetry]`+"\nname = \"demo\"\n[tool.poetry.dependencies]\npython = \"^3.12\"\n")
	writeFile(t, root, "poetry.lock", "[[package]]\nname = \"pytest\"\nversion = \"8.0.0\"\ngroups = [\"dev\"]\n")
	d := Detection{InputKind: "poetry", ManifestPath: filepath.Join(root, "pyproject.toml"), ProjectDir: root}
	declares, err := (pypiGenerator{}).DeclaresDependencies(d, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies without dev: %v", err)
	}
	if declares {
		t.Fatalf("dev-only poetry.lock should not declare dependencies when IncludeDev=false")
	}
	declares, err = (pypiGenerator{}).DeclaresDependencies(d, GenerateOptions{IncludeDev: true})
	if err != nil {
		t.Fatalf("DeclaresDependencies with dev: %v", err)
	}
	if !declares {
		t.Fatalf("dev-only poetry.lock should declare dependencies when IncludeDev=true")
	}
}

func TestPyPIGeneratorPoetryMetadataOnlyLockDoesNotDeclareDependencies(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pyproject.toml", `[tool.poetry]`+"\nname = \"demo\"\n[tool.poetry.dependencies]\npython = \"^3.12\"\n")
	writeFile(t, root, "poetry.lock", "[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.12\"\n")
	d := Detection{InputKind: "poetry", ManifestPath: filepath.Join(root, "pyproject.toml"), ProjectDir: root}
	declares, err := (pypiGenerator{}).DeclaresDependencies(d, GenerateOptions{IncludeDev: true})
	if err != nil {
		t.Fatalf("DeclaresDependencies: %v", err)
	}
	if declares {
		t.Fatalf("metadata-only poetry.lock should not declare dependencies")
	}
}

func TestPyPIGeneratorPoetryLockMainGroupsAndMalformedLock(t *testing.T) {
	if !poetryLockDeclaresDependencies([]byte("[[package]]\nname = \"Django\"\ncategory = \"main\"\n"), false) {
		t.Fatalf("main-category poetry.lock package should declare dependencies")
	}
	if !poetryLockDeclaresDependencies([]byte("[[package]]\nname = \"Django\"\ngroups = [\"main\"]\n"), false) {
		t.Fatalf("main-group poetry.lock package should declare dependencies")
	}
	if !poetryLockDeclaresDependencies([]byte("[[package]\n"), false) {
		t.Fatalf("malformed non-empty poetry.lock should conservatively declare dependencies")
	}
	if poetryLockDeclaresDependencies([]byte(" \n"), true) {
		t.Fatalf("empty poetry.lock should not declare dependencies")
	}
}
