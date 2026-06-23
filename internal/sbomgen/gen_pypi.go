package sbomgen

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type pypiGenerator struct{}

func (pypiGenerator) Ecosystem() string { return "pypi" }
func (pypiGenerator) Tool() string      { return "cyclonedx-py" }
func (pypiGenerator) InstallSpec() InstallSpec {
	return InstallSpec{
		Package:         "cyclonedx-bom",
		Source:          "PyPI",
		Args:            []string{"python", "-m", "pip", "install", "--user", "cyclonedx-bom==" + pypiGeneratorVersion},
		ExpectedVersion: pypiGeneratorVersion,
		VersionArgs:     []string{"--version"},
		CanAutoInstall:  true,
	}
}

func (pypiGenerator) Generate(ctx context.Context, d Detection, outPath string, genOpts GenerateOptions, run RunnerFunc) error {
	args := []string{d.InputKind, "--output-format", "JSON", "--output-file", outPath}
	opts := RunOptions{Name: "cyclonedx-py", Args: args}
	switch d.InputKind {
	case "requirements":
		opts.Args = append(opts.Args, d.ManifestPath)
	case "poetry":
		if !genOpts.IncludeDev {
			opts.Args = append(opts.Args, "--no-dev")
		}
		opts.Dir = d.ProjectDir
	default:
		return fmt.Errorf("unsupported PyPI input kind %q", d.InputKind)
	}
	out, err := run(ctx, opts)
	if err != nil {
		return fmt.Errorf("cyclonedx-py: %w: %s", err, commandOutputSummary(out))
	}
	return nil
}

func (pypiGenerator) DeclaresDependencies(d Detection, opts GenerateOptions) (bool, error) {
	switch d.InputKind {
	case "requirements":
		return requirementsDeclareDependencies(d.ManifestPath)
	case "poetry":
		return poetryDeclaresDependencies(d, opts)
	default:
		return false, fmt.Errorf("unsupported PyPI input kind %q", d.InputKind)
	}
}

func requirementsDeclareDependencies(path string) (bool, error) {
	return requirementsDeclareDependenciesSeen(path, map[string]struct{}{})
}

func requirementsDeclareDependenciesSeen(path string, seen map[string]struct{}) (bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	if _, ok := seen[abs]; ok {
		return false, nil
	}
	seen[abs] = struct{}{}

	file, err := os.Open(path) // #nosec G304 -- path comes from a bounded local manifest walk.
	if err != nil {
		return false, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if hash := strings.Index(line, " #"); hash >= 0 {
			line = strings.TrimSpace(line[:hash])
		}
		if line == "" {
			continue
		}
		if include, ok := requirementsIncludePath(line); ok {
			if !filepath.IsAbs(include) {
				include = filepath.Join(filepath.Dir(path), include)
			}
			declares, err := requirementsDeclareDependenciesSeen(include, seen)
			if err != nil {
				return true, nil
			}
			if declares {
				return true, nil
			}
			continue
		}
		if strings.HasPrefix(line, "--editable") || strings.HasPrefix(line, "-e ") {
			return true, nil
		}
		if strings.HasPrefix(line, "-") {
			continue
		}
		return true, nil
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func requirementsIncludePath(line string) (string, bool) {
	if strings.HasPrefix(line, "-r ") {
		return firstRequirementArg(strings.TrimSpace(strings.TrimPrefix(line, "-r ")))
	}
	if strings.HasPrefix(line, "-r") && len(line) > len("-r") {
		return firstRequirementArg(strings.TrimSpace(strings.TrimPrefix(line, "-r")))
	}
	if strings.HasPrefix(line, "--requirement=") {
		return firstRequirementArg(strings.TrimSpace(strings.TrimPrefix(line, "--requirement=")))
	}
	if strings.HasPrefix(line, "--requirement ") {
		return firstRequirementArg(strings.TrimSpace(strings.TrimPrefix(line, "--requirement ")))
	}
	return "", false
}

func firstRequirementArg(value string) (string, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "", false
	}
	return fields[0], true
}

func poetryDeclaresDependencies(d Detection, opts GenerateOptions) (bool, error) {
	data, err := readAutoSBOMManifest(d.ManifestPath)
	if err != nil {
		return false, err
	}
	var doc struct {
		Tool struct {
			Poetry struct {
				Dependencies    map[string]any `toml:"dependencies"`
				DevDependencies map[string]any `toml:"dev-dependencies"`
				Group           map[string]struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		return false, err
	}
	if poetryDependencyMapHasPackages(doc.Tool.Poetry.Dependencies, true) {
		return true, nil
	}
	if opts.IncludeDev {
		if poetryDependencyMapHasPackages(doc.Tool.Poetry.DevDependencies, false) {
			return true, nil
		}
		for _, group := range doc.Tool.Poetry.Group {
			if poetryDependencyMapHasPackages(group.Dependencies, false) {
				return true, nil
			}
		}
	}
	lockPath := filepath.Join(d.ProjectDir, "poetry.lock")
	lockData, err := readAutoSBOMManifest(lockPath)
	if err == nil {
		return poetryLockDeclaresDependencies(lockData, opts.IncludeDev), nil
	}
	return false, nil
}

func poetryLockDeclaresDependencies(data []byte, includeDev bool) bool {
	if len(strings.TrimSpace(string(data))) == 0 {
		return false
	}
	var lock struct {
		Package []struct {
			Name     string   `toml:"name"`
			Category string   `toml:"category"`
			Groups   []string `toml:"groups"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return true
	}
	for _, pkg := range lock.Package {
		if strings.TrimSpace(pkg.Name) == "" {
			continue
		}
		if includeDev {
			return true
		}
		if strings.TrimSpace(pkg.Category) == "" && len(pkg.Groups) == 0 {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(pkg.Category), "main") {
			return true
		}
		for _, group := range pkg.Groups {
			if strings.EqualFold(strings.TrimSpace(group), "main") {
				return true
			}
		}
	}
	return false
}

func poetryDependencyMapHasPackages(deps map[string]any, ignorePython bool) bool {
	for name := range deps {
		if ignorePython && strings.EqualFold(strings.TrimSpace(name), "python") {
			continue
		}
		return true
	}
	return false
}
