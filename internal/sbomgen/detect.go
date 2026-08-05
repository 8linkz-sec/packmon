package sbomgen

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/BurntSushi/toml"
)

// Detection is one concrete SBOM generation target found below a scan root.
type Detection struct {
	// Ecosystem selects the generator registry entry, such as go, npm, pypi, or maven.
	Ecosystem domain.Ecosystem
	// ScanRoot is the absolute root used to bound manifest discovery and path checks.
	ScanRoot string
	// ProjectDir is the directory where the generator should run.
	ProjectDir string
	// ManifestPath is the absolute path to the manifest that caused the detection.
	ManifestPath string
	// InputKind names the manifest style, for example go.mod, npm-package, or poetry.
	InputKind string
	// DisplayPath is the scan-root-relative path used in diagnostics and output names.
	DisplayPath string
}

var skipDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"vendor":       {},
	"__pycache__":  {},
}

var walkDir = filepath.WalkDir

// Detect walks root up to maxDepth and returns supported generation targets.
// Discovery stays within root, skips common dependency/cache directories, and
// suppresses child manifests already covered by supported workspace/module
// manifests.
func Detect(root string, maxDepth int) ([]Detection, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	bounds, err := newScanRootBounds(absRoot)
	if err != nil {
		return nil, err
	}

	detectManifestNames := autoSBOMDetectManifestNames()
	var manifests []string
	err = walkDir(absRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk %s: %w", relDisplay(absRoot, p), walkErr)
		}
		if d.IsDir() {
			if p == absRoot {
				return nil
			}
			name := d.Name()
			if _, skip := skipDirs[name]; skip || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			if depthExceeded(absRoot, p, maxDepth) {
				return filepath.SkipDir
			}
			return nil
		}

		if _, ok := detectManifestNames[d.Name()]; ok {
			if err := bounds.requireExisting(p); err != nil {
				return err
			}
			manifests = append(manifests, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	detections := make([]Detection, 0, len(manifests))
	for _, manifest := range manifests {
		det, ok, err := classifyManifest(bounds, manifest)
		if err != nil {
			return nil, err
		}
		if ok {
			detections = append(detections, det)
		}
	}
	return suppressCovered(detections)
}

func depthExceeded(root, dir string, maxDepth int) bool {
	if maxDepth < 0 {
		return false
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	return len(parts) > maxDepth
}

func classifyManifest(bounds scanRootBounds, manifest string) (Detection, bool, error) {
	descriptor, ok := autoSBOMDetectManifestDescriptor(filepath.Base(manifest))
	if !ok {
		return Detection{}, false, nil
	}
	dir := filepath.Dir(manifest)
	display := relDisplay(bounds.absRoot, manifest)
	switch descriptor.Kind {
	case autoSBOMManifestKindDetect:
		if descriptor.Name == "package.json" {
			hasUnsupportedLockfile, err := npmHasUnsupportedLockfileScoped(bounds.absRoot, dir)
			if err != nil {
				return Detection{}, false, err
			}
			hasNPMLockfile, err := npmHasLockfileScoped(bounds.absRoot, dir)
			if err != nil {
				return Detection{}, false, err
			}
			if hasUnsupportedLockfile && !hasNPMLockfile {
				return Detection{}, false, nil
			}
		}
		if descriptor.Name == "requirements.txt" {
			if err := validateRequirementsIncludesWithinRoot(bounds.absRoot, manifest); err != nil {
				return Detection{}, false, err
			}
		}
		return Detection{Ecosystem: descriptor.Ecosystem, ScanRoot: bounds.absRoot, ProjectDir: dir, ManifestPath: manifest, InputKind: descriptor.InputKind, DisplayPath: display}, true, nil
	case autoSBOMManifestKindPoetryPyproject:
		ok, err := isPoetryProjectForDetection(bounds.absRoot, manifest)
		if err != nil {
			return Detection{}, false, err
		}
		if ok {
			if err := checkPoetryLockReadable(bounds.absRoot, dir); err != nil {
				return Detection{}, false, err
			}
			return Detection{Ecosystem: descriptor.Ecosystem, ScanRoot: bounds.absRoot, ProjectDir: dir, ManifestPath: manifest, InputKind: descriptor.InputKind, DisplayPath: display}, true, nil
		}
	}
	return Detection{}, false, nil
}

func npmHasUnsupportedLockfileScoped(root, projectDir string) (bool, error) {
	var bounds scanRootBounds
	var err error
	if strings.TrimSpace(root) != "" {
		bounds, err = newScanRootBounds(root)
		if err != nil {
			return false, err
		}
	}
	for _, name := range []string{"pnpm-lock.yaml", "yarn.lock"} {
		path := filepath.Join(projectDir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			if err := bounds.requireExisting(path); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

func relDisplay(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return rel
}

func isPoetryProject(pyproject string) (bool, error) {
	return parsePoetryProject("", pyproject, false)
}

func isPoetryProjectForDetection(root, pyproject string) (bool, error) {
	return parsePoetryProject(root, pyproject, true)
}

func parsePoetryProject(root, pyproject string, strict bool) (bool, error) {
	data, err := readAutoSBOMManifestScoped(root, pyproject)
	if err != nil {
		return false, err
	}
	var doc struct {
		Tool struct {
			Poetry struct {
				Name         string         `toml:"name"`
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		if strict {
			return false, fmt.Errorf("parse %s: %w", pyproject, err)
		}
		return false, nil
	}
	return strings.TrimSpace(doc.Tool.Poetry.Name) != "" || len(doc.Tool.Poetry.Dependencies) > 0, nil
}

func checkPoetryLockReadable(root, projectDir string) error {
	lockPath := filepath.Join(projectDir, "poetry.lock")
	if _, err := readAutoSBOMManifestScoped(root, lockPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", relDisplay(root, lockPath), err)
	}
	return nil
}

func suppressCovered(ds []Detection) ([]Detection, error) {
	suppressed := map[string]struct{}{}
	key := func(ecosystem domain.Ecosystem, dir string) string {
		return string(ecosystem) + "\x00" + filepath.Clean(dir)
	}

	for _, d := range ds {
		switch d.Ecosystem {
		case domain.EcosystemNPM:
			children, err := npmWorkspaceChildren(d)
			if err != nil {
				return nil, err
			}
			for _, child := range children {
				if filepath.Clean(child) != filepath.Clean(d.ProjectDir) {
					suppressed[key(domain.EcosystemNPM, child)] = struct{}{}
				}
			}
		case domain.EcosystemMaven:
			children, err := mavenModuleChildren(d)
			if err != nil {
				return nil, err
			}
			for _, child := range children {
				if filepath.Clean(child) != filepath.Clean(d.ProjectDir) {
					suppressed[key(domain.EcosystemMaven, child)] = struct{}{}
				}
			}
		}
	}

	out := make([]Detection, 0, len(ds))
	for _, d := range ds {
		if _, ok := suppressed[key(d.Ecosystem, d.ProjectDir)]; ok {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

func npmWorkspaceChildren(d Detection) ([]string, error) {
	globs, err := npmWorkspaceGlobs(d.ScanRoot, d.ManifestPath)
	if err != nil {
		return nil, err
	}
	var bounds scanRootBounds
	if strings.TrimSpace(d.ScanRoot) != "" {
		bounds, err = newScanRootBounds(d.ScanRoot)
		if err != nil {
			return nil, err
		}
	}
	children := make([]string, 0, len(globs))
	for _, pattern := range globs {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if err := validateNPMWorkspacePattern(bounds, d.ProjectDir, pattern); err != nil {
			return nil, err
		}
		matches, _ := filepath.Glob(filepath.Join(d.ProjectDir, filepath.FromSlash(pattern)))
		for _, match := range matches {
			if err := bounds.requireDerived(match); err != nil {
				return nil, err
			}
			info, err := os.Stat(match)
			if err == nil && info.IsDir() {
				children = append(children, filepath.Clean(match))
			}
		}
	}
	return children, nil
}

func validateNPMWorkspacePattern(bounds scanRootBounds, projectDir, pattern string) error {
	if !bounds.enabled() {
		return nil
	}
	native := filepath.FromSlash(pattern)
	if filepath.IsAbs(native) {
		return bounds.escapeError(native)
	}
	base := native
	if idx := strings.IndexAny(base, "*?["); idx >= 0 {
		base = base[:idx]
	}
	if strings.TrimSpace(base) == "" {
		base = "."
	}
	return bounds.requireDerived(filepath.Join(projectDir, base))
}

func npmWorkspaceGlobs(root, packageJSON string) ([]string, error) {
	data, err := readAutoSBOMManifestScoped(root, packageJSON)
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil || len(pkg.Workspaces) == 0 {
		return nil, err
	}
	var arr []string
	if err := json.Unmarshal(pkg.Workspaces, &arr); err == nil {
		return arr, nil
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(pkg.Workspaces, &obj); err != nil {
		return nil, err
	}
	return obj.Packages, nil
}

func mavenModuleChildren(d Detection) ([]string, error) {
	return mavenModulesWalk(d.ScanRoot, d.ProjectDir, map[string]struct{}{})
}

func mavenModulesWalk(root, dir string, visited map[string]struct{}) ([]string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = filepath.Clean(dir)
	}
	if _, ok := visited[abs]; ok {
		return nil, nil
	}
	visited[abs] = struct{}{}

	data, err := readAutoSBOMManifestScoped(root, filepath.Join(dir, "pom.xml"))
	if err != nil {
		return nil, err
	}
	var project struct {
		Modules []string `xml:"modules>module"`
	}
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil, nil
	}
	children := make([]string, 0, len(project.Modules))
	for _, module := range project.Modules {
		module = strings.TrimSpace(module)
		if module == "" {
			continue
		}
		child := filepath.Clean(filepath.Join(dir, filepath.FromSlash(module)))
		if strings.TrimSpace(root) != "" {
			bounds, err := newScanRootBounds(root)
			if err != nil {
				return nil, err
			}
			if err := bounds.requireDerived(child); err != nil {
				return nil, err
			}
		}
		children = append(children, child)
		grandchildren, err := mavenModulesWalk(root, child, visited)
		if err != nil {
			return nil, err
		}
		children = append(children, grandchildren...)
	}
	return children, nil
}
