package sbomgen

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Detection is one concrete SBOM generation target.
type Detection struct {
	Ecosystem    string
	ProjectDir   string
	ManifestPath string
	InputKind    string
	DisplayPath  string
}

var skipDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"vendor":       {},
	"__pycache__":  {},
}

var walkDir = filepath.WalkDir

// Detect walks root up to maxDepth and returns supported generation targets.
func Detect(root string, maxDepth int) ([]Detection, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

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

		switch d.Name() {
		case "go.mod", "package.json", "requirements.txt", "pyproject.toml", "Pipfile", "pom.xml":
			manifests = append(manifests, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	detections := make([]Detection, 0, len(manifests))
	for _, manifest := range manifests {
		det, ok, err := classifyManifest(absRoot, manifest)
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

func classifyManifest(root, manifest string) (Detection, bool, error) {
	dir := filepath.Dir(manifest)
	display := relDisplay(root, manifest)
	switch filepath.Base(manifest) {
	case "go.mod":
		return Detection{Ecosystem: "go", ProjectDir: dir, ManifestPath: manifest, InputKind: "go.mod", DisplayPath: display}, true, nil
	case "package.json":
		return Detection{Ecosystem: "npm", ProjectDir: dir, ManifestPath: manifest, InputKind: "npm-package", DisplayPath: display}, true, nil
	case "requirements.txt":
		return Detection{Ecosystem: "pypi", ProjectDir: dir, ManifestPath: manifest, InputKind: "requirements", DisplayPath: display}, true, nil
	case "pom.xml":
		return Detection{Ecosystem: "maven", ProjectDir: dir, ManifestPath: manifest, InputKind: "maven-pom", DisplayPath: display}, true, nil
	case "pyproject.toml":
		ok, err := isPoetryProject(manifest)
		if err != nil {
			return Detection{}, false, err
		}
		if ok {
			return Detection{Ecosystem: "pypi", ProjectDir: dir, ManifestPath: manifest, InputKind: "poetry", DisplayPath: display}, true, nil
		}
	}
	return Detection{}, false, nil
}

func relDisplay(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return rel
}

func isPoetryProject(pyproject string) (bool, error) {
	data, err := readAutoSBOMManifest(pyproject)
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
		return false, nil
	}
	return strings.TrimSpace(doc.Tool.Poetry.Name) != "" || len(doc.Tool.Poetry.Dependencies) > 0, nil
}

func suppressCovered(ds []Detection) ([]Detection, error) {
	suppressed := map[string]struct{}{}
	key := func(ecosystem, dir string) string {
		return ecosystem + "\x00" + filepath.Clean(dir)
	}

	for _, d := range ds {
		switch d.Ecosystem {
		case "npm":
			children, err := npmWorkspaceChildren(d)
			if err != nil {
				return nil, err
			}
			for _, child := range children {
				if filepath.Clean(child) != filepath.Clean(d.ProjectDir) {
					suppressed[key("npm", child)] = struct{}{}
				}
			}
		case "maven":
			children, err := mavenModuleChildren(d)
			if err != nil {
				return nil, err
			}
			for _, child := range children {
				if filepath.Clean(child) != filepath.Clean(d.ProjectDir) {
					suppressed[key("maven", child)] = struct{}{}
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
	globs, err := npmWorkspaceGlobs(d.ManifestPath)
	if err != nil {
		return nil, err
	}
	children := make([]string, 0, len(globs))
	for _, pattern := range globs {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(d.ProjectDir, filepath.FromSlash(pattern)))
		for _, match := range matches {
			info, err := os.Stat(match)
			if err == nil && info.IsDir() {
				children = append(children, filepath.Clean(match))
			}
		}
	}
	return children, nil
}

func npmWorkspaceGlobs(packageJSON string) ([]string, error) {
	data, err := readAutoSBOMManifest(packageJSON)
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
	return mavenModulesWalk(d.ProjectDir, map[string]struct{}{})
}

func mavenModulesWalk(dir string, visited map[string]struct{}) ([]string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = filepath.Clean(dir)
	}
	if _, ok := visited[abs]; ok {
		return nil, nil
	}
	visited[abs] = struct{}{}

	data, err := readAutoSBOMManifest(filepath.Join(dir, "pom.xml"))
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
		children = append(children, child)
		grandchildren, err := mavenModulesWalk(child, visited)
		if err != nil {
			return nil, err
		}
		children = append(children, grandchildren...)
	}
	return children, nil
}
