package sbomgen

import (
	"encoding/json"
	"encoding/xml"
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

// Detect walks root up to maxDepth and returns supported generation targets.
func Detect(root string, maxDepth int) ([]Detection, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	var manifests []string
	err = filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
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
		if det, ok := classifyManifest(absRoot, manifest); ok {
			detections = append(detections, det)
		}
	}
	return suppressCovered(detections), nil
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

func classifyManifest(root, manifest string) (Detection, bool) {
	dir := filepath.Dir(manifest)
	display := relDisplay(root, manifest)
	switch filepath.Base(manifest) {
	case "go.mod":
		return Detection{Ecosystem: "go", ProjectDir: dir, ManifestPath: manifest, InputKind: "go.mod", DisplayPath: display}, true
	case "package.json":
		return Detection{Ecosystem: "npm", ProjectDir: dir, ManifestPath: manifest, InputKind: "npm-package", DisplayPath: display}, true
	case "requirements.txt":
		return Detection{Ecosystem: "pypi", ProjectDir: dir, ManifestPath: manifest, InputKind: "requirements", DisplayPath: display}, true
	case "pom.xml":
		return Detection{Ecosystem: "maven", ProjectDir: dir, ManifestPath: manifest, InputKind: "maven-pom", DisplayPath: display}, true
	case "pyproject.toml":
		if isPoetryProject(manifest) {
			return Detection{Ecosystem: "pypi", ProjectDir: dir, ManifestPath: manifest, InputKind: "poetry", DisplayPath: display}, true
		}
	}
	return Detection{}, false
}

func relDisplay(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return rel
}

func isPoetryProject(pyproject string) bool {
	data, err := os.ReadFile(pyproject) // #nosec G304 -- path comes from a bounded local manifest walk.
	if err != nil {
		return false
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
		return false
	}
	return strings.TrimSpace(doc.Tool.Poetry.Name) != "" || len(doc.Tool.Poetry.Dependencies) > 0
}

func suppressCovered(ds []Detection) []Detection {
	suppressed := map[string]struct{}{}
	key := func(ecosystem, dir string) string {
		return ecosystem + "\x00" + filepath.Clean(dir)
	}

	for _, d := range ds {
		switch d.Ecosystem {
		case "npm":
			for _, child := range npmWorkspaceChildren(d) {
				if filepath.Clean(child) != filepath.Clean(d.ProjectDir) {
					suppressed[key("npm", child)] = struct{}{}
				}
			}
		case "maven":
			for _, child := range mavenModuleChildren(d) {
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
	return out
}

func npmWorkspaceChildren(d Detection) []string {
	globs, err := npmWorkspaceGlobs(d.ManifestPath)
	if err != nil {
		return nil
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
	return children
}

func npmWorkspaceGlobs(packageJSON string) ([]string, error) {
	data, err := os.ReadFile(packageJSON) // #nosec G304 -- path comes from a bounded local manifest walk.
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

func mavenModuleChildren(d Detection) []string {
	return mavenModulesWalk(d.ProjectDir, map[string]struct{}{})
}

func mavenModulesWalk(dir string, visited map[string]struct{}) []string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = filepath.Clean(dir)
	}
	if _, ok := visited[abs]; ok {
		return nil
	}
	visited[abs] = struct{}{}

	data, err := os.ReadFile(filepath.Join(dir, "pom.xml")) // #nosec G304 -- path comes from a bounded local manifest walk.
	if err != nil {
		return nil
	}
	var project struct {
		Modules []string `xml:"modules>module"`
	}
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil
	}
	children := make([]string, 0, len(project.Modules))
	for _, module := range project.Modules {
		module = strings.TrimSpace(module)
		if module == "" {
			continue
		}
		child := filepath.Clean(filepath.Join(dir, filepath.FromSlash(module)))
		children = append(children, child)
		children = append(children, mavenModulesWalk(child, visited)...)
	}
	return children
}
