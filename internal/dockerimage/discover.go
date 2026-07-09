package dockerimage

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Kind string

const (
	KindDockerfile Kind = "dockerfile"
	KindCompose    Kind = "compose"
)

// File is a discovered Docker inventory input with its absolute path, display
// path relative to the root, and parser kind.
type File struct {
	Path    string
	RelPath string
	Kind    Kind
}

var walkDockerInventoryDir = filepath.WalkDir

// DiscoverFilesWithWarnings returns Docker inventory files below root up to
// maxDepth and reports non-fatal walk warnings. It skips hidden directories
// except .github plus common dependency caches such as node_modules, vendor,
// and __pycache__.
func DiscoverFilesWithWarnings(root string, maxDepth int) ([]File, []string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, &fs.PathError{Op: "walk", Path: absRoot, Err: fs.ErrInvalid}
	}

	rootDepth := strings.Count(filepath.ToSlash(absRoot), "/")
	var files []File
	var warnings []string
	err = walkDockerInventoryDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			warnings = append(warnings, dockerInventoryWalkWarning(absRoot, path, walkErr))
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name != "." && name != ".github" && strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			if name == "node_modules" || name == "vendor" || name == "__pycache__" {
				return fs.SkipDir
			}
			depth := strings.Count(filepath.ToSlash(path), "/") - rootDepth
			if depth > maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		kind, ok := classifyFile(filepath.Base(path))
		if !ok {
			return nil
		}
		rel, relErr := filepath.Rel(absRoot, path)
		if relErr != nil {
			warnings = append(warnings, dockerInventoryWalkWarning(absRoot, path, relErr))
			return nil
		}
		relPath, relErr := cleanDockerInventoryRelPath(rel)
		if relErr != nil {
			warnings = append(warnings, relErr.Error())
			return nil
		}
		files = append(files, File{Path: path, RelPath: filepath.ToSlash(relPath), Kind: kind})
		return nil
	})
	return files, warnings, err
}

func cleanDockerInventoryRelPath(rel string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || !filepath.IsLocal(clean) {
		return "", fmt.Errorf("%s: escapes scan root", dockerInventoryRelDisplay(rel))
	}
	return clean, nil
}

func dockerInventoryRelDisplay(rel string) string {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if strings.TrimSpace(clean) == "" || clean == "." {
		return "docker-inventory-file"
	}
	if filepath.IsAbs(clean) {
		base := filepath.Base(clean)
		if strings.TrimSpace(base) == "" || base == "." || base == string(filepath.Separator) {
			return "docker-inventory-file"
		}
		return filepath.ToSlash(base)
	}
	return filepath.ToSlash(clean)
}

func dockerInventoryWalkWarning(root, path string, cause error) string {
	display := filepath.ToSlash(path)
	if rel, err := filepath.Rel(root, path); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
		display = filepath.ToSlash(rel)
	}
	if pathErr, ok := cause.(*fs.PathError); ok {
		return fmt.Sprintf("%s: %v", display, pathErr.Err)
	}
	return fmt.Sprintf("%s: %v", display, cause)
}

func classifyFile(base string) (Kind, bool) {
	lower := strings.ToLower(base)
	switch lower {
	case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
		return KindCompose, true
	}
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		return KindDockerfile, true
	}
	return "", false
}
