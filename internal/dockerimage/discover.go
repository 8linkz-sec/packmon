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

type File struct {
	Path    string
	RelPath string
	Kind    Kind
}

var walkDockerInventoryDir = filepath.WalkDir

func DiscoverFiles(root string, maxDepth int) ([]File, error) {
	files, _, err := DiscoverFilesWithWarnings(root, maxDepth)
	return files, err
}

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
			rel = path
		}
		files = append(files, File{Path: path, RelPath: filepath.ToSlash(rel), Kind: kind})
		return nil
	})
	return files, warnings, err
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
