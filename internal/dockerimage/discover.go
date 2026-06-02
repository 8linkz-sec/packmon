package dockerimage

import (
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

func DiscoverFiles(root string, maxDepth int) ([]File, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &fs.PathError{Op: "walk", Path: absRoot, Err: fs.ErrInvalid}
	}

	rootDepth := strings.Count(filepath.ToSlash(absRoot), "/")
	var files []File
	err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
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
	return files, err
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
