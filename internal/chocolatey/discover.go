package chocolatey

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Kind classifies a discovered inventory input file.
type Kind string

const (
	// KindConfigXML is a candidate `config.xml` package list.
	KindConfigXML Kind = "config-xml"
	// KindScript is a Windows script that may contain `choco install` lines.
	KindScript Kind = "script"
)

// File is a discovered inventory input with its absolute path, display path
// relative to the root, and parser kind.
type File struct {
	Path    string
	RelPath string
	Kind    Kind
}

var walkInventoryDir = filepath.WalkDir

// DiscoverFilesWithWarnings returns candidate Chocolatey inventory files below
// root up to maxDepth and reports non-fatal walk warnings. It skips hidden
// directories except .github plus common dependency caches.
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
	err = walkInventoryDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			warnings = append(warnings, walkWarning(absRoot, path, walkErr))
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
			warnings = append(warnings, walkWarning(absRoot, path, relErr))
			return nil
		}
		relPath, relErr := cleanRelPath(rel)
		if relErr != nil {
			warnings = append(warnings, relErr.Error())
			return nil
		}
		files = append(files, File{Path: path, RelPath: filepath.ToSlash(relPath), Kind: kind})
		return nil
	})
	return files, warnings, err
}

func classifyFile(base string) (Kind, bool) {
	lower := strings.ToLower(base)
	if lower == "config.xml" {
		return KindConfigXML, true
	}
	switch filepath.Ext(lower) {
	case ".ps1", ".psm1", ".bat", ".cmd":
		return KindScript, true
	}
	return "", false
}

func cleanRelPath(rel string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || !filepath.IsLocal(clean) {
		return "", fmt.Errorf("%s: escapes scan root", relDisplay(rel))
	}
	return clean, nil
}

// relDisplay renders a repository-relative path for warnings without ever
// exposing absolute host paths.
func relDisplay(rel string) string {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if strings.TrimSpace(clean) == "" || clean == "." {
		return "chocolatey-inventory-file"
	}
	if filepath.IsAbs(clean) {
		base := filepath.Base(clean)
		if strings.TrimSpace(base) == "" || base == "." || base == string(filepath.Separator) {
			return "chocolatey-inventory-file"
		}
		return filepath.ToSlash(base)
	}
	return filepath.ToSlash(clean)
}

// walkWarning renders a walk failure for the warnings list. The display path
// is always root-relative: the root itself is shown as ".", and paths outside
// the root (which WalkDir never yields, but a hook might) fall back to their
// base name so no absolute host path can leak.
func walkWarning(root, path string, cause error) string {
	display := relDisplay(filepath.Base(path))
	if rel, err := filepath.Rel(root, path); err == nil {
		switch {
		case rel == ".":
			display = "."
		case rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)):
			display = filepath.ToSlash(rel)
		}
	}
	return fmt.Sprintf("%s: %v", display, unwrapPathError(cause))
}

// unwrapPathError strips the path from a *fs.PathError so callers can render
// their own repository-relative display path exactly once.
func unwrapPathError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}
