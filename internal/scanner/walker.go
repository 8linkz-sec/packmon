// Package scanner provides directory walking and orchestration for
// dependency scanning.
package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/8linkz/packmon/internal/parser"
)

// LockFile represents a discovered lock file on disk.
type LockFile struct {
	// Path is the absolute path to the lock file.
	Path string
	// RelPath is the path relative to the walk root.
	RelPath string
	// Parser is the parser that can handle this file.
	Parser parser.Parser
}

// Walker recursively searches a directory tree for lock files that can be
// parsed by the provided registry.
type Walker struct {
	registry   *parser.Registry
	maxDepth   int
	ecosystems map[string]struct{} // nil means all
}

// NewWalker creates a Walker. If ecosystems is empty, all ecosystems are
// included.
func NewWalker(reg *parser.Registry, maxDepth int, ecosystems []string) *Walker {
	var ecoFilter map[string]struct{}
	if len(ecosystems) > 0 {
		ecoFilter = make(map[string]struct{}, len(ecosystems))
		for _, e := range ecosystems {
			ecoFilter[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
		}
	}
	return &Walker{
		registry:   reg,
		maxDepth:   maxDepth,
		ecosystems: ecoFilter,
	}
}

// Walk discovers lock files under root up to maxDepth levels deep.
// It skips hidden directories (starting with ".") and common vendor/node_modules
// directories.
func (w *Walker) Walk(root string) ([]LockFile, error) {
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

	var files []LockFile
	rootDepth := strings.Count(filepath.ToSlash(absRoot), "/")

	err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Skip directories we cannot read.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			name := d.Name()
			// Skip hidden directories except .github, where workflow dependency
			// references live.
			if name != "." && name != ".github" && strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			if name == "node_modules" || name == "vendor" || name == "__pycache__" {
				return fs.SkipDir
			}
			// Enforce max depth.
			depth := strings.Count(filepath.ToSlash(path), "/") - rootDepth
			if depth > w.maxDepth {
				return fs.SkipDir
			}
			return nil
		}

		p := w.registry.ParserFor(path)
		if p == nil {
			return nil
		}

		// Apply ecosystem filter.
		if w.ecosystems != nil {
			eco := strings.ToLower(string(p.Ecosystem()))
			if _, ok := w.ecosystems[eco]; !ok {
				return nil
			}
		}

		rel, relErr := filepath.Rel(absRoot, path)
		if relErr != nil {
			rel = path
		}

		files = append(files, LockFile{
			Path:    path,
			RelPath: filepath.ToSlash(rel),
			Parser:  p,
		})
		return nil
	})

	return files, err
}
