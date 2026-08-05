package sbomgen

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var errScanRootEscape = errors.New("path escapes scan root")

type scanRootBounds struct {
	absRoot  string
	realRoot string
}

func newScanRootBounds(root string) (scanRootBounds, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return scanRootBounds{}, err
	}
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return scanRootBounds{}, err
	}
	return scanRootBounds{
		absRoot:  filepath.Clean(absRoot),
		realRoot: filepath.Clean(realRoot),
	}, nil
}

func (b scanRootBounds) enabled() bool {
	return strings.TrimSpace(b.absRoot) != ""
}

func (b scanRootBounds) requireExisting(path string) error {
	return b.require(path, true)
}

func (b scanRootBounds) requireDerived(path string) error {
	return b.require(path, false)
}

func (b scanRootBounds) require(path string, existing bool) error {
	if !b.enabled() {
		return nil
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	absPath = filepath.Clean(absPath)
	if !pathWithinRoot(b.absRoot, absPath) {
		return b.escapeError(path)
	}

	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		if existing || !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if !pathWithinRoot(b.realRoot, realPath) {
		return b.escapeError(path)
	}
	return nil
}

func (b scanRootBounds) escapeError(path string) error {
	display := filepath.ToSlash(relDisplay(b.absRoot, path))
	return fmt.Errorf("%s escapes scan root: %w", display, errScanRootEscape)
}

func pathWithinRoot(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	return relWithinRoot(rel)
}

func relWithinRoot(rel string) bool {
	if rel == "." {
		return true
	}
	return rel != ".." &&
		!strings.HasPrefix(rel, ".."+string(filepath.Separator)) &&
		!filepath.IsAbs(rel)
}

func readAutoSBOMManifestScoped(root, path string) ([]byte, error) {
	if strings.TrimSpace(root) == "" {
		return readAutoSBOMManifest(path)
	}
	return readFileLimitedScoped(root, path, maxAutoSBOMManifestBytes, "auto-SBOM manifest")
}

func readFileLimitedScoped(root, path string, maxBytes int, label string) ([]byte, error) {
	bounds, err := newScanRootBounds(root)
	if err != nil {
		return nil, err
	}
	if err := bounds.requireExisting(path); err != nil {
		return nil, err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(bounds.absRoot, absPath)
	if err != nil {
		return nil, err
	}

	rootHandle, err := os.OpenRoot(bounds.absRoot)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rootHandle.Close() }()

	file, err := rootHandle.Open(filepath.Clean(rel))
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	return readOpenedFileLimited(file, filepath.ToSlash(rel), maxBytes, label)
}
