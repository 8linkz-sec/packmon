package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/parser"
	"github.com/8linkz/packmon/internal/sbom"
)

// CollectConfig controls lockfile and SBOM package collection.
type CollectConfig struct {
	Registry   *parser.Registry
	Root       string
	MaxDepth   int
	Ecosystems []string
	SBOMFiles  []string
	IncludeDev bool
}

// CollectedPackage keeps package identity together with the input file that
// produced it.
type CollectedPackage struct {
	Package    domain.Package
	SourceFile string
	SourceType string
}

// PackageCollection is the result of package collection from all configured
// inputs.
type PackageCollection struct {
	Packages    []domain.Package
	Entries     []CollectedPackage
	ParseErrors []string
	LockFiles   int
	SBOMFiles   int
}

// CollectPackages walks lockfiles under the root and parses explicit SBOM
// files, then returns deduplicated packages.
func CollectPackages(cfg CollectConfig) (*PackageCollection, error) {
	reg := cfg.Registry
	if reg == nil {
		reg = parser.NewRegistry()
	}

	root := cfg.Root
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	result := &PackageCollection{}
	ecoFilter := ecosystemFilter(cfg.Ecosystems)

	walker := NewWalker(reg, cfg.MaxDepth, cfg.Ecosystems)
	lockFiles, err := walker.Walk(absRoot)
	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}
	result.LockFiles = len(lockFiles)

	for _, lf := range lockFiles {
		pkgs, parseErr := parseCollectedLockFile(lf)
		if parseErr != nil {
			result.ParseErrors = append(result.ParseErrors, fmt.Sprintf("%s: %v", lf.RelPath, parseErr))
			continue
		}
		for _, pkg := range pkgs {
			if !ecoFilter.allows(pkg.Ecosystem) {
				continue
			}
			result.add(pkg, lf.RelPath, "lockfile")
		}
	}

	for _, sbomPath := range cfg.SBOMFiles {
		if strings.TrimSpace(sbomPath) == "" {
			continue
		}
		result.SBOMFiles++
		displayPath, packages, parseErr := parseCollectedSBOM(absRoot, sbomPath)
		if parseErr != nil {
			var inputErr *sbomInputError
			if errors.As(parseErr, &inputErr) {
				return nil, fmt.Errorf("%s: %w", displayPath, inputErr)
			}
			result.ParseErrors = append(result.ParseErrors, fmt.Sprintf("%s: %v", displayPath, parseErr))
			continue
		}
		for _, pkg := range packages {
			if !ecoFilter.allows(pkg.Ecosystem) {
				continue
			}
			result.add(pkg, displayPath, "sbom")
		}
	}

	if !cfg.IncludeDev {
		result.filterDev()
	}
	result.rebuildPackages()
	return result, nil
}

type sbomInputError struct {
	err error
}

func (e *sbomInputError) Error() string {
	return e.err.Error()
}

func (e *sbomInputError) Unwrap() error {
	return e.err
}

func parseCollectedLockFile(lf LockFile) ([]domain.Package, error) {
	f, err := os.Open(lf.Path)
	if err != nil {
		return nil, err
	}
	defer closeSilently(f)
	return lf.Parser.Parse(f)
}

func parseCollectedSBOM(root, path string) (string, []domain.Package, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path, nil, &sbomInputError{err: fmt.Errorf("resolve SBOM path: %w", err)}
	}
	displayPath := displayRelativePath(root, absPath)

	rootDir, fileName := filepath.Split(absPath)
	if rootDir == "" {
		rootDir = "."
	}
	rootHandle, err := os.OpenRoot(rootDir)
	if err != nil {
		return displayPath, nil, &sbomInputError{err: fmt.Errorf("open SBOM root: %w", err)}
	}
	defer closeSilently(rootHandle)

	f, err := rootHandle.Open(fileName)
	if err != nil {
		return displayPath, nil, &sbomInputError{err: fmt.Errorf("open SBOM: %w", err)}
	}
	defer closeSilently(f)

	parsed, err := sbom.Parse(f)
	if err != nil {
		return displayPath, nil, err
	}

	packages := make([]domain.Package, 0, len(parsed.Packages))
	for _, entry := range parsed.Packages {
		packages = append(packages, entry.Package)
	}
	return displayPath, packages, nil
}

func displayRelativePath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return path
	}
	return rel
}

type packageCollectionKey struct {
	name      string
	version   string
	ecosystem domain.Ecosystem
}

func (c *PackageCollection) add(pkg domain.Package, sourceFile, sourceType string) {
	k := packageCollectionKey{pkg.Name, pkg.Version, pkg.Ecosystem}
	for i, entry := range c.Entries {
		existing := entry.Package
		if (packageCollectionKey{existing.Name, existing.Version, existing.Ecosystem}) != k {
			continue
		}
		mergeCollectedPackageMetadata(&c.Entries[i].Package, pkg)
		return
	}
	c.Entries = append(c.Entries, CollectedPackage{
		Package:    pkg,
		SourceFile: sourceFile,
		SourceType: sourceType,
	})
}

func (c *PackageCollection) filterDev() {
	out := c.Entries[:0]
	for _, entry := range c.Entries {
		if !entry.Package.Dev {
			out = append(out, entry)
		}
	}
	c.Entries = out
}

func (c *PackageCollection) rebuildPackages() {
	c.Packages = make([]domain.Package, 0, len(c.Entries))
	for _, entry := range c.Entries {
		c.Packages = append(c.Packages, entry.Package)
	}
}

func mergeCollectedPackageMetadata(dst *domain.Package, src domain.Package) {
	if dst.Dev && !src.Dev {
		dst.Dev = false
	}
	dst.Direct = dst.Direct || src.Direct
	dst.Indirect = dst.Indirect || src.Indirect
	dst.Optional = dst.Optional || src.Optional
	dst.Peer = dst.Peer || src.Peer
	dst.Via = mergeCollectedStringSet(dst.Via, src.Via)
}

func mergeCollectedStringSet(left, right []string) []string {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(left)+len(right))
	for _, value := range left {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	for _, value := range right {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

type ecosystemNameFilter map[string]struct{}

func ecosystemFilter(ecosystems []string) ecosystemNameFilter {
	if len(ecosystems) == 0 {
		return nil
	}
	filter := make(ecosystemNameFilter, len(ecosystems))
	for _, eco := range ecosystems {
		if trimmed := strings.ToLower(strings.TrimSpace(eco)); trimmed != "" {
			filter[trimmed] = struct{}{}
		}
	}
	return filter
}

func (f ecosystemNameFilter) allows(eco domain.Ecosystem) bool {
	if len(f) == 0 {
		return true
	}
	_, ok := f[strings.ToLower(string(eco))]
	return ok
}
