package scanner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/parser"
	"github.com/8linkz-sec/packmon/internal/sbom"
)

const maxLockfileSize = 100 << 20

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
	Packages         []domain.Package
	Entries          []CollectedPackage
	ParseErrors      []string
	FatalParseErrors []string
	LockFiles        int
	SBOMFiles        int
	index            map[packageCollectionKey]int
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
		displayPath, packages, skipped, parseErr := parseCollectedSBOM(absRoot, sbomPath)
		if parseErr != nil {
			var inputErr *sbomInputError
			if errors.As(parseErr, &inputErr) {
				return nil, fmt.Errorf("%s: %w", displayPath, inputErr)
			}
			msg := fmt.Sprintf("%s: %v", displayPath, parseErr)
			result.ParseErrors = append(result.ParseErrors, msg)
			result.FatalParseErrors = append(result.FatalParseErrors, msg)
			continue
		}
		for _, item := range skipped {
			result.ParseErrors = append(result.ParseErrors, formatSBOMSkippedComponent(displayPath, item))
		}
		for _, pkg := range packages {
			if !ecoFilter.allows(pkg.Ecosystem) {
				continue
			}
			result.add(pkg, displayPath, "sbom")
		}
	}

	result.filterStaleGoSumVersions()
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
	if info, err := f.Stat(); err != nil {
		return nil, err
	} else if info.Mode().IsRegular() && info.Size() > maxLockfileSize {
		return nil, lockfileSizeLimitError()
	}
	return lf.Parser.Parse(&limitedLockfileReader{
		r: f,
	})
}

type limitedLockfileReader struct {
	r        io.Reader
	read     int64
	overflow bool
}

func (r *limitedLockfileReader) Read(p []byte) (int, error) {
	if r.overflow {
		return 0, lockfileSizeLimitError()
	}
	remainingWithSentinel := maxLockfileSize + 1 - r.read
	if remainingWithSentinel <= 0 {
		r.overflow = true
		return 0, lockfileSizeLimitError()
	}
	if int64(len(p)) > remainingWithSentinel {
		p = p[:int(remainingWithSentinel)]
	}
	n, err := r.r.Read(p)
	if n == 0 {
		return n, err
	}
	previous := r.read
	r.read += int64(n)
	if r.read > maxLockfileSize {
		r.overflow = true
		allowed := int(maxLockfileSize - previous)
		if allowed > 0 {
			return allowed, nil
		}
		return 0, lockfileSizeLimitError()
	}
	return n, err
}

func lockfileSizeLimitError() error {
	return fmt.Errorf("lockfile exceeds maximum lockfile size of %d bytes", maxLockfileSize)
}

func parseCollectedSBOM(root, path string) (string, []domain.Package, []sbom.SkippedComponent, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path, nil, nil, &sbomInputError{err: fmt.Errorf("resolve SBOM path: %w", err)}
	}
	displayPath := displayRelativePath(root, absPath)

	rootDir, fileName := filepath.Split(absPath)
	if rootDir == "" {
		rootDir = "."
	}
	rootHandle, err := os.OpenRoot(rootDir)
	if err != nil {
		return displayPath, nil, nil, &sbomInputError{err: fmt.Errorf("open SBOM root: %w", err)}
	}
	defer closeSilently(rootHandle)

	f, err := rootHandle.Open(fileName)
	if err != nil {
		return displayPath, nil, nil, &sbomInputError{err: fmt.Errorf("open SBOM: %w", err)}
	}
	defer closeSilently(f)

	parsed, err := sbom.Parse(f)
	if err != nil {
		return displayPath, nil, nil, err
	}

	packages := make([]domain.Package, 0, len(parsed.Packages))
	for _, entry := range parsed.Packages {
		packages = append(packages, entry.Package)
	}
	return displayPath, packages, parsed.Skipped, nil
}

func formatSBOMSkippedComponent(path string, item sbom.SkippedComponent) string {
	name := strings.TrimSpace(item.Name)
	reason := strings.TrimSpace(item.Reason)
	switch {
	case name != "" && reason != "":
		return fmt.Sprintf("%s: skipped SBOM component %q: %s", path, name, reason)
	case name != "":
		return fmt.Sprintf("%s: skipped SBOM component %q", path, name)
	case reason != "":
		return fmt.Sprintf("%s: skipped SBOM component: %s", path, reason)
	default:
		return fmt.Sprintf("%s: skipped SBOM component", path)
	}
}

func displayRelativePath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return safeExternalDisplayPath(path)
	}
	return rel
}

func safeExternalDisplayPath(path string) string {
	base := filepath.Base(filepath.Clean(path))
	if strings.TrimSpace(base) == "" || base == "." || base == string(filepath.Separator) {
		return "external-sbom"
	}
	return base
}

type packageCollectionKey struct {
	name      string
	version   string
	ecosystem domain.Ecosystem
}

func (c *PackageCollection) add(pkg domain.Package, sourceFile, sourceType string) {
	c.ensureIndex()
	k := packageCollectionKey{pkg.Name, pkg.Version, pkg.Ecosystem}
	if i, ok := c.index[k]; ok {
		domain.MergePackageMetadata(&c.Entries[i].Package, pkg)
		return
	}
	c.index[k] = len(c.Entries)
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
	c.rebuildIndex()
}

func (c *PackageCollection) filterStaleGoSumVersions() {
	selected := make(map[string]struct{})
	selectedNames := make(map[string]struct{})
	for _, entry := range c.Entries {
		pkg := entry.Package
		if pkg.Ecosystem != domain.EcosystemGo || isGoSumSource(entry.SourceFile) {
			continue
		}
		key := pkg.Name + "@" + pkg.Version
		selected[key] = struct{}{}
		selectedNames[pkg.Name] = struct{}{}
	}
	if len(selectedNames) == 0 {
		return
	}

	out := c.Entries[:0]
	for _, entry := range c.Entries {
		pkg := entry.Package
		if pkg.Ecosystem == domain.EcosystemGo && isGoSumSource(entry.SourceFile) {
			if _, hasSelectedName := selectedNames[pkg.Name]; hasSelectedName {
				if _, selectedVersion := selected[pkg.Name+"@"+pkg.Version]; !selectedVersion {
					continue
				}
			}
		}
		out = append(out, entry)
	}
	c.Entries = out
	c.rebuildIndex()
}

func isGoSumSource(sourceFile string) bool {
	return strings.EqualFold(filepath.Base(filepath.Clean(sourceFile)), "go.sum")
}

func (c *PackageCollection) rebuildPackages() {
	c.Packages = make([]domain.Package, 0, len(c.Entries))
	for _, entry := range c.Entries {
		c.Packages = append(c.Packages, entry.Package)
	}
}

func (c *PackageCollection) ensureIndex() {
	if c.index != nil {
		return
	}
	c.rebuildIndex()
}

func (c *PackageCollection) rebuildIndex() {
	c.index = make(map[packageCollectionKey]int, len(c.Entries))
	for i, entry := range c.Entries {
		pkg := entry.Package
		c.index[packageCollectionKey{pkg.Name, pkg.Version, pkg.Ecosystem}] = i
	}
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
