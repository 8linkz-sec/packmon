package chocolatey

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

const (
	// maxConfigFileSize bounds a config.xml package list.
	maxConfigFileSize = 16 << 20
	// maxScriptFileSize bounds a script scanned for choco install lines. Scripts
	// are matched by extension only, so the cap is deliberately tighter.
	maxScriptFileSize = 1 << 20
)

// Collection is the bounded Chocolatey inventory discovered for list-all
// output. It is report metadata only; Chocolatey rows must not be sent to
// /api/v1/check as vulnerability-scan inputs.
type Collection struct {
	Packages          []Package
	ParseErrors       []string
	DiscoveryWarnings []string
	Files             int
}

// Collect discovers config.xml package lists and Windows scripts below root up
// to maxDepth, parses Chocolatey package declarations, records per-file parse
// errors and discovery warnings, and enforces the inventory file-size caps.
func Collect(root string, maxDepth int) (*Collection, error) {
	files, warnings, err := DiscoverFilesWithWarnings(root, maxDepth)
	if err != nil {
		return nil, err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	rootHandle, err := os.OpenRoot(absRoot)
	if err != nil {
		return nil, err
	}
	defer ioutils.CloseSilently(rootHandle)

	result := &Collection{Files: len(files), DiscoveryWarnings: warnings}
	for _, file := range files {
		packages, parseErr := parseFileFromRoot(rootHandle, file)
		if parseErr != nil {
			result.ParseErrors = append(result.ParseErrors, parseErr.Error())
			continue
		}
		result.Packages = append(result.Packages, packages...)
	}
	result.Packages = dedupPackages(result.Packages)
	return result, nil
}

func parseFileFromRoot(root *os.Root, file File) ([]Package, error) {
	relPath, err := cleanRelPath(file.RelPath)
	if err != nil {
		return nil, err
	}
	file.RelPath = filepath.ToSlash(relPath)
	f, err := root.Open(relPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file.RelPath, err)
	}
	defer ioutils.CloseSilently(f)

	limit := int64(maxScriptFileSize)
	if file.Kind == KindConfigXML {
		limit = maxConfigFileSize
	}
	sizeErr := func() error {
		return fmt.Errorf("%s: chocolatey inventory file exceeds maximum size of %d bytes", file.RelPath, limit)
	}
	if info, err := f.Stat(); err != nil {
		return nil, fmt.Errorf("%s: %w", file.RelPath, err)
	} else if !info.Mode().IsRegular() {
		return nil, nil
	} else if info.Size() > limit {
		return nil, sizeErr()
	}
	r := ioutils.NewSizeLimitReader(f, limit, sizeErr)
	switch file.Kind {
	case KindConfigXML:
		return ParseConfigXML(r, file.RelPath)
	case KindScript:
		return ParseScript(r, file.RelPath)
	default:
		return nil, fmt.Errorf("%s: unsupported chocolatey inventory file kind %q", file.RelPath, file.Kind)
	}
}

func dedupPackages(packages []Package) []Package {
	seen := make(map[string]int, len(packages))
	out := make([]Package, 0, len(packages))
	for _, pkg := range packages {
		key := pkg.Name + "@" + pkg.Version + "|" + pkg.SourceFile
		if idx, ok := seen[key]; ok {
			out[idx].Flags = mergeStrings(out[idx].Flags, pkg.Flags)
			continue
		}
		seen[key] = len(out)
		out = append(out, pkg)
	}
	return out
}

func mergeStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, values := range [][]string{a, b} {
		for _, value := range values {
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}
