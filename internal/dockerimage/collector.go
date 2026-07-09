package dockerimage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

const maxDockerInventoryFileSize = 16 << 20

// Collection is the bounded Docker inventory discovered for list-all/report
// output. It is report metadata only; Docker rows must not be sent to
// /api/v1/check as vulnerability-scan inputs.
type Collection struct {
	Images            []Image
	ParseErrors       []string
	DiscoveryWarnings []string
	Files             int
}

// Collect discovers Dockerfiles and Compose files below root, parses image
// references up to maxDepth, records per-file parse errors and discovery
// warnings, and enforces the Docker inventory file-size cap.
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
		images, parseErr := parseFileFromRoot(rootHandle, file)
		if parseErr != nil {
			result.ParseErrors = append(result.ParseErrors, parseErr.Error())
			continue
		}
		result.Images = append(result.Images, images...)
	}
	result.Images = dedupImages(result.Images)
	return result, nil
}

func parseFile(file File) ([]Image, error) {
	relPath, err := cleanDockerInventoryRelPath(file.RelPath)
	if err != nil {
		return nil, err
	}
	rootPath, err := impliedDockerInventoryRoot(file.Path, relPath)
	if err != nil {
		return nil, err
	}
	rootHandle, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer ioutils.CloseSilently(rootHandle)
	return parseFileFromRoot(rootHandle, File{Path: file.Path, RelPath: filepath.ToSlash(relPath), Kind: file.Kind})
}

func parseFileFromRoot(root *os.Root, file File) ([]Image, error) {
	relPath, err := cleanDockerInventoryRelPath(file.RelPath)
	if err != nil {
		return nil, err
	}
	file.RelPath = filepath.ToSlash(relPath)
	f, err := root.Open(relPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file.RelPath, err)
	}
	return parseOpenedFile(f, file)
}

func impliedDockerInventoryRoot(path, relPath string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	root := filepath.Clean(absPath)
	for _, part := range strings.Split(relPath, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		root = filepath.Dir(root)
	}
	return root, nil
}

func parseOpenedFile(f *os.File, file File) ([]Image, error) {
	defer ioutils.CloseSilently(f)
	if info, err := f.Stat(); err != nil {
		return nil, err
	} else if info.Mode().IsRegular() && info.Size() > maxDockerInventoryFileSize {
		return nil, dockerInventorySizeLimitError()
	}
	r := ioutils.NewSizeLimitReader(f, maxDockerInventoryFileSize, dockerInventorySizeLimitError)
	switch file.Kind {
	case KindDockerfile:
		return ParseDockerfileImages(r, file.RelPath)
	case KindCompose:
		return ParseComposeImages(r, file.RelPath)
	default:
		return nil, fmt.Errorf("%s: unsupported docker inventory file kind %q", file.RelPath, file.Kind)
	}
}

func dockerInventorySizeLimitError() error {
	return fmt.Errorf("docker inventory file exceeds maximum docker inventory size of %d bytes", maxDockerInventoryFileSize)
}

func dedupImages(images []Image) []Image {
	seen := make(map[string]int, len(images))
	out := make([]Image, 0, len(images))
	for _, image := range images {
		key := image.Ref.Name + "@" + image.Ref.Reference + "|" + image.SourceFile + "|" + image.Relation
		if idx, ok := seen[key]; ok {
			out[idx].Flags = mergeStrings(out[idx].Flags, image.Flags)
			out[idx].LocalBuild = out[idx].LocalBuild || image.LocalBuild
			continue
		}
		seen[key] = len(out)
		out = append(out, image)
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
