package dockerimage

import (
	"fmt"
	"io"
	"os"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

const maxDockerInventoryFileSize = 16 << 20

type Collection struct {
	Images            []Image
	ParseErrors       []string
	DiscoveryWarnings []string
	Files             int
}

func Collect(root string, maxDepth int) (*Collection, error) {
	files, warnings, err := DiscoverFilesWithWarnings(root, maxDepth)
	if err != nil {
		return nil, err
	}
	result := &Collection{Files: len(files), DiscoveryWarnings: warnings}
	for _, file := range files {
		images, parseErr := parseFile(file)
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
	f, err := os.Open(file.Path)
	if err != nil {
		return nil, err
	}
	defer ioutils.CloseSilently(f)
	if info, err := f.Stat(); err != nil {
		return nil, err
	} else if info.Mode().IsRegular() && info.Size() > maxDockerInventoryFileSize {
		return nil, dockerInventorySizeLimitError()
	}
	r := &limitedDockerInventoryReader{r: f}
	switch file.Kind {
	case KindDockerfile:
		return ParseDockerfileImages(r, file.RelPath)
	case KindCompose:
		return ParseComposeImages(r, file.RelPath)
	default:
		return nil, fmt.Errorf("%s: unsupported docker inventory file kind %q", file.RelPath, file.Kind)
	}
}

type limitedDockerInventoryReader struct {
	r        io.Reader
	read     int64
	overflow bool
}

func (r *limitedDockerInventoryReader) Read(p []byte) (int, error) {
	if r.overflow {
		return 0, dockerInventorySizeLimitError()
	}
	remainingWithSentinel := maxDockerInventoryFileSize + 1 - r.read
	if remainingWithSentinel <= 0 {
		r.overflow = true
		return 0, dockerInventorySizeLimitError()
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
	if r.read > maxDockerInventoryFileSize {
		r.overflow = true
		allowed := int(maxDockerInventoryFileSize - previous)
		if allowed > 0 {
			return allowed, nil
		}
		return 0, dockerInventorySizeLimitError()
	}
	return n, err
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
