package dockerimage

import (
	"fmt"
	"os"
)

type Collection struct {
	Images      []Image
	ParseErrors []string
	Files       int
}

func Collect(root string, maxDepth int) (*Collection, error) {
	files, err := DiscoverFiles(root, maxDepth)
	if err != nil {
		return nil, err
	}
	result := &Collection{Files: len(files)}
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
	defer f.Close()
	switch file.Kind {
	case KindDockerfile:
		return ParseDockerfileImages(f, file.RelPath)
	case KindCompose:
		return ParseComposeImages(f, file.RelPath)
	default:
		return nil, fmt.Errorf("%s: unsupported docker inventory file kind %q", file.RelPath, file.Kind)
	}
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
