package dockerimage

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

type composeFile struct {
	Services []composeServiceEntry
}

type composeServiceEntry struct {
	Name    string
	Service composeService
}

func (f *composeFile) UnmarshalYAML(value *yaml.Node) error {
	for i := 0; i+1 < len(value.Content); i += 2 {
		if value.Content[i].Value != "services" {
			continue
		}
		services := value.Content[i+1]
		for j := 0; j+1 < len(services.Content); j += 2 {
			var service composeService
			if err := services.Content[j+1].Decode(&service); err != nil {
				return err
			}
			f.Services = append(f.Services, composeServiceEntry{
				Name:    services.Content[j].Value,
				Service: service,
			})
		}
	}
	return nil
}

type composeService struct {
	Image string       `yaml:"image"`
	Build composeBuild `yaml:"build"`
}

type composeBuild struct {
	Present    bool
	Context    string
	Dockerfile string
	Target     string
}

func (b *composeBuild) UnmarshalYAML(value *yaml.Node) error {
	b.Present = true
	if value.Kind == yaml.ScalarNode {
		b.Context = strings.TrimSpace(value.Value)
		return nil
	}
	var raw struct {
		Context    string `yaml:"context"`
		Dockerfile string `yaml:"dockerfile"`
		Target     string `yaml:"target"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	b.Context = strings.TrimSpace(raw.Context)
	b.Dockerfile = strings.TrimSpace(raw.Dockerfile)
	b.Target = strings.TrimSpace(raw.Target)
	return nil
}

func ParseComposeImages(r io.Reader, sourceFile string) ([]Image, error) {
	var doc composeFile
	if err := yaml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: parse compose YAML: %w", sourceFile, err)
	}
	var images []Image
	for _, entry := range doc.Services {
		serviceName := entry.Name
		service := entry.Service
		hasBuild := service.Build.Present
		if strings.TrimSpace(service.Image) == "" {
			if hasBuild {
				images = append(images, localBuildImage(sourceFile, serviceName, service.Build))
			}
			continue
		}
		ref, ok := ParseRef(service.Image)
		if !ok {
			return nil, fmt.Errorf("%s: invalid image for service %s: %q", sourceFile, serviceName, service.Image)
		}
		flags := []string{"service=" + serviceName}
		if hasBuild {
			flags = composeBuildFlags(serviceName, service.Build)
		}
		images = append(images, Image{
			Ref:        ref,
			SourceFile: sourceFile,
			SourceType: SourceCompose,
			Scope:      "runtime",
			Relation:   "compose",
			Direct:     true,
			LocalBuild: hasBuild,
			Flags:      flags,
		})
	}
	return images, nil
}

func localBuildImage(sourceFile, serviceName string, build composeBuild) Image {
	reference := serviceName
	if build.Target != "" {
		reference = build.Target
	}
	return Image{
		Ref: Ref{
			Original:   serviceName,
			Name:       "local/" + serviceName,
			Registry:   "",
			Repository: serviceName,
			Reference:  reference,
		},
		SourceFile: sourceFile,
		SourceType: SourceCompose,
		Scope:      "runtime",
		Relation:   "compose-build",
		Direct:     true,
		LocalBuild: true,
		Flags:      composeBuildFlags(serviceName, build),
	}
}

func composeBuildFlags(serviceName string, build composeBuild) []string {
	flags := []string{"service=" + serviceName, "local-build"}
	if build.Context != "" {
		flags = append(flags, "context="+build.Context)
	}
	if build.Dockerfile != "" {
		flags = append(flags, "dockerfile="+build.Dockerfile)
	}
	if build.Target != "" {
		flags = append(flags, "target="+build.Target)
	}
	return flags
}
