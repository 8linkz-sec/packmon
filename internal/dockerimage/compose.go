package dockerimage

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// composeVarPattern matches a single ${...} Docker Compose interpolation with an
// optional operator (:-, -, :+, +, :?, ?) and its default/argument text.
var composeVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-|-|:\+|\+|:\?|\?)?([^}]*)\}`)

// resolveComposeImageDefault resolves Docker Compose variable interpolation in an
// image reference using only the defaults declared in the file. Every variable
// is treated as unset -- the host environment is intentionally ignored so the
// inventory is deterministic -- so ${VAR:-default} and ${VAR-default} yield
// their default and every other form yields empty. It returns the resolved
// reference and whether it is concrete: non-empty with no interpolation left.
func resolveComposeImageDefault(raw string) (string, bool) {
	resolved := composeVarPattern.ReplaceAllStringFunc(raw, func(match string) string {
		parts := composeVarPattern.FindStringSubmatch(match)
		switch parts[2] {
		case ":-", "-":
			return parts[3] // declared default for the (unset) variable
		default:
			return "" // no usable default -- variable is unset
		}
	})
	resolved = strings.TrimSpace(resolved)
	if resolved == "" || strings.Contains(resolved, "$") {
		return resolved, false
	}
	return resolved, true
}

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
	Image     string
	ImageLine int
	Build     composeBuild
}

func (s *composeService) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Image string       `yaml:"image"`
		Build composeBuild `yaml:"build"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		if value.Content[i].Value == "image" {
			s.ImageLine = value.Content[i+1].Line
			break
		}
	}
	s.Image = raw.Image
	s.Build = raw.Build
	return nil
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

// ParseComposeImages parses service image and local-build metadata from a
// Docker Compose reader. Returned rows are Docker inventory for list-all/report
// surfaces, including source flags such as service, build context, dockerfile,
// and target; they are not server scan inputs.
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
		resolvedImage, resolved := resolveComposeImageDefault(service.Image)
		if !resolved {
			// The image is a variable reference with no declared default (e.g.
			// ${IMAGE} or ${IMAGE:?required}); its concrete value is unknown, so
			// skip its image row but keep inventorying the rest of the file. Fall
			// back to a local build image when the service defines one.
			if hasBuild {
				images = append(images, localBuildImage(sourceFile, serviceName, service.Build))
			}
			continue
		}
		ref, ok := ParseRef(resolvedImage)
		if !ok {
			if service.ImageLine > 0 {
				return nil, fmt.Errorf("%s:%d: invalid image for compose service", sourceFile, service.ImageLine)
			}
			return nil, fmt.Errorf("%s: invalid image for compose service", sourceFile)
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
