package sbomgen

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

const (
	autoSBOMManifestSupportPath = "internal/sbomgen/auto_sbom_manifests.tsv"

	autoSBOMManifestKindDetect          autoSBOMManifestKind = "detect"
	autoSBOMManifestKindPoetryPyproject autoSBOMManifestKind = "poetry-pyproject"
	autoSBOMManifestKindSupportFile     autoSBOMManifestKind = "support-file"
	autoSBOMManifestKindUnsupported     autoSBOMManifestKind = "unsupported"
)

//go:embed auto_sbom_manifests.tsv
var autoSBOMManifestSupportData string

type autoSBOMManifestKind string

type autoSBOMManifestDescriptor struct {
	Name           string
	Kind           autoSBOMManifestKind
	Ecosystem      domain.Ecosystem
	InputKind      string
	RequirementIDs []string
}

func autoSBOMManifestDescriptors() []autoSBOMManifestDescriptor {
	descriptors, err := parseAutoSBOMManifestDescriptors(autoSBOMManifestSupportData)
	if err != nil {
		panic(err)
	}
	return descriptors
}

func parseAutoSBOMManifestDescriptors(data string) ([]autoSBOMManifestDescriptor, error) {
	var descriptors []autoSBOMManifestDescriptor
	for lineNo, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 5 {
			return nil, fmt.Errorf("parse %s:%d: expected 5 fields, got %d", autoSBOMManifestSupportPath, lineNo+1, len(fields))
		}
		ecosystem, err := parseAutoSBOMManifestEcosystem(fields[2])
		if err != nil {
			return nil, fmt.Errorf("parse %s:%d: %w", autoSBOMManifestSupportPath, lineNo+1, err)
		}
		descriptor := autoSBOMManifestDescriptor{
			Name:           strings.TrimSpace(fields[0]),
			Kind:           autoSBOMManifestKind(strings.TrimSpace(fields[1])),
			Ecosystem:      ecosystem,
			InputKind:      strings.TrimSpace(fields[3]),
			RequirementIDs: splitCommaFields(fields[4]),
		}
		if descriptor.Name == "" {
			return nil, fmt.Errorf("parse %s:%d: empty manifest name", autoSBOMManifestSupportPath, lineNo+1)
		}
		descriptors = append(descriptors, descriptor)
	}
	return descriptors, nil
}

func parseAutoSBOMManifestEcosystem(raw string) (domain.Ecosystem, error) {
	switch value := strings.ToLower(strings.TrimSpace(raw)); value {
	case "":
		return "", nil
	case string(domain.EcosystemGo):
		return domain.EcosystemGo, nil
	case string(domain.EcosystemNPM):
		return domain.EcosystemNPM, nil
	case string(domain.EcosystemPyPI):
		return domain.EcosystemPyPI, nil
	case string(domain.EcosystemMaven):
		return domain.EcosystemMaven, nil
	default:
		return "", fmt.Errorf("unsupported auto-SBOM ecosystem %q", raw)
	}
}

func splitCommaFields(value string) []string {
	parts := strings.Split(value, ",")
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func autoSBOMDetectManifestNames() map[string]struct{} {
	names := map[string]struct{}{}
	for _, descriptor := range autoSBOMManifestDescriptors() {
		switch descriptor.Kind {
		case autoSBOMManifestKindDetect, autoSBOMManifestKindPoetryPyproject:
			names[descriptor.Name] = struct{}{}
		}
	}
	return names
}

func autoSBOMDetectManifestDescriptor(name string) (autoSBOMManifestDescriptor, bool) {
	for _, descriptor := range autoSBOMManifestDescriptors() {
		switch descriptor.Kind {
		case autoSBOMManifestKindDetect, autoSBOMManifestKindPoetryPyproject:
			if descriptor.Name == name {
				return descriptor, true
			}
		}
	}
	return autoSBOMManifestDescriptor{}, false
}
