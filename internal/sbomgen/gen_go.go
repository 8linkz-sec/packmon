package sbomgen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
)

type goGenerator struct{}

func (goGenerator) Ecosystem() string { return "go" }
func (goGenerator) Tool() string      { return "go" }
func (goGenerator) InstallSpec() InstallSpec {
	return InstallSpec{
		Package: "go",
		Source:  "Go toolchain",
	}
}

func (goGenerator) Generate(ctx context.Context, d Detection, outPath string, opts GenerateOptions, run RunnerFunc) error {
	out, err := run(ctx, RunOptions{
		Name: "go",
		Args: []string{"list", "-mod=readonly", "-m", "-json", "all"},
		Dir:  d.ProjectDir,
		Env:  []string{"GOWORK=off"},
	})
	if err != nil {
		return fmt.Errorf("go list modules: %w: %s", err, commandOutputSummary(out))
	}
	return writeGoListCycloneDX(outPath, out)
}

func (goGenerator) DeclaresDependencies(d Detection, _ GenerateOptions) (bool, error) {
	data, err := readAutoSBOMManifest(d.ManifestPath)
	if err != nil {
		return false, err
	}
	file, err := modfile.Parse(d.ManifestPath, data, nil)
	if err != nil {
		return false, err
	}
	return len(file.Require) > 0, nil
}

type goListModule struct {
	Path     string `json:"Path"`
	Version  string `json:"Version"`
	Main     bool   `json:"Main"`
	Indirect bool   `json:"Indirect"`
	Replace  *struct {
		Path    string `json:"Path"`
		Version string `json:"Version"`
	} `json:"Replace,omitempty"`
}

type goCycloneDXBOM struct {
	BOMFormat    string                     `json:"bomFormat"`
	SpecVersion  string                     `json:"specVersion"`
	Version      int                        `json:"version"`
	Metadata     goCycloneDXMetadata        `json:"metadata"`
	Components   []goCycloneDXComponent     `json:"components"`
	Dependencies []goCycloneDXDependencyRef `json:"dependencies"`
}

type goCycloneDXMetadata struct {
	Timestamp string               `json:"timestamp"`
	Component goCycloneDXComponent `json:"component"`
	Tools     []goCycloneDXTool    `json:"tools,omitempty"`
}

type goCycloneDXTool struct {
	Vendor string `json:"vendor"`
	Name   string `json:"name"`
}

type goCycloneDXComponent struct {
	Type       string                `json:"type"`
	Name       string                `json:"name"`
	Version    string                `json:"version,omitempty"`
	BOMRef     string                `json:"bom-ref"`
	PURL       string                `json:"purl,omitempty"`
	Properties []goCycloneDXProperty `json:"properties,omitempty"`
}

type goCycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type goCycloneDXDependencyRef struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

func writeGoListCycloneDX(outPath string, data []byte) error {
	modules, err := parseGoListModules(data)
	if err != nil {
		return err
	}
	bom, err := buildGoListCycloneDX(modules)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Go CycloneDX: %w", err)
	}
	if err := os.WriteFile(outPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write Go CycloneDX %s: %w", outPath, err)
	}
	return nil
}

func parseGoListModules(data []byte) ([]goListModule, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var modules []goListModule
	for decoder.More() {
		var module goListModule
		if err := decoder.Decode(&module); err != nil {
			return nil, fmt.Errorf("parse go list module JSON: %w", err)
		}
		modules = append(modules, module)
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("go list returned no modules")
	}
	return modules, nil
}

func buildGoListCycloneDX(modules []goListModule) (goCycloneDXBOM, error) {
	root := strings.TrimSpace(modules[0].Path)
	if root == "" {
		return goCycloneDXBOM{}, fmt.Errorf("go list main module path is empty")
	}
	rootRef := "pkg:golang/" + purlPath(root)
	bom := goCycloneDXBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: goCycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: goCycloneDXComponent{
				Type:   "application",
				Name:   root,
				BOMRef: rootRef,
				PURL:   rootRef,
			},
			Tools: []goCycloneDXTool{{Vendor: "Go", Name: "go list"}},
		},
		Dependencies: []goCycloneDXDependencyRef{{Ref: rootRef}},
	}
	seen := map[string]struct{}{}
	for _, module := range modules {
		if module.Main {
			continue
		}
		path, version, properties := goModuleCycloneDXIdentity(module)
		if path == "" || version == "" {
			continue
		}
		purl := "pkg:golang/" + purlPath(path) + "@" + version
		if _, ok := seen[purl]; ok {
			continue
		}
		seen[purl] = struct{}{}
		bom.Components = append(bom.Components, goCycloneDXComponent{
			Type:       "library",
			Name:       path,
			Version:    version,
			BOMRef:     purl,
			PURL:       purl,
			Properties: properties,
		})
		if !module.Indirect {
			bom.Dependencies[0].DependsOn = append(bom.Dependencies[0].DependsOn, purl)
		}
	}
	return bom, nil
}

func goModuleCycloneDXIdentity(module goListModule) (path, version string, properties []goCycloneDXProperty) {
	path = strings.TrimSpace(module.Path)
	version = strings.TrimSpace(module.Version)
	if module.Replace == nil {
		return path, version, nil
	}

	replacePath := strings.TrimSpace(module.Replace.Path)
	replaceVersion := strings.TrimSpace(module.Replace.Version)
	if replacePath == "" {
		return path, version, nil
	}

	properties = append(properties,
		goCycloneDXProperty{Name: "packmon:go:original_path", Value: path},
		goCycloneDXProperty{Name: "packmon:go:replace_path", Value: replacePath},
	)
	if version != "" {
		properties = append(properties, goCycloneDXProperty{Name: "packmon:go:original_version", Value: version})
	}
	if replaceVersion != "" {
		properties = append(properties, goCycloneDXProperty{Name: "packmon:go:replace_version", Value: replaceVersion})
	}

	if replaceVersion == "" || isLocalGoReplacementPath(replacePath) {
		properties = append(properties, goCycloneDXProperty{Name: "packmon:go:replacement_kind", Value: "local"})
		return path, version, properties
	}

	properties = append(properties, goCycloneDXProperty{Name: "packmon:go:replacement_kind", Value: "module"})
	return replacePath, replaceVersion, properties
}

func isLocalGoReplacementPath(path string) bool {
	path = strings.TrimSpace(path)
	return strings.HasPrefix(path, "./") ||
		strings.HasPrefix(path, "../") ||
		strings.HasPrefix(path, "/") ||
		strings.HasPrefix(path, `.\`) ||
		strings.HasPrefix(path, `..\`) ||
		strings.Contains(path, `:\`)
}

func purlPath(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}
