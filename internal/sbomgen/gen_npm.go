package sbomgen

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

type npmGenerator struct{}

func (npmGenerator) Ecosystem() domain.Ecosystem { return domain.EcosystemNPM }
func (npmGenerator) Tool() string                { return "cyclonedx-npm" }
func (npmGenerator) InstallSpec() InstallSpec {
	return InstallSpec{
		Package:         "@cyclonedx/cyclonedx-npm",
		Source:          "npm registry",
		Args:            []string{"npm", "install", "--global", "--ignore-scripts", "@cyclonedx/cyclonedx-npm@" + npmGeneratorVersion},
		ExpectedVersion: npmGeneratorVersion,
		VersionArgs:     []string{"--version"},
		CanAutoInstall:  true,
	}
}

func (npmGenerator) Generate(ctx context.Context, d Detection, outPath string, opts GenerateOptions, run RunnerFunc) error {
	args := []string{"--output-format", "JSON", "--output-file", outPath}
	hasLockfile, err := npmHasLockfileScoped(d.ScanRoot, d.ProjectDir)
	if err != nil {
		return err
	}
	if hasLockfile {
		args = append(args, "--package-lock-only")
	}
	if !opts.IncludeDev {
		args = append(args, "--omit", "dev")
	}
	args = append(args, "--", d.ManifestPath)
	out, err := run(ctx, RunOptions{Name: "cyclonedx-npm", Args: args})
	if err != nil {
		return fmt.Errorf("cyclonedx-npm: %w: %s", err, commandOutputSummary(out))
	}
	return nil
}

func npmHasLockfileScoped(root, projectDir string) (bool, error) {
	var bounds scanRootBounds
	var err error
	if strings.TrimSpace(root) != "" {
		bounds, err = newScanRootBounds(root)
		if err != nil {
			return false, err
		}
	}
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		path := filepath.Join(projectDir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			if err := bounds.requireExisting(path); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

func (npmGenerator) DeclaresDependencies(d Detection, opts GenerateOptions) (bool, error) {
	declares, err := packageJSONDeclaresDependenciesScoped(d.ScanRoot, d.ManifestPath, opts)
	if err != nil || declares {
		return declares, err
	}
	children, err := npmWorkspaceChildren(d)
	if err != nil {
		return false, err
	}
	for _, child := range children {
		childManifest := filepath.Join(child, "package.json")
		if _, err := os.Stat(childManifest); err != nil {
			continue
		}
		declares, err := packageJSONDeclaresDependenciesScoped(d.ScanRoot, childManifest, opts)
		if err != nil || declares {
			return declares, err
		}
	}
	return false, nil
}

func packageJSONDeclaresDependenciesScoped(root, path string, opts GenerateOptions) (bool, error) {
	data, err := readAutoSBOMManifestScoped(root, path)
	if err != nil {
		return false, err
	}
	var pkg struct {
		Dependencies         map[string]any `json:"dependencies"`
		DevDependencies      map[string]any `json:"devDependencies"`
		OptionalDependencies map[string]any `json:"optionalDependencies"`
		PeerDependencies     map[string]any `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return false, err
	}
	if len(pkg.Dependencies) > 0 || len(pkg.OptionalDependencies) > 0 || len(pkg.PeerDependencies) > 0 {
		return true, nil
	}
	return opts.IncludeDev && len(pkg.DevDependencies) > 0, nil
}
