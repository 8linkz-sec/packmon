package sbomgen

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

type mavenGenerator struct{}

func (mavenGenerator) Ecosystem() domain.Ecosystem { return domain.EcosystemMaven }
func (mavenGenerator) Tool() string                { return "mvn" }
func (mavenGenerator) InstallSpec() InstallSpec {
	return InstallSpec{
		Package:        "cyclonedx-maven-plugin",
		Source:         "Maven Central",
		CanAutoInstall: false,
	}
}

func (mavenGenerator) Generate(ctx context.Context, d Detection, outPath string, opts GenerateOptions, run RunnerFunc) error {
	stage, err := os.MkdirTemp("", "packmon-maven-sbom-*")
	if err != nil {
		return fmt.Errorf("create Maven SBOM staging dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(stage) }()

	args := []string{
		"-q",
		"-f", filepath.Join(d.ProjectDir, "pom.xml"),
		"org.cyclonedx:cyclonedx-maven-plugin:" + mavenPluginVersion + ":makeAggregateBom",
		"-DoutputFormat=json",
		"-DoutputDirectory=" + stage,
		"-DoutputName=bom",
	}
	if opts.IncludeDev {
		args = append(args, "-DincludeTestScope=true")
	}
	out, err := run(ctx, RunOptions{Name: "mvn", Args: args})
	if err != nil {
		return fmt.Errorf("mvn: %w: %s", err, commandOutputSummary(out))
	}
	data, err := readGeneratedSBOMFile(filepath.Join(stage, "bom.json"))
	if err != nil {
		return fmt.Errorf("read Maven generated bom.json: %w", err)
	}
	if err := os.WriteFile(outPath, data, 0o600); err != nil { // #nosec G703 -- outPath is a sanitized filename under a private temp dir or the user's explicit --keep-sbom directory, not an attacker-controlled traversal path.
		return fmt.Errorf("write Maven SBOM %s: %w", outPath, err)
	}
	return nil
}

func (mavenGenerator) DeclaresDependencies(d Detection, opts GenerateOptions) (bool, error) {
	return mavenProjectDeclaresDependencies(d.ScanRoot, d.ProjectDir, opts, map[string]struct{}{})
}

func mavenProjectDeclaresDependencies(root, dir string, opts GenerateOptions, visited map[string]struct{}) (bool, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = filepath.Clean(dir)
	}
	if _, ok := visited[abs]; ok {
		return false, nil
	}
	visited[abs] = struct{}{}

	data, err := readAutoSBOMManifestScoped(root, filepath.Join(dir, "pom.xml"))
	if err != nil {
		return false, err
	}
	var project struct {
		Dependencies []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Scope      string `xml:"scope"`
		} `xml:"dependencies>dependency"`
		Modules []string `xml:"modules>module"`
	}
	if err := xml.Unmarshal(data, &project); err != nil {
		return false, err
	}
	for _, dep := range project.Dependencies {
		if strings.TrimSpace(dep.GroupID) == "" || strings.TrimSpace(dep.ArtifactID) == "" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(dep.Scope), "test") && !opts.IncludeDev {
			continue
		}
		return true, nil
	}
	for _, module := range project.Modules {
		module = strings.TrimSpace(module)
		if module == "" {
			continue
		}
		child := filepath.Join(dir, filepath.FromSlash(module))
		if strings.TrimSpace(root) != "" {
			bounds, err := newScanRootBounds(root)
			if err != nil {
				return false, err
			}
			if err := bounds.requireDerived(child); err != nil {
				return false, err
			}
		}
		declares, err := mavenProjectDeclaresDependencies(root, child, opts, visited)
		if err != nil || declares {
			return declares, err
		}
	}
	return false, nil
}
