package sbomgen

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/mod/modfile"
)

type goGenerator struct{}

func (goGenerator) Ecosystem() string { return "go" }
func (goGenerator) Tool() string      { return "cyclonedx-gomod" }
func (goGenerator) InstallSpec() InstallSpec {
	return InstallSpec{
		Package:        "cyclonedx-gomod",
		Source:         "Go module proxy",
		Args:           []string{"go", "install", "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@" + goGeneratorVersion},
		CanAutoInstall: true,
	}
}

func (goGenerator) Generate(ctx context.Context, d Detection, outPath string, opts GenerateOptions, run RunnerFunc) error {
	args := []string{"mod", "-json", "-output", outPath}
	if opts.IncludeDev {
		args = append(args, "-test")
	}
	args = append(args, d.ProjectDir)
	out, err := run(ctx, RunOptions{Name: "cyclonedx-gomod", Args: args})
	if err != nil {
		return fmt.Errorf("cyclonedx-gomod: %w: %s", err, string(out))
	}
	return nil
}

func (goGenerator) DeclaresDependencies(d Detection, _ GenerateOptions) (bool, error) {
	data, err := os.ReadFile(d.ManifestPath) // #nosec G304 -- path comes from a bounded local manifest walk.
	if err != nil {
		return false, err
	}
	file, err := modfile.Parse(d.ManifestPath, data, nil)
	if err != nil {
		return false, err
	}
	return len(file.Require) > 0, nil
}
