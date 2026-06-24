package sbomgen

import "context"

const (
	npmGeneratorVersion  = "4.2.1"
	pypiGeneratorVersion = "7.3.0"
	mavenPluginVersion   = "2.9.1"
)

// RunOptions describes one external command invocation. Dir is optional.
type RunOptions struct {
	Name string
	Args []string
	Dir  string
	Env  []string
}

// RunnerFunc runs an external command and returns combined output.
type RunnerFunc func(ctx context.Context, opts RunOptions) ([]byte, error)

// GenerateOptions controls a single generated SBOM.
type GenerateOptions struct {
	IncludeDev bool
}

// InstallSpec describes how to obtain a missing generator.
type InstallSpec struct {
	Package         string
	Source          string
	Args            []string
	ExpectedVersion string
	VersionArgs     []string
	CanAutoInstall  bool
	PythonPackage   bool
}

// Generator builds a CycloneDX SBOM for one ecosystem.
type Generator interface {
	Ecosystem() string
	Tool() string
	InstallSpec() InstallSpec
	Generate(ctx context.Context, d Detection, outPath string, opts GenerateOptions, run RunnerFunc) error
	DeclaresDependencies(d Detection, opts GenerateOptions) (bool, error)
}

// DefaultRegistry returns the pinned v1 generator set.
func DefaultRegistry() map[string]Generator {
	return map[string]Generator{
		"go":    goGenerator{},
		"npm":   npmGenerator{},
		"pypi":  pypiGenerator{},
		"maven": mavenGenerator{},
	}
}
