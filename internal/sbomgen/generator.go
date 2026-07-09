package sbomgen

import (
	"context"

	"github.com/8linkz-sec/packmon/internal/domain"
)

const (
	npmGeneratorVersion  = "5.0.0"
	pypiGeneratorVersion = "7.3.0"
	mavenPluginVersion   = "2.9.1"
)

// RunOptions describes one external command invocation. Dir is optional and Env
// is merged through the package command environment allowlist.
type RunOptions struct {
	// Name is the executable path or command name resolved by the caller.
	Name string
	// Args are passed directly to the command without a shell.
	Args []string
	// Dir is the working directory for generators that must run in a project root.
	Dir string
	// Env contains extra environment entries allowed by the command environment filter.
	Env []string
}

// RunnerFunc runs an external command and returns bounded combined output.
type RunnerFunc func(ctx context.Context, opts RunOptions) ([]byte, error)

// GenerateOptions controls a single generated SBOM.
type GenerateOptions struct {
	// IncludeDev requests development dependencies when the generator supports that split.
	IncludeDev bool
}

// InstallSpec describes how to obtain or verify a missing generator.
type InstallSpec struct {
	// Package is the tool or package name used in diagnostics and install commands.
	Package string
	// Source identifies the ecosystem/source for operator-facing install messages.
	Source string
	// Args is the pinned install command; Args[0] is resolved as the installer.
	Args []string
	// ExpectedVersion is the pinned version Run verifies when VersionArgs is set.
	ExpectedVersion string
	// VersionArgs are passed to the tool to confirm ExpectedVersion.
	VersionArgs []string
	// CanAutoInstall marks generators that Run may install when Config.InstallTools is true.
	CanAutoInstall bool
	// PythonPackage indicates the package should be installed into Packmon's Python tool cache.
	PythonPackage bool
}

// Generator builds a CycloneDX SBOM for one ecosystem.
type Generator interface {
	// Ecosystem returns the registry key this generator handles.
	Ecosystem() domain.Ecosystem
	// Tool returns the executable Run must find or install before generation.
	Tool() string
	// InstallSpec returns pinned tool installation and version-check metadata.
	InstallSpec() InstallSpec
	// Generate writes one CycloneDX SBOM to outPath using run for external commands.
	Generate(ctx context.Context, d Detection, outPath string, opts GenerateOptions, run RunnerFunc) error
	// DeclaresDependencies reports whether the manifest declares dependencies even if output was empty.
	DeclaresDependencies(d Detection, opts GenerateOptions) (bool, error)
}

// DefaultRegistry returns the pinned v1 generator set.
func DefaultRegistry() map[domain.Ecosystem]Generator {
	return map[domain.Ecosystem]Generator{
		domain.EcosystemGo:    goGenerator{},
		domain.EcosystemNPM:   npmGenerator{},
		domain.EcosystemPyPI:  pypiGenerator{},
		domain.EcosystemMaven: mavenGenerator{},
	}
}
