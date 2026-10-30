package sbomgen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/logsafe"
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
	out, err := run(ctx, RunOptions{Name: "cyclonedx-npm", Args: npmManifestArgs(args, d.ManifestPath)})
	if err == nil {
		return nil
	}
	if !bytes.Contains(out, []byte(npmLSProblemsCode)) {
		return fmt.Errorf("cyclonedx-npm: %w: %s", err, commandOutputSummary(out))
	}

	// npm ls reports tree problems that do not stop it from emitting a usable
	// tree, notably bundleDependencies of optional platform packages (e.g.
	// @tailwindcss/oxide-wasm32-wasi) that npm never records in the lockfile.
	// Retry once ignoring them, and warn with the reported problems so the
	// gap stays visible instead of failing the whole scan.
	retryArgs := npmManifestArgs(append(append([]string(nil), args...), "--ignore-npm-errors"), d.ManifestPath)
	retryOut, retryErr := run(ctx, RunOptions{Name: "cyclonedx-npm", Args: retryArgs})
	if retryErr != nil {
		return fmt.Errorf("cyclonedx-npm: %w: %s; retry with --ignore-npm-errors: %w: %s",
			err, commandOutputSummary(out), retryErr, commandOutputSummary(retryOut))
	}
	if opts.Logger != nil {
		opts.Logger.Warn("npm reported dependency-tree problems; generated SBOM with --ignore-npm-errors and may omit these packages",
			"manifest", d.DisplayPath,
			"npm_problems", logsafe.BoundedDiagnosticValue(strings.Join(npmLSProblems(out), "; "), maxCommandOutputBytes),
		)
	}
	return nil
}

// npmLSProblemsCode is the npm error code for missing, invalid, or extraneous
// packages in the dependency tree reported by `npm ls`.
const npmLSProblemsCode = "ELSPROBLEMS"

var npmLSProblemPattern = regexp.MustCompile(`(?:missing|invalid|extraneous): [^,\s]+(?:, required by [^,\s]+)?`)

func npmManifestArgs(args []string, manifestPath string) []string {
	return append(append([]string(nil), args...), "--", manifestPath)
}

// npmLSProblems returns the de-duplicated problem entries from npm ls output
// in first-seen order.
func npmLSProblems(out []byte) []string {
	var problems []string
	seen := map[string]bool{}
	for _, problem := range npmLSProblemPattern.FindAllString(string(out), -1) {
		if !seen[problem] {
			seen[problem] = true
			problems = append(problems, problem)
		}
	}
	return problems
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
