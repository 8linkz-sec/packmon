package sbomgen

import (
	"context"
	"encoding/json"
	"errors"
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
	problems, tolerated := toleratedNpmLSProblems(d, out)
	if !tolerated {
		return fmt.Errorf("cyclonedx-npm: %w: %s", err, commandOutputSummary(out))
	}

	// npm ls flags bundleDependencies of optional platform packages (e.g.
	// @tailwindcss/oxide-wasm32-wasi) as missing because npm never records
	// them in the lockfile. Only that case is retried ignoring npm errors, and
	// the reported problems are logged so the gap stays visible.
	retryArgs := npmManifestArgs(append(append([]string(nil), args...), "--ignore-npm-errors"), d.ManifestPath)
	retryOut, retryErr := run(ctx, RunOptions{Name: "cyclonedx-npm", Args: retryArgs})
	if retryErr != nil {
		return fmt.Errorf("cyclonedx-npm: %w: %s; retry with --ignore-npm-errors: %w: %s",
			err, commandOutputSummary(out), retryErr, commandOutputSummary(retryOut))
	}
	if opts.Logger != nil {
		opts.Logger.Warn("npm reported dependency-tree problems; generated SBOM with --ignore-npm-errors and may omit these packages",
			"manifest", d.DisplayPath,
			"npm_problems", logsafe.BoundedDiagnosticValue(strings.Join(problems, "; "), maxCommandOutputBytes),
		)
	}
	return nil
}

// npmLSProblemsCodeLine matches npm's own error-code line for dependency-tree
// problems (ELSPROBLEMS), with the current and the legacy log prefix;
// cyclonedx-npm indents the npm output it relays.
var npmLSProblemsCodeLine = regexp.MustCompile(`(?m)^[ \t]*npm (?:error|ERR!) code ELSPROBLEMS\r?$`)

var npmLSProblemPattern = regexp.MustCompile(`(missing|invalid|extraneous): ([^,\s]+)(?:, required by ([^,\s]+))?`)

func npmManifestArgs(args []string, manifestPath string) []string {
	return append(append([]string(nil), args...), "--", manifestPath)
}

// toleratedNpmLSProblems returns the de-duplicated npm ls problems in out and
// whether all of them may be ignored. That holds only when npm reported
// ELSPROBLEMS and every problem is a missing dependency of a package the
// lockfile marks optional; invalid or extraneous packages, missing
// dependencies of required packages, or an unreadable lockfile stay fatal.
func toleratedNpmLSProblems(d Detection, out []byte) ([]string, bool) {
	if !npmLSProblemsCodeLine.Match(out) {
		return nil, false
	}
	matches := npmLSProblemPattern.FindAllSubmatch(out, -1)
	if len(matches) == 0 {
		return nil, false
	}
	optional, err := npmLockfileOptionalPackages(d)
	if err != nil {
		return nil, false
	}
	var problems []string
	seen := map[string]bool{}
	for _, m := range matches {
		if string(m[1]) != "missing" || !optional[string(m[3])] {
			return nil, false
		}
		if problem := string(m[0]); !seen[problem] {
			seen[problem] = true
			problems = append(problems, problem)
		}
	}
	return problems, true
}

// npmLockfileOptionalPackages returns the name@version keys whose every
// lockfile entry is marked optional.
func npmLockfileOptionalPackages(d Detection) (map[string]bool, error) {
	data, err := readNpmLockfile(d)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Version  string `json:"version"`
			Optional bool   `json:"optional"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	optional := map[string]bool{}
	required := map[string]bool{}
	for key, pkg := range lock.Packages {
		_, name, found := strings.CutLast(key, "node_modules/")
		if !found || pkg.Version == "" {
			continue
		}
		id := name + "@" + pkg.Version
		if pkg.Optional {
			optional[id] = true
		} else {
			required[id] = true
		}
	}
	for id := range required {
		delete(optional, id)
	}
	return optional, nil
}

func readNpmLockfile(d Detection) ([]byte, error) {
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		path := filepath.Join(d.ProjectDir, name)
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			continue
		}
		if strings.TrimSpace(d.ScanRoot) == "" {
			return readFileLimited(path, maxGeneratedSBOMBytes, "npm lockfile")
		}
		return readFileLimitedScoped(d.ScanRoot, path, maxGeneratedSBOMBytes, "npm lockfile")
	}
	return nil, errors.New("no npm lockfile")
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
