package sbomgen

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const defaultGenerationTimeout = 2 * time.Minute

// Config controls auto-SBOM detection, generation, and validation.
type Config struct {
	Target       string
	Ecosystems   []string
	InstallTools bool
	KeepSBOMDir  string
	IncludeDev   bool
	MaxDepth     int
	Timeout      time.Duration
	Logger       *slog.Logger
	Registry     map[string]Generator
	LookPath     func(string) (string, error)
	Runner       RunnerFunc
	Now          func() time.Time
	ToolCacheDir string
}

// Result contains generated SBOM paths and the cleanup action for temporary mode.
type Result struct {
	SBOMPaths []string
	Cleanup   func() error
}

func Run(ctx context.Context, cfg Config) (result Result, err error) {
	cfg = normalizeConfig(cfg)

	detections, err := Detect(cfg.Target, cfg.MaxDepth)
	if err != nil {
		return Result{}, fmt.Errorf("detect manifests: %w", err)
	}
	detections = filterDetections(detections, cfg.Ecosystems)
	if len(detections) == 0 {
		return Result{}, fmt.Errorf("no supported manifests found for auto-SBOM generation")
	}

	outDir, successCleanup, failureCleanup, err := prepareOutputDir(cfg.KeepSBOMDir)
	if err != nil {
		return Result{}, err
	}
	created := []string{}
	success := false
	defer func() {
		if !success {
			var cleanupErr error
			if cfg.KeepSBOMDir != "" {
				cleanupErr = errors.Join(cleanupErr, removeFiles(created))
			}
			cleanupErr = errors.Join(cleanupErr, failureCleanup())
			if cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("cleanup generated SBOMs: %w", cleanupErr))
			}
		}
	}()

	paths := make([]string, 0, len(detections))
	opts := GenerateOptions{IncludeDev: cfg.IncludeDev}
	usedNames := map[string]int{}
	nameTag := ""
	if cfg.KeepSBOMDir != "" {
		nameTag = sbomSnapshotTag(cfg.Now().UTC())
	}
	for _, d := range detections {
		gen, ok := cfg.Registry[d.Ecosystem]
		if !ok {
			return Result{}, fmt.Errorf("no SBOM generator registered for ecosystem %q", d.Ecosystem)
		}
		if err := ensureTool(ctx, cfg, gen); err != nil {
			return Result{}, fmt.Errorf("%s: %w", d.DisplayPath, err)
		}

		outPath, err := reserveUniqueOutputPath(outDir, d, usedNames, nameTag)
		if err != nil {
			return Result{}, err
		}
		if cfg.KeepSBOMDir != "" {
			created = append(created, outPath)
		}

		genCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		err = gen.Generate(genCtx, d, outPath, opts, cfg.Runner)
		cancel()
		if err != nil {
			return Result{}, fmt.Errorf("generate SBOM for %s: %w", d.DisplayPath, err)
		}
		if err := normalizeGeneratedSBOMFile(outPath); err != nil {
			return Result{}, err
		}
		packages, skipped, err := validateGeneratedSBOM(outPath)
		if err != nil {
			return Result{}, err
		}
		if packages == 0 {
			declares, err := gen.DeclaresDependencies(d, opts)
			if err != nil {
				return Result{}, fmt.Errorf("check declared dependencies for %s: %w", d.DisplayPath, err)
			}
			if declares {
				return Result{}, fmt.Errorf("%s declares dependencies but generated SBOM imported 0 packages (skipped components: %d)", d.DisplayPath, skipped)
			}
		}
		paths = append(paths, outPath)
	}

	success = true
	return Result{SBOMPaths: paths, Cleanup: successCleanup}, nil
}

func normalizeConfig(cfg Config) Config {
	if strings.TrimSpace(cfg.Target) == "" {
		cfg.Target = "."
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultGenerationTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	if cfg.Registry == nil {
		cfg.Registry = DefaultRegistry()
	}
	if cfg.LookPath == nil {
		cfg.LookPath = exec.LookPath
	}
	if cfg.Runner == nil {
		cfg.Runner = defaultRunner
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return cfg
}

func filterDetections(ds []Detection, ecosystems []string) []Detection {
	if len(ecosystems) == 0 {
		return ds
	}
	allow := map[string]struct{}{}
	for _, eco := range ecosystems {
		eco = strings.ToLower(strings.TrimSpace(eco))
		if eco != "" {
			allow[eco] = struct{}{}
		}
	}
	if len(allow) == 0 {
		return ds
	}
	out := make([]Detection, 0, len(ds))
	for _, d := range ds {
		if _, ok := allow[d.Ecosystem]; ok {
			out = append(out, d)
		}
	}
	return out
}

func prepareOutputDir(keepDir string) (string, func() error, func() error, error) {
	keepDir = strings.TrimSpace(keepDir)
	if keepDir != "" {
		absKeepDir, err := filepath.Abs(keepDir)
		if err != nil {
			return "", nil, nil, fmt.Errorf("resolve SBOM output directory %s: %w", keepDir, err)
		}
		if err := os.MkdirAll(absKeepDir, 0o700); err != nil {
			return "", nil, nil, fmt.Errorf("create SBOM output directory %s: %w", keepDir, err)
		}
		return absKeepDir, func() error { return nil }, func() error { return nil }, nil
	}
	dir, err := os.MkdirTemp("", "packmon-sbom-*")
	if err != nil {
		return "", nil, nil, fmt.Errorf("create temporary SBOM directory: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(dir) }
	return dir, cleanup, cleanup, nil
}

func outputFileName(d Detection) string {
	name := filepath.ToSlash(d.DisplayPath)
	ext := filepath.Ext(name)
	if ext != "" {
		name = strings.TrimSuffix(name, ext)
	}
	name = strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(name)
	if strings.TrimSpace(name) == "" {
		name = d.Ecosystem
	}
	return name + ".cdx.json"
}

func uniqueOutputFileName(d Detection, used map[string]int, tag string) string {
	name := taggedOutputFileName(d, tag)
	count := used[name]
	used[name] = count + 1
	if count == 0 {
		return name
	}
	base := strings.TrimSuffix(name, ".cdx.json")
	return fmt.Sprintf("%s-%d.cdx.json", base, count+1)
}

func taggedOutputFileName(d Detection, tag string) string {
	name := outputFileName(d)
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return name
	}
	base := strings.TrimSuffix(name, ".cdx.json")
	return base + "-" + tag + ".cdx.json"
}

func sbomSnapshotTag(t time.Time) string {
	return t.UTC().Format("20060102T150405Z")
}

var errOutputExists = errors.New("SBOM output already exists")

func reserveUniqueOutputPath(outDir string, d Detection, used map[string]int, tag string) (string, error) {
	for attempts := 0; attempts < 1000; attempts++ {
		outPath := filepath.Join(outDir, uniqueOutputFileName(d, used, tag))
		if err := reserveOutputPath(outPath); err != nil {
			if errors.Is(err, errOutputExists) {
				continue
			}
			return "", err
		}
		return outPath, nil
	}
	return "", fmt.Errorf("reserve SBOM output for %s: too many filename collisions", d.DisplayPath)
}

func reserveOutputPath(path string) error {
	// Create with O_EXCL to prove the path did not already exist (collision
	// protection for --keep-sbom), then remove it so the generator writes to a
	// fresh path. Some generators (e.g. cyclonedx-py) refuse to overwrite an
	// existing --output-file, so the reserved placeholder must not remain.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path is built from a caller-selected output directory plus a sanitized SBOM filename.
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", errOutputExists, path)
		}
		return fmt.Errorf("reserve SBOM output %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("reserve SBOM output %s: %w", path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("reserve SBOM output %s: %w", path, err)
	}
	return nil
}

func ensureTool(ctx context.Context, cfg Config, gen Generator) error {
	cfg = normalizeConfig(cfg)
	spec := gen.InstallSpec()
	if spec.PythonPackage {
		if err := prependPythonToolPath(cfg, spec); err != nil {
			return err
		}
	}
	toolPath, pathErr := cfg.LookPath(gen.Tool())
	var versionErr error
	if pathErr == nil {
		if versionErr = verifyToolVersion(ctx, cfg, gen, toolPath); versionErr == nil {
			return nil
		}
		if !spec.CanAutoInstall || !cfg.InstallTools {
			return versionErr
		}
	}
	if !spec.CanAutoInstall {
		return fmt.Errorf("required SBOM generator %q is not on PATH; install %s manually", gen.Tool(), spec.Package)
	}
	if !cfg.InstallTools {
		return fmt.Errorf("required SBOM generator %q is not on PATH; rerun with --install-tools to install pinned package %s from %s", gen.Tool(), spec.Package, spec.Source)
	}
	if len(spec.Args) == 0 {
		return fmt.Errorf("generator %q has no install command", gen.Tool())
	}
	installer, installerErr := resolveInstaller(cfg, spec)
	if installerErr != nil {
		return installerErr
	}
	if spec.PythonPackage {
		if err := installPythonPackageTool(ctx, cfg, spec, installer); err != nil {
			return err
		}
		toolPath, err := cfg.LookPath(gen.Tool())
		if err != nil {
			return fmt.Errorf("installed %s but %q is still not on PATH: %w", spec.Package, gen.Tool(), err)
		}
		if err := verifyToolVersion(ctx, cfg, gen, toolPath); err != nil {
			return err
		}
		return nil
	}
	installArgs := append([]string(nil), spec.Args[1:]...)
	displayArgs := append([]string{installer}, installArgs...)

	if cfg.Logger != nil {
		cfg.Logger.Info("installing SBOM generator", "package", spec.Package, "source", spec.Source, "command", strings.Join(displayArgs, " "))
	}
	installCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	output, err := cfg.Runner(installCtx, RunOptions{Name: installer, Args: installArgs})
	if err != nil {
		return fmt.Errorf("install %s: %w: %s", spec.Package, err, strings.TrimSpace(commandOutputSummary(output)))
	}
	toolPath, err = cfg.LookPath(gen.Tool())
	if err != nil {
		return fmt.Errorf("installed %s but %q is still not on PATH: %w", spec.Package, gen.Tool(), err)
	}
	if err := verifyToolVersion(ctx, cfg, gen, toolPath); err != nil {
		return err
	}
	return nil
}

func installPythonPackageTool(ctx context.Context, cfg Config, spec InstallSpec, python string) error {
	venvDir, err := pythonToolVenvDir(cfg, spec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(venvDir), 0o750); err != nil {
		return fmt.Errorf("create Python tool cache: %w", err)
	}
	if cfg.Logger != nil {
		cfg.Logger.Info("installing SBOM generator", "package", spec.Package, "source", spec.Source, "command", strings.Join([]string{python, "-m", "venv", venvDir}, " "))
	}
	installCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	output, err := cfg.Runner(installCtx, RunOptions{Name: python, Args: []string{"-m", "venv", venvDir}})
	if err != nil {
		return fmt.Errorf("create venv for %s: %w: %s", spec.Package, err, strings.TrimSpace(commandOutputSummary(output)))
	}

	venvPython := pythonToolVenvPython(venvDir)
	pkg := pythonPackagePin(spec)
	if cfg.Logger != nil {
		cfg.Logger.Info("installing SBOM generator", "package", spec.Package, "source", spec.Source, "command", strings.Join([]string{venvPython, "-m", "pip", "install", pkg}, " "))
	}
	output, err = cfg.Runner(installCtx, RunOptions{Name: venvPython, Args: []string{"-m", "pip", "install", pkg}})
	if err != nil {
		return fmt.Errorf("install %s: %w: %s", spec.Package, err, strings.TrimSpace(commandOutputSummary(output)))
	}
	if err := prependPythonToolPath(cfg, spec); err != nil {
		return err
	}
	return nil
}

func pythonPackagePin(spec InstallSpec) string {
	if strings.TrimSpace(spec.ExpectedVersion) == "" {
		return spec.Package
	}
	return spec.Package + "==" + strings.TrimSpace(spec.ExpectedVersion)
}

func prependPythonToolPath(cfg Config, spec InstallSpec) error {
	venvDir, err := pythonToolVenvDir(cfg, spec)
	if err != nil {
		return err
	}
	binDir := pythonToolBinDir(venvDir)
	path := os.Getenv("PATH")
	for _, part := range filepath.SplitList(path) {
		if filepath.Clean(part) == filepath.Clean(binDir) {
			return nil
		}
	}
	if path == "" {
		return os.Setenv("PATH", binDir)
	}
	return os.Setenv("PATH", binDir+string(os.PathListSeparator)+path)
}

func pythonToolVenvDir(cfg Config, spec InstallSpec) (string, error) {
	root := strings.TrimSpace(cfg.ToolCacheDir)
	if root == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("resolve user cache dir: %w", err)
		}
		root = filepath.Join(cacheDir, "packmon", "tools")
	}
	version := strings.TrimSpace(spec.ExpectedVersion)
	if version == "" {
		version = "default"
	}
	return filepath.Join(root, "python", safeToolCachePart(spec.Package), safeToolCachePart(version)), nil
}

func safeToolCachePart(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func pythonToolBinDir(venvDir string) string {
	if os.PathSeparator == '\\' {
		return filepath.Join(venvDir, "Scripts")
	}
	return filepath.Join(venvDir, "bin")
}

func pythonToolVenvPython(venvDir string) string {
	if os.PathSeparator == '\\' {
		return filepath.Join(pythonToolBinDir(venvDir), "python.exe")
	}
	return filepath.Join(pythonToolBinDir(venvDir), "python")
}

func resolveInstaller(cfg Config, spec InstallSpec) (string, error) {
	installer := spec.Args[0]
	if _, err := cfg.LookPath(installer); err == nil {
		return installer, nil
	} else if installer != "python" {
		return "", fmt.Errorf("installer %q for %s is not on PATH: %w", installer, spec.Package, err)
	}
	if _, err := cfg.LookPath("python3"); err != nil {
		return "", fmt.Errorf("installer %q for %s is not on PATH: %w", installer, spec.Package, err)
	}
	return "python3", nil
}

func verifyToolVersion(ctx context.Context, cfg Config, gen Generator, toolPath string) error {
	spec := gen.InstallSpec()
	expected := strings.TrimSpace(spec.ExpectedVersion)
	if expected == "" || len(spec.VersionArgs) == 0 {
		return nil
	}
	versionCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	output, err := cfg.Runner(versionCtx, RunOptions{Name: toolPath, Args: append([]string(nil), spec.VersionArgs...)})
	if err != nil {
		return fmt.Errorf("check %q version: %w: %s", gen.Tool(), err, strings.TrimSpace(commandOutputSummary(output)))
	}
	actual := strings.TrimSpace(commandOutputSummary(output))
	if !versionOutputContainsVersion(actual, expected) {
		return fmt.Errorf("required SBOM generator %q version %s, found %s", gen.Tool(), expected, actual)
	}
	return nil
}

func versionOutputContainsVersion(output, expected string) bool {
	expected = strings.TrimPrefix(strings.TrimSpace(expected), "v")
	for _, field := range strings.FieldsFunc(output, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '-' && r != '_'
	}) {
		if strings.TrimPrefix(strings.TrimSpace(field), "v") == expected {
			return true
		}
	}
	return false
}

func removeFiles(paths []string) error {
	var joined error
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}

func normalizeGeneratedSBOMFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set generated SBOM permissions for %s: %w", path, err)
	}
	return nil
}

func defaultRunner(ctx context.Context, opts RunOptions) ([]byte, error) {
	cmd := exec.CommandContext(ctx, opts.Name, opts.Args...) // #nosec G204 -- names come from pinned generators or explicit injected test seams; no shell is used.
	if opts.Dir != "" {
		cmd.Dir = opts.Dir
	}
	cmd.Env = sanitizedCommandEnv(opts.Env)
	cmd.WaitDelay = 2 * time.Second
	var output boundedOutputWriter
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.Bytes(), err
}

func sanitizedCommandEnv(extra []string) []string {
	out := make([]string, 0, len(os.Environ())+len(extra))
	seen := make(map[string]int)
	add := func(kv string) {
		key, _, ok := strings.Cut(kv, "=")
		if !ok || !allowToolEnvKey(key) {
			return
		}
		normalized := strings.ToUpper(strings.TrimSpace(key))
		if idx, exists := seen[normalized]; exists {
			out[idx] = kv
			return
		}
		seen[normalized] = len(out)
		out = append(out, kv)
	}
	for _, kv := range os.Environ() {
		add(kv)
	}
	for _, kv := range extra {
		add(kv)
	}
	return out
}

func allowToolEnvKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	if upper == "" {
		return false
	}
	if strings.HasPrefix(upper, "PACKMON_") {
		return false
	}
	switch upper {
	case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE":
		return false
	}
	for _, marker := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL", "AUTH", "COOKIE", "SESSION"} {
		if strings.Contains(upper, marker) {
			return false
		}
	}
	return true
}
