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
}

// Result contains generated SBOM paths and the cleanup action for temporary mode.
type Result struct {
	SBOMPaths []string
	Cleanup   func() error
}

func Run(ctx context.Context, cfg Config) (Result, error) {
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
			if cfg.KeepSBOMDir != "" {
				_ = removeFiles(created)
			}
			_ = failureCleanup()
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
	if _, err := cfg.LookPath(gen.Tool()); err == nil {
		return nil
	}
	spec := gen.InstallSpec()
	if !spec.CanAutoInstall {
		return fmt.Errorf("required SBOM generator %q is not on PATH; install %s manually", gen.Tool(), spec.Package)
	}
	if !cfg.InstallTools {
		return fmt.Errorf("required SBOM generator %q is not on PATH; rerun with --install-tools to install pinned package %s from %s", gen.Tool(), spec.Package, spec.Source)
	}
	if len(spec.Args) == 0 {
		return fmt.Errorf("generator %q has no install command", gen.Tool())
	}
	installer := spec.Args[0]
	if _, err := cfg.LookPath(installer); err != nil {
		return fmt.Errorf("installer %q for %s is not on PATH: %w", installer, spec.Package, err)
	}

	if cfg.Logger != nil {
		cfg.Logger.Info("installing SBOM generator", "package", spec.Package, "source", spec.Source, "command", strings.Join(spec.Args, " "))
	}
	installCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	output, err := cfg.Runner(installCtx, RunOptions{Name: installer, Args: spec.Args[1:]})
	if err != nil {
		return fmt.Errorf("install %s: %w: %s", spec.Package, err, strings.TrimSpace(string(output)))
	}
	if _, err := cfg.LookPath(gen.Tool()); err != nil {
		return fmt.Errorf("installed %s but %q is still not on PATH: %w", spec.Package, gen.Tool(), err)
	}
	return nil
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

func defaultRunner(ctx context.Context, opts RunOptions) ([]byte, error) {
	cmd := exec.CommandContext(ctx, opts.Name, opts.Args...) // #nosec G204 -- names come from pinned generators or explicit injected test seams; no shell is used.
	if opts.Dir != "" {
		cmd.Dir = opts.Dir
	}
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}
	cmd.WaitDelay = 2 * time.Second
	return cmd.CombinedOutput()
}
