package sbomgen

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

type fakeGenerator struct {
	ecosystem      domain.Ecosystem
	tool           string
	install        InstallSpec
	declares       bool
	declaresErr    error
	generateErr    error
	generateOutput string
	generateCalls  int
}

func (g *fakeGenerator) Ecosystem() domain.Ecosystem { return g.ecosystem }
func (g *fakeGenerator) Tool() string                { return g.tool }
func (g *fakeGenerator) InstallSpec() InstallSpec {
	return g.install
}

func (g *fakeGenerator) Generate(_ context.Context, _ Detection, outPath string, _ GenerateOptions, _ RunnerFunc) error {
	g.generateCalls++
	if g.generateErr != nil {
		return g.generateErr
	}
	content := g.generateOutput
	if content == "" {
		content = validCycloneDXWithPackage()
	}
	return os.WriteFile(outPath, []byte(content), 0o600)
}

func (g *fakeGenerator) DeclaresDependencies(Detection, GenerateOptions) (bool, error) {
	return g.declares, g.declaresErr
}

type cleanupFailureGenerator struct {
	fakeGenerator
}

func (g *cleanupFailureGenerator) Generate(_ context.Context, _ Detection, outPath string, _ GenerateOptions, _ RunnerFunc) error {
	g.generateCalls++
	if err := os.Mkdir(outPath, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outPath, "child.txt"), []byte("left behind"), 0o600); err != nil {
		return err
	}
	return errors.New("generate boom")
}

type looseModeGenerator struct {
	fakeGenerator
}

func (g *looseModeGenerator) Generate(_ context.Context, _ Detection, outPath string, _ GenerateOptions, _ RunnerFunc) error {
	g.generateCalls++
	return os.WriteFile(outPath, []byte(validCycloneDXWithPackage()), 0o644) //nolint:gosec // test generator intentionally writes loose permissions for validation.
}

func validCycloneDXWithPackage() string {
	return `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]}`
}

func validCycloneDXNoPackages() string {
	return `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`
}

func TestRunRequiresAtLeastOneDetectedEcosystem(t *testing.T) {
	root := t.TempDir()
	_, err := Run(context.Background(), Config{Target: root, Logger: slog.Default()})
	if err == nil || !strings.Contains(err.Error(), "no supported manifests") {
		t.Fatalf("Run err = %v, want no supported manifests", err)
	}
}

func TestRunMissingToolSuggestsInstallTools(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	gen := &fakeGenerator{ecosystem: "npm", tool: "cyclonedx-npm", install: InstallSpec{CanAutoInstall: true}}
	_, err := Run(context.Background(), Config{
		Target:   root,
		Registry: map[domain.Ecosystem]Generator{"npm": gen},
		LookPath: func(string) (string, error) { return "", errors.New("missing") },
		Logger:   slog.Default(),
	})
	if err == nil || !strings.Contains(err.Error(), "--install-tools") {
		t.Fatalf("Run err = %v, want --install-tools hint", err)
	}
}

func TestRunInstallsMissingToolThenGenerates(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	gen := &fakeGenerator{
		ecosystem: "npm",
		tool:      "cyclonedx-npm",
		install: InstallSpec{
			Package:        "@cyclonedx/cyclonedx-npm",
			Source:         "npm registry",
			Args:           []string{"npm", "install", "--global", "--ignore-scripts", "@cyclonedx/cyclonedx-npm@" + npmGeneratorVersion},
			CanAutoInstall: true,
		},
		declares: true,
	}
	var lookups []string
	var runs []RunOptions
	result, err := Run(context.Background(), Config{
		Target:       root,
		InstallTools: true,
		Registry:     map[domain.Ecosystem]Generator{"npm": gen},
		LookPath: func(name string) (string, error) {
			lookups = append(lookups, name)
			if name == "npm" || len(lookups) > 2 {
				return "found", nil
			}
			return "", errors.New("missing")
		},
		Runner: func(_ context.Context, opts RunOptions) ([]byte, error) {
			runs = append(runs, opts)
			return nil, nil
		},
		Logger: slog.Default(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer func() { _ = result.Cleanup() }()
	if len(runs) != 1 || runs[0].Name != "npm" {
		t.Fatalf("install runs = %+v, want npm installer", runs)
	}
	if gen.generateCalls != 1 || len(result.SBOMPaths) != 1 {
		t.Fatalf("generateCalls/SBOMPaths = %d/%v", gen.generateCalls, result.SBOMPaths)
	}
}

func TestSanitizedCommandEnvDropsSecretsAndKeepsToolOverrides(t *testing.T) {
	t.Setenv("PACKMON_API_KEY", "packmon-secret")
	t.Setenv("GITHUB_TOKEN", "github-secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	t.Setenv("HTTP_PROXY", "http://user:pass@proxy.example")
	t.Setenv("SAFE_TOOL_ENV", "visible")

	env := sanitizedCommandEnv([]string{
		"GOWORK=off",
		"PACKMON_WEBHOOK_SECRET=bad",
		"CUSTOM_TOKEN=bad",
	})

	for _, key := range []string{"PACKMON_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "HTTP_PROXY", "PACKMON_WEBHOOK_SECRET", "CUSTOM_TOKEN"} {
		if envHasKey(env, key) {
			t.Fatalf("sanitized env kept sensitive key %s in %v", key, env)
		}
	}
	if !envHasPair(env, "SAFE_TOOL_ENV=visible") {
		t.Fatalf("sanitized env dropped safe inherited value: %v", env)
	}
	if !envHasPair(env, "GOWORK=off") {
		t.Fatalf("sanitized env dropped safe override: %v", env)
	}
}

func TestRunZeroPackagesCrossCheck(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	gen := &fakeGenerator{
		ecosystem:      "npm",
		tool:           "cyclonedx-npm",
		declares:       true,
		generateOutput: validCycloneDXNoPackages(),
	}
	_, err := Run(context.Background(), Config{
		Target:   root,
		Registry: map[domain.Ecosystem]Generator{"npm": gen},
		LookPath: func(string) (string, error) { return "found", nil },
		Logger:   slog.Default(),
	})
	if err == nil || !strings.Contains(err.Error(), "declares dependencies but generated SBOM imported 0 packages") {
		t.Fatalf("Run err = %v, want zero-package cross-check", err)
	}
}

func envHasKey(env []string, key string) bool {
	for _, kv := range env {
		got, _, ok := strings.Cut(kv, "=")
		if ok && got == key {
			return true
		}
	}
	return false
}

func envHasPair(env []string, pair string) bool {
	for _, kv := range env {
		if kv == pair {
			return true
		}
	}
	return false
}

func TestRunKeepCollisionDoesNotDeleteExistingFile(t *testing.T) {
	root := t.TempDir()
	keep := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	collision := filepath.Join(keep, "package.cdx.json")
	if err := os.WriteFile(collision, []byte("do-not-delete"), 0o600); err != nil {
		t.Fatal(err)
	}
	gen := &fakeGenerator{ecosystem: "npm", tool: "cyclonedx-npm"}
	result, err := Run(context.Background(), Config{
		Target:      root,
		KeepSBOMDir: keep,
		Registry:    map[domain.Ecosystem]Generator{"npm": gen},
		LookPath:    func(string) (string, error) { return "found", nil },
		Now:         fixedSBOMTestTime,
		Logger:      slog.Default(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, readErr := os.ReadFile(collision) // #nosec G304 -- test reads a file it just created in t.TempDir.
	if readErr != nil {
		t.Fatalf("collision file was deleted: %v", readErr)
	}
	if string(got) != "do-not-delete" {
		t.Fatalf("collision file = %q, want preserved content", got)
	}
	if len(result.SBOMPaths) != 1 {
		t.Fatalf("SBOMPaths = %v", result.SBOMPaths)
	}
	if got := filepath.Base(result.SBOMPaths[0]); got != "package-20260607T150405Z.cdx.json" {
		t.Fatalf("SBOM path = %q, want timestamped snapshot name", got)
	}
}

func TestRunKeepTimestampCollisionUsesCounterSuffix(t *testing.T) {
	root := t.TempDir()
	keep := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	existing := filepath.Join(keep, "package-20260607T150405Z.cdx.json")
	if err := os.WriteFile(existing, []byte("do-not-delete"), 0o600); err != nil {
		t.Fatal(err)
	}
	gen := &fakeGenerator{ecosystem: "npm", tool: "cyclonedx-npm"}
	result, err := Run(context.Background(), Config{
		Target:      root,
		KeepSBOMDir: keep,
		Registry:    map[domain.Ecosystem]Generator{"npm": gen},
		LookPath:    func(string) (string, error) { return "found", nil },
		Now:         fixedSBOMTestTime,
		Logger:      slog.Default(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := filepath.Base(result.SBOMPaths[0]); got != "package-20260607T150405Z-2.cdx.json" {
		t.Fatalf("SBOM path = %q, want collision suffix", got)
	}
	if got, err := os.ReadFile(existing); err != nil || string(got) != "do-not-delete" { //nolint:gosec // test reads a file it created in t.TempDir.
		t.Fatalf("existing timestamped file changed, got %q err %v", got, err)
	}
}

func TestRunRespectsMaxDepthZero(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"root":"1.0.0"}}`)
	writeFile(t, root, filepath.Join("nested", "package.json"), `{"dependencies":{"child":"1.0.0"}}`)
	gen := &fakeGenerator{ecosystem: "npm", tool: "cyclonedx-npm", declares: true}
	result, err := Run(context.Background(), Config{
		Target:      root,
		MaxDepth:    0,
		KeepSBOMDir: t.TempDir(),
		Registry:    map[domain.Ecosystem]Generator{"npm": gen},
		LookPath:    func(string) (string, error) { return "found", nil },
		Now:         fixedSBOMTestTime,
		Logger:      slog.Default(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.SBOMPaths) != 1 {
		t.Fatalf("SBOMPaths = %v, want only root manifest with max-depth 0", result.SBOMPaths)
	}
	if got := filepath.Base(result.SBOMPaths[0]); got != "package-20260607T150405Z.cdx.json" {
		t.Fatalf("SBOM path = %v, want root package SBOM", result.SBOMPaths)
	}
}

func fixedSBOMTestTime() time.Time {
	return time.Date(2026, 6, 7, 15, 4, 5, 0, time.UTC)
}

func TestRunDisambiguatesInternalOutputNameCollisions(t *testing.T) {
	root := t.TempDir()
	keep := t.TempDir()
	writeFile(t, root, filepath.Join("a", "b", "package.json"), `{"dependencies":{"a":"1.0.0"}}`)
	writeFile(t, root, filepath.Join("a_b", "package.json"), `{"dependencies":{"b":"1.0.0"}}`)
	gen := &fakeGenerator{ecosystem: "npm", tool: "cyclonedx-npm", declares: true}
	result, err := Run(context.Background(), Config{
		Target:      root,
		MaxDepth:    3,
		KeepSBOMDir: keep,
		Registry:    map[domain.Ecosystem]Generator{"npm": gen},
		LookPath:    func(string) (string, error) { return "found", nil },
		Logger:      slog.Default(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.SBOMPaths) != 2 {
		t.Fatalf("SBOMPaths = %v, want both package manifests", result.SBOMPaths)
	}
	seen := map[string]struct{}{}
	for _, path := range result.SBOMPaths {
		name := filepath.Base(path)
		if _, ok := seen[name]; ok {
			t.Fatalf("duplicate SBOM basename %q in %v", name, result.SBOMPaths)
		}
		seen[name] = struct{}{}
	}
}

func TestRunTemporaryCleanupRemovesGeneratedDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	gen := &fakeGenerator{ecosystem: "npm", tool: "cyclonedx-npm", declares: true}
	result, err := Run(context.Background(), Config{
		Target:   root,
		Registry: map[domain.Ecosystem]Generator{"npm": gen},
		LookPath: func(string) (string, error) { return "found", nil },
		Logger:   slog.Default(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.SBOMPaths) != 1 {
		t.Fatalf("SBOMPaths = %v", result.SBOMPaths)
	}
	dir := filepath.Dir(result.SBOMPaths[0])
	if err := result.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("generated dir still exists or unexpected err: %v", err)
	}
}
