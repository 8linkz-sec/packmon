package sbomgen

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNpmGeneratorGenerateArgsOmitDevByDefault(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	d := Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root}
	var got RunOptions
	err := (npmGenerator{}).Generate(context.Background(), d, filepath.Join(root, "bom.json"), GenerateOptions{}, func(_ context.Context, opts RunOptions) ([]byte, error) {
		got = opts
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	joined := strings.Join(got.Args, " ")
	if got.Name != "cyclonedx-npm" || !strings.Contains(joined, "--omit dev") || !strings.Contains(joined, d.ManifestPath) {
		t.Fatalf("RunOptions = %+v", got)
	}
	if len(got.Args) < 2 || got.Args[len(got.Args)-2] != "--" || got.Args[len(got.Args)-1] != d.ManifestPath {
		t.Fatalf("manifest must be separated from variadic --omit args with --, got %+v", got.Args)
	}
}

func TestNpmGeneratorGenerateArgsIncludeDevDoesNotOmitDev(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"devDependencies":{"vitest":"1.0.0"}}`)
	d := Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root}
	var got RunOptions
	err := (npmGenerator{}).Generate(context.Background(), d, filepath.Join(root, "bom.json"), GenerateOptions{IncludeDev: true}, func(_ context.Context, opts RunOptions) ([]byte, error) {
		got = opts
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(strings.Join(got.Args, " "), "--omit dev") {
		t.Fatalf("include-dev args unexpectedly omit dev: %+v", got)
	}
}

func TestNpmGeneratorGenerateArgsUsePackageLockOnlyWhenLockfileExists(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	writeFile(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{}}`)
	d := Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root}
	var got RunOptions
	err := (npmGenerator{}).Generate(context.Background(), d, filepath.Join(root, "bom.json"), GenerateOptions{}, func(_ context.Context, opts RunOptions) ([]byte, error) {
		got = opts
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(strings.Join(got.Args, " "), "--package-lock-only") {
		t.Fatalf("RunOptions = %+v, want --package-lock-only for package-lock.json", got)
	}
}

// npmLSProblemsOutput mirrors what cyclonedx-npm relays when `npm ls` flags
// bundled dependencies of an optional platform package as missing.
const npmLSProblemsOutput = "npm error code ELSPROBLEMS\n" +
	"npm error missing: @emnapi/core@^1.11.1, required by @tailwindcss/oxide-wasm32-wasi@4.3.3\n" +
	"npm error missing: @emnapi/runtime@^1.11.1, required by @tailwindcss/oxide-wasm32-wasi@4.3.3\n" +
	"npm error code ELSPROBLEMS\n" +
	"npm error missing: @emnapi/core@^1.11.1, required by @tailwindcss/oxide-wasm32-wasi@4.3.3\n" +
	"Error: npm-ls exited with errors: 1 noSignal\n"

// optionalWasmLockfile records the requirers from npmLSProblemsOutput as
// optional packages, as npm does for platform-specific Tailwind binaries.
const optionalWasmLockfile = `{"lockfileVersion":3,"packages":{
	"":{"devDependencies":{"tailwindcss":"4.3.3"}},
	"node_modules/@tailwindcss/oxide-wasm32-wasi":{"version":"4.3.3","optional":true,
		"bundleDependencies":["@emnapi/core","@emnapi/runtime"]},
	"node_modules/tailwindcss":{"version":"4.3.3","dev":true}}}`

// npmTreeProblemsDetection writes a package.json and the given lockfile into a
// fresh scan root and returns the matching detection.
func npmTreeProblemsDetection(t *testing.T, lockfile string) (Detection, string) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"devDependencies":{"tailwindcss":"4.3.3"}}`)
	writeFile(t, root, "package-lock.json", lockfile)
	return Detection{ScanRoot: root, ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root, DisplayPath: "package.json"}, root
}

func TestNpmGeneratorRetriesWithIgnoreNpmErrorsOnTreeProblems(t *testing.T) {
	// cyclonedx-npm relays npm's stderr indented by two spaces, with CRLF on
	// Windows; both shapes must be recognized.
	relayed := "Command failed: npm ls --json --long --all --package-lock-only\r\n" +
		"  " + strings.ReplaceAll(strings.TrimSuffix(npmLSProblemsOutput, "\n"), "\n", "\r\n  ") + "\r\n"
	for name, output := range map[string]string{"plain npm": npmLSProblemsOutput, "relayed by cyclonedx-npm": relayed} {
		t.Run(name, func(t *testing.T) {
			assertNpmTreeProblemsRetried(t, output)
		})
	}
}

func assertNpmTreeProblemsRetried(t *testing.T, output string) {
	t.Helper()
	d, root := npmTreeProblemsDetection(t, optionalWasmLockfile)
	var logs bytes.Buffer
	opts := GenerateOptions{IncludeDev: true, Logger: slog.New(slog.NewTextHandler(&logs, nil))}
	var calls []RunOptions
	err := (npmGenerator{}).Generate(context.Background(), d, filepath.Join(root, "bom.json"), opts, func(_ context.Context, opts RunOptions) ([]byte, error) {
		calls = append(calls, opts)
		if len(calls) == 1 {
			return []byte(output), errors.New("exit status 254")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (initial + retry)", len(calls))
	}
	if slices.Contains(calls[0].Args, "--ignore-npm-errors") {
		t.Fatalf("first attempt must not ignore npm errors: %+v", calls[0].Args)
	}
	retry := calls[1].Args
	if !slices.Contains(retry, "--ignore-npm-errors") || !slices.Contains(retry, "--package-lock-only") {
		t.Fatalf("retry args = %+v, want --ignore-npm-errors and the original flags", retry)
	}
	if len(retry) < 2 || retry[len(retry)-2] != "--" || retry[len(retry)-1] != d.ManifestPath {
		t.Fatalf("retry must keep the manifest after --, got %+v", retry)
	}

	logged := logs.String()
	for _, want := range []string{
		"level=WARN",
		"manifest=package.json",
		"missing: @emnapi/core@^1.11.1, required by @tailwindcss/oxide-wasm32-wasi@4.3.3",
		"missing: @emnapi/runtime@^1.11.1, required by @tailwindcss/oxide-wasm32-wasi@4.3.3",
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("warning log missing %q:\n%s", want, logged)
		}
	}
	if strings.Count(logged, "missing: @emnapi/core@^1.11.1") != 1 {
		t.Fatalf("npm problems must be de-duplicated:\n%s", logged)
	}
	if strings.Contains(logged, root) {
		t.Fatalf("warning must not log absolute paths:\n%s", logged)
	}
}

func TestNpmGeneratorDoesNotRetryOtherFailures(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	d := Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root, DisplayPath: "package.json"}
	calls := 0
	err := (npmGenerator{}).Generate(context.Background(), d, filepath.Join(root, "bom.json"), GenerateOptions{}, func(context.Context, RunOptions) ([]byte, error) {
		calls++
		return []byte("npm error code ENOENT"), errors.New("exit status 1")
	})
	if err == nil || !strings.Contains(err.Error(), "ENOENT") {
		t.Fatalf("Generate error = %v, want the original npm failure", err)
	}
	if calls != 1 {
		t.Fatalf("runner calls = %d, want 1 (no retry for non-tree errors)", calls)
	}
}

func TestNpmGeneratorDoesNotRetryUntoleratedTreeProblems(t *testing.T) {
	requiredLockfile := `{"lockfileVersion":3,"packages":{
		"node_modules/@tailwindcss/oxide-wasm32-wasi":{"version":"4.3.3"}}}`
	for _, tc := range []struct {
		name     string
		lockfile string
		output   string
	}{
		{
			name:     "missing dependency of a required package",
			lockfile: requiredLockfile,
			output:   npmLSProblemsOutput,
		},
		{
			name:     "invalid package",
			lockfile: optionalWasmLockfile,
			output: "npm error code ELSPROBLEMS\n" +
				"npm error invalid: left-pad@1.0.0, required by @tailwindcss/oxide-wasm32-wasi@4.3.3\n",
		},
		{
			name:     "extraneous package",
			lockfile: optionalWasmLockfile,
			output:   "npm error code ELSPROBLEMS\nnpm error extraneous: left-pad@1.3.0\n",
		},
		{
			name:     "code only as a substring",
			lockfile: optionalWasmLockfile,
			output: "npm error code EOTHER mentioning ELSPROBLEMS\n" +
				"npm error missing: @emnapi/core@^1.11.1, required by @tailwindcss/oxide-wasm32-wasi@4.3.3\n",
		},
		{
			name:     "unparseable lockfile",
			lockfile: `{`,
			output:   npmLSProblemsOutput,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := npmTreeProblemsDetection(t, tc.lockfile)
			calls := 0
			err := (npmGenerator{}).Generate(context.Background(), d, filepath.Join(d.ProjectDir, "bom.json"), GenerateOptions{IncludeDev: true}, func(context.Context, RunOptions) ([]byte, error) {
				calls++
				return []byte(tc.output), errors.New("exit status 254")
			})
			if err == nil {
				t.Fatal("Generate succeeded, want the npm failure to stay fatal")
			}
			if calls != 1 {
				t.Fatalf("runner calls = %d, want 1 (no retry)", calls)
			}
		})
	}
}

func TestNpmGeneratorFailsWhenRetryAlsoFails(t *testing.T) {
	d, _ := npmTreeProblemsDetection(t, optionalWasmLockfile)
	calls := 0
	err := (npmGenerator{}).Generate(context.Background(), d, filepath.Join(d.ProjectDir, "bom.json"), GenerateOptions{}, func(context.Context, RunOptions) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte(npmLSProblemsOutput), errors.New("exit status 254")
		}
		return []byte("cannot write output"), errors.New("exit status 1")
	})
	if err == nil || !strings.Contains(err.Error(), "ELSPROBLEMS") || !strings.Contains(err.Error(), "cannot write output") {
		t.Fatalf("Generate error = %v, want both the npm problems and the retry failure", err)
	}
	if calls != 2 {
		t.Fatalf("runner calls = %d, want 2", calls)
	}
}

func TestNpmGeneratorDeclaresWorkspaceChildDependencies(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"workspaces":{"packages":["packages/*"]}}`)
	writeFile(t, root, "packages/a/package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	declares, err := (npmGenerator{}).DeclaresDependencies(Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root}, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies: %v", err)
	}
	if !declares {
		t.Fatalf("workspace child dependency should count")
	}
}

func TestNpmGeneratorDeclaresDevOnlyOnlyWhenIncluded(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"devDependencies":{"vitest":"1.0.0"}}`)
	d := Detection{ManifestPath: filepath.Join(root, "package.json"), ProjectDir: root}
	declares, err := (npmGenerator{}).DeclaresDependencies(d, GenerateOptions{})
	if err != nil {
		t.Fatalf("DeclaresDependencies without dev: %v", err)
	}
	if declares {
		t.Fatalf("dev-only package should not declare scanned dependencies when IncludeDev=false")
	}
	declares, err = (npmGenerator{}).DeclaresDependencies(d, GenerateOptions{IncludeDev: true})
	if err != nil {
		t.Fatalf("DeclaresDependencies with dev: %v", err)
	}
	if !declares {
		t.Fatalf("dev-only package should declare dependencies when IncludeDev=true")
	}
}
