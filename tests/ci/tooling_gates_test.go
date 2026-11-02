package ci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestNonGoFormattingGateIsConfigured(t *testing.T) {
	t.Parallel()

	editorconfig := readRepoFile(t, ".editorconfig")
	for _, want := range []string{
		"root = true",
		"end_of_line = lf",
		"insert_final_newline = true",
		"trim_trailing_whitespace = true",
		"[*.go]",
		"[Makefile]",
		"[*.{ps1,psm1}]",
	} {
		if !strings.Contains(editorconfig, want) {
			t.Fatalf(".editorconfig missing non-Go formatting marker %q", want)
		}
	}

	script := readRepoFile(t, filepath.Join("scripts", "check-non-go-format.sh"))
	for _, want := range []string{
		`git -C "$ROOT_DIR" ls-files`,
		"internal/web/static/tailwind.css",
		"internal/web/static/htmx.min.js",
		"docs/vendor/*",
		`grep -q $'\r'`,
		`grep -n '[[:blank:]]$'`,
		"tail -c 1",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("scripts/check-non-go-format.sh missing marker %q", want)
		}
	}

	makefile := readRepoFile(t, "Makefile")
	for _, want := range []string{
		"lint-nongo:",
		"bash scripts/check-non-go-format.sh",
		"lint: check-go-lint-tools lint-nongo lint-web lint-openapi lint-shell lint-docker lint-actions lint-powershell",
	} {
		if !strings.Contains(makefile, want) {
			t.Fatalf("Makefile missing non-Go formatting gate marker %q", want)
		}
	}
}

func TestWebAssetAndOpenAPILintScriptsArePinned(t *testing.T) {
	t.Parallel()

	var pkg struct {
		Scripts         map[string]string `json:"scripts"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, "package.json")), &pkg); err != nil {
		t.Fatalf("parse package.json: %v", err)
	}

	scriptMarkers := map[string][]string{
		// tailwind.config.js was removed: Tailwind v4 keeps design tokens in
		// tailwind.input.css (@theme). theme-init.js took its place in the lint set.
		"lint:js": {
			"node --check ./scripts/build-web-assets.mjs",
			"node --check ./internal/web/static/auto-refresh.js",
			"node --check ./internal/web/static/theme-init.js",
			"eslint ./scripts/build-web-assets.mjs ./internal/web/static/auto-refresh.js ./internal/web/static/theme-init.js",
		},
		"lint:css": {
			"stylelint",
			"internal/web/static/{style,tailwind.input}.css",
		},
		"lint:openapi": {
			"redocly lint ./api/openapi/packmon-v1.yaml",
		},
		"lint:web": {
			"npm run lint:js",
			"npm run lint:css",
		},
	}
	for scriptName, markers := range scriptMarkers {
		script, ok := pkg.Scripts[scriptName]
		if !ok {
			t.Fatalf("package.json missing script %q", scriptName)
		}
		for _, want := range markers {
			if !strings.Contains(script, want) {
				t.Fatalf("package.json script %s = %q, missing %q", scriptName, script, want)
			}
		}
	}

	for name, wantVersion := range map[string]string{
		"@eslint/js":   "10.0.1",
		"@redocly/cli": "2.72.1",
		"eslint":       "10.14.0",
		"stylelint":    "17.16.0",
	} {
		if got := pkg.DevDependencies[name]; got != wantVersion {
			t.Fatalf("package.json devDependency %s = %q, want %q", name, got, wantVersion)
		}
	}

	var packageLock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, "package-lock.json")), &packageLock); err != nil {
		t.Fatalf("parse package-lock.json: %v", err)
	}
	for name, wantVersion := range map[string]string{
		"node_modules/@eslint/js":   pkg.DevDependencies["@eslint/js"],
		"node_modules/@redocly/cli": pkg.DevDependencies["@redocly/cli"],
		"node_modules/eslint":       pkg.DevDependencies["eslint"],
		"node_modules/stylelint":    pkg.DevDependencies["stylelint"],
	} {
		if got := packageLock.Packages[name].Version; got != wantVersion {
			t.Fatalf("package-lock.json %s version = %q, want %q", name, got, wantVersion)
		}
	}

	eslintConfig := readRepoFile(t, "eslint.config.mjs")
	for _, want := range []string{
		`import js from "@eslint/js";`,
		"js.configs.recommended",
		`"internal/web/static/htmx.min.js"`,
		`"internal/web/static/tailwind.css"`,
	} {
		if !strings.Contains(eslintConfig, want) {
			t.Fatalf("eslint.config.mjs missing marker %q", want)
		}
	}

	stylelintConfig := readRepoFile(t, ".stylelintrc.json")
	for _, want := range []string{
		`"internal/web/static/htmx.min.js"`,
		`"internal/web/static/tailwind.css"`,
		`"block-no-empty"`,
		`"color-no-invalid-hex"`,
		`"no-duplicate-selectors"`,
	} {
		if !strings.Contains(stylelintConfig, want) {
			t.Fatalf(".stylelintrc.json missing marker %q", want)
		}
	}

	var redocly struct {
		Apis map[string]struct {
			Root string `yaml:"root"`
		} `yaml:"apis"`
		Extends []string          `yaml:"extends"`
		Rules   map[string]string `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "redocly.yaml")), &redocly); err != nil {
		t.Fatalf("parse redocly.yaml: %v", err)
	}
	if redocly.Apis["packmon@v1"].Root != "api/openapi/packmon-v1.yaml" {
		t.Fatalf("redocly.yaml packmon@v1 root = %q", redocly.Apis["packmon@v1"].Root)
	}
	if !stringSliceContains(redocly.Extends, "recommended") {
		t.Fatalf("redocly.yaml extends = %#v, want recommended", redocly.Extends)
	}
	for _, rule := range []string{"no-server-example.com", "operation-4xx-response"} {
		if redocly.Rules[rule] != "off" {
			t.Fatalf("redocly.yaml rule %s = %q, want off", rule, redocly.Rules[rule])
		}
	}
}

func TestMakefileLintTargetsEnforcePinnedTooling(t *testing.T) {
	t.Parallel()

	makefile := readRepoFile(t, "Makefile")
	for _, want := range []string{
		"GOFUMPT_VERSION ?= v0.9.2",
		"GOLANGCI_LINT_VERSION ?= v2.14.0",
		"SHELLCHECK_IMAGE ?= koalaman/shellcheck-alpine:v0.10.0",
		"HADOLINT_IMAGE ?= hadolint/hadolint:v2.12.0-alpine",
		"ACTIONLINT_VERSION ?= v1.7.7",
		"PSSCRIPTANALYZER_VERSION ?= 1.24.0",
		"lint: check-go-lint-tools lint-nongo lint-web lint-openapi lint-shell lint-docker lint-actions lint-powershell",
		"fmt: check-gofumpt-tool",
		"check-go-lint-tools: check-gofumpt-tool check-golangci-lint-tool",
		"check-gofumpt-tool:",
		"gofumpt -version",
		"$(GOFUMPT_VERSION)",
		"check-golangci-lint-tool:",
		"golangci-lint version",
		"$(GOLANGCI_LINT_VERSION_NUMBER)",
		"lint-shell:",
		"$(SHELLCHECK_IMAGE)",
		"lint-docker:",
		"$(HADOLINT_IMAGE)",
		"lint-actions:",
		"$(ACTIONLINT_VERSION)",
		"lint-powershell:",
		"$(PSSCRIPTANALYZER_VERSION)",
	} {
		if !strings.Contains(makefile, want) {
			t.Fatalf("Makefile missing pinned tooling marker %q", want)
		}
	}
}

// TestMakefileGateStepsFailOnFindingsAndIgnoreScratchDirs keeps the lint and
// security steps meaningful: actionlint must not fail verify when the repo
// ships no workflows, PSScriptAnalyzer must turn findings into a non-zero exit,
// and trivy must not scan gitignored scratch copies under .gotmp or .build.
func TestMakefileGateStepsFailOnFindingsAndIgnoreScratchDirs(t *testing.T) {
	t.Parallel()

	makefile := readRepoFile(t, "Makefile")
	for _, want := range []string{
		`@if [ ! -d .github/workflows ]; then echo "lint-actions: .github/workflows absent, skipping actionlint"; exit 0; fi; \`,
		`$$findings = Invoke-ScriptAnalyzer -Path scripts -Recurse -Severity Error; if ($$findings) { $$findings; exit 1 }`,
		"--exit-code 1 --skip-dirs .gotmp,.build .",
	} {
		if !strings.Contains(makefile, want) {
			t.Fatalf("Makefile missing gate marker %q", want)
		}
	}
}

func TestGolangCIConfigContract(t *testing.T) {
	var cfg struct {
		Version string `yaml:"version"`
		Linters struct {
			Default  string   `yaml:"default"`
			Enable   []string `yaml:"enable"`
			Settings struct {
				Misspell struct {
					IgnoreRules []string `yaml:"ignore-rules"`
				} `yaml:"misspell"`
				Nolintlint struct {
					RequireExplanation bool `yaml:"require-explanation"`
					RequireSpecific    bool `yaml:"require-specific"`
				} `yaml:"nolintlint"`
				Gosec struct {
					Excludes []string `yaml:"excludes"`
				} `yaml:"gosec"`
			} `yaml:"settings"`
		} `yaml:"linters"`
		Formatters struct {
			Enable   []string `yaml:"enable"`
			Settings struct {
				Gofumpt struct {
					Extra struct {
						GroupParams   bool `yaml:"group-params"`
						ClotheReturns bool `yaml:"clothe-returns"`
						BalanceCalls  bool `yaml:"balance-calls"`
					} `yaml:"extra"`
				} `yaml:"gofumpt"`
			} `yaml:"settings"`
		} `yaml:"formatters"`
	}
	decoder := yaml.NewDecoder(strings.NewReader(readRepoFile(t, ".golangci.yml")))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		t.Fatalf("parse .golangci.yml: %v", err)
	}

	if cfg.Version != "2" {
		t.Fatalf(".golangci.yml version = %q, want 2", cfg.Version)
	}
	if cfg.Linters.Default != "none" {
		t.Fatalf(".golangci.yml linters.default = %q, want none", cfg.Linters.Default)
	}
	assertStringSet(t, ".golangci.yml linters.enable", cfg.Linters.Enable, []string{
		"errcheck", "gosec", "govet", "ineffassign", "misspell", "nolintlint", "staticcheck", "unused",
	})
	assertStringSet(t, ".golangci.yml misspell.ignore-rules", cfg.Linters.Settings.Misspell.IgnoreRules, []string{"packageid"})
	if !cfg.Linters.Settings.Nolintlint.RequireExplanation {
		t.Fatal(".golangci.yml nolintlint.require-explanation must be true")
	}
	if !cfg.Linters.Settings.Nolintlint.RequireSpecific {
		t.Fatal(".golangci.yml nolintlint.require-specific must be true")
	}
	if stringSliceContains(cfg.Linters.Settings.Gosec.Excludes, "G104") {
		t.Fatal(".golangci.yml must not globally exclude gosec G104; use narrow inline suppressions with rationale")
	}
	if len(cfg.Linters.Settings.Gosec.Excludes) != 0 {
		t.Fatalf(".golangci.yml gosec.excludes = %#v, want no global security-rule exclusions", cfg.Linters.Settings.Gosec.Excludes)
	}
	assertStringSet(t, ".golangci.yml formatters.enable", cfg.Formatters.Enable, []string{"gofumpt"})
	if !cfg.Formatters.Settings.Gofumpt.Extra.GroupParams ||
		!cfg.Formatters.Settings.Gofumpt.Extra.ClotheReturns ||
		!cfg.Formatters.Settings.Gofumpt.Extra.BalanceCalls {
		t.Fatalf(".golangci.yml gofumpt extra settings = group-params:%t clothe-returns:%t balance-calls:%t; all must be true",
			cfg.Formatters.Settings.Gofumpt.Extra.GroupParams,
			cfg.Formatters.Settings.Gofumpt.Extra.ClotheReturns,
			cfg.Formatters.Settings.Gofumpt.Extra.BalanceCalls)
	}
}

func TestGolangCIConfigSchemaAndBehavior(t *testing.T) {
	golangciLint, err := exec.LookPath("golangci-lint")
	if err != nil {
		t.Fatalf("golangci-lint is required for its configuration contract: %v", err)
	}
	configPath, err := filepath.Abs(filepath.Join("..", "..", ".golangci.yml"))
	if err != nil {
		t.Fatalf("resolve absolute .golangci.yml path: %v", err)
	}

	t.Run("schema accepts repository config", func(t *testing.T) {
		output, runErr := runBoundedCommand(t, "golangci config verify", golangciLint, []string{"config", "verify", "--config", configPath}, filepath.Dir(configPath), nil)
		if runErr != nil {
			t.Fatalf("golangci-lint rejected repository config: %v\n%s", runErr, output)
		}
	})

	t.Run("schema rejects unknown keys", func(t *testing.T) {
		invalidConfig := filepath.Join(t.TempDir(), ".golangci.yml")
		contents := readRepoFile(t, ".golangci.yml") + "\nunknown-contract-key: true\n"
		if err := os.WriteFile(invalidConfig, []byte(contents), 0o600); err != nil {
			t.Fatalf("write invalid config fixture: %v", err)
		}
		output, runErr := runBoundedCommand(t, "golangci invalid config verify", golangciLint, []string{"config", "verify", "--config", invalidConfig}, filepath.Dir(invalidConfig), nil)
		if runErr == nil {
			t.Fatalf("golangci-lint accepted config with unknown key\n%s", output)
		}
		if !strings.Contains(output, "unknown-contract-key") {
			t.Fatalf("golangci-lint unknown-key failure did not identify the key: %v\n%s", runErr, output)
		}
	})

	fixtures := []struct {
		name       string
		source     string
		wantPass   bool
		wantMarker string
	}{
		{
			name: "full config reports G304",
			source: `package fixture

import "os"

func ReadPath(path string) error {
	_, err := os.ReadFile(path)
	return err
}
`,
			wantMarker: "G304",
		},
		{
			name: "nonspecific nolint fails",
			source: `package fixture

import "os"

func ReadPath(path string) error {
	_, err := os.ReadFile(path) //nolint // fixture intentionally exercises nolintlint
	return err
}
`,
			wantMarker: "should mention specific linter",
		},
		{
			name: "unexplained nolint fails",
			source: `package fixture

import "os"

func ReadPath(path string) error {
	_, err := os.ReadFile(path) //nolint:gosec
	return err
}
`,
			wantMarker: "should provide explanation",
		},
		{
			name: "specific explained nolint passes",
			source: `package fixture

import "os"

func ReadPath(path string) error {
	_, err := os.ReadFile(path) //nolint:gosec // fixture deliberately accepts its caller-provided path
	return err
}
`,
			wantPass: true,
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			output, runErr := runGolangCIFixture(t, golangciLint, configPath, fixture.source)
			if fixture.wantPass {
				if runErr != nil {
					t.Fatalf("golangci-lint fixture failed: %v\n%s", runErr, output)
				}
				return
			}
			if runErr == nil {
				t.Fatalf("golangci-lint fixture unexpectedly passed\n%s", output)
			}
			if !strings.Contains(output, fixture.wantMarker) {
				t.Fatalf("golangci-lint output missing %q: %v\n%s", fixture.wantMarker, runErr, output)
			}
		})
	}
}

func assertStringSet(t *testing.T, label string, got, want []string) {
	t.Helper()

	gotCopy := append([]string(nil), got...)
	wantCopy := append([]string(nil), want...)
	sort.Strings(gotCopy)
	sort.Strings(wantCopy)
	if !reflect.DeepEqual(gotCopy, wantCopy) {
		t.Fatalf("%s = %#v, want order-independent set %#v", label, got, want)
	}
}

func runGolangCIFixture(t *testing.T, binary, configPath, source string) (string, error) {
	t.Helper()

	fixtureDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixtureDir, "go.mod"), []byte("module example.test/toolingfixture\n\ngo 1.25\n"), 0o600); err != nil {
		t.Fatalf("write fixture go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "fixture.go"), []byte(source), 0o600); err != nil {
		t.Fatalf("write fixture source: %v", err)
	}

	cacheRoot := t.TempDir()
	env := []string{
		"GOCACHE=" + filepath.Join(cacheRoot, "go-build"),
		"GOLANGCI_LINT_CACHE=" + filepath.Join(cacheRoot, "golangci-lint"),
		"GOMODCACHE=" + filepath.Join(cacheRoot, "go-mod"),
		"GOPROXY=off",
		"GOWORK=off",
		"GOFLAGS=-mod=readonly",
	}
	return runBoundedCommand(t, "golangci fixture", binary, []string{"run", "--config", configPath, "--max-issues-per-linter=0", "--max-same-issues=0", "./..."}, fixtureDir, env)
}

func runBoundedCommand(t *testing.T, label, binary string, args []string, dir string, extraEnv []string) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- test executes an explicitly resolved tooling binary with fixed or test-controlled arguments.
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return output.String(), fmt.Errorf("%s timed out after 90s", label)
	}
	return output.String(), err
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()

	path := filepath.Join("..", "..", rel)
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}
