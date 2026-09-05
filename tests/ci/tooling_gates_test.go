package ci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		"@redocly/cli": "2.46.1",
		"eslint":       "10.10.0",
		"stylelint":    "17.15.0",
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
		"GOLANGCI_LINT_VERSION ?= v2.11.0",
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

func TestGolangCINolintlintRequiresSpecificExplanations(t *testing.T) {
	t.Parallel()

	var cfg struct {
		Linters struct {
			Settings struct {
				Nolintlint struct {
					RequireExplanation bool `yaml:"require-explanation"`
					RequireSpecific    bool `yaml:"require-specific"`
				} `yaml:"nolintlint"`
			} `yaml:"settings"`
		} `yaml:"linters"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".golangci.yml")), &cfg); err != nil {
		t.Fatalf("parse .golangci.yml: %v", err)
	}
	if !cfg.Linters.Settings.Nolintlint.RequireExplanation {
		t.Fatal(".golangci.yml nolintlint.require-explanation must be true")
	}
	if !cfg.Linters.Settings.Nolintlint.RequireSpecific {
		t.Fatal(".golangci.yml nolintlint.require-specific must be true")
	}
}

func TestGolangCIGosecDoesNotGloballyExcludeUncheckedErrors(t *testing.T) {
	t.Parallel()

	var cfg struct {
		Linters struct {
			Settings struct {
				Gosec struct {
					Excludes []string `yaml:"excludes"`
				} `yaml:"gosec"`
			} `yaml:"settings"`
		} `yaml:"linters"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".golangci.yml")), &cfg); err != nil {
		t.Fatalf("parse .golangci.yml: %v", err)
	}

	if stringSliceContains(cfg.Linters.Settings.Gosec.Excludes, "G104") {
		t.Fatal(".golangci.yml must not globally exclude gosec G104; use narrow inline suppressions with rationale")
	}
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
