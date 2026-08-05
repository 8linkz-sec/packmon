package ci

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
	"golang.org/x/mod/modfile"
)

func moduleToolchainGoVersion(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	modFile, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	if modFile.Toolchain == nil {
		t.Fatal("go.mod must declare an explicit toolchain")
	}
	toolchain := modFile.Toolchain.Name
	if !strings.HasPrefix(toolchain, "go") {
		t.Fatalf("go.mod toolchain %q must use a go-prefixed version", toolchain)
	}
	version := strings.TrimPrefix(toolchain, "go")
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(version) {
		t.Fatalf("go.mod toolchain %q must pin a full patch version", toolchain)
	}
	return version
}

func TestHTMLReportTemplatesAreParsedLazily(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{
		"cmd/packmon/list_all.go",
		"cmd/packmon/outdated.go",
		"internal/scanner/html.go",
	} {
		t.Run(rel, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join("..", "..", filepath.FromSlash(rel))
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", rel, err)
			}
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.VAR {
					continue
				}
				for _, spec := range gen.Specs {
					valueSpec, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, value := range valueSpec.Values {
						if isTemplateMustCall(value) {
							name := "<unnamed>"
							if i < len(valueSpec.Names) {
								name = valueSpec.Names[i].Name
							}
							t.Fatalf("%s initializes %s with template.Must at package load; parse report templates lazily", rel, name)
						}
					}
				}
			}
		})
	}
}

func isTemplateMustCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Must" {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == "template"
}

func TestGolangCILintEnablesNolintlint(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".golangci.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read .golangci.yml: %v", err)
	}

	var cfg struct {
		Linters struct {
			Enable []string `yaml:"enable"`
		} `yaml:"linters"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse .golangci.yml: %v", err)
	}
	if !slices.Contains(cfg.Linters.Enable, "nolintlint") {
		t.Fatalf(".golangci.yml linters.enable = %#v, want nolintlint enabled", cfg.Linters.Enable)
	}
}

func TestParserFuzzTargetsCoverActionsParser(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "parser", "fuzz_test.go")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read parser fuzz tests: %v", err)
	}
	if !strings.Contains(string(data), "func FuzzActionsParser(") {
		t.Fatal("internal/parser/fuzz_test.go must include FuzzActionsParser for the GitHub Actions parser")
	}
}

func TestInstallHelpersStampBinaryMetadata(t *testing.T) {
	t.Parallel()

	shellPath := filepath.Join("..", "..", "scripts", "install.sh")
	shellData, err := os.ReadFile(shellPath) //nolint:gosec // static repository script path.
	if err != nil {
		t.Fatalf("read scripts/install.sh: %v", err)
	}
	shellText := string(shellData)
	for _, want := range []string{
		`VERSION="${PACKMON_VERSION:-dev}"`,
		`PACKMON_COMMIT`,
		`PACKMON_BUILD_DATE`,
		`LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"`,
		`go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/packmon" ./cmd/packmon`,
		`go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/packmon-server" ./cmd/packmon-server`,
	} {
		if !strings.Contains(shellText, want) {
			t.Fatalf("scripts/install.sh missing build metadata marker %q", want)
		}
	}

	powerShellPath := filepath.Join("..", "..", "scripts", "install.ps1")
	powerShellData, err := os.ReadFile(powerShellPath) //nolint:gosec // static repository script path.
	if err != nil {
		t.Fatalf("read scripts/install.ps1: %v", err)
	}
	powerShellText := string(powerShellData)
	for _, want := range []string{
		`$Version = if ($env:PACKMON_VERSION)`,
		`$env:PACKMON_COMMIT`,
		`$env:PACKMON_BUILD_DATE`,
		`$Ldflags = "-s -w -X main.version=$Version -X main.commit=$Commit -X main.date=$Date"`,
		`go build -ldflags $Ldflags -o (Join-Path $BuildDir "packmon.exe") ./cmd/packmon`,
		`go build -ldflags $Ldflags -o (Join-Path $BuildDir "packmon-server.exe") ./cmd/packmon-server`,
	} {
		if !strings.Contains(powerShellText, want) {
			t.Fatalf("scripts/install.ps1 missing build metadata marker %q", want)
		}
	}
}

func TestMakeSecurityTargetRunsNPMWebAssetAudit(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "Makefile")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}

	text := string(data)
	for _, want := range []string{
		"npm ci --ignore-scripts",
		"npm audit --audit-level=high",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Makefile security target missing npm vulnerability gate %q", want)
		}
	}
}

func TestWebAssetBuildDeclaresNode20AndUsesLockfileManagedTools(t *testing.T) {
	t.Parallel()

	packageJSONPath := filepath.Join("..", "..", "package.json")
	data, err := os.ReadFile(packageJSONPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}

	var pkg struct {
		Scripts map[string]string `json:"scripts"`
		Engines map[string]string `json:"engines"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		t.Fatalf("parse package.json: %v", err)
	}

	if pkg.Engines["node"] != ">=24.11.0" {
		t.Fatalf("package.json engines.node = %q, want Node >=24.11.0", pkg.Engines["node"])
	}
	if strings.Contains(pkg.Scripts["build:web:css"], "npx") {
		t.Fatalf("build:web:css uses npx outside lockfile guardrails: %q", pkg.Scripts["build:web:css"])
	}
	if !strings.Contains(pkg.Scripts["build:web:css"], "tailwindcss ") {
		t.Fatalf("build:web:css should use the lockfile-managed local Tailwind binary, got %q", pkg.Scripts["build:web:css"])
	}

	npmrc, err := os.ReadFile(filepath.Join("..", "..", ".npmrc"))
	if err != nil {
		t.Fatalf("read .npmrc: %v", err)
	}
	if !strings.Contains(string(npmrc), "engine-strict=true") {
		t.Fatal(".npmrc must set engine-strict=true so npm ci fails on unsupported Node versions")
	}
	if !strings.Contains(string(npmrc), "ignore-scripts=true") {
		t.Fatal(".npmrc must set ignore-scripts=true so web asset installs skip dependency lifecycle scripts")
	}
}

func TestMakeTestTargetsSetGOTMPDIR(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "Makefile")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"GOTMPDIR ?= $(CURDIR)/.gotmp",
		"COVERAGE_MIN ?= 79.5",
		"GO_PACKAGES ?= $(shell go list ./... | grep -v /node_modules/)",
		"GOSEC_DIRS ?= $(shell go list -f '{{.Dir}}' ./...)",
		`mkdir -p "$(GOTMPDIR)"`,
		`GOTMPDIR="$(GOTMPDIR)" go test -count=1 -race -coverprofile=coverage.out $(GO_PACKAGES)`,
		`go run ./tools/checkcoverage -profile=coverage.out -min=$(COVERAGE_MIN)`,
		`GOTMPDIR="$(GOTMPDIR)" go vet $(GO_PACKAGES)`,
		`GOTMPDIR="$(GOTMPDIR)" go test -count=1 ./tests/ci`,
		`GOTMPDIR="$(GOTMPDIR)" PACKMON_TEST_BIN_DIR=$(CURDIR) go test -count=1 -tags integration`,
		`GOTMPDIR="$(GOTMPDIR)" PACKMON_TEST_BIN_DIR=$(CURDIR) go test -count=1 -tags e2e`,
		"GOFMT_FILES ?= $(shell git ls-files '*.go')",
		`gofumpt -extra -l $(GOFMT_FILES)`,
		`gofumpt -extra -w $(GOFMT_FILES)`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Makefile missing %q", want)
		}
	}
}

func TestContributingGuideUsesCanonicalFormatterGate(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "CONTRIBUTING.md")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read CONTRIBUTING.md: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"gofumpt -extra",
		"git ls-files '*.go'",
		"make fmt",
		"make lint",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("CONTRIBUTING.md missing canonical formatter marker %q", want)
		}
	}
	for _, forbidden := range []string{
		"gofmt -w",
		"gofumpt -w ./...",
		"gofumpt -extra -w ./...",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("CONTRIBUTING.md still contains unsafe formatter guidance %q", forbidden)
		}
	}
}

func TestReadmeTestCommandsUseUncachedGoTests(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "README.md")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "go test ") {
			continue
		}
		if strings.Contains(line, "go test -count=1 ") {
			continue
		}
		t.Fatalf("README.md uses cacheable test command %q", line)
	}
}

type composeDeployResources struct {
	Resources struct {
		Limits struct {
			Memory string `yaml:"memory"`
			CPUs   string `yaml:"cpus"`
		} `yaml:"limits"`
		Reservations struct {
			Memory string `yaml:"memory"`
		} `yaml:"reservations"`
	} `yaml:"resources"`
}

func composeCommandContains(command any, token string) bool {
	return strings.Contains(strings.ToLower(fmt.Sprint(command)), strings.ToLower(token))
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func dockerignoreContains(text, pattern string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == pattern {
			return true
		}
	}
	return false
}
