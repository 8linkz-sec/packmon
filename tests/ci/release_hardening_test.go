package ci

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
	"golang.org/x/mod/modfile"
)

const (
	patchedGovulncheckVersion = "v1.5.0"
	patchedGosecVersion       = "v2.27.1"
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

func TestGitHubWorkflowActionsArePinnedToCommitSHAs(t *testing.T) {
	t.Parallel()

	workflowDir := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("read workflow directory: %v", err)
	}

	useRE := regexp.MustCompile(`(?m)^\s*uses:\s*([^@\s#]+)@([^\s#]+)`)
	fullSHA := regexp.MustCompile(`^[0-9a-f]{40}$`)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		rel := filepath.Join(".github", "workflows", entry.Name())
		path := filepath.Join("..", "..", rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, match := range useRE.FindAllStringSubmatch(string(data), -1) {
			action, ref := match[1], match[2]
			if strings.HasPrefix(action, "./") || strings.HasPrefix(action, "../") {
				continue
			}
			if !fullSHA.MatchString(ref) {
				t.Fatalf("%s uses mutable action ref %s@%s; pin actions to a full commit SHA", rel, action, ref)
			}
		}
	}
}

func TestGitHubWorkflowsUseExplicitRunnerLabels(t *testing.T) {
	t.Parallel()

	workflowDir := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("read workflow directory: %v", err)
	}

	mutableLabels := []string{"ubuntu-latest", "macos-latest", "windows-latest"}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		rel := filepath.Join(".github", "workflows", entry.Name())
		data, err := os.ReadFile(filepath.Join("..", "..", rel)) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, label := range mutableLabels {
			if strings.Contains(text, label) {
				t.Fatalf("%s uses mutable GitHub-hosted runner label %q; use explicit supported labels", rel, label)
			}
		}
	}
}

func TestBuildToolchainPinsPatchedGoVersion(t *testing.T) {
	t.Parallel()

	patchedGoVersion := moduleToolchainGoVersion(t)
	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	wantBuildImage := "ARG PACKMON_GO_BUILDER_IMAGE=golang:" + patchedGoVersion + "-alpine@sha256:"
	dockerText := string(dockerData)
	if !strings.Contains(dockerText, wantBuildImage) || !strings.Contains(dockerText, "FROM ${PACKMON_GO_BUILDER_IMAGE} AS build") {
		t.Fatalf("Dockerfile must pin golang:%s-alpine by digest in the build-stage mirror ARG", patchedGoVersion)
	}

	for _, rel := range []string{
		filepath.Join(".github", "workflows", "ci.yml"),
		filepath.Join(".github", "workflows", "nightly.yml"),
		filepath.Join(".github", "workflows", "release.yml"),
	} {
		path := filepath.Join("..", "..", rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if strings.Contains(text, `go-version: "1.26"`) || strings.Contains(text, `go: ["1.26"]`) {
			t.Fatalf("%s still uses an unpinned Go minor version", rel)
		}
		if !strings.Contains(text, patchedGoVersion) {
			t.Fatalf("%s does not reference patched Go version %s", rel, patchedGoVersion)
		}
	}
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

func TestGitHubWorkflowsPinCurrentSecurityToolVersions(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{
		filepath.Join(".github", "workflows", "ci.yml"),
		filepath.Join(".github", "workflows", "release.yml"),
	} {
		path := filepath.Join("..", "..", rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, want := range []string{
			"golang.org/x/vuln/cmd/govulncheck@" + patchedGovulncheckVersion,
			"github.com/securego/gosec/v2/cmd/gosec@" + patchedGosecVersion,
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing security tool pin %q", rel, want)
			}
		}
		if strings.Contains(text, "govulncheck@latest") || strings.Contains(text, "gosec@latest") {
			t.Fatalf("%s must pin security tools to explicit versions", rel)
		}
	}
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

func TestNightlyFuzzWorkflowFailsWhenNoTargetsAreDiscovered(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "nightly.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read nightly.yml: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"mapfile -t fuzz_targets",
		"grep '^Fuzz'",
		"${#fuzz_targets[@]} -eq 0",
		"no parser fuzz targets discovered",
		"exit 1",
		"for target in \"${fuzz_targets[@]}\"",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("nightly parser fuzz step missing fail-closed marker %q", want)
		}
	}
	if strings.Contains(text, "-list '^Fuzz' |\n            while read -r target") {
		t.Fatal("nightly parser fuzz step still pipes discovery directly into a while loop")
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

func TestGoBuildSurfacesEnforceReadonlyModuleState(t *testing.T) {
	t.Parallel()

	dockerData, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile")) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	dockerText := string(dockerData)
	if !strings.Contains(dockerText, "ENV GOFLAGS=-mod=readonly") {
		t.Fatal("Dockerfile build stage must set GOFLAGS=-mod=readonly")
	}
	assertSubstringOrder(t, dockerText, "ENV GOFLAGS=-mod=readonly", "RUN go mod download")
	assertSubstringOrder(t, dockerText, "ENV GOFLAGS=-mod=readonly", "RUN CGO_ENABLED=0 go build")

	makeData, err := os.ReadFile(filepath.Join("..", "..", "Makefile")) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	makeText := string(makeData)
	for _, want := range []string{
		"override GOFLAGS := -mod=readonly",
		"export GOFLAGS",
	} {
		if !strings.Contains(makeText, want) {
			t.Fatalf("Makefile must enforce read-only module state, missing %q", want)
		}
	}

	for _, tc := range []struct {
		rel         string
		job         string
		step        string
		runFragment string
	}{
		{
			rel:         filepath.Join(".github", "workflows", "ci.yml"),
			job:         "lint",
			step:        "Validate GitLab CI template",
			runFragment: "go test -count=1 ./tests/ci",
		},
		{
			rel:         filepath.Join(".github", "workflows", "ci.yml"),
			job:         "test",
			step:        "Run tests",
			runFragment: "mapfile -t packages < <(go list ./...)",
		},
		{
			rel:         filepath.Join(".github", "workflows", "ci.yml"),
			job:         "e2e",
			step:        "Run E2E tests",
			runFragment: "go build -o",
		},
		{
			rel:         filepath.Join(".github", "workflows", "ci.yml"),
			job:         "security",
			step:        "govulncheck",
			runFragment: "mapfile -t packages < <(go list ./...)",
		},
		{
			rel:         filepath.Join(".github", "workflows", "ci.yml"),
			job:         "security",
			step:        "gosec",
			runFragment: "mapfile -t package_dirs < <(go list -f '{{.Dir}}' ./...)",
		},
		{
			rel:         filepath.Join(".github", "workflows", "ci.yml"),
			job:         "build",
			step:        "Build packmon",
			runFragment: "go build -ldflags=",
		},
		{
			rel:         filepath.Join(".github", "workflows", "release.yml"),
			job:         "verify",
			step:        "Run tests",
			runFragment: "mapfile -t packages < <(go list ./...)",
		},
		{
			rel:         filepath.Join(".github", "workflows", "release.yml"),
			job:         "verify",
			step:        "Run go vet",
			runFragment: "mapfile -t packages < <(go list ./...)",
		},
		{
			rel:         filepath.Join(".github", "workflows", "release.yml"),
			job:         "verify",
			step:        "Run govulncheck",
			runFragment: "mapfile -t packages < <(go list ./...)",
		},
		{
			rel:         filepath.Join(".github", "workflows", "release.yml"),
			job:         "verify",
			step:        "Run gosec",
			runFragment: "mapfile -t package_dirs < <(go list -f '{{.Dir}}' ./...)",
		},
	} {
		assertWorkflowStepEnforcesReadonlyModuleState(t, tc.rel, tc.job, tc.step, tc.runFragment)
	}

	releaseBuild := workflowStepByName(t, filepath.Join(".github", "workflows", "release.yml"), "release", "Build all targets")
	assertAllRunLinesWithGoCommandUseReadonlyModuleState(t, releaseBuild.Run, `go build -trimpath -ldflags="$LDFLAGS"`)
}

func TestGitHubReleaseWorkflowBuildsArtifactsReproducibly(t *testing.T) {
	t.Parallel()

	releaseWorkflow := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	releaseData, err := os.ReadFile(releaseWorkflow) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	releaseText := string(releaseData)
	for _, forbidden := range []string{
		"date -u +%Y-%m-%dT%H:%M:%SZ",
		"DATE=$(date -u",
		`BUILD_DATE="$(date -u`,
	} {
		if strings.Contains(releaseText, forbidden) {
			t.Fatalf("release workflow must derive build timestamps from the release commit, found wall-clock marker %q", forbidden)
		}
	}

	verifyBuild := workflowStepByName(t, filepath.Join(".github", "workflows", "release.yml"), "verify", "Build deployment images")
	for _, want := range []string{
		`BUILD_DATE="$(git show -s --format=%cI "${GITHUB_SHA}")"`,
		`--build-arg DATE="${BUILD_DATE}"`,
	} {
		if !strings.Contains(verifyBuild.Run, want) {
			t.Fatalf("release verify image build missing reproducible timestamp marker %q", want)
		}
	}

	releaseBuild := workflowStepByName(t, filepath.Join(".github", "workflows", "release.yml"), "release", "Build all targets")
	for _, want := range []string{
		`SOURCE_DATE_EPOCH="$(git show -s --format=%ct "${GITHUB_SHA}")"`,
		"export SOURCE_DATE_EPOCH",
		`DATE="$(git show -s --format=%cI "${GITHUB_SHA}")"`,
		`go build -trimpath -ldflags="$LDFLAGS"`,
	} {
		if !strings.Contains(releaseBuild.Run, want) {
			t.Fatalf("release build step missing reproducible binary marker %q", want)
		}
	}
}

func TestGitHubReleaseWorkflowPacksGoLicenseNoticesDeterministically(t *testing.T) {
	t.Parallel()

	releaseBuild := workflowStepByName(t, filepath.Join(".github", "workflows", "release.yml"), "release", "Build all targets")
	for _, forbidden := range []string{
		"tar -C dist -czf dist/go-license-notices.tar.gz go-license-notices",
		"tar -czf",
		"gzip dist/go-license-notices.tar",
	} {
		if strings.Contains(releaseBuild.Run, forbidden) {
			t.Fatalf("release workflow must not use nondeterministic license notice archive marker %q", forbidden)
		}
	}
	for _, want := range []string{
		"tar --sort=name",
		"--owner=0",
		"--group=0",
		"--numeric-owner",
		`--mtime="@${SOURCE_DATE_EPOCH}"`,
		"-C dist -cf dist/go-license-notices.tar go-license-notices",
		"gzip -n -9 dist/go-license-notices.tar",
	} {
		if !strings.Contains(releaseBuild.Run, want) {
			t.Fatalf("release workflow missing deterministic license notice archive marker %q", want)
		}
	}
	assertSubstringOrder(t, releaseBuild.Run, "go-licenses save", "tar --sort=name")
	assertSubstringOrder(t, releaseBuild.Run, "tar --sort=name", "gzip -n -9 dist/go-license-notices.tar")
	assertSubstringOrder(t, releaseBuild.Run, "gzip -n -9 dist/go-license-notices.tar", "rm -rf dist/go-license-notices")
}

func TestManualReleaseInstallDocsAndScriptsVerifyBinaryIntegrity(t *testing.T) {
	t.Parallel()

	readmePath := filepath.Join("..", "..", "README.md")
	readmeData, err := os.ReadFile(readmePath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readmeText := string(readmeData)
	for _, want := range []string{
		"### Verify Release Binary",
		"Get-FileHash .\\packmon-windows-amd64.exe -Algorithm SHA256",
		"sha256sum -c packmon-linux-amd64.sha256",
		"shasum -a 256 -c packmon-darwin-amd64.sha256",
		"--signer-workflow 8linkz-sec/packmon/.github/workflows/release.yml",
		`--source-ref "refs/tags/<release-tag>"`,
		".\\scripts\\install-release.ps1 -Version <release-tag> -Arch amd64",
		"./scripts/install-release.sh <release-tag>",
	} {
		if !strings.Contains(readmeText, want) {
			t.Fatalf("README.md missing manual release verification marker %q", want)
		}
	}
	assertSubstringOrder(t, readmeText, "### Verify Release Binary", "### Windows")
	assertSubstringOrder(t, readmeText, "### Verify Release Binary", ".\\packmon.exe version")
	assertSubstringOrder(t, readmeText, "### Verify Release Binary", "./packmon version")

	for _, rel := range []string{
		filepath.Join("scripts", "install-release.sh"),
		filepath.Join("scripts", "install-release.ps1"),
	} {
		path := filepath.Join("..", "..", rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository script path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, want := range []string{
			"checksums.txt",
			"gh attestation verify",
			"--repo 8linkz-sec/packmon",
			"--signer-workflow 8linkz-sec/packmon/.github/workflows/release.yml",
			"refs/tags/",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing release verification marker %q", rel, want)
			}
		}
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

func TestGitHubReleaseWorkflowDoesNotPublishContainerImages(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string            `yaml:"name"`
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}

	text := string(data)
	for _, forbidden := range []string{
		"packages: write",
		"ghcr.io",
		"GHCR_TOKEN",
		"docker/login-action",
		"docker/build-push-action",
		"docker/setup-buildx-action",
		"docker/setup-qemu-action",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("release workflow still contains container publish marker %q", forbidden)
		}
	}

	for _, step := range wf.Jobs["release"].Steps {
		if strings.Contains(strings.ToLower(step.Name), "docker") ||
			strings.Contains(strings.ToLower(step.Name), "ghcr") ||
			strings.Contains(strings.ToLower(step.Uses), "docker/") {
			t.Fatalf("release workflow must not publish container images; found step name=%q uses=%q", step.Name, step.Uses)
		}
	}
}

func TestGitHubReleaseWorkflowValidatesVersionAndRunsReleaseGates(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Needs any               `yaml:"needs"`
			Steps []workflowStep    `yaml:"steps"`
			Env   map[string]string `yaml:"env"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}

	verify, ok := wf.Jobs["verify"]
	if !ok {
		t.Fatal("release workflow must run a verify job before publishing")
	}
	verifyRuns := joinedStepRuns(verify.Steps)
	for _, want := range []string{
		"npm ci --ignore-scripts",
		"npm audit --audit-level=high",
		"npm run build:web",
		"git diff --exit-code -- internal/web/static/tailwind.css internal/web/static/htmx.min.js",
		"mapfile -t packages < <(go list ./...)",
		`go test -count=1 "${packages[@]}"`,
		`go vet "${packages[@]}"`,
		`govulncheck "${packages[@]}"`,
		"mapfile -t package_dirs < <(go list -f '{{.Dir}}' ./...)",
		`gosec -nosec-require-rules -nosec-require-justification "${package_dirs[@]}"`,
		"make test-integration",
		"make test-e2e",
		"go install mvdan.cc/gofumpt@v0.9.2",
		"mapfile -t go_files < <(git ls-files '*.go')",
		`gofumpt -extra -l "${go_files[@]}"`,
	} {
		if !strings.Contains(verifyRuns, want) {
			t.Fatalf("release verify job missing gate %q", want)
		}
	}
	verifyUses := strings.Builder{}
	for _, step := range verify.Steps {
		verifyUses.WriteString(step.Uses)
		verifyUses.WriteByte('\n')
	}
	for _, want := range []string{
		"actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e",
		"golangci/golangci-lint-action@82606bf257cbaff209d206a39f5134f0cfbfd2ee",
	} {
		if !strings.Contains(verifyUses.String(), want) {
			t.Fatalf("release verify job missing action %q", want)
		}
	}

	release, ok := wf.Jobs["release"]
	if !ok {
		t.Fatal("release workflow has no release job")
	}
	if !needsIncludes(release.Needs, "verify") {
		t.Fatalf("release job needs = %#v, want it to depend on verify", release.Needs)
	}

	for _, step := range release.Steps {
		if strings.Contains(step.Run, "${{ inputs.release_version }}") {
			t.Fatalf("release step %q interpolates workflow input directly into shell", step.Name)
		}
	}

	text := string(data)
	for _, want := range []string{
		"REQUESTED_RELEASE_VERSION: ${{ inputs.release_version }}",
		"RELEASE_VERSION_REGEX",
		"release version must match",
		`git rev-parse -q --verify "${RELEASE_VERSION}^{commit}"`,
		"release tag must point at checked-out commit",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("release workflow missing release-version hardening marker %q", want)
		}
	}
}

func TestGitHubReleaseWorkflowRequiresSecurityDisclosureNotes(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"Verify release security disclosure notes",
		"CHANGELOG.md",
		"Security updates",
		"Operator action",
		"Extract release notes",
		"dist/release-notes.md",
		"body_path: dist/release-notes.md",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("release workflow missing security disclosure marker %q", want)
		}
	}
	if strings.Contains(text, "generate_release_notes: true") {
		t.Fatal("release workflow must not rely only on generated release notes for security disclosures")
	}
	assertSubstringOrder(t, text, "Verify release security disclosure notes", "Build deployment images")
	assertSubstringOrder(t, text, "Extract release notes", "Create GitHub Release")

	changelogData, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md")) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	changelog := string(changelogData)
	for _, want := range []string{
		"## Unreleased",
		"### Security updates",
		"### Operator action",
		"No security fixes pending disclosure.",
		"No operator action required.",
	} {
		if !strings.Contains(changelog, want) {
			t.Fatalf("CHANGELOG.md missing security disclosure template marker %q", want)
		}
	}
}

func TestGitHubReleaseWorkflowAttestsReleaseArtifacts(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Permissions map[string]string `yaml:"permissions"`
			Steps       []workflowStep    `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}

	release, ok := wf.Jobs["release"]
	if !ok {
		t.Fatal("release workflow has no release job")
	}
	for permission, want := range map[string]string{
		"contents":     "write",
		"attestations": "write",
		"id-token":     "write",
	} {
		if got := release.Permissions[permission]; got != want {
			t.Fatalf("release permission %s = %q, want %q", permission, got, want)
		}
	}

	attestIndex := -1
	releaseIndex := -1
	for i, step := range release.Steps {
		if strings.Contains(step.Uses, "actions/attest@") {
			attestIndex = i
			if step.Uses != "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26" {
				t.Fatalf("release attest action = %q, want pinned actions/attest v4.1.0 SHA", step.Uses)
			}
			subjectPath := step.With["subject-path"]
			for _, want := range []string{
				"dist/packmon-*",
				"dist/checksums.txt",
				"dist/packmon.cdx.json",
				"dist/packmon-web-assets.cdx.json",
				"dist/go-license-notices.tar.gz",
				"dist/THIRD_PARTY_NOTICES.md",
				"dist/SECURITY.md",
				"dist/release-notes.md",
				"dist/LICENSE",
			} {
				if !strings.Contains(subjectPath, want) {
					t.Fatalf("release attestation subject-path missing %q: %q", want, subjectPath)
				}
			}
		}
		if strings.Contains(step.Uses, "softprops/action-gh-release@") {
			releaseIndex = i
		}
	}
	if attestIndex == -1 {
		t.Fatal("release workflow has no artifact attestation step")
	}
	if releaseIndex == -1 {
		t.Fatal("release workflow has no GitHub Release step")
	}
	if attestIndex > releaseIndex {
		t.Fatal("release artifacts must be attested before creating the GitHub Release")
	}
}

func TestThirdPartyNoticesShipWithEmbeddedWebAssets(t *testing.T) {
	t.Parallel()

	noticePath := filepath.Join("..", "..", "THIRD_PARTY_NOTICES.md")
	notice, err := os.ReadFile(noticePath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read THIRD_PARTY_NOTICES.md: %v", err)
	}
	noticeText := string(notice)
	for _, want := range []string{
		"Tailwind CSS",
		"MIT License",
		"Copyright (c) Tailwind Labs, Inc.",
		"htmx.org",
		"Zero-Clause BSD",
	} {
		if !strings.Contains(noticeText, want) {
			t.Fatalf("THIRD_PARTY_NOTICES.md missing %q", want)
		}
	}

	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if got := strings.Count(string(dockerData), "COPY THIRD_PARTY_NOTICES.md /usr/share/doc/packmon/THIRD_PARTY_NOTICES.md"); got != 2 {
		t.Fatalf("Dockerfile notice copy count = %d, want 2 runtime stages", got)
	}
	dockerText := string(dockerData)
	for _, want := range []string{
		"go install github.com/google/go-licenses@v1.6.0",
		"go-licenses save ./cmd/packmon ./cmd/packmon-server --save_path /go-license-notices --force",
		"--ignore github.com/8linkz-sec/packmon",
		"--ignore modernc.org/mathutil",
		"COPY --from=build /go-license-notices /usr/share/doc/packmon/go-license-notices",
	} {
		if !strings.Contains(dockerText, want) {
			t.Fatalf("Dockerfile missing Go module license notice marker %q", want)
		}
	}
	if got := strings.Count(dockerText, "COPY --from=build /go-license-notices /usr/share/doc/packmon/go-license-notices"); got != 2 {
		t.Fatalf("Dockerfile Go module license notice copy count = %d, want 2 runtime stages", got)
	}

	releaseWorkflow := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	releaseData, err := os.ReadFile(releaseWorkflow) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	releaseText := string(releaseData)
	for _, want := range []string{
		"cp THIRD_PARTY_NOTICES.md dist/THIRD_PARTY_NOTICES.md",
		"go install github.com/google/go-licenses@",
		"go-licenses save ./cmd/packmon ./cmd/packmon-server --save_path dist/go-license-notices --force",
		"--ignore github.com/8linkz-sec/packmon",
		"--ignore modernc.org/mathutil",
		"tar --sort=name",
		"gzip -n -9 dist/go-license-notices.tar",
	} {
		if !strings.Contains(releaseText, want) {
			t.Fatalf("release workflow missing third-party notice marker %q", want)
		}
	}
	if strings.Index(releaseText, "cp THIRD_PARTY_NOTICES.md dist/THIRD_PARTY_NOTICES.md") >
		strings.Index(releaseText, "find . -type f ! -name checksums.txt") {
		t.Fatal("release workflow must copy third-party notices before generating checksums")
	}
}

func TestSecurityPolicyShipsWithReleaseArtifactsAndImages(t *testing.T) {
	t.Parallel()

	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	dockerText := string(dockerData)
	const dockerSecurityCopy = "COPY SECURITY.md /usr/share/doc/packmon/SECURITY.md"
	if got := strings.Count(dockerText, dockerSecurityCopy); got != 2 {
		t.Fatalf("Dockerfile SECURITY.md copy count = %d, want 2 runtime stages", got)
	}

	releaseWorkflow := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	releaseData, err := os.ReadFile(releaseWorkflow) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	releaseText := string(releaseData)
	for _, want := range []string{
		"cp SECURITY.md dist/SECURITY.md",
		"dist/SECURITY.md",
		"files: dist/**",
	} {
		if !strings.Contains(releaseText, want) {
			t.Fatalf("release workflow missing security policy artifact marker %q", want)
		}
	}
	if strings.Index(releaseText, "cp SECURITY.md dist/SECURITY.md") >
		strings.Index(releaseText, "find . -type f ! -name checksums.txt") {
		t.Fatal("release workflow must copy SECURITY.md before generating checksums")
	}
}

func TestGitHubReleaseWorkflowPublishesSBOMAndLicenseArtifacts(t *testing.T) {
	t.Parallel()

	releaseWorkflow := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	releaseData, err := os.ReadFile(releaseWorkflow) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	releaseText := string(releaseData)
	for _, want := range []string{
		"go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@",
		"cyclonedx-gomod mod -licenses -json -output dist/packmon.cdx.json",
		"mkdir -p dist/LICENSES",
		"cp LICENSE dist/LICENSE",
		"cp SECURITY.md dist/SECURITY.md",
		"find . -type f ! -name checksums.txt -print0 | sort -z | xargs -0 sha256sum > checksums.txt",
		"files: dist/**",
	} {
		if !strings.Contains(releaseText, want) {
			t.Fatalf("release workflow missing SBOM/license artifact marker %q", want)
		}
	}
	if strings.Index(releaseText, "cyclonedx-gomod mod -licenses -json -output dist/packmon.cdx.json") >
		strings.Index(releaseText, "find . -type f ! -name checksums.txt") {
		t.Fatal("release workflow must generate the SBOM before checksums")
	}
	for _, want := range []string{
		"actions/setup-node@",
		"node-version: \"24\"",
		"npm ci --ignore-scripts",
		"npm install --global --ignore-scripts @cyclonedx/cyclonedx-npm@5.0.0",
		"cyclonedx-npm --output-format JSON --output-file dist/packmon-web-assets.cdx.json --package-lock-only -- package.json",
	} {
		if !strings.Contains(releaseText, want) {
			t.Fatalf("release workflow missing web asset SBOM marker %q", want)
		}
	}
	if strings.Index(releaseText, "cyclonedx-npm --output-format JSON --output-file dist/packmon-web-assets.cdx.json --package-lock-only -- package.json") >
		strings.Index(releaseText, "find . -type f ! -name checksums.txt") {
		t.Fatal("release workflow must generate the web asset SBOM before checksums")
	}
	if strings.Contains(releaseText, "cyclonedx-npm --output-format JSON --output-file dist/packmon-web-assets.cdx.json --package-lock-only --omit dev") ||
		strings.Contains(releaseText, "cyclonedx-npm --omit dev") {
		t.Fatal("release web asset SBOM must include devDependencies because they produce embedded server assets")
	}

	for _, rel := range []string{
		"LICENSE",
	} {
		path := filepath.Join("..", "..", rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, want := range []string{"Packmon Proprietary License", "All rights reserved"} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing private license marker %q", rel, want)
			}
		}
	}

	openAPIPath := filepath.Join("..", "..", "api", "openapi", "packmon-v1.yaml")
	openAPIData, err := os.ReadFile(openAPIPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read OpenAPI contract: %v", err)
	}
	openAPIText := string(openAPIData)
	for _, want := range []string{
		"identifier: LicenseRef-Private",
		"url: https://github.com/8linkz-sec/packmon/blob/main/LICENSE",
	} {
		if !strings.Contains(openAPIText, want) {
			t.Fatalf("OpenAPI license block missing %q", want)
		}
	}
}

func TestGitHubReleaseWorkflowUsesRequiredSBOMToolPins(t *testing.T) {
	t.Parallel()

	releaseWorkflow := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	releaseData, err := os.ReadFile(releaseWorkflow) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	releaseText := string(releaseData)

	for _, tool := range []string{"cyclonedx-gomod", "cyclonedx-npm"} {
		want := releaseInstallCommandFromRequirement(t, tool)
		if !strings.Contains(releaseText, want) {
			t.Fatalf("release workflow SBOM install for %s drifted from requirements; missing %q", tool, want)
		}
	}
}

func TestGitHubReleaseWorkflowUsesRequiredReleaseToolPins(t *testing.T) {
	t.Parallel()

	releaseWorkflow := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	releaseData, err := os.ReadFile(releaseWorkflow) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	releaseText := string(releaseData)

	for _, tool := range []string{"go-licenses"} {
		want := releaseInstallCommandFromRequirement(t, tool)
		if !strings.Contains(releaseText, want) {
			t.Fatalf("release workflow install for %s drifted from requirements; missing %q", tool, want)
		}
	}
}

func releaseInstallCommandFromRequirement(t *testing.T, tool string) string {
	t.Helper()

	for _, line := range strings.Split(requirementData(t), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 6 || fields[0] != tool {
			continue
		}
		installer := fields[5]
		if installArg, ok := strings.CutPrefix(installer, "go-install:"); ok {
			return "go install " + installArg
		}
		if installArg, ok := strings.CutPrefix(installer, "npm-global:"); ok {
			return "npm install --global --ignore-scripts " + installArg
		}
		t.Fatalf("unsupported installer for %s: %q", tool, installer)
	}
	t.Fatalf("requirements/packmon-tools.tsv missing %s", tool)
	return ""
}

func requirementToolVersion(t *testing.T, tool string) string {
	t.Helper()

	for _, line := range strings.Split(requirementData(t), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 5 || fields[0] != tool {
			continue
		}
		return fields[4]
	}
	t.Fatalf("requirements/packmon-tools.tsv missing %s", tool)
	return ""
}

func requirementData(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "requirements", "packmon-tools.tsv")) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read requirements/packmon-tools.tsv: %v", err)
	}
	return string(data)
}

func TestGitHubReusableScanWorkflowPinsBinaryAndScopesWrites(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}

	var wf struct {
		Permissions map[string]string `yaml:"permissions"`
		Jobs        map[string]struct {
			Needs       any               `yaml:"needs"`
			Permissions map[string]string `yaml:"permissions"`
			Steps       []workflowStep    `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse packmon-scan.yml: %v", err)
	}

	for permission, level := range wf.Permissions {
		if level == "write" {
			t.Fatalf("top-level reusable workflow permission %s must not be write; scope writes to optional jobs", permission)
		}
	}

	scan, ok := wf.Jobs["scan"]
	if !ok {
		t.Fatal("packmon-scan workflow has no scan job")
	}
	for permission, level := range scan.Permissions {
		if level == "write" {
			t.Fatalf("scan job permission %s must not be write", permission)
		}
	}

	sarif, ok := wf.Jobs["upload-sarif"]
	if !ok {
		t.Fatal("packmon-scan workflow must isolate SARIF upload in its own job")
	}
	if got := sarif.Permissions["security-events"]; got != "write" {
		t.Fatalf("upload-sarif security-events permission = %q, want write", got)
	}
	if !needsIncludes(sarif.Needs, "scan") {
		t.Fatalf("upload-sarif needs = %#v, want scan", sarif.Needs)
	}

	comment, ok := wf.Jobs["pr-comment"]
	if !ok {
		t.Fatal("packmon-scan workflow must isolate PR comments in its own job")
	}
	if got := comment.Permissions["issues"]; got != "write" {
		t.Fatalf("pr-comment issues permission = %q, want write", got)
	}
	if !needsIncludes(comment.Needs, "scan") {
		t.Fatalf("pr-comment needs = %#v, want scan", comment.Needs)
	}

	text := string(data)
	if strings.Contains(text, "releases/latest/download") {
		t.Fatal("packmon-scan workflow must download from an immutable release tag, not latest")
	}
	for _, want := range []string{
		"packmon_version:",
		"PACKMON_VERSION: ${{ inputs.packmon_version }}",
		"PACKMON_SCAN_PATH: ${{ inputs.scan_path }}",
		"PACKMON_FAIL_ON: ${{ inputs.fail_on }}",
		"case \"${PACKMON_FAIL_ON}\"",
		"--no-project-config",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packmon-scan workflow missing input hardening marker %q", want)
		}
	}
	for _, step := range scan.Steps {
		if strings.Contains(step.Run, "${{ inputs.scan_path }}") ||
			strings.Contains(step.Run, "${{ inputs.fail_on }}") {
			t.Fatalf("scan step %q interpolates workflow_call inputs directly into shell", step.Name)
		}
	}
	for _, step := range comment.Steps {
		if strings.Contains(step.With["script"], "${{ inputs.fail_on }}") {
			t.Fatalf("PR comment step %q interpolates fail_on directly into JavaScript", step.Name)
		}
	}
}

func TestGitHubReusableScanWorkflowPRCommentsAreOptInAndEscaped(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}

	var wf struct {
		On struct {
			WorkflowCall struct {
				Inputs map[string]struct {
					Default any `yaml:"default"`
				} `yaml:"inputs"`
			} `yaml:"workflow_call"`
		} `yaml:"on"`
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse packmon-scan.yml: %v", err)
	}

	postComment, ok := wf.On.WorkflowCall.Inputs["post_pr_comment"]
	if !ok {
		t.Fatal("packmon-scan workflow has no post_pr_comment input")
	}
	if postComment.Default != false {
		t.Fatalf("post_pr_comment default = %#v, want false so detailed PR comments are opt-in", postComment.Default)
	}

	commentJob, ok := wf.Jobs["pr-comment"]
	if !ok {
		t.Fatal("packmon-scan workflow has no pr-comment job")
	}

	script := ""
	for _, step := range commentJob.Steps {
		if strings.Contains(step.Uses, "actions/github-script@") {
			script = step.With["script"]
			break
		}
	}
	if script == "" {
		t.Fatal("pr-comment job has no github-script step")
	}

	for _, want := range []string{
		"const mdCell =",
		"const safeMarkdownURL =",
		"const packageCell =",
		"const advisoryCell =",
		".replace(/\\|/g, '\\\\|')",
		".replace(/[\\r\\n\\t]+/g, ' ')",
		"new URL(raw)",
		"const findings = Array.isArray(results.findings) ? results.findings : [];",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("PR comment script missing Markdown escaping marker %q", want)
		}
	}

	for _, forbidden := range []string{
		"`| ${f.severity} | ${pkg} | ${f.ecosystem} | ${advisory}",
		"`| ${f.severity} | ${pkg} | ${f.ecosystem} | ${threat}",
		"`| ${f.severity} | ${pkg} | ${f.ecosystem} | ${risk}",
		"`| ${f.severity} | ${pkg} | ${f.ecosystem} | ${status}",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("PR comment script still interpolates raw finding fields: %q", forbidden)
		}
	}
}

func TestGitHubReusableScanWorkflowPRCommentMarkdownEscapingExecutesScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skipf("node executable not found; skipping executable PR comment Markdown escaping contract: %v", err)
	}

	step := workflowStepByName(t, filepath.Join(".github", "workflows", "packmon-scan.yml"), "pr-comment", "PR comment")
	if !strings.Contains(step.Uses, "actions/github-script@") {
		t.Fatalf("pr-comment PR comment step uses %q, want actions/github-script", step.Uses)
	}
	script := strings.TrimSpace(step.With["script"])
	if script == "" {
		t.Fatal("pr-comment github-script step has no script body")
	}

	resultsPath := filepath.FromSlash("/tmp/packmon-results/results.json")
	resultsDir := filepath.Dir(resultsPath)
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		t.Fatalf("create workflow results directory %s: %v", resultsDir, err)
	}
	if _, err := os.Stat(resultsPath); err == nil {
		t.Skipf("%s already exists; skipping to avoid overwriting shared workflow artifact path", resultsPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat workflow results path %s: %v", resultsPath, err)
	}
	t.Cleanup(func() {
		_ = os.Remove(resultsPath)
		_ = os.Remove(resultsDir)
	})

	results := map[string]any{
		"findings_count":   4,
		"packages_scanned": 11,
		"mode":             "remote",
		"feed_status":      "degraded|partial",
		"db_stale":         true,
		"db_age_days":      "12|[days](https://example.test)",
		"findings": []map[string]any{
			{
				"type":          "vulnerability",
				"severity":      "HIGH|`sev`",
				"name":          "pkg|name[link](https://evil.example)<tag>",
				"version":       "1.0.0`beta`",
				"ecosystem":     "npm|ecosystem",
				"advisory_id":   "GHSA-[bad](link)|`id`",
				"url":           "javascript:alert(1)",
				"fixed_version": "2.0.0|[fix](https://fix.example)",
				"source":        "OSV|<source>",
			},
			{
				"type":      "malicious",
				"severity":  "CRITICAL|`sev`",
				"name":      "evil\nname|pkg",
				"version":   "0.0.1",
				"ecosystem": "pypi|ecosystem",
				"risk_type": "typosquat|[risk](https://risk.example)",
				"source":    "reversinglabs|<source>",
			},
			{
				"type":      "supply_chain_risk",
				"severity":  "HIGH|`sev`",
				"name":      "risky|pkg",
				"version":   "3.2.1",
				"ecosystem": "npm|ecosystem",
				"title":     "maintainer <takeover>|[risk](https://risk.example)",
				"source":    "socket|<source>",
			},
			{
				"type":          "lifecycle",
				"severity":      "MEDIUM|`sev`",
				"name":          "legacy|pkg",
				"version":       "4.5.6",
				"ecosystem":     "maven|ecosystem",
				"title":         "unsupported|[status](https://status.example)",
				"fixed_version": "5.0.0|[fix](https://fix.example)",
				"source":        "endoflife.date|<source>",
			},
		},
	}
	resultsJSON, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal hostile scan results fixture: %v", err)
	}
	if err := os.WriteFile(resultsPath, resultsJSON, 0o600); err != nil {
		t.Fatalf("write workflow results fixture %s: %v", resultsPath, err)
	}

	harness := fmt.Sprintf(`
const captured = [];
const github = {
  rest: {
    issues: {
      listComments: async () => ({ data: [{ id: 321, body: '## Packmon Security Scan\nold body' }] }),
      updateComment: async (args) => {
        captured.push({ method: 'updateComment', args });
        return { data: { id: args.comment_id } };
      },
      createComment: async (args) => {
        captured.push({ method: 'createComment', args });
        return { data: { id: 654 } };
      },
    },
  },
};
const context = {
  repo: { owner: '8linkz-sec', repo: 'packmon' },
  issue: { number: 476 },
};

(async () => {
%s
  process.stdout.write(JSON.stringify(captured));
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
`, script)
	harnessPath := filepath.Join(t.TempDir(), "pr-comment-harness.js")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatalf("write Node harness: %v", err)
	}

	cmd := exec.Command(node, harnessPath) // #nosec G204 -- test executes the local Node binary with a generated harness path.
	cmd.Env = append(os.Environ(), "PACKMON_FAIL_ON=LOW")
	cmd.Dir = filepath.Join("..", "..")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("execute PR comment github-script with Node: %v\n%s", err, output)
	}

	var calls []struct {
		Method string `json:"method"`
		Args   struct {
			Body string `json:"body"`
		} `json:"args"`
	}
	if err := json.Unmarshal(output, &calls); err != nil {
		t.Fatalf("parse captured PR comment call JSON %q: %v", output, err)
	}
	if len(calls) != 1 {
		t.Fatalf("captured %d PR comment API calls, want 1: %#v", len(calls), calls)
	}
	if calls[0].Method != "updateComment" {
		t.Fatalf("captured PR comment method = %q, want updateComment", calls[0].Method)
	}
	body := calls[0].Args.Body
	for _, want := range []string{
		"> **Coverage warning:** Packmon scan coverage degraded. feed_status=degraded\\|partial",
		"### Vulnerability Findings",
		"### Malicious Findings",
		"### Supply Chain Risk Findings",
		"### Lifecycle Findings",
		"HIGH\\|\\`sev\\`",
		"pkg\\|name\\[link\\]\\(https://evil.example\\)&lt;tag&gt;@1.0.0\\`beta\\`",
		"GHSA-\\[bad\\]\\(link\\)\\|\\`id\\`",
		"typosquat\\|\\[risk\\]\\(https://risk.example\\)",
		"maintainer &lt;takeover&gt;\\|\\[risk\\]\\(https://risk.example\\)",
		"unsupported\\|\\[status\\]\\(https://status.example\\)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("captured PR comment body missing escaped Markdown fragment %q\nbody:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{
		"javascript:alert(1)",
		"](javascript:",
		"| pkg|name",
		"maintainer <takeover>",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("captured PR comment body contains unsafe/unescaped fragment %q\nbody:\n%s", forbidden, body)
		}
	}
}

func TestGitHubReusableScanWorkflowPRCommentLimitsFindingsPerCategory(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skipf("node executable not found; skipping executable PR comment row limit contract: %v", err)
	}

	step := workflowStepByName(t, filepath.Join(".github", "workflows", "packmon-scan.yml"), "pr-comment", "PR comment")
	if !strings.Contains(step.Uses, "actions/github-script@") {
		t.Fatalf("pr-comment PR comment step uses %q, want actions/github-script", step.Uses)
	}
	script := strings.TrimSpace(step.With["script"])
	if script == "" {
		t.Fatal("pr-comment github-script step has no script body")
	}
	for _, want := range []string{
		"const FINDINGS_PER_CATEGORY_LIMIT = 10;",
		"entries.slice(0, FINDINGS_PER_CATEGORY_LIMIT)",
		"packmon-results artifact",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("PR comment script missing bounded rendering marker %q", want)
		}
	}
	for _, forbidden := range []string{
		"for (const f of vulns)",
		"for (const f of malicious)",
		"for (const f of supplyChain)",
		"for (const f of lifecycle)",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("PR comment script still has unbounded finding loop %q", forbidden)
		}
	}

	resultsPath := filepath.FromSlash("/tmp/packmon-results/results.json")
	resultsDir := filepath.Dir(resultsPath)
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		t.Fatalf("create workflow results directory %s: %v", resultsDir, err)
	}
	if _, err := os.Stat(resultsPath); err == nil {
		t.Skipf("%s already exists; skipping to avoid overwriting shared workflow artifact path", resultsPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat workflow results path %s: %v", resultsPath, err)
	}
	t.Cleanup(func() {
		_ = os.Remove(resultsPath)
		_ = os.Remove(resultsDir)
	})

	findings := make([]map[string]any, 0, 23)
	for i := 0; i < 12; i++ {
		findings = append(findings, map[string]any{
			"type":          "vulnerability",
			"severity":      "HIGH",
			"name":          fmt.Sprintf("vulnpkg-%02d", i),
			"version":       fmt.Sprintf("1.0.%d", i),
			"ecosystem":     "npm",
			"advisory_id":   fmt.Sprintf("VULN-%02d", i),
			"fixed_version": "2.0.0",
			"source":        "osv",
		})
	}
	for i := 0; i < 11; i++ {
		findings = append(findings, map[string]any{
			"type":      "malicious",
			"severity":  "CRITICAL",
			"name":      fmt.Sprintf("malpkg-%02d", i),
			"version":   fmt.Sprintf("0.0.%d", i),
			"ecosystem": "pypi",
			"risk_type": "malware",
			"source":    "openssf",
		})
	}
	results := map[string]any{
		"findings_count":   len(findings),
		"packages_scanned": len(findings),
		"mode":             "remote",
		"feed_status":      "healthy",
		"findings":         findings,
	}
	resultsJSON, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal large scan results fixture: %v", err)
	}
	if err := os.WriteFile(resultsPath, resultsJSON, 0o600); err != nil {
		t.Fatalf("write workflow results fixture %s: %v", resultsPath, err)
	}

	harness := fmt.Sprintf(`
const captured = [];
const github = {
  rest: {
    issues: {
      listComments: async () => ({ data: [{ id: 321, body: '## Packmon Security Scan\nold body' }] }),
      updateComment: async (args) => {
        captured.push({ method: 'updateComment', args });
        return { data: { id: args.comment_id } };
      },
      createComment: async (args) => {
        captured.push({ method: 'createComment', args });
        return { data: { id: 654 } };
      },
    },
  },
};
const context = {
  repo: { owner: '8linkz-sec', repo: 'packmon' },
  issue: { number: 476 },
};

(async () => {
%s
  process.stdout.write(JSON.stringify(captured));
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
`, script)
	harnessPath := filepath.Join(t.TempDir(), "pr-comment-limit-harness.js")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatalf("write Node harness: %v", err)
	}

	cmd := exec.Command(node, harnessPath) // #nosec G204 -- test executes the local Node binary with a generated harness path.
	cmd.Env = append(os.Environ(), "PACKMON_FAIL_ON=LOW")
	cmd.Dir = filepath.Join("..", "..")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("execute PR comment github-script with Node: %v\n%s", err, output)
	}

	var calls []struct {
		Method string `json:"method"`
		Args   struct {
			Body string `json:"body"`
		} `json:"args"`
	}
	if err := json.Unmarshal(output, &calls); err != nil {
		t.Fatalf("parse captured PR comment call JSON %q: %v", output, err)
	}
	if len(calls) != 1 {
		t.Fatalf("captured %d PR comment API calls, want 1: %#v", len(calls), calls)
	}
	if calls[0].Method != "updateComment" {
		t.Fatalf("captured PR comment method = %q, want updateComment", calls[0].Method)
	}
	body := calls[0].Args.Body
	for _, want := range []string{
		"vulnpkg-00@1.0.0",
		"vulnpkg-09@1.0.9",
		"malpkg-00@0.0.0",
		"malpkg-09@0.0.9",
		"2 more vulnerability finding(s) omitted; see packmon-results artifact.",
		"1 more malicious finding(s) omitted; see packmon-results artifact.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("captured PR comment body missing bounded finding fragment %q\nbody:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{
		"vulnpkg-10@1.0.10",
		"vulnpkg-11@1.0.11",
		"malpkg-10@0.0.10",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("captured PR comment body rendered finding beyond the category cap %q\nbody:\n%s", forbidden, body)
		}
	}
}

func TestGitHubReusableScanWorkflowAttestsResultsAndVerifiesBinary(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Needs       any               `yaml:"needs"`
			Permissions map[string]string `yaml:"permissions"`
			Steps       []workflowStep    `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse packmon-scan.yml: %v", err)
	}

	scan, ok := wf.Jobs["scan"]
	if !ok {
		t.Fatal("packmon-scan workflow has no scan job")
	}
	installRun := joinedStepRuns(scan.Steps)
	for _, want := range []string{
		`gh attestation verify "/tmp/${BINARY_NAME}"`,
		"--repo 8linkz-sec/packmon",
		"--signer-workflow 8linkz-sec/packmon/.github/workflows/release.yml",
		`--source-ref "refs/tags/${PACKMON_VERSION}"`,
	} {
		if !strings.Contains(installRun, want) {
			t.Fatalf("install step missing binary attestation verification marker %q", want)
		}
	}

	attest, ok := wf.Jobs["attest-results"]
	if !ok {
		t.Fatal("packmon-scan workflow has no attest-results job")
	}
	if !needsIncludes(attest.Needs, "scan") {
		t.Fatalf("attest-results needs = %#v, want scan", attest.Needs)
	}
	for permission, want := range map[string]string{
		"contents":     "read",
		"attestations": "write",
		"id-token":     "write",
	} {
		if got := attest.Permissions[permission]; got != want {
			t.Fatalf("attest-results permission %s = %q, want %q", permission, got, want)
		}
	}

	foundAttestStep := false
	for _, step := range attest.Steps {
		if !strings.Contains(step.Uses, "actions/attest@") {
			continue
		}
		foundAttestStep = true
		if step.Uses != "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26" {
			t.Fatalf("scan result attest action = %q, want pinned actions/attest v4.1.0 SHA", step.Uses)
		}
		subjectPath := step.With["subject-path"]
		for _, want := range []string{
			"/tmp/packmon-results/results.json",
			"/tmp/packmon-results/results.sarif",
			"/tmp/packmon-results/results.xml",
		} {
			if !strings.Contains(subjectPath, want) {
				t.Fatalf("scan result attestation subject-path missing %q: %q", want, subjectPath)
			}
		}
	}
	if !foundAttestStep {
		t.Fatal("attest-results job has no artifact attestation step")
	}
}

func TestGitHubCIWorkflowRunsTaggedIntegrationTests(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Name  string `yaml:"name"`
			Needs any    `yaml:"needs"`
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}

	for key, job := range wf.Jobs {
		if key != "integration" && !strings.Contains(strings.ToLower(job.Name), "integration") {
			continue
		}
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "make test-integration") {
				return
			}
		}
		t.Fatalf("integration job %q does not run make test-integration", key)
	}
	t.Fatal("ci workflow has no integration job")
}

func TestGitHubCIWorkflowRunsTaggedE2ETestsBeforeBuild(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Name     string `yaml:"name"`
			Needs    any    `yaml:"needs"`
			RunsOn   string `yaml:"runs-on"`
			Strategy struct {
				Matrix map[string]any `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}

	e2e, ok := wf.Jobs["e2e"]
	if !ok {
		t.Fatal("ci workflow has no e2e job")
	}
	if !strings.Contains(e2e.RunsOn, "matrix.os") {
		t.Fatalf("ci e2e runs-on = %q, want matrix.os", e2e.RunsOn)
	}
	for _, wantOS := range []string{"ubuntu-24.04", "macos-15", "windows-2025"} {
		if !matrixIncludes(e2e.Strategy.Matrix, "os", wantOS) {
			t.Fatalf("ci e2e matrix os missing %q: %#v", wantOS, e2e.Strategy.Matrix)
		}
	}
	e2eRuns := joinedStepRuns(e2e.Steps)
	for _, want := range []string{
		"go build",
		"PACKMON_TEST_BIN_DIR",
		"go test -count=1 -tags e2e ./tests/e2e",
	} {
		if !strings.Contains(e2eRuns, want) {
			t.Fatalf("ci e2e job run steps missing %q", want)
		}
	}
	if !needsIncludes(e2e.Needs, "test") {
		t.Fatalf("e2e job needs = %#v, want it to depend on test", e2e.Needs)
	}

	build, ok := wf.Jobs["build"]
	if !ok {
		t.Fatal("ci workflow has no build job")
	}
	if !needsIncludes(build.Needs, "e2e") {
		t.Fatalf("build job needs = %#v, want it to depend on e2e", build.Needs)
	}
}

func TestGitHubWorkflowsUseUncachedGoTests(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{
		filepath.Join(".github", "workflows", "ci.yml"),
		filepath.Join(".github", "workflows", "nightly.yml"),
	} {
		path := filepath.Join("..", "..", rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}

		var wf struct {
			Jobs map[string]struct {
				Steps []workflowStep `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(data, &wf); err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}

		for jobName, job := range wf.Jobs {
			for _, step := range job.Steps {
				for _, line := range strings.Split(step.Run, "\n") {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "go test ") {
						continue
					}
					if !strings.Contains(line, " -count=1 ") {
						t.Fatalf("%s job %q step %q uses cacheable test command %q", rel, jobName, step.Name, line)
					}
				}
			}
		}
	}
}

func TestGitHubCIWorkflowUsesConfiguredFormatterGate(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}

	for jobName, job := range wf.Jobs {
		for _, step := range job.Steps {
			if !strings.Contains(strings.ToLower(step.Name), "gofumpt") {
				continue
			}
			if !strings.Contains(step.Run, "git ls-files '*.go'") || !strings.Contains(step.Run, `gofumpt -extra -l "${go_files[@]}"`) {
				t.Fatalf("ci job %q step %q does not scope gofumpt to tracked Go files", jobName, step.Name)
			}
			return
		}
	}

	t.Fatal("ci workflow has no gofumpt formatting step")
}

func TestGitHubCIWorkflowUsesManagedGolangCILintVersion(t *testing.T) {
	t.Parallel()

	step := workflowStepByName(t, filepath.Join(".github", "workflows", "ci.yml"), "lint", "golangci-lint")
	if !strings.Contains(step.Uses, "golangci/golangci-lint-action@") {
		t.Fatalf("ci lint step uses %q, want golangci-lint action", step.Uses)
	}
	if got, want := step.With["version"], requirementToolVersion(t, "golangci-lint"); got != want {
		t.Fatalf("ci golangci-lint version = %q, want managed requirement pin %q", got, want)
	}
}

func TestGitHubCIWorkflowVerifiesGeneratedWebAssets(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}

	for jobName, job := range wf.Jobs {
		setupNode24 := false
		runs := joinedStepRuns(job.Steps)
		for _, step := range job.Steps {
			if !strings.Contains(step.Uses, "actions/setup-node@") {
				continue
			}
			if step.With["node-version"] == "24" {
				setupNode24 = true
			}
		}
		if setupNode24 &&
			strings.Contains(runs, "npm ci --ignore-scripts") &&
			strings.Contains(runs, "npm run build:web") &&
			strings.Contains(runs, "git diff --exit-code -- internal/web/static/tailwind.css internal/web/static/htmx.min.js") {
			return
		}
		t.Logf("ci job %q does not fully gate generated web assets", jobName)
	}

	t.Fatal("ci workflow must set up Node 24, run npm ci, rebuild web assets, and fail on generated asset drift")
}

func TestGitHubCIWorkflowAuditsNPMWebAssetDependencies(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}

	security, ok := wf.Jobs["security"]
	if !ok {
		t.Fatal("ci workflow has no security job")
	}
	setupNode24 := false
	for _, step := range security.Steps {
		if strings.Contains(step.Uses, "actions/setup-node@") && step.With["node-version"] == "24" {
			setupNode24 = true
		}
	}
	if !setupNode24 {
		t.Fatal("security job must set up Node 24 for npm web asset audit")
	}
	runs := joinedStepRuns(security.Steps)
	for _, want := range []string{
		"npm ci --ignore-scripts",
		"npm audit --audit-level=high",
	} {
		if !strings.Contains(runs, want) {
			t.Fatalf("security job missing npm vulnerability gate %q", want)
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
		"GO_PACKAGES ?= $(shell go list ./...)",
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

func TestGitHubCIWorkflowRunsGoVetGate(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}

	testJob, ok := wf.Jobs["test"]
	if !ok {
		t.Fatal("ci workflow missing test job")
	}
	runs := joinedStepRuns(testJob.Steps)
	for _, want := range []string{
		"mapfile -t packages < <(go list ./...)",
		`go vet "${packages[@]}"`,
	} {
		if !strings.Contains(runs, want) {
			t.Fatalf("ci test job missing go vet gate fragment %q", want)
		}
	}
	assertSubstringOrder(t, runs, `go vet "${packages[@]}"`, `go test -count=1 -race`)
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

func TestGitHubCIWorkflowEnforcesCoverageThreshold(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}

	testJob, ok := wf.Jobs["test"]
	if !ok {
		t.Fatal("ci workflow missing test job")
	}
	runs := joinedStepRuns(testJob.Steps)
	for _, want := range []string{
		"mapfile -t packages < <(go list ./...)",
		`go vet "${packages[@]}"`,
		`go test -count=1 -race -coverprofile=coverage.out -covermode=atomic "${packages[@]}"`,
		"go run ./tools/checkcoverage -profile=coverage.out -min=79.5",
	} {
		if !strings.Contains(runs, want) {
			t.Fatalf("ci test job missing coverage gate fragment %q", want)
		}
	}
}

func TestGitHubReusableScanWorkflowUsesConfigurableArtifactRetention(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}

	var wf struct {
		On struct {
			WorkflowCall struct {
				Inputs map[string]struct {
					Default any    `yaml:"default"`
					Type    string `yaml:"type"`
				} `yaml:"inputs"`
			} `yaml:"workflow_call"`
		} `yaml:"on"`
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse packmon-scan.yml: %v", err)
	}

	retention, ok := wf.On.WorkflowCall.Inputs["artifact_retention_days"]
	if !ok {
		t.Fatal("packmon-scan workflow has no artifact_retention_days input")
	}
	if retention.Type != "number" {
		t.Fatalf("artifact_retention_days type = %q, want number", retention.Type)
	}
	if fmt.Sprint(retention.Default) != "90" {
		t.Fatalf("artifact_retention_days default = %#v, want 90", retention.Default)
	}

	scan, ok := wf.Jobs["scan"]
	if !ok {
		t.Fatal("packmon-scan workflow has no scan job")
	}
	for _, step := range scan.Steps {
		if !strings.Contains(step.Uses, "actions/upload-artifact@") {
			continue
		}
		if got := step.With["retention-days"]; got != "${{ inputs.artifact_retention_days }}" {
			t.Fatalf("packmon results retention-days = %q, want workflow input", got)
		}
		return
	}
	t.Fatal("packmon-scan workflow scan job has no upload-artifact step")
}

func TestSecurityGatesUseGoListPackageScope(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{
		filepath.Join(".github", "workflows", "ci.yml"),
		filepath.Join(".github", "workflows", "release.yml"),
		"Makefile",
		"AGENTS.md",
		"DESIGN.md",
		"SECURITY.md",
		"README.md",
	} {
		path := filepath.Join("..", "..", rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if strings.Contains(text, "gosec ./...") {
			t.Fatalf("%s uses raw gosec ./... instead of a go list package scope", rel)
		}
		if !strings.Contains(text, "go list ./...") && !strings.Contains(text, "go list -f") {
			t.Fatalf("%s does not document or configure go list package scoping", rel)
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

func TestHelmAndRancherDeploymentAssetsAreRemoved(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{
		filepath.Join("deploy", "helm"),
		filepath.Join("deploy", "rancher"),
	} {
		path := filepath.Join("..", "..", rel)
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("%s still exists; Helm/Rancher deployment assets are no longer supported", rel)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", rel, err)
		}
	}

	for _, rel := range []string{
		filepath.Join(".github", "dependabot.yml"),
		"ARCHITECTURE.md",
		"CONTRIBUTING.md",
		"Makefile",
		"README.md",
		"DESIGN.md",
		filepath.Join("docs", "runbook.md"),
	} {
		path := filepath.Join("..", "..", rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := strings.ToLower(string(data))
		for _, forbidden := range []string{
			"deploy/helm",
			"deploy\\helm",
			"deploy/rancher",
			"deploy\\rancher",
			"helm chart",
			"helm template",
			"helm-template",
			"rancher",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s still references removed Helm/Rancher deployment support via %q", rel, forbidden)
			}
		}
	}
}

func TestDependabotCoversRootNPMWebAssets(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{"package.json", "package-lock.json"} {
		if _, err := os.Stat(filepath.Join("..", "..", rel)); err != nil {
			t.Fatalf("root npm web asset manifest %s is not present: %v", rel, err)
		}
	}

	path := filepath.Join("..", "..", ".github", "dependabot.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read dependabot.yml: %v", err)
	}

	var cfg struct {
		Updates []struct {
			PackageEcosystem string `yaml:"package-ecosystem"`
			Directory        string `yaml:"directory"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse dependabot.yml: %v", err)
	}

	for _, update := range cfg.Updates {
		if update.PackageEcosystem == "npm" && update.Directory == "/" {
			return
		}
	}

	t.Fatal("dependabot.yml does not monitor root npm web asset dependencies")
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

type workflowStep struct {
	Name string            `yaml:"name"`
	Run  string            `yaml:"run"`
	Uses string            `yaml:"uses"`
	Env  map[string]string `yaml:"env"`
	With map[string]string `yaml:"with"`
}

type workflowJob struct {
	Steps []workflowStep `yaml:"steps"`
}

func workflowStepByName(t *testing.T, rel, jobName, stepName string) workflowStep {
	t.Helper()

	path := filepath.Join("..", "..", rel)
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}

	var wf struct {
		Jobs map[string]workflowJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}

	job, ok := wf.Jobs[jobName]
	if !ok {
		t.Fatalf("%s has no job %q", rel, jobName)
	}
	for _, step := range job.Steps {
		if step.Name == stepName {
			return step
		}
	}
	t.Fatalf("%s job %q has no step %q", rel, jobName, stepName)
	return workflowStep{}
}

func assertWorkflowStepEnforcesReadonlyModuleState(t *testing.T, rel, jobName, stepName, runFragment string) {
	t.Helper()

	step := workflowStepByName(t, rel, jobName, stepName)
	runIndex := strings.Index(step.Run, runFragment)
	if runIndex < 0 {
		t.Fatalf("%s job %q step %q does not contain %q", rel, jobName, stepName, runFragment)
	}
	if step.Env["GOFLAGS"] == "-mod=readonly" {
		return
	}
	if exportIndex := strings.Index(step.Run, "export GOFLAGS=-mod=readonly"); exportIndex >= 0 && exportIndex < runIndex {
		return
	}
	if goCommandLineHasReadonlyModuleState(step.Run, runIndex) {
		return
	}
	t.Fatalf("%s job %q step %q must set GOFLAGS=-mod=readonly before %q", rel, jobName, stepName, runFragment)
}

func assertAllRunLinesWithGoCommandUseReadonlyModuleState(t *testing.T, run, goCommand string) {
	t.Helper()

	found := false
	for _, line := range strings.Split(run, "\n") {
		commandIndex := strings.Index(line, goCommand)
		if commandIndex < 0 {
			continue
		}
		found = true
		if !strings.Contains(line[:commandIndex], "GOFLAGS=-mod=readonly") {
			t.Fatalf("go command line %q must set GOFLAGS=-mod=readonly", strings.TrimSpace(line))
		}
	}
	if !found {
		t.Fatalf("run block does not contain go command %q", goCommand)
	}
}

func goCommandLineHasReadonlyModuleState(run string, commandIndex int) bool {
	lineStart := strings.LastIndex(run[:commandIndex], "\n") + 1
	return strings.Contains(run[lineStart:commandIndex], "GOFLAGS=-mod=readonly")
}

func joinedStepRuns(steps []workflowStep) string {
	var runs []string
	for _, step := range steps {
		if step.Run != "" {
			runs = append(runs, step.Run)
		}
	}
	return strings.Join(runs, "\n")
}

func needsIncludes(needs any, want string) bool {
	switch typed := needs.(type) {
	case string:
		return typed == want
	case []any:
		for _, item := range typed {
			if item == want {
				return true
			}
		}
	}
	return false
}

func matrixIncludes(matrix map[string]any, key, want string) bool {
	values, ok := matrix[key]
	if !ok {
		return false
	}
	switch typed := values.(type) {
	case []any:
		for _, item := range typed {
			if item == want {
				return true
			}
		}
	case []string:
		for _, item := range typed {
			if item == want {
				return true
			}
		}
	case string:
		return typed == want
	}
	return false
}
