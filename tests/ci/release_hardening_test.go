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

	"golang.org/x/mod/modfile"
	"gopkg.in/yaml.v3"
)

const (
	patchedGovulncheckVersion = "v1.4.0"
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

func TestBuildToolchainPinsPatchedGoVersion(t *testing.T) {
	t.Parallel()

	patchedGoVersion := moduleToolchainGoVersion(t)
	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	wantBuildImage := "FROM golang:" + patchedGoVersion + "-alpine@sha256:"
	dockerText := string(dockerData)
	if !strings.Contains(dockerText, wantBuildImage) || !strings.Contains(dockerText, " AS build") {
		t.Fatalf("Dockerfile must pin golang:%s-alpine by digest in the build stage", patchedGoVersion)
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

func TestDockerBuildsStampBinaryMetadata(t *testing.T) {
	t.Parallel()

	dockerData, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	dockerText := string(dockerData)
	for _, want := range []string{
		"ARG VERSION=dev",
		"ARG COMMIT=none",
		"ARG DATE=unknown",
		"-X main.version=${VERSION}",
		"-X main.commit=${COMMIT}",
		"-X main.date=${DATE}",
		"./cmd/packmon",
		"./cmd/packmon-server",
	} {
		if !strings.Contains(dockerText, want) {
			t.Fatalf("Dockerfile missing Docker build metadata marker %q", want)
		}
	}
	if strings.Count(dockerText, "-X main.version=${VERSION}") < 2 {
		t.Fatal("Dockerfile must stamp both packmon and packmon-server binaries")
	}

	composeData, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	composeText := string(composeData)
	for _, want := range []string{
		"VERSION: ${PACKMON_VERSION:-dev}",
		"COMMIT: ${PACKMON_COMMIT:-none}",
		"DATE: ${PACKMON_BUILD_DATE:-unknown}",
	} {
		if !strings.Contains(composeText, want) {
			t.Fatalf("docker-compose.yml missing build arg %q", want)
		}
	}
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

func TestDockerRuntimeStagesUseCurrentAlpine(t *testing.T) {
	t.Parallel()

	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	dockerText := string(dockerData)
	for _, want := range []string{
		"FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS server",
		"FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS cli",
	} {
		if !strings.Contains(dockerText, want) {
			t.Fatalf("Dockerfile missing runtime stage %q", want)
		}
	}
	if strings.Contains(dockerText, "FROM alpine:3.23") {
		t.Fatal("Dockerfile still uses alpine:3.23 in a runtime stage")
	}
}

func TestDockerfilePinsAllExternalBaseImagesByDigest(t *testing.T) {
	t.Parallel()

	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}

	fromRE := regexp.MustCompile(`(?m)^FROM\s+([^\s]+)`)
	for _, match := range fromRE.FindAllStringSubmatch(string(dockerData), -1) {
		imageRef := match[1]
		if imageRef == "scratch" || strings.HasPrefix(imageRef, "$") {
			continue
		}
		if !strings.Contains(imageRef, "@sha256:") {
			t.Fatalf("Dockerfile base image %q is not pinned by digest", imageRef)
		}
	}
}

func TestDockerHealthcheckFollowsInAppTLSConfiguration(t *testing.T) {
	t.Parallel()

	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	dockerText := string(dockerData)
	for _, want := range []string{
		"PACKMON_TLS_CERT_FILE",
		"PACKMON_TLS_KEY_FILE",
		"scheme=https",
		"--no-check-certificate",
		"${PACKMON_PORT:-8080}",
		"/readyz",
	} {
		if !strings.Contains(dockerText, want) {
			t.Fatalf("Dockerfile healthcheck missing TLS-aware marker %q", want)
		}
	}
	if strings.Contains(dockerText, "wget -qO- http://localhost:8080/healthz") {
		t.Fatal("Dockerfile healthcheck still hard-codes plain HTTP on port 8080")
	}
	if strings.Contains(dockerText, "/healthz") {
		t.Fatal("Dockerfile healthcheck must use /readyz instead of the liveness-only /healthz endpoint")
	}
}

func TestDockerignoreExcludesLocalStateAndPackmonConfig(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".dockerignore")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read .dockerignore: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		".gotmp/",
		".build/",
		".builds/",
		".claude/",
		".superpowers/",
		".packmon.yaml",
		".packmon.yml",
		"coverage.out",
		"*.test",
		"Audit.md",
		"Todo.txt",
		"CLAUDE.md",
		"Phase *.md",
		".idea/",
		".vscode/",
		"*.swp",
		"*.swo",
		"*~",
		".DS_Store",
		"Thumbs.db",
		"Desktop.ini",
	} {
		if !dockerignoreContains(text, want) {
			t.Fatalf(".dockerignore missing %q", want)
		}
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

func TestDockerfileDoesNotMaskGoModuleDownloadFailures(t *testing.T) {
	t.Parallel()

	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	dockerText := string(dockerData)
	if strings.Contains(dockerText, "go mod download 2>/dev/null || true") ||
		strings.Contains(dockerText, "go mod download || true") {
		t.Fatal("Dockerfile must not mask go mod download failures")
	}
	if !strings.Contains(dockerText, "RUN go mod download") {
		t.Fatal("Dockerfile should download Go modules in a cacheable layer")
	}
}

func TestDockerfileDoesNotUpgradeAlpinePackagesAtBuildTime(t *testing.T) {
	t.Parallel()

	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if strings.Contains(string(dockerData), "apk upgrade") {
		t.Fatal("Dockerfile must not run apk upgrade at build time; use pinned base images and explicit package installs")
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

func TestDeploymentAndIntegrationContainerImagesAreDigestPinned(t *testing.T) {
	t.Parallel()

	const hardenedPostgresImage = "cgr.dev/chainguard/postgres:latest@sha256:891139a6d9036632791857fb7585425f1bf0c64516fc52bc39da94305ee92461"

	for _, tc := range []struct {
		rel       string
		want      string
		forbidden []string
	}{
		{
			rel:  "docker-compose.yml",
			want: "image: " + hardenedPostgresImage,
			forbidden: []string{
				"image: postgres:18-alpine\n",
				"image: postgres:18-alpine\r\n",
				"image: postgres:18-alpine@sha256:",
			},
		},
		{
			rel:  filepath.Join("ci", "gitlab", ".packmon-scan.yml"),
			want: "image: alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40",
			forbidden: []string{
				"image: alpine:3.23\n",
				"image: alpine:3.23\r\n",
			},
		},
		{
			rel:  filepath.Join("tests", "integration", "production_test.go"),
			want: `postgresIntegrationImage = "` + hardenedPostgresImage + `"`,
			forbidden: []string{
				`"postgres:18-alpine"`,
				`"postgres:18-alpine@sha256:`,
			},
		},
		{
			rel:  filepath.Join("tests", "integration", "store_test.go"),
			want: `startIntegrationPostgres(t, "packmon-store-it")`,
			forbidden: []string{
				`"postgres:18-alpine"`,
			},
		},
		{
			rel:  filepath.Join("internal", "db", "postgres", "store_docker_test.go"),
			want: `postgresDockerTestImage = "` + hardenedPostgresImage + `"`,
			forbidden: []string{
				`"postgres:18-alpine"`,
				`"postgres:18-alpine@sha256:`,
			},
		},
		{
			rel:  filepath.Join("internal", "db", "postgres", "migrations", "migrator_docker_test.go"),
			want: `postgresMigrationTestImage = "` + hardenedPostgresImage + `"`,
			forbidden: []string{
				`"postgres:18-alpine"`,
				`"postgres:18-alpine@sha256:`,
			},
		},
	} {
		path := filepath.Join("..", "..", tc.rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", tc.rel, err)
		}
		text := string(data)
		if !strings.Contains(text, tc.want) {
			t.Fatalf("%s missing digest-pinned image marker %q", tc.rel, tc.want)
		}
		for _, forbidden := range tc.forbidden {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s still contains tag-only image reference %q", tc.rel, forbidden)
			}
		}
	}
}

func TestDockerBackedPostgresTestsUseExplicitIntegrationGate(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{
		filepath.Join("internal", "db", "postgres", "store_docker_test.go"),
		filepath.Join("internal", "db", "postgres", "lifecycle_test.go"),
		filepath.Join("internal", "db", "postgres", "store_closed_test.go"),
		filepath.Join("internal", "db", "postgres", "migrations", "migrator_docker_test.go"),
		filepath.Join("tests", "integration", "production_test.go"),
		filepath.Join("tests", "integration", "store_test.go"),
	} {
		path := filepath.Join("..", "..", rel)
		data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if !strings.HasPrefix(text, "//go:build integration\n\n") {
			t.Fatalf("%s must be behind the explicit integration build tag", rel)
		}
		for _, forbidden := range []string{
			`t.Skip("docker not available")`,
			`t.Skipf("docker postgres unavailable`,
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s silently skips Docker-backed integration coverage via %q", rel, forbidden)
			}
		}
	}

	makefile := filepath.Join("..", "..", "Makefile")
	data, err := os.ReadFile(makefile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	makeText := string(data)
	for _, want := range []string{
		"./tests/integration",
		"./internal/db/postgres",
		"./internal/db/postgres/migrations",
	} {
		if !strings.Contains(makeText, want) {
			t.Fatalf("Makefile test-integration target missing %q", want)
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
		"mapfile -t packages < <(go list ./...)",
		`go test -count=1 "${packages[@]}"`,
		`go vet "${packages[@]}"`,
		`govulncheck "${packages[@]}"`,
		"mapfile -t package_dirs < <(go list -f '{{.Dir}}' ./...)",
		`gosec -nosec-require-rules -nosec-require-justification "${package_dirs[@]}"`,
	} {
		if !strings.Contains(verifyRuns, want) {
			t.Fatalf("release verify job missing gate %q", want)
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
				"dist/go-license-notices.tar.gz",
				"dist/THIRD_PARTY_NOTICES.md",
				"dist/LICENSE",
				"dist/LICENSES/LicenseRef-Private.txt",
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

	releaseWorkflow := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	releaseData, err := os.ReadFile(releaseWorkflow) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	releaseText := string(releaseData)
	for _, want := range []string{
		"cp THIRD_PARTY_NOTICES.md dist/THIRD_PARTY_NOTICES.md",
		"go install github.com/google/go-licenses@",
		"go-licenses save ./cmd/packmon --save_path dist/go-license-notices",
		"go-licenses save ./cmd/packmon-server --save_path dist/go-license-notices",
		"tar -C dist -czf dist/go-license-notices.tar.gz go-license-notices",
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
		"cp LICENSES/LicenseRef-Private.txt dist/LICENSES/LicenseRef-Private.txt",
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

	for _, rel := range []string{
		"LICENSE",
		filepath.Join("LICENSES", "LicenseRef-Private.txt"),
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
		"url: https://github.com/8linkz-sec/packmon/blob/main/LICENSES/LicenseRef-Private.txt",
	} {
		if !strings.Contains(openAPIText, want) {
			t.Fatalf("OpenAPI license block missing %q", want)
		}
	}
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
	for _, wantOS := range []string{"ubuntu-24.04", "macos-latest", "windows-latest"} {
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
		setupNode20 := false
		runs := joinedStepRuns(job.Steps)
		for _, step := range job.Steps {
			if !strings.Contains(step.Uses, "actions/setup-node@") {
				continue
			}
			if step.With["node-version"] == "20" {
				setupNode20 = true
			}
		}
		if setupNode20 &&
			strings.Contains(runs, "npm ci --ignore-scripts") &&
			strings.Contains(runs, "npm run build:web") &&
			strings.Contains(runs, "git diff --exit-code -- internal/web/static/tailwind.css internal/web/static/htmx.min.js") {
			return
		}
		t.Logf("ci job %q does not fully gate generated web assets", jobName)
	}

	t.Fatal("ci workflow must set up Node 20, run npm ci, rebuild web assets, and fail on generated asset drift")
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

	if !strings.Contains(pkg.Engines["node"], ">=20") {
		t.Fatalf("package.json engines.node = %q, want Node 20+", pkg.Engines["node"])
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

func TestDockerComposeDoesNotRunMigrationsAutomatically(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "docker-compose.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	var compose struct {
		Services map[string]struct {
			Command   any      `yaml:"command"`
			DependsOn any      `yaml:"depends_on"`
			Profiles  []string `yaml:"profiles"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatalf("parse docker-compose.yml: %v", err)
	}
	if _, ok := compose.Services["migrate"]; ok {
		t.Fatal("docker-compose.yml must not define an auto-run migrate service")
	}
	server, ok := compose.Services["packmon-server"]
	if !ok {
		t.Fatal("docker-compose.yml has no packmon-server service")
	}
	dependsOn := strings.ToLower(fmt.Sprint(server.DependsOn))
	if strings.Contains(dependsOn, "migrate") || strings.Contains(dependsOn, "service_completed_successfully") {
		t.Fatalf("packmon-server depends_on still gates startup on migrations: %#v", server.DependsOn)
	}
	if composeCommandContains(server.Command, "migrate") {
		t.Fatalf("packmon-server must not run migrations automatically: %#v", server.Command)
	}
	if migrate, ok := compose.Services["packmon-migrate"]; ok {
		if !stringSliceContains(migrate.Profiles, "manual") {
			t.Fatalf("packmon-migrate must stay behind the manual profile, got %#v", migrate.Profiles)
		}
	}
}

func TestDockerComposeMigrationServiceUsesOnlyDatabaseSecrets(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "docker-compose.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	var compose struct {
		Services map[string]struct {
			Command     any               `yaml:"command"`
			EnvFile     any               `yaml:"env_file"`
			Environment map[string]string `yaml:"environment"`
			Profiles    []string          `yaml:"profiles"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatalf("parse docker-compose.yml: %v", err)
	}

	service, ok := compose.Services["packmon-migrate"]
	if !ok {
		t.Fatal("docker-compose.yml must define a manual packmon-migrate service")
	}
	if !composeCommandContains(service.Command, "migrate") {
		t.Fatalf("packmon-migrate command = %#v, want migrate", service.Command)
	}
	if !stringSliceContains(service.Profiles, "manual") {
		t.Fatalf("packmon-migrate profiles = %#v, want manual", service.Profiles)
	}
	if fmt.Sprint(service.EnvFile) != "<nil>" && strings.TrimSpace(fmt.Sprint(service.EnvFile)) != "" {
		t.Fatalf("packmon-migrate must not import env_file: %#v", service.EnvFile)
	}

	allowed := map[string]bool{
		"PACKMON_DB_HOST":            true,
		"PACKMON_DB_PORT":            true,
		"PACKMON_DB_NAME":            true,
		"PACKMON_DB_USER":            true,
		"PACKMON_DB_PASSWORD":        true,
		"PACKMON_DB_SSLMODE":         true,
		"PACKMON_DB_CONNECT_TIMEOUT": true,
		"PACKMON_LOG_LEVEL":          true,
		"PACKMON_LOG_FORMAT":         true,
	}
	for key := range service.Environment {
		if !allowed[key] {
			t.Fatalf("packmon-migrate receives non-migration environment key %s", key)
		}
	}
	for _, key := range []string{
		"PACKMON_DB_HOST",
		"PACKMON_DB_PORT",
		"PACKMON_DB_NAME",
		"PACKMON_DB_USER",
		"PACKMON_DB_PASSWORD",
		"PACKMON_DB_SSLMODE",
	} {
		if _, ok := service.Environment[key]; !ok {
			t.Fatalf("packmon-migrate missing required database environment key %s", key)
		}
	}
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
