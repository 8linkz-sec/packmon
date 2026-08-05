package ci

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestDockerHardeningTestsStayOutOfReleaseCatchAll(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "ci", "release_hardening_test.go"))
	if err != nil {
		t.Fatalf("read release hardening test: %v", err)
	}
	text := string(data)
	for _, forbidden := range []string{
		"func TestDocker",
		"func TestDeploymentAndIntegrationContainerImagesAreDigestPinned",
		"func TestGitHubWorkflowsScanDeploymentImagesForOSPackageVulnerabilities",
		"func TestSecurityGatesRunTrivyFilesystemDependencyScan",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("release_hardening_test.go still contains Docker hardening test marker %q", forbidden)
		}
	}
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
		"PACKMON_GO_BUILDER_IMAGE: ${PACKMON_GO_BUILDER_IMAGE:-golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2}",
		"PACKMON_ALPINE_RUNTIME_IMAGE: ${PACKMON_ALPINE_RUNTIME_IMAGE:-alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b}",
	} {
		if !strings.Contains(composeText, want) {
			t.Fatalf("docker-compose.yml missing build arg %q", want)
		}
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
		"ARG PACKMON_ALPINE_RUNTIME_IMAGE=alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
		"FROM ${PACKMON_ALPINE_RUNTIME_IMAGE} AS server",
		"FROM ${PACKMON_ALPINE_RUNTIME_IMAGE} AS cli",
	} {
		if !strings.Contains(dockerText, want) {
			t.Fatalf("Dockerfile missing runtime stage %q", want)
		}
	}
	if strings.Contains(dockerText, "FROM alpine:3.23") {
		t.Fatal("Dockerfile still uses alpine:3.23 in a runtime stage")
	}
}

func TestDockerfilePinsAlpineRuntimePackageInstalls(t *testing.T) {
	t.Parallel()

	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	assertApkPackagesPinned(t, "Dockerfile", string(dockerData), []string{
		"ca-certificates",
		"git",
		"tzdata",
	})
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
	for _, want := range []string{
		"ARG PACKMON_GO_BUILDER_IMAGE=golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2",
		"ARG PACKMON_ALPINE_RUNTIME_IMAGE=alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
	} {
		if !strings.Contains(string(dockerData), want) {
			t.Fatalf("Dockerfile missing digest-pinned mirror build arg default %q", want)
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
		"${PACKMON_SERVER_PORT:-8080}",
		"/readyz",
	} {
		if !strings.Contains(dockerText, want) {
			t.Fatalf("Dockerfile healthcheck missing TLS-aware marker %q", want)
		}
	}
	if strings.Contains(dockerText, "PACKMON_PORT") {
		t.Fatal("Dockerfile healthcheck must use documented PACKMON_SERVER_PORT, not PACKMON_PORT")
	}
	if strings.Contains(dockerText, "wget -qO- http://localhost:8080/healthz") {
		t.Fatal("Dockerfile healthcheck still hard-codes plain HTTP on port 8080")
	}
	if strings.Contains(dockerText, "/healthz") {
		t.Fatal("Dockerfile healthcheck must use /readyz instead of the liveness-only /healthz endpoint")
	}
}

func TestDockerfileExposesPackmonListenerPortEnvironmentDefaults(t *testing.T) {
	t.Parallel()

	dockerfile := filepath.Join("..", "..", "Dockerfile")
	dockerData, err := os.ReadFile(dockerfile) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	dockerText := string(dockerData)
	for _, want := range []string{
		"ENV PACKMON_SERVER_PORT=8080",
		"ENV PACKMON_METRICS_PORT=9090",
		"EXPOSE ${PACKMON_SERVER_PORT} ${PACKMON_METRICS_PORT}",
	} {
		if !strings.Contains(dockerText, want) {
			t.Fatalf("Dockerfile listener port exposure must use documented environment defaults, missing %q", want)
		}
	}
	if strings.Contains(dockerText, "EXPOSE 8080") {
		t.Fatal("Dockerfile must not expose the server port through a hard-coded 8080 value")
	}
	if strings.Contains(dockerText, "EXPOSE ${PACKMON_SERVER_PORT} 9090") {
		t.Fatal("Dockerfile must not expose the metrics port through a hard-coded 9090 value")
	}
}

func TestDockerComposePublishesPackmonServerPortFromEnvironment(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "docker-compose.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	var compose struct {
		Services map[string]struct {
			Ports []string `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatalf("parse docker-compose.yml: %v", err)
	}
	server, ok := compose.Services["packmon-server"]
	if !ok {
		t.Fatal("docker-compose.yml has no packmon-server service")
	}
	const want = "127.0.0.1:${PACKMON_SERVER_PORT:-8080}:${PACKMON_SERVER_PORT:-8080}"
	if !slices.Contains(server.Ports, want) {
		t.Fatalf("packmon-server ports = %#v, want loopback host and container ports to follow PACKMON_SERVER_PORT via %q", server.Ports, want)
	}
	for _, port := range server.Ports {
		if port == "127.0.0.1:8080:8080" {
			t.Fatal("packmon-server must not publish the server listener through a hard-coded 8080:8080 mapping")
		}
	}
}

func TestDockerComposeLocalIsRelaxedAndServerFileIsStrict(t *testing.T) {
	t.Parallel()

	type composeDoc struct {
		Services map[string]struct {
			Command     any               `yaml:"command"`
			Environment map[string]string `yaml:"environment"`
			Volumes     []string          `yaml:"volumes"`
			DependsOn   any               `yaml:"depends_on"`
			Profiles    []string          `yaml:"profiles"`
		} `yaml:"services"`
	}

	basePath := filepath.Join("..", "..", "docker-compose.yml")
	baseData, err := os.ReadFile(basePath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	var base composeDoc
	if err := yaml.Unmarshal(baseData, &base); err != nil {
		t.Fatalf("parse docker-compose.yml: %v", err)
	}
	baseServer, ok := base.Services["packmon-server"]
	if !ok {
		t.Fatal("docker-compose.yml has no packmon-server service")
	}
	const wantBaseInsecureHTTP = "${PACKMON_ALLOW_INSECURE_LOCAL_HTTP:-false}"
	if got := baseServer.Environment["PACKMON_ALLOW_INSECURE_LOCAL_HTTP"]; got != wantBaseInsecureHTTP {
		t.Fatalf("docker-compose.yml packmon-server PACKMON_ALLOW_INSECURE_LOCAL_HTTP = %q, want permissive default %q", got, wantBaseInsecureHTTP)
	}
	baseSecrets := []string{
		"POSTGRES_PASSWORD", "PACKMON_DB_PASSWORD", "PACKMON_ADMIN_INITIAL_PASSWORD",
		"PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY",
	}
	baseText := string(baseData)
	for _, secret := range baseSecrets {
		if strings.Contains(baseText, "${"+secret+":?") {
			t.Fatalf("docker-compose.yml must not keep a hard :? guard on %s; the base must stay permissive so init-secrets can run", secret)
		}
	}
	baseMigrate, ok := base.Services["packmon-migrate"]
	if !ok {
		t.Fatal("docker-compose.yml has no packmon-migrate service")
	}
	if !stringSliceContains(baseMigrate.Profiles, "manual") {
		t.Fatalf("docker-compose.yml packmon-migrate profiles = %#v, want manual", baseMigrate.Profiles)
	}

	overridePath := filepath.Join("..", "..", "docker-compose.override.yml")
	overrideData, err := os.ReadFile(overridePath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.override.yml: %v", err)
	}

	var override composeDoc
	if err := yaml.Unmarshal(overrideData, &override); err != nil {
		t.Fatalf("parse docker-compose.override.yml: %v", err)
	}

	overrideServer, ok := override.Services["packmon-server"]
	if !ok {
		t.Fatal("docker-compose.override.yml has no packmon-server service")
	}
	const wantOverrideInsecureHTTP = "${PACKMON_ALLOW_INSECURE_LOCAL_HTTP:-true}"
	if got := overrideServer.Environment["PACKMON_ALLOW_INSECURE_LOCAL_HTTP"]; got != wantOverrideInsecureHTTP {
		t.Fatalf("docker-compose.override.yml packmon-server PACKMON_ALLOW_INSECURE_LOCAL_HTTP = %q, want local-relaxed default %q", got, wantOverrideInsecureHTTP)
	}

	initSecrets, ok := override.Services["init-secrets"]
	if !ok {
		t.Fatal("docker-compose.override.yml must define an init-secrets service")
	}
	if !composeCommandContains(initSecrets.Command, "init-secrets") {
		t.Fatalf("docker-compose.override.yml init-secrets command = %#v, want it to run the init-secrets subcommand", initSecrets.Command)
	}
	if !stringSliceContains(initSecrets.Volumes, ".:/workspace") {
		t.Fatalf("docker-compose.override.yml init-secrets volumes = %#v, want a .:/workspace bind mount", initSecrets.Volumes)
	}
	overrideMigrate, ok := override.Services["packmon-migrate"]
	if !ok {
		t.Fatal("docker-compose.override.yml must clear the manual profile on packmon-migrate for the local auto-chain")
	}
	if len(overrideMigrate.Profiles) != 0 {
		t.Fatalf("docker-compose.override.yml packmon-migrate profiles = %#v, want cleared for the local auto-chain", overrideMigrate.Profiles)
	}

	// The strict, fail-closed secret guards live in the self-contained
	// docker-compose.server.yml (fully covered by
	// TestServerComposeIsSelfContainedAndHardened in bootstrap_flow_test.go);
	// this is just a cross-check that the server file, not the base, holds them.
	serverPath := filepath.Join("..", "..", "docker-compose.server.yml")
	serverData, err := os.ReadFile(serverPath) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.server.yml: %v", err)
	}
	if !strings.Contains(string(serverData), "${PACKMON_ENCRYPTION_KEY:?") {
		t.Fatal("docker-compose.server.yml must keep the strict :? guard on PACKMON_ENCRYPTION_KEY")
	}
}

func TestDockerComposeCapsServiceLogRetention(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "docker-compose.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	var compose struct {
		Services map[string]struct {
			Logging struct {
				Driver  string            `yaml:"driver"`
				Options map[string]string `yaml:"options"`
			} `yaml:"logging"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatalf("parse docker-compose.yml: %v", err)
	}

	for _, serviceName := range []string{"postgres", "packmon-server", "packmon-migrate"} {
		service, ok := compose.Services[serviceName]
		if !ok {
			t.Fatalf("docker-compose.yml has no %s service", serviceName)
		}
		if service.Logging.Driver != "json-file" {
			t.Fatalf("%s logging driver = %q, want json-file", serviceName, service.Logging.Driver)
		}
		if service.Logging.Options["max-size"] != "10m" {
			t.Fatalf("%s logging max-size = %q, want 10m", serviceName, service.Logging.Options["max-size"])
		}
		if service.Logging.Options["max-file"] != "5" {
			t.Fatalf("%s logging max-file = %q, want 5", serviceName, service.Logging.Options["max-file"])
		}
	}
}

func TestDockerComposePostgresVolumeIsProjectScoped(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "docker-compose.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	compose := string(data)

	if !strings.Contains(compose, "postgres-data:/var/lib/postgresql/data") {
		t.Fatalf("docker-compose.yml must keep the postgres data volume mount")
	}
	if strings.Contains(compose, "name: packmon-postgres-data") {
		t.Fatalf("docker-compose.yml must not force the postgres volume to a global Docker volume name")
	}
}

func TestDockerComposeDefinesManualPostgresBackupJob(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "docker-compose.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	var compose struct {
		Services map[string]struct {
			Command     any               `yaml:"command"`
			DependsOn   any               `yaml:"depends_on"`
			Environment map[string]string `yaml:"environment"`
			Profiles    []string          `yaml:"profiles"`
			Volumes     []string          `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatalf("parse docker-compose.yml: %v", err)
	}

	backup, ok := compose.Services["packmon-backup"]
	if !ok {
		t.Fatal("docker-compose.yml must define a manual packmon-backup service")
	}
	if !stringSliceContains(backup.Profiles, "manual") {
		t.Fatalf("packmon-backup profiles = %#v, want manual", backup.Profiles)
	}
	commandText := strings.ToLower(fmt.Sprint(backup.Command))
	for _, want := range []string{
		"pg_dump",
		"--format=custom",
		"pg_restore --list",
		"/backups/packmon",
	} {
		if !strings.Contains(commandText, strings.ToLower(want)) {
			t.Fatalf("packmon-backup command missing %q: %#v", want, backup.Command)
		}
	}
	for _, key := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD"} {
		if backup.Environment[key] == "" {
			t.Fatalf("packmon-backup environment missing %s", key)
		}
	}
	if !stringSliceContains(backup.Volumes, "${PACKMON_BACKUP_DIR:-./backups}:/backups/packmon") {
		t.Fatalf("packmon-backup volumes = %#v, want operator backup bind mount", backup.Volumes)
	}
	server, ok := compose.Services["packmon-server"]
	if !ok {
		t.Fatal("docker-compose.yml has no packmon-server service")
	}
	if strings.Contains(strings.ToLower(fmt.Sprint(server.DependsOn)), "packmon-backup") {
		t.Fatalf("packmon-server must not depend on backup job: %#v", server.DependsOn)
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
		".npmrc",
		".netrc",
		"*.key",
		"*.pem",
		"*.p12",
		"*.pfx",
		"*.crt",
		"*.cer",
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

func TestDeploymentAndIntegrationContainerImagesAreDigestPinned(t *testing.T) {
	t.Parallel()

	const hardenedPostgresImage = "cgr.dev/chainguard/postgres:18@sha256:891139a6d9036632791857fb7585425f1bf0c64516fc52bc39da94305ee92461"
	const composePostgresMirrorDefault = "image: ${PACKMON_POSTGRES_IMAGE:-" + hardenedPostgresImage + "}"

	for _, tc := range []struct {
		rel       string
		want      string
		forbidden []string
	}{
		{
			rel:  "docker-compose.yml",
			want: composePostgresMirrorDefault,
			forbidden: []string{
				"image: postgres:18-alpine\n",
				"image: postgres:18-alpine\r\n",
				"image: postgres:18-alpine@sha256:",
				"image: cgr.dev/chainguard/postgres:latest@sha256:",
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
				`"cgr.dev/chainguard/postgres:latest@sha256:`,
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
				`"cgr.dev/chainguard/postgres:latest@sha256:`,
			},
		},
		{
			rel:  filepath.Join("internal", "db", "postgres", "migrations", "migrator_docker_test.go"),
			want: `postgresMigrationTestImage = "` + hardenedPostgresImage + `"`,
			forbidden: []string{
				`"postgres:18-alpine"`,
				`"postgres:18-alpine@sha256:`,
				`"cgr.dev/chainguard/postgres:latest@sha256:`,
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

func TestDockerComposeAllowsDigestPinnedPostgresImageMirrorOverride(t *testing.T) {
	t.Parallel()

	const hardenedPostgresImage = "cgr.dev/chainguard/postgres:18@sha256:891139a6d9036632791857fb7585425f1bf0c64516fc52bc39da94305ee92461"
	const wantImage = "${PACKMON_POSTGRES_IMAGE:-" + hardenedPostgresImage + "}"

	path := filepath.Join("..", "..", "docker-compose.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	var compose struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatalf("parse docker-compose.yml: %v", err)
	}

	for _, serviceName := range []string{"postgres", "packmon-backup"} {
		service, ok := compose.Services[serviceName]
		if !ok {
			t.Fatalf("docker-compose.yml has no %s service", serviceName)
		}
		if service.Image != wantImage {
			t.Fatalf("%s image = %q, want digest-pinned PACKMON_POSTGRES_IMAGE default %q", serviceName, service.Image, wantImage)
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
			Command     any                    `yaml:"command"`
			Deploy      composeDeployResources `yaml:"deploy"`
			EnvFile     any                    `yaml:"env_file"`
			Environment map[string]string      `yaml:"environment"`
			Profiles    []string               `yaml:"profiles"`
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
	if service.Deploy.Resources.Limits.Memory == "" || service.Deploy.Resources.Limits.CPUs == "" {
		t.Fatalf("packmon-migrate must set deploy.resources.limits, got %#v", service.Deploy.Resources.Limits)
	}
	if service.Deploy.Resources.Reservations.Memory == "" {
		t.Fatalf("packmon-migrate must set deploy.resources.reservations.memory, got %#v", service.Deploy.Resources.Reservations)
	}
	if service.Deploy.Resources.Limits.Memory == "1G" || service.Deploy.Resources.Limits.CPUs == "2.0" {
		t.Fatalf("packmon-migrate resource limits must be smaller than packmon-server, got %#v", service.Deploy.Resources.Limits)
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

func TestDockerComposeServerDoesNotImportPostgresBootstrapPassword(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "docker-compose.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	var compose struct {
		Services map[string]struct {
			EnvFile     any               `yaml:"env_file"`
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatalf("parse docker-compose.yml: %v", err)
	}

	server, ok := compose.Services["packmon-server"]
	if !ok {
		t.Fatal("docker-compose.yml has no packmon-server service")
	}
	if fmt.Sprint(server.EnvFile) != "<nil>" && strings.TrimSpace(fmt.Sprint(server.EnvFile)) != "" {
		t.Fatalf("packmon-server must not import broad env_file values: %#v", server.EnvFile)
	}
	if _, ok := server.Environment["POSTGRES_PASSWORD"]; ok {
		t.Fatal("packmon-server must not receive POSTGRES_PASSWORD")
	}
}

func TestDockerComposeServerUsesPreparedFeedDataDirectory(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "docker-compose.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	var compose struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatalf("parse docker-compose.yml: %v", err)
	}
	server, ok := compose.Services["packmon-server"]
	if !ok {
		t.Fatal("docker-compose.yml has no packmon-server service")
	}
	if got := server.Environment["PACKMON_FEED_DATA_DIR"]; got != "${PACKMON_FEED_DATA_DIR:-/data/feeds}" {
		t.Fatalf("packmon-server PACKMON_FEED_DATA_DIR = %q, want container default /data/feeds", got)
	}
}

func assertApkPackagesPinned(t *testing.T, source, text string, packageNames []string) {
	t.Helper()

	normalized := regexp.MustCompile(`\\r?\n\s*`).ReplaceAllString(text, " ")
	apkAddRE := regexp.MustCompile(`apk\s+add\s+--no-cache\s+([^&;\r\n]+)`)
	versionPinRE := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:-]*-r[0-9]+$`)
	found := make(map[string]bool, len(packageNames))

	for _, match := range apkAddRE.FindAllStringSubmatch(normalized, -1) {
		for _, token := range strings.Fields(match[1]) {
			token = strings.Trim(token, `"'`)
			if token == "" || strings.HasPrefix(token, "-") {
				continue
			}
			for _, packageName := range packageNames {
				if token == packageName {
					t.Fatalf("%s installs Alpine package %q without an exact version pin", source, packageName)
				}
				if !strings.HasPrefix(token, packageName+"=") {
					continue
				}
				found[packageName] = true
				version := strings.TrimPrefix(token, packageName+"=")
				if !versionPinRE.MatchString(version) {
					t.Fatalf("%s installs Alpine package %q with non-exact pin %q; want name=version-rN", source, packageName, token)
				}
			}
		}
	}

	for _, packageName := range packageNames {
		if !found[packageName] {
			t.Fatalf("%s does not install expected Alpine package %q with name=version-rN", source, packageName)
		}
	}
}
