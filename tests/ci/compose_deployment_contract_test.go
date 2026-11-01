package ci

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// composeServiceContract is the parsed subset of a Compose service that the
// deployment contract tests below inspect. Parsing (instead of substring
// matching) matters: a commented-out `# restart: unless-stopped` or a port
// mapping without the matching environment entry must not count as evidence.
type composeServiceContract struct {
	Restart     string            `yaml:"restart"`
	Ports       []string          `yaml:"ports"`
	Environment map[string]string `yaml:"environment"`
	Volumes     []string          `yaml:"volumes"`
}

type composeFileContract struct {
	Services map[string]composeServiceContract `yaml:"services"`
	Volumes  map[string]any                    `yaml:"volumes"`
}

func readComposeContract(t *testing.T, name string) composeFileContract {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var compose composeFileContract
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return compose
}

// TestDockerComposeServerListenerFollowsPublishedPort pins that the container
// listener and the published container port are driven by the same
// PACKMON_SERVER_PORT expression. Publishing ${PACKMON_SERVER_PORT} on both
// sides without passing it into the container environment let a shell
// override map 8181:8181 while the image default kept the listener on 8080.
func TestDockerComposeServerListenerFollowsPublishedPort(t *testing.T) {
	t.Parallel()

	const portExpr = "${PACKMON_SERVER_PORT:-8080}"
	const wantMapping = "127.0.0.1:" + portExpr + ":" + portExpr
	for _, name := range []string{"docker-compose.yml", "docker-compose.server.yml"} {
		compose := readComposeContract(t, name)
		server, ok := compose.Services["packmon-server"]
		if !ok {
			t.Fatalf("%s has no packmon-server service", name)
		}
		if !slices.Contains(server.Ports, wantMapping) {
			t.Fatalf("%s packmon-server ports = %#v, want loopback mapping %q", name, server.Ports, wantMapping)
		}
		if got := server.Environment["PACKMON_SERVER_PORT"]; got != portExpr {
			t.Fatalf("%s packmon-server PACKMON_SERVER_PORT = %q, want %q so the listener matches the published container port", name, got, portExpr)
		}
	}
}

// TestDockerComposeFilesPersistServerFeedData pins durable feed storage
// (DESIGN.md "Deployment Architecture"): both Compose models mount the named
// feed-data volume at the prepared /data/feeds directory and point
// PACKMON_FEED_DATA_DIR at it, so container recreation keeps the git-backed
// GHSA/OpenSSF checkouts instead of falling back to temporary storage.
func TestDockerComposeFilesPersistServerFeedData(t *testing.T) {
	t.Parallel()

	wantFeedDir := map[string]string{
		"docker-compose.yml": "${PACKMON_FEED_DATA_DIR:-/data/feeds}",
		// The hardened file pins the container path: the volume is mounted at
		// /data/feeds, so an env_file value pointing elsewhere would bypass it.
		"docker-compose.server.yml": "/data/feeds",
	}
	for name, wantDir := range wantFeedDir {
		compose := readComposeContract(t, name)
		server, ok := compose.Services["packmon-server"]
		if !ok {
			t.Fatalf("%s has no packmon-server service", name)
		}
		if !slices.Contains(server.Volumes, "feed-data:/data/feeds") {
			t.Fatalf("%s packmon-server volumes = %#v, want feed-data:/data/feeds", name, server.Volumes)
		}
		if _, ok := compose.Volumes["feed-data"]; !ok {
			t.Fatalf("%s must declare the named feed-data volume, got %#v", name, compose.Volumes)
		}
		if got := server.Environment["PACKMON_FEED_DATA_DIR"]; got != wantDir {
			t.Fatalf("%s packmon-server PACKMON_FEED_DATA_DIR = %q, want %q", name, got, wantDir)
		}
	}
}

// TestDockerComposeServerFileRestartsOnlyLongLivedServices pins real, parsed
// restart policies in the production file: PostgreSQL and the server come
// back after a crash or host reboot, while the one-shot migrate and backup
// jobs never loop.
func TestDockerComposeServerFileRestartsOnlyLongLivedServices(t *testing.T) {
	t.Parallel()

	compose := readComposeContract(t, "docker-compose.server.yml")
	for _, name := range []string{"postgres", "packmon-server"} {
		service, ok := compose.Services[name]
		if !ok {
			t.Fatalf("docker-compose.server.yml has no %s service", name)
		}
		if service.Restart != "unless-stopped" {
			t.Fatalf("docker-compose.server.yml %s restart = %q, want unless-stopped", name, service.Restart)
		}
	}
	for _, name := range []string{"packmon-migrate", "packmon-backup"} {
		service, ok := compose.Services[name]
		if !ok {
			t.Fatalf("docker-compose.server.yml has no %s service", name)
		}
		if service.Restart != "" && service.Restart != "no" {
			t.Fatalf("docker-compose.server.yml one-shot %s restart = %q, want unset or \"no\"", name, service.Restart)
		}
	}
}

// TestDockerComposeRetentionDefaultsMatchDocumentedDefaults pins every
// retention default a Compose file supplies to the defaults documented in
// DESIGN.md / SECURITY.md / README.md and implemented in internal/config, so
// an absent or empty override never silently extends metadata retention.
func TestDockerComposeRetentionDefaultsMatchDocumentedDefaults(t *testing.T) {
	t.Parallel()

	documented := map[string]string{
		"PACKMON_SCAN_LOG_RETENTION":             "720h",
		"PACKMON_ADMIN_AUDIT_LOG_RETENTION":      "720h",
		"PACKMON_REFRESH_QUEUE_RETENTION":        "720h",
		"PACKMON_PACKAGE_CHECK_STATUS_RETENTION": "2160h",
		"PACKMON_AUDIT_RETENTION_INTERVAL":       "24h",
	}
	for _, name := range []string{"docker-compose.yml", "docker-compose.server.yml", "docker-compose.override.yml"} {
		compose := readComposeContract(t, name)
		for serviceName, service := range compose.Services {
			for key, value := range service.Environment {
				wantDefault, ok := documented[key]
				if !ok {
					continue
				}
				want := "${" + key + ":-" + wantDefault + "}"
				if value != want && value != wantDefault {
					t.Fatalf("%s %s %s = %q, want documented default %q", name, serviceName, key, value, want)
				}
			}
		}
	}
	// The local base file spells the defaults out; keep the two
	// metadata-retention entries present so the check above has teeth.
	base := readComposeContract(t, "docker-compose.yml")
	for _, key := range []string{"PACKMON_SCAN_LOG_RETENTION", "PACKMON_ADMIN_AUDIT_LOG_RETENTION"} {
		if _, ok := base.Services["packmon-server"].Environment[key]; !ok {
			t.Fatalf("docker-compose.yml packmon-server must set %s", key)
		}
	}
}

// TestDockerignoreMirrorsGitignore keeps every git-ignored path out of the
// Docker build context too: `COPY . .` would otherwise put local working
// documents (agent guides, backlog, test inventory), database backup dumps,
// or secrets into the build stage.
func TestDockerignoreMirrorsGitignore(t *testing.T) {
	t.Parallel()

	gitignore := repoFile(t, ".gitignore")
	dockerignore := repoFile(t, ".dockerignore")
	normalize := func(pattern string) string {
		return strings.TrimSuffix(strings.TrimPrefix(pattern, "/"), "/")
	}
	var dockerPatterns []string
	for _, line := range strings.Split(dockerignore, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		dockerPatterns = append(dockerPatterns, normalize(line))
	}
	covered := func(pattern string) bool {
		for _, docker := range dockerPatterns {
			if docker == pattern || docker == "**/"+pattern || strings.HasPrefix(pattern, docker+"/") {
				return true
			}
		}
		return false
	}
	for _, line := range strings.Split(gitignore, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !covered(normalize(line)) {
			t.Fatalf(".dockerignore does not exclude git-ignored pattern %q", line)
		}
	}

	// Subsystem agent guides live below internal/ as well, so the root-only
	// form is not enough for AGENTS.md.
	if !dockerignoreContains(dockerignore, "**/AGENTS.md") {
		t.Fatal(".dockerignore must exclude AGENTS.md at every depth via **/AGENTS.md")
	}
}
