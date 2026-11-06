package ci

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// composeServiceContract is the parsed subset of a Compose service that the
// deployment contract tests below inspect. Parsing (instead of substring
// matching) matters: a commented-out `# restart: unless-stopped` or a port
// mapping without the matching environment entry must not count as evidence.
type composeServiceContract struct {
	User            string                               `yaml:"user"`
	Restart         string                               `yaml:"restart"`
	Image           string                               `yaml:"image"`
	Profiles        []string                             `yaml:"profiles"`
	Ports           composePortList                      `yaml:"ports"`
	Environment     map[string]string                    `yaml:"environment"`
	Volumes         composeMountList                     `yaml:"volumes"`
	DependsOn       map[string]composeDependencyContract `yaml:"depends_on"`
	Command         any                                  `yaml:"command"`
	Entrypoint      any                                  `yaml:"entrypoint"`
	StopGracePeriod string                               `yaml:"stop_grace_period"`
	Build           composeBuildContract                 `yaml:"build"`
	Logging         composeLoggingContract               `yaml:"logging"`
	Deploy          composeDeployContract                `yaml:"deploy"`
}

type composeDependencyContract struct {
	Condition string `yaml:"condition"`
}

type composeBuildContract struct {
	Target string `yaml:"target"`
}

type composeLoggingContract struct {
	Driver  string            `yaml:"driver"`
	Options map[string]string `yaml:"options"`
}

type composeDeployContract struct {
	Resources composeResourcesContract `yaml:"resources"`
}

type composeResourcesContract struct {
	Limits       map[string]any `yaml:"limits"`
	Reservations map[string]any `yaml:"reservations"`
}

type composePortList []string

func (ports *composePortList) UnmarshalYAML(node *yaml.Node) error {
	for _, item := range node.Content {
		if item.Kind == yaml.ScalarNode {
			*ports = append(*ports, item.Value)
			continue
		}
		var value struct {
			HostIP    string `yaml:"host_ip"`
			Published string `yaml:"published"`
			Target    string `yaml:"target"`
		}
		if err := item.Decode(&value); err != nil {
			return err
		}
		*ports = append(*ports, value.HostIP+":"+value.Published+":"+value.Target)
	}
	return nil
}

type composeMountList []string

func (mounts *composeMountList) UnmarshalYAML(node *yaml.Node) error {
	for _, item := range node.Content {
		if item.Kind == yaml.ScalarNode {
			*mounts = append(*mounts, item.Value)
			continue
		}
		var value struct {
			Source   string `yaml:"source"`
			Target   string `yaml:"target"`
			ReadOnly bool   `yaml:"read_only"`
		}
		if err := item.Decode(&value); err != nil {
			return err
		}
		mode := "rw"
		if value.ReadOnly {
			mode = "ro"
		}
		*mounts = append(*mounts, value.Source+":"+value.Target+":"+mode)
	}
	return nil
}

type composeFileContract struct {
	Services map[string]composeServiceContract `yaml:"services"`
	Volumes  map[string]any                    `yaml:"volumes"`
}

func TestDockerComposeResolvedServiceContracts(t *testing.T) {
	t.Parallel()

	local := renderComposeContract(t, []string{"docker-compose.yml", "docker-compose.override.yml"}, validComposeEnvironment())
	production := renderComposeContract(t, []string{"docker-compose.server.yml"}, validComposeEnvironment())

	assertComposeModel := func(t *testing.T, model composeFileContract, productionModel bool) {
		t.Helper()
		postgres := requireComposeService(t, model, "postgres")
		server := requireComposeService(t, model, "packmon-server")
		migrate := requireComposeService(t, model, "packmon-migrate")
		backup := requireComposeService(t, model, "packmon-backup")

		if productionModel {
			if !reflect.DeepEqual(migrate.Profiles, []string{"manual"}) || !reflect.DeepEqual(backup.Profiles, []string{"manual"}) {
				t.Fatalf("production one-shot profiles = migrate %#v backup %#v, want [manual]", migrate.Profiles, backup.Profiles)
			}
		} else if len(migrate.Profiles) != 0 {
			t.Fatalf("local migrate profiles = %#v, want cleared", migrate.Profiles)
		}

		assertDependencyCondition(t, migrate, "postgres", "service_healthy")
		assertDependencyCondition(t, server, "postgres", "service_healthy")
		assertDependencyCondition(t, backup, "postgres", "service_healthy")
		if productionModel {
			if _, ok := server.DependsOn["packmon-migrate"]; ok {
				t.Fatal("production server must not depend on the manual migrate service")
			}
		} else {
			assertDependencyCondition(t, server, "packmon-migrate", "service_completed_successfully")
		}

		if got := server.Environment["PACKMON_SERVER_MODE"]; got != "production" {
			t.Fatalf("server mode = %q, want production", got)
		}
		wantInsecure := "false"
		if !productionModel {
			wantInsecure = "true"
		}
		if got := server.Environment["PACKMON_ALLOW_INSECURE_LOCAL_HTTP"]; got != wantInsecure {
			t.Fatalf("insecure HTTP = %q, want %q", got, wantInsecure)
		}
		if got := server.Environment["PACKMON_METRICS_HOST"]; got != "127.0.0.1" {
			t.Fatalf("metrics host = %q, want literal loopback", got)
		}
		for _, published := range append(postgres.Ports, server.Ports...) {
			if !strings.HasPrefix(published, "127.0.0.1:") {
				t.Fatalf("published port %q is not loopback-only", published)
			}
		}
		if got := server.Environment["PACKMON_SERVER_PORT"]; got != "8080" {
			t.Fatalf("resolved server listener port = %q, want 8080", got)
		}
		if !slices.Contains(server.Ports, "127.0.0.1:8080:8080") {
			t.Fatalf("server ports = %#v, want matching listener mapping", server.Ports)
		}

		wantRestart := ""
		if productionModel {
			wantRestart = "unless-stopped"
		}
		if postgres.Restart != wantRestart || server.Restart != wantRestart {
			t.Fatalf("long-lived restart = postgres %q server %q, want %q", postgres.Restart, server.Restart, wantRestart)
		}
		for name, service := range map[string]composeServiceContract{"migrate": migrate, "backup": backup} {
			if service.Restart != "" && service.Restart != "no" {
				t.Fatalf("%s restart = %q, want no restart", name, service.Restart)
			}
		}
		if got := server.Environment["PACKMON_FEED_DATA_DIR"]; got != "/data/feeds" || !slices.Contains(server.Volumes, "feed-data:/data/feeds:rw") {
			t.Fatalf("feed persistence = dir %q volumes %#v", got, server.Volumes)
		}

		for name, service := range map[string]composeServiceContract{"postgres": postgres, "server": server, "migrate": migrate, "backup": backup} {
			if service.Logging.Driver != "json-file" || service.Logging.Options["max-size"] != "10m" || service.Logging.Options["max-file"] != "5" {
				t.Fatalf("%s logging = %#v", name, service.Logging)
			}
		}
		assertResources := func(name string, service composeServiceContract, memory, cpus, reservation string) {
			t.Helper()
			if fmt.Sprint(service.Deploy.Resources.Limits["memory"]) != memory || fmt.Sprint(service.Deploy.Resources.Limits["cpus"]) != cpus || fmt.Sprint(service.Deploy.Resources.Reservations["memory"]) != reservation {
				t.Fatalf("%s resources = %#v", name, service.Deploy.Resources)
			}
		}
		assertResources("postgres", postgres, "536870912", "1", "134217728")
		assertResources("server", server, "1073741824", "2", "268435456")
		assertResources("migrate", migrate, "536870912", "1", "134217728")

		if !strings.Contains(postgres.Image, "@sha256:") || postgres.Image != backup.Image {
			t.Fatalf("PostgreSQL/backup images must share a digest pin: %q / %q", postgres.Image, backup.Image)
		}
		if server.Build.Target != "server" || migrate.Build.Target != "server" {
			t.Fatalf("server build targets = server %q migrate %q", server.Build.Target, migrate.Build.Target)
		}

		wantMigrateEnv := []string{"PACKMON_DB_CONNECT_TIMEOUT", "PACKMON_DB_HOST", "PACKMON_DB_NAME", "PACKMON_DB_PASSWORD", "PACKMON_DB_PORT", "PACKMON_DB_SSLMODE", "PACKMON_DB_USER", "PACKMON_LOG_FORMAT", "PACKMON_LOG_LEVEL"}
		gotMigrateEnv := make([]string, 0, len(migrate.Environment))
		for key := range migrate.Environment {
			gotMigrateEnv = append(gotMigrateEnv, key)
		}
		slices.Sort(gotMigrateEnv)
		if !reflect.DeepEqual(gotMigrateEnv, wantMigrateEnv) {
			t.Fatalf("migrate environment keys = %#v, want exact database/logging subset %#v", gotMigrateEnv, wantMigrateEnv)
		}
	}

	t.Run("local", func(t *testing.T) { assertComposeModel(t, local, false) })
	t.Run("production", func(t *testing.T) { assertComposeModel(t, production, true) })
}

func TestDockerComposePostgresDataStaysInsideNamedVolume(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"docker-compose.yml", "docker-compose.server.yml"} {
		name := name
		t.Run(name, func(t *testing.T) {
			compose := readComposeContract(t, name)
			postgres := requireComposeService(t, compose, "postgres")
			server := requireComposeService(t, compose, "packmon-server")
			const pgMount = "/var/lib/postgresql/data"
			pgdata := path.Clean(postgres.Environment["PGDATA"])
			rel, err := filepath.Rel(filepath.FromSlash(pgMount), filepath.FromSlash(pgdata))
			if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("PGDATA %q is not a child of %q", pgdata, pgMount)
			}
			_, postgresDeclared := compose.Volumes["postgres-data"]
			if !slices.Contains(postgres.Volumes, "postgres-data:/var/lib/postgresql/data") || !postgresDeclared {
				t.Fatalf("postgres volume contract = volumes %#v declarations %#v", postgres.Volumes, compose.Volumes)
			}
			if !slices.Contains(server.Volumes, "feed-data:/data/feeds") || server.Environment["PACKMON_FEED_DATA_DIR"] != map[string]string{"docker-compose.yml": "${PACKMON_FEED_DATA_DIR:-/data/feeds}", "docker-compose.server.yml": "/data/feeds"}[name] {
				t.Fatalf("feed volume contract = environment %#v volumes %#v", server.Environment, server.Volumes)
			}
			if _, ok := compose.Volumes["feed-data"]; !ok {
				t.Fatal("feed-data named volume is not declared")
			}
		})
	}
}

func TestDockerComposeBackupServiceContract(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"docker-compose.yml", "docker-compose.server.yml"} {
		name := name
		t.Run(name, func(t *testing.T) {
			compose := readComposeContract(t, name)
			backup := requireComposeService(t, compose, "packmon-backup")
			postgres := requireComposeService(t, compose, "postgres")
			server := requireComposeService(t, compose, "packmon-server")
			if !reflect.DeepEqual(backup.Profiles, []string{"manual"}) || backup.Image != postgres.Image || !strings.Contains(backup.Image, "@sha256:") {
				t.Fatalf("backup profile/image = %#v %q, postgres %q", backup.Profiles, backup.Image, postgres.Image)
			}
			wantPGEnv := []string{"PGDATABASE", "PGHOST", "PGPASSWORD", "PGPORT", "PGUSER"}
			gotPGEnv := make([]string, 0, len(backup.Environment))
			for key := range backup.Environment {
				gotPGEnv = append(gotPGEnv, key)
			}
			slices.Sort(gotPGEnv)
			if !reflect.DeepEqual(gotPGEnv, wantPGEnv) {
				t.Fatalf("backup environment keys = %#v", gotPGEnv)
			}
			if len(backup.Volumes) != 1 || !strings.HasSuffix(backup.Volumes[0], ":/backups/packmon") {
				t.Fatalf("backup volumes = %#v", backup.Volumes)
			}
			command := composeCommandText(t, backup.Command)
			markers := []string{"install -d -m 0700", "pg_dump --format=custom", "pg_restore --list", "find /backups/packmon"}
			last := -1
			for _, marker := range markers {
				at := strings.Index(command, marker)
				if at <= last {
					t.Fatalf("backup command marker %q missing or out of order: %q", marker, command)
				}
				last = at
			}
			if _, ok := server.DependsOn["packmon-backup"]; ok {
				t.Fatal("server must not depend on backup")
			}
		})
	}
}

func TestDockerComposeShutdownGraceCoversConfiguredTimeout(t *testing.T) {
	t.Parallel()

	const (
		shutdownExpression = "${PACKMON_SERVER_SHUTDOWN_TIMEOUT:-15s}"
		graceExpression    = "${PACKMON_SERVER_STOP_GRACE_PERIOD:-25s}"
	)
	for _, name := range []string{"docker-compose.yml", "docker-compose.server.yml"} {
		compose := readComposeContract(t, name)
		server := requireComposeService(t, compose, "packmon-server")
		if server.StopGracePeriod != graceExpression || server.Environment["PACKMON_SERVER_STOP_GRACE_PERIOD"] != graceExpression {
			t.Fatalf("%s stop grace = Compose %q container %q, want identical expression %q", name, server.StopGracePeriod, server.Environment["PACKMON_SERVER_STOP_GRACE_PERIOD"], graceExpression)
		}
		if server.Environment["PACKMON_SERVER_SHUTDOWN_TIMEOUT"] != shutdownExpression {
			t.Fatalf("%s container shutdown timeout = %q, want explicit expression %q", name, server.Environment["PACKMON_SERVER_SHUTDOWN_TIMEOUT"], shutdownExpression)
		}
	}

	for _, model := range []string{"local", "production"} {
		model := model
		for _, values := range []struct {
			name     string
			shutdown string
			grace    string
		}{
			{name: "defaults", shutdown: "15s", grace: "25s"},
			{name: "custom", shutdown: "30s", grace: "35s"},
		} {
			values := values
			t.Run(model+"_"+values.name, func(t *testing.T) {
				env := validComposeEnvironment()
				env["PACKMON_SERVER_SHUTDOWN_TIMEOUT"] = values.shutdown
				env["PACKMON_SERVER_STOP_GRACE_PERIOD"] = values.grace
				var compose composeFileContract
				if model == "local" {
					compose = renderComposeContract(t, []string{"docker-compose.yml"}, env)
				} else {
					stage := stageComposeFiles(t, []string{"docker-compose.server.yml"})
					serviceEnv := filepath.Join(stage, "shutdown.env")
					if err := os.WriteFile(serviceEnv, []byte("PACKMON_SERVER_SHUTDOWN_TIMEOUT=2s\nPACKMON_SERVER_STOP_GRACE_PERIOD=3s\n"), 0o600); err != nil {
						t.Fatalf("write synthetic shutdown environment: %v", err)
					}
					overlay := filepath.Join(stage, "shutdown.override.yml")
					if err := os.WriteFile(overlay, []byte("services:\n  packmon-server:\n    env_file: !override\n      - path: shutdown.env\n        required: true\n"), 0o600); err != nil {
						t.Fatalf("write synthetic shutdown overlay: %v", err)
					}
					compose = runComposeConfig(t, stage, []string{filepath.Join(stage, "docker-compose.server.yml"), overlay}, env, true)
				}
				server := requireComposeService(t, compose, "packmon-server")
				configured, err := time.ParseDuration(server.Environment["PACKMON_SERVER_SHUTDOWN_TIMEOUT"])
				if err != nil {
					t.Fatalf("parse configured timeout: %v", err)
				}
				containerGrace, err := time.ParseDuration(server.Environment["PACKMON_SERVER_STOP_GRACE_PERIOD"])
				if err != nil {
					t.Fatalf("parse configured container stop grace: %v", err)
				}
				grace, err := time.ParseDuration(server.StopGracePeriod)
				if err != nil {
					t.Fatalf("parse stop grace period: %v", err)
				}
				if configured != mustParseComposeDuration(t, values.shutdown) || grace != mustParseComposeDuration(t, values.grace) || containerGrace != grace {
					t.Fatalf("resolved shutdown/grace = %s/%s (container grace %s), want %s/%s", configured, grace, containerGrace, values.shutdown, values.grace)
				}
				if grace < configured || grace-configured < 5*time.Second {
					t.Fatalf("configured shutdown timeout %s lacks the five-second stop-grace buffer in %s", configured, grace)
				}
			})
		}
	}
}

func mustParseComposeDuration(t *testing.T, value string) time.Duration {
	t.Helper()
	duration, err := time.ParseDuration(value)
	if err != nil {
		t.Fatalf("parse test duration %q: %v", value, err)
	}
	return duration
}

func requireComposeService(t *testing.T, compose composeFileContract, name string) composeServiceContract {
	t.Helper()
	service, ok := compose.Services[name]
	if !ok {
		t.Fatalf("Compose model has no %s service", name)
	}
	return service
}

func assertDependencyCondition(t *testing.T, service composeServiceContract, name, want string) {
	t.Helper()
	if got := service.DependsOn[name].Condition; got != want {
		t.Fatalf("dependency %s condition = %q, want %q", name, got, want)
	}
}

func composeCommandText(t *testing.T, command any) string {
	t.Helper()
	switch value := command.(type) {
	case string:
		return value
	case []any:
		parts := make([]string, len(value))
		for i := range value {
			parts[i] = fmt.Sprint(value[i])
		}
		return strings.Join(parts, "\n")
	default:
		t.Fatalf("unexpected Compose command type %T", command)
		return ""
	}
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

// TestInitSecretsRunsAsCheckoutOwner pins the native-Linux bootstrap fix:
// init-secrets writes .env into the bind-mounted checkout, so it must run as
// the checkout owner instead of the image's packmon system account (which
// cannot create the temp file in a host-owned 0755 directory or read an
// existing host-owned 0600 .env). The wrapper script supplies the host IDs;
// the production server image keeps USER packmon.
func TestInitSecretsRunsAsCheckoutOwner(t *testing.T) {
	t.Parallel()

	override := readComposeContract(t, "docker-compose.override.yml")
	initSecrets, ok := override.Services["init-secrets"]
	if !ok {
		t.Fatal("docker-compose.override.yml has no init-secrets service")
	}
	const wantUser = "${PACKMON_UID:-1000}:${PACKMON_GID:-1000}"
	if initSecrets.User != wantUser {
		t.Fatalf("init-secrets user = %q, want %q", initSecrets.User, wantUser)
	}

	server := readComposeContract(t, "docker-compose.server.yml")
	for name, service := range server.Services {
		if service.User != "" {
			t.Fatalf("docker-compose.server.yml %s overrides user %q; production services keep the image's non-root user", name, service.User)
		}
	}

	// The wrapper must, in this order and outside comments: detect rootless
	// Docker, default to 0:0 there (container root is the invoking user) and
	// to the host IDs otherwise, let explicit PACKMON_UID/PACKMON_GID win,
	// export them, and only then run init-secrets.
	assertOrderedCommandLines(t, "scripts/init-secrets.sh", shellCommandLines(repoFile(t, "scripts/init-secrets.sh")), []func(string) bool{
		func(line string) bool {
			return strings.Contains(line, "docker info") && strings.Contains(line, "{{.SecurityOptions}}")
		},
		func(line string) bool { return strings.HasPrefix(line, "if ") && strings.Contains(line, "rootless") },
		exactLine("default_uid=0"),
		exactLine("default_gid=0"),
		exactLine("else"),
		exactLine(`default_uid="$(id -u)"`),
		exactLine(`default_gid="$(id -g)"`),
		exactLine("fi"),
		exactLine(`PACKMON_UID="${PACKMON_UID:-$default_uid}"`),
		exactLine(`PACKMON_GID="${PACKMON_GID:-$default_gid}"`),
		exactLine("export PACKMON_UID PACKMON_GID"),
		exactLine("docker compose --profile bootstrap run --rm --no-deps init-secrets"),
	})

	// Every runtime stage's effective (last) USER instruction stays packmon.
	for name, stage := range dockerfileRuntimeStages(t, repoFile(t, "Dockerfile")) {
		lastUser := ""
		for _, line := range shellCommandLines(stage) {
			if fields := strings.Fields(line); len(fields) == 2 && strings.EqualFold(fields[0], "USER") {
				lastUser = fields[1]
			}
		}
		if lastUser != "packmon" {
			t.Fatalf("Dockerfile %s stage effective USER = %q, want packmon", name, lastUser)
		}
	}
}

// shellCommandLines returns the trimmed, non-empty lines of a shell script or
// Dockerfile, skipping full-line comments, so a commented-out command never
// counts as evidence.
func shellCommandLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func exactLine(want string) func(string) bool {
	return func(line string) bool { return line == want }
}

// assertOrderedCommandLines requires one line per matcher, in matcher order.
func assertOrderedCommandLines(t *testing.T, name string, lines []string, matchers []func(string) bool) {
	t.Helper()

	next := 0
	for i, match := range matchers {
		found := false
		for next < len(lines) {
			line := lines[next]
			next++
			if match(line) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s: step %d of the expected command sequence is missing or out of order", name, i+1)
		}
	}
}
