package ci

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func TestOldLocalStackScriptsAreGone(t *testing.T) {
	t.Parallel()
	for _, rel := range []string{"scripts/start-local-stack.sh", "scripts/start-local-stack.ps1"} {
		if _, err := os.Stat(filepath.Join("..", "..", filepath.FromSlash(rel))); !os.IsNotExist(err) {
			t.Fatalf("%s must be removed", rel)
		}
	}
}

func TestOverrideDefinesInitSecretsAndMigrateChain(t *testing.T) {
	t.Parallel()
	override := repoFile(t, "docker-compose.override.yml")
	for _, want := range []string{
		"init-secrets:",
		`command: ["init-secrets"]`,
		".:/workspace",
		"packmon-migrate:",
		"service_completed_successfully",
		// ValidateMetricsExposure fails closed in production unless /metrics is
		// on loopback. The local override keeps production mode (real
		// PostgreSQL store, not the in-memory dev store) and pins metrics to
		// loopback so the server starts even with an older .env that still
		// carries the former 0.0.0.0 seed.
		`PACKMON_METRICS_HOST: "127.0.0.1"`,
	} {
		if !strings.Contains(override, want) {
			t.Fatalf("docker-compose.override.yml missing %q", want)
		}
	}
	// Guard against reintroducing development mode locally: it silently swaps
	// PostgreSQL for an ephemeral in-memory store and makes postgres + migrate
	// decorative.
	if strings.Contains(override, "PACKMON_SERVER_MODE: development") {
		t.Fatal("docker-compose.override.yml must not force development mode (uses in-memory store, bypasses postgres)")
	}
	parsed := readComposeContract(t, "docker-compose.override.yml")
	initSecrets := requireComposeService(t, parsed, "init-secrets")
	if initSecrets.User != "${PACKMON_UID:-1000}:${PACKMON_GID:-1000}" || len(initSecrets.DependsOn) != 0 ||
		!slices.Equal(initSecrets.Profiles, []string{"bootstrap"}) {
		t.Fatalf("parsed init-secrets contract = user %q dependencies %#v profiles %#v", initSecrets.User, initSecrets.DependsOn, initSecrets.Profiles)
	}
	server := requireComposeService(t, parsed, "packmon-server")
	assertDependencyCondition(t, server, "postgres", "service_healthy")
	assertDependencyCondition(t, server, "packmon-migrate", "service_completed_successfully")
	if server.Environment["PACKMON_METRICS_HOST"] != "127.0.0.1" {
		t.Fatalf("parsed local metrics host = %q, want literal loopback", server.Environment["PACKMON_METRICS_HOST"])
	}
}

func TestBaseComposeStaysPermissive(t *testing.T) {
	t.Parallel()
	base := repoFile(t, "docker-compose.yml")
	for _, key := range []string{"POSTGRES_PASSWORD", "PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY"} {
		if strings.Contains(base, "${"+key+":?") {
			t.Fatalf("docker-compose.yml must stay permissive on %s (strict guards live in docker-compose.server.yml)", key)
		}
	}
}

// TestDockerComposeConfigResolvesForLocalAndFailsClosedForServer is a real
// `docker compose config` invocation. It is the test that would have caught
// the original bug: Compose interpolates a base file's `:?` guard at load
// time, before any override merges, so softening the secrets only in an
// override never worked. The fix moved the strict guards into the
// self-contained docker-compose.server.yml, keeping the base + auto-loaded
// override permissive.
func TestDockerComposeConfigResolvesForLocalAndFailsClosedForServer(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	t.Parallel()

	blank := map[string]string{
		"POSTGRES_USER":                  "packmon",
		"POSTGRES_DB":                    "packmon",
		"POSTGRES_PASSWORD":              "",
		"PACKMON_DB_PASSWORD":            "",
		"PACKMON_ADMIN_INITIAL_PASSWORD": "",
		"PACKMON_ENCRYPTION_KEY":         "",
		"PACKMON_ADMIN_AUDIT_HMAC_KEY":   "",
		"PACKMON_TRUSTED_PROXIES":        "",
	}

	// (a) local path: base + auto-loaded override must resolve even though the
	// secrets are blank, because init-secrets needs to run before .env exists.
	localStage := stageComposeFiles(t, []string{"docker-compose.yml", "docker-compose.override.yml"})
	_, localOut, localErr := composeConfig(localStage, []string{
		filepath.Join(localStage, "docker-compose.yml"),
		filepath.Join(localStage, "docker-compose.override.yml"),
	}, blank)
	if localErr != nil {
		t.Fatalf("local `docker compose config` (base+override) must resolve with blank secrets, got error: %v\noutput:\n%s", localErr, localOut)
	}

	// (b) server path: the self-contained docker-compose.server.yml must fail
	// closed on blank secrets (and a blank PACKMON_TRUSTED_PROXIES), since its
	// :? guards are authoritative and it loads no base/override file.
	serverStage := stageComposeFiles(t, []string{"docker-compose.server.yml"})
	_, serverOut, serverErr := composeConfig(serverStage, []string{filepath.Join(serverStage, "docker-compose.server.yml")}, blank)
	if serverErr == nil {
		t.Fatalf("server `docker compose config` (docker-compose.server.yml) must fail closed on blank secrets, but it resolved:\n%s", serverOut)
	}

	outText := serverOut
	guardedSecrets := []string{
		"POSTGRES_PASSWORD", "PACKMON_DB_PASSWORD", "PACKMON_ADMIN_INITIAL_PASSWORD",
		"PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY", "PACKMON_TRUSTED_PROXIES",
	}
	found := false
	for _, secret := range guardedSecrets {
		if strings.Contains(outText, secret) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("server `docker compose config` failure output should mention a guarded secret name, got:\n%s", outText)
	}
}

func TestDockerComposeConfigPrecedenceAndRequiredVariables(t *testing.T) {
	t.Parallel()

	env := validComposeEnvironment()
	env["PACKMON_SERVER_PORT"] = "18181"
	stage := stageComposeFiles(t, []string{"docker-compose.server.yml"})
	serviceEnv := filepath.Join(stage, "service.env")
	if err := os.WriteFile(serviceEnv, []byte("PACKMON_SERVER_PORT=19191\nPACKMON_SERVER_MODE=development\nPACKMON_FEED_DATA_DIR=/tmp/wrong\n"), 0o600); err != nil {
		t.Fatalf("write synthetic service env: %v", err)
	}
	overlay := filepath.Join(stage, "service-env.override.yml")
	if err := os.WriteFile(overlay, []byte("services:\n  packmon-server:\n    env_file: !override\n      - path: service.env\n        required: true\n"), 0o600); err != nil {
		t.Fatalf("write synthetic service env overlay: %v", err)
	}
	resolved := runComposeConfig(t, stage, []string{filepath.Join(stage, "docker-compose.server.yml"), overlay}, env, true)
	server := requireComposeService(t, resolved, "packmon-server")
	if server.Environment["PACKMON_SERVER_PORT"] != "18181" || !slices.Contains(server.Ports, "127.0.0.1:18181:18181") {
		t.Fatalf("explicit shell/interpolation port did not win: environment port %q, mappings %#v", server.Environment["PACKMON_SERVER_PORT"], server.Ports)
	}
	if server.Environment["PACKMON_SERVER_MODE"] != "production" || server.Environment["PACKMON_FEED_DATA_DIR"] != "/data/feeds" {
		t.Fatalf("explicit Compose environment did not override service env_file: mode %q feed dir %q", server.Environment["PACKMON_SERVER_MODE"], server.Environment["PACKMON_FEED_DATA_DIR"])
	}

	for _, key := range []string{"POSTGRES_PASSWORD", "PACKMON_DB_PASSWORD", "PACKMON_ADMIN_INITIAL_PASSWORD", "PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY", "PACKMON_TRUSTED_PROXIES"} {
		key := key
		t.Run("missing_"+strings.ToLower(key), func(t *testing.T) {
			missing := validComposeEnvironment()
			delete(missing, key)
			_, output, err := composeConfig(stage, []string{filepath.Join(stage, "docker-compose.server.yml")}, missing)
			if err == nil {
				t.Fatalf("Compose resolved with required %s omitted", key)
			}
			if !strings.Contains(output, key) {
				t.Fatalf("Compose failure for omitted %s did not name that key: %s", key, boundedComposeDiagnostic(output, missing))
			}
		})
		t.Run("empty_"+strings.ToLower(key), func(t *testing.T) {
			empty := validComposeEnvironment()
			empty[key] = ""
			_, output, err := composeConfig(stage, []string{filepath.Join(stage, "docker-compose.server.yml")}, empty)
			if err == nil {
				t.Fatalf("Compose resolved with required %s empty", key)
			}
			if !strings.Contains(output, key) {
				t.Fatalf("Compose failure for empty %s did not name that key: %s", key, boundedComposeDiagnostic(output, empty))
			}
		})
	}
}

func TestDockerComposeBootstrapLifecycle(t *testing.T) {
	t.Parallel()

	compose := renderComposeContract(t, []string{"docker-compose.yml", "docker-compose.override.yml"}, validComposeEnvironment())
	initSecrets := requireComposeService(t, compose, "init-secrets")
	if initSecrets.User != "1000:1000" {
		t.Fatalf("resolved init-secrets user = %q, want checkout-owner defaults", initSecrets.User)
	}
	if len(initSecrets.DependsOn) != 0 {
		t.Fatalf("explicit init-secrets unexpectedly depends on application services: %#v", initSecrets.DependsOn)
	}
	if !slices.Equal(initSecrets.Profiles, []string{"bootstrap"}) {
		t.Fatalf("resolved init-secrets profiles = %#v, want [bootstrap]", initSecrets.Profiles)
	}

	t.Run("plain_application_startup_excludes_bootstrap", func(t *testing.T) {
		services := renderDefaultComposeServices(t, []string{"docker-compose.yml", "docker-compose.override.yml"}, validComposeEnvironment())
		if slices.Contains(services, "init-secrets") {
			t.Fatalf("plain Compose model services = %#v, must exclude init-secrets", services)
		}
		for _, want := range []string{"postgres", "packmon-migrate", "packmon-server"} {
			if !slices.Contains(services, want) {
				t.Fatalf("plain Compose model services = %#v, missing %s", services, want)
			}
		}
	})
}

func TestServerComposeIsSelfContainedAndHardened(t *testing.T) {
	t.Parallel()
	server := repoFile(t, "docker-compose.server.yml")

	// Fail-closed secret guards (strict :? on all five secrets).
	for _, key := range []string{
		"POSTGRES_PASSWORD", "PACKMON_DB_PASSWORD", "PACKMON_ADMIN_INITIAL_PASSWORD",
		"PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY",
	} {
		if !strings.Contains(server, key+":?") && !strings.Contains(server, key+" :?") &&
			!strings.Contains(server, "${"+key+":?") {
			t.Fatalf("docker-compose.server.yml missing fail-closed :? guard for %s", key)
		}
	}

	// Hardening: production mode, no insecure HTTP, loopback metrics, required trusted proxy.
	for _, want := range []string{
		"PACKMON_SERVER_MODE: production",
		"PACKMON_ALLOW_INSECURE_LOCAL_HTTP:",
		`PACKMON_METRICS_HOST: "127.0.0.1"`,
		"${PACKMON_TRUSTED_PROXIES:?",
		"PACKMON_DB_HOST: ${PACKMON_DB_HOST:-postgres}",
		"env_file:",
		"required: false",
	} {
		if !strings.Contains(server, want) {
			t.Fatalf("docker-compose.server.yml missing hardening marker %q", want)
		}
	}
	// Restart policies are checked on the parsed file: a substring match also
	// accepted a commented-out `# restart: unless-stopped`, which is no policy.
	parsed := readComposeContract(t, "docker-compose.server.yml")
	for _, name := range []string{"postgres", "packmon-server"} {
		if got := parsed.Services[name].Restart; got != "unless-stopped" {
			t.Fatalf("docker-compose.server.yml %s restart = %q, want a parsed unless-stopped policy", name, got)
		}
	}
	if strings.Contains(server, "PACKMON_ALLOW_INSECURE_LOCAL_HTTP: ${PACKMON_ALLOW_INSECURE_LOCAL_HTTP:-true}") ||
		strings.Contains(server, `PACKMON_ALLOW_INSECURE_LOCAL_HTTP: "true"`) {
		t.Fatal("server compose must not enable insecure local HTTP")
	}

	// No dev conveniences.
	for _, forbidden := range []string{"init-secrets", ".:/workspace", "service_completed_successfully"} {
		if strings.Contains(server, forbidden) {
			t.Fatalf("docker-compose.server.yml must not contain dev-mode marker %q", forbidden)
		}
	}
	// Migrate stays a manual, explicit step.
	if !strings.Contains(server, "packmon-migrate:") || !strings.Contains(server, `profiles: ["manual"]`) {
		t.Fatal("docker-compose.server.yml packmon-migrate must stay behind profiles: [\"manual\"]")
	}
	for _, name := range []string{"packmon-migrate", "packmon-backup"} {
		service := requireComposeService(t, parsed, name)
		if !slices.Equal(service.Profiles, []string{"manual"}) {
			t.Fatalf("docker-compose.server.yml %s profiles = %#v, want [manual]", name, service.Profiles)
		}
	}
	serverService := requireComposeService(t, parsed, "packmon-server")
	if serverService.Environment["PACKMON_SERVER_MODE"] != "production" || serverService.Environment["PACKMON_METRICS_HOST"] != "127.0.0.1" {
		t.Fatalf("parsed server hardening environment = %#v", serverService.Environment)
	}
	if serverService.Environment["PACKMON_ALLOW_INSECURE_LOCAL_HTTP"] != "false" {
		t.Fatalf("production insecure HTTP = %q, want false", serverService.Environment["PACKMON_ALLOW_INSECURE_LOCAL_HTTP"])
	}
}

func TestReadmeHasTroubleshootingSection(t *testing.T) {
	t.Parallel()
	readme := repoFile(t, "README.md")
	for _, want := range []string{
		"## Troubleshooting",
		"docker compose --profile bootstrap run --rm --no-deps init-secrets",
		"UTF-16",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("README missing troubleshooting marker %q", want)
		}
	}
}

func validComposeEnvironment() map[string]string {
	return map[string]string{ // #nosec G101 -- fake bootstrap environment values.
		"POSTGRES_DB":                     "packmon",
		"POSTGRES_USER":                   "packmon",
		"POSTGRES_PASSWORD":               "test-postgres-password",
		"PACKMON_DB_PASSWORD":             "test-database-password",
		"PACKMON_ADMIN_INITIAL_PASSWORD":  "test-admin-password",
		"PACKMON_ENCRYPTION_KEY":          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"PACKMON_ADMIN_AUDIT_HMAC_KEY":    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		"PACKMON_TRUSTED_PROXIES":         "127.0.0.1/32",
		"PACKMON_UID":                     "1000",
		"PACKMON_GID":                     "1000",
		"PACKMON_SERVER_SHUTDOWN_TIMEOUT": "15s",
	}
}

func renderComposeContract(t *testing.T, names []string, env map[string]string) composeFileContract {
	t.Helper()
	stage := stageComposeFiles(t, names)
	files := make([]string, len(names))
	for i, name := range names {
		files[i] = filepath.Join(stage, filepath.Base(name))
	}
	return runComposeConfig(t, stage, files, env, true)
}

func renderDefaultComposeServices(t *testing.T, names []string, env map[string]string) []string {
	t.Helper()
	stage := stageComposeFiles(t, names)
	blankEnv := filepath.Join(stage, "interpolation.env")
	if err := os.WriteFile(blankEnv, nil, 0o600); err != nil {
		t.Fatalf("write blank Compose environment: %v", err)
	}
	args := []string{"compose", "--env-file", blankEnv}
	for _, name := range names {
		args = append(args, "-f", filepath.Join(stage, filepath.Base(name)))
	}
	args = append(args, "config", "--services")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- fixed executable and staged repository Compose files
	cmd.Dir = stage
	cmd.Env = sanitizedComposeEnvironment(env)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("plain Compose service model timed out: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("resolve plain Compose service model: %v: %s", err, boundedComposeDiagnostic(string(output), env))
	}
	return strings.Fields(string(output))
}

func stageComposeFiles(t *testing.T, names []string) string {
	t.Helper()
	stage := t.TempDir()
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(stage, filepath.Base(name)), data, 0o600); err != nil { // #nosec G703 -- stage is t.TempDir and name a fixed repository file.
			t.Fatalf("stage %s: %v", name, err)
		}
	}
	return stage
}

func runComposeConfig(t *testing.T, dir string, files []string, env map[string]string, requireSuccess bool) composeFileContract {
	t.Helper()
	output, diagnostic, err := composeConfig(dir, files, env)
	if err != nil {
		if requireSuccess {
			t.Fatalf("docker compose config: %v: %s", err, boundedComposeDiagnostic(diagnostic, env))
		}
		return composeFileContract{}
	}
	var compose composeFileContract
	if err := yaml.Unmarshal(output, &compose); err != nil {
		t.Fatalf("parse normalized Compose output: %v", err)
	}
	return compose
}

func composeConfig(dir string, files []string, env map[string]string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	blankEnv := filepath.Join(dir, "interpolation.env")
	if err := os.WriteFile(blankEnv, nil, 0o600); err != nil {
		return nil, err.Error(), err
	}
	args := []string{"compose", "--env-file", blankEnv, "--profile", "*"}
	for _, file := range files {
		args = append(args, "-f", file)
	}
	args = append(args, "config")
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- fixed executable; all files and environment are test-owned
	cmd.Dir = dir
	cmd.Env = sanitizedComposeEnvironment(env)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, string(output), fmt.Errorf("compose config timeout: %w", ctx.Err())
	}
	return output, string(output), err
}

func sanitizedComposeEnvironment(extra map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "COMPOSE_") || strings.HasPrefix(upper, "PACKMON_") || strings.HasPrefix(upper, "POSTGRES_") || strings.HasPrefix(upper, "PG") {
			continue
		}
		env = append(env, entry)
	}
	for key, value := range extra {
		env = append(env, key+"="+value)
	}
	return env
}

func boundedComposeDiagnostic(output string, secrets map[string]string) string {
	for _, value := range secrets {
		if value != "" {
			output = strings.ReplaceAll(output, value, "[REDACTED]")
		}
	}
	const limit = 2000
	if len(output) > limit {
		return output[:limit] + "...[truncated]"
	}
	return output
}
