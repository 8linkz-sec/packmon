package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerEnvExampleKeepsAccountGatedFeedsDisabled(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}

	values := activeEnvExampleValues(string(data))
	for _, key := range []string{
		"PACKMON_FEED_VULNCHECK_ENABLED",
		"PACKMON_FEED_SOCKET_ENABLED",
		"PACKMON_FEED_REVERSINGLABS_ENABLED",
	} {
		if got := values[key]; got != "false" {
			t.Fatalf("%s = %q in .env.example, want false unless the matching API key is configured", key, got)
		}
	}
	if _, active := values["PACKMON_VULNCHECK_API_KEY"]; active {
		t.Fatal("PACKMON_VULNCHECK_API_KEY must remain commented in .env.example")
	}
	if !strings.Contains(string(data), "account-gated") {
		t.Fatal(".env.example should disclose that optional keyed feeds are account-gated opt-ins")
	}
}

func TestReadmeDockerQuickStartUsesInitSecretsFlow(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	text := string(data)

	startIndex := strings.Index(text, "docker compose run --rm init-secrets")
	if startIndex < 0 {
		t.Fatal("README Docker quick start must show the init-secrets flow")
	}
	agentCheckIndex := strings.Index(text, `.\scripts\check-requirements.ps1 -Profile agent`)
	if agentCheckIndex < 0 {
		t.Fatal("README local server + agent test must check agent build requirements")
	}
	agentBuildIndex := strings.Index(text, `go build -o .build\packmon.exe .\cmd\packmon`)
	if agentBuildIndex < 0 {
		t.Fatal("README local server + agent test must build packmon.exe from the cloned source")
	}
	if agentCheckIndex >= agentBuildIndex || agentBuildIndex >= startIndex {
		t.Fatal("README local server + agent test must check agent requirements and build packmon.exe before starting the server")
	}
	firstLocalSectionEnd := strings.Index(text, "Packmon is distributed under the private project license")
	if firstLocalSectionEnd < 0 {
		t.Fatal("README.md must keep the license paragraph after the first local test")
	}
	if strings.Contains(text[:firstLocalSectionEnd], "If you do not already have a Packmon release binary") {
		t.Fatal("README first local server + agent test must always build the agent from source")
	}
	descriptionIndex := strings.Index(text, "It can run as a local CLI, as a central API server, or both together.")
	if descriptionIndex < 0 {
		t.Fatal("README.md must keep the short product description")
	}
	capabilitiesIndex := strings.Index(text, "## Current Capabilities")
	if capabilitiesIndex < 0 {
		t.Fatal("README.md must keep Current Capabilities")
	}
	if startIndex <= descriptionIndex || startIndex >= capabilitiesIndex {
		t.Fatal("README Docker quick start must appear near the top, directly after the short product description")
	}
	if !strings.Contains(text, "docker compose up") {
		t.Fatal("README Docker quick start must show the docker compose up step")
	}
	if strings.Contains(text[:startIndex], "Copy-Item .env.example .env") || strings.Contains(text[:startIndex], "cp .env.example .env") {
		t.Fatal("README Docker quick start must not require manually copying .env before init-secrets")
	}
	if strings.Contains(text[:startIndex], "edit `.env`") {
		t.Fatal("README Docker quick start must not require editing .env before stack startup")
	}
	collapsedReadme := strings.Join(strings.Fields(text), " ")
	for _, want := range []string{
		"creates or completes `.env`",
		"generated local-only secrets",
		"Admins can later adjust `.env`",
		"do not print generated secret values",
	} {
		if !strings.Contains(collapsedReadme, want) {
			t.Fatalf("README Docker quick start must document init-secrets flow behavior with %q", want)
		}
	}
}

func TestDockerComposeFailsFastOnEmptyRequiredSecrets(t *testing.T) {
	t.Parallel()

	// The base docker-compose.yml stays permissive (${VAR:-}) so
	// `docker compose run --rm init-secrets` can run on a fresh clone; the hard
	// :? guards live in the self-contained docker-compose.server.yml instead.
	data, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.server.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.server.yml: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		`POSTGRES_PASSWORD: "${POSTGRES_PASSWORD:?missing. Set it in .env or your secrets manager (see README → Troubleshooting).}"`,
		`PACKMON_DB_PASSWORD: "${PACKMON_DB_PASSWORD:?missing. Set in .env/secrets manager. See README → Troubleshooting}"`,
		`PACKMON_ADMIN_INITIAL_PASSWORD: "${PACKMON_ADMIN_INITIAL_PASSWORD:?missing. Set in .env/secrets manager. See README → Troubleshooting}"`,
		`PACKMON_ENCRYPTION_KEY: "${PACKMON_ENCRYPTION_KEY:?missing (base64 32 bytes). Set in .env/secrets manager. See README → Troubleshooting}"`,
		`PACKMON_ADMIN_AUDIT_HMAC_KEY: "${PACKMON_ADMIN_AUDIT_HMAC_KEY:?missing (base64 32 bytes). Set in .env/secrets manager. See README → Troubleshooting}"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("docker-compose.server.yml must fail fast on empty required secret via %q", want)
		}
	}

	baseData, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	baseText := string(baseData)
	for _, secret := range []string{
		"POSTGRES_PASSWORD", "PACKMON_DB_PASSWORD", "PACKMON_ADMIN_INITIAL_PASSWORD",
		"PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY",
	} {
		if strings.Contains(baseText, "${"+secret+":?") {
			t.Fatalf("docker-compose.yml (base) must stay permissive on %s so init-secrets can run before .env exists", secret)
		}
	}
}

func TestRetentionControlsAreDocumentedInReadmeAndEnvExample(t *testing.T) {
	t.Parallel()

	readmeData, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	envData, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}

	for _, key := range []string{
		"PACKMON_SCAN_LOG_RETENTION",
		"PACKMON_ADMIN_AUDIT_LOG_RETENTION",
		"PACKMON_AUDIT_RETENTION_INTERVAL",
	} {
		if !strings.Contains(string(readmeData), key) {
			t.Fatalf("README.md must document %s", key)
		}
		if !strings.Contains(string(envData), key+"=") {
			t.Fatalf(".env.example must expose %s", key)
		}
	}
}

func TestDatabaseTLSDefaultsAreDocumentedAndLocalComposeOverrideIsExplicit(t *testing.T) {
	t.Parallel()

	readmeData, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	envData, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	composeData, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	if !strings.Contains(string(readmeData), "default `verify-full` in production") {
		t.Fatal("README.md must document verify-full as the production PACKMON_DB_SSLMODE default")
	}
	envValues := activeEnvExampleValues(string(envData))
	if got := envValues["PACKMON_DB_SSLMODE"]; got != "disable" {
		t.Fatalf(".env.example PACKMON_DB_SSLMODE = %q, want explicit local Docker disable override", got)
	}
	if !strings.Contains(string(envData), "Local Docker only") || !strings.Contains(string(envData), "built-in production default is `verify-full`") {
		t.Fatal(".env.example must explain that its disable SSL mode is a local Docker-only override")
	}
	if !strings.Contains(string(composeData), "PACKMON_DB_SSLMODE: ${PACKMON_DB_SSLMODE:-disable}") {
		t.Fatal("docker-compose.yml must keep the local packmon-migrate DB SSL override explicit")
	}
}

func TestEnvExampleDocumentsWebAndReversingLabsOperatorSettings(t *testing.T) {
	t.Parallel()

	envData, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	text := string(envData)

	for _, tt := range []struct {
		key  string
		want string
	}{
		{key: "PACKMON_WEB_PRIVACY_URL", want: "/privacy"},
		{key: "PACKMON_WEB_LEGAL_URL", want: ""},
		{key: "PACKMON_WEB_TERMS_URL", want: "/terms"},
		{key: "PACKMON_REVERSINGLABS_MAX_SCHEDULE_PER_CHECK", want: "100"},
		{key: "PACKMON_REVERSINGLABS_CACHE_RETENTION", want: "168h"},
		{key: "PACKMON_REVERSINGLABS_EXCLUDED_NAMESPACES", want: ""},
	} {
		if !envExampleContainsAssignment(text, tt.key, tt.want) {
			t.Fatalf(".env.example must document %s=%s", tt.key, tt.want)
		}
	}
}

func TestEnvExampleDocumentsDBPoolZeroDefaultBehavior(t *testing.T) {
	t.Parallel()

	envData, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	text := string(envData)

	for _, tt := range []struct {
		key  string
		want string
	}{
		{key: "PACKMON_DB_MAX_CONNS", want: "20"},
		{key: "PACKMON_DB_MIN_CONNS", want: "2"},
	} {
		if !envExampleContainsAssignment(text, tt.key, tt.want) {
			t.Fatalf(".env.example must document %s=%s", tt.key, tt.want)
		}
	}
	if !strings.Contains(text, "Set either value to 0 to leave that pgx pool setting at its default") {
		t.Fatal(".env.example must explain that zero leaves DB pool settings at pgx defaults")
	}
}

func TestDockerEnvExampleMetricsBindMatchesComposePort(t *testing.T) {
	t.Parallel()

	envData, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	composeData, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	values := activeEnvExampleValues(string(envData))
	if got := values["PACKMON_METRICS_HOST"]; got != "0.0.0.0" {
		t.Fatalf("PACKMON_METRICS_HOST = %q in .env.example, want 0.0.0.0 so Compose's published host metrics port reaches the container listener", got)
	}
	if got := values["PACKMON_METRICS_PORT"]; got != "9090" {
		t.Fatalf("PACKMON_METRICS_PORT = %q in .env.example, want 9090 to match docker-compose.yml", got)
	}
	const wantMetricsPort = `"127.0.0.1:${PACKMON_METRICS_PORT:-9090}:${PACKMON_METRICS_PORT:-9090}"`
	if !strings.Contains(string(composeData), wantMetricsPort) {
		t.Fatalf("docker-compose.yml must publish metrics on host loopback with PACKMON_METRICS_PORT via %s", wantMetricsPort)
	}
	if strings.Contains(string(composeData), `"127.0.0.1:9090:9090"`) {
		t.Fatal("docker-compose.yml must not hard-code the metrics listener port to 9090")
	}
}

func TestDockerComposeStopGraceExceedsServerShutdownTimeout(t *testing.T) {
	t.Parallel()

	envData, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	composeData, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}

	values := activeEnvExampleValues(string(envData))
	shutdownTimeout, err := time.ParseDuration(values["PACKMON_SERVER_SHUTDOWN_TIMEOUT"])
	if err != nil {
		t.Fatalf("PACKMON_SERVER_SHUTDOWN_TIMEOUT = %q is not a duration: %v", values["PACKMON_SERVER_SHUTDOWN_TIMEOUT"], err)
	}
	stopGrace, err := time.ParseDuration(composeScalarValue(string(composeData), "stop_grace_period"))
	if err != nil {
		t.Fatalf("docker-compose.yml stop_grace_period is not a duration: %v", err)
	}
	minimum := shutdownTimeout + 5*time.Second
	if stopGrace < minimum {
		t.Fatalf("docker-compose.yml stop_grace_period = %s, want at least %s for shutdown timeout %s plus hard-exit buffer", stopGrace, minimum, shutdownTimeout)
	}
}

func activeEnvExampleValues(text string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return values
}

func envExampleContainsAssignment(text, wantKey, wantValue string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) == wantKey && strings.TrimSpace(value) == wantValue {
			return true
		}
	}
	return false
}

func composeScalarValue(text, key string) string {
	prefix := key + ":"
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}
