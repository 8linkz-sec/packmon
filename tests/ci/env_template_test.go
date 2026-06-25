package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestReadmeDockerQuickStartUsesLocalFirstStackHelper(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	text := string(data)

	startIndex := strings.Index(text, "scripts\\start-local-stack.ps1")
	if startIndex < 0 {
		t.Fatal("README Docker quick start must show the Windows local stack helper")
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
	if !strings.Contains(text, "scripts/start-local-stack.sh") {
		t.Fatal("README Docker quick start must show the Bash local stack helper")
	}
	if strings.Contains(text[:startIndex], "Copy-Item .env.example .env") || strings.Contains(text[:startIndex], "cp .env.example .env") {
		t.Fatal("README Docker quick start must not require manually copying .env before the local stack helper")
	}
	if strings.Contains(text[:startIndex], "edit `.env`") {
		t.Fatal("README Docker quick start must not require editing .env before stack startup")
	}
	for _, want := range []string{
		"creates or completes `.env`",
		"generated local-only secrets",
		"Admins can later adjust `.env`",
		"do not print generated secret values",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("README Docker quick start must document local-first helper behavior with %q", want)
		}
	}

	for _, rel := range []string{
		filepath.Join("scripts", "start-local-stack.ps1"),
		filepath.Join("scripts", "start-local-stack.sh"),
	} {
		scriptData, err := os.ReadFile(filepath.Join("..", "..", rel)) //nolint:gosec // static repository script path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		script := string(scriptData)
		if !strings.Contains(script, ".env.example") {
			t.Fatalf("%s must use .env.example when bootstrapping local .env", rel)
		}
		if !strings.Contains(script, ".env") {
			t.Fatalf("%s must write or update local .env", rel)
		}
		for _, key := range []string{
			"POSTGRES_PASSWORD",
			"PACKMON_DB_PASSWORD",
			"PACKMON_ADMIN_INITIAL_PASSWORD",
			"PACKMON_ENCRYPTION_KEY",
		} {
			if !strings.Contains(script, key) {
				t.Fatalf("%s must ensure required env value %s", rel, key)
			}
		}
		migrateIndex := strings.Index(script, "docker compose run --build --rm packmon-migrate")
		if migrateIndex < 0 {
			t.Fatalf("%s must prepare the database with packmon-migrate", rel)
		}
		upIndex := strings.Index(script, "docker compose up --build -d")
		if upIndex < 0 {
			t.Fatalf("%s must start the local stack detached", rel)
		}
		if migrateIndex >= upIndex {
			t.Fatalf("%s must prepare the database before starting compose", rel)
		}
	}
}

func TestDockerComposeFailsFastOnEmptyRequiredSecrets(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}",
		"PACKMON_DB_PASSWORD: ${PACKMON_DB_PASSWORD:?PACKMON_DB_PASSWORD is required}",
		"PACKMON_ADMIN_INITIAL_PASSWORD: ${PACKMON_ADMIN_INITIAL_PASSWORD:?PACKMON_ADMIN_INITIAL_PASSWORD is required}",
		"PACKMON_ENCRYPTION_KEY: ${PACKMON_ENCRYPTION_KEY:?PACKMON_ENCRYPTION_KEY is required}",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("docker-compose.yml must fail fast on empty required secret via %q", want)
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
	if !strings.Contains(string(composeData), `"127.0.0.1:9090:9090"`) {
		t.Fatal("docker-compose.yml must keep metrics published only on host loopback")
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
