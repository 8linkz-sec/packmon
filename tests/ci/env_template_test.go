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

func TestReadmeDockerQuickStartRequiresSecretEditsBeforeCompose(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	text := string(data)

	copyIndex := strings.Index(text, "cp .env.example .env")
	if copyIndex < 0 {
		t.Fatal("README Docker quick start must copy .env.example to .env")
	}
	migrateIndex := strings.Index(text, "docker compose run --build --rm packmon-migrate")
	if migrateIndex < 0 {
		t.Fatal("README Docker quick start must show the explicit migration command")
	}
	upIndex := strings.Index(text, "docker compose up --build")
	if upIndex < 0 {
		t.Fatal("README Docker quick start must show docker compose up --build")
	}
	if copyIndex >= migrateIndex || migrateIndex >= upIndex {
		t.Fatal("README Docker quick start must copy .env, run migrations, then start compose")
	}

	secretEditText := text[copyIndex:migrateIndex]
	if !strings.Contains(secretEditText, "edit `.env`") {
		t.Fatal("README Docker quick start must require editing .env before migrations or compose startup")
	}
	for _, key := range []string{
		"POSTGRES_PASSWORD",
		"PACKMON_DB_PASSWORD",
		"PACKMON_ADMIN_INITIAL_PASSWORD",
		"PACKMON_ENCRYPTION_KEY",
	} {
		if !strings.Contains(secretEditText, key) {
			t.Fatalf("README Docker quick start must name required env value %s before compose commands", key)
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
