package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	} {
		if !strings.Contains(override, want) {
			t.Fatalf("docker-compose.override.yml missing %q", want)
		}
	}
}

func TestBaseComposeKeepsStrictSecretGuards(t *testing.T) {
	t.Parallel()
	base := repoFile(t, "docker-compose.yml")
	for _, key := range []string{
		"PACKMON_ENCRYPTION_KEY:", "PACKMON_ADMIN_AUDIT_HMAC_KEY:", "POSTGRES_PASSWORD:",
	} {
		if !strings.Contains(base, key) {
			t.Fatalf("base compose missing %q", key)
		}
	}
	if !strings.Contains(base, "init-secrets") {
		t.Fatal("base :? messages must point users at init-secrets")
	}
	if !strings.Contains(base, "Troubleshooting") {
		t.Fatal("base :? messages must point at README Troubleshooting")
	}
}

func TestReadmeHasTroubleshootingSection(t *testing.T) {
	t.Parallel()
	readme := repoFile(t, "README.md")
	for _, want := range []string{
		"## Troubleshooting",
		"docker compose run --rm init-secrets",
		"UTF-16",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("README missing troubleshooting marker %q", want)
		}
	}
}
