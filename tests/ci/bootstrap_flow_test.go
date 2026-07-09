package ci

import (
	"os"
	"os/exec"
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
	prod := repoFile(t, "docker-compose.prod.yml")

	secrets := []string{
		"POSTGRES_PASSWORD", "PACKMON_DB_PASSWORD", "PACKMON_ADMIN_INITIAL_PASSWORD",
		"PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY",
	}
	for _, key := range secrets {
		if !strings.Contains(prod, key+":") {
			t.Fatalf("docker-compose.prod.yml missing %q", key)
		}
		if !strings.Contains(prod, "${"+key+":?") {
			t.Fatalf("docker-compose.prod.yml must keep a hard :? guard on %s", key)
		}
		if strings.Contains(base, "${"+key+":?") {
			t.Fatalf("docker-compose.yml (base) must not keep a hard :? guard on %s; strict guards now live in docker-compose.prod.yml", key)
		}
	}
	if !strings.Contains(prod, "Troubleshooting") {
		t.Fatal("docker-compose.prod.yml :? messages must point at README Troubleshooting")
	}
}

// TestDockerComposeConfigResolvesForLocalAndFailsClosedForProd is a real
// `docker compose config` invocation. It is the test that would have caught
// the original bug: Compose interpolates a base file's `:?` guard at load
// time, before any override merges, so softening the secrets only in an
// override never worked. The fix moves the strict guards into
// docker-compose.prod.yml (the last-loaded file in the production
// invocation), keeping the base + auto-loaded override permissive.
func TestDockerComposeConfigResolvesForLocalAndFailsClosedForProd(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	t.Parallel()

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	envPath := filepath.Join(t.TempDir(), "blank.env")
	const envContent = "POSTGRES_USER=packmon\n" +
		"POSTGRES_DB=packmon\n" +
		"POSTGRES_PASSWORD=\n" +
		"PACKMON_DB_PASSWORD=\n" +
		"PACKMON_ADMIN_INITIAL_PASSWORD=\n" +
		"PACKMON_ENCRYPTION_KEY=\n" +
		"PACKMON_ADMIN_AUDIT_HMAC_KEY=\n"
	if err := os.WriteFile(envPath, []byte(envContent), 0o600); err != nil {
		t.Fatalf("write scratch env file: %v", err)
	}

	// (a) local path: base + auto-loaded override must resolve even though the
	// secrets are blank, because init-secrets needs to run before .env exists.
	localCmd := exec.Command("docker", "compose", "--env-file", envPath, "config") // #nosec G204 -- fixed docker/compose args, no user input.
	localCmd.Dir = repoRoot
	localOut, localErr := localCmd.CombinedOutput()
	if localErr != nil {
		t.Fatalf("local `docker compose config` (base+override) must resolve with blank secrets, got error: %v\noutput:\n%s", localErr, localOut)
	}

	// (b) production path: base + docker-compose.prod.yml must fail closed on
	// blank secrets, since docker-compose.prod.yml is the last-loaded file and
	// its :? guards are authoritative.
	prodCmd := exec.Command("docker", "compose", //nolint:gosec // fixed docker/compose args, no user input.
		"-f", "docker-compose.yml", "-f", "docker-compose.prod.yml",
		"--env-file", envPath, "config")
	prodCmd.Dir = repoRoot
	prodOut, prodErr := prodCmd.CombinedOutput()
	if prodErr == nil {
		t.Fatalf("production `docker compose config` (base+prod overlay) must fail closed on blank secrets, but it resolved:\n%s", prodOut)
	}

	outText := string(prodOut)
	guardedSecrets := []string{
		"POSTGRES_PASSWORD", "PACKMON_DB_PASSWORD", "PACKMON_ADMIN_INITIAL_PASSWORD",
		"PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY",
	}
	found := false
	for _, secret := range guardedSecrets {
		if strings.Contains(outText, secret) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("production `docker compose config` failure output should mention a guarded secret name, got:\n%s", outText)
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
