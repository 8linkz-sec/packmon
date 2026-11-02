package main

import (
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/envfile"
)

func TestEnsureSecretsFillsOnlyGaps(t *testing.T) {
	entries := envfile.Parse([]byte(
		"POSTGRES_PASSWORD=keepme\n" +
			"PACKMON_DB_PASSWORD=\n" +
			"PACKMON_ADMIN_INITIAL_PASSWORD=\n" +
			"PACKMON_ENCRYPTION_KEY=\n" +
			"PACKMON_ADMIN_AUDIT_HMAC_KEY=\n",
	))
	out, generated, kept, err := ensureSecrets(entries)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if v, _ := envfile.Value(out, "POSTGRES_PASSWORD"); v != "keepme" {
		t.Fatalf("existing value overwritten: %q", v)
	}
	if v, _ := envfile.Value(out, "PACKMON_DB_PASSWORD"); v != "keepme" {
		t.Fatalf("DB password must mirror POSTGRES_PASSWORD, got %q", v)
	}
	if kept != 1 || generated != 3 {
		t.Fatalf("generated=%d kept=%d, want generated=3 kept=1", generated, kept)
	}
	for _, s := range config.RequiredSecrets() {
		v, _ := envfile.Value(out, s.Key)
		if err := s.Validate(v); err != nil {
			t.Fatalf("%s invalid after ensure: %v", s.Key, err)
		}
	}
}

// TestEnsureSecretsMirrorsDBPasswordOntoBlankPostgresPassword covers the
// reverse sync direction: with only PACKMON_DB_PASSWORD set, generating a new
// POSTGRES_PASSWORD would initialize the bundled database with a password
// the server and migrator never use.
func TestEnsureSecretsMirrorsDBPasswordOntoBlankPostgresPassword(t *testing.T) {
	entries := envfile.Parse([]byte(
		"POSTGRES_PASSWORD=\n" +
			"PACKMON_DB_PASSWORD=app-db-password\n" +
			"PACKMON_ADMIN_INITIAL_PASSWORD=\n" +
			"PACKMON_ENCRYPTION_KEY=\n" +
			"PACKMON_ADMIN_AUDIT_HMAC_KEY=\n",
	))
	out, generated, kept, err := ensureSecrets(entries)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if v, _ := envfile.Value(out, "PACKMON_DB_PASSWORD"); v != "app-db-password" {
		t.Fatal("existing PACKMON_DB_PASSWORD was overwritten")
	}
	if v, _ := envfile.Value(out, "POSTGRES_PASSWORD"); v != "app-db-password" {
		t.Fatal("POSTGRES_PASSWORD must mirror the existing PACKMON_DB_PASSWORD, not a newly generated value")
	}
	if kept != 1 || generated != 3 {
		t.Fatalf("generated=%d kept=%d, want generated=3 kept=1", generated, kept)
	}
}

func TestInitSecretsFillsQuotedAndMissingSecretsWithoutReplacingNonEmptyValues(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	const preservedEncryptionKey = "invalid-but-explicit-encryption-key"
	if err := os.WriteFile(env, []byte(
		"POSTGRES_PASSWORD=\"\"\n"+
			"PACKMON_DB_PASSWORD=''\n"+
			"PACKMON_ENCRYPTION_KEY="+preservedEncryptionKey+"\n",
	), 0o600); err != nil {
		t.Fatalf("write fixture .env: %v", err)
	}

	var stdout, stderr strings.Builder
	if err := initSecrets([]string{"--env", env}, &stdout, &stderr); err != nil {
		t.Fatalf("initSecrets() error = %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("initSecrets() stderr = %q, want empty", stderr.String())
	}
	if got := stdout.String(); strings.Count(got, "\n") != 1 ||
		!strings.HasPrefix(got, "init-secrets: 3 generated, 1 kept") ||
		!strings.HasSuffix(strings.TrimSuffix(got, "\n"), env+" ready") {
		t.Fatalf("initSecrets() stdout = %q, want one 3-generated/1-kept status line for %s", got, env)
	}

	data, err := os.ReadFile(env) //nolint:gosec // test reads a path built from t.TempDir().
	if err != nil {
		t.Fatalf("read completed .env: %v", err)
	}
	entries := envfile.Parse(data)
	for _, spec := range config.RequiredSecrets() {
		count := 0
		for _, entry := range entries {
			if entry.Key == spec.Key {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s assignment count = %d, want 1", spec.Key, count)
		}
		value, ok := envfile.Value(entries, spec.Key)
		if !ok || envfile.IsBlank(value) {
			t.Fatalf("%s = %q, want one non-blank value", spec.Key, value)
		}
		if spec.Key != "PACKMON_ENCRYPTION_KEY" {
			if err := spec.Validate(value); err != nil {
				t.Fatalf("filled %s is invalid: %v", spec.Key, err)
			}
		}
		if strings.Contains(stdout.String()+stderr.String(), value) {
			t.Fatalf("init-secrets output leaks %s", spec.Key)
		}
	}
	if value, _ := envfile.Value(entries, "PACKMON_ENCRYPTION_KEY"); value != preservedEncryptionKey {
		t.Fatalf("PACKMON_ENCRYPTION_KEY = %q, want preserved explicit invalid value", value)
	}
	postgresPassword, _ := envfile.Value(entries, "POSTGRES_PASSWORD")
	databasePassword, _ := envfile.Value(entries, "PACKMON_DB_PASSWORD")
	if postgresPassword != databasePassword {
		t.Fatal("missing PACKMON_DB_PASSWORD did not mirror the generated POSTGRES_PASSWORD")
	}
}

func TestInitSecretsCreatesFreshFileWhenEnvironmentAndTemplateAreMissing(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	example := filepath.Join(dir, ".env.example")

	var stdout, stderr strings.Builder
	if err := initSecrets([]string{"--env", env, "--example", example}, &stdout, &stderr); err != nil {
		t.Fatalf("initSecrets() error = %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("initSecrets() stderr = %q, want empty", stderr.String())
	}
	if got := stdout.String(); strings.Count(got, "\n") != 1 ||
		!strings.HasPrefix(got, "init-secrets: 4 generated, 0 kept") ||
		!strings.HasSuffix(strings.TrimSuffix(got, "\n"), env+" ready") {
		t.Fatalf("initSecrets() stdout = %q, want one 4-generated/0-kept status line for %s", got, env)
	}

	data, err := os.ReadFile(env) //nolint:gosec // test reads a path built from t.TempDir().
	if err != nil {
		t.Fatalf("read fresh .env: %v", err)
	}
	entries := envfile.Parse(data)
	if len(entries) != len(config.RequiredSecrets()) {
		t.Fatalf("fresh .env entry count = %d, want %d required secret assignments", len(entries), len(config.RequiredSecrets()))
	}
	uniqueGenerated := make(map[string]string)
	output := stdout.String() + stderr.String()
	for _, spec := range config.RequiredSecrets() {
		count := 0
		for _, entry := range entries {
			if entry.Key == spec.Key {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s assignment count = %d, want 1", spec.Key, count)
		}
		value, ok := envfile.Value(entries, spec.Key)
		if !ok {
			t.Fatalf("fresh .env is missing %s", spec.Key)
		}
		if err := spec.Validate(value); err != nil {
			t.Fatalf("fresh %s is invalid: %v", spec.Key, err)
		}
		if strings.Contains(output, value) {
			t.Fatalf("init-secrets output leaks generated %s", spec.Key)
		}
		if spec.Key != "PACKMON_DB_PASSWORD" {
			if previous, exists := uniqueGenerated[value]; exists {
				t.Fatalf("generated %s duplicates %s", spec.Key, previous)
			}
			uniqueGenerated[value] = spec.Key
		}
	}
	postgresPassword, _ := envfile.Value(entries, "POSTGRES_PASSWORD")
	databasePassword, _ := envfile.Value(entries, "PACKMON_DB_PASSWORD")
	if postgresPassword != databasePassword {
		t.Fatal("fresh database password pair must share one generated value")
	}
	if len(uniqueGenerated) != 4 {
		t.Fatalf("unique generated value count = %d, want 4 including one shared database password", len(uniqueGenerated))
	}
}

func TestEnsureSecretsGeneratesOneSharedDatabasePassword(t *testing.T) {
	entries := envfile.Parse([]byte("POSTGRES_PASSWORD=\nPACKMON_DB_PASSWORD=\n"))
	out, generated, kept, err := ensureSecrets(entries)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	pg, _ := envfile.Value(out, "POSTGRES_PASSWORD")
	db, _ := envfile.Value(out, "PACKMON_DB_PASSWORD")
	if envfile.IsBlank(pg) || pg != db {
		t.Fatal("a fresh database password pair must be generated once and shared by both keys")
	}
	// One database password plus the three other required secrets.
	if kept != 0 || generated != 4 {
		t.Fatalf("generated=%d kept=%d, want generated=4 kept=0", generated, kept)
	}
}

func TestEnsureSecretsKeepsDivergentExplicitDatabasePasswords(t *testing.T) {
	entries := envfile.Parse([]byte("POSTGRES_PASSWORD=superuser-pw\nPACKMON_DB_PASSWORD=app-pw\n"))
	out, _, _, err := ensureSecrets(entries)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if v, _ := envfile.Value(out, "POSTGRES_PASSWORD"); v != "superuser-pw" {
		t.Fatal("explicit POSTGRES_PASSWORD was overwritten")
	}
	if v, _ := envfile.Value(out, "PACKMON_DB_PASSWORD"); v != "app-pw" {
		t.Fatal("explicit PACKMON_DB_PASSWORD was overwritten")
	}
}

// TestInitSecretsWarnsAboutDivergentDatabasePasswordsWithoutValues pins the
// warning for two explicit, different database passwords: a fresh bundled
// PostgreSQL is initialized with POSTGRES_PASSWORD and would reject the
// server login with PACKMON_DB_PASSWORD. The warning names both variables but
// must never print a secret value, explicit or generated.
func TestInitSecretsWarnsAboutDivergentDatabasePasswordsWithoutValues(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(env, []byte(
		"POSTGRES_PASSWORD=superuser-secret-value\n"+
			"PACKMON_DB_PASSWORD=application-secret-value\n"+
			"PACKMON_ADMIN_INITIAL_PASSWORD=\nPACKMON_ENCRYPTION_KEY=\n"+
			"PACKMON_ADMIN_AUDIT_HMAC_KEY=\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr strings.Builder
	if err := initSecrets([]string{"--env", env}, &stdout, &stderr); err != nil {
		t.Fatalf("init-secrets: %v", err)
	}
	warning := stderr.String()
	if strings.Count(warning, "\n") != 1 || !strings.Contains(warning, "warning") ||
		!strings.Contains(warning, "POSTGRES_PASSWORD") || !strings.Contains(warning, "PACKMON_DB_PASSWORD") {
		t.Fatalf("want one warning line naming both variables, got %q", warning)
	}

	data, err := os.ReadFile(env) //nolint:gosec // test reads a path built from t.TempDir()
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	output := stdout.String() + stderr.String()
	for _, s := range config.RequiredSecrets() {
		value, _ := envfile.Value(envfile.Parse(data), s.Key)
		if envfile.IsBlank(value) {
			t.Fatalf("%s left blank", s.Key)
		}
		if strings.Contains(output, value) {
			t.Fatalf("init-secrets output leaks the %s value", s.Key)
		}
	}
}

func TestInitSecretsDoesNotWarnForMatchingOrMirroredDatabasePasswords(t *testing.T) {
	for name, content := range map[string]string{
		"matching": "POSTGRES_PASSWORD=same-value\nPACKMON_DB_PASSWORD=same-value\n",
		"mirrored": "POSTGRES_PASSWORD=\nPACKMON_DB_PASSWORD=only-app-value\n",
		"fresh":    "POSTGRES_PASSWORD=\nPACKMON_DB_PASSWORD=\n",
	} {
		t.Run(name, func(t *testing.T) {
			env := filepath.Join(t.TempDir(), ".env")
			if err := os.WriteFile(env, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr strings.Builder
			if err := initSecrets([]string{"--env", env}, &stdout, &stderr); err != nil {
				t.Fatalf("init-secrets: %v", err)
			}
			if stderr.Len() != 0 {
				t.Fatalf("unexpected warning: %q", stderr.String())
			}
		})
	}
}

type initSecretsErrorWriter struct{}

func (initSecretsErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("output failure")
}

func TestInitSecretsPropagatesOutputErrors(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tt := range []struct {
		name     string
		postgres string
		database string
		stdout   io.Writer
		stderr   io.Writer
	}{
		{
			name:     "status output",
			postgres: "same-password",
			database: "same-password",
			stdout:   initSecretsErrorWriter{},
			stderr:   &strings.Builder{},
		},
		{
			name:     "warning output",
			postgres: "postgres-password",
			database: "database-password",
			stdout:   &strings.Builder{},
			stderr:   initSecretsErrorWriter{},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := filepath.Join(t.TempDir(), ".env")
			content := "POSTGRES_PASSWORD=" + tt.postgres + "\n" +
				"PACKMON_DB_PASSWORD=" + tt.database + "\n" +
				"PACKMON_ADMIN_INITIAL_PASSWORD=admin-password\n" +
				"PACKMON_ENCRYPTION_KEY=" + key + "\n" +
				"PACKMON_ADMIN_AUDIT_HMAC_KEY=" + key + "\n"
			if err := os.WriteFile(env, []byte(content), 0o600); err != nil {
				t.Fatalf("write fixture .env: %v", err)
			}
			err := initSecrets([]string{"--env", env}, tt.stdout, tt.stderr)
			if err == nil || err.Error() != "output failure" {
				t.Fatalf("initSecrets error = %v, want output failure", err)
			}
		})
	}
}

func TestRunInitSecretsSeedsFromExample(t *testing.T) {
	dir := t.TempDir()
	example := filepath.Join(dir, ".env.example")
	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(example, []byte(
		"# packmon config\nPACKMON_LOG_LEVEL=info\nPOSTGRES_PASSWORD=\n"+
			"PACKMON_DB_PASSWORD=\nPACKMON_ADMIN_INITIAL_PASSWORD=\n"+
			"PACKMON_ENCRYPTION_KEY=\nPACKMON_ADMIN_AUDIT_HMAC_KEY=\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runInitSecrets([]string{"--env", env, "--example", example}); err != nil {
		t.Fatalf("run: %v", err)
	}
	data, err := os.ReadFile(env) //nolint:gosec // test reads a path built from t.TempDir()
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatal("output must be LF-terminated")
	}
	if data[0] == 0xEF {
		t.Fatal("output must not have a BOM")
	}
	entries := envfile.Parse(data)
	if v, _ := envfile.Value(entries, "PACKMON_LOG_LEVEL"); v != "info" {
		t.Fatalf("template key lost: %q", v)
	}
	for _, s := range config.RequiredSecrets() {
		v, _ := envfile.Value(entries, s.Key)
		if err := s.Validate(v); err != nil {
			t.Fatalf("%s invalid: %v", s.Key, err)
		}
	}
	// On Unix, verify 0600 permissions; Windows uses a different permission model
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(env); fi.Mode().Perm() != 0o600 {
			t.Fatalf("perm = %v, want 0600", fi.Mode().Perm())
		}
	}
}

// TestInitSecretsBootstrapsTrackedTemplateForCompose covers the real checkout
// handoff: the tracked template is completed without losing comments, its
// generated secrets stay out of command output, and Docker Compose accepts the
// resulting env file.
func TestInitSecretsBootstrapsTrackedTemplateForCompose(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	example := filepath.Join(repoRoot, ".env.example")
	exampleBefore, err := os.ReadFile(example) // #nosec G304 -- fixed tracked repository fixture path.
	if err != nil {
		t.Fatalf("read tracked .env.example: %v", err)
	}
	env := filepath.Join(t.TempDir(), ".env")

	var stdout, stderr strings.Builder
	if err := initSecrets([]string{"--env", env, "--example", example}, &stdout, &stderr); err != nil {
		t.Fatalf("init-secrets from tracked template: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("init-secrets emitted an unexpected warning: %q", stderr.String())
	}
	data, err := os.ReadFile(env) //nolint:gosec // test reads a path built from t.TempDir().
	if err != nil {
		t.Fatalf("read generated .env: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatal("generated .env must be non-empty and LF-terminated")
	}
	entries := envfile.Parse(data)
	output := stdout.String() + stderr.String()
	for _, spec := range config.RequiredSecrets() {
		value, ok := envfile.Value(entries, spec.Key)
		if !ok {
			t.Fatalf("generated .env is missing %s", spec.Key)
		}
		if err := spec.Validate(value); err != nil {
			t.Fatalf("generated %s is invalid: %v", spec.Key, err)
		}
		if strings.Contains(output, value) {
			t.Fatalf("init-secrets output leaks generated %s", spec.Key)
		}
	}
	postgresPassword, postgresOK := envfile.Value(entries, "POSTGRES_PASSWORD")
	databasePassword, databaseOK := envfile.Value(entries, "PACKMON_DB_PASSWORD")
	if !postgresOK || !databaseOK || postgresPassword != databasePassword {
		t.Fatal("generated POSTGRES_PASSWORD and PACKMON_DB_PASSWORD must both exist and match")
	}
	for _, raw := range strings.Split(string(exampleBefore), "\n") {
		if line := strings.TrimSpace(raw); strings.HasPrefix(line, "#") && !strings.Contains(string(data), raw) {
			t.Fatalf("generated .env lost tracked template comment %q", raw)
		}
	}
	for _, key := range []string{
		"PACKMON_FEED_IMPORT_SECRET",
		"PACKMON_VULNCHECK_API_KEY",
		"PACKMON_NVD_API_KEY",
		"PACKMON_SOCKET_API_KEY",
		"PACKMON_REVERSINGLABS_API_KEY",
	} {
		if !strings.Contains(string(data), "# "+key+"=") {
			t.Fatalf("generated .env lost commented optional credential %s", key)
		}
	}
	exampleAfter, err := os.ReadFile(example) // #nosec G304 -- fixed tracked repository fixture path.
	if err != nil {
		t.Fatalf("re-read tracked .env.example: %v", err)
	}
	if string(exampleAfter) != string(exampleBefore) {
		t.Fatal("init-secrets modified the tracked .env.example")
	}

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("Docker Compose unavailable; generated env-file render not executed: %v", err)
	}
	version := exec.Command("docker", "compose", "version") // #nosec G204 -- fixed availability probe.
	if output, err := version.CombinedOutput(); err != nil {
		t.Skipf("Docker Compose unavailable; generated env-file render not executed: %v: %s", err, output)
	}
	t.Setenv("PACKMON_DB_PASSWORD", "host-packmon-password-must-not-override-env-file")
	t.Setenv("POSTGRES_PASSWORD", "host-postgres-password-must-not-override-env-file")
	t.Setenv("COMPOSE_FILE", filepath.Join(t.TempDir(), "must-not-be-used.yml"))
	validationEnv := composeValidationEnv(os.Environ())
	for _, entry := range validationEnv {
		key, _, _ := strings.Cut(entry, "=")
		upperKey := strings.ToUpper(key)
		if strings.HasPrefix(upperKey, "PACKMON_") ||
			strings.HasPrefix(upperKey, "POSTGRES_") ||
			strings.HasPrefix(upperKey, "COMPOSE_") {
			t.Fatalf("Compose validation environment retained forbidden host override %s", key)
		}
	}
	cmd := exec.Command( // #nosec G204 -- fixed Compose arguments and test/repository paths.
		"docker", "compose",
		"--env-file", env,
		"--project-directory", repoRoot,
		"-f", filepath.Join(repoRoot, "docker-compose.yml"),
		"-f", filepath.Join(repoRoot, "docker-compose.override.yml"),
		"config", "--quiet",
	)
	cmd.Env = validationEnv
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker compose rejected generated .env: %v (output suppressed because the env file contains secrets)", err)
	}
}

func composeValidationEnv(environ []string) []string {
	filtered := make([]string, 0, len(environ))
	for _, entry := range environ {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			filtered = append(filtered, entry)
			continue
		}
		upperKey := strings.ToUpper(key)
		if strings.HasPrefix(upperKey, "PACKMON_") ||
			strings.HasPrefix(upperKey, "POSTGRES_") ||
			strings.HasPrefix(upperKey, "COMPOSE_") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func TestRunInitSecretsIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	example := filepath.Join(dir, ".env.example")
	if err := os.WriteFile(example, []byte("POSTGRES_PASSWORD=\nPACKMON_DB_PASSWORD=\n"+
		"PACKMON_ADMIN_INITIAL_PASSWORD=\nPACKMON_ENCRYPTION_KEY=\n"+
		"PACKMON_ADMIN_AUDIT_HMAC_KEY=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runInitSecrets([]string{"--env", env, "--example", example}); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(env) //nolint:gosec // test reads a path built from t.TempDir()
	if err := runInitSecrets([]string{"--env", env, "--example", example}); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(env) //nolint:gosec // test reads a path built from t.TempDir()
	if string(first) != string(second) {
		t.Fatal("second run changed .env; must be idempotent")
	}
}

func TestRunInitSecretsReportsInvalidInputPaths(t *testing.T) {
	t.Run("invalid flag preserves selected environment", func(t *testing.T) {
		dir := t.TempDir()
		env := filepath.Join(dir, ".env")
		const original = "UNCHANGED=operator-content\n"
		if err := os.WriteFile(env, []byte(original), 0o600); err != nil {
			t.Fatalf("write existing environment: %v", err)
		}

		err := runInitSecrets([]string{"--env", env, "--unknown"})
		if err == nil || err.Error() != "flag provided but not defined: -unknown" {
			t.Fatalf("runInitSecrets() error = %v, want exact invalid-flag error", err)
		}
		data, readErr := os.ReadFile(env) //nolint:gosec // test reads a path built from t.TempDir().
		if readErr != nil {
			t.Fatalf("read existing environment: %v", readErr)
		}
		if string(data) != original {
			t.Fatalf("invalid flag changed existing environment: %q", data)
		}
		assertNoInitSecretsTempFiles(t, filepath.Join(dir, ".env-*.tmp"))
	})

	t.Run("environment path is directory", func(t *testing.T) {
		root := t.TempDir()
		env := filepath.Join(root, "environment")
		if err := os.Mkdir(env, 0o700); err != nil {
			t.Fatalf("create environment directory: %v", err)
		}
		const original = "operator-owned fixture content\n"
		fixture := filepath.Join(env, "operator-file")
		if err := os.WriteFile(fixture, []byte(original), 0o600); err != nil {
			t.Fatalf("write environment fixture: %v", err)
		}
		if err := os.Mkdir(filepath.Join(env, "operator-directory"), 0o700); err != nil {
			t.Fatalf("create nested environment directory: %v", err)
		}
		beforeEntries, err := os.ReadDir(env)
		if err != nil {
			t.Fatalf("read environment directory before init-secrets: %v", err)
		}
		example := filepath.Join(root, ".env.example")
		if err := os.WriteFile(example, []byte("POSTGRES_PASSWORD=\n"), 0o600); err != nil {
			t.Fatalf("write example: %v", err)
		}

		err = runInitSecrets([]string{"--env", env, "--example", example})
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) || pathErr.Op != "read" || pathErr.Path != env {
			t.Fatalf("runInitSecrets() error = %v, want read PathError for %s", err, env)
		}
		if info, statErr := os.Stat(env); statErr != nil || !info.IsDir() {
			t.Fatalf("environment directory after failure = %v, %v; want preserved directory", info, statErr)
		}
		afterEntries, readErr := os.ReadDir(env)
		if readErr != nil {
			t.Fatalf("read environment directory after init-secrets: %v", readErr)
		}
		if len(afterEntries) != len(beforeEntries) {
			t.Fatalf("environment directory entry count = %d, want unchanged %d", len(afterEntries), len(beforeEntries))
		}
		for i := range beforeEntries {
			if afterEntries[i].Name() != beforeEntries[i].Name() ||
				afterEntries[i].Type() != beforeEntries[i].Type() ||
				afterEntries[i].IsDir() != beforeEntries[i].IsDir() {
				t.Fatalf("environment directory entry %d = %s (%v), want unchanged %s (%v)",
					i, afterEntries[i].Name(), afterEntries[i].Type(), beforeEntries[i].Name(), beforeEntries[i].Type())
			}
		}
		data, readErr := os.ReadFile(fixture) //nolint:gosec // test reads a path built from t.TempDir().
		if readErr != nil {
			t.Fatalf("read preserved environment fixture: %v", readErr)
		}
		if string(data) != original {
			t.Fatalf("environment fixture content = %q, want unchanged %q", data, original)
		}
		assertNoInitSecretsTempFiles(t, filepath.Join(env, ".env-*.tmp"))
	})

	t.Run("template path is directory for fresh environment", func(t *testing.T) {
		dir := t.TempDir()
		env := filepath.Join(dir, ".env")

		err := runInitSecrets([]string{"--env", env, "--example", dir})
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) || pathErr.Op != "read" || pathErr.Path != dir {
			t.Fatalf("runInitSecrets() error = %v, want read PathError for %s", err, dir)
		}
		if _, statErr := os.Stat(env); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("fresh environment stat error = %v, want os.ErrNotExist", statErr)
		}
		assertNoInitSecretsTempFiles(t, filepath.Join(dir, ".env-*.tmp"))
	})

	t.Run("environment parent cannot be created", func(t *testing.T) {
		dir := t.TempDir()
		example := filepath.Join(dir, ".env.example")
		if err := os.WriteFile(example, []byte("POSTGRES_PASSWORD=\n"), 0o600); err != nil {
			t.Fatalf("write example: %v", err)
		}
		missingDir := filepath.Join(dir, "missing")
		env := filepath.Join(missingDir, ".env")

		err := runInitSecrets([]string{"--env", env, "--example", example})
		if err == nil || !strings.HasPrefix(err.Error(), "write "+env+": ") || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("runInitSecrets() error = %v, want wrapped write error with os.ErrNotExist", err)
		}
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) || pathErr.Op != "open" ||
			filepath.Dir(pathErr.Path) != missingDir ||
			!strings.HasPrefix(filepath.Base(pathErr.Path), ".env-") ||
			!strings.HasSuffix(filepath.Base(pathErr.Path), ".tmp") {
			t.Fatalf("runInitSecrets() path error = %+v, want open of an atomic .env-*.tmp file below %s", pathErr, missingDir)
		}
		if _, statErr := os.Stat(env); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed destination stat error = %v, want os.ErrNotExist", statErr)
		}
		assertNoInitSecretsTempFiles(t, filepath.Join(missingDir, ".env-*.tmp"))
	})
}

func assertNoInitSecretsTempFiles(t *testing.T, pattern string) {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob init-secrets temporary files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("init-secrets left temporary files matching %s: %v", pattern, matches)
	}
}
