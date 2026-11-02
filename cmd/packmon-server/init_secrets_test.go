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
	cmd := exec.Command( // #nosec G204 -- fixed Compose arguments and test/repository paths.
		"docker", "compose",
		"--env-file", env,
		"--project-directory", repoRoot,
		"-f", filepath.Join(repoRoot, "docker-compose.yml"),
		"-f", filepath.Join(repoRoot, "docker-compose.override.yml"),
		"config", "--quiet",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker compose rejected generated .env: %v:\n%s", err, output)
	}
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
	dir := t.TempDir()
	example := filepath.Join(dir, ".env.example")
	if err := os.WriteFile(example, []byte("POSTGRES_PASSWORD=\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "invalid flag",
			args: []string{"--unknown"},
			want: "flag provided but not defined",
		},
		{
			name: "environment path is directory",
			args: []string{"--env", dir, "--example", example},
			want: "read " + dir,
		},
		{
			name: "template path is directory for fresh environment",
			args: []string{"--env", filepath.Join(dir, ".env"), "--example", dir},
			want: "read " + dir,
		},
		{
			name: "environment parent cannot be created",
			args: []string{"--env", filepath.Join(dir, "missing", ".env"), "--example", example},
			want: "write " + filepath.Join(dir, "missing", ".env"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runInitSecrets(tt.args)
			if err == nil {
				t.Fatal("runInitSecrets succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}
