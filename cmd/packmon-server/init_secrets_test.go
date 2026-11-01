package main

import (
	"os"
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
