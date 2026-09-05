package main

import (
	"os"
	"path/filepath"
	"runtime"
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
