package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/config"
)

// TestVerifyProductionSchemaRedactsVersionReadError keeps driver diagnostics
// out of the startup log. migrations.VersionContext forwards database errors
// unredacted, and those can carry the DSN password, secret assignments, or
// local filesystem paths.
func TestVerifyProductionSchemaRedactsVersionReadError(t *testing.T) {
	originalVersion := readDatabaseMigrationVersionContext
	t.Cleanup(func() {
		readDatabaseMigrationVersionContext = originalVersion
	})
	readDatabaseMigrationVersionContext = func(context.Context, string) (uint, bool, error) {
		return 0, false, errors.New(`migrations: open db: cannot connect to postgres://packmon:dsn-secret-pass@db.internal:5432/packmon?sslmode=require password=kv-secret-pass; reading /var/lib/postgresql/data/pg_hba.conf and C:\Users\Operator\AppData\Local\Packmon\pgpass.conf failed` + "\nforged=line")
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	cfg := &config.Config{Server: config.ServerConfig{Mode: config.ModeProduction}}
	if _, err := verifyProductionSchema(context.Background(), cfg, logger); err == nil {
		t.Fatal("verifyProductionSchema() error = nil, want version read failure")
	}

	got := logs.String()
	for _, leaked := range []string{
		"dsn-secret-pass",
		"kv-secret-pass",
		"/var/lib/postgresql/data/pg_hba.conf",
		`AppData\\Local\\Packmon\\pgpass.conf`,
		`\nforged=line`,
	} {
		if strings.Contains(got, leaked) {
			t.Fatalf("schema check log leaked %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "failed to read database schema version") {
		t.Fatalf("schema check log = %s, want the schema version failure message", got)
	}
	if !strings.Contains(got, "migrations: open db") {
		t.Fatalf("schema check log = %s, want the failure class kept", got)
	}
}
