package migrations

import (
	"fmt"
	iofs "io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestExpectedVersionMatchesHighestEmbeddedMigration(t *testing.T) {
	t.Parallel()

	highest := 0
	seenUp := map[int]bool{}
	seenDown := map[int]bool{}
	err := iofs.WalkDir(fs, ".", func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".sql" {
			return nil
		}
		base := filepath.Base(path)
		if len(base) < 3 {
			return fmt.Errorf("migration filename %q is too short", base)
		}
		version, err := strconv.Atoi(base[:3])
		if err != nil {
			return fmt.Errorf("migration filename %q does not start with a numeric version: %w", base, err)
		}
		if version > highest {
			highest = version
		}
		switch {
		case strings.HasSuffix(base, ".up.sql"):
			seenUp[version] = true
		case strings.HasSuffix(base, ".down.sql"):
			seenDown[version] = true
		default:
			return fmt.Errorf("migration filename %q must end with .up.sql or .down.sql", base)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded migrations: %v", err)
	}

	if highest != ExpectedVersion {
		t.Fatalf("highest embedded migration = %d, ExpectedVersion = %d", highest, ExpectedVersion)
	}
	for version := 1; version <= highest; version++ {
		if !seenUp[version] || !seenDown[version] {
			t.Fatalf("migration %03d has up=%v down=%v, want both", version, seenUp[version], seenDown[version])
		}
	}
}

func TestEmbeddedUpMigrationsAreSortedAndComplete(t *testing.T) {
	t.Parallel()

	migrations, err := embeddedUpMigrations()
	if err != nil {
		t.Fatalf("embeddedUpMigrations: %v", err)
	}
	if len(migrations) != ExpectedVersion {
		t.Fatalf("embedded up migration count = %d, want %d", len(migrations), ExpectedVersion)
	}
	for i, migration := range migrations {
		wantVersion := i + 1
		if migration.version != wantVersion {
			t.Fatalf("migration[%d].version = %d, want %d", i, migration.version, wantVersion)
		}
		if migration.name == "" || !strings.HasSuffix(migration.name, ".up.sql") {
			t.Fatalf("migration[%d].name = %q", i, migration.name)
		}
		if strings.TrimSpace(migration.sql) == "" {
			t.Fatalf("migration[%d].sql is empty", i)
		}
	}
}

func TestParseMigrationVersionRejectsInvalidFilenames(t *testing.T) {
	t.Parallel()

	if version, err := parseMigrationVersion("006_api_key_expiration.up.sql"); err != nil || version != 6 {
		t.Fatalf("parseMigrationVersion(valid) = %d, %v", version, err)
	}
	for _, name := range []string{"1.sql", "abc_name.up.sql"} {
		if _, err := parseMigrationVersion(name); err == nil {
			t.Fatalf("parseMigrationVersion(%q) error = nil", name)
		}
	}
}
