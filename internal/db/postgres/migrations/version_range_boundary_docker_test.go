//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/jackc/pgx/v5/pgconn"
)

const versionRangeBoundaryMigrationVersion = 50

// versionRangeBoundaryRow is one affected_packages / malicious_findings fixture:
// the version_ranges value it is seeded with and whether migration 050 must
// keep it (valid under the strict check) or repair it.
type versionRangeBoundaryRow struct {
	name   string
	ranges string
	keep   bool
}

// versionRangeBoundaryRows are accepted by the pre-050 check (which only tested
// that a boundary key exists) but only the keep rows satisfy the strict one.
var versionRangeBoundaryRows = []versionRangeBoundaryRow{
	{name: "empty-array", ranges: `[]`, keep: true},
	{name: "osv-single-key-events", ranges: `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`, keep: true},
	{name: "ghsa-blank-sibling-keys", ranges: `[{"type":"ECOSYSTEM","events":[{"introduced":"0","fixed":"","last_affected":""},{"introduced":"","fixed":"2.0.0","last_affected":""}]}]`, keep: true},
	{name: "null-sibling-key", ranges: `[{"events":[{"introduced":"0","fixed":null}]}]`, keep: true},
	{name: "limit-only", ranges: `[{"events":[{"limit":"*"}]}]`, keep: true},
	{name: "range-without-events", ranges: `[{}]`},
	{name: "null-boundary", ranges: `[{"events":[{"introduced":null}]}]`},
	{name: "numeric-boundary", ranges: `[{"events":[{"introduced":1}]}]`},
	{name: "blank-boundary", ranges: `[{"events":[{"introduced":"  "}]}]`},
	{name: "numeric-sibling", ranges: `[{"events":[{"introduced":"0","fixed":5}]}]`},
	{name: "valid-then-invalid-range", ranges: `[{"events":[{"introduced":"0"}]},{}]`},
}

// TestVersionRangeBoundaryMigrationRepairsAndTightensAgainstPostgres seeds rows
// the old check accepted, applies 050, and verifies the repair (affected
// packages fall back to [] and malicious findings to NULL, as 032 did), the
// validated stricter constraints, and that 050 down restores the old check.
func TestVersionRangeBoundaryMigrationRepairsAndTightensAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	migrations, err := embeddedUpMigrations()
	if err != nil {
		t.Fatalf("embeddedUpMigrations() error = %v", err)
	}
	for _, migration := range migrations {
		if migration.version >= versionRangeBoundaryMigrationVersion {
			break
		}
		if err := applyMigration(ctx, db, migration); err != nil {
			t.Fatalf("apply migration %s: %v", migration.name, err)
		}
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, summary, published, modified)
		VALUES ('GHSA-boundary-fixture', 'boundary fixture', NOW(), NOW())`); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	for _, row := range versionRangeBoundaryRows {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO affected_packages (vulnerability_id, ecosystem, name, version_ranges, versions_affected)
			VALUES ('GHSA-boundary-fixture', 'npm', $1, $2::jsonb, '["1.0.0"]'::jsonb)`, row.name, row.ranges); err != nil {
			t.Fatalf("seed affected package %s (must pass the pre-050 check): %v", row.name, err)
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO malicious_findings (id, ecosystem, name, version_ranges, versions, source, risk_type, summary)
			VALUES ($1, 'npm', $1, $2::jsonb, '["1.0.0"]'::jsonb, 'openssf', 'malware', 'boundary fixture')`, "MAL-"+row.name, row.ranges); err != nil {
			t.Fatalf("seed malicious finding %s (must pass the pre-050 check): %v", row.name, err)
		}
	}

	up, err := ReadEmbeddedMigration(versionRangeBoundaryMigrationVersion, MigrationDirectionUp)
	if err != nil {
		t.Fatalf("read migration 050 up: %v", err)
	}
	if err := applyMigration(ctx, db, migrationFile{version: up.Version, name: up.Name, direction: up.Direction, sql: up.SQL}); err != nil {
		t.Fatalf("apply migration 050 up: %v", err)
	}

	for _, row := range versionRangeBoundaryRows {
		var affectedRanges, affectedVersions string
		if err := db.QueryRowContext(ctx, `
			SELECT version_ranges::text, versions_affected::text
			FROM affected_packages
			WHERE vulnerability_id = 'GHSA-boundary-fixture' AND name = $1`, row.name).Scan(&affectedRanges, &affectedVersions); err != nil {
			t.Fatalf("read affected package %s: %v", row.name, err)
		}
		var maliciousRanges sql.NullString
		if err := db.QueryRowContext(ctx, `SELECT version_ranges::text FROM malicious_findings WHERE id = $1`, "MAL-"+row.name).Scan(&maliciousRanges); err != nil {
			t.Fatalf("read malicious finding %s: %v", row.name, err)
		}
		if affectedVersions != `["1.0.0"]` {
			t.Fatalf("%s versions_affected = %s, want untouched", row.name, affectedVersions)
		}
		if row.keep {
			if !jsonTextEqual(t, db, affectedRanges, row.ranges) {
				t.Fatalf("%s affected version_ranges = %s, want kept %s", row.name, affectedRanges, row.ranges)
			}
			if !maliciousRanges.Valid || !jsonTextEqual(t, db, maliciousRanges.String, row.ranges) {
				t.Fatalf("%s malicious version_ranges = %v, want kept %s", row.name, maliciousRanges, row.ranges)
			}
			continue
		}
		if affectedRanges != `[]` {
			t.Fatalf("%s affected version_ranges = %s, want repaired to []", row.name, affectedRanges)
		}
		if maliciousRanges.Valid {
			t.Fatalf("%s malicious version_ranges = %s, want repaired to NULL", row.name, maliciousRanges.String)
		}
	}

	for _, constraint := range []string{
		"affected_packages_version_ranges_array_check",
		"malicious_findings_version_ranges_array_check",
	} {
		var validated bool
		if err := db.QueryRowContext(ctx, `SELECT convalidated FROM pg_constraint WHERE conname = $1`, constraint).Scan(&validated); err != nil {
			t.Fatalf("read constraint %s: %v", constraint, err)
		}
		if !validated {
			t.Fatalf("constraint %s is NOT VALID after 050 up, want validated", constraint)
		}
	}
	for _, row := range versionRangeBoundaryRows {
		_, err := db.ExecContext(ctx, `
			UPDATE affected_packages SET version_ranges = $2::jsonb
			WHERE vulnerability_id = 'GHSA-boundary-fixture' AND name = $1`, row.name, row.ranges)
		if row.keep {
			if err != nil {
				t.Fatalf("write valid version_ranges %s after 050: %v", row.name, err)
			}
			continue
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("write invalid version_ranges %s after 050 error = %v, want check violation", row.name, err)
		}
	}

	down, err := ReadEmbeddedMigration(versionRangeBoundaryMigrationVersion, MigrationDirectionDown)
	if err != nil {
		t.Fatalf("read migration 050 down: %v", err)
	}
	if err := applyMigration(ctx, db, migrationFile{version: down.Version, name: down.Name, direction: down.Direction, sql: down.SQL}); err != nil {
		t.Fatalf("apply migration 050 down: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE affected_packages SET version_ranges = '[{}]'::jsonb
		WHERE vulnerability_id = 'GHSA-boundary-fixture' AND name = 'range-without-events'`); err != nil {
		t.Fatalf("050 down did not restore the previous check: %v", err)
	}
}

func jsonTextEqual(t *testing.T, db *sql.DB, left, right string) bool {
	t.Helper()

	var equal bool
	if err := db.QueryRowContext(context.Background(), `SELECT $1::jsonb = $2::jsonb`, left, right).Scan(&equal); err != nil {
		t.Fatalf("compare JSON %s and %s: %v", left, right, err)
	}
	return equal
}
