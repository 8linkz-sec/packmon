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

// maliciousRepairRow is a malicious finding with an invalid range whose repair
// depends on its exact versions and tombstone state.
type maliciousRepairRow struct {
	id         string
	versions   sql.NullString
	removed    bool
	wantAction string
	// changedAfterRepair is a write that happens between 050 up and down:
	// "retombstone" (an import resurrects the finding, then it is tombstoned
	// again, leaving NULL ranges) or "reimport" (an import rewrites it with
	// valid NULL ranges and new exact versions). 050 down must keep the row's
	// current state although it still looks repaired.
	changedAfterRepair string
}

var maliciousRepairRows = []maliciousRepairRow{
	// Exact versions present: ranges are cleared and only those versions match.
	{id: "MAL-repair-with-versions", versions: sql.NullString{String: `["1.0.0"]`, Valid: true}, wantAction: "ranges_cleared"},
	// No exact versions: clearing the ranges would match every version.
	{id: "MAL-repair-null-versions", wantAction: "quarantined"},
	{id: "MAL-repair-empty-versions", versions: sql.NullString{String: `[]`, Valid: true}, wantAction: "quarantined"},
	{id: "MAL-repair-manual", wantAction: "quarantined"},
	// Already tombstoned: stays tombstoned, only the ranges are cleared.
	{id: "MAL-repair-already-removed", removed: true, wantAction: "ranges_cleared"},
	// Written again after the repair: 050 down must leave them alone.
	{id: "MAL-repair-retombstoned", wantAction: "quarantined", changedAfterRepair: "retombstone"},
	{id: "MAL-repair-reimported", versions: sql.NullString{String: `["1.0.0"]`, Valid: true}, wantAction: "ranges_cleared", changedAfterRepair: "reimport"},
}

// rewrittenAffectedPackage is an affected package that 050 resets to [] and a
// later feed import rewrites with a legitimate [] of its own.
const rewrittenAffectedPackage = "rewritten-to-empty"

// TestVersionRangeBoundaryMigrationRepairsAndTightensAgainstPostgres seeds rows
// the old check accepted, applies 050, and verifies every repair branch and its
// repair-log entry, the validated stricter constraints, and that 050 down
// restores the old check and the recorded original rows.
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
	if _, err := db.ExecContext(ctx, `
		INSERT INTO affected_packages (vulnerability_id, ecosystem, name, version_ranges, versions_affected)
		VALUES ('GHSA-boundary-fixture', 'npm', $1, '[{}]'::jsonb, '[]'::jsonb)`, rewrittenAffectedPackage); err != nil {
		t.Fatalf("seed rewritten affected package: %v", err)
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
	const invalidRanges = `[{"events":[{"introduced":null}]}]`
	for _, row := range maliciousRepairRows {
		source, id := "openssf", row.id
		if row.id == "MAL-repair-manual" {
			source, id = "manual", "manual:repair-fixture"
		}
		var versions any
		if row.versions.Valid {
			versions = row.versions.String
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO malicious_findings (id, ecosystem, name, version_ranges, versions, source, risk_type, summary, removed_at)
			VALUES ($1, 'npm', $1, $2::jsonb, $3::jsonb, $4, 'malware', 'repair fixture',
			        CASE WHEN $5 THEN TIMESTAMPTZ '2026-01-02T03:04:05Z' END)`,
			id, invalidRanges, versions, source, row.removed); err != nil {
			t.Fatalf("seed malicious repair row %s: %v", row.id, err)
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
		var maliciousActive bool
		if err := db.QueryRowContext(ctx, `SELECT version_ranges::text, removed_at IS NULL FROM malicious_findings WHERE id = $1`, "MAL-"+row.name).Scan(&maliciousRanges, &maliciousActive); err != nil {
			t.Fatalf("read malicious finding %s: %v", row.name, err)
		}
		if affectedVersions != `["1.0.0"]` {
			t.Fatalf("%s versions_affected = %s, want untouched", row.name, affectedVersions)
		}
		if !maliciousActive {
			t.Fatalf("%s malicious finding with exact versions was tombstoned, want active", row.name)
		}
		if row.keep {
			if !jsonTextEqual(t, db, affectedRanges, row.ranges) {
				t.Fatalf("%s affected version_ranges = %s, want kept %s", row.name, affectedRanges, row.ranges)
			}
			if !maliciousRanges.Valid || !jsonTextEqual(t, db, maliciousRanges.String, row.ranges) {
				t.Fatalf("%s malicious version_ranges = %v, want kept %s", row.name, maliciousRanges, row.ranges)
			}
			assertNoRepairLogEntry(t, db, "malicious_findings", "MAL-"+row.name)
			continue
		}
		if affectedRanges != `[]` {
			t.Fatalf("%s affected version_ranges = %s, want repaired to []", row.name, affectedRanges)
		}
		if maliciousRanges.Valid {
			t.Fatalf("%s malicious version_ranges = %s, want repaired to NULL", row.name, maliciousRanges.String)
		}
		assertRepairLogEntry(t, db, "malicious_findings", "MAL-"+row.name, "ranges_cleared", row.ranges)
		var affectedID string
		if err := db.QueryRowContext(ctx, `SELECT id::text FROM affected_packages WHERE vulnerability_id = 'GHSA-boundary-fixture' AND name = $1`, row.name).Scan(&affectedID); err != nil {
			t.Fatalf("read affected package id %s: %v", row.name, err)
		}
		assertRepairLogEntry(t, db, "affected_packages", affectedID, "ranges_reset", row.ranges)
	}

	for _, row := range maliciousRepairRows {
		id := row.id
		if row.id == "MAL-repair-manual" {
			id = "manual:repair-fixture"
		}
		var ranges sql.NullString
		var removedAt sql.NullTime
		if err := db.QueryRowContext(ctx, `SELECT version_ranges::text, removed_at FROM malicious_findings WHERE id = $1`, id).Scan(&ranges, &removedAt); err != nil {
			t.Fatalf("read malicious repair row %s: %v", id, err)
		}
		if ranges.Valid {
			t.Fatalf("%s version_ranges = %s, want NULL", id, ranges.String)
		}
		switch {
		case row.removed:
			if !removedAt.Valid || removedAt.Time.UTC().Format("2006-01-02T15:04:05Z") != "2026-01-02T03:04:05Z" {
				t.Fatalf("%s removed_at = %v, want the original tombstone kept", id, removedAt)
			}
		case row.wantAction == "quarantined":
			if !removedAt.Valid {
				t.Fatalf("%s removed_at = NULL, want quarantined (no exact versions)", id)
			}
		default:
			if removedAt.Valid {
				t.Fatalf("%s removed_at = %v, want active with its exact versions", id, removedAt.Time)
			}
		}
		assertRepairLogEntry(t, db, "malicious_findings", id, row.wantAction, invalidRanges)
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
			WHERE vulnerability_id = 'GHSA-boundary-fixture' AND name = $1 AND $2::jsonb <> version_ranges`, row.name, row.ranges)
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

	// Writes after the repair: each moves updated_at away from repaired_at.
	if _, err := db.ExecContext(ctx, `
		UPDATE affected_packages SET version_ranges = '[]'::jsonb, versions_affected = '["3.0.0"]'::jsonb, updated_at = clock_timestamp()
		WHERE vulnerability_id = 'GHSA-boundary-fixture' AND name = $1`, rewrittenAffectedPackage); err != nil {
		t.Fatalf("rewrite affected package after repair: %v", err)
	}
	for _, row := range maliciousRepairRows {
		switch row.changedAfterRepair {
		case "retombstone":
			for _, statement := range []string{
				`UPDATE malicious_findings SET removed_at = NULL, versions = '["2.0.0"]'::jsonb, updated_at = clock_timestamp() WHERE id = $1`,
				`UPDATE malicious_findings SET removed_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = $1`,
			} {
				if _, err := db.ExecContext(ctx, statement, row.id); err != nil {
					t.Fatalf("re-tombstone %s: %v", row.id, err)
				}
			}
		case "reimport":
			if _, err := db.ExecContext(ctx, `
				UPDATE malicious_findings SET version_ranges = NULL, versions = '["1.0.1"]'::jsonb, updated_at = clock_timestamp()
				WHERE id = $1`, row.id); err != nil {
				t.Fatalf("re-import %s: %v", row.id, err)
			}
		}
	}

	down, err := ReadEmbeddedMigration(versionRangeBoundaryMigrationVersion, MigrationDirectionDown)
	if err != nil {
		t.Fatalf("read migration 050 down: %v", err)
	}
	if err := applyMigration(ctx, db, migrationFile{version: down.Version, name: down.Name, direction: down.Direction, sql: down.SQL}); err != nil {
		t.Fatalf("apply migration 050 down: %v", err)
	}

	for _, row := range versionRangeBoundaryRows {
		var affectedRanges, maliciousRanges string
		if err := db.QueryRowContext(ctx, `
			SELECT version_ranges::text FROM affected_packages
			WHERE vulnerability_id = 'GHSA-boundary-fixture' AND name = $1`, row.name).Scan(&affectedRanges); err != nil {
			t.Fatalf("read affected package %s after down: %v", row.name, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT version_ranges::text FROM malicious_findings WHERE id = $1`, "MAL-"+row.name).Scan(&maliciousRanges); err != nil {
			t.Fatalf("read malicious finding %s after down: %v", row.name, err)
		}
		if !jsonTextEqual(t, db, affectedRanges, row.ranges) || !jsonTextEqual(t, db, maliciousRanges, row.ranges) {
			t.Fatalf("%s after 050 down: affected=%s malicious=%s, want restored %s", row.name, affectedRanges, maliciousRanges, row.ranges)
		}
	}
	for _, row := range maliciousRepairRows {
		id := row.id
		if row.id == "MAL-repair-manual" {
			id = "manual:repair-fixture"
		}
		var ranges, versions sql.NullString
		var removedAt sql.NullTime
		if err := db.QueryRowContext(ctx, `SELECT version_ranges::text, versions::text, removed_at FROM malicious_findings WHERE id = $1`, id).Scan(&ranges, &versions, &removedAt); err != nil {
			t.Fatalf("read malicious repair row %s after down: %v", id, err)
		}
		switch row.changedAfterRepair {
		case "retombstone":
			if ranges.Valid || !removedAt.Valid || versions.String != `["2.0.0"]` {
				t.Fatalf("%s after down = ranges %v versions %v removed %v, want the later tombstone kept (not reactivated)", id, ranges, versions, removedAt)
			}
			continue
		case "reimport":
			if ranges.Valid || removedAt.Valid || versions.String != `["1.0.1"]` {
				t.Fatalf("%s after down = ranges %v versions %v removed %v, want the re-imported row kept", id, ranges, versions, removedAt)
			}
			continue
		}
		if !ranges.Valid || !jsonTextEqual(t, db, ranges.String, invalidRanges) {
			t.Fatalf("%s version_ranges after down = %v, want restored %s", id, ranges, invalidRanges)
		}
		if removedAt.Valid != row.removed {
			t.Fatalf("%s removed_at after down = %v, want tombstoned=%t as before 050", id, removedAt, row.removed)
		}
	}
	var rewrittenRanges, rewrittenVersions string
	if err := db.QueryRowContext(ctx, `
		SELECT version_ranges::text, versions_affected::text FROM affected_packages
		WHERE vulnerability_id = 'GHSA-boundary-fixture' AND name = $1`, rewrittenAffectedPackage).Scan(&rewrittenRanges, &rewrittenVersions); err != nil {
		t.Fatalf("read rewritten affected package after down: %v", err)
	}
	if rewrittenRanges != `[]` || rewrittenVersions != `["3.0.0"]` {
		t.Fatalf("rewritten affected package after down = %s / %s, want the newer [] / [\"3.0.0\"] kept", rewrittenRanges, rewrittenVersions)
	}

	var repairLog sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.packmon_m050_version_range_repairs')::text`).Scan(&repairLog); err != nil {
		t.Fatalf("check repair log after down: %v", err)
	}
	if repairLog.Valid {
		t.Fatal("packmon_m050_version_range_repairs still exists after 050 down")
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE affected_packages SET version_ranges = '[{}]'::jsonb
		WHERE vulnerability_id = 'GHSA-boundary-fixture' AND name = 'osv-single-key-events'`); err != nil {
		t.Fatalf("050 down did not restore the previous check: %v", err)
	}
}

func assertRepairLogEntry(t *testing.T, db *sql.DB, table, rowID, wantAction, wantOriginal string) {
	t.Helper()

	var action, original string
	if err := db.QueryRowContext(context.Background(), `
		SELECT action, original_version_ranges::text
		FROM packmon_m050_version_range_repairs
		WHERE table_name = $1 AND row_id = $2`, table, rowID).Scan(&action, &original); err != nil {
		t.Fatalf("read repair log for %s %s: %v", table, rowID, err)
	}
	if action != wantAction || !jsonTextEqual(t, db, original, wantOriginal) {
		t.Fatalf("repair log for %s %s = (%s, %s), want (%s, %s)", table, rowID, action, original, wantAction, wantOriginal)
	}
}

func assertNoRepairLogEntry(t *testing.T, db *sql.DB, table, rowID string) {
	t.Helper()

	var count int
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM packmon_m050_version_range_repairs
		WHERE table_name = $1 AND row_id = $2`, table, rowID).Scan(&count); err != nil {
		t.Fatalf("count repair log for %s %s: %v", table, rowID, err)
	}
	if count != 0 {
		t.Fatalf("repair log has %d entries for valid %s %s, want none", count, table, rowID)
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
