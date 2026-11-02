//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type f123F128ReputationRow struct {
	status      string
	severity    string
	summary     string
	description string
	evidence    string
	updatedAt   time.Time
}

func TestF123F128MigrationContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	db, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	db.SetMaxOpenConns(4)

	t.Run("migration_008_malicious_tombstones", func(t *testing.T) {
		t.Run("populated_round_trip_catalog_and_repeatability", func(t *testing.T) {
			ctx := f123F128PrepareLeaf(t, db)
			f123F128AssertStatementCounts(t, 8, 2, 2)
			f123F128ApplyThrough(t, ctx, db, 7)
			f123F128SeedMaliciousFindings(t, ctx, db)

			before := f123F128Snapshot(t, ctx, db, `SELECT id, ecosystem, name, versions, source, risk_type, severity, summary, description, reference_urls, origin_ref, published, created_at, updated_at, created_by FROM malicious_findings ORDER BY id`)
			up := f123F128Apply(t, ctx, db, 8, MigrationDirectionUp)
			f123F128AssertCleanMetadata(t, ctx, db, up, 1)
			f123F128AssertColumn(t, ctx, db, "malicious_findings", "removed_at", "timestamp with time zone", "YES", "")
			f123F128AssertIndex(t, ctx, db, "idx_malicious_removed_at", "malicious_findings", false, "removed_at", "")
			f123F128AssertNullCount(t, ctx, db, "malicious_findings", "removed_at", 2)
			f123F128Exec(t, ctx, db, `UPDATE malicious_findings SET removed_at = '2026-01-02T03:04:05Z' WHERE id = 'MAL-REMOVED'`)

			down := f123F128Apply(t, ctx, db, 8, MigrationDirectionDown)
			f123F128AssertCleanMetadata(t, ctx, db, down, 2)
			f123F128AssertColumnAbsent(t, ctx, db, "malicious_findings", "removed_at")
			f123F128AssertRelationAbsent(t, ctx, db, "idx_malicious_removed_at")
			if got := f123F128Snapshot(t, ctx, db, `SELECT id, ecosystem, name, versions, source, risk_type, severity, summary, description, reference_urls, origin_ref, published, created_at, updated_at, created_by FROM malicious_findings ORDER BY id`); got != before {
				t.Fatalf("008 down changed surviving malicious finding fields\ngot:  %s\nwant: %s", got, before)
			}

			f123F128Apply(t, ctx, db, 8, MigrationDirectionDown)
			f123F128AssertColumnAbsent(t, ctx, db, "malicious_findings", "removed_at")
			f123F128Apply(t, ctx, db, 8, MigrationDirectionUp)
			f123F128AssertColumn(t, ctx, db, "malicious_findings", "removed_at", "timestamp with time zone", "YES", "")
			f123F128AssertIndex(t, ctx, db, "idx_malicious_removed_at", "malicious_findings", false, "removed_at", "")
			f123F128AssertNullCount(t, ctx, db, "malicious_findings", "removed_at", 2)
		})

		t.Run("up_collision_is_atomic_and_dirty_run_is_refused", func(t *testing.T) {
			ctx := f123F128PrepareLeaf(t, db)
			f123F128ApplyThrough(t, ctx, db, 7)
			f123F128SeedMaliciousFindings(t, ctx, db)
			f123F128Exec(t, ctx, db, `CREATE INDEX idx_malicious_removed_at ON malicious_findings(name)`)
			up := f123F128Embedded(t, 8, MigrationDirectionUp)
			started := time.Now().UTC()
			err := applyMigration(ctx, db, up)
			finished := time.Now().UTC()
			if err == nil || !strings.Contains(err.Error(), "idx_malicious_removed_at") {
				t.Fatalf("008 up collision error = %v, want idx_malicious_removed_at conflict", err)
			}
			f123F128AssertColumnAbsent(t, ctx, db, "malicious_findings", "removed_at")
			f123F128AssertIndex(t, ctx, db, "idx_malicious_removed_at", "malicious_findings", false, "name", "")
			f123F128AssertDirtyMetadata(t, ctx, db, up, started, finished, 1)
			f123F128AssertRunRefusesDirty(t, ctx, instance.dsn, 8)
			f123F128AssertColumnAbsent(t, ctx, db, "malicious_findings", "removed_at")

			f123F128ClearDirty(t, ctx, db, 8)
			f123F128Exec(t, ctx, db, `DROP INDEX idx_malicious_removed_at`)
			f123F128Apply(t, ctx, db, 8, MigrationDirectionUp)
			f123F128AssertColumn(t, ctx, db, "malicious_findings", "removed_at", "timestamp with time zone", "YES", "")
			f123F128AssertIndex(t, ctx, db, "idx_malicious_removed_at", "malicious_findings", false, "removed_at", "")
			f123F128AssertTargetEvents(t, ctx, db, up, 2, 1, 1)
		})

		t.Run("down_dependency_is_atomic_and_recoverable", func(t *testing.T) {
			ctx := f123F128PrepareLeaf(t, db)
			f123F128ApplyThrough(t, ctx, db, 8)
			f123F128SeedMaliciousFindings(t, ctx, db)
			f123F128Exec(t, ctx, db, `CREATE VIEW f123_f128_removed_view AS SELECT id, removed_at FROM malicious_findings`)
			down := f123F128Embedded(t, 8, MigrationDirectionDown)
			started := time.Now().UTC()
			err := applyMigration(ctx, db, down)
			finished := time.Now().UTC()
			if err == nil || !strings.Contains(err.Error(), "other objects depend") {
				t.Fatalf("008 down dependency error = %v, want dependent-view failure", err)
			}
			f123F128AssertColumn(t, ctx, db, "malicious_findings", "removed_at", "timestamp with time zone", "YES", "")
			f123F128AssertIndex(t, ctx, db, "idx_malicious_removed_at", "malicious_findings", false, "removed_at", "")
			f123F128AssertDirtyMetadata(t, ctx, db, down, started, finished, 2)
			f123F128AssertRunRefusesDirty(t, ctx, instance.dsn, 8)

			f123F128ClearDirty(t, ctx, db, 8)
			f123F128Exec(t, ctx, db, `DROP VIEW f123_f128_removed_view`)
			f123F128Apply(t, ctx, db, 8, MigrationDirectionDown)
			f123F128AssertColumnAbsent(t, ctx, db, "malicious_findings", "removed_at")
			f123F128AssertRelationAbsent(t, ctx, db, "idx_malicious_removed_at")
			f123F128AssertTargetEvents(t, ctx, db, down, 3, 1, 1)
		})
	})

	t.Run("migration_009_reputation_risk_status", func(t *testing.T) {
		t.Run("selective_conversion_exact_restore_and_catalog", func(t *testing.T) {
			ctx := f123F128PrepareLeaf(t, db)
			f123F128AssertStatementCounts(t, 9, 5, 5)
			f123F128ApplyThrough(t, ctx, db, 8)
			f123F128SeedReputationRows(t, ctx, db)
			before := f123F128ReadReputationRows(t, ctx, db)

			up := f123F128Apply(t, ctx, db, 9, MigrationDirectionUp)
			f123F128AssertCleanMetadata(t, ctx, db, up, 1)
			f123F128AssertRiskConversion(t, ctx, db, "convert-assessment", before["convert-assessment"], true)
			f123F128AssertRiskConversion(t, ctx, db, "convert-absent", before["convert-absent"], false)
			f123F128AssertRiskConversion(t, ctx, db, "convert-null", before["convert-null"], false)
			afterUp := f123F128ReadReputationRows(t, ctx, db)
			f123F128AssertReputationExclusionsUnchanged(t, ctx, db, before)
			f123F128AssertReputationConstraint(t, ctx, db)
			f123F128AssertIndex(t, ctx, db, "idx_reputation_due", "package_reputation_cache", false, "source,ecosystem,name,next_check_at", "status=anyarray['pending','error','malicious','removed','risk','clean','not_found']")

			f123F128Exec(t, ctx, db, `
				INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,severity,summary,description,evidence,updated_at) VALUES
				('npm','unmarked-risk','1','reversinglabs','risk','LOW','later risk','later description','{"keep":"unmarked"}','2026-03-01Z'),
				('npm','invalid-marker','1','reversinglabs','risk','LOW','invalid marker','unchanged','{"packmon_migration_009":{"previous_status":"bogus"},"keep":"invalid"}','2026-03-02Z'),
				('npm','changed-current-status','1','reversinglabs','risk','LOW','changed status','unchanged','{"packmon_migration_009":{"previous_status":"malicious","previous_severity":"MEDIUM","previous_summary":"old","previous_description":"old","previous_assessment":"old"},"assessment":"risk"}','2026-03-03Z')`)
			f123F128Exec(t, ctx, db, `UPDATE package_reputation_cache SET status = 'clean' WHERE name = 'changed-current-status'`)
			controls := f123F128Snapshot(t, ctx, db, `SELECT name,status,severity,summary,description,evidence,updated_at FROM package_reputation_cache WHERE name IN ('unmarked-risk','invalid-marker','changed-current-status') ORDER BY name`)
			f123F128AssertDatabaseClockAfter(t, ctx, db, afterUp["convert-assessment"].updatedAt)
			f123F128AssertDatabaseClockAfter(t, ctx, db, afterUp["convert-absent"].updatedAt)
			f123F128AssertDatabaseClockAfter(t, ctx, db, afterUp["convert-null"].updatedAt)

			down := f123F128Apply(t, ctx, db, 9, MigrationDirectionDown)
			f123F128AssertCleanMetadata(t, ctx, db, down, 2)
			f123F128AssertReputationRestored(t, ctx, db, "convert-assessment", before["convert-assessment"], afterUp["convert-assessment"], true)
			f123F128AssertReputationRestored(t, ctx, db, "convert-absent", before["convert-absent"], afterUp["convert-absent"], false)
			f123F128AssertReputationRestored(t, ctx, db, "convert-null", before["convert-null"], afterUp["convert-null"], false)
			f123F128AssertReputationExclusionsUnchanged(t, ctx, db, before)
			if got := f123F128Snapshot(t, ctx, db, `SELECT name,status,severity,summary,description,evidence,updated_at FROM package_reputation_cache WHERE name IN ('unmarked-risk','invalid-marker','changed-current-status') ORDER BY name`); got != controls {
				t.Fatalf("009 down changed unmarked, invalid-marker, or non-risk controls\ngot:  %s\nwant: %s", got, controls)
			}
			f123F128AssertReputationConstraint(t, ctx, db)
			f123F128AssertIndex(t, ctx, db, "idx_reputation_due", "package_reputation_cache", false, "source,ecosystem,name,next_check_at", "status=anyarray['pending','error','malicious','removed','clean','not_found']")

			restored := f123F128Snapshot(t, ctx, db, `SELECT name,status,severity,summary,description,evidence,updated_at FROM package_reputation_cache ORDER BY name`)
			f123F128Apply(t, ctx, db, 9, MigrationDirectionDown)
			if got := f123F128Snapshot(t, ctx, db, `SELECT name,status,severity,summary,description,evidence,updated_at FROM package_reputation_cache ORDER BY name`); got != restored {
				t.Fatalf("repeated 009 down changed restored rows\ngot:  %s\nwant: %s", got, restored)
			}
		})

		t.Run("up_catalog_collision_is_atomic_and_recoverable", func(t *testing.T) {
			ctx := f123F128PrepareLeaf(t, db)
			f123F128ApplyThrough(t, ctx, db, 8)
			f123F128SeedReputationRows(t, ctx, db)
			before := f123F128ReadReputationRows(t, ctx, db)
			f123F128Exec(t, ctx, db, `DROP INDEX idx_reputation_due`)
			f123F128Exec(t, ctx, db, `CREATE TABLE idx_reputation_due(id integer)`)
			up := f123F128Embedded(t, 9, MigrationDirectionUp)
			started := time.Now().UTC()
			err := applyMigration(ctx, db, up)
			finished := time.Now().UTC()
			if err == nil || !strings.Contains(err.Error(), "idx_reputation_due") {
				t.Fatalf("009 up catalog collision error = %v, want idx_reputation_due failure", err)
			}
			f123F128AssertReputationRowsEqual(t, ctx, db, before)
			f123F128AssertStatusRejected(t, ctx, db, "risk")
			f123F128AssertRelationKind(t, ctx, db, "idx_reputation_due", "r")
			f123F128AssertDirtyMetadata(t, ctx, db, up, started, finished, 1)
			f123F128AssertRunRefusesDirty(t, ctx, instance.dsn, 9)

			f123F128ClearDirty(t, ctx, db, 9)
			f123F128Exec(t, ctx, db, `DROP TABLE idx_reputation_due`)
			f123F128Exec(t, ctx, db, `CREATE INDEX idx_reputation_due ON package_reputation_cache(source, ecosystem, name, next_check_at) WHERE status IN ('pending','error','malicious','removed','clean','not_found')`)
			f123F128Apply(t, ctx, db, 9, MigrationDirectionUp)
			f123F128AssertRiskConversion(t, ctx, db, "convert-assessment", before["convert-assessment"], true)
			f123F128AssertTargetEvents(t, ctx, db, up, 2, 1, 1)
		})

		t.Run("down_catalog_collision_is_atomic_and_recoverable", func(t *testing.T) {
			ctx := f123F128PrepareLeaf(t, db)
			f123F128ApplyThrough(t, ctx, db, 8)
			f123F128SeedReputationRows(t, ctx, db)
			before := f123F128ReadReputationRows(t, ctx, db)
			f123F128Apply(t, ctx, db, 9, MigrationDirectionUp)
			afterUp := f123F128ReadReputationRows(t, ctx, db)
			converted := f123F128Snapshot(t, ctx, db, `SELECT name,status,severity,summary,description,evidence,updated_at FROM package_reputation_cache ORDER BY name`)
			f123F128Exec(t, ctx, db, `DROP INDEX idx_reputation_due`)
			f123F128Exec(t, ctx, db, `CREATE TABLE idx_reputation_due(id integer)`)
			down := f123F128Embedded(t, 9, MigrationDirectionDown)
			started := time.Now().UTC()
			err := applyMigration(ctx, db, down)
			finished := time.Now().UTC()
			if err == nil || !strings.Contains(err.Error(), "idx_reputation_due") {
				t.Fatalf("009 down catalog collision error = %v, want idx_reputation_due failure", err)
			}
			if got := f123F128Snapshot(t, ctx, db, `SELECT name,status,severity,summary,description,evidence,updated_at FROM package_reputation_cache ORDER BY name`); got != converted {
				t.Fatalf("failed transactional 009 down changed rows\ngot:  %s\nwant: %s", got, converted)
			}
			f123F128AssertRelationKind(t, ctx, db, "idx_reputation_due", "r")
			f123F128AssertDirtyMetadata(t, ctx, db, down, started, finished, 2)
			f123F128AssertRunRefusesDirty(t, ctx, instance.dsn, 9)

			f123F128ClearDirty(t, ctx, db, 9)
			f123F128Exec(t, ctx, db, `DROP TABLE idx_reputation_due`)
			f123F128Exec(t, ctx, db, `CREATE INDEX idx_reputation_due ON package_reputation_cache(source, ecosystem, name, next_check_at) WHERE status IN ('pending','error','malicious','removed','risk','clean','not_found')`)
			f123F128AssertDatabaseClockAfter(t, ctx, db, afterUp["convert-assessment"].updatedAt)
			f123F128Apply(t, ctx, db, 9, MigrationDirectionDown)
			f123F128AssertReputationRestored(t, ctx, db, "convert-assessment", before["convert-assessment"], afterUp["convert-assessment"], true)
			f123F128AssertTargetEvents(t, ctx, db, down, 3, 1, 1)
		})
	})

	t.Run("migration_010_affected_packages_updated_at", func(t *testing.T) {
		t.Run("populated_round_trip_catalog_delta_and_retries", func(t *testing.T) {
			ctx := f123F128PrepareLeaf(t, db)
			f123F128AssertStatementCounts(t, 10, 2, 2)
			f123F128ApplyThrough(t, ctx, db, 9)
			f123F128SeedAffectedPackages(t, ctx, db)
			before := f123F128Snapshot(t, ctx, db, `SELECT id,vulnerability_id,ecosystem,name,version_ranges,versions_affected FROM affected_packages ORDER BY id`)
			lowerBound := f123F128DatabaseClock(t, ctx, db)
			up := f123F128Apply(t, ctx, db, 10, MigrationDirectionUp)
			upperBound := f123F128DatabaseClock(t, ctx, db)
			f123F128AssertCleanMetadata(t, ctx, db, up, 1)
			f123F128AssertAffectedTimestampContract(t, ctx, db, lowerBound, upperBound)
			f123F128AssertColumn(t, ctx, db, "affected_packages", "updated_at", "timestamp with time zone", "NO", "now()")
			f123F128AssertIndex(t, ctx, db, "idx_affected_packages_updated_at", "affected_packages", false, "updated_at", "")
			var deltaCount int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM affected_packages WHERE updated_at >= $1`, lowerBound.Add(-time.Second)).Scan(&deltaCount); err != nil {
				t.Fatalf("count migration-010 delta rows: %v", err)
			}
			if deltaCount != 2 {
				t.Fatalf("migration-010 delta row count = %d, want 2", deltaCount)
			}
			_, err := db.ExecContext(ctx, `UPDATE affected_packages SET updated_at = NULL WHERE id = 9101`)
			f123F128ExpectSQLState(t, err, "23502")

			down := f123F128Apply(t, ctx, db, 10, MigrationDirectionDown)
			f123F128AssertCleanMetadata(t, ctx, db, down, 2)
			f123F128AssertColumnAbsent(t, ctx, db, "affected_packages", "updated_at")
			f123F128AssertRelationAbsent(t, ctx, db, "idx_affected_packages_updated_at")
			if got := f123F128Snapshot(t, ctx, db, `SELECT id,vulnerability_id,ecosystem,name,version_ranges,versions_affected FROM affected_packages ORDER BY id`); got != before {
				t.Fatalf("010 down changed surviving affected-package fields\ngot:  %s\nwant: %s", got, before)
			}

			f123F128Apply(t, ctx, db, 10, MigrationDirectionDown)
			f123F128AssertColumnAbsent(t, ctx, db, "affected_packages", "updated_at")
			f123F128Apply(t, ctx, db, 10, MigrationDirectionUp)
			f123F128AssertNullCount(t, ctx, db, "affected_packages", "updated_at", 0)
			f123F128Exec(t, ctx, db, `DROP INDEX CONCURRENTLY idx_affected_packages_updated_at`)
			f123F128Apply(t, ctx, db, 10, MigrationDirectionDown)
			f123F128AssertColumnAbsent(t, ctx, db, "affected_packages", "updated_at")
			f123F128AssertRelationAbsent(t, ctx, db, "idx_affected_packages_updated_at")
		})

		t.Run("up_second_statement_failure_requires_manual_inverse", func(t *testing.T) {
			ctx := f123F128PrepareLeaf(t, db)
			f123F128ApplyThrough(t, ctx, db, 9)
			f123F128SeedAffectedPackages(t, ctx, db)
			f123F128Exec(t, ctx, db, `CREATE TABLE idx_affected_packages_updated_at(id integer)`)
			up := f123F128Embedded(t, 10, MigrationDirectionUp)
			if migrationRunsInTransaction(up) {
				t.Fatal("010 up classified transactional, want no-transaction")
			}
			started := time.Now().UTC()
			err := applyMigration(ctx, db, up)
			finished := time.Now().UTC()
			if err == nil || !strings.Contains(err.Error(), "idx_affected_packages_updated_at") {
				t.Fatalf("010 up partial failure error = %v, want index-name collision", err)
			}
			f123F128AssertColumn(t, ctx, db, "affected_packages", "updated_at", "timestamp with time zone", "NO", "now()")
			f123F128AssertRelationKind(t, ctx, db, "idx_affected_packages_updated_at", "r")
			f123F128AssertDirtyMetadata(t, ctx, db, up, started, finished, 1)
			f123F128AssertRunRefusesDirty(t, ctx, instance.dsn, 10)
			f123F128AssertColumn(t, ctx, db, "affected_packages", "updated_at", "timestamp with time zone", "NO", "now()")

			f123F128ClearDirty(t, ctx, db, 10)
			f123F128Exec(t, ctx, db, `DROP TABLE idx_affected_packages_updated_at`)
			f123F128Exec(t, ctx, db, `ALTER TABLE affected_packages DROP COLUMN updated_at`)
			f123F128AssertColumnAbsent(t, ctx, db, "affected_packages", "updated_at")
			f123F128Apply(t, ctx, db, 10, MigrationDirectionUp)
			f123F128AssertColumn(t, ctx, db, "affected_packages", "updated_at", "timestamp with time zone", "NO", "now()")
			f123F128AssertIndex(t, ctx, db, "idx_affected_packages_updated_at", "affected_packages", false, "updated_at", "")
			f123F128AssertTargetEvents(t, ctx, db, up, 2, 1, 1)
		})

		t.Run("down_second_statement_failure_requires_manual_inverse", func(t *testing.T) {
			ctx := f123F128PrepareLeaf(t, db)
			f123F128ApplyThrough(t, ctx, db, 10)
			f123F128SeedAffectedPackages(t, ctx, db)
			f123F128Exec(t, ctx, db, `CREATE VIEW f123_f128_affected_updated_view AS SELECT id, updated_at FROM affected_packages`)
			down := f123F128Embedded(t, 10, MigrationDirectionDown)
			if migrationRunsInTransaction(down) {
				t.Fatal("010 down classified transactional, want no-transaction")
			}
			started := time.Now().UTC()
			err := applyMigration(ctx, db, down)
			finished := time.Now().UTC()
			if err == nil || !strings.Contains(err.Error(), "other objects depend") {
				t.Fatalf("010 down partial failure error = %v, want dependent-view failure", err)
			}
			f123F128AssertRelationAbsent(t, ctx, db, "idx_affected_packages_updated_at")
			f123F128AssertColumn(t, ctx, db, "affected_packages", "updated_at", "timestamp with time zone", "NO", "now()")
			f123F128AssertDirtyMetadata(t, ctx, db, down, started, finished, 2)
			f123F128AssertRunRefusesDirty(t, ctx, instance.dsn, 10)

			f123F128ClearDirty(t, ctx, db, 10)
			f123F128Exec(t, ctx, db, `CREATE INDEX CONCURRENTLY idx_affected_packages_updated_at ON affected_packages(updated_at)`)
			f123F128Exec(t, ctx, db, `DROP VIEW f123_f128_affected_updated_view`)
			f123F128AssertIndex(t, ctx, db, "idx_affected_packages_updated_at", "affected_packages", false, "updated_at", "")
			f123F128Apply(t, ctx, db, 10, MigrationDirectionDown)
			f123F128AssertColumnAbsent(t, ctx, db, "affected_packages", "updated_at")
			f123F128AssertRelationAbsent(t, ctx, db, "idx_affected_packages_updated_at")
			f123F128AssertTargetEvents(t, ctx, db, down, 3, 1, 1)
		})
	})
}

func f123F128PrepareLeaf(t *testing.T, db *sql.DB) context.Context {
	t.Helper()
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, err := db.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public AUTHORIZATION packmon`); err != nil {
			t.Errorf("bounded migration leaf cleanup: %v", err)
		}
	})
	resetCtx, resetCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer resetCancel()
	if _, err := db.ExecContext(resetCtx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public AUTHORIZATION packmon`); err != nil {
		t.Fatalf("reset public schema before migration leaf: %v", err)
	}
	for _, relation := range []string{"schema_migrations", "schema_migration_events"} {
		f123F128AssertRelationAbsent(t, resetCtx, db, relation)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func f123F128ApplyThrough(t *testing.T, ctx context.Context, db *sql.DB, target int) {
	t.Helper()
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensure migration metadata tables: %v", err)
	}
	for version := 1; version <= target; version++ {
		f123F128Apply(t, ctx, db, version, MigrationDirectionUp)
	}
}

func f123F128Embedded(t *testing.T, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	embedded, err := ReadEmbeddedMigration(version, direction)
	if err != nil {
		t.Fatalf("read embedded migration %03d %s: %v", version, direction, err)
	}
	return migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
}

func f123F128Apply(t *testing.T, ctx context.Context, db *sql.DB, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	migration := f123F128Embedded(t, version, direction)
	if err := applyMigration(ctx, db, migration); err != nil {
		t.Fatalf("apply embedded migration %s: %v", migration.name, err)
	}
	return migration
}

func f123F128AssertStatementCounts(t *testing.T, version, upCount, downCount int) {
	t.Helper()
	for _, tc := range []struct {
		direction MigrationDirection
		want      int
	}{{MigrationDirectionUp, upCount}, {MigrationDirectionDown, downCount}} {
		migration := f123F128Embedded(t, version, tc.direction)
		statements, err := splitSQLStatements(migration.sql)
		if err != nil {
			t.Fatalf("split %s: %v", migration.name, err)
		}
		if len(statements) != tc.want {
			t.Fatalf("%s statement count = %d, want %d", migration.name, len(statements), tc.want)
		}
	}
}

func f123F128Exec(t *testing.T, ctx context.Context, db *sql.DB, statement string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(ctx, statement, args...); err != nil {
		t.Fatalf("execute migration fixture SQL: %v\nSQL:\n%s", err, statement)
	}
}

func f123F128SeedMaliciousFindings(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	f123F128Exec(t, ctx, db, `
		INSERT INTO malicious_findings(id,ecosystem,name,versions,source,risk_type,severity,summary,description,reference_urls,origin_ref,published,created_at,updated_at,created_by) VALUES
		('MAL-ACTIVE','npm','active-package','["1.0.0"]','fixture','malware','CRITICAL','active summary','active description','["https://active.test"]','active-origin','2025-01-01Z','2025-01-02Z','2025-01-03Z','fixture-writer'),
		('MAL-REMOVED','pypi','removed-package','["2.0.0"]','fixture','supply_chain','HIGH','removed summary','removed description','["https://removed.test"]','removed-origin','2025-02-01Z','2025-02-02Z','2025-02-03Z','fixture-writer')`)
}

func f123F128SeedReputationRows(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	f123F128Exec(t, ctx, db, `
		INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,severity,summary,description,evidence,updated_at) VALUES
		('npm','convert-assessment','1','reversinglabs','malicious','MEDIUM','old summary','old description','{"signals":["incidents.type.malware"],"assessment":"old-assessment","keep":{"nested":1}}','2020-01-01Z'),
		('npm','convert-absent','1','reversinglabs','malicious','LOW','absent summary','absent description','{"signals":["incidents.type.malware"],"keep":"absent"}','2020-01-02Z'),
		('npm','convert-null','1','reversinglabs','malicious','UNKNOWN','null summary','null description','{"signals":["incidents.type.malware"],"assessment":null,"keep":"null"}','2020-01-03Z'),
		('npm','excluded-all','1','reversinglabs','malicious','CRITICAL','excluded all','unchanged','{"signals":["incidents.type.malware","package.all_malicious"]}','2020-02-01Z'),
		('npm','excluded-assessment','1','reversinglabs','malicious','CRITICAL','excluded assessment','unchanged','{"signals":["incidents.type.malware","assessments.malware.status"]}','2020-02-02Z'),
		('npm','excluded-classification','1','reversinglabs','malicious','CRITICAL','excluded classification','unchanged','{"signals":["incidents.type.malware","classifications.status"]}','2020-02-03Z'),
		('npm','excluded-dependency','1','reversinglabs','malicious','CRITICAL','excluded dependency','unchanged','{"signals":["incidents.type.malware","dependencies.classification.status"]}','2020-02-04Z'),
		('npm','other-source','1','socket','malicious','HIGH','other source','unchanged','{"signals":["incidents.type.malware"]}','2020-02-05Z'),
		('npm','other-status','1','reversinglabs','clean','LOW','other status','unchanged','{"signals":["incidents.type.malware"]}','2020-02-06Z'),
		('npm','missing-signals','1','reversinglabs','malicious','HIGH','missing signals','unchanged','{"keep":"missing"}','2020-02-07Z'),
		('npm','non-array-signals','1','reversinglabs','malicious','HIGH','non-array signals','unchanged','{"signals":"incidents.type.malware"}','2020-02-08Z')`)
}

func f123F128ReadReputationRows(t *testing.T, ctx context.Context, db *sql.DB) map[string]f123F128ReputationRow {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT name,status,severity,summary,description,evidence::text,updated_at FROM package_reputation_cache ORDER BY name`)
	if err != nil {
		t.Fatalf("read reputation rows: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	result := make(map[string]f123F128ReputationRow)
	for rows.Next() {
		var name string
		var row f123F128ReputationRow
		if err := rows.Scan(&name, &row.status, &row.severity, &row.summary, &row.description, &row.evidence, &row.updatedAt); err != nil {
			t.Fatalf("scan reputation row: %v", err)
		}
		row.updatedAt = row.updatedAt.UTC()
		result[name] = row
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate reputation rows: %v", err)
	}
	return result
}

func f123F128AssertReputationRowsEqual(t *testing.T, ctx context.Context, db *sql.DB, want map[string]f123F128ReputationRow) {
	t.Helper()
	got := f123F128ReadReputationRows(t, ctx, db)
	if fmt.Sprintf("%#v", got) != fmt.Sprintf("%#v", want) {
		t.Fatalf("reputation rows changed\ngot:  %#v\nwant: %#v", got, want)
	}
}

func f123F128AssertRiskConversion(t *testing.T, ctx context.Context, db *sql.DB, name string, before f123F128ReputationRow, hadAssessment bool) {
	t.Helper()
	wantMarker := map[string]string{
		"convert-assessment": `{"previous_status":"malicious","previous_severity":"MEDIUM","previous_summary":"old summary","previous_description":"old description","previous_assessment":"old-assessment"}`,
		"convert-absent":     `{"previous_status":"malicious","previous_severity":"LOW","previous_summary":"absent summary","previous_description":"absent description","previous_assessment":null}`,
		"convert-null":       `{"previous_status":"malicious","previous_severity":"UNKNOWN","previous_summary":"null summary","previous_description":"null description","previous_assessment":null}`,
	}[name]
	wantEvidence := map[string]string{
		"convert-assessment": `{"signals":["incidents.type.malware"],"assessment":"risk","keep":{"nested":1},"packmon_migration_009":{"previous_status":"malicious","previous_severity":"MEDIUM","previous_summary":"old summary","previous_description":"old description","previous_assessment":"old-assessment"}}`,
		"convert-absent":     `{"signals":["incidents.type.malware"],"assessment":"risk","keep":"absent","packmon_migration_009":{"previous_status":"malicious","previous_severity":"LOW","previous_summary":"absent summary","previous_description":"absent description","previous_assessment":null}}`,
		"convert-null":       `{"signals":["incidents.type.malware"],"assessment":"risk","keep":"null","packmon_migration_009":{"previous_status":"malicious","previous_severity":"UNKNOWN","previous_summary":"null summary","previous_description":"null description","previous_assessment":null}}`,
	}[name]
	var status, severity, summary, description string
	var assessment, markerStatus, markerSeverity, markerSummary, markerDescription string
	var markerAssessment sql.NullString
	var markerPresent, keepPresent, markerAssessmentPresent, exactMarker, exactEvidence bool
	var markerAssessmentType string
	var updatedAt time.Time
	err := db.QueryRowContext(ctx, `
		SELECT status,severity,summary,description,evidence->>'assessment',
		       evidence ? 'packmon_migration_009', evidence ? 'keep',
		       evidence->'packmon_migration_009'->>'previous_status',
		       evidence->'packmon_migration_009'->>'previous_severity',
		       evidence->'packmon_migration_009'->>'previous_summary',
		       evidence->'packmon_migration_009'->>'previous_description',
		       evidence->'packmon_migration_009'->>'previous_assessment',
		       evidence->'packmon_migration_009' ? 'previous_assessment',
		       COALESCE(jsonb_typeof(evidence->'packmon_migration_009'->'previous_assessment'),'missing'),
		       evidence->'packmon_migration_009'=$2::jsonb, evidence=$3::jsonb, updated_at
		FROM package_reputation_cache WHERE name=$1`, name, wantMarker, wantEvidence).Scan(
		&status, &severity, &summary, &description, &assessment, &markerPresent, &keepPresent,
		&markerStatus, &markerSeverity, &markerSummary, &markerDescription, &markerAssessment,
		&markerAssessmentPresent, &markerAssessmentType, &exactMarker, &exactEvidence, &updatedAt,
	)
	if err != nil {
		t.Fatalf("read converted reputation row %s: %v", name, err)
	}
	if status != "risk" || severity != "HIGH" || summary != "ReversingLabs: malware incident history" || description != before.description || assessment != "risk" || !markerPresent || !keepPresent {
		t.Fatalf("converted row %s = status:%q severity:%q summary:%q description:%q assessment:%q marker:%t keep:%t", name, status, severity, summary, description, assessment, markerPresent, keepPresent)
	}
	if markerStatus != before.status || markerSeverity != before.severity || markerSummary != before.summary || markerDescription != before.description {
		t.Fatalf("converted row %s marker = (%q,%q,%q,%q), want (%q,%q,%q,%q)", name, markerStatus, markerSeverity, markerSummary, markerDescription, before.status, before.severity, before.summary, before.description)
	}
	if !markerAssessmentPresent || !exactMarker || !exactEvidence {
		t.Fatalf("converted row %s marker/evidence = previous-assessment-present:%t exact-marker:%t exact-evidence:%t, want all true", name, markerAssessmentPresent, exactMarker, exactEvidence)
	}
	if hadAssessment {
		if !markerAssessment.Valid || markerAssessment.String != "old-assessment" || markerAssessmentType != "string" {
			t.Fatalf("converted row %s previous assessment = value:%#v type:%q, want string old-assessment", name, markerAssessment, markerAssessmentType)
		}
	} else if markerAssessment.Valid || markerAssessmentType != "null" {
		t.Fatalf("converted row %s previous assessment = value:%#v type:%q, want explicit JSON null", name, markerAssessment, markerAssessmentType)
	}
	if !updatedAt.After(before.updatedAt) {
		t.Fatalf("converted row %s updated_at = %v, want after %v", name, updatedAt, before.updatedAt)
	}
}

func f123F128AssertReputationRestored(t *testing.T, ctx context.Context, db *sql.DB, name string, before, afterUp f123F128ReputationRow, wantAssessment bool) {
	t.Helper()
	var status, severity, summary, description string
	var evidence string
	var markerPresent, assessmentPresent bool
	var assessment sql.NullString
	var updatedAt time.Time
	if err := db.QueryRowContext(ctx, `
		SELECT status,severity,summary,description,evidence::text,
		       evidence ? 'packmon_migration_009', evidence ? 'assessment', evidence->>'assessment', updated_at
		FROM package_reputation_cache WHERE name=$1`, name).Scan(
		&status, &severity, &summary, &description, &evidence, &markerPresent, &assessmentPresent, &assessment, &updatedAt,
	); err != nil {
		t.Fatalf("read restored reputation row %s: %v", name, err)
	}
	if status != before.status || severity != before.severity || summary != before.summary || description != before.description || markerPresent {
		t.Fatalf("restored row %s = status:%q severity:%q summary:%q description:%q marker:%t", name, status, severity, summary, description, markerPresent)
	}
	if wantAssessment {
		if !assessmentPresent || !assessment.Valid || assessment.String != "old-assessment" {
			t.Fatalf("restored row %s assessment = present:%t value:%#v, want old-assessment", name, assessmentPresent, assessment)
		}
	} else if assessmentPresent || assessment.Valid {
		t.Fatalf("restored row %s assessment = present:%t value:%#v, want absent", name, assessmentPresent, assessment)
	}
	if !strings.Contains(evidence, `"keep"`) {
		t.Fatalf("restored row %s lost unrelated evidence: %s", name, evidence)
	}
	wantEvidence := map[string]string{
		"convert-assessment": `{"signals":["incidents.type.malware"],"assessment":"old-assessment","keep":{"nested":1}}`,
		"convert-absent":     `{"signals":["incidents.type.malware"],"keep":"absent"}`,
		"convert-null":       `{"signals":["incidents.type.malware"],"keep":"null"}`,
	}[name]
	var exactEvidence bool
	if err := db.QueryRowContext(ctx, `SELECT evidence=$2::jsonb FROM package_reputation_cache WHERE name=$1`, name, wantEvidence).Scan(&exactEvidence); err != nil {
		t.Fatalf("compare restored evidence for %s: %v", name, err)
	}
	if !exactEvidence {
		t.Fatalf("restored row %s evidence = %s, want exact %s", name, evidence, wantEvidence)
	}
	if !updatedAt.After(afterUp.updatedAt) {
		t.Fatalf("restored row %s updated_at = %v, want strictly after post-up %v (pre-up %v)", name, updatedAt, afterUp.updatedAt, before.updatedAt)
	}
}

func f123F128AssertReputationExclusionsUnchanged(t *testing.T, ctx context.Context, db *sql.DB, before map[string]f123F128ReputationRow) {
	t.Helper()
	got := f123F128ReadReputationRows(t, ctx, db)
	for _, name := range []string{"excluded-all", "excluded-assessment", "excluded-classification", "excluded-dependency", "other-source", "other-status", "missing-signals", "non-array-signals"} {
		if fmt.Sprintf("%#v", got[name]) != fmt.Sprintf("%#v", before[name]) {
			t.Fatalf("009 changed excluded row %s\ngot:  %#v\nwant: %#v", name, got[name], before[name])
		}
	}
}

func f123F128AssertReputationConstraint(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var definition string
	var validated bool
	if err := db.QueryRowContext(ctx, `
		SELECT pg_get_constraintdef(c.oid),c.convalidated
		FROM pg_constraint c
		WHERE c.conrelid='public.package_reputation_cache'::regclass
		  AND c.conname='package_reputation_cache_status_check'`).Scan(&definition, &validated); err != nil {
		t.Fatalf("inspect package reputation status constraint: %v", err)
	}
	wantStatuses := []string{"pending", "malicious", "removed", "risk", "clean", "not_found", "unsupported", "error"}
	normalized := f123F128NormalizePredicate(definition)
	if !validated || !strings.HasPrefix(normalized, "checkstatus=anyarray[") {
		t.Fatalf("status constraint = definition:%q validated:%t, want validated CHECK over exact status array", definition, validated)
	}
	for _, status := range wantStatuses {
		if strings.Count(normalized, "'"+status+"'") != 1 {
			t.Fatalf("status constraint definition = %q, want status %q exactly once", definition, status)
		}
	}
	if strings.Count(normalized, "'::") != 0 || strings.Count(normalized, "'") != 2*len(wantStatuses) {
		t.Fatalf("status constraint definition = %q, want exactly %d accepted literals", definition, len(wantStatuses))
	}
	f123F128Exec(t, ctx, db, `DELETE FROM package_reputation_cache WHERE source='constraint-test'`)
	for i, status := range wantStatuses {
		name := fmt.Sprintf("accepted-status-%d", i)
		if _, err := db.ExecContext(ctx, `INSERT INTO package_reputation_cache(ecosystem,name,version,source,status) VALUES('npm',$1,'1','constraint-test',$2)`, name, status); err != nil {
			t.Fatalf("insert accepted reputation status %q: %v", status, err)
		}
	}
	f123F128AssertStatusRejected(t, ctx, db, "invalid")
}

func f123F128DatabaseClock(t *testing.T, ctx context.Context, db *sql.DB) time.Time {
	t.Helper()
	var value time.Time
	if err := db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&value); err != nil {
		t.Fatalf("read PostgreSQL clock: %v", err)
	}
	return value
}

func f123F128AssertDatabaseClockAfter(t *testing.T, ctx context.Context, db *sql.DB, earlier time.Time) {
	t.Helper()
	var later time.Time
	var after bool
	if err := db.QueryRowContext(ctx, `SELECT clock_timestamp(),clock_timestamp()>$1`, earlier).Scan(&later, &after); err != nil {
		t.Fatalf("compare PostgreSQL clock with %v: %v", earlier, err)
	}
	if !after {
		t.Fatalf("PostgreSQL clock barrier = %v, want strictly after %v", later, earlier)
	}
}

func f123F128AssertStatusRejected(t *testing.T, ctx context.Context, db *sql.DB, status string) {
	t.Helper()
	_, err := db.ExecContext(ctx, `INSERT INTO package_reputation_cache(ecosystem,name,version,source,status) VALUES('npm','rejected-status','1','constraint-test',$1)`, status)
	f123F128ExpectSQLState(t, err, "23514")
}

func f123F128SeedAffectedPackages(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	f123F128Exec(t, ctx, db, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES('F123-VULN','fixture vulnerability','HIGH','2025-01-01Z','2025-01-02Z')`)
	f123F128Exec(t, ctx, db, `
		INSERT INTO affected_packages(id,vulnerability_id,ecosystem,name,version_ranges,versions_affected) VALUES
		(9101,'F123-VULN','npm','fixture-one','[{"type":"SEMVER","events":[{"introduced":"0"}]}]','["1.0.0"]'),
		(9102,'F123-VULN','pypi','fixture-two','[]','["2.0.0","2.1.0"]')`)
}

func f123F128AssertAffectedTimestampContract(t *testing.T, ctx context.Context, db *sql.DB, lower, upper time.Time) {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT id,updated_at FROM affected_packages ORDER BY id`)
	if err != nil {
		t.Fatalf("read affected-package timestamps: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	count := 0
	for rows.Next() {
		var id int
		var updatedAt time.Time
		if err := rows.Scan(&id, &updatedAt); err != nil {
			t.Fatalf("scan affected-package timestamp: %v", err)
		}
		if updatedAt.Before(lower) || updatedAt.After(upper) {
			t.Fatalf("affected package %d updated_at = %v, want within [%v,%v]", id, updatedAt, lower, upper)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate affected-package timestamps: %v", err)
	}
	if count != 2 {
		t.Fatalf("affected-package timestamp row count = %d, want 2", count)
	}
}

func f123F128AssertColumn(t *testing.T, ctx context.Context, db *sql.DB, table, column, dataType, nullable, defaultValue string) {
	t.Helper()
	var gotType, gotNullable, gotDefault string
	if err := db.QueryRowContext(ctx, `SELECT data_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name=$2`, table, column).Scan(&gotType, &gotNullable, &gotDefault); err != nil {
		t.Fatalf("inspect column %s.%s: %v", table, column, err)
	}
	if gotType != dataType || gotNullable != nullable || gotDefault != defaultValue {
		t.Fatalf("column %s.%s = type:%q nullable:%q default:%q, want type:%q nullable:%q default:%q", table, column, gotType, gotNullable, gotDefault, dataType, nullable, defaultValue)
	}
}

func f123F128AssertColumnAbsent(t *testing.T, ctx context.Context, db *sql.DB, table, column string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name=$2`, table, column).Scan(&count); err != nil {
		t.Fatalf("inspect absent column %s.%s: %v", table, column, err)
	}
	if count != 0 {
		t.Fatalf("column %s.%s count = %d, want 0", table, column, count)
	}
}

func f123F128AssertIndex(t *testing.T, ctx context.Context, db *sql.DB, name, table string, unique bool, keys, predicate string) {
	t.Helper()
	var gotTable, gotKeys, gotPredicate string
	var gotUnique, valid, ready bool
	if err := db.QueryRowContext(ctx, `
		SELECT tbl.relname,i.indisunique,
		       (SELECT string_agg(pg_get_indexdef(i.indexrelid,n,true),',' ORDER BY n) FROM generate_series(1,i.indnkeyatts) n),
		       COALESCE(pg_get_expr(i.indpred,i.indrelid),''),i.indisvalid,i.indisready
		FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid JOIN pg_class tbl ON tbl.oid=i.indrelid
		WHERE idx.oid=to_regclass('public.' || $1)`, name).Scan(&gotTable, &gotUnique, &gotKeys, &gotPredicate, &valid, &ready); err != nil {
		t.Fatalf("inspect index %s: %v", name, err)
	}
	if gotTable != table || gotUnique != unique || gotKeys != keys || f123F128NormalizePredicate(gotPredicate) != predicate || !valid || !ready {
		t.Fatalf("index %s = table:%q unique:%t keys:%q predicate:%q valid:%t ready:%t, want table:%q unique:%t keys:%q predicate:%q", name, gotTable, gotUnique, gotKeys, gotPredicate, valid, ready, table, unique, keys, predicate)
	}
}

func f123F128NormalizePredicate(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "::text", "")
	return strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", "(", "", ")", "").Replace(value)
}

func f123F128AssertNullCount(t *testing.T, ctx context.Context, db *sql.DB, table, column string, want int) {
	t.Helper()
	var got int
	query := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE %s IS NULL`, table, column)
	if err := db.QueryRowContext(ctx, query).Scan(&got); err != nil {
		t.Fatalf("count NULL %s.%s: %v", table, column, err)
	}
	if got != want {
		t.Fatalf("NULL count for %s.%s = %d, want %d", table, column, got, want)
	}
}

func f123F128AssertRelationAbsent(t *testing.T, ctx context.Context, db *sql.DB, relation string) {
	t.Helper()
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, relation).Scan(&exists); err != nil {
		t.Fatalf("inspect relation %s: %v", relation, err)
	}
	if exists {
		t.Fatalf("relation %s exists, want absent", relation)
	}
}

func f123F128AssertRelationKind(t *testing.T, ctx context.Context, db *sql.DB, relation, wantKind string) {
	t.Helper()
	var kind string
	if err := db.QueryRowContext(ctx, `SELECT relkind::text FROM pg_class WHERE oid=to_regclass('public.' || $1)`, relation).Scan(&kind); err != nil {
		t.Fatalf("inspect relation kind %s: %v", relation, err)
	}
	if kind != wantKind {
		t.Fatalf("relation %s kind = %q, want %q", relation, kind, wantKind)
	}
}

func f123F128Snapshot(t *testing.T, ctx context.Context, db *sql.DB, query string) string {
	t.Helper()
	var snapshot string
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(row_data)),'[]'::jsonb)::text FROM (`+query+`) row_data`).Scan(&snapshot); err != nil {
		t.Fatalf("snapshot query: %v\nSQL:\n%s", err, query)
	}
	return snapshot
}

func f123F128AssertCleanMetadata(t *testing.T, ctx context.Context, db *sql.DB, migration migrationFile, eventCount int) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt time.Time
	if err := db.QueryRowContext(ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read clean metadata for %s: %v", migration.name, err)
	}
	wantChecksum := migrationChecksum(migration.sql)
	if name != migration.name || checksum != wantChecksum || dirty || appliedAt.IsZero() {
		t.Fatalf("clean metadata for %s = name:%q checksum:%q dirty:%t applied:%v", migration.name, name, checksum, dirty, appliedAt)
	}
	var count, success, dirtyEvents, unfinished int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*),COUNT(*) FILTER(WHERE success),COUNT(*) FILTER(WHERE dirty),COUNT(*) FILTER(WHERE finished_at IS NULL) FROM schema_migration_events WHERE version=$1`, migration.version).Scan(&count, &success, &dirtyEvents, &unfinished); err != nil {
		t.Fatalf("count clean events for %s: %v", migration.name, err)
	}
	if count != eventCount || success != eventCount || dirtyEvents != 0 || unfinished != 0 {
		t.Fatalf("events for %s = count:%d success:%d dirty:%d unfinished:%d, want %d all clean", migration.name, count, success, dirtyEvents, unfinished, eventCount)
	}
	var latestName, latestChecksum string
	if err := db.QueryRowContext(ctx, `SELECT name,checksum FROM schema_migration_events WHERE version=$1 ORDER BY id DESC LIMIT 1`, migration.version).Scan(&latestName, &latestChecksum); err != nil {
		t.Fatalf("inspect latest event identity for %s: %v", migration.name, err)
	}
	if latestName != migration.name || latestChecksum != wantChecksum {
		t.Fatalf("latest event identity for %s = name:%q checksum:%q, want exact migration identity", migration.name, latestName, latestChecksum)
	}
}

func f123F128AssertDirtyMetadata(t *testing.T, ctx context.Context, db *sql.DB, migration migrationFile, lower, upper time.Time, eventCount int) {
	t.Helper()
	wantChecksum := migrationChecksum(migration.sql)
	var name, checksum string
	var dirty bool
	var appliedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read dirty metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != wantChecksum || !dirty || appliedAt.Valid {
		t.Fatalf("dirty metadata for %s = name:%q checksum:%q dirty:%t applied:%v", migration.name, name, checksum, dirty, appliedAt)
	}
	var eventName, eventChecksum string
	var startedAt, finishedAt time.Time
	var success, eventDirty bool
	if err := db.QueryRowContext(ctx, `SELECT name,checksum,started_at,finished_at,success,dirty FROM schema_migration_events WHERE version=$1 ORDER BY id DESC LIMIT 1`, migration.version).Scan(&eventName, &eventChecksum, &startedAt, &finishedAt, &success, &eventDirty); err != nil {
		t.Fatalf("read dirty event for %s: %v", migration.name, err)
	}
	if eventName != migration.name || eventChecksum != wantChecksum || success || !eventDirty || startedAt.Before(lower.Add(-time.Second)) || finishedAt.After(upper.Add(time.Second)) || finishedAt.Before(startedAt) {
		t.Fatalf("dirty event for %s = name:%q checksum:%q started:%v finished:%v success:%t dirty:%t; operation [%v,%v]", migration.name, eventName, eventChecksum, startedAt, finishedAt, success, eventDirty, lower, upper)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migration_events WHERE version=$1`, migration.version).Scan(&count); err != nil {
		t.Fatalf("count dirty events for %s: %v", migration.name, err)
	}
	if count != eventCount {
		t.Fatalf("event count for %s after failure = %d, want %d", migration.name, count, eventCount)
	}
}

func f123F128AssertTargetEvents(t *testing.T, ctx context.Context, db *sql.DB, migration migrationFile, total, failed, succeeded int) {
	t.Helper()
	wantChecksum := migrationChecksum(migration.sql)
	var gotTotal, gotFailed, gotSucceeded, unfinished int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COUNT(*) FILTER(WHERE name=$2 AND checksum=$3 AND NOT success AND dirty),
		       COUNT(*) FILTER(WHERE name=$2 AND checksum=$3 AND success AND NOT dirty),
		       COUNT(*) FILTER(WHERE finished_at IS NULL)
		FROM schema_migration_events WHERE version=$1`, migration.version, migration.name, wantChecksum).Scan(&gotTotal, &gotFailed, &gotSucceeded, &unfinished); err != nil {
		t.Fatalf("read target events for %s: %v", migration.name, err)
	}
	if gotTotal != total || gotFailed != failed || gotSucceeded != succeeded || unfinished != 0 {
		t.Fatalf("events for %s = total:%d target-failed:%d target-succeeded:%d unfinished:%d, want %d/%d/%d/0", migration.name, gotTotal, gotFailed, gotSucceeded, unfinished, total, failed, succeeded)
	}
}

func f123F128AssertRunRefusesDirty(t *testing.T, ctx context.Context, dsn string, version int) {
	t.Helper()
	err := RunContext(ctx, dsn)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("dirty at version %d", version)) {
		t.Fatalf("RunContext() on dirty version %d error = %v, want dirty refusal", version, err)
	}
}

func f123F128ClearDirty(t *testing.T, ctx context.Context, db *sql.DB, version int) {
	t.Helper()
	result, err := db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version=$1 AND dirty`, version)
	if err != nil {
		t.Fatalf("clear dirty marker for version %d: %v", version, err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		t.Fatalf("clear dirty marker for version %d affected=%d err=%v, want 1", version, affected, err)
	}
}

func f123F128ExpectSQLState(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("PostgreSQL error = nil, want SQLSTATE %s", want)
	}
	var state interface{ SQLState() string }
	if !errors.As(err, &state) || state.SQLState() != want {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, want)
	}
}
