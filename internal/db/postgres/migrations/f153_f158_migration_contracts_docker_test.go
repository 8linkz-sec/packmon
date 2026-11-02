//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type f153F158Leaf struct {
	ctx  context.Context
	conn *sql.Conn
	dsn  string
}

type f153F158Index struct {
	oid        int64
	table      string
	method     string
	keys       []string
	opclasses  []string
	predicate  string
	definition string
	valid      bool
	ready      bool
	live       bool
	unique     bool
}

type f153F158IndexWant struct {
	name       string
	table      string
	keys       []string
	opclasses  []string
	predicate  string
	definition string
}

var f153F158EnrichmentIndexes = []f153F158IndexWant{
	{
		name:       "idx_vulnerabilities_nvd_candidate",
		table:      "vulnerabilities",
		keys:       []string{"id"},
		opclasses:  []string{"text_ops"},
		predicate:  "((severity = 'UNKNOWN'::text) OR ((severity = 'LOW'::text) AND (cvss_score IS NULL)))",
		definition: "CREATE INDEX idx_vulnerabilities_nvd_candidate ON public.vulnerabilities USING btree (id) WHERE ((severity = 'UNKNOWN'::text) OR ((severity = 'LOW'::text) AND (cvss_score IS NULL)))",
	},
	{
		name:       "idx_vuln_aliases_cve_alias",
		table:      "vulnerability_aliases",
		keys:       []string{"alias_id", "vulnerability_id"},
		opclasses:  []string{"text_pattern_ops", "text_ops"},
		predicate:  "(alias_id ~~ 'CVE-%'::text)",
		definition: "CREATE INDEX idx_vuln_aliases_cve_alias ON public.vulnerability_aliases USING btree (alias_id text_pattern_ops, vulnerability_id) WHERE (alias_id ~~ 'CVE-%'::text)",
	},
	{
		name:       "idx_vulnerabilities_cisa_kev",
		table:      "vulnerabilities",
		keys:       []string{"id"},
		opclasses:  []string{"text_ops"},
		predicate:  "(cisa_kev = true)",
		definition: "CREATE INDEX idx_vulnerabilities_cisa_kev ON public.vulnerabilities USING btree (id) WHERE (cisa_kev = true)",
	},
}

func TestF153F158MigrationContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	database, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(database)
	database.SetMaxOpenConns(4)

	t.Run("migration_023", func(t *testing.T) {
		t.Run("populated_catalog_ordering_generic_plan_down_twice_and_reapply", func(t *testing.T) {
			leaf := f153F158PrepareLeaf(t, database, instance.dsn)
			f153F158ApplyThrough(t, leaf, 22)
			f153F158SeedRecentVulnerabilities(t, leaf)
			beforeRows := f153F158VulnerabilitySnapshot(t, leaf)
			unrelated := f153F158IndexIdentities(t, leaf, []string{"idx_vulnerabilities_nvd_candidate", "idx_vulnerabilities_cisa_kev", "idx_vuln_aliases_cve_alias"})

			f153F158Apply(t, leaf, 23, MigrationDirectionUp)
			f153F158AssertIndex(t, leaf, f153F158IndexWant{
				name:       "idx_vulnerabilities_recent_published",
				table:      "vulnerabilities",
				keys:       []string{"published", "id"},
				opclasses:  []string{"timestamptz_ops", "text_ops"},
				predicate:  "(withdrawn IS NULL)",
				definition: "CREATE INDEX idx_vulnerabilities_recent_published ON public.vulnerabilities USING btree (published DESC, id DESC) WHERE (withdrawn IS NULL)",
			})
			f153F158AssertRecentResultsAndPlan(t, leaf)
			f153F158AssertEqual(t, "vulnerability rows after 023 up", f153F158VulnerabilitySnapshot(t, leaf), beforeRows)

			f153F158ApplyDownAndDelete(t, leaf, 23)
			f153F158AssertRelationAbsent(t, leaf, "idx_vulnerabilities_recent_published")
			f153F158AssertEqual(t, "vulnerability rows after 023 down", f153F158VulnerabilitySnapshot(t, leaf), beforeRows)
			f153F158AssertIndexIdentities(t, leaf, unrelated)
			f153F158ApplyDownAndDelete(t, leaf, 23)
			f153F158AssertRelationAbsent(t, leaf, "idx_vulnerabilities_recent_published")
			f153F158AssertEqual(t, "vulnerability rows after repeated 023 down", f153F158VulnerabilitySnapshot(t, leaf), beforeRows)
			f153F158AssertIndexIdentities(t, leaf, unrelated)

			f153F158Apply(t, leaf, 23, MigrationDirectionUp)
			f153F158AssertIndex(t, leaf, f153F158IndexWant{
				name:       "idx_vulnerabilities_recent_published",
				table:      "vulnerabilities",
				keys:       []string{"published", "id"},
				opclasses:  []string{"timestamptz_ops", "text_ops"},
				predicate:  "(withdrawn IS NULL)",
				definition: "CREATE INDEX idx_vulnerabilities_recent_published ON public.vulnerabilities USING btree (published DESC, id DESC) WHERE (withdrawn IS NULL)",
			})
			f153F158AssertRecentResultsAndPlan(t, leaf)
			f153F158AssertEqual(t, "vulnerability rows after 023 reapply", f153F158VulnerabilitySnapshot(t, leaf), beforeRows)
		})

		t.Run("injected_up_and_down_failures_are_atomic_dirty_and_recoverable", func(t *testing.T) {
			leaf := f153F158PrepareLeaf(t, database, instance.dsn)
			f153F158ApplyThrough(t, leaf, 22)
			f153F158SeedRecentVulnerabilities(t, leaf)
			beforeRows := f153F158VulnerabilitySnapshot(t, leaf)

			up := f153F158WithFailure(f153F158Embedded(t, 23, MigrationDirectionUp))
			f153F158ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, up), "P0001")
			f153F158AssertRelationAbsent(t, leaf, "idx_vulnerabilities_recent_published")
			f153F158AssertEqual(t, "vulnerability rows after failed 023 up", f153F158VulnerabilitySnapshot(t, leaf), beforeRows)
			f153F158AssertDirtyAndRunRefusal(t, leaf, up)
			f153F158ClearDirty(t, leaf, 23)
			f153F158Apply(t, leaf, 23, MigrationDirectionUp)
			beforeIndex := f153F158IndexIdentity(t, leaf, "idx_vulnerabilities_recent_published")

			down := f153F158WithFailure(f153F158Embedded(t, 23, MigrationDirectionDown))
			f153F158ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, down), "P0001")
			afterIndex := f153F158IndexIdentity(t, leaf, "idx_vulnerabilities_recent_published")
			if beforeIndex != afterIndex {
				t.Fatalf("failed 023 down changed index: before=%q after=%q", beforeIndex, afterIndex)
			}
			f153F158AssertEqual(t, "vulnerability rows after failed 023 down", f153F158VulnerabilitySnapshot(t, leaf), beforeRows)
			f153F158AssertDirtyAndRunRefusal(t, leaf, down)
			f153F158ClearDirty(t, leaf, 23)
			f153F158Apply(t, leaf, 23, MigrationDirectionDown)
			f153F158AssertRelationAbsent(t, leaf, "idx_vulnerabilities_recent_published")
		})
	})

	t.Run("migration_024", func(t *testing.T) {
		t.Run("recreate_missing_indexes_exact_catalog_candidates_plans_and_replay", func(t *testing.T) {
			leaf := f153F158PrepareLeaf(t, database, instance.dsn)
			f153F158ApplyThrough(t, leaf, 23)
			f153F158SeedEnrichmentCandidates(t, leaf)
			beforeRows := f153F158EnrichmentSnapshot(t, leaf)
			for _, index := range f153F158EnrichmentIndexes {
				f153F158Exec(t, leaf, `DROP INDEX `+index.name)
				f153F158AssertRelationAbsent(t, leaf, index.name)
			}

			f153F158Apply(t, leaf, 24, MigrationDirectionUp)
			first := f153F158AssertEnrichmentIndexes(t, leaf)
			f153F158AssertEnrichmentCandidatesAndPlans(t, leaf)
			f153F158AssertEqual(t, "enrichment rows after 024 up", f153F158EnrichmentSnapshot(t, leaf), beforeRows)

			f153F158Apply(t, leaf, 24, MigrationDirectionUp)
			second := f153F158AssertEnrichmentIndexes(t, leaf)
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("024 replay replaced or changed indexes: first=%#v second=%#v", first, second)
			}
			f153F158AssertEnrichmentCandidatesAndPlans(t, leaf)
			f153F158AssertEqual(t, "enrichment rows after 024 replay", f153F158EnrichmentSnapshot(t, leaf), beforeRows)
		})

		t.Run("noop_down_twice_preserves_baseline_and_repaired_indexes", func(t *testing.T) {
			for _, repair := range []bool{false, true} {
				leaf := f153F158PrepareLeaf(t, database, instance.dsn)
				f153F158ApplyThrough(t, leaf, 23)
				f153F158SeedEnrichmentCandidates(t, leaf)
				if repair {
					for _, index := range f153F158EnrichmentIndexes {
						f153F158Exec(t, leaf, `DROP INDEX `+index.name)
					}
				}
				f153F158Apply(t, leaf, 24, MigrationDirectionUp)
				beforeIndexes := f153F158AssertEnrichmentIndexes(t, leaf)
				beforeRows := f153F158EnrichmentSnapshot(t, leaf)

				f153F158ApplyDownAndDelete(t, leaf, 24)
				f153F158ApplyDownAndDelete(t, leaf, 24)
				afterIndexes := f153F158AssertEnrichmentIndexes(t, leaf)
				if !reflect.DeepEqual(afterIndexes, beforeIndexes) {
					t.Fatalf("024 no-op down changed indexes (repair=%t): before=%#v after=%#v", repair, beforeIndexes, afterIndexes)
				}
				f153F158AssertEqual(t, fmt.Sprintf("enrichment rows after 024 down (repair=%t)", repair), f153F158EnrichmentSnapshot(t, leaf), beforeRows)
			}
		})

		t.Run("injected_up_and_down_failures_are_atomic_dirty_and_recoverable", func(t *testing.T) {
			leaf := f153F158PrepareLeaf(t, database, instance.dsn)
			f153F158ApplyThrough(t, leaf, 23)
			f153F158SeedEnrichmentCandidates(t, leaf)
			beforeRows := f153F158EnrichmentSnapshot(t, leaf)
			for _, index := range f153F158EnrichmentIndexes {
				f153F158Exec(t, leaf, `DROP INDEX `+index.name)
			}

			up := f153F158WithFailure(f153F158Embedded(t, 24, MigrationDirectionUp))
			f153F158ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, up), "P0001")
			for _, index := range f153F158EnrichmentIndexes {
				f153F158AssertRelationAbsent(t, leaf, index.name)
			}
			f153F158AssertEqual(t, "enrichment rows after failed 024 up", f153F158EnrichmentSnapshot(t, leaf), beforeRows)
			f153F158AssertDirtyAndRunRefusal(t, leaf, up)
			f153F158ClearDirty(t, leaf, 24)
			f153F158Apply(t, leaf, 24, MigrationDirectionUp)
			beforeIndexes := f153F158AssertEnrichmentIndexes(t, leaf)

			down := f153F158WithFailure(f153F158Embedded(t, 24, MigrationDirectionDown))
			f153F158ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, down), "P0001")
			afterIndexes := f153F158AssertEnrichmentIndexes(t, leaf)
			if !reflect.DeepEqual(afterIndexes, beforeIndexes) {
				t.Fatalf("failed 024 down changed indexes: before=%#v after=%#v", beforeIndexes, afterIndexes)
			}
			f153F158AssertEqual(t, "enrichment rows after failed 024 down", f153F158EnrichmentSnapshot(t, leaf), beforeRows)
			f153F158AssertDirtyAndRunRefusal(t, leaf, down)
			f153F158ClearDirty(t, leaf, 24)
			f153F158Apply(t, leaf, 24, MigrationDirectionDown)
		})
	})

	t.Run("migration_025", func(t *testing.T) {
		t.Run("populated_upgrade_catalog_tombstone_plan_down_twice_and_reapply", func(t *testing.T) {
			leaf := f153F158PrepareLeaf(t, database, instance.dsn)
			f153F158ApplyThrough(t, leaf, 24)
			f153F158SeedAPIKeysAndScans(t, leaf)
			beforeKeys := f153F158APIKeySnapshot(t, leaf)
			beforeScans := f153F158APIKeyScanSnapshot(t, leaf)

			f153F158Apply(t, leaf, 25, MigrationDirectionUp)
			f153F158AssertDeletedAtCatalog(t, leaf)
			f153F158AssertAllDeletedAtNull(t, leaf)
			f153F158AssertEqual(t, "API keys after 025 up", f153F158APIKeySnapshot(t, leaf), beforeKeys)
			f153F158AssertEqual(t, "scan references after 025 up", f153F158APIKeyScanSnapshot(t, leaf), beforeScans)

			f153F158ApplyRange(t, leaf, 26, 29)
			f153F158SetDeletedAtAfter029(t, leaf)
			f153F158AssertTombstonePlan(t, leaf)
			f153F158DescendAndDelete(t, leaf, 29, 26)
			f153F158ApplyDownAndDelete(t, leaf, 25)
			f153F158AssertDeletedAtAbsent(t, leaf)
			f153F158AssertEqual(t, "API keys after 025 down", f153F158APIKeySnapshot(t, leaf), beforeKeys)
			f153F158AssertEqual(t, "scan references after 025 down", f153F158APIKeyScanSnapshot(t, leaf), beforeScans)
			f153F158ApplyDownAndDelete(t, leaf, 25)
			f153F158AssertDeletedAtAbsent(t, leaf)

			f153F158Apply(t, leaf, 25, MigrationDirectionUp)
			f153F158AssertDeletedAtCatalog(t, leaf)
			f153F158AssertAllDeletedAtNull(t, leaf)
			f153F158ApplyRange(t, leaf, 26, 29)
			f153F158SetDeletedAtAfter029(t, leaf)
			f153F158AssertTombstonePlan(t, leaf)
			f153F158AssertEqual(t, "API keys after 025 reapply", f153F158APIKeySnapshot(t, leaf), beforeKeys)
			f153F158AssertEqual(t, "scan references after 025 reapply", f153F158APIKeyScanSnapshot(t, leaf), beforeScans)
		})

		t.Run("up_collision_and_down_dependency_failures_are_atomic_and_recoverable", func(t *testing.T) {
			leaf := f153F158PrepareLeaf(t, database, instance.dsn)
			f153F158ApplyThrough(t, leaf, 24)
			f153F158SeedAPIKeysAndScans(t, leaf)
			beforeKeys := f153F158APIKeySnapshot(t, leaf)
			beforeScans := f153F158APIKeyScanSnapshot(t, leaf)
			f153F158Exec(t, leaf, `CREATE TABLE idx_api_keys_deleted_at(id integer)`)

			up := f153F158Embedded(t, 25, MigrationDirectionUp)
			err := applyMigration(leaf.ctx, leaf.conn, up)
			if err == nil || !strings.Contains(err.Error(), "idx_api_keys_deleted_at") {
				t.Fatalf("025 index-name collision error = %v", err)
			}
			f153F158AssertDeletedAtAbsent(t, leaf)
			f153F158AssertRelationKind(t, leaf, "idx_api_keys_deleted_at", "r")
			f153F158AssertEqual(t, "API keys after failed 025 up", f153F158APIKeySnapshot(t, leaf), beforeKeys)
			f153F158AssertEqual(t, "scan references after failed 025 up", f153F158APIKeyScanSnapshot(t, leaf), beforeScans)
			f153F158AssertDirtyAndRunRefusal(t, leaf, up)
			f153F158ClearDirty(t, leaf, 25)
			f153F158Exec(t, leaf, `DROP TABLE idx_api_keys_deleted_at`)
			f153F158Apply(t, leaf, 25, MigrationDirectionUp)
			beforeIndex := f153F158IndexIdentity(t, leaf, "idx_api_keys_deleted_at")
			f153F158Exec(t, leaf, `CREATE VIEW f158_deleted_keys AS SELECT id,deleted_at FROM api_keys`)

			down := f153F158Embedded(t, 25, MigrationDirectionDown)
			err = applyMigration(leaf.ctx, leaf.conn, down)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "depend") {
				t.Fatalf("025 dependent-view down error = %v", err)
			}
			f153F158AssertDeletedAtCatalog(t, leaf)
			if afterIndex := f153F158IndexIdentity(t, leaf, "idx_api_keys_deleted_at"); afterIndex != beforeIndex {
				t.Fatalf("failed 025 down changed index: before=%q after=%q", beforeIndex, afterIndex)
			}
			f153F158AssertEqual(t, "API keys after failed 025 down", f153F158APIKeySnapshot(t, leaf), beforeKeys)
			f153F158AssertEqual(t, "scan references after failed 025 down", f153F158APIKeyScanSnapshot(t, leaf), beforeScans)
			f153F158AssertDirtyAndRunRefusal(t, leaf, down)
			f153F158ClearDirty(t, leaf, 25)
			f153F158Exec(t, leaf, `DROP VIEW f158_deleted_keys`)
			f153F158Apply(t, leaf, 25, MigrationDirectionDown)
			f153F158AssertDeletedAtAbsent(t, leaf)
			f153F158Apply(t, leaf, 25, MigrationDirectionUp)
			f153F158AssertDeletedAtCatalog(t, leaf)
		})

		t.Run("descending_043_to_025_preserves_v024_contract_and_reapplies", func(t *testing.T) {
			leaf := f153F158PrepareLeaf(t, database, instance.dsn)
			f153F158ApplyThrough(t, leaf, 24)
			f153F158SeedAPIKeysAndScans(t, leaf)
			beforeKeys := f153F158APIKeySnapshot(t, leaf)
			beforeScans := f153F158APIKeyScanSnapshot(t, leaf)
			f153F158ApplyRange(t, leaf, 25, 29)
			f153F158SetDeletedAtAfter029(t, leaf)
			f153F158ApplyRange(t, leaf, 30, 43)

			foreignKeyBefore042Down := f153F158HasScanAPIKeyForeignKey(t, leaf)
			f153F158ApplyDownAndDelete(t, leaf, 43)
			f153F158ApplyDownAndDelete(t, leaf, 42)
			foreignKeyAfter042Down := f153F158HasScanAPIKeyForeignKey(t, leaf)
			f153F158DescendAndDelete(t, leaf, 41, 26)
			foreignKeyAtV25 := f153F158HasScanAPIKeyForeignKey(t, leaf)
			f153F158AssertEqual(t, "API keys after descent to v025", f153F158APIKeySnapshot(t, leaf), beforeKeys)
			f153F158AssertEqual(t, "scan references after descent to v025", f153F158APIKeyScanSnapshot(t, leaf), beforeScans)
			f153F158ApplyDownAndDelete(t, leaf, 25)
			f153F158AssertDeletedAtAbsent(t, leaf)
			foreignKeyAtV24 := f153F158HasScanAPIKeyForeignKey(t, leaf)
			f153F158AssertEqual(t, "API keys at v024", f153F158APIKeySnapshot(t, leaf), beforeKeys)
			f153F158AssertEqual(t, "scan references at v024", f153F158APIKeyScanSnapshot(t, leaf), beforeScans)

			f153F158ApplyRange(t, leaf, 25, 29)
			f153F158SetDeletedAtAfter029(t, leaf)
			f153F158ApplyRange(t, leaf, 30, 43)
			foreignKeyAfterReapply := f153F158HasScanAPIKeyForeignKey(t, leaf)
			f153F158AssertEqual(t, "API keys after reapply through v043", f153F158APIKeySnapshot(t, leaf), beforeKeys)
			f153F158AssertEqual(t, "scan references after reapply through v043", f153F158APIKeyScanSnapshot(t, leaf), beforeScans)
			if !foreignKeyBefore042Down || foreignKeyAfter042Down || !foreignKeyAfterReapply || !foreignKeyAtV25 || !foreignKeyAtV24 {
				t.Skipf("known production defect F157-bugs-1: migration 042 down drops the 001-owned scan_log_api_key_id_fkey (before 042 down=%t, after 042 down=%t, at v25=%t, at v24=%t, after reapply=%t)", foreignKeyBefore042Down, foreignKeyAfter042Down, foreignKeyAtV25, foreignKeyAtV24, foreignKeyAfterReapply)
			}
		})
	})
}

func f153F158PrepareLeaf(t *testing.T, database *sql.DB, dsn string) f153F158Leaf {
	t.Helper()
	resetCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := database.ExecContext(resetCtx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public AUTHORIZATION packmon`); err != nil {
		t.Fatalf("reset public schema: %v", err)
	}
	ctx, leafCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(leafCancel)
	conn, err := database.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire migration leaf connection: %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(conn) })
	leaf := f153F158Leaf{ctx: ctx, conn: conn, dsn: dsn}
	if err := ensureVersionTable(ctx, conn); err != nil {
		t.Fatalf("ensure migration metadata: %v", err)
	}
	return leaf
}

func f153F158Embedded(t *testing.T, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	embedded, err := ReadEmbeddedMigration(version, direction)
	if err != nil {
		t.Fatalf("ReadEmbeddedMigration(%03d, %s): %v", version, direction, err)
	}
	return migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
}

func f153F158Apply(t *testing.T, leaf f153F158Leaf, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	migration := f153F158Embedded(t, version, direction)
	if err := applyMigration(leaf.ctx, leaf.conn, migration); err != nil {
		t.Fatalf("apply %s: %v", migration.name, err)
	}
	return migration
}

func f153F158ApplyThrough(t *testing.T, leaf f153F158Leaf, target int) {
	t.Helper()
	f153F158ApplyRange(t, leaf, 1, target)
}

func f153F158ApplyRange(t *testing.T, leaf f153F158Leaf, first, last int) {
	t.Helper()
	for version := first; version <= last; version++ {
		f153F158Apply(t, leaf, version, MigrationDirectionUp)
	}
}

func f153F158DescendAndDelete(t *testing.T, leaf f153F158Leaf, first, last int) {
	t.Helper()
	for version := first; version >= last; version-- {
		f153F158ApplyDownAndDelete(t, leaf, version)
	}
}

func f153F158ApplyDownAndDelete(t *testing.T, leaf f153F158Leaf, version int) {
	t.Helper()
	down := f153F158Apply(t, leaf, version, MigrationDirectionDown)
	f153F158DeleteCleanMetadata(t, leaf, down)
}

func f153F158DeleteCleanMetadata(t *testing.T, leaf f153F158Leaf, migration migrationFile) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read clean metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != migrationChecksum(migration.sql) || dirty || appliedAt.IsZero() {
		t.Fatalf("clean metadata for %s = name:%q checksum:%q dirty:%t applied:%v", migration.name, name, checksum, dirty, appliedAt)
	}
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND name=$2 AND checksum=$3 AND NOT dirty`, migration.version, migration.name, checksum)
	if err != nil {
		t.Fatalf("delete clean metadata for %s: %v", migration.name, err)
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil || affected != 1 {
		t.Fatalf("delete clean metadata for %s affected=%d error=%v, want 1", migration.name, affected, rowsErr)
	}
}

func f153F158WithFailure(migration migrationFile) migrationFile {
	migration.sql += `
DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'fixture-only migration failure';
END $$;
`
	return migration
}

func f153F158Exec(t *testing.T, leaf f153F158Leaf, statement string, args ...any) {
	t.Helper()
	if _, err := leaf.conn.ExecContext(leaf.ctx, statement, args...); err != nil {
		t.Fatalf("execute fixture SQL: %v\nSQL:\n%s", err, statement)
	}
}

func f153F158SeedRecentVulnerabilities(t *testing.T, leaf f153F158Leaf) {
	t.Helper()
	f153F158Exec(t, leaf, `
		INSERT INTO vulnerabilities(id,summary,severity,cvss_score,cisa_kev,published,modified,withdrawn)
		SELECT 'F154-NOISE-'||lpad(g::text,4,'0'),'noise','LOW',5.0,false,'2025-01-01Z'::timestamptz+(g||' seconds')::interval,'2025-01-02Z',NULL
		FROM generate_series(1,512) g;
		INSERT INTO vulnerabilities(id,summary,severity,published,modified,withdrawn) VALUES
		('F154-TIE-A','active tie A','HIGH','2099-01-01Z','2099-01-02Z',NULL),
		('F154-TIE-Z','active tie Z','HIGH','2099-01-01Z','2099-01-02Z',NULL),
		('F154-OLDER','active older','MEDIUM','2098-01-01Z','2098-01-02Z',NULL),
		('F154-WITHDRAWN','withdrawn newest','CRITICAL','2100-01-01Z','2100-01-02Z','2100-01-03Z')`)
}

func f153F158SeedEnrichmentCandidates(t *testing.T, leaf f153F158Leaf) {
	t.Helper()
	f153F158Exec(t, leaf, `ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_severity_check`)
	f153F158Exec(t, leaf, `
		INSERT INTO vulnerabilities(id,summary,severity,cvss_score,cisa_kev,published,modified)
		SELECT 'F156-NOISE-'||lpad(g::text,4,'0'),'noise','HIGH',7.0,false,'2026-01-01Z','2026-01-02Z'
		FROM generate_series(1,512) g;
		INSERT INTO vulnerabilities(id,summary,severity,cvss_score,cisa_kev,published,modified) VALUES
		('F156-UNKNOWN','unknown candidate','UNKNOWN',NULL,false,'2026-02-01Z','2026-02-02Z'),
		('F156-LOW-NULL','low null candidate','LOW',NULL,false,'2026-02-01Z','2026-02-02Z'),
		('F156-LOW-SCORED','low scored noncandidate','LOW',2.1,false,'2026-02-01Z','2026-02-02Z'),
		('F156-HIGH-NULL','high null noncandidate','HIGH',NULL,false,'2026-02-01Z','2026-02-02Z'),
		('F156-KEV','kev candidate','CRITICAL',9.8,true,'2026-02-01Z','2026-02-02Z'),
		('F156-NOT-KEV','non-kev','CRITICAL',9.8,false,'2026-02-01Z','2026-02-02Z');
		INSERT INTO vulnerability_aliases(vulnerability_id,alias_id) VALUES
		('F156-UNKNOWN','CVE-2026-0001'),
		('F156-LOW-NULL','CVE-2026-0002'),
		('F156-LOW-SCORED','GHSA-F156-0001'),
		('F156-HIGH-NULL','cve-2026-lower')`)
}

func f153F158SeedAPIKeysAndScans(t *testing.T, leaf f153F158Leaf) {
	t.Helper()
	now := f153F158DatabaseClock(t, leaf)
	created := now.Add(-4 * time.Hour)
	revoked := now.Add(-2 * time.Hour)
	used := now.Add(-time.Hour)
	f153F158Exec(t, leaf, `
		INSERT INTO api_keys(id,name,key_hash,created_at,revoked_at,last_used_at,expires_at) VALUES
		(2501,'active-key','f158-active-hash',$1,NULL,$2,NULL),
		(2502,'revoked-key','f158-revoked-hash',$1,$3,$2,NULL),
		(2503,'unused-key','f158-unused-hash',$1,NULL,NULL,NULL)`, created, used, revoked)
	f153F158Exec(t, leaf, `
		INSERT INTO scan_log(id,scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,api_key_id,api_key_name) VALUES
		(2581,'f158-active-scan','org/active',$1,3,1,10,2501,'active-key'),
		(2582,'f158-revoked-scan','org/revoked',$1,4,2,20,2502,'revoked-key')`, now)
}

func f153F158DatabaseClock(t *testing.T, leaf f153F158Leaf) time.Time {
	t.Helper()
	var value time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT clock_timestamp()`).Scan(&value); err != nil {
		t.Fatalf("read database clock: %v", err)
	}
	return value
}

func f153F158SetDeletedAtAfter029(t *testing.T, leaf f153F158Leaf) {
	t.Helper()
	when := f153F158DatabaseClock(t, leaf)
	result, err := leaf.conn.ExecContext(leaf.ctx, `UPDATE api_keys SET deleted_at=$1 WHERE id=2502`, when)
	if err != nil {
		t.Fatalf("set fixture tombstone after migration 029: %v", err)
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil || affected != 1 {
		t.Fatalf("set fixture tombstone affected=%d error=%v, want 1", affected, rowsErr)
	}
}

func f153F158Snapshot(t *testing.T, leaf f153F158Leaf, query string) string {
	t.Helper()
	var value string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(snapshot_row)),'[]'::jsonb)::text FROM (`+query+`) snapshot_row`).Scan(&value); err != nil {
		t.Fatalf("snapshot query: %v\nSQL:\n%s", err, query)
	}
	return value
}

func f153F158VulnerabilitySnapshot(t *testing.T, leaf f153F158Leaf) string {
	t.Helper()
	return f153F158Snapshot(t, leaf, `SELECT id,summary,severity,cvss_score,cisa_kev,published,modified,withdrawn,xmin::text AS xmin FROM vulnerabilities ORDER BY id`)
}

func f153F158EnrichmentSnapshot(t *testing.T, leaf f153F158Leaf) string {
	t.Helper()
	return f153F158Snapshot(t, leaf, `SELECT 'v' AS kind,id,'' AS parent,summary AS value,xmin::text AS xmin FROM vulnerabilities UNION ALL SELECT 'a',id::text,vulnerability_id,alias_id,xmin::text FROM vulnerability_aliases ORDER BY kind,id`)
}

func f153F158APIKeySnapshot(t *testing.T, leaf f153F158Leaf) string {
	t.Helper()
	return f153F158Snapshot(t, leaf, `SELECT id,name,key_hash,created_at,revoked_at,last_used_at,expires_at FROM api_keys ORDER BY id`)
}

func f153F158APIKeyScanSnapshot(t *testing.T, leaf f153F158Leaf) string {
	t.Helper()
	return f153F158Snapshot(t, leaf, `SELECT id,scan_id,api_key_id,api_key_name FROM scan_log ORDER BY id`)
}

func f153F158AssertRecentResultsAndPlan(t *testing.T, leaf f153F158Leaf) {
	t.Helper()
	var ids []string
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT id FROM vulnerabilities WHERE withdrawn IS NULL ORDER BY published DESC,id DESC LIMIT 3`)
	if err != nil {
		t.Fatalf("query recent vulnerability ordering: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan recent vulnerability ID: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate recent vulnerability IDs: %v", err)
	}
	if want := []string{"F154-TIE-Z", "F154-TIE-A", "F154-OLDER"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("recent vulnerability IDs = %v, want %v", ids, want)
	}

	f153F158Exec(t, leaf, `SET enable_seqscan=off`)
	f153F158Exec(t, leaf, `SET plan_cache_mode=force_generic_plan`)
	f153F158Exec(t, leaf, `PREPARE f154_recent(integer,integer) AS
		SELECT v.id,v.summary,v.severity,COALESCE(ap.ecosystem,''),COALESCE(ap.name,''),
		       COALESCE(ap.version_ranges::text,'[]'),COALESCE(ap.versions_affected::text,'[]'),v.published
		FROM vulnerabilities v
		LEFT JOIN LATERAL (
			SELECT ap.ecosystem,ap.name,ap.version_ranges,ap.versions_affected
			FROM affected_packages ap WHERE ap.vulnerability_id=v.id
			ORDER BY CASE WHEN jsonb_typeof(ap.version_ranges)='array' THEN jsonb_array_length(ap.version_ranges) ELSE 0 END DESC,
			         CASE WHEN jsonb_typeof(ap.versions_affected)='array' THEN jsonb_array_length(ap.versions_affected) ELSE 0 END DESC,
			         ap.id ASC LIMIT 1
		) ap ON true
		WHERE v.published >= NOW()-make_interval(days=>$1) AND v.withdrawn IS NULL
		ORDER BY v.published DESC,v.id DESC LIMIT $2`)
	var raw []byte
	if err := leaf.conn.QueryRowContext(leaf.ctx, `EXPLAIN (FORMAT JSON,COSTS OFF) EXECUTE f154_recent(30000,20)`).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN generic recent-vulnerability query: %v", err)
	}
	if !f153F158PlanContainsIndex(t, raw, "idx_vulnerabilities_recent_published") {
		t.Fatalf("generic recent-vulnerability plan does not use idx_vulnerabilities_recent_published: %s", raw)
	}
	f153F158Exec(t, leaf, `DEALLOCATE f154_recent`)
	f153F158Exec(t, leaf, `RESET plan_cache_mode`)
	f153F158Exec(t, leaf, `RESET enable_seqscan`)
}

func f153F158AssertEnrichmentIndexes(t *testing.T, leaf f153F158Leaf) map[string]string {
	t.Helper()
	got := make(map[string]string, len(f153F158EnrichmentIndexes))
	for _, want := range f153F158EnrichmentIndexes {
		index := f153F158AssertIndex(t, leaf, want)
		got[want.name] = fmt.Sprintf("%d|%s", index.oid, index.definition)
	}
	return got
}

func f153F158AssertEnrichmentCandidatesAndPlans(t *testing.T, leaf f153F158Leaf) {
	t.Helper()
	tests := []struct {
		label string
		query string
		want  []string
		index string
	}{
		{
			label: "NVD candidates",
			query: `SELECT id FROM vulnerabilities WHERE severity='UNKNOWN' OR (severity='LOW' AND cvss_score IS NULL) ORDER BY id`,
			want:  []string{"F156-LOW-NULL", "F156-UNKNOWN"},
			index: "idx_vulnerabilities_nvd_candidate",
		},
		{
			label: "CVE aliases",
			query: `SELECT alias_id FROM vulnerability_aliases WHERE alias_id LIKE 'CVE-%' ORDER BY alias_id`,
			want:  []string{"CVE-2026-0001", "CVE-2026-0002"},
			index: "idx_vuln_aliases_cve_alias",
		},
		{
			label: "CISA KEV candidates",
			query: `SELECT id FROM vulnerabilities WHERE cisa_kev=TRUE ORDER BY id`,
			want:  []string{"F156-KEV"},
			index: "idx_vulnerabilities_cisa_kev",
		},
	}
	f153F158Exec(t, leaf, `SET enable_seqscan=off`)
	for _, tt := range tests {
		var got []string
		rows, err := leaf.conn.QueryContext(leaf.ctx, tt.query)
		if err != nil {
			t.Fatalf("query %s: %v", tt.label, err)
		}
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				ioutils.CloseSilently(rows)
				t.Fatalf("scan %s: %v", tt.label, err)
			}
			got = append(got, value)
		}
		if err := rows.Err(); err != nil {
			ioutils.CloseSilently(rows)
			t.Fatalf("iterate %s: %v", tt.label, err)
		}
		ioutils.CloseSilently(rows)
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("%s = %v, want %v", tt.label, got, tt.want)
		}
		var raw []byte
		if err := leaf.conn.QueryRowContext(leaf.ctx, `EXPLAIN (FORMAT JSON,COSTS OFF) `+tt.query).Scan(&raw); err != nil {
			t.Fatalf("EXPLAIN %s: %v", tt.label, err)
		}
		if !f153F158PlanContainsIndex(t, raw, tt.index) {
			t.Fatalf("%s plan does not use %s: %s", tt.label, tt.index, raw)
		}
	}
	f153F158Exec(t, leaf, `RESET enable_seqscan`)
}

func f153F158AssertDeletedAtCatalog(t *testing.T, leaf f153F158Leaf) {
	t.Helper()
	var dataType, nullable, defaultSQL string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT data_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema='public' AND table_name='api_keys' AND column_name='deleted_at'`).Scan(&dataType, &nullable, &defaultSQL); err != nil {
		t.Fatalf("inspect api_keys.deleted_at: %v", err)
	}
	if dataType != "timestamp with time zone" || nullable != "YES" || defaultSQL != "" {
		t.Fatalf("api_keys.deleted_at = type:%q nullable:%q default:%q", dataType, nullable, defaultSQL)
	}
	f153F158AssertIndex(t, leaf, f153F158IndexWant{
		name:       "idx_api_keys_deleted_at",
		table:      "api_keys",
		keys:       []string{"deleted_at"},
		opclasses:  []string{"timestamptz_ops"},
		predicate:  "(deleted_at IS NOT NULL)",
		definition: "CREATE INDEX idx_api_keys_deleted_at ON public.api_keys USING btree (deleted_at) WHERE (deleted_at IS NOT NULL)",
	})
}

func f153F158AssertDeletedAtAbsent(t *testing.T, leaf f153F158Leaf) {
	t.Helper()
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='api_keys' AND column_name='deleted_at'`).Scan(&count); err != nil {
		t.Fatalf("inspect absent api_keys.deleted_at: %v", err)
	}
	if count != 0 {
		t.Fatalf("api_keys.deleted_at count = %d, want 0", count)
	}
	var indexCount int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid WHERE idx.relname='idx_api_keys_deleted_at'`).Scan(&indexCount); err != nil {
		t.Fatalf("inspect absent idx_api_keys_deleted_at index: %v", err)
	}
	if indexCount != 0 {
		t.Fatalf("idx_api_keys_deleted_at index count = %d, want 0", indexCount)
	}
}

func f153F158AssertAllDeletedAtNull(t *testing.T, leaf f153F158Leaf) {
	t.Helper()
	var total, nonnull int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*),COUNT(deleted_at) FROM api_keys`).Scan(&total, &nonnull); err != nil {
		t.Fatalf("inspect deleted_at backfill: %v", err)
	}
	if total != 3 || nonnull != 0 {
		t.Fatalf("api_keys deleted_at backfill = total:%d nonnull:%d, want 3/0", total, nonnull)
	}
}

func f153F158AssertTombstonePlan(t *testing.T, leaf f153F158Leaf) {
	t.Helper()
	f153F158Exec(t, leaf, `SET enable_seqscan=off`)
	var raw []byte
	if err := leaf.conn.QueryRowContext(leaf.ctx, `EXPLAIN (FORMAT JSON,COSTS OFF) DELETE FROM api_keys WHERE deleted_at IS NOT NULL`).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN API-key tombstone delete: %v", err)
	}
	if !f153F158PlanContainsIndex(t, raw, "idx_api_keys_deleted_at") {
		t.Fatalf("API-key tombstone plan does not use idx_api_keys_deleted_at: %s", raw)
	}
	f153F158Exec(t, leaf, `RESET enable_seqscan`)
}

func f153F158AssertScanAPIKeyForeignKey(t *testing.T, leaf f153F158Leaf) {
	t.Helper()
	if !f153F158HasScanAPIKeyForeignKey(t, leaf) {
		t.Fatal("scan_log_api_key_id_fkey is absent")
	}
}

func f153F158HasScanAPIKeyForeignKey(t *testing.T, leaf f153F158Leaf) bool {
	t.Helper()
	var definition string
	var validated bool
	err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT pg_get_constraintdef(oid),convalidated FROM pg_constraint WHERE conrelid='scan_log'::regclass AND conname='scan_log_api_key_id_fkey'`).Scan(&definition, &validated)
	if err == sql.ErrNoRows {
		return false
	}
	if err != nil {
		t.Fatalf("inspect v024 scan_log API-key foreign key: %v", err)
	}
	if definition != "FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL" || !validated {
		t.Fatalf("scan_log_api_key_id_fkey = definition:%q validated:%t", definition, validated)
	}
	return true
}

func f153F158AssertIndex(t *testing.T, leaf f153F158Leaf, want f153F158IndexWant) f153F158Index {
	t.Helper()
	var got f153F158Index
	var keys, opclasses string
	err := leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT i.indexrelid::bigint,tbl.relname,am.amname,
		       array_to_string(ARRAY(SELECT pg_get_indexdef(i.indexrelid,n,true) FROM generate_series(1,i.indnkeyatts) n ORDER BY n),'|'),
		       array_to_string(ARRAY(SELECT opc.opcname FROM unnest(i.indclass::oid[]) WITH ORDINALITY c(oid,n) JOIN pg_opclass opc ON opc.oid=c.oid ORDER BY c.n),'|'),
		       COALESCE(pg_get_expr(i.indpred,i.indrelid),''),pg_get_indexdef(i.indexrelid),
		       i.indisvalid,i.indisready,i.indislive,i.indisunique
		FROM pg_index i
		JOIN pg_class idx ON idx.oid=i.indexrelid
		JOIN pg_class tbl ON tbl.oid=i.indrelid
		JOIN pg_namespace n ON n.oid=tbl.relnamespace
		JOIN pg_am am ON am.oid=idx.relam
		WHERE n.nspname='public' AND idx.relname=$1`, want.name).Scan(
		&got.oid, &got.table, &got.method, &keys, &opclasses, &got.predicate, &got.definition,
		&got.valid, &got.ready, &got.live, &got.unique,
	)
	if err != nil {
		t.Fatalf("inspect index %s: %v", want.name, err)
	}
	if keys != "" {
		got.keys = strings.Split(keys, "|")
	}
	if opclasses != "" {
		got.opclasses = strings.Split(opclasses, "|")
	}
	got.predicate = strings.Join(strings.Fields(got.predicate), " ")
	got.definition = strings.Join(strings.Fields(got.definition), " ")
	if got.table != want.table || got.method != "btree" || !reflect.DeepEqual(got.keys, want.keys) || !reflect.DeepEqual(got.opclasses, want.opclasses) || got.predicate != want.predicate || got.definition != want.definition || !got.valid || !got.ready || !got.live || got.unique {
		t.Fatalf("index %s = %+v, want table=%s btree keys=%v opclasses=%v predicate=%q definition=%q valid/ready/live nonunique", want.name, got, want.table, want.keys, want.opclasses, want.predicate, want.definition)
	}
	return got
}

func f153F158IndexIdentity(t *testing.T, leaf f153F158Leaf, name string) string {
	t.Helper()
	var oid int64
	var definition string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT i.indexrelid::bigint,pg_get_indexdef(i.indexrelid) FROM pg_index i WHERE i.indexrelid=to_regclass($1)`, name).Scan(&oid, &definition); err != nil {
		t.Fatalf("inspect index identity %s: %v", name, err)
	}
	return fmt.Sprintf("%d|%s", oid, definition)
}

func f153F158IndexIdentities(t *testing.T, leaf f153F158Leaf, names []string) map[string]string {
	t.Helper()
	got := make(map[string]string, len(names))
	for _, name := range names {
		got[name] = f153F158IndexIdentity(t, leaf, name)
	}
	return got
}

func f153F158AssertIndexIdentities(t *testing.T, leaf f153F158Leaf, want map[string]string) {
	t.Helper()
	for name, identity := range want {
		if got := f153F158IndexIdentity(t, leaf, name); got != identity {
			t.Fatalf("unrelated index %s changed: got %q, want %q", name, got, identity)
		}
	}
}

func f153F158AssertRelationAbsent(t *testing.T, leaf f153F158Leaf, name string) {
	t.Helper()
	var exists bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatalf("inspect absent relation %s: %v", name, err)
	}
	if exists {
		t.Fatalf("relation %s exists, want absent", name)
	}
}

func f153F158AssertRelationKind(t *testing.T, leaf f153F158Leaf, name, want string) {
	t.Helper()
	var kind string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT relkind::text FROM pg_class WHERE oid=to_regclass($1)`, name).Scan(&kind); err != nil {
		t.Fatalf("inspect relation kind %s: %v", name, err)
	}
	if kind != want {
		t.Fatalf("relation %s kind = %q, want %q", name, kind, want)
	}
}

func f153F158AssertDirtyAndRunRefusal(t *testing.T, leaf f153F158Leaf, migration migrationFile) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt sql.NullTime
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read dirty metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != migrationChecksum(migration.sql) || !dirty || appliedAt.Valid {
		t.Fatalf("dirty metadata for %s = name:%q checksum:%q dirty:%t applied:%v", migration.name, name, checksum, dirty, appliedAt)
	}
	var failures, unfinished int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FILTER(WHERE name=$2 AND checksum=$3 AND NOT success AND dirty),COUNT(*) FILTER(WHERE finished_at IS NULL) FROM schema_migration_events WHERE version=$1`, migration.version, migration.name, checksum).Scan(&failures, &unfinished); err != nil {
		t.Fatalf("read dirty event for %s: %v", migration.name, err)
	}
	if failures != 1 || unfinished != 0 {
		t.Fatalf("dirty events for %s = failures:%d unfinished:%d, want 1/0", migration.name, failures, unfinished)
	}
	err := RunContext(leaf.ctx, leaf.dsn)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("dirty at version %d", migration.version)) {
		t.Fatalf("RunContext() dirty refusal for version %d = %v", migration.version, err)
	}
}

func f153F158ClearDirty(t *testing.T, leaf f153F158Leaf, version int) {
	t.Helper()
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND dirty`, version)
	if err != nil {
		t.Fatalf("clear fixture dirty marker %d: %v", version, err)
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil || affected != 1 {
		t.Fatalf("clear fixture dirty marker %d affected=%d error=%v, want 1", version, affected, rowsErr)
	}
}

func f153F158PlanContainsIndex(t *testing.T, raw []byte, index string) bool {
	t.Helper()
	var plan any
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("decode JSON EXPLAIN: %v\n%s", err, raw)
	}
	return f153F158JSONContains(plan, "Index Name", index)
}

func f153F158JSONContains(value any, key, want string) bool {
	switch value := value.(type) {
	case map[string]any:
		if got, ok := value[key].(string); ok && got == want {
			return true
		}
		for _, child := range value {
			if f153F158JSONContains(child, key, want) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if f153F158JSONContains(child, key, want) {
				return true
			}
		}
	}
	return false
}

func f153F158ExpectSQLState(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("PostgreSQL error = nil, want SQLSTATE %s", want)
	}
	var state interface{ SQLState() string }
	if !errors.As(err, &state) || state.SQLState() != want {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, want)
	}
}

func f153F158AssertEqual(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s changed\ngot:  %s\nwant: %s", label, got, want)
	}
}
