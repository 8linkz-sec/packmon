//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type f133F138Leaf struct {
	ctx    context.Context
	conn   *sql.Conn
	schema string
	dsn    string
}

type f133F138Event struct {
	name     string
	checksum string
	success  bool
	dirty    bool
}

type f133F138Column struct {
	dataType   string
	nullable   string
	defaultSQL string
}

var f133F138EvidenceColumns = map[string]f133F138Column{
	"findings_blocking":       {"boolean", "NO", "false"},
	"block_threshold":         {"text", "NO", "''::text"},
	"correlation_id":          {"text", "NO", "''::text"},
	"feed_status":             {"text", "NO", "''::text"},
	"feed_versions":           {"jsonb", "NO", "'{}'::jsonb"},
	"finding_ids":             {"jsonb", "NO", "'[]'::jsonb"},
	"finding_severities":      {"jsonb", "NO", "'[]'::jsonb"},
	"manual_advisories_count": {"integer", "NO", "0"},
}

func TestF133F138MigrationContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	db, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	db.SetMaxOpenConns(3)

	for _, version := range []int{13, 14, 15} {
		for _, direction := range []MigrationDirection{MigrationDirectionUp, MigrationDirectionDown} {
			migration := f133F138Embedded(t, version, direction)
			statements, splitErr := splitSQLStatements(migration.sql)
			if splitErr != nil {
				t.Fatalf("split %s: %v", migration.name, splitErr)
			}
			if len(statements) != 1 {
				t.Fatalf("%s statement count = %d, want 1", migration.name, len(statements))
			}
			if !migrationRunsInTransaction(migration) {
				t.Fatalf("%s is non-transactional, want transactional", migration.name)
			}
		}
	}

	leafNumber := 0
	newLeaf := func(t *testing.T, label string) f133F138Leaf {
		leafNumber++
		return f133F138PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f133_f138_%02d_%s", leafNumber, label))
	}

	t.Run("migration_013", func(t *testing.T) {
		t.Run("legacy_missing_column_upgrade_non_destructive_down_and_replay", func(t *testing.T) {
			leaf := newLeaf(t, "013_legacy")
			f133F138ApplyThrough(t, leaf, 12)
			f133F138SeedMalicious(t, leaf)
			f133F138Exec(t, leaf, `ALTER TABLE malicious_findings DROP COLUMN version_ranges`)
			before := f133F138Snapshot(t, leaf, `SELECT id,ecosystem,name,versions,source,risk_type,severity,summary,description,reference_urls,origin_ref,published,created_at,updated_at,created_by FROM malicious_findings ORDER BY id`)

			up := f133F138Apply(t, leaf, 13, MigrationDirectionUp)
			f133F138AssertColumn(t, leaf, "malicious_findings", "version_ranges", f133F138Column{"jsonb", "YES", ""})
			f133F138AssertNoColumnConstraint(t, leaf, "malicious_findings", "version_ranges")
			f133F138AssertMaliciousRanges(t, leaf, map[string]sql.NullString{
				"f133-null":  {},
				"f133-empty": {},
				"f133-range": {},
			})
			f133F138Exec(t, leaf, `INSERT INTO malicious_findings(id,ecosystem,name,version_ranges,versions,source,risk_type,severity,summary) VALUES('f133-new-range','npm','new-range','[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]'::jsonb,'["1.5.0"]'::jsonb,'fixture','malware','HIGH','new range')`)
			wantRanges := f133F138Snapshot(t, leaf, `SELECT id,version_ranges,versions FROM malicious_findings ORDER BY id`)
			down := f133F138Apply(t, leaf, 13, MigrationDirectionDown)
			f133F138AssertColumn(t, leaf, "malicious_findings", "version_ranges", f133F138Column{"jsonb", "YES", ""})
			if got := f133F138Snapshot(t, leaf, `SELECT id,version_ranges,versions FROM malicious_findings ORDER BY id`); got != wantRanges {
				t.Fatalf("013 down changed legacy-upgraded ranges\ngot:  %s\nwant: %s", got, wantRanges)
			}
			if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
				t.Fatalf("replay 013 up: %v", err)
			}
			if got := f133F138Snapshot(t, leaf, `SELECT id,version_ranges,versions FROM malicious_findings ORDER BY id`); got != wantRanges {
				t.Fatalf("013 replay changed ranges\ngot:  %s\nwant: %s", got, wantRanges)
			}
			if got := f133F138Snapshot(t, leaf, `SELECT id,ecosystem,name,versions,source,risk_type,severity,summary,description,reference_urls,origin_ref,published,created_at,updated_at,created_by FROM malicious_findings WHERE id <> 'f133-new-range' ORDER BY id`); got != before {
				t.Fatalf("013 legacy round trip changed retained fields\ngot:  %s\nwant: %s", got, before)
			}
			f133F138AssertEvents(t, leaf, 13, []f133F138Event{
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
				{name: down.name, checksum: migrationChecksum(down.sql), success: true},
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
			})
		})

		t.Run("current_baseline_populated_preservation_and_compatible_replay", func(t *testing.T) {
			leaf := newLeaf(t, "013_current")
			f133F138ApplyThrough(t, leaf, 12)
			f133F138SeedMalicious(t, leaf)
			before := f133F138Snapshot(t, leaf, `SELECT * FROM malicious_findings ORDER BY id`)
			constraintBefore := f133F138VersionRangeConstraint(t, leaf)

			up := f133F138Apply(t, leaf, 13, MigrationDirectionUp)
			if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
				t.Fatalf("compatible 013 up replay: %v", err)
			}
			down := f133F138Apply(t, leaf, 13, MigrationDirectionDown)
			if got := f133F138Snapshot(t, leaf, `SELECT * FROM malicious_findings ORDER BY id`); got != before {
				t.Fatalf("013 current-baseline cycle changed findings\ngot:  %s\nwant: %s", got, before)
			}
			if got := f133F138VersionRangeConstraint(t, leaf); got != constraintBefore {
				t.Fatalf("013 current-baseline cycle changed existing version-range constraint\ngot:  %s\nwant: %s", got, constraintBefore)
			}
			f133F138AssertMaliciousRanges(t, leaf, map[string]sql.NullString{
				"f133-null":  {},
				"f133-empty": {String: "[]", Valid: true},
				"f133-range": {String: `[{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]`, Valid: true},
			})
			f133F138AssertEvents(t, leaf, 13, []f133F138Event{
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
				{name: down.name, checksum: migrationChecksum(down.sql), success: true},
			})
		})

		t.Run("injected_up_and_down_failures_are_atomic_and_audited", func(t *testing.T) {
			leaf := newLeaf(t, "013_faults")
			f133F138ApplyThrough(t, leaf, 12)
			f133F138SeedMalicious(t, leaf)
			f133F138Exec(t, leaf, `ALTER TABLE malicious_findings DROP COLUMN version_ranges`)
			before := f133F138Snapshot(t, leaf, `SELECT id,summary,versions FROM malicious_findings ORDER BY id`)

			up := f133F138Embedded(t, 13, MigrationDirectionUp)
			failedUp := f133F138WithFailure(up, `SELECT 1`, "fixture-only 013 up failure")
			f133F138ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedUp), "P0001")
			f133F138AssertColumnAbsent(t, leaf, "malicious_findings", "version_ranges")
			if got := f133F138Snapshot(t, leaf, `SELECT id,summary,versions FROM malicious_findings ORDER BY id`); got != before {
				t.Fatalf("failed 013 up changed malicious rows\ngot:  %s\nwant: %s", got, before)
			}
			f133F138AssertDirtyAndRunRefusal(t, leaf, failedUp, 1)
			f133F138ClearDirty(t, leaf, 13)
			if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
				t.Fatalf("recover 013 up: %v", err)
			}
			f133F138Exec(t, leaf, `UPDATE malicious_findings SET version_ranges='[]'::jsonb WHERE id='f133-empty'`)
			beforeDown := f133F138Snapshot(t, leaf, `SELECT id,summary,version_ranges,versions FROM malicious_findings ORDER BY id`)

			down := f133F138Embedded(t, 13, MigrationDirectionDown)
			failedDown := f133F138WithFailure(down, `UPDATE malicious_findings SET summary='fixture-mutated-sentinel' WHERE id='f133-empty'`, "fixture-only 013 down failure")
			f133F138ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedDown), "P0001")
			if got := f133F138Snapshot(t, leaf, `SELECT id,summary,version_ranges,versions FROM malicious_findings ORDER BY id`); got != beforeDown {
				t.Fatalf("failed 013 down did not roll back sentinel mutation\ngot:  %s\nwant: %s", got, beforeDown)
			}
			f133F138AssertDirtyAndRunRefusal(t, leaf, failedDown, 3)
			f133F138ClearDirty(t, leaf, 13)
			if err := applyMigration(leaf.ctx, leaf.conn, down); err != nil {
				t.Fatalf("recover 013 down: %v", err)
			}
			if got := f133F138Snapshot(t, leaf, `SELECT id,summary,version_ranges,versions FROM malicious_findings ORDER BY id`); got != beforeDown {
				t.Fatalf("recovered 013 down changed ranges\ngot:  %s\nwant: %s", got, beforeDown)
			}
			f133F138AssertEvents(t, leaf, 13, []f133F138Event{
				{name: failedUp.name, checksum: migrationChecksum(failedUp.sql), dirty: true},
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
				{name: failedDown.name, checksum: migrationChecksum(failedDown.sql), dirty: true},
				{name: down.name, checksum: migrationChecksum(down.sql), success: true},
			})
		})
	})

	t.Run("migration_014", func(t *testing.T) {
		t.Run("populated_upgrade_catalog_defaults_nulls_and_preservation", func(t *testing.T) {
			leaf := newLeaf(t, "014_upgrade")
			f133F138ApplyThrough(t, leaf, 13)
			f133F138SeedScan(t, leaf, "f136-historical")
			before := f133F138BaseScanSnapshot(t, leaf)

			up := f133F138Apply(t, leaf, 14, MigrationDirectionUp)
			f133F138AssertEvidenceCatalog(t, leaf, true)
			f133F138AssertEvidence(t, leaf, "f136-historical", false, "", "", "", `{}`, `[]`, `[]`, 0)
			for column := range f133F138EvidenceColumns {
				_, nullErr := leaf.conn.ExecContext(leaf.ctx, `UPDATE scan_log SET `+f133F138QuoteIdentifier(column)+`=NULL WHERE scan_id='f136-historical'`)
				f133F138ExpectSQLState(t, nullErr, "23502")
			}
			f133F138Exec(t, leaf, `
				INSERT INTO scan_log(scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,findings_blocking,block_threshold,correlation_id,feed_status,feed_versions,finding_ids,finding_severities,manual_advisories_count)
				VALUES('f136-evidence','org/evidence','2026-05-06T07:08:09Z',8,3,456,true,'HIGH','corr-evidence','degraded','{"ghsa":"2026-05-01","osv":"2026-05-02"}'::jsonb,'["GHSA-1","OSV-2"]'::jsonb,'["CRITICAL","HIGH"]'::jsonb,4)`)
			f133F138AssertEvidence(t, leaf, "f136-evidence", true, "HIGH", "corr-evidence", "degraded", `{"ghsa": "2026-05-01", "osv": "2026-05-02"}`, `["GHSA-1", "OSV-2"]`, `["CRITICAL", "HIGH"]`, 4)
			if got := f133F138Snapshot(t, leaf, `SELECT id,scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,client_ip,client_version,api_key_id,api_key_name FROM scan_log WHERE scan_id='f136-historical' ORDER BY id`); got != before {
				t.Fatalf("014 upgrade did not preserve historical scan metadata\ngot:  %s\nwant historical row: %s", got, before)
			}
			f133F138AssertCleanMetadata(t, leaf, up)
		})

		t.Run("populated_down_repeat_reapply_and_evidence_loss", func(t *testing.T) {
			leaf := newLeaf(t, "014_cycle")
			f133F138ApplyThrough(t, leaf, 13)
			f133F138SeedScan(t, leaf, "f135-cycle")
			before := f133F138BaseScanSnapshot(t, leaf)
			up := f133F138Apply(t, leaf, 14, MigrationDirectionUp)
			f133F138Exec(t, leaf, `UPDATE scan_log SET findings_blocking=true,block_threshold='LOW',correlation_id='lost-corr',feed_status='healthy',feed_versions='{"osv":"lost"}',finding_ids='["LOST-1","LOST-2"]',finding_severities='["LOW","MEDIUM"]',manual_advisories_count=2 WHERE scan_id='f135-cycle'`)

			down := f133F138Apply(t, leaf, 14, MigrationDirectionDown)
			f133F138AssertEvidenceCatalog(t, leaf, false)
			if got := f133F138BaseScanSnapshot(t, leaf); got != before {
				t.Fatalf("014 down changed retained scan fields\ngot:  %s\nwant: %s", got, before)
			}
			if err := applyMigration(leaf.ctx, leaf.conn, down); err != nil {
				t.Fatalf("repeat 014 down: %v", err)
			}
			if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
				t.Fatalf("reapply 014 up: %v", err)
			}
			f133F138AssertEvidenceCatalog(t, leaf, true)
			f133F138AssertEvidence(t, leaf, "f135-cycle", false, "", "", "", `{}`, `[]`, `[]`, 0)
			f133F138AssertEvents(t, leaf, 14, []f133F138Event{
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
				{name: down.name, checksum: migrationChecksum(down.sql), success: true},
				{name: down.name, checksum: migrationChecksum(down.sql), success: true},
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
			})
		})

		t.Run("injected_up_and_down_failures_are_atomic_and_audited", func(t *testing.T) {
			leaf := newLeaf(t, "014_faults")
			f133F138ApplyThrough(t, leaf, 13)
			f133F138SeedScan(t, leaf, "f136-fault")
			before := f133F138BaseScanSnapshot(t, leaf)
			up := f133F138Embedded(t, 14, MigrationDirectionUp)
			failedUp := f133F138WithFailure(up, `SELECT 1`, "fixture-only 014 up failure")
			f133F138ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedUp), "P0001")
			f133F138AssertEvidenceCatalog(t, leaf, false)
			if got := f133F138BaseScanSnapshot(t, leaf); got != before {
				t.Fatalf("failed 014 up changed scan row\ngot:  %s\nwant: %s", got, before)
			}
			f133F138AssertDirtyAndRunRefusal(t, leaf, failedUp, 1)
			f133F138ClearDirty(t, leaf, 14)
			if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
				t.Fatalf("recover 014 up: %v", err)
			}
			f133F138Exec(t, leaf, `UPDATE scan_log SET findings_blocking=true,block_threshold='MEDIUM',correlation_id='kept-on-failure',feed_status='healthy',feed_versions='{"osv":"kept"}',finding_ids='["KEPT"]',finding_severities='["MEDIUM"]',manual_advisories_count=1 WHERE scan_id='f136-fault'`)
			wantEvidence := f133F138EvidenceSnapshot(t, leaf)

			down := f133F138Embedded(t, 14, MigrationDirectionDown)
			failedDown := f133F138WithFailure(down, `SELECT 1`, "fixture-only 014 down failure")
			f133F138ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedDown), "P0001")
			f133F138AssertEvidenceCatalog(t, leaf, true)
			if got := f133F138EvidenceSnapshot(t, leaf); got != wantEvidence {
				t.Fatalf("failed 014 down changed evidence\ngot:  %s\nwant: %s", got, wantEvidence)
			}
			f133F138AssertDirtyAndRunRefusal(t, leaf, failedDown, 3)
			f133F138ClearDirty(t, leaf, 14)
			if err := applyMigration(leaf.ctx, leaf.conn, down); err != nil {
				t.Fatalf("recover 014 down: %v", err)
			}
			f133F138AssertEvidenceCatalog(t, leaf, false)
			f133F138AssertEvents(t, leaf, 14, []f133F138Event{
				{name: failedUp.name, checksum: migrationChecksum(failedUp.sql), dirty: true},
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
				{name: failedDown.name, checksum: migrationChecksum(failedDown.sql), dirty: true},
				{name: down.name, checksum: migrationChecksum(down.sql), success: true},
			})
		})
	})

	t.Run("migration_015", func(t *testing.T) {
		t.Run("populated_upgrade_catalog_digest_default_null_and_replay", func(t *testing.T) {
			leaf := newLeaf(t, "015_upgrade")
			f133F138ApplyThrough(t, leaf, 14)
			f133F138SeedScan(t, leaf, "f138-historical")
			before := f133F138BaseAndEvidenceSnapshot(t, leaf)
			up := f133F138Apply(t, leaf, 15, MigrationDirectionUp)
			f133F138AssertColumn(t, leaf, "scan_log", "result_digest", f133F138Column{"text", "NO", "''::text"})
			f133F138AssertDigest(t, leaf, "f138-historical", "")
			f133F138Exec(t, leaf, `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms) VALUES('f138-omitted',0,0,0)`)
			f133F138AssertDigest(t, leaf, "f138-omitted", "")
			_, nullErr := leaf.conn.ExecContext(leaf.ctx, `UPDATE scan_log SET result_digest=NULL WHERE scan_id='f138-historical'`)
			f133F138ExpectSQLState(t, nullErr, "23502")
			f133F138Exec(t, leaf, `UPDATE scan_log SET result_digest='sha256:kept-explicit-digest' WHERE scan_id='f138-historical'`)
			if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
				t.Fatalf("replay 015 up: %v", err)
			}
			f133F138AssertDigest(t, leaf, "f138-historical", "sha256:kept-explicit-digest")
			if got := f133F138BaseAndEvidenceSnapshotWhere(t, leaf, `scan_id='f138-historical'`); got != before {
				t.Fatalf("015 upgrade/replay changed retained scan metadata\ngot:  %s\nwant: %s", got, before)
			}
			f133F138AssertEvents(t, leaf, 15, []f133F138Event{
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
			})
		})

		t.Run("populated_down_repeat_reapply_and_digest_loss", func(t *testing.T) {
			leaf := newLeaf(t, "015_cycle")
			f133F138ApplyThrough(t, leaf, 14)
			f133F138SeedScan(t, leaf, "f137-cycle")
			before := f133F138BaseAndEvidenceSnapshot(t, leaf)
			up := f133F138Apply(t, leaf, 15, MigrationDirectionUp)
			f133F138Exec(t, leaf, `UPDATE scan_log SET result_digest='sha256:discarded-by-down' WHERE scan_id='f137-cycle'`)
			down := f133F138Apply(t, leaf, 15, MigrationDirectionDown)
			f133F138AssertColumnAbsent(t, leaf, "scan_log", "result_digest")
			if got := f133F138BaseAndEvidenceSnapshot(t, leaf); got != before {
				t.Fatalf("015 down changed retained scan fields\ngot:  %s\nwant: %s", got, before)
			}
			if err := applyMigration(leaf.ctx, leaf.conn, down); err != nil {
				t.Fatalf("repeat 015 down: %v", err)
			}
			if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
				t.Fatalf("reapply 015 up: %v", err)
			}
			f133F138AssertDigest(t, leaf, "f137-cycle", "")
			f133F138AssertEvents(t, leaf, 15, []f133F138Event{
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
				{name: down.name, checksum: migrationChecksum(down.sql), success: true},
				{name: down.name, checksum: migrationChecksum(down.sql), success: true},
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
			})
		})

		t.Run("injected_up_and_down_failures_are_atomic_and_audited", func(t *testing.T) {
			leaf := newLeaf(t, "015_faults")
			f133F138ApplyThrough(t, leaf, 14)
			f133F138SeedScan(t, leaf, "f138-fault")
			before := f133F138BaseAndEvidenceSnapshot(t, leaf)
			up := f133F138Embedded(t, 15, MigrationDirectionUp)
			failedUp := f133F138WithFailure(up, `SELECT 1`, "fixture-only 015 up failure")
			f133F138ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedUp), "P0001")
			f133F138AssertColumnAbsent(t, leaf, "scan_log", "result_digest")
			if got := f133F138BaseAndEvidenceSnapshot(t, leaf); got != before {
				t.Fatalf("failed 015 up changed scan row\ngot:  %s\nwant: %s", got, before)
			}
			f133F138AssertDirtyAndRunRefusal(t, leaf, failedUp, 1)
			f133F138ClearDirty(t, leaf, 15)
			if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
				t.Fatalf("recover 015 up: %v", err)
			}
			f133F138Exec(t, leaf, `UPDATE scan_log SET result_digest='sha256:kept-on-failed-down' WHERE scan_id='f138-fault'`)

			down := f133F138Embedded(t, 15, MigrationDirectionDown)
			failedDown := f133F138WithFailure(down, `SELECT 1`, "fixture-only 015 down failure")
			f133F138ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedDown), "P0001")
			f133F138AssertDigest(t, leaf, "f138-fault", "sha256:kept-on-failed-down")
			f133F138AssertDirtyAndRunRefusal(t, leaf, failedDown, 3)
			f133F138ClearDirty(t, leaf, 15)
			if err := applyMigration(leaf.ctx, leaf.conn, down); err != nil {
				t.Fatalf("recover 015 down: %v", err)
			}
			f133F138AssertColumnAbsent(t, leaf, "scan_log", "result_digest")
			f133F138AssertEvents(t, leaf, 15, []f133F138Event{
				{name: failedUp.name, checksum: migrationChecksum(failedUp.sql), dirty: true},
				{name: up.name, checksum: migrationChecksum(up.sql), success: true},
				{name: failedDown.name, checksum: migrationChecksum(failedDown.sql), dirty: true},
				{name: down.name, checksum: migrationChecksum(down.sql), success: true},
			})
		})
	})

	t.Run("ordered_descending_015_014_013_and_reapply", func(t *testing.T) {
		leaf := newLeaf(t, "ordered")
		f133F138ApplyThrough(t, leaf, 15)
		f133F138SeedMalicious(t, leaf)
		f133F138SeedScan(t, leaf, "f138-ordered")
		f133F138Exec(t, leaf, `UPDATE scan_log SET findings_blocking=true,block_threshold='HIGH',correlation_id='ordered-lost',feed_status='degraded',feed_versions='{"osv":"ordered"}',finding_ids='["ORDERED"]',finding_severities='["HIGH"]',manual_advisories_count=1,result_digest='sha256:ordered-lost' WHERE scan_id='f138-ordered'`)
		maliciousBefore := f133F138Snapshot(t, leaf, `SELECT * FROM malicious_findings ORDER BY id`)
		scanBefore := f133F138BaseScanSnapshot(t, leaf)
		var marker int64
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COALESCE(MAX(id),0) FROM schema_migration_events`).Scan(&marker); err != nil {
			t.Fatalf("read ordered-cycle event marker: %v", err)
		}

		down15 := f133F138Apply(t, leaf, 15, MigrationDirectionDown)
		down14 := f133F138Apply(t, leaf, 14, MigrationDirectionDown)
		down13 := f133F138Apply(t, leaf, 13, MigrationDirectionDown)
		f133F138AssertColumnAbsent(t, leaf, "scan_log", "result_digest")
		f133F138AssertEvidenceCatalog(t, leaf, false)
		if got := f133F138Snapshot(t, leaf, `SELECT * FROM malicious_findings ORDER BY id`); got != maliciousBefore {
			t.Fatalf("descending 015/014/013 changed malicious ranges\ngot:  %s\nwant: %s", got, maliciousBefore)
		}
		if got := f133F138BaseScanSnapshot(t, leaf); got != scanBefore {
			t.Fatalf("descending 015/014/013 changed retained scan metadata\ngot:  %s\nwant: %s", got, scanBefore)
		}

		up13 := f133F138Apply(t, leaf, 13, MigrationDirectionUp)
		up14 := f133F138Apply(t, leaf, 14, MigrationDirectionUp)
		up15 := f133F138Apply(t, leaf, 15, MigrationDirectionUp)
		f133F138AssertEvidence(t, leaf, "f138-ordered", false, "", "", "", `{}`, `[]`, `[]`, 0)
		f133F138AssertDigest(t, leaf, "f138-ordered", "")
		f133F138AssertEventsAfter(t, leaf, marker, []f133F138Event{
			{name: down15.name, checksum: migrationChecksum(down15.sql), success: true},
			{name: down14.name, checksum: migrationChecksum(down14.sql), success: true},
			{name: down13.name, checksum: migrationChecksum(down13.sql), success: true},
			{name: up13.name, checksum: migrationChecksum(up13.sql), success: true},
			{name: up14.name, checksum: migrationChecksum(up14.sql), success: true},
			{name: up15.name, checksum: migrationChecksum(up15.sql), success: true},
		})
	})
}

func f133F138PrepareLeaf(t *testing.T, db *sql.DB, dsn, schema string) f133F138Leaf {
	t.Helper()
	quoted := f133F138QuoteIdentifier(schema)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, err := db.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+quoted+` CASCADE`); err != nil {
			t.Errorf("drop isolated schema %s: %v", schema, err)
		}
	})
	setupCtx, cancelSetup := context.WithTimeout(context.Background(), 20*time.Second)
	if _, err := db.ExecContext(setupCtx, `CREATE SCHEMA `+quoted); err != nil {
		cancelSetup()
		t.Fatalf("create isolated schema %s: %v", schema, err)
	}
	cancelSetup()

	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := db.Conn(connectCtx)
	cancelConnect()
	if err != nil {
		t.Fatalf("pin isolated schema connection: %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(conn) })
	setCtx, cancelSet := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := conn.ExecContext(setCtx, `SET search_path TO `+quoted); err != nil {
		cancelSet()
		t.Fatalf("set search_path to %s: %v", schema, err)
	}
	cancelSet()

	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse migration DSN: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return f133F138Leaf{ctx: ctx, conn: conn, schema: schema, dsn: parsed.String()}
}

func f133F138ApplyThrough(t *testing.T, leaf f133F138Leaf, target int) {
	t.Helper()
	if err := ensureVersionTable(leaf.ctx, leaf.conn); err != nil {
		t.Fatalf("ensure migration metadata: %v", err)
	}
	for version := 1; version <= target; version++ {
		f133F138Apply(t, leaf, version, MigrationDirectionUp)
	}
}

func f133F138Embedded(t *testing.T, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	embedded, err := ReadEmbeddedMigration(version, direction)
	if err != nil {
		t.Fatalf("ReadEmbeddedMigration(%d, %s): %v", version, direction, err)
	}
	return migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
}

func f133F138Apply(t *testing.T, leaf f133F138Leaf, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	migration := f133F138Embedded(t, version, direction)
	if err := applyMigration(leaf.ctx, leaf.conn, migration); err != nil {
		t.Fatalf("apply embedded migration %s: %v", migration.name, err)
	}
	return migration
}

func f133F138WithFailure(migration migrationFile, sentinelSQL, message string) migrationFile {
	migration.sql += "\n" + sentinelSQL + `;
DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = '` + message + `';
END $$;
`
	return migration
}

func f133F138Exec(t *testing.T, leaf f133F138Leaf, statement string, args ...any) {
	t.Helper()
	if _, err := leaf.conn.ExecContext(leaf.ctx, statement, args...); err != nil {
		t.Fatalf("execute fixture SQL: %v\nSQL:\n%s", err, statement)
	}
}

func f133F138SeedMalicious(t *testing.T, leaf f133F138Leaf) {
	t.Helper()
	f133F138Exec(t, leaf, `
		INSERT INTO malicious_findings(id,ecosystem,name,version_ranges,versions,source,risk_type,severity,summary,description,reference_urls,origin_ref,published,created_at,updated_at,created_by) VALUES
		('f133-null','npm','null-range',NULL,'["1.0.0"]','fixture','malware','CRITICAL','null summary','null description','["https://null.example"]','null-origin','2026-01-01Z','2026-01-02Z','2026-01-03Z','fixture'),
		('f133-empty','pypi','empty-range','[]','["2.0.0","2.1.0"]','fixture','supply_chain','HIGH','empty summary','empty description','[]','empty-origin','2026-02-01Z','2026-02-02Z','2026-02-03Z','fixture'),
		('f133-range','go','range-value','[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]','["1.5.0"]','fixture','typosquatting','MEDIUM','range summary','range description','["https://range.example"]','range-origin','2026-03-01Z','2026-03-02Z','2026-03-03Z','fixture')`)
}

func f133F138SeedScan(t *testing.T, leaf f133F138Leaf, scanID string) {
	t.Helper()
	f133F138Exec(t, leaf, `INSERT INTO scan_log(scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,client_ip,client_version) VALUES($1,'org/fixture','2026-04-05T06:07:08Z',7,2,345,'192.0.2.33','packmon/f133')`, scanID)
}

func f133F138Snapshot(t *testing.T, leaf f133F138Leaf, query string) string {
	t.Helper()
	var value string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(row_data)),'[]'::jsonb)::text FROM (`+query+`) row_data`).Scan(&value); err != nil {
		t.Fatalf("snapshot query: %v\nSQL:\n%s", err, query)
	}
	return value
}

func f133F138BaseScanSnapshot(t *testing.T, leaf f133F138Leaf) string {
	t.Helper()
	return f133F138Snapshot(t, leaf, `SELECT id,scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,client_ip,client_version,api_key_id,api_key_name FROM scan_log ORDER BY id`)
}

func f133F138EvidenceSnapshot(t *testing.T, leaf f133F138Leaf) string {
	t.Helper()
	return f133F138Snapshot(t, leaf, `SELECT scan_id,findings_blocking,block_threshold,correlation_id,feed_status,feed_versions,finding_ids,finding_severities,manual_advisories_count FROM scan_log ORDER BY id`)
}

func f133F138BaseAndEvidenceSnapshot(t *testing.T, leaf f133F138Leaf) string {
	t.Helper()
	return f133F138BaseAndEvidenceSnapshotWhere(t, leaf, `TRUE`)
}

func f133F138BaseAndEvidenceSnapshotWhere(t *testing.T, leaf f133F138Leaf, predicate string) string {
	t.Helper()
	return f133F138Snapshot(t, leaf, `SELECT id,scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,client_ip,client_version,api_key_id,api_key_name,findings_blocking,block_threshold,correlation_id,feed_status,feed_versions,finding_ids,finding_severities,manual_advisories_count FROM scan_log WHERE `+predicate+` ORDER BY id`)
}

func f133F138AssertColumn(t *testing.T, leaf f133F138Leaf, table, column string, want f133F138Column) {
	t.Helper()
	var got f133F138Column
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT data_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2 AND column_name=$3`, leaf.schema, table, column).Scan(&got.dataType, &got.nullable, &got.defaultSQL); err != nil {
		t.Fatalf("inspect %s.%s: %v", table, column, err)
	}
	if got != want {
		t.Fatalf("column %s.%s = %#v, want %#v", table, column, got, want)
	}
}

func f133F138AssertColumnAbsent(t *testing.T, leaf f133F138Leaf, table, column string) {
	t.Helper()
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2 AND column_name=$3`, leaf.schema, table, column).Scan(&count); err != nil {
		t.Fatalf("inspect absent %s.%s: %v", table, column, err)
	}
	if count != 0 {
		t.Fatalf("column %s.%s count = %d, want 0", table, column, count)
	}
}

func f133F138AssertEvidenceCatalog(t *testing.T, leaf f133F138Leaf, present bool) {
	t.Helper()
	for column, want := range f133F138EvidenceColumns {
		if present {
			f133F138AssertColumn(t, leaf, "scan_log", column, want)
		} else {
			f133F138AssertColumnAbsent(t, leaf, "scan_log", column)
		}
	}
}

func f133F138AssertNoColumnConstraint(t *testing.T, leaf f133F138Leaf, table, column string) {
	t.Helper()
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT COUNT(*)
		FROM pg_constraint c
		JOIN pg_class r ON r.oid=c.conrelid
		JOIN pg_namespace n ON n.oid=r.relnamespace
		WHERE n.nspname=$1 AND r.relname=$2
		  AND pg_get_constraintdef(c.oid) ILIKE '%' || $3 || '%'`, leaf.schema, table, column).Scan(&count); err != nil {
		t.Fatalf("count constraints for %s.%s: %v", table, column, err)
	}
	if count != 0 {
		t.Fatalf("constraints mentioning %s.%s = %d, want no migration-invented constraint", table, column, count)
	}
}

func f133F138VersionRangeConstraint(t *testing.T, leaf f133F138Leaf) string {
	t.Helper()
	var value string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT oid::text || '|' || pg_get_constraintdef(oid) || '|' || convalidated::text FROM pg_constraint WHERE conrelid='malicious_findings'::regclass AND conname='malicious_findings_version_ranges_array_check'`).Scan(&value); err != nil {
		t.Fatalf("read malicious version-range constraint: %v", err)
	}
	return value
}

func f133F138AssertMaliciousRanges(t *testing.T, leaf f133F138Leaf, want map[string]sql.NullString) {
	t.Helper()
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT id,version_ranges::text FROM malicious_findings ORDER BY id`)
	if err != nil {
		t.Fatalf("read malicious ranges: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	got := make(map[string]sql.NullString)
	for rows.Next() {
		var id string
		var value sql.NullString
		if err := rows.Scan(&id, &value); err != nil {
			t.Fatalf("scan malicious range: %v", err)
		}
		got[id] = value
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate malicious ranges: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("malicious ranges = %#v, want %#v", got, want)
	}
}

func f133F138AssertEvidence(t *testing.T, leaf f133F138Leaf, scanID string, blocking bool, threshold, correlationID, status, versions, ids, severities string, manual int) {
	t.Helper()
	var gotBlocking bool
	var gotThreshold, gotCorrelationID, gotStatus, gotVersions, gotIDs, gotSeverities string
	var gotManual int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT findings_blocking,block_threshold,correlation_id,feed_status,feed_versions::text,finding_ids::text,finding_severities::text,manual_advisories_count FROM scan_log WHERE scan_id=$1`, scanID).Scan(&gotBlocking, &gotThreshold, &gotCorrelationID, &gotStatus, &gotVersions, &gotIDs, &gotSeverities, &gotManual); err != nil {
		t.Fatalf("read decision evidence for %s: %v", scanID, err)
	}
	if gotBlocking != blocking || gotThreshold != threshold || gotCorrelationID != correlationID || gotStatus != status || !f133F138JSONEqual(t, gotVersions, versions) || !f133F138JSONEqual(t, gotIDs, ids) || !f133F138JSONEqual(t, gotSeverities, severities) || gotManual != manual {
		t.Fatalf("decision evidence for %s = blocking:%t threshold:%q correlation:%q status:%q versions:%s ids:%s severities:%s manual:%d", scanID, gotBlocking, gotThreshold, gotCorrelationID, gotStatus, gotVersions, gotIDs, gotSeverities, gotManual)
	}
}

func f133F138JSONEqual(t *testing.T, got, want string) bool {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal([]byte(got), &gotValue); err != nil {
		t.Fatalf("decode actual JSON %q: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("decode expected JSON %q: %v", want, err)
	}
	return reflect.DeepEqual(gotValue, wantValue)
}

func f133F138AssertDigest(t *testing.T, leaf f133F138Leaf, scanID, want string) {
	t.Helper()
	var got string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT result_digest FROM scan_log WHERE scan_id=$1`, scanID).Scan(&got); err != nil {
		t.Fatalf("read result digest for %s: %v", scanID, err)
	}
	if got != want {
		t.Fatalf("result digest for %s = %q, want %q", scanID, got, want)
	}
}

func f133F138AssertCleanMetadata(t *testing.T, leaf f133F138Leaf, migration migrationFile) {
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
}

func f133F138AssertDirtyAndRunRefusal(t *testing.T, leaf f133F138Leaf, migration migrationFile, eventCount int) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt sql.NullTime
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read dirty metadata for %s: %v", migration.name, err)
	}
	wantChecksum := migrationChecksum(migration.sql)
	if name != migration.name || checksum != wantChecksum || !dirty || appliedAt.Valid {
		t.Fatalf("dirty metadata for %s = name:%q checksum:%q dirty:%t applied:%v, want checksum %q", migration.name, name, checksum, dirty, appliedAt, wantChecksum)
	}
	var total, matching, unfinished int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*),COUNT(*) FILTER(WHERE name=$2 AND checksum=$3 AND NOT success AND dirty),COUNT(*) FILTER(WHERE finished_at IS NULL) FROM schema_migration_events WHERE version=$1`, migration.version, migration.name, wantChecksum).Scan(&total, &matching, &unfinished); err != nil {
		t.Fatalf("read dirty migration events for %s: %v", migration.name, err)
	}
	if total != eventCount || matching != 1 || unfinished != 0 {
		t.Fatalf("dirty events for %s = total:%d matching:%d unfinished:%d, want %d/1/0", migration.name, total, matching, unfinished, eventCount)
	}
	err := RunContext(leaf.ctx, leaf.dsn)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("dirty at version %d", migration.version)) {
		t.Fatalf("RunContext() dirty refusal for %d = %v", migration.version, err)
	}
}

func f133F138ClearDirty(t *testing.T, leaf f133F138Leaf, version int) {
	t.Helper()
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND dirty`, version)
	if err != nil {
		t.Fatalf("clear fixture dirty marker %d: %v", version, err)
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil || affected != 1 {
		t.Fatalf("clear fixture dirty marker %d affected=%d error=%v", version, affected, rowsErr)
	}
}

func f133F138AssertEvents(t *testing.T, leaf f133F138Leaf, version int, want []f133F138Event) {
	t.Helper()
	f133F138AssertEventsQuery(t, leaf, `SELECT name,checksum,success,dirty,finished_at IS NOT NULL FROM schema_migration_events WHERE version=$1 ORDER BY id`, []any{version}, want)
}

func f133F138AssertEventsAfter(t *testing.T, leaf f133F138Leaf, marker int64, want []f133F138Event) {
	t.Helper()
	f133F138AssertEventsQuery(t, leaf, `SELECT name,checksum,success,dirty,finished_at IS NOT NULL FROM schema_migration_events WHERE id>$1 ORDER BY id`, []any{marker}, want)
}

func f133F138AssertEventsQuery(t *testing.T, leaf f133F138Leaf, query string, args []any, want []f133F138Event) {
	t.Helper()
	rows, err := leaf.conn.QueryContext(leaf.ctx, query, args...)
	if err != nil {
		t.Fatalf("read migration events: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	got := make([]f133F138Event, 0, len(want))
	for rows.Next() {
		var event f133F138Event
		var finished bool
		if err := rows.Scan(&event.name, &event.checksum, &event.success, &event.dirty, &finished); err != nil {
			t.Fatalf("scan migration event: %v", err)
		}
		if !finished {
			t.Fatalf("migration event %d is unfinished", len(got)+1)
		}
		got = append(got, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migration events: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("migration events = %#v, want %#v", got, want)
	}
}

func f133F138ExpectSQLState(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("PostgreSQL error = nil, want SQLSTATE %s", want)
	}
	var state interface{ SQLState() string }
	if !errors.As(err, &state) || state.SQLState() != want {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, want)
	}
}

func f133F138QuoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
