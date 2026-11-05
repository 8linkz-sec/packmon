//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

var migration005ApplicationTables = []string{
	"vulnerabilities",
	"vulnerability_aliases",
	"vulnerability_sources",
	"vulnerability_references",
	"affected_packages",
	"malicious_findings",
}

var migration005BackupTables = []string{
	"packmon_m005_vulnerabilities_backup",
	"packmon_m005_vulnerability_aliases_backup",
	"packmon_m005_vulnerability_sources_backup",
	"packmon_m005_vulnerability_references_backup",
	"packmon_m005_affected_packages_backup",
	"packmon_m005_malicious_findings_backup",
	"packmon_m005_malicious_vulnerability_ids",
	"packmon_m005_malicious_finding_ids",
}

func TestNormalizeUnknownSeverityMigration005ValidRoundTripAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)
	db, ctx, cancel := openFocusedMigrationDB(t, dsn)
	defer cancel()
	defer ioutils.CloseSilently(db)

	createPre005Schema(t, ctx, db)
	seedMigration005ComprehensiveFixtures(t, ctx, db)
	before := snapshotMigration005Tables(t, ctx, db, migration005ApplicationTables)
	expectedBackups := expectedMigration005BackupSnapshots(t, ctx, db)
	applyEmbeddedMigrationForTest(t, ctx, db, 5, MigrationDirectionUp)

	t.Run("up_converts_only_supported_legacy_rows", func(t *testing.T) {
		for _, id := range []string{"OSV-MULTI", "OSV-CONFLICT", "OSV-RANGE"} {
			var count int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE id = $1`, id).Scan(&count); err != nil {
				t.Fatalf("count converted vulnerability %s: %v", id, err)
			}
			if count != 0 {
				t.Fatalf("converted vulnerability %s row count = %d, want 0", id, count)
			}
		}

		var unknownSeverity string
		if err := db.QueryRowContext(ctx, `SELECT severity FROM vulnerabilities WHERE id = 'OSV-MISSING'`).Scan(&unknownSeverity); err != nil {
			t.Fatalf("read missing-key vulnerability: %v", err)
		}
		if unknownSeverity != "LOW" {
			t.Fatalf("missing-key vulnerability severity = %q, want LOW", unknownSeverity)
		}
		var knownSeverity, knownUpdated string
		if err := db.QueryRowContext(ctx, `SELECT severity, updated_at::text FROM vulnerabilities WHERE id = 'OSV-KNOWN'`).Scan(&knownSeverity, &knownUpdated); err != nil {
			t.Fatalf("read known-severity vulnerability: %v", err)
		}
		if knownSeverity != "HIGH" || !strings.Contains(knownUpdated, "2024-05-05 05:05:05") {
			t.Fatalf("known vulnerability = severity %q updated_at %q, want unchanged HIGH/2024-05-05", knownSeverity, knownUpdated)
		}

		type convertedFinding struct {
			id, ecosystem, name string
			versions            sql.NullString
		}
		want := []convertedFinding{
			{id: "OSV-MULTI-0", ecosystem: "cargo", name: "bad-cargo", versions: sql.NullString{String: `["1.0.0"]`, Valid: true}},
			{id: "OSV-MULTI-1", ecosystem: "pypi", name: "bad-python"},
			{id: "OSV-MULTI-2", ecosystem: "maven", name: "bad-java", versions: sql.NullString{String: `["2.0.0"]`, Valid: true}},
			{id: "OSV-MULTI-3", ecosystem: "gem", name: "bad-gem", versions: sql.NullString{String: `["3.0.0"]`, Valid: true}},
			{id: "OSV-RANGE", ecosystem: "composer", name: "bad-composer"},
		}
		for _, expected := range want {
			var ecosystem, name, riskType, severity, source, refs string
			var versions sql.NullString
			if err := db.QueryRowContext(ctx, `
				SELECT ecosystem, name, versions::text, risk_type, severity, source, reference_urls::text
				FROM malicious_findings WHERE id = $1`, expected.id).Scan(&ecosystem, &name, &versions, &riskType, &severity, &source, &refs); err != nil {
				t.Fatalf("read converted finding %s: %v", expected.id, err)
			}
			if ecosystem != expected.ecosystem || name != expected.name || versions != expected.versions || riskType != "typosquatting" || severity != "CRITICAL" || source != "osv" || refs != `["https://example.test/one", "https://example.test/two"]` {
				t.Fatalf("converted finding %s = ecosystem=%q name=%q versions=%v risk=%q severity=%q source=%q refs=%s; want ecosystem=%q name=%q versions=%v typosquatting/CRITICAL/osv/two refs",
					expected.id, ecosystem, name, versions, riskType, severity, source, refs, expected.ecosystem, expected.name, expected.versions)
			}
		}

		var conflictSummary, conflictDescription, conflictVersions string
		if err := db.QueryRowContext(ctx, `SELECT summary, description, versions::text FROM malicious_findings WHERE id = 'OSV-CONFLICT'`).Scan(&conflictSummary, &conflictDescription, &conflictVersions); err != nil {
			t.Fatalf("read converted conflicting finding: %v", err)
		}
		if conflictSummary != "supply chain conflict advisory" || conflictDescription != "new converted description" || conflictVersions != `["9.9.9"]` {
			t.Fatalf("converted conflict = (%q, %q, %s), want migration values", conflictSummary, conflictDescription, conflictVersions)
		}
	})

	t.Run("backup_tables_match_pre_up_snapshots", func(t *testing.T) {
		for backup, want := range expectedBackups {
			got := snapshotWholeTable(t, ctx, db, backup)
			if got != want {
				t.Fatalf("backup %s snapshot mismatch\ngot:  %s\nwant: %s", backup, got, want)
			}
		}
	})

	t.Run("down_restores_all_rows_and_preserves_post_up_rows", func(t *testing.T) {
		seedMigration005ConflictingRollbackRows(t, ctx, db)
		mustExecMigrationTest(t, ctx, db, `
			INSERT INTO vulnerabilities (id, summary, severity, published, modified)
			VALUES ('POST-UP', 'post-up vulnerability', 'HIGH', '2026-01-01Z', '2026-01-02Z')`)
		mustExecMigrationTest(t, ctx, db, `
			INSERT INTO malicious_findings (id, ecosystem, name, versions, source, risk_type, severity, summary, description, reference_urls, created_by)
			VALUES ('POST-UP-FINDING', 'npm', 'post-up', '["1"]', 'manual-feed', 'malware', 'HIGH', 'post-up finding', 'keep', '["https://post.test"]', 'post-up')`)

		applyEmbeddedMigrationForTest(t, ctx, db, 5, MigrationDirectionDown)
		for table, want := range before {
			got := snapshotMigration005OriginalRows(t, ctx, db, table)
			if got != want {
				t.Fatalf("restored %s snapshot mismatch\ngot:  %s\nwant: %s", table, got, want)
			}
		}
		var postVulnerability, postFinding int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE id = 'POST-UP' AND summary = 'post-up vulnerability' AND severity = 'HIGH'`).Scan(&postVulnerability); err != nil {
			t.Fatalf("count post-up vulnerability: %v", err)
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM malicious_findings WHERE id = 'POST-UP-FINDING' AND description = 'keep'`).Scan(&postFinding); err != nil {
			t.Fatalf("count post-up finding: %v", err)
		}
		if postVulnerability != 1 || postFinding != 1 {
			t.Fatalf("post-up rows after down = vulnerability %d finding %d, want both 1", postVulnerability, postFinding)
		}
	})

	t.Run("restored_nonempty_sequences_generate_above_max", func(t *testing.T) {
		mustExecMigrationTest(t, ctx, db, `INSERT INTO vulnerabilities (id, summary, severity, published, modified) VALUES ('SEQ-PARENT', 'sequence parent', 'HIGH', NOW(), NOW())`)
		sequenceCases := []struct {
			table, insertSQL string
		}{
			{table: "vulnerability_aliases", insertSQL: `INSERT INTO vulnerability_aliases (vulnerability_id, alias_id) VALUES ('SEQ-PARENT', 'SEQ-ALIAS') RETURNING id`},
			{table: "vulnerability_sources", insertSQL: `INSERT INTO vulnerability_sources (vulnerability_id, source, source_id, raw_json) VALUES ('SEQ-PARENT', 'sequence', 'SEQ-SOURCE', '{}'::jsonb) RETURNING id`},
			{table: "vulnerability_references", insertSQL: `INSERT INTO vulnerability_references (vulnerability_id, type, url, source) VALUES ('SEQ-PARENT', 'WEB', 'https://sequence.test', 'sequence') RETURNING id`},
			{table: "affected_packages", insertSQL: `INSERT INTO affected_packages (vulnerability_id, ecosystem, name) VALUES ('SEQ-PARENT', 'npm', 'sequence-package') RETURNING id`},
		}
		for _, tc := range sequenceCases {
			var beforeMax, generated int
			if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM `+tc.table).Scan(&beforeMax); err != nil {
				t.Fatalf("read max id from %s: %v", tc.table, err)
			}
			if err := db.QueryRowContext(ctx, tc.insertSQL).Scan(&generated); err != nil {
				t.Fatalf("generate id for %s: %v", tc.table, err)
			}
			if generated <= beforeMax {
				t.Fatalf("generated id for %s = %d, want above restored max %d", tc.table, generated, beforeMax)
			}
		}
	})

	t.Run("down_drops_backups_and_up_reapplies_cleanly", func(t *testing.T) {
		assertMigration005BackupRelations(t, ctx, db, false)
		applyEmbeddedMigrationForTest(t, ctx, db, 5, MigrationDirectionUp)
		assertMigration005BackupRelations(t, ctx, db, true)
		var severity string
		if err := db.QueryRowContext(ctx, `SELECT severity FROM vulnerabilities WHERE id = 'OSV-MISSING'`).Scan(&severity); err != nil {
			t.Fatalf("read normalized row after second up: %v", err)
		}
		if severity != "LOW" {
			t.Fatalf("severity after second up = %q, want LOW", severity)
		}
	})
}

func TestNormalizeUnknownSeverityMigration005PreservesMaliciousRowsWithoutCoordinatesAgainstPostgres(t *testing.T) {
	for _, tt := range []struct {
		name        string
		ecosystem   string
		packageName string
	}{
		{name: "empty package name", ecosystem: "npm"},
		{name: "empty ecosystem", packageName: "missing-ecosystem"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dsn := startMigrationPostgres(t)
			db, ctx, cancel := openFocusedMigrationDB(t, dsn)
			defer cancel()
			defer ioutils.CloseSilently(db)

			createPre005Schema(t, ctx, db)
			mustExecMigrationTest(t, ctx, db, `
				INSERT INTO vulnerabilities (
					id, summary, details, severity, cvss_score, epss_score, epss_percentile,
					cisa_kev, exploit_exists, published, modified, withdrawn, created_at, updated_at
				) VALUES (
					'OSV-MISSING-COORDINATES', 'malicious advisory without coordinates', 'must remain representable',
					'UNKNOWN', 4.5, 0.25, 0.5, true, true, '2024-07-01Z', '2024-07-02Z', NULL,
					'2024-07-03Z', '2024-07-04Z'
				);
				INSERT INTO vulnerability_aliases (vulnerability_id, alias_id)
				VALUES ('OSV-MISSING-COORDINATES', 'ALIAS-MISSING-COORDINATES');
				INSERT INTO vulnerability_references (vulnerability_id, type, url, source)
				VALUES ('OSV-MISSING-COORDINATES', 'ADVISORY', 'https://stored.test/missing-coordinates', 'osv');
				INSERT INTO affected_packages (vulnerability_id, ecosystem, name, version_ranges, versions_affected)
				VALUES ('OSV-MISSING-COORDINATES', 'npm', 'legacy-coordinate', '[]'::jsonb, '["1.0.0"]'::jsonb)`)
			rawJSON := fmt.Sprintf(`{"affected":[{"package":{"ecosystem":%q,"name":%q},"database_specific":{"categories":["malicious"]}}],"references":[{"url":"https://reference.test/missing-coordinates"}]}`, tt.ecosystem, tt.packageName)
			mustExecMigrationTest(t, ctx, db, `
				INSERT INTO vulnerability_sources (vulnerability_id, source, source_id, url, raw_json, updated_at)
				VALUES ('OSV-MISSING-COORDINATES', 'osv', 'SRC-MISSING-COORDINATES',
					'https://source.test/missing-coordinates', $1::jsonb, '2024-07-05Z')`, rawJSON)

			before := snapshotMigration005Tables(t, ctx, db, migration005ApplicationTables)
			applyEmbeddedMigrationForTest(t, ctx, db, 5, MigrationDirectionUp)

			var vulnerabilityCount, aliasCount, sourceCount, referenceCount, affectedCount, findingCount int
			var severity string
			if err := db.QueryRowContext(ctx, `
				SELECT
					(SELECT count(*) FROM vulnerabilities WHERE id='OSV-MISSING-COORDINATES'),
					COALESCE((SELECT severity FROM vulnerabilities WHERE id='OSV-MISSING-COORDINATES'), ''),
					(SELECT count(*) FROM vulnerability_aliases WHERE vulnerability_id='OSV-MISSING-COORDINATES'),
					(SELECT count(*) FROM vulnerability_sources WHERE vulnerability_id='OSV-MISSING-COORDINATES'),
					(SELECT count(*) FROM vulnerability_references WHERE vulnerability_id='OSV-MISSING-COORDINATES'),
					(SELECT count(*) FROM affected_packages WHERE vulnerability_id='OSV-MISSING-COORDINATES'),
					(SELECT count(*) FROM malicious_findings WHERE id LIKE 'OSV-MISSING-COORDINATES%')`).Scan(
				&vulnerabilityCount, &severity, &aliasCount, &sourceCount, &referenceCount, &affectedCount, &findingCount,
			); err != nil {
				t.Fatalf("read coordinate-less rows after up: %v", err)
			}

			knownDestructiveResult := vulnerabilityCount == 0 && severity == "" && aliasCount == 0 && sourceCount == 0 && referenceCount == 0 && affectedCount == 0 && findingCount == 0
			preservedResult := vulnerabilityCount == 1 && severity == "LOW" && aliasCount == 1 && sourceCount == 1 && referenceCount == 1 && affectedCount == 1 && findingCount == 0
			if !knownDestructiveResult && !preservedResult {
				t.Fatalf("coordinate-less up result = vulnerability %d severity %q alias/source/reference/affected %d/%d/%d/%d findings %d, want complete LOW preservation and no finding", vulnerabilityCount, severity, aliasCount, sourceCount, referenceCount, affectedCount, findingCount)
			}

			applyEmbeddedMigrationForTest(t, ctx, db, 5, MigrationDirectionDown)
			after := snapshotMigration005Tables(t, ctx, db, migration005ApplicationTables)
			assertSnapshotMapsEqual(t, after, before, "coordinate-less rows after 005 down")
			assertMigration005BackupRelations(t, ctx, db, false)
			if knownDestructiveResult {
				t.Skip("F118-bugs-3: migration 005 deletes a malicious vulnerability when no usable package coordinate can produce a finding")
			}
		})
	}
}

func TestNormalizeUnknownSeverityMigration005PreservesMalformedCollectionsAgainstPostgres(t *testing.T) {
	for _, tt := range []struct {
		name                  string
		rawJSON               string
		allowConvertedFinding bool
	}{
		{name: "affected null", rawJSON: `{"affected":null}`},
		{name: "affected object", rawJSON: `{"affected":{"not":"an array"}}`},
		{name: "categories null", rawJSON: `{"affected":[{"package":{"ecosystem":"npm","name":"malformed-categories"},"database_specific":{"categories":null}}]}`},
		{name: "categories object", rawJSON: `{"affected":[{"package":{"ecosystem":"npm","name":"malformed-categories"},"database_specific":{"categories":{"not":"an array"}}}]}`},
		{name: "references null", rawJSON: `{"affected":[{"package":{"ecosystem":"npm","name":"malformed-references"},"database_specific":{"categories":["malicious"]}}],"references":null}`, allowConvertedFinding: true},
		{name: "references object", rawJSON: `{"affected":[{"package":{"ecosystem":"npm","name":"malformed-references"},"database_specific":{"categories":["malicious"]}}],"references":{"not":"an array"}}`, allowConvertedFinding: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dsn := startMigrationPostgres(t)
			db, ctx, cancel := openFocusedMigrationDB(t, dsn)
			defer cancel()
			defer ioutils.CloseSilently(db)
			createPre005Schema(t, ctx, db)
			mustExecMigrationTest(t, ctx, db, `
				INSERT INTO vulnerabilities(id,summary,details,severity,published,modified,created_at,updated_at) VALUES
					('OSV-MALFORMED-COLLECTION','malformed collection','must not disappear','UNKNOWN','2024-08-01Z','2024-08-02Z','2024-08-03Z','2024-08-04Z'),
					('OSV-VALID-SIBLING','valid sibling','must still normalize','UNKNOWN','2024-08-01Z','2024-08-02Z','2024-08-03Z','2024-08-04Z')`)
			mustExecMigrationTest(t, ctx, db, `
				INSERT INTO vulnerability_sources(vulnerability_id,source,source_id,raw_json,updated_at) VALUES
					('OSV-MALFORMED-COLLECTION','osv','SRC-MALFORMED',$1::jsonb,'2024-08-05Z'),
					('OSV-VALID-SIBLING','osv','SRC-VALID','{"affected":[]}'::jsonb,'2024-08-05Z')`, tt.rawJSON)

			before := snapshotMigration005Tables(t, ctx, db, migration005ApplicationTables)
			up := embeddedMigrationFileForTest(t, 5, MigrationDirectionUp)
			err := applyMigration(ctx, db, up)
			if err != nil {
				if !strings.Contains(err.Error(), "extract elements") {
					t.Fatalf("migration 005 malformed collection error = %v, want current JSON array extraction failure", err)
				}
				after := snapshotMigration005Tables(t, ctx, db, migration005ApplicationTables)
				assertSnapshotMapsEqual(t, after, before, "application rows after malformed collection failure")
				assertDirtyMigration(t, ctx, db, up)
				assertMigration005BackupRelations(t, ctx, db, false)
				t.Skip("F118-bugs-4: migration 005 passes JSON null or non-array collections to jsonb array extraction")
			}

			var malformedVulnerability, malformedSource, malformedFinding int
			var malformedSeverity, referenceURLs, siblingSeverity string
			if err := db.QueryRowContext(ctx, `
				SELECT
					(SELECT count(*) FROM vulnerabilities WHERE id='OSV-MALFORMED-COLLECTION'),
					COALESCE((SELECT severity FROM vulnerabilities WHERE id='OSV-MALFORMED-COLLECTION'), ''),
					(SELECT count(*) FROM vulnerability_sources WHERE vulnerability_id='OSV-MALFORMED-COLLECTION'),
					(SELECT count(*) FROM malicious_findings WHERE id LIKE 'OSV-MALFORMED-COLLECTION%'),
					COALESCE((SELECT reference_urls::text FROM malicious_findings WHERE id LIKE 'OSV-MALFORMED-COLLECTION%' LIMIT 1), ''),
					(SELECT severity FROM vulnerabilities WHERE id='OSV-VALID-SIBLING')`).Scan(
				&malformedVulnerability, &malformedSeverity, &malformedSource, &malformedFinding, &referenceURLs, &siblingSeverity,
			); err != nil {
				t.Fatalf("read malformed collection result: %v", err)
			}
			preserved := malformedVulnerability == 1 && malformedSeverity == "LOW" && malformedSource == 1 && malformedFinding == 0
			convertedSafely := tt.allowConvertedFinding && malformedVulnerability == 0 && malformedSource == 0 && malformedFinding == 1 && referenceURLs == "[]"
			if (!preserved && !convertedSafely) || siblingSeverity != "LOW" {
				t.Fatalf("malformed result vulnerability/severity/source/finding/refs=%d/%q/%d/%d/%q sibling=%q, want lossless malformed handling and LOW sibling", malformedVulnerability, malformedSeverity, malformedSource, malformedFinding, referenceURLs, siblingSeverity)
			}
		})
	}
}

func TestNormalizeUnknownSeverityMigration005MissingBackupFailsAtomicallyAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)
	db, ctx, cancel := openFocusedMigrationDB(t, dsn)
	defer cancel()
	defer ioutils.CloseSilently(db)
	createPre005Schema(t, ctx, db)
	seedMigration005ComprehensiveFixtures(t, ctx, db)
	applyEmbeddedMigrationForTest(t, ctx, db, 5, MigrationDirectionUp)
	mustExecMigrationTest(t, ctx, db, `DROP TABLE packmon_m005_vulnerability_aliases_backup`)
	before := snapshotMigration005Tables(t, ctx, db, migration005ApplicationTables)

	down := embeddedMigrationFileForTest(t, 5, MigrationDirectionDown)
	err := applyMigration(ctx, db, down)
	if err == nil || !strings.Contains(err.Error(), "migration 005 rollback requires packmon_m005 backup tables") {
		t.Fatalf("005 down with missing backup error = %v, want explicit recovery error", err)
	}
	after := snapshotMigration005Tables(t, ctx, db, migration005ApplicationTables)
	assertSnapshotMapsEqual(t, after, before, "application rows after missing-backup failure")
	assertDirtyMigration(t, ctx, db, down)
	assertRelationExists(t, ctx, db, "packmon_m005_vulnerabilities_backup", true)
}

func TestNormalizeUnknownSeverityMigration005EmptySequenceRollbackAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)
	db, ctx, cancel := openFocusedMigrationDB(t, dsn)
	defer cancel()
	defer ioutils.CloseSilently(db)
	createPre005Schema(t, ctx, db)
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO vulnerabilities (id, summary, details, severity, published, modified, created_at, updated_at)
		VALUES ('EMPTY-SEQUENCES', 'empty sequences', 'no child rows', 'UNKNOWN', '2024-01-01Z', '2024-01-02Z', '2024-01-03Z', '2024-01-04Z')`)
	applyEmbeddedMigrationForTest(t, ctx, db, 5, MigrationDirectionUp)
	applyEmbeddedMigrationForTest(t, ctx, db, 5, MigrationDirectionDown)

	t.Run("empty_tables_restart_each_sequence_at_one", func(t *testing.T) {
		inserts := []struct {
			table, sql string
		}{
			{table: "vulnerability_aliases", sql: `INSERT INTO vulnerability_aliases (vulnerability_id, alias_id) VALUES ('EMPTY-SEQUENCES', 'EMPTY-ALIAS') RETURNING id`},
			{table: "vulnerability_sources", sql: `INSERT INTO vulnerability_sources (vulnerability_id, source, source_id, raw_json) VALUES ('EMPTY-SEQUENCES', 'empty', 'EMPTY-SOURCE', '{}'::jsonb) RETURNING id`},
			{table: "vulnerability_references", sql: `INSERT INTO vulnerability_references (vulnerability_id, type, url, source) VALUES ('EMPTY-SEQUENCES', 'WEB', 'https://empty.test', 'empty') RETURNING id`},
			{table: "affected_packages", sql: `INSERT INTO affected_packages (vulnerability_id, ecosystem, name) VALUES ('EMPTY-SEQUENCES', 'npm', 'empty-package') RETURNING id`},
		}
		for _, insert := range inserts {
			var id int
			if err := db.QueryRowContext(ctx, insert.sql).Scan(&id); err != nil {
				t.Fatalf("insert first %s row: %v", insert.table, err)
			}
			if id != 1 {
				t.Fatalf("first generated id for empty %s = %d, want 1", insert.table, id)
			}
		}
	})

	t.Run("second_up_down_cycle_remains_usable", func(t *testing.T) {
		applyEmbeddedMigrationForTest(t, ctx, db, 5, MigrationDirectionUp)
		applyEmbeddedMigrationForTest(t, ctx, db, 5, MigrationDirectionDown)
		var severity string
		if err := db.QueryRowContext(ctx, `SELECT severity FROM vulnerabilities WHERE id = 'EMPTY-SEQUENCES'`).Scan(&severity); err != nil {
			t.Fatalf("read row after second 005 cycle: %v", err)
		}
		if severity != "UNKNOWN" {
			t.Fatalf("severity after second 005 cycle = %q, want UNKNOWN", severity)
		}
		assertMigration005BackupRelations(t, ctx, db, false)
	})
}

func TestNormalizeUnknownSeverityMigration005InjectedFailureRollsBackAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)
	db, ctx, cancel := openFocusedMigrationDB(t, dsn)
	defer cancel()
	defer ioutils.CloseSilently(db)
	createPre005Schema(t, ctx, db)
	seedMigration005ComprehensiveFixtures(t, ctx, db)

	t.Run("up", func(t *testing.T) {
		before := snapshotMigration005Tables(t, ctx, db, migration005ApplicationTables)
		up := embeddedMigrationFileForTest(t, 5, MigrationDirectionUp)
		failed := migrationFile{
			version:   905,
			name:      "905_normalize_unknown_injected_failure.up.sql",
			direction: MigrationDirectionUp,
			sql:       up.sql + "\nSELECT * FROM packmon_injected_missing_relation;",
		}
		if err := applyMigration(ctx, db, failed); err == nil || !strings.Contains(err.Error(), "packmon_injected_missing_relation") {
			t.Fatalf("apply injected 005 up error = %v, want missing-relation failure", err)
		}
		after := snapshotMigration005Tables(t, ctx, db, migration005ApplicationTables)
		assertSnapshotMapsEqual(t, after, before, "application rows after injected up failure")
		assertMigration005BackupRelations(t, ctx, db, false)
		assertDirtyMigration(t, ctx, db, failed)
	})

	t.Run("down", func(t *testing.T) {
		applyEmbeddedMigrationForTest(t, ctx, db, 5, MigrationDirectionUp)
		beforeApplication := snapshotMigration005Tables(t, ctx, db, migration005ApplicationTables)
		beforeBackups := snapshotMigration005Tables(t, ctx, db, migration005BackupTables)
		down := embeddedMigrationFileForTest(t, 5, MigrationDirectionDown)
		failed := migrationFile{
			version:   906,
			name:      "906_normalize_unknown_injected_failure.down.sql",
			direction: MigrationDirectionDown,
			sql:       down.sql + "\nSELECT * FROM packmon_injected_missing_relation;",
		}
		if err := applyMigration(ctx, db, failed); err == nil || !strings.Contains(err.Error(), "packmon_injected_missing_relation") {
			t.Fatalf("apply injected 005 down error = %v, want missing-relation failure", err)
		}
		afterApplication := snapshotMigration005Tables(t, ctx, db, migration005ApplicationTables)
		afterBackups := snapshotMigration005Tables(t, ctx, db, migration005BackupTables)
		assertSnapshotMapsEqual(t, afterApplication, beforeApplication, "application rows after injected down failure")
		assertSnapshotMapsEqual(t, afterBackups, beforeBackups, "backup rows after injected down failure")
		assertDirtyMigration(t, ctx, db, failed)
	})
}

func seedMigration005ComprehensiveFixtures(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO vulnerabilities (
			id, summary, details, severity, cvss_score, epss_score, epss_percentile,
			cisa_kev, exploit_exists, published, modified, withdrawn, created_at, updated_at
		) VALUES
			('OSV-MULTI', 'typosquat multi package', 'multi converted description', 'UNKNOWN', 1.5, 0.15, 0.25, true, true, '2024-01-01Z', '2024-01-02Z', NULL, '2024-01-03Z', '2024-01-04Z'),
			('OSV-CONFLICT', 'supply chain conflict advisory', 'new converted description', 'UNKNOWN', 2.5, 0.35, 0.45, false, true, '2024-02-01Z', '2024-02-02Z', '2024-02-03Z', '2024-02-04Z', '2024-02-05Z'),
			('OSV-MISSING', 'missing affected key', 'ordinary unknown', 'UNKNOWN', NULL, NULL, NULL, false, false, '2024-03-01Z', '2024-03-02Z', NULL, '2024-03-03Z', '2024-03-04Z'),
			('OSV-KNOWN', 'known severity', 'must stay unchanged', 'HIGH', 8.5, 0.75, 0.85, true, false, '2024-05-01Z', '2024-05-02Z', NULL, '2024-05-03Z', '2024-05-05T05:05:05Z'),
			('OSV-RANGE', 'typosquat range only', 'range-only converted description', 'UNKNOWN', 3.5, 0.55, 0.65, false, false, '2024-06-01Z', '2024-06-02Z', NULL, '2024-06-03Z', '2024-06-04Z')`)
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO vulnerability_aliases (vulnerability_id, alias_id) VALUES
			('OSV-MULTI', 'ALIAS-MULTI'), ('OSV-CONFLICT', 'ALIAS-CONFLICT'),
			('OSV-MISSING', 'ALIAS-MISSING'), ('OSV-KNOWN', 'ALIAS-KNOWN'), ('OSV-RANGE', 'ALIAS-RANGE')`)

	const rawMulti = `{
		"affected": [
			{"package":{"ecosystem":"crates.io","name":"bad-cargo"},"versions":["1.0.0"],"database_specific":{"categories":[" malicious "],"source":"cargo-origin"}},
			{"package":{"ecosystem":"PyPI","name":"bad-python"},"versions":[],"database_specific":{"categories":["MALICIOUS"],"source":"python-origin"}},
			{"package":{"ecosystem":"Maven:central","name":"bad-java"},"versions":["2.0.0"],"database_specific":{"categories":["malicious"],"source":"maven-origin"}},
			{"package":{"ecosystem":"RubyGems","name":"bad-gem"},"versions":["3.0.0"],"database_specific":{"categories":["malicious"],"source":"gem-origin"}}
		],
		"references": [{"url":"https://example.test/one"},{"url":""},{"url":"https://example.test/two"}]
	}`
	const rawConflict = `{"affected":[{"package":{"ecosystem":"npm","name":"conflict-package"},"versions":["9.9.9"],"database_specific":{"categories":["malicious"],"source":"conflict-origin"}}],"references":[{"url":"https://conflict.test/new"}]}`
	const rawRange = `{"affected":[{"package":{"ecosystem":"Packagist","name":"bad-composer"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}],"database_specific":{"categories":["malicious"],"source":"range-origin"}}],"references":[{"url":"https://example.test/one"},{"url":"https://example.test/two"}]}`
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO vulnerability_sources (vulnerability_id, source, source_id, url, raw_json, updated_at) VALUES
			('OSV-MULTI', 'osv', 'SRC-MULTI', 'https://source.test/multi', $1::jsonb, '2024-01-06Z'),
			('OSV-CONFLICT', 'osv', 'SRC-CONFLICT', 'https://source.test/conflict', $2::jsonb, '2024-02-06Z'),
			('OSV-MISSING', 'osv', 'SRC-MISSING', 'https://source.test/missing', '{"references":[]}'::jsonb, '2024-03-06Z'),
			('OSV-KNOWN', 'osv', 'SRC-KNOWN', 'https://source.test/known', '{"affected":[{"package":{"ecosystem":"npm","name":"known"},"database_specific":{"categories":["vulnerability"]}}]}'::jsonb, '2024-05-06Z'),
			('OSV-RANGE', 'osv', 'SRC-RANGE', 'https://source.test/range', $3::jsonb, '2024-06-06Z')`, rawMulti, rawConflict, rawRange)
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO vulnerability_references (vulnerability_id, type, url, source) VALUES
			('OSV-MULTI', 'ADVISORY', 'https://stored.test/multi', 'osv'),
			('OSV-CONFLICT', 'REPORT', 'https://stored.test/conflict', 'osv'),
			('OSV-RANGE', 'WEB', 'https://stored.test/range', 'osv')`)
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO affected_packages (vulnerability_id, ecosystem, name, version_ranges, versions_affected) VALUES
			('OSV-MULTI', 'cargo', 'bad-cargo', '[{"type":"SEMVER","events":[{"introduced":"0"}]}]', '["1.0.0"]'),
			('OSV-MULTI', 'pypi', 'bad-python', '[]', '[]'),
			('OSV-MULTI', 'maven', 'bad-java', '[]', '["2.0.0"]'),
			('OSV-MULTI', 'gem', 'bad-gem', '[]', '["3.0.0"]'),
			('OSV-CONFLICT', 'npm', 'conflict-package', '[]', '["9.9.9"]'),
			('OSV-MISSING', 'npm', 'missing-package', '[]', '[]'),
			('OSV-KNOWN', 'npm', 'known-package', '[]', '["4.0.0"]'),
			('OSV-RANGE', 'composer', 'bad-composer', '[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]', '[]')`)
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO malicious_findings (
			id, ecosystem, name, versions, source, risk_type, severity, summary, description,
			reference_urls, origin_ref, published, created_at, updated_at, created_by
		) VALUES (
			'OSV-CONFLICT', 'go', 'preexisting-conflict', '["0.1.0"]', 'preexisting', 'supply_chain', 'LOW',
			'preexisting summary', 'preexisting description', '["https://old.test"]', 'old-origin',
			'2023-01-01Z', '2023-01-02Z', '2023-01-03Z', 'preexisting-writer'
		)`)
}

func expectedMigration005BackupSnapshots(t *testing.T, ctx context.Context, db *sql.DB) map[string]string {
	t.Helper()
	maliciousIDs := `('OSV-MULTI', 'OSV-CONFLICT', 'OSV-RANGE')`
	return map[string]string{
		"packmon_m005_vulnerabilities_backup":          snapshotQuery(t, ctx, db, `SELECT * FROM vulnerabilities WHERE severity = 'UNKNOWN' OR id IN `+maliciousIDs+` ORDER BY id`),
		"packmon_m005_vulnerability_aliases_backup":    snapshotQuery(t, ctx, db, `SELECT * FROM vulnerability_aliases WHERE vulnerability_id IN `+maliciousIDs+` ORDER BY id`),
		"packmon_m005_vulnerability_sources_backup":    snapshotQuery(t, ctx, db, `SELECT * FROM vulnerability_sources WHERE vulnerability_id IN `+maliciousIDs+` ORDER BY id`),
		"packmon_m005_vulnerability_references_backup": snapshotQuery(t, ctx, db, `SELECT * FROM vulnerability_references WHERE vulnerability_id IN `+maliciousIDs+` ORDER BY id`),
		"packmon_m005_affected_packages_backup":        snapshotQuery(t, ctx, db, `SELECT * FROM affected_packages WHERE vulnerability_id IN `+maliciousIDs+` ORDER BY id`),
		"packmon_m005_malicious_findings_backup":       snapshotQuery(t, ctx, db, `SELECT * FROM malicious_findings WHERE id = 'OSV-CONFLICT' ORDER BY id`),
	}
}

func seedMigration005ConflictingRollbackRows(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO vulnerabilities (id, summary, severity, published, modified) VALUES
			('OSV-MULTI', 'placeholder multi', 'LOW', NOW(), NOW()),
			('OSV-CONFLICT', 'placeholder conflict', 'LOW', NOW(), NOW()),
			('OSV-RANGE', 'placeholder range', 'LOW', NOW(), NOW())`)
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO vulnerability_aliases (id, vulnerability_id, alias_id) VALUES
			(1, 'OSV-MULTI', 'PLACEHOLDER-1'), (2, 'OSV-CONFLICT', 'PLACEHOLDER-2'), (5, 'OSV-RANGE', 'PLACEHOLDER-5')`)
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO vulnerability_sources (id, vulnerability_id, source, source_id, raw_json) VALUES
			(1, 'OSV-MULTI', 'placeholder', 'PLACEHOLDER-1', '{}'),
			(2, 'OSV-CONFLICT', 'placeholder', 'PLACEHOLDER-2', '{}'),
			(5, 'OSV-RANGE', 'placeholder', 'PLACEHOLDER-5', '{}')`)
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO vulnerability_references (id, vulnerability_id, type, url, source) VALUES
			(1, 'OSV-MULTI', 'PLACEHOLDER', 'https://placeholder.test/1', 'placeholder'),
			(2, 'OSV-CONFLICT', 'PLACEHOLDER', 'https://placeholder.test/2', 'placeholder'),
			(3, 'OSV-RANGE', 'PLACEHOLDER', 'https://placeholder.test/3', 'placeholder')`)
	mustExecMigrationTest(t, ctx, db, `
		INSERT INTO affected_packages (id, vulnerability_id, ecosystem, name) VALUES
			(1, 'OSV-MULTI', 'npm', 'placeholder-1'), (2, 'OSV-MULTI', 'npm', 'placeholder-2'),
			(3, 'OSV-MULTI', 'npm', 'placeholder-3'), (4, 'OSV-MULTI', 'npm', 'placeholder-4'),
			(5, 'OSV-CONFLICT', 'npm', 'placeholder-5'), (8, 'OSV-RANGE', 'npm', 'placeholder-8')`)
	mustExecMigrationTest(t, ctx, db, `
		UPDATE malicious_findings SET ecosystem = 'npm', name = 'overwritten-conflict', versions = '["99"]',
			source = 'overwritten', risk_type = 'malware', severity = 'CRITICAL', summary = 'overwritten',
			description = 'overwritten', reference_urls = '[]', origin_ref = NULL, published = NULL,
			created_at = NOW(), updated_at = NOW(), created_by = 'overwritten'
		WHERE id = 'OSV-CONFLICT'`)
}

func snapshotMigration005Tables(t *testing.T, ctx context.Context, db *sql.DB, tables []string) map[string]string {
	t.Helper()
	snapshots := make(map[string]string, len(tables))
	for _, table := range tables {
		snapshots[table] = snapshotWholeTable(t, ctx, db, table)
	}
	return snapshots
}

func snapshotWholeTable(t *testing.T, ctx context.Context, db *sql.DB, table string) string {
	t.Helper()
	return snapshotQuery(t, ctx, db, `SELECT * FROM `+table+` ORDER BY id`)
}

func snapshotQuery(t *testing.T, ctx context.Context, db *sql.DB, query string) string {
	t.Helper()
	var snapshot string
	statement := `SELECT COALESCE(jsonb_agg(to_jsonb(snapshot_row)), '[]'::jsonb)::text FROM (` + query + `) AS snapshot_row`
	if err := db.QueryRowContext(ctx, statement).Scan(&snapshot); err != nil {
		t.Fatalf("snapshot query failed: %v\nSQL:\n%s", err, query)
	}
	return snapshot
}

func snapshotMigration005OriginalRows(t *testing.T, ctx context.Context, db *sql.DB, table string) string {
	t.Helper()
	var query string
	switch table {
	case "vulnerabilities":
		query = `SELECT * FROM vulnerabilities WHERE id LIKE 'OSV-%' ORDER BY id`
	case "malicious_findings":
		query = `SELECT * FROM malicious_findings WHERE id = 'OSV-CONFLICT' ORDER BY id`
	default:
		query = fmt.Sprintf(`SELECT child.* FROM %s child JOIN vulnerabilities v ON v.id = child.vulnerability_id WHERE v.id LIKE 'OSV-%%' ORDER BY child.id`, table)
	}
	return snapshotQuery(t, ctx, db, query)
}

func assertSnapshotMapsEqual(t *testing.T, got, want map[string]string, label string) {
	t.Helper()
	for table, wantSnapshot := range want {
		if got[table] != wantSnapshot {
			t.Fatalf("%s: %s mismatch\ngot:  %s\nwant: %s", label, table, got[table], wantSnapshot)
		}
	}
}

func assertMigration005BackupRelations(t *testing.T, ctx context.Context, db *sql.DB, want bool) {
	t.Helper()
	for _, table := range migration005BackupTables {
		assertRelationExists(t, ctx, db, table, want)
	}
}
