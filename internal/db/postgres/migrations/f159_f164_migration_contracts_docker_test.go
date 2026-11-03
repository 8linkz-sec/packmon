//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	packmondb "github.com/8linkz-sec/packmon/internal/db"
	postgresstore "github.com/8linkz-sec/packmon/internal/db/postgres"
	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type f159F164Leaf struct {
	ctx    context.Context
	conn   *sql.Conn
	dsn    string
	schema string
}

type f159F164ScanCandidate struct {
	scanID         string
	requestDigest  string
	resultDigest   string
	packages       int
	findings       int
	idempotencyKey string
}

func TestF159F164MigrationContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	database, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(database)
	database.SetMaxOpenConns(6)

	extensionCtx, cancelExtension := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelExtension()
	if _, err := database.ExecContext(extensionCtx, `CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public`); err != nil {
		t.Fatalf("install pg_trgm once in public: %v", err)
	}

	leafNumber := 0
	newLeaf := func(t *testing.T) f159F164Leaf {
		t.Helper()
		leafNumber++
		return f159F164PrepareLeaf(t, database, instance.dsn, leafNumber)
	}

	t.Run("migration_026", func(t *testing.T) {
		t.Run("populated_025_upgrade_catalog_defaults_and_constraints", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 25)
			f159F164SeedLegacyScans(t, leaf)
			before := f159F164ScanSurvivingSnapshot(t, leaf)

			f159F164Apply(t, leaf, 26, MigrationDirectionUp)
			f159F164Assert026Catalog(t, leaf)
			f159F164AssertEqual(t, "legacy scan fields after 026 up", f159F164ScanSurvivingSnapshot(t, leaf), before)
			var nullKeys, emptyDigests int
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FILTER (WHERE idempotency_key IS NULL),COUNT(*) FILTER (WHERE request_digest='') FROM scan_log`).Scan(&nullKeys, &emptyDigests); err != nil {
				t.Fatalf("inspect 026 backfill defaults: %v", err)
			}
			if nullKeys != 2 || emptyDigests != 2 {
				t.Fatalf("026 backfill = null keys:%d empty digests:%d, want 2/2", nullKeys, emptyDigests)
			}

			_, err := leaf.conn.ExecContext(leaf.ctx, `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,idempotency_key,request_digest) VALUES ('null-digest',1,1,1,'null-digest-key',NULL)`)
			f159F164ExpectSQLState(t, err, "23502")
			f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,idempotency_key,request_digest) VALUES ('unique-a',1,1,1,'same-key','digest-a')`)
			_, err = leaf.conn.ExecContext(leaf.ctx, `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,idempotency_key,request_digest) VALUES ('unique-b',1,1,1,'same-key','digest-b')`)
			f159F164ExpectSQLState(t, err, "23505")
		})

		t.Run("partial_object_replay_preserves_index_identity", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 25)
			f159F164Exec(t, leaf, `ALTER TABLE scan_log ADD COLUMN idempotency_key TEXT,ADD COLUMN request_digest TEXT NOT NULL DEFAULT ''; CREATE UNIQUE INDEX idx_scan_log_idempotency_key ON scan_log(idempotency_key) WHERE idempotency_key IS NOT NULL`)
			f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,idempotency_key,request_digest) VALUES ('partial',2,1,5,'partial-key','partial-digest')`)
			beforeIndex := f159F164IndexIdentity(t, leaf, "idx_scan_log_idempotency_key")
			beforeRows := f159F164Scan026Snapshot(t, leaf)

			f159F164Apply(t, leaf, 26, MigrationDirectionUp)
			f159F164Assert026Catalog(t, leaf)
			if got := f159F164IndexIdentity(t, leaf, "idx_scan_log_idempotency_key"); got != beforeIndex {
				t.Fatalf("026 replay replaced index: got %q, want %q", got, beforeIndex)
			}
			f159F164AssertEqual(t, "scan rows after 026 partial replay", f159F164Scan026Snapshot(t, leaf), beforeRows)
		})

		t.Run("concurrent_same_key_writes_one_row_and_one_totals_contribution", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 43)
			store, err := postgresstore.New(leaf.ctx, leaf.dsn, nil, &postgresstore.PoolConfig{MaxConns: 4, MinConns: 2})
			if err != nil {
				t.Fatalf("postgres.New() error = %v", err)
			}
			t.Cleanup(func() { _ = store.Close() })

			candidates := []f159F164ScanCandidate{
				{scanID: "f160-concurrent-a", requestDigest: "request-a", resultDigest: "result-a", packages: 7, findings: 2, idempotencyKey: "f160-shared-key"},
				{scanID: "f160-concurrent-b", requestDigest: "request-b", resultDigest: "result-b", packages: 11, findings: 5, idempotencyKey: "f160-shared-key"},
			}
			writeCtx, cancel := context.WithTimeout(leaf.ctx, 10*time.Second)
			defer cancel()
			ready := make(chan struct{}, len(candidates))
			start := make(chan struct{})
			results := make(chan error, len(candidates))
			for _, candidate := range candidates {
				candidate := candidate
				go func() {
					ready <- struct{}{}
					select {
					case <-start:
					case <-writeCtx.Done():
						results <- writeCtx.Err()
						return
					}
					results <- store.InsertScanLog(writeCtx, &packmondb.ScanLogEntry{
						ScanID: candidate.scanID, ScannedAt: time.Now().UTC(), PackagesCount: candidate.packages,
						FindingsCount: candidate.findings, DurationMs: 1, IdempotencyKey: candidate.idempotencyKey,
						RequestDigest: candidate.requestDigest, ResultDigest: candidate.resultDigest,
						BlockThreshold: "CRITICAL", FeedStatus: "healthy",
					})
				}()
			}
			for range candidates {
				select {
				case <-ready:
				case <-writeCtx.Done():
					t.Fatalf("workers did not reach ready barrier: %v", writeCtx.Err())
				}
			}
			close(start)
			for range candidates {
				select {
				case err := <-results:
					if err != nil {
						t.Fatalf("concurrent InsertScanLog() error = %v", err)
					}
				case <-writeCtx.Done():
					t.Fatalf("concurrent InsertScanLog() join timed out: %v", writeCtx.Err())
				}
			}

			var scanID, requestDigest, resultDigest string
			var packages, findings, rows int
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT MIN(scan_id),MIN(request_digest),MIN(result_digest),MIN(packages_count),MIN(findings_count),COUNT(*) FROM scan_log WHERE idempotency_key='f160-shared-key'`).Scan(&scanID, &requestDigest, &resultDigest, &packages, &findings, &rows); err != nil {
				t.Fatalf("read concurrent winner: %v", err)
			}
			if rows != 1 {
				t.Fatalf("durable same-key rows = %d, want 1", rows)
			}
			var winner *f159F164ScanCandidate
			for i := range candidates {
				if candidates[i].scanID == scanID {
					winner = &candidates[i]
				}
			}
			if winner == nil {
				t.Fatalf("durable scan_id %q is not a submitted candidate", scanID)
			}
			if requestDigest != winner.requestDigest || resultDigest != winner.resultDigest || packages != winner.packages || findings != winner.findings {
				t.Fatalf("durable winner = scan:%q request:%q result:%q packages:%d findings:%d, want %+v", scanID, requestDigest, resultDigest, packages, findings, *winner)
			}
			var totalPackages, totalFindings int64
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT packages_scanned,findings FROM scan_log_totals`).Scan(&totalPackages, &totalFindings); err != nil {
				t.Fatalf("read scan totals: %v", err)
			}
			if totalPackages != int64(winner.packages) || totalFindings != int64(winner.findings) {
				t.Fatalf("scan totals = packages:%d findings:%d, want winner-derived %d/%d", totalPackages, totalFindings, winner.packages, winner.findings)
			}
		})

		t.Run("down_partial_repeat_reapply_preserves_rows_and_totals", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 26)
			f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,repo_name,packages_count,findings_count,duration_ms,idempotency_key,request_digest) VALUES ('roundtrip','org/repo',4,3,9,'roundtrip-key','roundtrip-digest'); UPDATE scan_log_totals SET packages_scanned=44,findings=33 WHERE id=TRUE`)
			beforeRows := f159F164ScanSurvivingSnapshot(t, leaf)
			beforeTotals := f159F164TotalsSnapshot(t, leaf)
			f159F164Exec(t, leaf, `ALTER TABLE scan_log DROP COLUMN request_digest`)

			f159F164ApplyDownAndDelete(t, leaf, 26)
			f159F164Assert026Absent(t, leaf)
			f159F164AssertEqual(t, "scan rows after partial 026 down", f159F164ScanSurvivingSnapshot(t, leaf), beforeRows)
			f159F164AssertEqual(t, "totals after partial 026 down", f159F164TotalsSnapshot(t, leaf), beforeTotals)
			f159F164ApplyDownAndDelete(t, leaf, 26)
			f159F164Assert026Absent(t, leaf)

			f159F164Apply(t, leaf, 26, MigrationDirectionUp)
			f159F164Assert026Catalog(t, leaf)
			var key sql.NullString
			var digest string
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT idempotency_key,request_digest FROM scan_log WHERE scan_id='roundtrip'`).Scan(&key, &digest); err != nil {
				t.Fatalf("read reapplied legacy defaults: %v", err)
			}
			if key.Valid || digest != "" {
				t.Fatalf("reapplied legacy defaults = key:%v digest:%q, want NULL/empty", key, digest)
			}
			f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms) VALUES ('roundtrip-new',1,0,1)`)
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT idempotency_key,request_digest FROM scan_log WHERE scan_id='roundtrip-new'`).Scan(&key, &digest); err != nil {
				t.Fatalf("read omitted 026 defaults: %v", err)
			}
			if key.Valid || digest != "" {
				t.Fatalf("omitted 026 defaults = key:%v digest:%q, want NULL/empty", key, digest)
			}
			f159F164AssertEqual(t, "totals after 026 reapply", f159F164TotalsSnapshot(t, leaf), beforeTotals)
		})

		t.Run("up_and_down_failures_are_atomic_dirty_and_recoverable", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 25)
			f159F164Exec(t, leaf, `ALTER TABLE scan_log ADD COLUMN idempotency_key TEXT; INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,idempotency_key) VALUES ('dup-a',2,1,1,'duplicate'),('dup-b',3,1,1,'duplicate')`)
			beforeUpRows := f159F164ScanSurvivingSnapshot(t, leaf)
			beforeUpCatalog := f159F164ScanCatalogSnapshot(t, leaf)
			up := f159F164Embedded(t, 26, MigrationDirectionUp)
			err := applyMigration(leaf.ctx, leaf.conn, up)
			f159F164ExpectSQLState(t, err, "23505")
			f159F164AssertEqual(t, "rows after failed 026 up", f159F164ScanSurvivingSnapshot(t, leaf), beforeUpRows)
			f159F164AssertEqual(t, "catalog after failed 026 up", f159F164ScanCatalogSnapshot(t, leaf), beforeUpCatalog)
			f159F164AssertDirtyEventAndRefusal(t, leaf, up)
			f159F164ClearDirty(t, leaf, 26)
			f159F164Exec(t, leaf, `UPDATE scan_log SET idempotency_key='duplicate-b' WHERE scan_id='dup-b'`)
			f159F164Apply(t, leaf, 26, MigrationDirectionUp)
			f159F164Assert026Catalog(t, leaf)

			f159F164Exec(t, leaf, `CREATE VIEW f160_request_digest_dependency AS SELECT request_digest FROM scan_log`)
			beforeDownRows := f159F164Scan026Snapshot(t, leaf)
			beforeDownCatalog := f159F164ScanCatalogSnapshot(t, leaf)
			down := f159F164Embedded(t, 26, MigrationDirectionDown)
			err = applyMigration(leaf.ctx, leaf.conn, down)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "depend") {
				t.Fatalf("026 dependent-view down error = %v", err)
			}
			f159F164AssertEqual(t, "rows after failed 026 down", f159F164Scan026Snapshot(t, leaf), beforeDownRows)
			f159F164AssertEqual(t, "catalog after failed 026 down", f159F164ScanCatalogSnapshot(t, leaf), beforeDownCatalog)
			f159F164AssertDirtyEventAndRefusal(t, leaf, down)
			f159F164ClearDirty(t, leaf, 26)
			f159F164Exec(t, leaf, `DROP VIEW f160_request_digest_dependency`)
			f159F164Apply(t, leaf, 26, MigrationDirectionDown)
			f159F164Assert026Absent(t, leaf)
		})
	})

	t.Run("migration_027", func(t *testing.T) {
		t.Run("normalization_catalog_and_complete_acceptance_matrix", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 26)
			f159F164DropSeverityChecks(t, leaf)
			baseline := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
			f159F164SeedSeverityRows(t, leaf, baseline)

			f159F164Apply(t, leaf, 27, MigrationDirectionUp)
			f159F164AssertSeverityNormalization(t, leaf, baseline)
			f159F164AssertSeverityConstraints(t, leaf)
			f159F164AssertSeverityAcceptanceMatrix(t, leaf)
		})

		t.Run("down_partial_repeat_reapply_preserves_rows_and_timestamps", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 27)
			f159F164SeedCanonicalSeverityRows(t, leaf)
			beforeRows := f159F164SeveritySnapshot(t, leaf)
			f159F164Exec(t, leaf, `ALTER TABLE malicious_findings DROP CONSTRAINT malicious_findings_severity_check`)

			f159F164ApplyDownAndDelete(t, leaf, 27)
			f159F164AssertSeverityChecksAbsent(t, leaf)
			f159F164AssertEqual(t, "severity rows after partial 027 down", f159F164SeveritySnapshot(t, leaf), beforeRows)
			f159F164ApplyDownAndDelete(t, leaf, 27)
			f159F164AssertSeverityChecksAbsent(t, leaf)
			f159F164AssertEqual(t, "severity rows after repeated 027 down", f159F164SeveritySnapshot(t, leaf), beforeRows)

			f159F164Apply(t, leaf, 27, MigrationDirectionUp)
			f159F164AssertSeverityConstraints(t, leaf)
			f159F164AssertEqual(t, "severity rows after 027 reapply", f159F164SeveritySnapshot(t, leaf), beforeRows)
			f159F164AssertSeverityAcceptanceMatrix(t, leaf)
		})

		t.Run("up_and_down_failures_are_atomic_dirty_and_recoverable", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 26)
			f159F164DropSeverityChecks(t, leaf)
			baseline := time.Date(2023, 6, 7, 8, 9, 10, 0, time.UTC)
			f159F164SeedSeverityRows(t, leaf, baseline)
			beforeUpRows := f159F164SeveritySnapshot(t, leaf)
			beforeUpConstraints := f159F164AllSeverityTableConstraints(t, leaf)

			up := f159F164WithFailure(f159F164Embedded(t, 27, MigrationDirectionUp))
			f159F164ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, up), "P0001")
			f159F164AssertEqual(t, "full rows/timestamps after failed 027 up", f159F164SeveritySnapshot(t, leaf), beforeUpRows)
			f159F164AssertEqual(t, "full constraints after failed 027 up", f159F164AllSeverityTableConstraints(t, leaf), beforeUpConstraints)
			f159F164AssertDirtyEventAndRefusal(t, leaf, up)
			f159F164ClearDirty(t, leaf, 27)
			f159F164Apply(t, leaf, 27, MigrationDirectionUp)
			f159F164AssertSeverityConstraints(t, leaf)

			beforeDownRows := f159F164SeveritySnapshot(t, leaf)
			beforeDownConstraints := f159F164AllSeverityTableConstraints(t, leaf)
			down := f159F164WithFailure(f159F164Embedded(t, 27, MigrationDirectionDown))
			f159F164ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, down), "P0001")
			f159F164AssertEqual(t, "full rows/timestamps after failed 027 down", f159F164SeveritySnapshot(t, leaf), beforeDownRows)
			f159F164AssertEqual(t, "full constraints after failed 027 down", f159F164AllSeverityTableConstraints(t, leaf), beforeDownConstraints)
			f159F164AssertDirtyEventAndRefusal(t, leaf, down)
			f159F164ClearDirty(t, leaf, 27)
			f159F164Apply(t, leaf, 27, MigrationDirectionDown)
			f159F164AssertSeverityChecksAbsent(t, leaf)
			f159F164AssertEqual(t, "rows after recovered 027 down", f159F164SeveritySnapshot(t, leaf), beforeDownRows)
		})
	})

	t.Run("migration_028", func(t *testing.T) {
		t.Run("absent_index_populated_catalog_replay_and_prune_plan", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 27)
			f159F164Exec(t, leaf, `DROP INDEX idx_package_check_status_socket_updated_at`)
			f159F164SeedPackageCheckRows(t, leaf)
			before := f159F164PackageCheckSnapshot(t, leaf)

			f159F164Apply(t, leaf, 28, MigrationDirectionUp)
			first := f159F164Assert028Index(t, leaf)
			f159F164AssertEqual(t, "package-check rows after 028 up", f159F164PackageCheckSnapshot(t, leaf), before)
			f159F164Apply(t, leaf, 28, MigrationDirectionUp)
			second := f159F164Assert028Index(t, leaf)
			if second != first {
				t.Fatalf("028 replay replaced or changed index: first=%q second=%q", first, second)
			}
			f159F164AssertPackageCheckPrunePlan(t, leaf)

			store, err := postgresstore.New(leaf.ctx, leaf.dsn, nil, &postgresstore.PoolConfig{MaxConns: 2, MinConns: 1})
			if err != nil {
				t.Fatalf("postgres.New() for prune error = %v", err)
			}
			t.Cleanup(func() { _ = store.Close() })
			removed, err := store.PrunePackageCheckStatus(leaf.ctx, time.Hour)
			if err != nil {
				t.Fatalf("PrunePackageCheckStatus() error = %v", err)
			}
			if removed != 1 {
				t.Fatalf("PrunePackageCheckStatus() = %d, want 1", removed)
			}
			var oldSocket, oldOther, recentSocket int
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FILTER(WHERE name='old-socket'),COUNT(*) FILTER(WHERE name='old-other'),COUNT(*) FILTER(WHERE name='recent-socket') FROM package_check_status`).Scan(&oldSocket, &oldOther, &recentSocket); err != nil {
				t.Fatalf("read package-check prune result: %v", err)
			}
			if oldSocket != 0 || oldOther != 1 || recentSocket != 1 {
				t.Fatalf("package-check survivors = old socket:%d old other:%d recent socket:%d, want 0/1/1", oldSocket, oldOther, recentSocket)
			}
		})

		t.Run("no_op_down_repeat_reapply_preserves_index_and_rows", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 28)
			f159F164SeedPackageCheckRows(t, leaf)
			beforeRows := f159F164PackageCheckSnapshot(t, leaf)
			beforeIndex := f159F164Assert028Index(t, leaf)

			f159F164ApplyDownAndDelete(t, leaf, 28)
			if got := f159F164Assert028Index(t, leaf); got != beforeIndex {
				t.Fatalf("028 no-op down changed index: got %q, want %q", got, beforeIndex)
			}
			f159F164AssertEqual(t, "package-check rows after 028 down", f159F164PackageCheckSnapshot(t, leaf), beforeRows)
			f159F164ApplyDownAndDelete(t, leaf, 28)
			if got := f159F164Assert028Index(t, leaf); got != beforeIndex {
				t.Fatalf("repeated 028 no-op down changed index: got %q, want %q", got, beforeIndex)
			}
			f159F164AssertEqual(t, "package-check rows after repeated 028 down", f159F164PackageCheckSnapshot(t, leaf), beforeRows)

			f159F164Apply(t, leaf, 28, MigrationDirectionUp)
			if got := f159F164Assert028Index(t, leaf); got != beforeIndex {
				t.Fatalf("028 reapply changed existing index: got %q, want %q", got, beforeIndex)
			}
			f159F164AssertEqual(t, "package-check rows after 028 reapply", f159F164PackageCheckSnapshot(t, leaf), beforeRows)
		})
	})

	t.Run("descending_028_through_026_and_reapply", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 25)
		f159F164SeedLegacyScans(t, leaf)
		f159F164ApplyRange(t, leaf, 26, 28)
		f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,repo_name,packages_count,findings_count,duration_ms,idempotency_key,request_digest) VALUES ('post-026','org/post',6,2,8,'post-key','post-digest')`)
		beforeSurviving := f159F164ScanSurvivingSnapshot(t, leaf)

		f159F164DescendAndDelete(t, leaf, 28, 26)
		f159F164Assert026Absent(t, leaf)
		f159F164AssertEqual(t, "surviving scan fields after 028-to-026 descent", f159F164ScanSurvivingSnapshot(t, leaf), beforeSurviving)

		f159F164ApplyRange(t, leaf, 26, 28)
		f159F164Assert026Catalog(t, leaf)
		f159F164AssertSeverityConstraints(t, leaf)
		f159F164Assert028Index(t, leaf)
		f159F164AssertEqual(t, "surviving scan fields after reapply", f159F164ScanSurvivingSnapshot(t, leaf), beforeSurviving)
		var nonnullKeys, nonemptyDigests int
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FILTER(WHERE idempotency_key IS NOT NULL),COUNT(*) FILTER(WHERE request_digest<>'') FROM scan_log`).Scan(&nonnullKeys, &nonemptyDigests); err != nil {
			t.Fatalf("inspect defaults after descending reapply: %v", err)
		}
		if nonnullKeys != 0 || nonemptyDigests != 0 {
			t.Fatalf("reapplied existing rows = nonnull keys:%d nonempty digests:%d, want 0/0 after intentional 026 field loss", nonnullKeys, nonemptyDigests)
		}
		f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms) VALUES ('after-reapply',1,0,1)`)
		var key sql.NullString
		var digest string
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT idempotency_key,request_digest FROM scan_log WHERE scan_id='after-reapply'`).Scan(&key, &digest); err != nil {
			t.Fatalf("read defaults for new row after reapply: %v", err)
		}
		if key.Valid || digest != "" {
			t.Fatalf("new row defaults after reapply = key:%v digest:%q, want NULL/empty", key, digest)
		}
	})
}

func f159F164PrepareLeaf(t *testing.T, database *sql.DB, baseDSN string, number int) f159F164Leaf {
	t.Helper()
	schema := fmt.Sprintf("f159_f164_%02d", number)
	setupCtx, setupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer setupCancel()
	if _, err := database.ExecContext(setupCtx, `CREATE SCHEMA `+f159F164QuoteIdentifier(schema)+` AUTHORIZATION packmon`); err != nil {
		t.Fatalf("create leaf schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := database.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+f159F164QuoteIdentifier(schema)+` CASCADE`); err != nil {
			t.Errorf("drop leaf schema %s: %v", schema, err)
		}
	})

	dsn := f159F164DSNWithSearchPath(t, baseDSN, schema+",public")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	conn, err := database.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire leaf connection: %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(conn) })
	if _, err := conn.ExecContext(ctx, `SET search_path TO `+f159F164QuoteIdentifier(schema)+`, public`); err != nil {
		t.Fatalf("set search_path for leaf %s: %v", schema, err)
	}
	leaf := f159F164Leaf{ctx: ctx, conn: conn, dsn: dsn, schema: schema}
	if err := ensureVersionTable(ctx, conn); err != nil {
		t.Fatalf("ensure migration metadata in leaf %s: %v", schema, err)
	}
	return leaf
}

func f159F164DSNWithSearchPath(t *testing.T, dsn, searchPath string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse Postgres DSN: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", searchPath)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func f159F164QuoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

func f159F164Embedded(t *testing.T, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	embedded, err := ReadEmbeddedMigration(version, direction)
	if err != nil {
		t.Fatalf("ReadEmbeddedMigration(%03d, %s): %v", version, direction, err)
	}
	return migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
}

func f159F164Apply(t *testing.T, leaf f159F164Leaf, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	migration := f159F164Embedded(t, version, direction)
	if err := applyMigration(leaf.ctx, leaf.conn, migration); err != nil {
		t.Fatalf("apply %s: %v", migration.name, err)
	}
	return migration
}

func f159F164ApplyThrough(t *testing.T, leaf f159F164Leaf, last int) {
	t.Helper()
	f159F164ApplyRange(t, leaf, 1, last)
}

func f159F164ApplyRange(t *testing.T, leaf f159F164Leaf, first, last int) {
	t.Helper()
	for version := first; version <= last; version++ {
		f159F164Apply(t, leaf, version, MigrationDirectionUp)
	}
}

func f159F164DescendAndDelete(t *testing.T, leaf f159F164Leaf, first, last int) {
	t.Helper()
	for version := first; version >= last; version-- {
		f159F164ApplyDownAndDelete(t, leaf, version)
	}
}

func f159F164ApplyDownAndDelete(t *testing.T, leaf f159F164Leaf, version int) {
	t.Helper()
	migration := f159F164Apply(t, leaf, version, MigrationDirectionDown)
	var name, checksum string
	var dirty bool
	var appliedAt time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read clean metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != migrationChecksum(migration.sql) || dirty || appliedAt.IsZero() {
		t.Fatalf("clean metadata for %s = name:%q checksum:%q dirty:%t applied:%v", migration.name, name, checksum, dirty, appliedAt)
	}
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND name=$2 AND checksum=$3 AND NOT dirty`, version, name, checksum)
	if err != nil {
		t.Fatalf("delete clean metadata for %s: %v", migration.name, err)
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil || affected != 1 {
		t.Fatalf("delete clean metadata for %s affected=%d error=%v, want 1", migration.name, affected, rowsErr)
	}
}

func f159F164WithFailure(migration migrationFile) migrationFile {
	migration.sql += `
DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'fixture-only migration failure';
END $$;
`
	return migration
}

func f159F164Exec(t *testing.T, leaf f159F164Leaf, statement string, args ...any) {
	t.Helper()
	if _, err := leaf.conn.ExecContext(leaf.ctx, statement, args...); err != nil {
		t.Fatalf("execute fixture SQL: %v\nSQL:\n%s", err, statement)
	}
}

func f159F164Snapshot(t *testing.T, leaf f159F164Leaf, query string) string {
	t.Helper()
	var value string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(snapshot_row)),'[]'::jsonb)::text FROM (`+query+`) snapshot_row`).Scan(&value); err != nil {
		t.Fatalf("snapshot query: %v\nSQL:\n%s", err, query)
	}
	return value
}

func f159F164SeedLegacyScans(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms) VALUES ('legacy-a','org/a','2026-01-01Z',2,1,10),('legacy-b','org/b','2026-01-02Z',5,0,20)`)
}

func f159F164ScanSurvivingSnapshot(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT id,scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,client_ip::text,client_version,api_key_id,api_key_name FROM scan_log ORDER BY id`)
}

func f159F164Scan026Snapshot(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT id,scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,idempotency_key,request_digest FROM scan_log ORDER BY id`)
}

func f159F164TotalsSnapshot(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT id,packages_scanned,findings,updated_at FROM scan_log_totals ORDER BY id`)
}

func f159F164ScanCatalogSnapshot(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `
		SELECT 'column' AS kind,column_name AS name,data_type AS definition,is_nullable||'|'||COALESCE(column_default,'') AS state
		FROM information_schema.columns WHERE table_schema=`+f159F164SQLLiteral(leaf.schema)+` AND table_name='scan_log' AND column_name IN ('idempotency_key','request_digest')
		UNION ALL
		SELECT 'index',idx.relname,pg_get_indexdef(i.indexrelid),i.indisvalid::text||'|'||i.indisready::text
		FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid JOIN pg_class tbl ON tbl.oid=i.indrelid JOIN pg_namespace n ON n.oid=tbl.relnamespace
		WHERE n.nspname=`+f159F164SQLLiteral(leaf.schema)+` AND tbl.relname='scan_log' AND idx.relname='idx_scan_log_idempotency_key'
		ORDER BY kind,name`)
}

func f159F164Assert026Catalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	type column struct{ name, dataType, nullable, defaultSQL string }
	for _, want := range []column{{"idempotency_key", "text", "YES", ""}, {"request_digest", "text", "NO", "''::text"}} {
		var got column
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT column_name,data_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema=$1 AND table_name='scan_log' AND column_name=$2`, leaf.schema, want.name).Scan(&got.name, &got.dataType, &got.nullable, &got.defaultSQL); err != nil {
			t.Fatalf("inspect scan_log.%s: %v", want.name, err)
		}
		if got != want {
			t.Fatalf("scan_log.%s = %+v, want %+v", want.name, got, want)
		}
	}
	var table, key, predicate string
	var unique, valid, ready bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT tbl.relname,pg_get_indexdef(i.indexrelid,1,true),pg_get_expr(i.indpred,i.indrelid),i.indisunique,i.indisvalid,i.indisready
		FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid JOIN pg_class tbl ON tbl.oid=i.indrelid JOIN pg_namespace n ON n.oid=tbl.relnamespace
		WHERE n.nspname=$1 AND idx.relname='idx_scan_log_idempotency_key'`, leaf.schema).Scan(&table, &key, &predicate, &unique, &valid, &ready); err != nil {
		t.Fatalf("inspect idx_scan_log_idempotency_key: %v", err)
	}
	if table != "scan_log" || key != "idempotency_key" || strings.Join(strings.Fields(predicate), " ") != "(idempotency_key IS NOT NULL)" || !unique || !valid || !ready {
		t.Fatalf("idx_scan_log_idempotency_key = table:%q key:%q predicate:%q unique:%t valid:%t ready:%t", table, key, predicate, unique, valid, ready)
	}
}

func f159F164Assert026Absent(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var columns, indexes int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=$1 AND table_name='scan_log' AND column_name IN ('idempotency_key','request_digest')`, leaf.schema).Scan(&columns); err != nil {
		t.Fatalf("inspect absent 026 columns: %v", err)
	}
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname='idx_scan_log_idempotency_key'`, leaf.schema).Scan(&indexes); err != nil {
		t.Fatalf("inspect absent 026 index: %v", err)
	}
	if columns != 0 || indexes != 0 {
		t.Fatalf("026 objects after down = columns:%d indexes:%d, want 0/0", columns, indexes)
	}
}

func f159F164IndexIdentity(t *testing.T, leaf f159F164Leaf, name string) string {
	t.Helper()
	var oid int64
	var definition string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT i.indexrelid::bigint,pg_get_indexdef(i.indexrelid) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2`, leaf.schema, name).Scan(&oid, &definition); err != nil {
		t.Fatalf("inspect index identity %s: %v", name, err)
	}
	return fmt.Sprintf("%d|%s", oid, strings.Join(strings.Fields(definition), " "))
}

func f159F164DropSeverityChecks(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_severity_check; ALTER TABLE malicious_findings DROP CONSTRAINT IF EXISTS malicious_findings_severity_check; ALTER TABLE package_reputation_cache DROP CONSTRAINT IF EXISTS package_reputation_cache_severity_check`)
}

func f159F164SeedSeverityRows(t *testing.T, leaf f159F164Leaf, baseline time.Time) {
	t.Helper()
	f159F164Exec(t, leaf, `
		INSERT INTO vulnerabilities(id,summary,severity,published,modified,updated_at) VALUES
		('v-blank','blank','','2020-01-01Z','2020-01-02Z',$1),('v-unknown','unknown','UNKNOWN','2020-01-01Z','2020-01-02Z',$1),
		('v-padded','padded',' high ','2020-01-01Z','2020-01-02Z',$1),('v-unsupported','unsupported','SEVERE','2020-01-01Z','2020-01-02Z',$1),
		('v-canonical','canonical','LOW','2020-01-01Z','2020-01-02Z',$1)`, baseline)
	f159F164Exec(t, leaf, `
		INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary,updated_at) VALUES
		('m-blank','npm','m-blank','fixture','malware','','blank',$1),('m-unknown','npm','m-unknown','fixture','malware',' unknown ','unknown',$1),
		('m-padded','npm','m-padded','fixture','malware',' high ','padded',$1),('m-unsupported','npm','m-unsupported','fixture','malware','SEVERE','unsupported',$1),
		('m-canonical','npm','m-canonical','fixture','malware','LOW','canonical',$1)`, baseline)
	f159F164Exec(t, leaf, `
		INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,severity,updated_at) VALUES
		('npm','r-blank','1','fixture','clean','',$1),('npm','r-unknown','1','fixture','clean',' unknown ',$1),
		('npm','r-padded','1','fixture','clean',' high ',$1),('npm','r-unsupported','1','fixture','clean','SEVERE',$1),
		('npm','r-canonical','1','fixture','clean','LOW',$1)`, baseline)
}

func f159F164SeedCanonicalSeverityRows(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	stamp := time.Date(2025, 2, 3, 4, 5, 6, 0, time.UTC)
	f159F164Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,severity,published,modified,updated_at) VALUES ('v-canonical','canonical','HIGH','2020-01-01Z','2020-01-02Z',$1)`, stamp)
	f159F164Exec(t, leaf, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary,updated_at) VALUES ('m-canonical','npm','canonical','fixture','malware','UNKNOWN','canonical',$1)`, stamp)
	f159F164Exec(t, leaf, `INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,severity,updated_at) VALUES ('npm','r-canonical','1','fixture','clean','MEDIUM',$1)`, stamp)
}

func f159F164SeveritySnapshot(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `
		SELECT 'vulnerability' AS kind,id,severity,updated_at FROM vulnerabilities WHERE id LIKE 'v-%'
		UNION ALL SELECT 'malicious',id,severity,updated_at FROM malicious_findings WHERE id LIKE 'm-%'
		UNION ALL SELECT 'reputation',name,severity,updated_at FROM package_reputation_cache WHERE name LIKE 'r-%'
		ORDER BY kind,id`)
}

func f159F164AssertSeverityNormalization(t *testing.T, leaf f159F164Leaf, baseline time.Time) {
	t.Helper()
	tests := []struct {
		table, keyColumn, key, want string
		changed                     bool
	}{
		{"vulnerabilities", "id", "v-blank", "LOW", true},
		{"vulnerabilities", "id", "v-unknown", "LOW", true},
		{"vulnerabilities", "id", "v-padded", "HIGH", true},
		{"vulnerabilities", "id", "v-unsupported", "LOW", true},
		{"vulnerabilities", "id", "v-canonical", "LOW", false},
		{"malicious_findings", "id", "m-blank", "UNKNOWN", true},
		{"malicious_findings", "id", "m-unknown", "UNKNOWN", true},
		{"malicious_findings", "id", "m-padded", "HIGH", true},
		{"malicious_findings", "id", "m-unsupported", "UNKNOWN", true},
		{"malicious_findings", "id", "m-canonical", "LOW", false},
		{"package_reputation_cache", "name", "r-blank", "CRITICAL", true},
		{"package_reputation_cache", "name", "r-unknown", "CRITICAL", true},
		{"package_reputation_cache", "name", "r-padded", "HIGH", true},
		{"package_reputation_cache", "name", "r-unsupported", "CRITICAL", true},
		{"package_reputation_cache", "name", "r-canonical", "LOW", false},
	}
	for _, tt := range tests {
		var severity string
		var updated time.Time
		query := fmt.Sprintf(`SELECT severity,updated_at FROM %s WHERE %s=$1`, tt.table, tt.keyColumn)
		if err := leaf.conn.QueryRowContext(leaf.ctx, query, tt.key).Scan(&severity, &updated); err != nil {
			t.Fatalf("read normalized %s %s: %v", tt.table, tt.key, err)
		}
		if severity != tt.want {
			t.Fatalf("%s %s severity = %q, want %q", tt.table, tt.key, severity, tt.want)
		}
		if tt.changed && !updated.After(baseline) {
			t.Fatalf("%s %s updated_at = %v, want after %v", tt.table, tt.key, updated, baseline)
		}
		if !tt.changed && !updated.Equal(baseline) {
			t.Fatalf("%s %s untouched updated_at = %v, want %v", tt.table, tt.key, updated, baseline)
		}
	}
}

func f159F164AssertSeverityConstraints(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	wants := map[string]string{
		"vulnerabilities_severity_check":          "CHECK ((severity = ANY (ARRAY['CRITICAL'::text, 'HIGH'::text, 'MEDIUM'::text, 'LOW'::text])))",
		"malicious_findings_severity_check":       "CHECK ((severity = ANY (ARRAY['CRITICAL'::text, 'HIGH'::text, 'MEDIUM'::text, 'LOW'::text, 'UNKNOWN'::text])))",
		"package_reputation_cache_severity_check": "CHECK ((severity = ANY (ARRAY['CRITICAL'::text, 'HIGH'::text, 'MEDIUM'::text, 'LOW'::text])))",
	}
	for name, want := range wants {
		var definition string
		var validated bool
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT pg_get_constraintdef(c.oid),c.convalidated FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname=$1 AND c.conname=$2`, leaf.schema, name).Scan(&definition, &validated); err != nil {
			t.Fatalf("inspect severity constraint %s: %v", name, err)
		}
		if definition != want || !validated {
			t.Fatalf("constraint %s = definition:%q validated:%t, want %q/true", name, definition, validated, want)
		}
	}
}

func f159F164AssertSeverityChecksAbsent(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname=$1 AND c.conname IN ('vulnerabilities_severity_check','malicious_findings_severity_check','package_reputation_cache_severity_check')`, leaf.schema).Scan(&count); err != nil {
		t.Fatalf("inspect absent severity constraints: %v", err)
	}
	if count != 0 {
		t.Fatalf("severity constraint count after down = %d, want 0", count)
	}
}

func f159F164AllSeverityTableConstraints(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `
		SELECT rel.relname,c.conname,pg_get_constraintdef(c.oid) AS definition,c.convalidated
		FROM pg_constraint c JOIN pg_class rel ON rel.oid=c.conrelid JOIN pg_namespace n ON n.oid=rel.relnamespace
		WHERE n.nspname=`+f159F164SQLLiteral(leaf.schema)+` AND rel.relname IN ('vulnerabilities','malicious_findings','package_reputation_cache')
		ORDER BY rel.relname,c.conname`)
}

func f159F164AssertSeverityAcceptanceMatrix(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	type severityTable struct {
		name       string
		constraint string
		allowed    []string
		insertSQL  string
		updateSQL  string
	}
	tables := []severityTable{
		{"vulnerabilities", "vulnerabilities_severity_check", []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES ($1,'matrix',$2,'2020-01-01Z','2020-01-02Z')`, `UPDATE vulnerabilities SET severity=$1 WHERE id='v-canonical'`},
		{"malicious_findings", "malicious_findings_severity_check", []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary) VALUES ($1,'npm',$1,'fixture','malware',$2,'matrix')`, `UPDATE malicious_findings SET severity=$1 WHERE id='m-canonical'`},
		{"package_reputation_cache", "package_reputation_cache_severity_check", []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}, `INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,severity) VALUES ('npm',$1,'1','matrix','clean',$2)`, `UPDATE package_reputation_cache SET severity=$1 WHERE name='r-canonical'`},
	}
	for _, table := range tables {
		for i, severity := range table.allowed {
			key := fmt.Sprintf("matrix-%s-%d", table.name, i)
			if _, err := leaf.conn.ExecContext(leaf.ctx, table.insertSQL, key, severity); err != nil {
				t.Fatalf("%s INSERT severity %s: %v", table.name, severity, err)
			}
			if _, err := leaf.conn.ExecContext(leaf.ctx, table.updateSQL, severity); err != nil {
				t.Fatalf("%s UPDATE severity %s: %v", table.name, severity, err)
			}
		}
		_, err := leaf.conn.ExecContext(leaf.ctx, table.insertSQL, "matrix-invalid-"+table.name, "SEVERE")
		f159F164ExpectConstraint(t, err, table.constraint)
		_, err = leaf.conn.ExecContext(leaf.ctx, table.updateSQL, "SEVERE")
		f159F164ExpectConstraint(t, err, table.constraint)
	}
	_, err := leaf.conn.ExecContext(leaf.ctx, `INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,severity) VALUES ('npm','matrix-reputation-unknown','1','matrix','clean','UNKNOWN')`)
	f159F164ExpectConstraint(t, err, "package_reputation_cache_severity_check")
	if _, err := leaf.conn.ExecContext(leaf.ctx, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary) VALUES ('matrix-malicious-unknown','npm','matrix-malicious-unknown','fixture','malware','UNKNOWN','matrix')`); err != nil {
		t.Fatalf("malicious_findings INSERT UNKNOWN error = %v", err)
	}
}

func f159F164SeedPackageCheckRows(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	now := time.Now().UTC()
	f159F164Exec(t, leaf, `
		INSERT INTO package_check_status(ecosystem,name,source,updated_at) VALUES
		('npm','old-socket','socket',$1),('npm','old-other','other',$1),('npm','recent-socket','socket',$2)`, now.Add(-2*time.Hour), now)
	f159F164Exec(t, leaf, `
		INSERT INTO package_check_status(ecosystem,name,source,updated_at)
		SELECT 'npm','noise-'||lpad(g::text,4,'0'),'socket',$1 FROM generate_series(1,256) g`, now)
}

func f159F164PackageCheckSnapshot(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT id,ecosystem,name,source,last_checked_at,next_check_at,check_count,last_result,created_at,updated_at FROM package_check_status ORDER BY id`)
}

func f159F164Assert028Index(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	var oid int64
	var table, method, key, predicate, definition string
	var valid, ready, live, unique bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT i.indexrelid::bigint,tbl.relname,am.amname,pg_get_indexdef(i.indexrelid,1,true),pg_get_expr(i.indpred,i.indrelid),pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,i.indislive,i.indisunique
		FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid JOIN pg_class tbl ON tbl.oid=i.indrelid JOIN pg_namespace n ON n.oid=tbl.relnamespace JOIN pg_am am ON am.oid=idx.relam
		WHERE n.nspname=$1 AND idx.relname='idx_package_check_status_socket_updated_at'`, leaf.schema).Scan(&oid, &table, &method, &key, &predicate, &definition, &valid, &ready, &live, &unique); err != nil {
		t.Fatalf("inspect 028 index: %v", err)
	}
	predicate = strings.Join(strings.Fields(predicate), " ")
	definition = strings.Join(strings.Fields(definition), " ")
	if table != "package_check_status" || method != "btree" || key != "updated_at" || predicate != "(source = 'socket'::text)" || !valid || !ready || !live || unique {
		t.Fatalf("028 index = oid:%d table:%q method:%q key:%q predicate:%q definition:%q valid:%t ready:%t live:%t unique:%t", oid, table, method, key, predicate, definition, valid, ready, live, unique)
	}
	return fmt.Sprintf("%d|%s", oid, definition)
}

func f159F164AssertPackageCheckPrunePlan(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `SET enable_seqscan=off`)
	defer f159F164Exec(t, leaf, `RESET enable_seqscan`)
	var raw []byte
	if err := leaf.conn.QueryRowContext(leaf.ctx, `EXPLAIN (FORMAT JSON,COSTS OFF) DELETE FROM package_check_status WHERE source='socket' AND updated_at<$1`, time.Now().UTC().Add(-time.Hour)).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN package-check prune: %v", err)
	}
	if !f159F164JSONContainsIndex(t, raw, "idx_package_check_status_socket_updated_at") {
		t.Fatalf("package-check prune plan does not use idx_package_check_status_socket_updated_at: %s", raw)
	}
}

func f159F164JSONContainsIndex(t *testing.T, raw []byte, name string) bool {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode JSON plan: %v", err)
	}
	var walk func(any) bool
	walk = func(current any) bool {
		switch current := current.(type) {
		case map[string]any:
			if got, ok := current["Index Name"].(string); ok && got == name {
				return true
			}
			for _, child := range current {
				if walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range current {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(value)
}

func f159F164AssertDirtyEventAndRefusal(t *testing.T, leaf f159F164Leaf, migration migrationFile) {
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
	var started, finished time.Time
	var success, eventDirty bool
	var eventName, eventChecksum string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,started_at,finished_at,success,dirty FROM schema_migration_events WHERE version=$1 ORDER BY id DESC LIMIT 1`, migration.version).Scan(&eventName, &eventChecksum, &started, &finished, &success, &eventDirty); err != nil {
		t.Fatalf("read latest failed event for %s: %v", migration.name, err)
	}
	if eventName != migration.name || eventChecksum != checksum || success || !eventDirty || finished.Before(started) {
		t.Fatalf("failed event for %s = name:%q checksum:%q started:%v finished:%v success:%t dirty:%t", migration.name, eventName, eventChecksum, started, finished, success, eventDirty)
	}
	err := RunContext(leaf.ctx, leaf.dsn)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("dirty at version %d", migration.version)) {
		t.Fatalf("RunContext() dirty refusal for version %d = %v", migration.version, err)
	}
}

func f159F164ClearDirty(t *testing.T, leaf f159F164Leaf, version int) {
	t.Helper()
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND dirty`, version)
	if err != nil {
		t.Fatalf("clear dirty marker %d: %v", version, err)
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil || affected != 1 {
		t.Fatalf("clear dirty marker %d affected=%d error=%v, want 1", version, affected, rowsErr)
	}
}

func f159F164ExpectSQLState(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("PostgreSQL error = nil, want SQLSTATE %s", want)
	}
	var state interface{ SQLState() string }
	if !errors.As(err, &state) || state.SQLState() != want {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, want)
	}
}

func f159F164ExpectConstraint(t *testing.T, err error, constraint string) {
	t.Helper()
	f159F164ExpectSQLState(t, err, "23514")
	if !strings.Contains(err.Error(), constraint) {
		t.Fatalf("constraint error = %v, want named constraint %s", err, constraint)
	}
}

func f159F164AssertEqual(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s changed\ngot:  %s\nwant: %s", label, got, want)
	}
}

func f159F164SQLLiteral(value string) string {
	return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
}
