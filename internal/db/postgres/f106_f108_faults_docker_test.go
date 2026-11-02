//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var f106ShadowSerial atomic.Uint64

func TestF106F108PostgresFaultAtomicity(t *testing.T) {
	_, dsn := startDockerPostgresStore(t)

	t.Run("F106 late package map failure rolls back products children and tombstones", func(t *testing.T) {
		store := f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
			f106MirrorRelations(t, ctx, pool, schema, "lifecycle_products", "lifecycle_releases", "lifecycle_package_map", "lifecycle_sync_tombstones")
		})
		ctx := context.Background()
		base := f106LifecycleProduct("fault-map", []string{"1"}, []db.LifecyclePackageMap{{Ecosystem: "npm", Name: "fault-map-old"}})
		if _, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{base}); err != nil {
			t.Fatal(err)
		}
		f106InstallTrigger(t, store.pool, "lifecycle_package_map", "INSERT", "f106_fail_late_map", "P6101", "NEW.name = 'fault-map-new'")
		changed := f106LifecycleProduct("fault-map", []string{"1", "2"}, []db.LifecyclePackageMap{{Ecosystem: "npm", Name: "fault-map-old"}, {Ecosystem: "npm", Name: "fault-map-new"}})
		_, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{changed})
		f106RequirePgError(t, err, "P6101", "forced f106_fail_late_map failure")
		var cycles, maps, tombstones int
		if err := store.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM lifecycle_releases WHERE product_slug='fault-map'),
			(SELECT count(*) FROM lifecycle_package_map WHERE product_slug='fault-map'),
			(SELECT count(*) FROM lifecycle_sync_tombstones WHERE product_slug='fault-map')`).Scan(&cycles, &maps, &tombstones); err != nil {
			t.Fatal(err)
		}
		if cycles != 1 || maps != 1 || tombstones != 0 {
			t.Fatalf("state after rollback cycles=%d maps=%d tombstones=%d", cycles, maps, tombstones)
		}
	})

	t.Run("F106 stale final delete failure leaves state and DB time XID delta empty", func(t *testing.T) {
		store := f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
			f106MirrorRelations(t, ctx, pool, schema, "lifecycle_products", "lifecycle_releases", "lifecycle_package_map", "lifecycle_sync_tombstones")
		})
		ctx := context.Background()
		base := f106LifecycleProduct("fault-stale", []string{"1"}, []db.LifecyclePackageMap{{Ecosystem: "npm", Name: "fault-stale"}})
		if _, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{base}); err != nil {
			t.Fatal(err)
		}
		baseline := f106SyncSnapshot(t, store, ctx)
		f106InstallTrigger(t, store.pool, "lifecycle_products", "DELETE", "f106_fail_stale_delete", "P6102", "OLD.product_slug = 'fault-stale'")
		_, err := store.ReplaceLifecycleProducts(ctx, nil)
		f106RequirePgError(t, err, "P6102", "forced f106_fail_stale_delete failure")
		var products, tombstones int
		if err := store.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM lifecycle_products WHERE product_slug='fault-stale'),
			(SELECT count(*) FROM lifecycle_sync_tombstones WHERE product_slug='fault-stale')`).Scan(&products, &tombstones); err != nil {
			t.Fatal(err)
		}
		delta := f106SyncDelta(t, store, ctx, baseline)
		var relevant int
		for _, item := range delta.Lifecycle {
			if strings.Contains(item.ID, "fault-stale") {
				relevant++
			}
		}
		if products != 1 || tombstones != 0 || relevant != 0 || baseline.SyncedAt.IsZero() || baseline.SyncedXID == 0 || delta.SyncedAt.Before(baseline.SyncedAt) || delta.SyncedXID == 0 {
			t.Fatalf("state products=%d tombstones=%d relevant delta=%d baseline=%s/%d delta=%s/%d", products, tombstones, relevant, baseline.SyncedAt, baseline.SyncedXID, delta.SyncedAt, delta.SyncedXID)
		}
	})

	t.Run("F106 lifecycle public query reports second row scan failure without partial findings", func(t *testing.T) {
		store := f106LifecycleReadShadow(t, dsn, false, true)
		got, err := store.FindLifecycleFindingsBatch(context.Background(), []db.PackageQuery{{Ecosystem: "npm", Name: "good", Version: "1"}, {Ecosystem: "pypi", Name: "bad", Version: "1"}}, time.Now().UTC())
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: scan lifecycle row:") {
			t.Fatalf("FindLifecycleFindingsBatch() = %+v, %v", got, err)
		}
	})

	t.Run("F106 lifecycle public query preserves second row iteration PgError", func(t *testing.T) {
		store := f106LifecycleReadShadow(t, dsn, true, false)
		got, err := store.FindLifecycleFindingsBatch(context.Background(), []db.PackageQuery{{Ecosystem: "npm", Name: "good", Version: "1"}, {Ecosystem: "pypi", Name: "bad", Version: "1"}}, time.Now().UTC())
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: iterate lifecycle rows:") {
			t.Fatalf("FindLifecycleFindingsBatch() = %+v, %v", got, err)
		}
		f106RequirePgError(t, err, "P6106", "f106 lifecycle rows marker")
	})

	t.Run("F107 late import delete failure rolls back items deletes status and audit", func(t *testing.T) {
		store := f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
			f106MirrorRelations(t, ctx, pool, schema, "malicious_findings", "feed_sync_status", "admin_audit_log")
		})
		ctx := context.Background()
		if _, err := store.pool.Exec(ctx, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary) VALUES
			('fault-delete-first','npm','first','fault-feed','malware','HIGH',''),
			('fault-delete-late','npm','late','fault-feed','malware','HIGH','')`); err != nil {
			t.Fatal(err)
		}
		f106InstallTrigger(t, store.pool, "malicious_findings", "UPDATE", "f107_fail_late_delete", "P6103", "OLD.id = 'fault-delete-late' AND NEW.removed_at IS NOT NULL")
		item := db.MaliciousFinding{ID: "fault-import-new", Ecosystem: "npm", Name: "new", Source: "fault-feed", RiskType: "malware", Severity: "HIGH"}
		status := &db.FeedSyncStatus{FeedName: "fault-feed", LastSyncStatus: "success", EntriesSynced: 1, EntriesTotal: 1}
		_, _, err := store.ImportMaliciousFeedWithAudit(ctx, "fault-feed", []db.MaliciousFinding{item}, []string{"fault-delete-first", "fault-delete-late"}, status, func(_, _ int) db.AdminAuditEntry { return db.AdminAuditEntry{Action: "fault_import"} })
		f106RequirePgError(t, err, "P6103", "forced f107_fail_late_delete failure")
		var active, inserted, statuses, audits int
		if err := store.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM malicious_findings WHERE id IN ('fault-delete-first','fault-delete-late') AND removed_at IS NULL),
			(SELECT count(*) FROM malicious_findings WHERE id='fault-import-new'),
			(SELECT count(*) FROM feed_sync_status),
			(SELECT count(*) FROM admin_audit_log)`).Scan(&active, &inserted, &statuses, &audits); err != nil {
			t.Fatal(err)
		}
		if active != 2 || inserted != 0 || statuses != 0 || audits != 0 {
			t.Fatalf("rollback active=%d inserted=%d status=%d audit=%d", active, inserted, statuses, audits)
		}
	})

	t.Run("F107 bulk delete and prune execution failures preserve active rows", func(t *testing.T) {
		store := f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
			f106MirrorRelations(t, ctx, pool, schema, "malicious_findings")
		})
		ctx := context.Background()
		if _, err := store.pool.Exec(ctx, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary,updated_at) VALUES
			('fault-bulk','npm','bulk','fault-bulk','malware','HIGH','',now()-interval '2 hours'),
			('fault-prune','npm','prune','fault-prune','malware','HIGH','',now()-interval '2 hours')`); err != nil {
			t.Fatal(err)
		}
		f106InstallTrigger(t, store.pool, "malicious_findings", "UPDATE", "f107_fail_bulk_update", "P6104", "NEW.removed_at IS NOT NULL")
		if err := store.DeleteMaliciousFinding(ctx, "fault-bulk"); err == nil {
			t.Fatal("global delete unexpectedly succeeded")
		} else {
			f106RequirePgError(t, err, "P6104", "forced f107_fail_bulk_update failure")
		}
		if err := store.DeleteMaliciousFindingForSource(ctx, "fault-prune", "fault-prune"); err == nil {
			t.Fatal("source delete unexpectedly succeeded")
		} else {
			f106RequirePgError(t, err, "P6104", "forced f107_fail_bulk_update failure")
		}
		if _, err := store.DeleteMaliciousFindingsNotInSource(ctx, "fault-bulk", []string{"not-present"}); err == nil {
			t.Fatal("bulk delete unexpectedly succeeded")
		} else {
			f106RequirePgError(t, err, "P6104", "forced f107_fail_bulk_update failure")
		}
		if _, err := store.PruneMaliciousFindingsForSourceUpdatedBefore(ctx, "fault-prune", time.Now().UTC()); err == nil {
			t.Fatal("prune unexpectedly succeeded")
		} else {
			f106RequirePgError(t, err, "P6104", "forced f107_fail_bulk_update failure")
		}
		var active int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM malicious_findings WHERE id IN ('fault-bulk','fault-prune') AND removed_at IS NULL`).Scan(&active); err != nil || active != 2 {
			t.Fatalf("active=%d err=%v", active, err)
		}
	})

	t.Run("F107 single lookup reports second row scan failure without partial findings", func(t *testing.T) {
		store := f106MaliciousReadShadow(t, dsn, "scan")
		got, err := store.FindMalicious(context.Background(), "npm", "fault-read", "1")
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: scan malicious row:") {
			t.Fatalf("FindMalicious() = %+v, %v", got, err)
		}
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		if got, err := store.FindMalicious(canceled, "npm", "fault-read", "1"); got != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("FindMalicious(canceled) = %+v, %v", got, err)
		}
	})

	t.Run("F107 single lookup preserves second row iteration PgError", func(t *testing.T) {
		store := f106MaliciousReadShadow(t, dsn, "rows")
		got, err := store.FindMalicious(context.Background(), "npm", "fault-read", "1")
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: iterate malicious findings:") {
			t.Fatalf("FindMalicious() = %+v, %v", got, err)
		}
		f106RequirePgError(t, err, "P6107", "f107 malicious rows marker")
	})

	t.Run("F107 batch lookup reports second row scan failure without partial findings", func(t *testing.T) {
		store := f106MaliciousReadShadow(t, dsn, "scan")
		got, err := store.FindMaliciousBatch(context.Background(), []db.PackageQuery{{Ecosystem: "npm", Name: "fault-read", Version: "1"}})
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: scan malicious batch row:") {
			t.Fatalf("FindMaliciousBatch() = %+v, %v", got, err)
		}
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		if got, err := store.FindMaliciousBatch(canceled, []db.PackageQuery{{Ecosystem: "npm", Name: "fault-read", Version: "1"}}); got != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("FindMaliciousBatch(canceled) = %+v, %v", got, err)
		}
	})

	t.Run("F107 batch lookup preserves second row iteration PgError", func(t *testing.T) {
		store := f106MaliciousReadShadow(t, dsn, "rows")
		got, err := store.FindMaliciousBatch(context.Background(), []db.PackageQuery{{Ecosystem: "npm", Name: "fault-read", Version: "1"}})
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: iterate malicious batch:") {
			t.Fatalf("FindMaliciousBatch() = %+v, %v", got, err)
		}
		f106RequirePgError(t, err, "P6107", "f107 malicious rows marker")
	})

	t.Run("F107 list reports second row scan failure without partial rows", func(t *testing.T) {
		store := f106MaliciousReadShadow(t, dsn, "scan")
		got, err := store.ListMaliciousFindings(context.Background(), "fault-source", 10)
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: scan malicious finding row:") {
			t.Fatalf("ListMaliciousFindings() = %+v, %v", got, err)
		}
	})

	t.Run("F107 list preserves second row iteration PgError", func(t *testing.T) {
		store := f106MaliciousReadShadow(t, dsn, "rows")
		got, err := store.ListMaliciousFindings(context.Background(), "fault-source", 10)
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: iterate malicious findings:") {
			t.Fatalf("ListMaliciousFindings() = %+v, %v", got, err)
		}
		f106RequirePgError(t, err, "P6107", "f107 malicious rows marker")
	})

	t.Run("F108 reverse counterpart delete failure preserves original malicious row and no audit", func(t *testing.T) {
		store := f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
			f106MirrorRelations(t, ctx, pool, schema, "malicious_findings", "vulnerabilities", "vulnerability_sources", "affected_packages", "vulnerability_aliases", "vulnerability_references", "admin_audit_log")
		})
		ctx := context.Background()
		if _, err := store.pool.Exec(ctx, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary) VALUES('manual:f108-fault','npm','old','manual','malware','CRITICAL','old')`); err != nil {
			t.Fatal(err)
		}
		assertRollbackState := func(stage string, expectReplacement bool) {
			t.Helper()
			var ecosystem, name, source, riskType, severity, summary string
			var reverseActive bool
			var reverseVulnerabilities int
			if err := store.pool.QueryRow(ctx, `SELECT ecosystem,name,source,risk_type,severity,summary,removed_at IS NULL,
				(SELECT count(*) FROM vulnerabilities WHERE id='manual:f108-fault')
				FROM malicious_findings WHERE id='manual:f108-fault'`).Scan(&ecosystem, &name, &source, &riskType, &severity, &summary, &reverseActive, &reverseVulnerabilities); err != nil {
				t.Fatalf("%s: read reverse original: %v", stage, err)
			}
			if ecosystem != "npm" || name != "old" || source != "manual" || riskType != "malware" || severity != "CRITICAL" || summary != "old" || !reverseActive || reverseVulnerabilities != 0 {
				t.Fatalf("%s: reverse original changed: ecosystem=%q name=%q source=%q risk=%q severity=%q summary=%q active=%v vulnerabilities=%d", stage, ecosystem, name, source, riskType, severity, summary, reverseActive, reverseVulnerabilities)
			}
			var failedMalicious, failedVulnerabilities, failedSources, failedAffected, lockRows, audits int
			if err := store.pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM malicious_findings WHERE id='manual:f108-malicious-fault'),
				(SELECT count(*) FROM vulnerabilities WHERE id IN ('manual:f108-malicious-fault','manual:f108-vulnerability-fault')),
				(SELECT count(*) FROM vulnerability_sources WHERE vulnerability_id IN ('manual:f108-malicious-fault','manual:f108-vulnerability-fault')),
				(SELECT count(*) FROM affected_packages WHERE vulnerability_id IN ('manual:f108-malicious-fault','manual:f108-vulnerability-fault')),
				((SELECT count(*) FROM malicious_findings WHERE id='manual:f108-lock-fault') + (SELECT count(*) FROM vulnerabilities WHERE id='manual:f108-lock-fault')),
				(SELECT count(*) FROM admin_audit_log)`).Scan(&failedMalicious, &failedVulnerabilities, &failedSources, &failedAffected, &lockRows, &audits); err != nil {
				t.Fatalf("%s: read failed-create state: %v", stage, err)
			}
			if failedMalicious != 0 || failedVulnerabilities != 0 || failedSources != 0 || failedAffected != 0 || lockRows != 0 || audits != 0 {
				t.Fatalf("%s: leaked state malicious=%d vulnerabilities=%d sources=%d affected=%d lock=%d audits=%d", stage, failedMalicious, failedVulnerabilities, failedSources, failedAffected, lockRows, audits)
			}
			if !expectReplacement {
				return
			}
			var replacementRows, oldPackages, newPackages, allPackages int
			var replacementSeverity string
			if err := store.pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM vulnerabilities WHERE id='manual:f108-replace-fault'),
				COALESCE((SELECT severity FROM vulnerabilities WHERE id='manual:f108-replace-fault'),''),
				(SELECT count(*) FROM affected_packages WHERE vulnerability_id='manual:f108-replace-fault' AND ecosystem='npm' AND name='old-pkg'),
				(SELECT count(*) FROM affected_packages WHERE vulnerability_id='manual:f108-replace-fault' AND name='new-pkg'),
				(SELECT count(*) FROM affected_packages WHERE vulnerability_id='manual:f108-replace-fault')`).Scan(&replacementRows, &replacementSeverity, &oldPackages, &newPackages, &allPackages); err != nil {
				t.Fatalf("%s: read replacement state: %v", stage, err)
			}
			if replacementRows != 1 || replacementSeverity != "HIGH" || oldPackages != 1 || newPackages != 0 || allPackages != 1 {
				t.Fatalf("%s: replacement state rows=%d severity=%q old=%d new=%d all=%d", stage, replacementRows, replacementSeverity, oldPackages, newPackages, allPackages)
			}
		}
		assertRollbackState("baseline", false)
		f106InstallTrigger(t, store.pool, "malicious_findings", "UPDATE", "f108_fail_counterpart", "P6108", "OLD.id = 'manual:f108-fault' AND NEW.removed_at IS NOT NULL")
		plain := &db.ManualAdvisory{ID: "manual:f108-fault", FindingType: "vulnerability", Ecosystem: "npm", Name: "new", Severity: "LOW"}
		if err := store.UpsertManualAdvisory(ctx, plain); err == nil {
			t.Fatal("plain reverse unexpectedly succeeded")
		} else {
			f106RequirePgError(t, err, "P6108", "forced f108_fail_counterpart failure")
		}
		assertRollbackState("plain reverse failure", false)
		err := store.UpsertManualAdvisoryWithAudit(ctx, plain, &db.AdminAuditEntry{Action: "f108_fault_reverse"})
		f106RequirePgError(t, err, "P6108", "forced f108_fail_counterpart failure")
		assertRollbackState("audited reverse failure", false)
		f106InstallTrigger(t, store.pool, "malicious_findings", "INSERT", "f108_fail_malicious_insert", "P6110", "NEW.id = 'manual:f108-malicious-fault'")
		err = store.UpsertManualAdvisoryWithAudit(ctx, &db.ManualAdvisory{ID: "manual:f108-malicious-fault", FindingType: "malicious", Ecosystem: "npm", Name: "bad", Severity: "HIGH", RiskType: "malware"}, &db.AdminAuditEntry{Action: "f108_fault_malicious"})
		f106RequirePgError(t, err, "P6110", "forced f108_fail_malicious_insert failure")
		assertRollbackState("malicious create failure", false)
		f106InstallTrigger(t, store.pool, "vulnerabilities", "INSERT", "f108_fail_vulnerability_insert", "P6111", "NEW.id = 'manual:f108-vulnerability-fault'")
		err = store.UpsertManualAdvisoryWithAudit(ctx, &db.ManualAdvisory{ID: "manual:f108-vulnerability-fault", FindingType: "vulnerability", Ecosystem: "npm", Name: "bad", Severity: "LOW"}, &db.AdminAuditEntry{Action: "f108_fault_vulnerability"})
		f106RequirePgError(t, err, "P6111", "forced f108_fail_vulnerability_insert failure")
		assertRollbackState("vulnerability create failure", false)
		if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{ID: "manual:f108-replace-fault", FindingType: "vulnerability", Ecosystem: "npm", Name: "old-pkg", Severity: "HIGH", Summary: "same"}); err != nil {
			t.Fatal(err)
		}
		assertRollbackState("replacement baseline", true)
		f106InstallTrigger(t, store.pool, "vulnerabilities", "UPDATE", "f108_fail_replace_update", "P6112", "OLD.id = 'manual:f108-replace-fault' AND OLD.severity = 'HIGH' AND NEW.severity = 'LOW'")
		err = store.UpsertManualAdvisoryWithAudit(ctx, &db.ManualAdvisory{ID: "manual:f108-replace-fault", FindingType: "vulnerability", Ecosystem: "npm", Name: "old-pkg", Severity: "LOW", Summary: "same"}, &db.AdminAuditEntry{Action: "f108_fault_replace"})
		f106RequirePgError(t, err, "P6112", "forced f108_fail_replace_update failure")
		assertRollbackState("replacement update failure", true)
		f106InstallTrigger(t, store.pool, "affected_packages", "DELETE", "f108_fail_package_delete", "P6113", "OLD.vulnerability_id = 'manual:f108-replace-fault' AND OLD.name = 'old-pkg'")
		err = store.UpsertManualAdvisoryWithAudit(ctx, &db.ManualAdvisory{ID: "manual:f108-replace-fault", FindingType: "vulnerability", Ecosystem: "npm", Name: "new-pkg", Severity: "HIGH", Summary: "same"}, &db.AdminAuditEntry{Action: "f108_fault_package"})
		f106RequirePgError(t, err, "P6113", "forced f108_fail_package_delete failure")
		assertRollbackState("replacement package failure", true)
		external, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := external.Acquire(ctx)
		if err != nil {
			external.Close()
			t.Fatal(err)
		}
		lockKey := manualAdvisoryLockKey("manual:f108-lock-fault")
		if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
			conn.Release()
			external.Close()
			t.Fatal(err)
		}
		blockedCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		err = store.UpsertManualAdvisory(blockedCtx, &db.ManualAdvisory{ID: "manual:f108-lock-fault", FindingType: "vulnerability", Ecosystem: "npm", Name: "lock", Severity: "LOW"})
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("per-ID lock error = %v", err)
		}
		var unlocked bool
		if err := conn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, lockKey).Scan(&unlocked); err != nil || !unlocked {
			t.Fatalf("unlock per-ID lock = %v, %v", unlocked, err)
		}
		conn.Release()
		external.Close()
		assertRollbackState("lock timeout and final", true)
	})

	t.Run("F108 manual list reports second row scan failure without partial rows", func(t *testing.T) {
		store := f106ManualReadShadow(t, dsn, "scan")
		got, err := store.ListManualAdvisoriesPage(context.Background(), 10, 0)
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: scan manual advisory row:") {
			t.Fatalf("ListManualAdvisoriesPage() = %+v, %v", got, err)
		}
		if got, err := store.GetManualAdvisory(context.Background(), "manual:bad"); got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: get manual advisory") {
			t.Fatalf("GetManualAdvisory() = %+v, %v", got, err)
		}
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		if got, err := store.ListManualAdvisoriesPage(canceled, 10, 0); got != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("ListManualAdvisoriesPage(canceled) = %+v, %v", got, err)
		}
	})

	t.Run("F108 manual list preserves second row iteration PgError", func(t *testing.T) {
		store := f106ManualReadShadow(t, dsn, "rows")
		got, err := store.ListManualAdvisoriesPage(context.Background(), 10, 0)
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: iterate manual advisories:") {
			t.Fatalf("ListManualAdvisoriesPage() = %+v, %v", got, err)
		}
		f106RequirePgError(t, err, "P6109", "f108 manual rows marker")
	})
}

func f106ShadowStore(t *testing.T, dsn string, setup func(context.Context, *pgxpool.Pool, string)) *Store {
	t.Helper()
	schema := fmt.Sprintf("f106_shadow_%d_%d", time.Now().UnixNano(), f106ShadowSerial.Add(1))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Cleanup is registered before the first DDL. It closes the search-path
	// pool, then uses a fresh original-DSN pool and a bounded context to remove
	// every trigger and function before dropping the schema itself.
	var shadowPool *pgxpool.Pool
	t.Cleanup(func() {
		if shadowPool != nil {
			shadowPool.Close()
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		pool, err := pgxpool.New(cleanupCtx, dsn)
		if err != nil {
			t.Errorf("fresh cleanup pool: %v", err)
			return
		}
		defer pool.Close()
		cleanupSQL := fmt.Sprintf(`DO $cleanup$
		DECLARE r record;
		BEGIN
		  FOR r IN SELECT c.relname table_name,t.tgname trigger_name FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%[1]s AND NOT t.tgisinternal LOOP
		    EXECUTE format('DROP TRIGGER IF EXISTS %%I ON %%I.%%I',r.trigger_name,%[1]s,r.table_name);
		  END LOOP;
		  FOR r IN SELECT p.proname,pg_get_function_identity_arguments(p.oid) args FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=%[1]s LOOP
		    EXECUTE format('DROP FUNCTION IF EXISTS %%I.%%I(%%s) CASCADE',%[1]s,r.proname,r.args);
		  END LOOP;
		END $cleanup$;
		DROP SCHEMA IF EXISTS %s CASCADE`, quoteLiteral(schema), quoteIdentifier(schema))
		if _, err := pool.Exec(cleanupCtx, cleanupSQL); err != nil {
			t.Errorf("cleanup shadow schema %s: %v", schema, err)
			return
		}
		var count int
		var reg *string
		if err := pool.QueryRow(cleanupCtx, `SELECT count(*),to_regnamespace($1)::text FROM pg_namespace WHERE nspname=$1`, schema).Scan(&count, &reg); err != nil {
			t.Errorf("verify shadow cleanup %s: %v", schema, err)
		} else if count != 0 || reg != nil {
			t.Errorf("shadow cleanup %s left count=%d reg=%v", schema, count, reg)
		}
	})

	root, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Exec(ctx, "CREATE SCHEMA "+quoteIdentifier(schema)); err != nil {
		root.Close()
		t.Fatal(err)
	}
	setup(ctx, root, schema)
	root.Close()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	cfg.MinConns = 1
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	shadowPool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := shadowPool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	return &Store{pool: shadowPool}
}

func f106MirrorRelations(t *testing.T, ctx context.Context, pool *pgxpool.Pool, schema string, relations ...string) {
	t.Helper()
	for _, relation := range relations {
		query := fmt.Sprintf("CREATE TABLE %s.%s (LIKE public.%s INCLUDING ALL)", quoteIdentifier(schema), quoteIdentifier(relation), quoteIdentifier(relation))
		if _, err := pool.Exec(ctx, query); err != nil {
			t.Fatalf("mirror %s: %v", relation, err)
		}
	}
}

func f106InstallTrigger(t *testing.T, pool *pgxpool.Pool, table, event, name, sqlState, condition string) {
	t.Helper()
	ctx := context.Background()
	var schema string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	function := name + "_fn"
	query := fmt.Sprintf(`CREATE FUNCTION %s.%s() RETURNS trigger LANGUAGE plpgsql AS $fn$
	BEGIN RAISE EXCEPTION USING ERRCODE=%s, MESSAGE=%s; END $fn$;
	CREATE TRIGGER %s BEFORE %s ON %s.%s FOR EACH ROW WHEN (%s) EXECUTE FUNCTION %s.%s()`,
		quoteIdentifier(schema), quoteIdentifier(function), quoteLiteral(sqlState), quoteLiteral("forced "+name+" failure"),
		quoteIdentifier(name), event, quoteIdentifier(schema), quoteIdentifier(table), condition, quoteIdentifier(schema), quoteIdentifier(function))
	if _, err := pool.Exec(ctx, query); err != nil {
		t.Fatalf("install %s: %v", name, err)
	}
}

func f106RequirePgError(t *testing.T, err error, code, message string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code || pgErr.Message != message {
		t.Fatalf("error=%v pg=%+v, want code=%s message=%q", err, pgErr, code, message)
	}
}

func f106LifecycleReadShadow(t *testing.T, dsn string, rowsErr, scanErr bool) *Store {
	t.Helper()
	return f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
		f106MirrorRelations(t, ctx, pool, schema, "lifecycle_releases")
		productBase := quoteIdentifier(schema) + ".lifecycle_products_base"
		mapBase := quoteIdentifier(schema) + ".lifecycle_package_map_base"
		if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE public.lifecycle_products INCLUDING ALL); CREATE TABLE %s (LIKE public.lifecycle_package_map INCLUDING ALL)", productBase, mapBase)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s(product_slug,name,source) VALUES('good-product','Good','endoflife.date'),('bad-product','Bad','endoflife.date');
			INSERT INTO %s(product_slug,cycle,is_eol) VALUES('good-product','1',true),('bad-product','1',true);
			INSERT INTO %s(ecosystem,name,product_slug,source) VALUES('npm','good','good-product','endoflife.date'),('pypi','bad','bad-product','endoflife.date')`, productBase, quoteIdentifier(schema)+".lifecycle_releases", mapBase)); err != nil {
			t.Fatal(err)
		}
		nameExpr := "name"
		if rowsErr {
			if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s.f106_rows_marker(value text,slug text) RETURNS text LANGUAGE plpgsql AS $fn$
			BEGIN IF slug='bad-product' THEN RAISE EXCEPTION USING ERRCODE='P6106',MESSAGE='f106 lifecycle rows marker'; END IF; RETURN value; END $fn$`, quoteIdentifier(schema))); err != nil {
				t.Fatal(err)
			}
			nameExpr = fmt.Sprintf("%s.f106_rows_marker(name,product_slug)", quoteIdentifier(schema))
		} else if scanErr {
			nameExpr = "CASE WHEN product_slug='bad-product' THEN NULL::text ELSE name END"
		}
		ecosystemExpr := "ecosystem"
		if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE VIEW %s.lifecycle_products AS SELECT product_slug,%s AS name,category,source,identifiers,raw,updated_at FROM %s;
			CREATE VIEW %s.lifecycle_package_map AS SELECT %s AS ecosystem,name,product_slug,purl_type,purl_namespace,purl_name,source,updated_at FROM %s`, quoteIdentifier(schema), nameExpr, productBase, quoteIdentifier(schema), ecosystemExpr, mapBase)); err != nil {
			t.Fatal(err)
		}
	})
}

func f106MaliciousReadShadow(t *testing.T, dsn, mode string) *Store {
	t.Helper()
	return f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
		base := quoteIdentifier(schema) + ".malicious_findings_base"
		if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE public.malicious_findings INCLUDING ALL)", base)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s(id,ecosystem,name,source,risk_type,severity,summary,updated_at,created_at) VALUES
			('good','npm','fault-read','fault-source','malware','HIGH','good',now(),now()),
			('bad','npm','fault-read','fault-source','malware','HIGH','bad',now()-interval '1 second',now()-interval '1 second')`, base)); err != nil {
			t.Fatal(err)
		}
		idExpr := "id"
		if mode == "scan" {
			idExpr = "CASE WHEN id='bad' THEN NULL::text ELSE id END"
		} else {
			if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s.f107_rows_marker(value text) RETURNS text LANGUAGE plpgsql AS $fn$
			BEGIN IF value='bad' THEN RAISE EXCEPTION USING ERRCODE='P6107',MESSAGE='f107 malicious rows marker'; END IF; RETURN value; END $fn$`, quoteIdentifier(schema))); err != nil {
				t.Fatal(err)
			}
			idExpr = fmt.Sprintf("%s.f107_rows_marker(id)", quoteIdentifier(schema))
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE VIEW %s.malicious_findings AS SELECT %s AS id,ecosystem,name,version_ranges,versions,source,risk_type,severity,summary,description,reference_urls,origin_ref,published,created_at,updated_at,created_by,removed_at FROM %s`, quoteIdentifier(schema), idExpr, base)); err != nil {
			t.Fatal(err)
		}
	})
}

func f106ManualReadShadow(t *testing.T, dsn, mode string) *Store {
	t.Helper()
	return f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
		f106MirrorRelations(t, ctx, pool, schema, "vulnerabilities", "vulnerability_sources", "affected_packages")
		base := quoteIdentifier(schema) + ".malicious_findings_base"
		if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE public.malicious_findings INCLUDING ALL)", base)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s(id,ecosystem,name,source,risk_type,severity,summary,updated_at,created_at) VALUES
			('manual:good','npm','good','manual','malware','HIGH','good',now(),now()),
			('manual:bad','npm','bad','manual','malware','HIGH','bad',now()-interval '1 second',now()-interval '1 second')`, base)); err != nil {
			t.Fatal(err)
		}
		idExpr := "id"
		severityExpr := "severity"
		if mode == "scan" {
			severityExpr = "CASE WHEN id='manual:bad' THEN NULL::text ELSE severity END"
		} else {
			if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s.f108_rows_marker(value text) RETURNS text LANGUAGE plpgsql AS $fn$
			BEGIN IF value='manual:bad' THEN RAISE EXCEPTION USING ERRCODE='P6109',MESSAGE='f108 manual rows marker'; END IF; RETURN value; END $fn$`, quoteIdentifier(schema))); err != nil {
				t.Fatal(err)
			}
			idExpr = fmt.Sprintf("%s.f108_rows_marker(id)", quoteIdentifier(schema))
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE VIEW %s.malicious_findings AS SELECT %s AS id,ecosystem,name,version_ranges,versions,source,risk_type,%s AS severity,summary,description,reference_urls,origin_ref,published,created_at,updated_at,created_by,removed_at FROM %s`, quoteIdentifier(schema), idExpr, severityExpr, base)); err != nil {
			t.Fatal(err)
		}
	})
}

func quoteIdentifier(value string) string { return `"` + strings.ReplaceAll(value, `"`, `""`) + `"` }

func quoteLiteral(value string) string { return `'` + strings.ReplaceAll(value, `'`, `''`) + `'` }
