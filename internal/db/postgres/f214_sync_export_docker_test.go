//go:build integration

package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF214SyncSnapshotAndExporterFailuresAgainstPostgres(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	t.Run("snapshot resolution and empty completed export", func(t *testing.T) {
		snapshot := time.Date(2026, 11, 3, 12, 34, 56, 789, time.FixedZone("f214", 2*60*60))
		gotSnapshot, gotXID, err := store.resolveSyncSnapshot(ctx, db.SyncExportOptions{SnapshotAt: snapshot, SnapshotXID: ^uint64(0)})
		if err != nil || !gotSnapshot.Equal(snapshot) || gotSnapshot.Location() != time.UTC || gotXID != ^uint64(0) {
			t.Fatalf("resolve pinned snapshot = %v/%d, %v; want %v UTC/%d", gotSnapshot, gotXID, err, snapshot, ^uint64(0))
		}

		gotSnapshot, gotXID, err = store.resolveSyncSnapshot(ctx, db.SyncExportOptions{SnapshotAt: snapshot})
		if err != nil || !gotSnapshot.Equal(snapshot) || gotXID == 0 {
			t.Fatalf("resolve pinned timestamp without XID = %v/%d, %v", gotSnapshot, gotXID, err)
		}

		started := time.Now().UTC()
		generatedSnapshot, generatedXID, err := store.resolveSyncSnapshot(ctx, db.SyncExportOptions{})
		finished := time.Now().UTC()
		if err != nil || generatedSnapshot.Before(started.Add(-time.Second)) || generatedSnapshot.After(finished.Add(time.Second)) || generatedSnapshot.Location() != time.UTC || generatedXID == 0 {
			t.Fatalf("generated snapshot = %v/%d, %v; want UTC in [%v,%v] and nonzero XID", generatedSnapshot, generatedXID, err, started, finished)
		}

		export, err := store.ExportSync(ctx, db.SyncExportOptions{
			SnapshotAt:  snapshot,
			SnapshotXID: 4242,
			Limit:       1,
			Cursor: db.SyncCursor{
				VulnerabilitiesDone: true,
				MaliciousDone:       true,
				ReputationDone:      true,
				LifecycleDone:       true,
			},
		})
		if err != nil || export == nil {
			t.Fatalf("ExportSync(completed datasets) = %#v, %v", export, err)
		}
		if !export.SyncedAt.Equal(snapshot) || export.SyncedAt.Location() != time.UTC || export.SyncedXID != 4242 || export.Truncated || export.NextCursor != nil ||
			len(export.Vulnerabilities)+len(export.Malicious)+len(export.Reputation)+len(export.Lifecycle) != 0 {
			t.Fatalf("completed ExportSync() = %#v, want the pinned empty final page", export)
		}
	})

	t.Run("ExportSync rejects snapshot and dataset failures without a partial page", func(t *testing.T) {
		canceled, stop := context.WithCancel(context.Background())
		stop()
		pinned := time.Now().UTC()
		if gotSnapshot, gotXID, err := store.resolveSyncSnapshot(canceled, db.SyncExportOptions{SnapshotAt: pinned}); err == nil || !gotSnapshot.IsZero() || gotXID != 0 || !strings.Contains(err.Error(), "postgres: read sync snapshot xid") {
			t.Fatalf("resolveSyncSnapshot(pinned query failure) = %v/%d, %v; want zero values and wrapped XID error", gotSnapshot, gotXID, err)
		}
		if export, err := store.ExportSync(canceled, db.SyncExportOptions{}); err == nil || export != nil || !strings.Contains(err.Error(), "postgres: read sync snapshot") {
			t.Fatalf("ExportSync(snapshot failure) = %#v, %v; want nil wrapped snapshot error", export, err)
		}

		opts := db.SyncExportOptions{
			SnapshotAt:  time.Now().UTC(),
			SnapshotXID: 42,
			Limit:       10,
		}
		if export, err := store.ExportSync(canceled, opts); err == nil || export != nil || !strings.Contains(err.Error(), "postgres: export sync vulnerabilities") {
			t.Fatalf("ExportSync(dataset failure) = %#v, %v; want nil first-dataset error", export, err)
		}
		assertF214PoolReleased(t, store)
	})

	t.Run("every dataset wraps query failures", func(t *testing.T) {
		canceled, stop := context.WithCancel(context.Background())
		stop()
		snapshot := time.Now().UTC()
		checks := []struct {
			name string
			want string
			run  func() error
		}{
			{name: "vulnerabilities", want: "postgres: export sync vulnerabilities", run: func() error {
				_, err := store.exportSyncVulnerabilities(canceled, db.SyncExportOptions{Limit: 1}, snapshot, 0)
				return err
			}},
			{name: "reputation", want: "postgres: export sync reputation findings", run: func() error {
				_, err := store.exportSyncReputation(canceled, db.SyncExportOptions{Limit: 1}, snapshot, 0)
				return err
			}},
			{name: "malicious", want: "postgres: export sync malicious findings", run: func() error {
				_, err := store.exportSyncMalicious(canceled, db.SyncExportOptions{Limit: 1}, snapshot, 0)
				return err
			}},
			{name: "lifecycle", want: "postgres: export sync lifecycle releases", run: func() error {
				_, err := store.exportSyncLifecycle(canceled, db.SyncExportOptions{Limit: 1}, snapshot, 0)
				return err
			}},
		}
		for _, check := range checks {
			if err := check.run(); err == nil || !strings.Contains(err.Error(), check.want) {
				t.Errorf("%s query failure = %v, want %q", check.name, err, check.want)
			}
		}
		assertF214PoolReleased(t, store)
	})

	t.Run("every dataset rejects an invalid scanned row and releases rows", func(t *testing.T) {
		snapshot := time.Now().UTC().Add(time.Hour)
		checks := []struct {
			name    string
			setup   string
			restore string
			want    string
			run     func() error
		}{
			{
				name: "vulnerabilities",
				setup: `
					ALTER TABLE vulnerabilities ALTER COLUMN severity DROP NOT NULL;
					INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES('F214-SCAN-VULN','f214',NULL,clock_timestamp(),clock_timestamp());
					INSERT INTO affected_packages(vulnerability_id,ecosystem,name) VALUES('F214-SCAN-VULN','npm','f214-vuln')`,
				restore: `DELETE FROM vulnerabilities WHERE id='F214-SCAN-VULN'; ALTER TABLE vulnerabilities ALTER COLUMN severity SET NOT NULL`,
				want:    "postgres: scan sync vulnerability row",
				run: func() error {
					_, err := store.exportSyncVulnerabilities(ctx, db.SyncExportOptions{Limit: 10}, snapshot, 0)
					return err
				},
			},
			{
				name: "reputation",
				setup: `
					ALTER TABLE package_reputation_cache ALTER COLUMN reference_urls DROP NOT NULL;
					INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,reference_urls) VALUES('npm','f214-reputation','1.0.0','reversinglabs','malicious',NULL)`,
				restore: `DELETE FROM package_reputation_cache WHERE name='f214-reputation'; ALTER TABLE package_reputation_cache ALTER COLUMN reference_urls SET NOT NULL`,
				want:    "postgres: scan sync reputation row",
				run: func() error {
					_, err := store.exportSyncReputation(ctx, db.SyncExportOptions{Limit: 10}, snapshot, 0)
					return err
				},
			},
			{
				name: "malicious",
				setup: `
					ALTER TABLE malicious_findings ALTER COLUMN severity DROP NOT NULL;
					INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary) VALUES('F214-SCAN-MAL','npm','f214-malicious','openssf','malware',NULL,'f214')`,
				restore: `DELETE FROM malicious_findings WHERE id='F214-SCAN-MAL'; ALTER TABLE malicious_findings ALTER COLUMN severity SET NOT NULL`,
				want:    "postgres: scan sync malicious row",
				run: func() error {
					_, err := store.exportSyncMalicious(ctx, db.SyncExportOptions{Limit: 10}, snapshot, 0)
					return err
				},
			},
			{
				name: "lifecycle",
				setup: `
					ALTER TABLE lifecycle_products ALTER COLUMN name DROP NOT NULL;
					INSERT INTO lifecycle_products(product_slug,name) VALUES('f214-product',NULL);
					INSERT INTO lifecycle_releases(product_slug,cycle) VALUES('f214-product','1');
					INSERT INTO lifecycle_package_map(ecosystem,name,product_slug) VALUES('npm','f214-lifecycle','f214-product')`,
				restore: `DELETE FROM lifecycle_products WHERE product_slug='f214-product'; ALTER TABLE lifecycle_products ALTER COLUMN name SET NOT NULL`,
				want:    "postgres: scan sync lifecycle row",
				run: func() error {
					_, err := store.exportSyncLifecycle(ctx, db.SyncExportOptions{Limit: 10}, snapshot, 0)
					return err
				},
			},
		}

		for _, check := range checks {
			t.Run(check.name, func(t *testing.T) {
				t.Cleanup(func() {
					if _, err := store.pool.Exec(context.Background(), check.restore); err != nil {
						t.Errorf("restore %s scan fixture: %v", check.name, err)
					}
				})
				if _, err := store.pool.Exec(ctx, check.setup); err != nil {
					t.Fatalf("setup %s scan fixture: %v", check.name, err)
				}
				if err := check.run(); err == nil || !strings.Contains(err.Error(), check.want) {
					t.Fatalf("%s scan failure = %v, want %q", check.name, err, check.want)
				}
				assertF214PoolReleased(t, store)
			})
		}
	})

	t.Run("lifecycle iteration failure discards the partial page and releases rows", func(t *testing.T) {
		query := `
			SELECT
				'f214-' || g::text, 'npm', 'f214', 'f214-product', 'F214 Product', g::text, '1.0.0',
				NULL::date, false, NULL::date, false, NULL::date, false, NULL::date,
				false, NULL::date, NULL::boolean, NULL::date, false,
				CASE WHEN g = 2 THEN (1 / 0) = 0 ELSE false END
			FROM generate_series(1, 2) AS g`
		page, err := store.querySyncLifecycleRows(ctx, query, nil, newSyncRowPageBuilder(10, db.SyncLifecyclePageByteBudget, syncLifecycleWireBytes))
		if err == nil || !strings.Contains(err.Error(), "postgres: iterate sync lifecycle rows") {
			t.Fatalf("querySyncLifecycleRows(iteration failure) = %#v, %v; want empty page and iteration error", page, err)
		}
		if len(page.rows) != 0 || page.hasMore {
			t.Fatalf("iteration failure leaked partial page: %#v", page)
		}
		assertF214PoolReleased(t, store)
	})
}

func assertF214PoolReleased(t *testing.T, store *Store) {
	t.Helper()
	if acquired := store.pool.Stat().AcquiredConns(); acquired != 0 {
		t.Fatalf("PostgreSQL pool retains %d acquired connections after export failure", acquired)
	}
}
