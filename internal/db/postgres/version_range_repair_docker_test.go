//go:build integration

package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/db/postgres/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestVersionRangeBoundaryRepairKeepsMaliciousFindingsScopedAgainstPostgres
// runs the 050 repair through the store's own lookups. A malicious finding with
// an invalid range and exact versions must keep blocking only those versions;
// one without exact versions must not turn into an all-version blocking finding
// but be quarantined, i.e. gone from lookups and exported to delta-syncing
// clients as withdrawn. The migration reports its counts as a NOTICE.
func TestVersionRangeBoundaryRepairKeepsMaliciousFindingsScopedAgainstPostgres(t *testing.T) {
	store, dsn := startDockerPostgresStore(t)
	ctx := context.Background()

	down, err := migrations.ReadEmbeddedMigration(50, migrations.MigrationDirectionDown)
	if err != nil {
		t.Fatalf("read migration 050 down: %v", err)
	}
	up, err := migrations.ReadEmbeddedMigration(50, migrations.MigrationDirectionUp)
	if err != nil {
		t.Fatalf("read migration 050 up: %v", err)
	}
	// Go back to the pre-050 check so rows it accepted can be seeded.
	if _, err := store.pool.Exec(ctx, down.SQL); err != nil {
		t.Fatalf("apply 050 down: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO malicious_findings (id, ecosystem, name, version_ranges, versions, source, risk_type, summary)
		VALUES
			('MAL-050-scoped', 'npm', 'repair-scoped', '[{}]'::jsonb, '["1.0.0"]'::jsonb, 'openssf', 'malware', 'scoped fixture'),
			('MAL-050-unscoped', 'npm', 'repair-unscoped', '[{"events":[{"introduced":null}]}]'::jsonb, NULL, 'openssf', 'malware', 'unscoped fixture')`); err != nil {
		t.Fatalf("seed malicious findings accepted by the pre-050 check: %v", err)
	}
	var since time.Time
	if err := store.pool.QueryRow(ctx, `SELECT NOW()`).Scan(&since); err != nil {
		t.Fatalf("read database time: %v", err)
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	var notices []string
	config.OnNotice = func(_ *pgconn.PgConn, notice *pgconn.Notice) {
		notices = append(notices, notice.Message)
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := conn.Exec(ctx, up.SQL); err != nil {
		_ = conn.Close(ctx)
		t.Fatalf("apply 050 up: %v", err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatalf("close connection: %v", err)
	}

	wantNotice := "malicious_findings version_ranges cleared (exact versions apply): 1; malicious_findings quarantined (removed_at set): 1"
	if len(notices) != 1 || !strings.Contains(notices[0], wantNotice) {
		t.Fatalf("050 notices = %q, want one containing %q", notices, wantNotice)
	}

	if findings, err := store.FindMalicious(ctx, "npm", "repair-scoped", "1.0.0"); err != nil || len(findings) != 1 {
		t.Fatalf("FindMalicious(repair-scoped@1.0.0) = %+v, %v; want the exact-version finding", findings, err)
	}
	if findings, err := store.FindMalicious(ctx, "npm", "repair-scoped", "2.0.0"); err != nil || len(findings) != 0 {
		t.Fatalf("FindMalicious(repair-scoped@2.0.0) = %+v, %v; want none (only exact versions match)", findings, err)
	}
	for _, version := range []string{"0.0.1", "1.0.0", "9.9.9"} {
		if findings, err := store.FindMalicious(ctx, "npm", "repair-unscoped", version); err != nil || len(findings) != 0 {
			t.Fatalf("FindMalicious(repair-unscoped@%s) = %+v, %v; want none (quarantined, not all-version)", version, findings, err)
		}
	}

	exported, err := store.ExportSync(ctx, db.SyncExportOptions{
		Since:      &since,
		SnapshotAt: time.Now().UTC().Add(time.Minute),
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("ExportSync(delta) error = %v", err)
	}
	got := map[string]db.SyncMalicious{}
	for _, row := range exported.Malicious {
		got[row.ID] = row
	}
	if row, ok := got["MAL-050-unscoped"]; !ok || !row.Withdrawn {
		t.Fatalf("delta export of quarantined finding = %+v (present=%t), want withdrawn", row, ok)
	}
	if row, ok := got["MAL-050-scoped"]; !ok || row.Withdrawn || row.VersionRanges != "" || row.Versions != `["1.0.0"]` {
		t.Fatalf("delta export of scoped finding = %+v (present=%t), want active with exact versions only", row, ok)
	}
}
