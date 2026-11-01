//go:build integration

package postgres

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// syncDeltaBoundary returns a database timestamp after every committed write
// so far, usable as the since bound of the next delta export.
func syncDeltaBoundary(ctx context.Context, t *testing.T, store *Store) time.Time {
	t.Helper()
	var boundary time.Time
	if err := store.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&boundary); err != nil {
		t.Fatalf("read delta boundary: %v", err)
	}
	return boundary.UTC()
}

// deltaAffectedPackages exports a delta since the boundary and returns the
// ecosystem/name pairs it sends for one vulnerability.
func deltaAffectedPackages(ctx context.Context, t *testing.T, store *Store, since time.Time, id string) []string {
	t.Helper()
	exported, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &since})
	if err != nil {
		t.Fatalf("ExportSync(delta) error = %v", err)
	}
	if !exported.VulnerabilityAffectedComplete {
		t.Fatal("ExportSync(delta).VulnerabilityAffectedComplete = false, want the complete-affected-set guarantee")
	}
	var packages []string
	for _, row := range exported.Vulnerabilities {
		if row.ID == id {
			packages = append(packages, row.Ecosystem+"/"+row.Name)
		}
	}
	slices.Sort(packages)
	return packages
}

// testManualEditDeltaSendsCompleteAffectedSet moves a manual advisory from one
// package to another. The next delta must include the advisory with exactly
// its current package, so a client replacing the advisory's local affected
// rows drops the old package.
func testManualEditDeltaSendsCompleteAffectedSet(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const id = "manual:delta-coverage-move"
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID: id, FindingType: "vulnerability", Ecosystem: "npm", Name: "delta-move-a",
		Severity: "HIGH", Summary: "coverage move",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(create) error = %v", err)
	}
	current, err := store.GetManualAdvisory(ctx, id)
	if err != nil || current == nil {
		t.Fatalf("GetManualAdvisory(create) = %+v, %v; want advisory", current, err)
	}
	since := syncDeltaBoundary(ctx, t, store)

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID: id, FindingType: "vulnerability", Ecosystem: "npm", Name: "delta-move-b",
		Severity: "HIGH", Summary: "coverage move", UpdatedAt: current.UpdatedAt,
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(edit) error = %v", err)
	}

	if got, want := deltaAffectedPackages(ctx, t, store, since, id), []string{"npm/delta-move-b"}; !slices.Equal(got, want) {
		t.Fatalf("delta affected packages for %s = %q, want %q", id, got, want)
	}
}

// testPackageNameRepairDeltaIncludesMergedVulnerability seeds an advisory
// whose legacy non-canonical row duplicates its canonical row. The repair only
// deletes the legacy row, so it must still mark the advisory changed: otherwise
// no delta would ever send it again and clients would keep the legacy row.
func testPackageNameRepairDeltaIncludesMergedVulnerability(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const id = "GHSA-name-repair-delta"
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified)
		VALUES ('GHSA-name-repair-delta', 'repair delta', 'HIGH', NOW(), NOW());
		INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected)
		VALUES
			('GHSA-name-repair-delta', 'actions', 'Repair-Delta/Action', '[]'::jsonb, '["1.0.0"]'::jsonb),
			('GHSA-name-repair-delta', 'actions', 'repair-delta/action', '[]'::jsonb, '["1.0.0"]'::jsonb);
	`); err != nil {
		t.Fatalf("insert legacy duplicate rows: %v", err)
	}
	since := syncDeltaBoundary(ctx, t, store)

	if _, err := store.RepairCaseInsensitivePackageNames(ctx); err != nil {
		t.Fatalf("RepairCaseInsensitivePackageNames() error = %v", err)
	}

	if got, want := deltaAffectedPackages(ctx, t, store, since, id), []string{"actions/repair-delta/action"}; !slices.Equal(got, want) {
		t.Fatalf("delta affected packages for %s = %q, want %q", id, got, want)
	}
}
