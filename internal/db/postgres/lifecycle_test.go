//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestPostgresLifecycleDockerReplaceAndFindings(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	eolPast := now.AddDate(0, 0, -1)
	eoasPast := now.AddDate(0, 0, -7)
	eolSoon := now.AddDate(0, 0, 30)

	djangoProduct := db.LifecycleProduct{
		ProductSlug: "django",
		Name:        "Django",
		Category:    "framework",
		Identifiers: json.RawMessage(`[{"type":"purl","id":"pkg:pypi/django"}]`),
		Raw:         json.RawMessage(`{"name":"django"}`),
		Releases: []db.LifecycleRelease{
			{Cycle: "3.2", Latest: "3.2.25", EOLFrom: &eolPast, IsMaintained: false, Raw: json.RawMessage(`{"name":"3.2"}`)},
			{Cycle: "4", Latest: "4.1.13", IsEOL: true, IsMaintained: false, Raw: json.RawMessage(`{"name":"4"}`)},
			{Cycle: "4.2", Latest: "4.2.22", IsEOAS: true, EOASFrom: &eoasPast, IsMaintained: true, Raw: json.RawMessage(`{"name":"4.2"}`)},
			{Cycle: "5.0", Latest: "5.0.14", EOLFrom: &eolSoon, IsMaintained: true, Raw: json.RawMessage(`{"name":"5.0"}`)},
			{Cycle: "6.0", Latest: "6.0.1", IsMaintained: true, Raw: json.RawMessage(`{"name":"6.0"}`)},
		},
		PackageMaps: []db.LifecyclePackageMap{
			{Ecosystem: "pypi", Name: "django", ProductSlug: "django", PURLType: "pypi", PURLName: "django"},
		},
	}
	if _, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{djangoProduct}); err != nil {
		t.Fatalf("ReplaceLifecycleProducts(initial django) error = %v", err)
	}

	findings, err := store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{
		{Ecosystem: "pypi", Name: "django", Version: "3.2.25"},
		{Ecosystem: "pypi", Name: "django", Version: "4.1.1"},
		{Ecosystem: "pypi", Name: "django", Version: "4.2.11"},
		{Ecosystem: "pypi", Name: "django", Version: "5.0.1"},
		{Ecosystem: "pypi", Name: "django", Version: "6.0.0"},
	}, now)
	if err != nil {
		t.Fatalf("FindLifecycleFindingsBatch() error = %v", err)
	}

	byVersion := make(map[string]domain.Finding, len(findings))
	for _, finding := range findings {
		byVersion[finding.Version] = finding
	}
	if len(byVersion) != 4 {
		t.Fatalf("FindLifecycleFindingsBatch() returned %d findings: %+v", len(findings), findings)
	}

	assertLifecycleFinding(t, byVersion["3.2.25"], domain.FindingTypeSupplyChainRisk, domain.SeverityCritical, "eol")
	assertLifecycleFinding(t, byVersion["4.1.1"], domain.FindingTypeSupplyChainRisk, domain.SeverityCritical, "eol")
	assertLifecycleFinding(t, byVersion["4.2.11"], domain.FindingTypeLifecycle, domain.SeverityLow, "security_support_only")
	assertLifecycleFinding(t, byVersion["5.0.1"], domain.FindingTypeLifecycle, domain.SeverityMedium, "eol_soon")
	if _, ok := byVersion["6.0.0"]; ok {
		t.Fatalf("6.0.0 produced lifecycle finding despite no EOL/EOAS signal: %+v", byVersion["6.0.0"])
	}

	exported, err := store.ExportSync(ctx, db.SyncExportOptions{SnapshotAt: time.Now().UTC().Add(time.Minute)})
	if err != nil {
		t.Fatalf("ExportSync() error = %v", err)
	}
	if len(exported.Lifecycle) != 5 {
		t.Fatalf("ExportSync().Lifecycle = %d, want 5 release rows: %+v", len(exported.Lifecycle), exported.Lifecycle)
	}
	first := exported.Lifecycle[0]
	if first.ID == "" || first.Ecosystem != "pypi" || first.Name != "django" || first.ProductSlug != "django" || first.Cycle == "" {
		t.Fatalf("ExportSync().Lifecycle[0] = %+v, want flattened lifecycle release row", first)
	}

	oldlibProduct := db.LifecycleProduct{
		ProductSlug: "oldlib",
		Name:        "OldLib",
		Releases:    []db.LifecycleRelease{{Cycle: "1", IsEOL: true}},
		PackageMaps: []db.LifecyclePackageMap{{Ecosystem: "npm", Name: "oldlib", ProductSlug: "oldlib"}},
	}
	if _, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{djangoProduct, oldlibProduct}); err != nil {
		t.Fatalf("ReplaceLifecycleProducts(with oldlib) error = %v", err)
	}
	var beforeLifecycleDelete time.Time
	if err := store.pool.QueryRow(ctx, `SELECT NOW()`).Scan(&beforeLifecycleDelete); err != nil {
		t.Fatalf("read database time before lifecycle delete: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	deleted, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{djangoProduct})
	if err != nil {
		t.Fatalf("ReplaceLifecycleProducts() error = %v", err)
	}
	if deleted != 1 {
		t.Fatalf("ReplaceLifecycleProducts() deleted = %d, want 1 stale product", deleted)
	}
	tombstoneExport, err := store.ExportSync(ctx, db.SyncExportOptions{
		Since:      &beforeLifecycleDelete,
		SnapshotAt: time.Now().UTC().Add(time.Minute),
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("ExportSync(after lifecycle delete) error = %v", err)
	}
	if !syncLifecycleExportContains(tombstoneExport.Lifecycle, "endoflife:npm:oldlib:oldlib:1", true) {
		t.Fatalf("ExportSync(after lifecycle delete) missing oldlib tombstone: %+v", tombstoneExport.Lifecycle)
	}
	findings, err = store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "oldlib", Version: "1.0.0"},
	}, now)
	if err != nil {
		t.Fatalf("FindLifecycleFindingsBatch(oldlib) error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("oldlib findings after reconcile = %+v, want none", findings)
	}

	var beforeEmptyReplace time.Time
	if err := store.pool.QueryRow(ctx, `SELECT NOW()`).Scan(&beforeEmptyReplace); err != nil {
		t.Fatalf("read database time before empty lifecycle replace: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	deleted, err = store.ReplaceLifecycleProducts(ctx, nil)
	if err != nil {
		t.Fatalf("ReplaceLifecycleProducts(empty snapshot) error = %v", err)
	}
	if deleted != 1 {
		t.Fatalf("ReplaceLifecycleProducts(empty snapshot) deleted = %d, want remaining django product", deleted)
	}
	emptyReplaceExport, err := store.ExportSync(ctx, db.SyncExportOptions{
		Since:      &beforeEmptyReplace,
		SnapshotAt: time.Now().UTC().Add(time.Minute),
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("ExportSync(after empty lifecycle replace) error = %v", err)
	}
	if !syncLifecycleExportContains(emptyReplaceExport.Lifecycle, "endoflife:pypi:django:django:3.2", true) {
		t.Fatalf("ExportSync(after empty lifecycle replace) missing django tombstone: %+v", emptyReplaceExport.Lifecycle)
	}
}

func syncLifecycleExportContains(items []db.SyncLifecycleRelease, id string, withdrawn bool) bool {
	for _, item := range items {
		if item.ID == id && item.Withdrawn == withdrawn {
			return true
		}
	}
	return false
}

func assertLifecycleFinding(t *testing.T, finding domain.Finding, typ domain.FindingType, severity domain.Severity, riskType string) {
	t.Helper()

	if finding.Type != typ || finding.Severity != severity || finding.RiskType != riskType {
		t.Fatalf("finding for %s = type %s severity %s risk %s, want type %s severity %s risk %s",
			finding.Version, finding.Type, finding.Severity, finding.RiskType, typ, severity, riskType)
	}
	if finding.Source != "endoflife.date" {
		t.Fatalf("finding source = %q, want endoflife.date", finding.Source)
	}
	if finding.AdvisoryID == "" || finding.Title == "" || finding.URL == "" {
		t.Fatalf("finding missing identity fields: %+v", finding)
	}
}
