//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestF106F108PostgresContracts(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	t.Run("F106 child removal and resurrection produce exact lifecycle deltas", func(t *testing.T) {
		product := f106LifecycleProduct("f106-delta", []string{"1", "2"}, []db.LifecyclePackageMap{
			{Ecosystem: "npm", Name: "f106-delta-a"},
			{Ecosystem: "pypi", Name: "F106.Delta_B"},
		})
		if _, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{product}); err != nil {
			t.Fatal(err)
		}
		baseline := f106SyncSnapshot(t, store, ctx)

		reduced := product
		reduced.Releases = reduced.Releases[:1]
		reduced.PackageMaps = reduced.PackageMaps[:1]
		if _, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{reduced}); err != nil {
			t.Fatal(err)
		}
		delta := f106SyncDelta(t, store, ctx, baseline)
		f106AssertLifecycleDelta(t, delta.Lifecycle, map[string]bool{
			"endoflife:npm:f106-delta-a:f106-delta:1":  false,
			"endoflife:npm:f106-delta-a:f106-delta:2":  true,
			"endoflife:pypi:f106-delta-b:f106-delta:1": true,
			"endoflife:pypi:f106-delta-b:f106-delta:2": true,
		})

		reducedBaseline := f106SyncSnapshot(t, store, ctx)
		if _, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{product}); err != nil {
			t.Fatal(err)
		}
		resurrected := f106SyncDelta(t, store, ctx, reducedBaseline)
		want := map[string]bool{}
		for _, name := range []string{"f106-delta-a", "f106-delta-b"} {
			for _, cycle := range []string{"1", "2"} {
				want[fmt.Sprintf("endoflife:%s:%s:f106-delta:%s", map[bool]string{true: "npm", false: "pypi"}[name == "f106-delta-a"], name, cycle)] = false
			}
		}
		f106AssertLifecycleDelta(t, resurrected.Lifecycle, want)
	})

	t.Run("F106 feed deletion preserves nonfeed products and emits one tombstone", func(t *testing.T) {
		feed := f106LifecycleProduct("f106-feed-delete", []string{"1"}, []db.LifecyclePackageMap{{Ecosystem: "npm", Name: "f106-feed-delete"}})
		if _, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{feed}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO lifecycle_products(product_slug,name,source) VALUES('f106-owned','owned','other');
			INSERT INTO lifecycle_releases(product_slug,cycle,is_eol) VALUES('f106-owned','9',true);
			INSERT INTO lifecycle_package_map(ecosystem,name,product_slug,source) VALUES('npm','f106-owned','f106-owned','other')`); err != nil {
			t.Fatal(err)
		}
		baseline := f106SyncSnapshot(t, store, ctx)
		deleted, err := store.ReplaceLifecycleProducts(ctx, nil)
		if err != nil || deleted != 1 {
			t.Fatalf("ReplaceLifecycleProducts(nil) = %d, %v; want 1, nil", deleted, err)
		}
		delta := f106SyncDelta(t, store, ctx, baseline)
		f106AssertLifecycleDelta(t, delta.Lifecycle, map[string]bool{"endoflife:npm:f106-feed-delete:f106-feed-delete:1": true})
		var products, releases, maps int
		if err := store.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM lifecycle_products WHERE product_slug='f106-owned'),
			(SELECT count(*) FROM lifecycle_releases WHERE product_slug='f106-owned'),
			(SELECT count(*) FROM lifecycle_package_map WHERE product_slug='f106-owned')`).Scan(&products, &releases, &maps); err != nil {
			t.Fatal(err)
		}
		if products != 1 || releases != 1 || maps != 1 {
			t.Fatalf("nonfeed rows = product %d release %d map %d, want all 1", products, releases, maps)
		}
	})

	t.Run("F106 defaults blanks canonical names and multiple products are persisted", func(t *testing.T) {
		past := time.Now().UTC().AddDate(-1, 0, 0)
		products := []db.LifecycleProduct{
			{ProductSlug: " ", Releases: []db.LifecycleRelease{{Cycle: "ignored"}}, PackageMaps: []db.LifecyclePackageMap{{Ecosystem: "npm", Name: "ignored"}}},
			{ProductSlug: "f106-default-a", Releases: []db.LifecycleRelease{{Cycle: "1", EOLFrom: &past}, {Cycle: " "}}, PackageMaps: []db.LifecyclePackageMap{{Ecosystem: "pypi", Name: "Shared.Pkg"}, {Ecosystem: "nuget", Name: "Shared.Pkg"}, {Ecosystem: "", Name: "blank"}}},
			{ProductSlug: "f106-default-b", Name: "Second", Releases: []db.LifecycleRelease{{Cycle: "1", EOLFrom: &past}}, PackageMaps: []db.LifecyclePackageMap{{Ecosystem: "pypi", Name: "shared-pkg"}}},
		}
		if _, err := store.ReplaceLifecycleProducts(ctx, products); err != nil {
			t.Fatal(err)
		}
		var label, releaseOwner, mapSource, pypi, nuget string
		if err := store.pool.QueryRow(ctx, `SELECT p.name,r.product_slug,m.source,
			(SELECT name FROM lifecycle_package_map WHERE product_slug='f106-default-a' AND ecosystem='pypi'),
			(SELECT name FROM lifecycle_package_map WHERE product_slug='f106-default-a' AND ecosystem='nuget')
			FROM lifecycle_products p JOIN lifecycle_releases r USING(product_slug)
			JOIN lifecycle_package_map m USING(product_slug)
			WHERE p.product_slug='f106-default-a' ORDER BY m.ecosystem LIMIT 1`).Scan(&label, &releaseOwner, &mapSource, &pypi, &nuget); err != nil {
			t.Fatal(err)
		}
		if label != "f106-default-a" || releaseOwner != "f106-default-a" || mapSource != lifecycleSource || pypi != "shared-pkg" || nuget != "shared.pkg" {
			t.Fatalf("defaults/canonical values = %q %q %q %q %q", label, releaseOwner, mapSource, pypi, nuget)
		}
		findings, err := store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{{Ecosystem: "pypi", Name: "SHARED.PKG", Version: "1.0.0"}}, time.Now().UTC())
		if err != nil || len(findings) != 2 {
			t.Fatalf("FindLifecycleFindingsBatch() = %+v, %v; want exactly two products", findings, err)
		}
		ids := []string{findings[0].AdvisoryID, findings[1].AdvisoryID}
		sort.Strings(ids)
		if !slices.Equal(ids, []string{"endoflife:f106-default-a:1:eol", "endoflife:f106-default-b:1:eol"}) {
			t.Fatalf("finding identities = %q", ids)
		}
	})

	t.Run("F107 single and batch malicious lookups preserve order fields and deduplicate versions", func(t *testing.T) {
		items := []db.MaliciousFinding{
			{ID: "F107-lookup-b", Ecosystem: "npm", Name: "f107-lookup", Versions: json.RawMessage(`["1.0.0"]`), Source: "", RiskType: "", Severity: "HIGH", Summary: "", ReferenceURLs: json.RawMessage(`["https://example.invalid/b","https://example.invalid/ignored"]`)},
			{ID: "F107-lookup-a", Ecosystem: "npm", Name: "f107-lookup", Versions: json.RawMessage(`["1.0.0"]`), Source: "f107", RiskType: "typosquatting", Severity: "MEDIUM", Summary: "explicit", ReferenceURLs: json.RawMessage(`["https://example.invalid/a"]`)},
		}
		for i := range items {
			if err := store.UpsertMaliciousFinding(ctx, &items[i]); err != nil {
				t.Fatal(err)
			}
		}
		stamp := time.Now().UTC()
		if _, err := store.pool.Exec(ctx, `UPDATE malicious_findings SET updated_at=$1 WHERE id='F107-lookup-b'`, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `UPDATE malicious_findings SET updated_at=$1::timestamptz-$2::interval WHERE id='F107-lookup-a'`, stamp, "1 second"); err != nil {
			t.Fatal(err)
		}
		single, err := store.FindMalicious(ctx, "npm", "f107-lookup", "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		batch, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "f107-lookup", Version: "1.0.0"}, {Ecosystem: "npm", Name: "f107-lookup", Version: "1.0.0"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(single) != 2 || len(batch) != 2 || !reflectFindingSlices(single, batch) {
			t.Fatalf("single=%+v batch=%+v, want exact parity without duplicates", single, batch)
		}
		want := []domain.Finding{
			{Name: "f107-lookup", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Type: domain.FindingTypeMalicious, Severity: domain.SeverityHigh, AdvisoryID: "F107-lookup-b", Title: "malicious package: f107-lookup (malware)", URL: "https://example.invalid/b", RiskType: "malware", Source: "unknown"},
			{Name: "f107-lookup", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Type: domain.FindingTypeSupplyChainRisk, Severity: domain.SeverityMedium, AdvisoryID: "F107-lookup-a", Title: "explicit", URL: "https://example.invalid/a", RiskType: "typosquatting", Source: "f107"},
		}
		if !reflectFindingSlices(single, want) {
			t.Fatalf("findings = %+v, want %+v", single, want)
		}
	})

	t.Run("F107 import delete directives preserve foreign ownership and commit status audit atomically", func(t *testing.T) {
		for _, item := range []db.MaliciousFinding{
			{ID: "F107-delete-owned", Ecosystem: "npm", Name: "owned", Source: "f107-import", RiskType: "malware", Severity: "HIGH"},
			{ID: "F107-delete-foreign", Ecosystem: "npm", Name: "foreign", Source: "other", RiskType: "malware", Severity: "HIGH"},
		} {
			item := item
			if err := store.UpsertMaliciousFinding(ctx, &item); err != nil {
				t.Fatal(err)
			}
		}
		status := &db.FeedSyncStatus{FeedName: "f107-import", LastSyncStatus: "success", EntriesSynced: 0, EntriesTotal: 4, LastError: ""}
		builder := func(imported, deleted int) db.AdminAuditEntry {
			return db.AdminAuditEntry{Action: "f107_import_delete", Details: json.RawMessage(fmt.Sprintf(`{"imported":%d,"deleted":%d}`, imported, deleted))}
		}
		imported, deleted, err := store.ImportMaliciousFeedWithAudit(ctx, "f107-import", nil, []string{"F107-delete-owned", "F107-delete-missing", "F107-delete-foreign", "F107-delete-owned"}, status, builder)
		if err != nil || imported != 0 || deleted != 4 {
			t.Fatalf("ImportMaliciousFeedWithAudit() = %d,%d,%v", imported, deleted, err)
		}
		var ownedRemoved, foreignRemoved *time.Time
		if err := store.pool.QueryRow(ctx, `SELECT
			(SELECT removed_at FROM malicious_findings WHERE id='F107-delete-owned'),
			(SELECT removed_at FROM malicious_findings WHERE id='F107-delete-foreign')`).Scan(&ownedRemoved, &foreignRemoved); err != nil {
			t.Fatal(err)
		}
		if ownedRemoved == nil || foreignRemoved != nil {
			t.Fatalf("removed timestamps owned=%v foreign=%v", ownedRemoved, foreignRemoved)
		}
		var missing, tombstones int
		if err := store.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM malicious_findings WHERE id='F107-delete-missing'),
			(SELECT count(*) FROM malicious_findings WHERE id IN ('F107-delete-owned','F107-delete-foreign') AND removed_at IS NOT NULL)`).Scan(&missing, &tombstones); err != nil {
			t.Fatal(err)
		}
		if missing != 0 || tombstones != 1 {
			t.Fatalf("missing=%d tombstones=%d", missing, tombstones)
		}
		gotStatus, err := store.GetFeedSyncStatus(ctx, "f107-import")
		if err != nil || gotStatus == nil || gotStatus.LastSyncStatus != "success" || gotStatus.EntriesTotal != 4 || gotStatus.EntriesSynced != 0 {
			t.Fatalf("status=%+v err=%v", gotStatus, err)
		}
		f106RequireAuditActionCount(t, store, ctx, "f107_import_delete", 1)
		plain := db.MaliciousFinding{ID: "F107-plain-import", Ecosystem: "npm", Name: "plain", Source: "openssf", RiskType: "malware", Severity: "LOW"}
		if imported, deleted, err := store.ImportMaliciousFeed(ctx, "f107-plain", []db.MaliciousFinding{plain}, nil, nil); err != nil || imported != 1 || deleted != 0 {
			t.Fatalf("ImportMaliciousFeed() = %d,%d,%v", imported, deleted, err)
		}
	})

	t.Run("F107 listing maps optionals orders rows filters sources excludes tombstones and clamps limits", func(t *testing.T) {
		published := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		for _, item := range []db.MaliciousFinding{
			{ID: "F107-list-b", Ecosystem: "npm", Name: "list-b", VersionRanges: json.RawMessage(`[]`), Versions: json.RawMessage(`["1"]`), Source: "f107-list", RiskType: "malware", Severity: "HIGH", Summary: "b", Description: "desc", ReferenceURLs: json.RawMessage(`["https://example.invalid"]`), OriginRef: "origin", Published: &published, CreatedBy: "creator"},
			{ID: "F107-list-a", Ecosystem: "npm", Name: "list-a", Source: "f107-list", RiskType: "supply_chain", Severity: "LOW", Summary: "a"},
			{ID: "F107-list-other", Ecosystem: "npm", Name: "other", Source: "other-list", RiskType: "malware", Severity: "HIGH"},
			{ID: "F107-list-removed", Ecosystem: "npm", Name: "removed", Source: "f107-list", RiskType: "malware", Severity: "HIGH"},
		} {
			item := item
			if err := store.UpsertMaliciousFinding(ctx, &item); err != nil {
				t.Fatal(err)
			}
		}
		stamp := time.Now().UTC()
		if _, err := store.pool.Exec(ctx, `UPDATE malicious_findings SET updated_at=$1,created_at=$1 WHERE id='F107-list-b'`, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `UPDATE malicious_findings SET updated_at=$1::timestamptz,created_at=$1::timestamptz-$2::interval WHERE id='F107-list-a'`, stamp, "1 second"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `UPDATE malicious_findings SET removed_at=$1 WHERE id='F107-list-removed'`, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary)
			SELECT 'F107-limit-'||lpad(g::text,3,'0'),'npm','limit-'||g,'f107-limit','malware','LOW','' FROM generate_series(0,500) g`); err != nil {
			t.Fatal(err)
		}
		listed, err := store.ListMaliciousFindings(ctx, "f107-list", 20)
		if err != nil || len(listed) != 2 || listed[0].ID != "F107-list-b" || listed[1].ID != "F107-list-a" {
			t.Fatalf("list=%+v err=%v", listed, err)
		}
		got := listed[0]
		if string(got.VersionRanges) != "[]" || string(got.Versions) != `["1"]` || got.Description != "desc" || string(got.ReferenceURLs) != `["https://example.invalid"]` || got.OriginRef != "origin" || got.Published == nil || !got.Published.Equal(published) || got.CreatedBy != "creator" {
			t.Fatalf("optional fields = %+v", got)
		}
		limited, err := store.ListMaliciousFindings(ctx, "f107-limit", 501)
		if err != nil || len(limited) != 500 {
			t.Fatalf("limit 501 = %d, %v; want 500", len(limited), err)
		}
		if unscoped, err := store.ListMaliciousFindings(ctx, "", 1); err != nil || len(unscoped) != 1 {
			t.Fatalf("unscoped list = %d, %v", len(unscoped), err)
		}
	})

	t.Run("F107 repeated delete is timestamp stable and resurrection emits exact deltas", func(t *testing.T) {
		item := db.MaliciousFinding{ID: "F107-resurrect", Ecosystem: "npm", Name: "f107-resurrect", Source: "f107-resurrect", RiskType: "malware", Severity: "CRITICAL"}
		if err := store.UpsertMaliciousFinding(ctx, &item); err != nil {
			t.Fatal(err)
		}
		baseline := f106SyncSnapshot(t, store, ctx)
		if err := store.DeleteMaliciousFinding(ctx, item.ID); err != nil {
			t.Fatal(err)
		}
		var first time.Time
		if err := store.pool.QueryRow(ctx, `SELECT removed_at FROM malicious_findings WHERE id=$1`, item.ID).Scan(&first); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
		if err := store.DeleteMaliciousFinding(ctx, item.ID); err != nil {
			t.Fatal(err)
		}
		var second time.Time
		if err := store.pool.QueryRow(ctx, `SELECT removed_at FROM malicious_findings WHERE id=$1`, item.ID).Scan(&second); err != nil || !first.Equal(second) {
			t.Fatalf("repeated delete timestamp = %v, %v; want stable", second, err)
		}
		delta := f106SyncDelta(t, store, ctx, baseline)
		f106AssertMaliciousDelta(t, delta.Malicious, item.ID, true)
		deletedBaseline := f106SyncSnapshot(t, store, ctx)
		if err := store.UpsertMaliciousFinding(ctx, &item); err != nil {
			t.Fatal(err)
		}
		f106AssertMaliciousDelta(t, f106SyncDelta(t, store, ctx, deletedBaseline).Malicious, item.ID, false)
		for _, extra := range []db.MaliciousFinding{
			{ID: "F107-bulk-success", Ecosystem: "npm", Name: "bulk", Source: "f107-bulk-success", RiskType: "malware", Severity: "LOW"},
			{ID: "F107-prune-success", Ecosystem: "npm", Name: "prune", Source: "f107-prune-success", RiskType: "malware", Severity: "LOW"},
		} {
			extra := extra
			if err := store.UpsertMaliciousFinding(ctx, &extra); err != nil {
				t.Fatal(err)
			}
		}
		if count, err := store.DeleteMaliciousFindingsNotInSource(ctx, "f107-bulk-success", []string{"absent"}); err != nil || count != 1 {
			t.Fatalf("DeleteMaliciousFindingsNotInSource() = %d,%v", count, err)
		}
		if _, err := store.pool.Exec(ctx, `UPDATE malicious_findings SET updated_at=now()-interval '1 hour' WHERE id='F107-prune-success'`); err != nil {
			t.Fatal(err)
		}
		if count, err := store.PruneMaliciousFindingsForSourceUpdatedBefore(ctx, "f107-prune-success", time.Now().UTC()); err != nil || count != 1 {
			t.Fatalf("PruneMaliciousFindingsForSourceUpdatedBefore() = %d,%v", count, err)
		}
		if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{ID: "F107-source-delete-success", Ecosystem: "npm", Name: "source", Source: "f107-source-success", RiskType: "malware", Severity: "LOW"}); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteMaliciousFindingForSource(ctx, "F107-source-delete-success", "f107-source-success"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("F107 invalid late imports roll back rows status and audit", func(t *testing.T) {
		invalid := []db.MaliciousFinding{
			{ID: "F107-invalid-eco", Ecosystem: "invalid", Name: "pkg", Source: "f107-invalid", RiskType: "malware", Severity: "HIGH"},
			{ID: "F107-invalid-severity", Ecosystem: "npm", Name: "pkg", Source: "f107-invalid", RiskType: "malware", Severity: "invalid"},
			{ID: "F107-invalid-json", Ecosystem: "npm", Name: "pkg", Source: "f107-invalid", RiskType: "malware", Severity: "HIGH", Versions: json.RawMessage(`{}`)},
		}
		for i, bad := range invalid {
			goodID := fmt.Sprintf("F107-valid-before-%d", i)
			good := db.MaliciousFinding{ID: goodID, Ecosystem: "npm", Name: "good", Source: "f107-invalid", RiskType: "malware", Severity: "HIGH"}
			feed := fmt.Sprintf("f107-invalid-%d", i)
			status := &db.FeedSyncStatus{FeedName: feed, LastSyncStatus: "success"}
			action := fmt.Sprintf("f107_invalid_%d", i)
			_, _, err := store.ImportMaliciousFeedWithAudit(ctx, "f107-invalid", []db.MaliciousFinding{good, bad}, nil, status, func(_, _ int) db.AdminAuditEntry { return db.AdminAuditEntry{Action: action} })
			if err == nil {
				t.Fatalf("invalid import %d succeeded", i)
			}
			var rows int
			if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM malicious_findings WHERE id=ANY($1)`, []string{goodID, bad.ID}).Scan(&rows); err != nil || rows != 0 {
				t.Fatalf("invalid import rows=%d err=%v", rows, err)
			}
			if got, err := store.GetFeedSyncStatus(ctx, feed); err != nil || got != nil {
				t.Fatalf("status after rollback=%+v err=%v", got, err)
			}
			f106RequireAuditActionCount(t, store, ctx, action, 0)
		}
		good := db.MaliciousFinding{ID: "F107-invalid-status-good", Ecosystem: "npm", Name: "good", Source: "f107-invalid-status", RiskType: "malware", Severity: "HIGH"}
		if _, _, err := store.ImportMaliciousFeed(ctx, "f107-invalid-status", []db.MaliciousFinding{good}, nil, &db.FeedSyncStatus{FeedName: "f107-invalid-status", LastSyncStatus: "invalid"}); err == nil {
			t.Fatal("invalid status import unexpectedly succeeded")
		}
		if _, _, err := store.ImportMaliciousFeedWithAudit(ctx, "f107-invalid-audit", []db.MaliciousFinding{{ID: "F107-invalid-audit-good", Ecosystem: "npm", Name: "good", Source: "f107-invalid-audit", RiskType: "malware", Severity: "HIGH"}}, nil, nil, func(_, _ int) db.AdminAuditEntry { return db.AdminAuditEntry{} }); !errors.Is(err, db.ErrAdminAuditLog) {
			t.Fatalf("invalid audit error = %v", err)
		}
		var rolledBack int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM malicious_findings WHERE id IN ('F107-invalid-status-good','F107-invalid-audit-good')`).Scan(&rolledBack); err != nil || rolledBack != 0 {
			t.Fatalf("late invalid rollback rows=%d err=%v", rolledBack, err)
		}
	})

	t.Run("F108 matching revision audited update replaces exact vulnerability state", func(t *testing.T) {
		const id = "manual:f108-update"
		if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{ID: id, FindingType: "vulnerability", Ecosystem: "npm", Name: "f108-old", Severity: "HIGH", Summary: "old", Description: "old"}); err != nil {
			t.Fatal(err)
		}
		loaded, err := store.GetManualAdvisory(ctx, id)
		if err != nil || loaded == nil {
			t.Fatalf("loaded=%+v err=%v", loaded, err)
		}
		edit := &db.ManualAdvisory{ID: id, FindingType: "vulnerability", Ecosystem: "pypi", Name: "F108.New_Pkg", Severity: "LOW", Summary: "new", Description: "", UpdatedAt: loaded.UpdatedAt}
		if err := store.UpsertManualAdvisoryWithAudit(ctx, edit, &db.AdminAuditEntry{Action: "f108_update"}); err != nil {
			t.Fatal(err)
		}
		rows := manualAdvisoriesWithID(ctx, t, store, id)
		if len(rows) != 1 || rows[0].Severity != "LOW" || rows[0].Description != "" || rows[0].Ecosystem != "pypi" || rows[0].Name != "f108-new-pkg" || rows[0].Summary != "new" {
			t.Fatalf("updated advisory = %+v", rows)
		}
		old, _ := store.FindVulnerabilities(ctx, "npm", "f108-old", "1")
		moved, _ := store.FindVulnerabilities(ctx, "pypi", "f108-new-pkg", "1")
		if findingsContainAdvisory(old, id) || len(moved) != 1 || moved[0].Severity != domain.SeverityLow {
			t.Fatalf("old=%+v moved=%+v", old, moved)
		}
		f106RequireAuditActionCount(t, store, ctx, "f108_update", 1)
		err = store.UpsertManualAdvisoryWithAudit(ctx, &db.ManualAdvisory{ID: "manual:f108-audit-fail", FindingType: "vulnerability", Ecosystem: "npm", Name: "audit-fail", Severity: "LOW"}, &db.AdminAuditEntry{})
		if !errors.Is(err, db.ErrAdminAuditLog) {
			t.Fatalf("anonymous manual audit error = %v", err)
		}
		if got, err := store.GetManualAdvisory(ctx, "manual:f108-audit-fail"); err != nil || got != nil {
			t.Fatalf("anonymous audit rollback = %+v, %v", got, err)
		}
	})

	t.Run("F108 audited delete succeeds once and cannot affect feed data", func(t *testing.T) {
		const manualID = "manual:f108-delete"
		if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{ID: manualID, FindingType: "malicious", Ecosystem: "npm", Name: "f108-delete", Severity: "CRITICAL", RiskType: "malware"}); err != nil {
			t.Fatal(err)
		}
		feed := db.MaliciousFinding{ID: "F108-feed-preserved", Ecosystem: "npm", Name: "f108-delete", Source: "feed", RiskType: "malware", Severity: "HIGH"}
		if err := store.UpsertMaliciousFinding(ctx, &feed); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteManualAdvisoryWithAudit(ctx, manualID, &db.AdminAuditEntry{Action: "f108_delete"}); err != nil {
			t.Fatal(err)
		}
		if got, err := store.GetManualAdvisory(ctx, manualID); err != nil || got != nil {
			t.Fatalf("manual after delete=%+v err=%v", got, err)
		}
		feedRows, err := store.FindMalicious(ctx, "npm", "f108-delete", "1")
		if err != nil || len(feedRows) != 1 || feedRows[0].AdvisoryID != feed.ID {
			t.Fatalf("feed after manual delete=%+v err=%v", feedRows, err)
		}
		f106RequireAuditActionCount(t, store, ctx, "f108_delete", 1)
		const plainID = "manual:f108-delete-plain"
		if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{ID: plainID, FindingType: "vulnerability", Ecosystem: "npm", Name: "plain-delete", Severity: "LOW"}); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteManualAdvisory(ctx, plainID); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteManualAdvisory(ctx, plainID); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("second plain delete error = %v", err)
		}
		if err := store.DeleteManualAdvisoryWithAudit(ctx, plainID, &db.AdminAuditEntry{Action: "missing"}); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("missing audited delete error = %v", err)
		}
		const failedAuditID = "manual:f108-delete-audit-fail"
		if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{ID: failedAuditID, FindingType: "malicious", Ecosystem: "npm", Name: "failed-audit", Severity: "HIGH", RiskType: "malware"}); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteManualAdvisoryWithAudit(ctx, failedAuditID, &db.AdminAuditEntry{}); !errors.Is(err, db.ErrAdminAuditLog) {
			t.Fatalf("anonymous delete audit error = %v", err)
		}
		if got, err := store.GetManualAdvisory(ctx, failedAuditID); err != nil || got == nil {
			t.Fatalf("failed audited delete did not roll back: %+v, %v", got, err)
		}
		for _, deleteCall := range []func() error{
			func() error { return store.DeleteManualAdvisory(ctx, "CVE-2026-3") },
			func() error { return store.DeleteManualAdvisoryWithAudit(ctx, "CVE-2026-3", nil) },
		} {
			if err := deleteCall(); err == nil {
				t.Fatal("feed-owned delete ID unexpectedly accepted")
			}
		}
	})

	t.Run("F108 reverse malicious to vulnerability conversion leaves exactly one active advisory", func(t *testing.T) {
		const id = "manual:f108-reverse"
		if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{ID: id, FindingType: "malicious", Ecosystem: "npm", Name: "f108-reverse", Severity: "CRITICAL", RiskType: "malware"}); err != nil {
			t.Fatal(err)
		}
		loaded, _ := store.GetManualAdvisory(ctx, id)
		if err := store.UpsertManualAdvisoryWithAudit(ctx, &db.ManualAdvisory{ID: id, FindingType: "vulnerability", Ecosystem: "npm", Name: "f108-reverse-vuln", Severity: "MEDIUM", UpdatedAt: loaded.UpdatedAt}, &db.AdminAuditEntry{Action: "f108_reverse"}); err != nil {
			t.Fatal(err)
		}
		active := manualAdvisoriesWithID(ctx, t, store, id)
		if len(active) != 1 || active[0].FindingType != "vulnerability" || active[0].Name != "f108-reverse-vuln" {
			t.Fatalf("active after reverse = %+v", active)
		}
		malicious, _ := store.FindMalicious(ctx, "npm", "f108-reverse", "1")
		if findingsContainAdvisory(malicious, id) {
			t.Fatalf("old malicious remains active: %+v", malicious)
		}
	})

	t.Run("F108 concurrent same revision writers have exactly one audited winner", func(t *testing.T) {
		const id = "manual:f108-cas"
		if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{ID: id, FindingType: "vulnerability", Ecosystem: "npm", Name: "f108-cas", Severity: "MEDIUM", Summary: "base"}); err != nil {
			t.Fatal(err)
		}
		loaded, _ := store.GetManualAdvisory(ctx, id)
		var maxConns int32
		if err := store.pool.QueryRow(ctx, `SELECT current_setting('max_connections')::int`).Scan(&maxConns); err != nil || store.pool.Config().MaxConns != 2 || maxConns < 2 {
			t.Fatalf("pool/server capacity = %d/%d err=%v", store.pool.Config().MaxConns, maxConns, err)
		}
		start := make(chan struct{})
		ready := make(chan struct{}, 2)
		results := make(chan error, 2)
		var wg sync.WaitGroup
		for _, summary := range []string{"winner-a", "winner-b"} {
			summary := summary
			wg.Add(1)
			go func() {
				defer wg.Done()
				ready <- struct{}{}
				<-start
				callCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				results <- store.UpsertManualAdvisoryWithAudit(callCtx, &db.ManualAdvisory{ID: id, FindingType: "vulnerability", Ecosystem: "npm", Name: "f108-cas", Severity: "LOW", Summary: summary, UpdatedAt: loaded.UpdatedAt}, &db.AdminAuditEntry{Action: "f108_cas"})
			}()
		}
		<-ready
		<-ready
		close(start)
		wg.Wait()
		close(results)
		var successes, conflicts int
		for err := range results {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, db.ErrConflict):
				conflicts++
			default:
				t.Fatalf("concurrent write error = %v", err)
			}
		}
		current, _ := store.GetManualAdvisory(ctx, id)
		if successes != 1 || conflicts != 1 || current == nil || (current.Summary != "winner-a" && current.Summary != "winner-b") {
			t.Fatalf("success=%d conflict=%d current=%+v", successes, conflicts, current)
		}
		f106RequireAuditActionCount(t, store, ctx, "f108_cas", 1)
	})

	t.Run("F108 mixed pagination is stable complete clamped and offset safe", func(t *testing.T) {
		if _, err := store.pool.Exec(ctx, `
			DELETE FROM affected_packages WHERE vulnerability_id LIKE 'manual:%';
			DELETE FROM vulnerability_sources WHERE source='manual';
			DELETE FROM vulnerabilities WHERE id LIKE 'manual:%';
			DELETE FROM malicious_findings WHERE source='manual'`); err != nil {
			t.Fatal(err)
		}
		stamp := time.Date(2026, 11, 2, 16, 17, 18, 123456000, time.UTC)
		if _, err := store.pool.Exec(ctx, `WITH s AS (SELECT g, 'manual:page-'||lpad(g::text,4,'0') id FROM generate_series(0,500) g WHERE g%2=1)
			INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary,created_at,updated_at)
			SELECT id,'npm','page-'||g,'manual','malware','HIGH','page', $1,$1 FROM s`, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `WITH s AS (SELECT g, 'manual:page-'||lpad(g::text,4,'0') id FROM generate_series(0,500) g WHERE g%2=0)
			INSERT INTO vulnerabilities(id,summary,severity,published,modified,created_at,updated_at)
			SELECT id,'page','LOW',$1,$1,$1,$1 FROM s`, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `WITH s AS (SELECT g, 'manual:page-'||lpad(g::text,4,'0') id FROM generate_series(0,500) g WHERE g%2=0)
			INSERT INTO vulnerability_sources(vulnerability_id,source,source_id,raw_json)
			SELECT id,'manual',id,'{}'::jsonb FROM s`); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `WITH s AS (SELECT g, 'manual:page-'||lpad(g::text,4,'0') id FROM generate_series(0,500) g WHERE g%2=0)
			INSERT INTO affected_packages(vulnerability_id,ecosystem,name,version_ranges,versions_affected,updated_at)
			SELECT id,'npm','page-'||g,'[]'::jsonb,'[]'::jsonb,$1 FROM s`, stamp); err != nil {
			t.Fatal(err)
		}
		first, err := store.ListManualAdvisoriesPage(ctx, 500, 0)
		if err != nil || len(first) != 500 {
			t.Fatalf("first page=%d err=%v", len(first), err)
		}
		rest, err := store.ListManualAdvisoriesPage(ctx, 500, 500)
		if err != nil || len(rest) != 1 || rest[0].ID != "manual:page-0000" {
			t.Fatalf("rest=%+v err=%v", rest, err)
		}
		if empty, err := store.ListManualAdvisoriesPage(ctx, 500, 501); err != nil || len(empty) != 0 {
			t.Fatalf("offset 501=%+v err=%v", empty, err)
		}
		defaultPage, _ := store.ListManualAdvisoriesPage(ctx, 0, 0)
		clamped, _ := store.ListManualAdvisoriesPage(ctx, 501, 0)
		negative, _ := store.ListManualAdvisoriesPage(ctx, 1, -4)
		if len(defaultPage) != 100 || len(clamped) != 500 || len(negative) != 1 || negative[0].ID != first[0].ID {
			t.Fatalf("page sizes/defaults = %d %d negative=%+v", len(defaultPage), len(clamped), negative)
		}
		all := append(append([]db.ManualAdvisory(nil), first...), rest...)
		seen := make(map[string]struct{}, 501)
		for i, advisory := range all {
			wantID := fmt.Sprintf("manual:page-%04d", 500-i)
			wantType := "vulnerability"
			if (500-i)%2 == 1 {
				wantType = "malicious"
			}
			if advisory.ID != wantID || advisory.FindingType != wantType || !advisory.UpdatedAt.Equal(stamp) {
				t.Fatalf("row %d = %+v, want %s/%s/%s", i, advisory, wantID, wantType, stamp)
			}
			if _, duplicate := seen[advisory.ID]; duplicate {
				t.Fatalf("duplicate ID %s", advisory.ID)
			}
			seen[advisory.ID] = struct{}{}
		}
		var vulnCount, affectedCount int
		if err := store.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM vulnerabilities WHERE id LIKE 'manual:page-%'),
			(SELECT count(*) FROM affected_packages WHERE vulnerability_id LIKE 'manual:page-%')`).Scan(&vulnCount, &affectedCount); err != nil || vulnCount != 251 || affectedCount != 251 {
			t.Fatalf("vulnerability/affected rows=%d/%d err=%v", vulnCount, affectedCount, err)
		}
	})
}

func f106LifecycleProduct(slug string, cycles []string, maps []db.LifecyclePackageMap) db.LifecycleProduct {
	product := db.LifecycleProduct{ProductSlug: slug, Name: slug}
	for _, cycle := range cycles {
		product.Releases = append(product.Releases, db.LifecycleRelease{Cycle: cycle, IsEOL: true})
	}
	product.PackageMaps = append(product.PackageMaps, maps...)
	return product
}

func f106SyncSnapshot(t *testing.T, store *Store, ctx context.Context) *db.SyncExport {
	t.Helper()
	export, err := store.ExportSync(ctx, db.SyncExportOptions{Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	return export
}

func f106SyncDelta(t *testing.T, store *Store, ctx context.Context, baseline *db.SyncExport) *db.SyncExport {
	t.Helper()
	export, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &baseline.SyncedAt, SinceXID: baseline.SyncedXID, Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	return export
}

func f106AssertLifecycleDelta(t *testing.T, got []db.SyncLifecycleRelease, want map[string]bool) {
	t.Helper()
	seen := make(map[string]int, len(got))
	for _, item := range got {
		if _, relevant := want[item.ID]; relevant {
			seen[item.ID]++
			if item.Withdrawn != want[item.ID] {
				t.Fatalf("lifecycle %s withdrawn=%v, want %v", item.ID, item.Withdrawn, want[item.ID])
			}
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("lifecycle delta relevant IDs=%v, want %v; all=%+v", seen, want, got)
	}
	for id := range want {
		if seen[id] != 1 {
			t.Fatalf("lifecycle delta ID %s count=%d, want 1", id, seen[id])
		}
	}
}

func f106AssertMaliciousDelta(t *testing.T, got []db.SyncMalicious, id string, withdrawn bool) {
	t.Helper()
	var matches []db.SyncMalicious
	for _, item := range got {
		if item.ID == id {
			matches = append(matches, item)
		}
	}
	if len(matches) != 1 || matches[0].Withdrawn != withdrawn {
		t.Fatalf("malicious delta for %s = %+v, want one withdrawn=%v; all=%+v", id, matches, withdrawn, got)
	}
}

func f106RequireAuditActionCount(t *testing.T, store *Store, ctx context.Context, action string, want int) {
	t.Helper()
	rows, err := store.ListAdminAuditLog(ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, row := range rows {
		if row.Action == action {
			got++
		}
	}
	if got != want {
		t.Fatalf("audit action %q count=%d, want %d", action, got, want)
	}
}

func reflectFindingSlices(a, b []domain.Finding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !reflect.DeepEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}
