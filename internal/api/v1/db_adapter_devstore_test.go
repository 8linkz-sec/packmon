package v1

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/devstore"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestNewDBStoreAdapterRejectsNilStore(t *testing.T) {
	t.Parallel()

	if adapter := NewDBStoreAdapter(nil); adapter != nil {
		t.Fatalf("NewDBStoreAdapter(nil) = %+v, want nil", adapter)
	}
}

func TestPackageLookupsToDBMapsAllFields(t *testing.T) {
	t.Parallel()

	if out := packageLookupsToDB(nil); out != nil {
		t.Fatalf("packageLookupsToDB(nil) = %+v, want nil", out)
	}
	out := packageLookupsToDB([]PackageLookup{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
		{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"},
	})
	if len(out) != 2 {
		t.Fatalf("packageLookupsToDB() len = %d, want 2", len(out))
	}
	if out[0] != (db.PackageQuery{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}) {
		t.Fatalf("packageLookupsToDB()[0] = %+v, want mapped npm lookup", out[0])
	}
	if out[1] != (db.PackageQuery{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}) {
		t.Fatalf("packageLookupsToDB()[1] = %+v, want mapped pypi lookup", out[1])
	}
}

// ptr is needed where a pointer-API method takes the value helper's result.
func ptr[T any](v T) *T { return &v }

func adapterTestAudit(action string) db.AdminAuditEntry {
	return db.AdminAuditEntry{
		Action:  action,
		Details: json.RawMessage(`{"source":"db-adapter-test"}`),
		IP:      "127.0.0.1",
	}
}

// TestDBStoreAdapterDelegatesToBackingStore drives every adapter method
// against the in-memory dev store, the same wiring dev mode uses, so the
// delegation layer cannot silently drop or reorder arguments.
func TestDBStoreAdapterDelegatesToBackingStore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backing := devstore.NewStore()
	adapter := NewDBStoreAdapter(backing)
	if adapter == nil {
		t.Fatal("NewDBStoreAdapter(devstore) = nil, want adapter")
	}

	lookups := []PackageLookup{{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}}

	if err := adapter.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:       "CVE-2024-0001",
		Summary:  "test vulnerability",
		Severity: "HIGH",
		Sources:  []db.VulnerabilitySource{{Source: "osv", SourceID: "OSV-1"}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "lodash",
			VersionsAffected: json.RawMessage(`["4.17.20"]`),
		}},
	}); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	vulnerabilityFindings, err := adapter.FindVulnerabilities(ctx, "npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(vulnerabilityFindings) != 1 || vulnerabilityFindings[0].AdvisoryID != "CVE-2024-0001" || vulnerabilityFindings[0].Source != "osv" || vulnerabilityFindings[0].Version != "4.17.20" {
		t.Fatalf("FindVulnerabilities() = %+v, want the persisted vulnerability", vulnerabilityFindings)
	}
	vulnerabilityBatch, err := adapter.FindVulnerabilitiesBatch(ctx, lookups)
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch() error = %v", err)
	}
	if len(vulnerabilityBatch) != 1 || vulnerabilityBatch[0].AdvisoryID != "CVE-2024-0001" {
		t.Fatalf("FindVulnerabilitiesBatch() = %+v, want persisted vulnerability", vulnerabilityBatch)
	}

	if err := adapter.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "MAL-0001",
		Ecosystem: "npm",
		Name:      "evil-package",
		Versions:  json.RawMessage(`["1.0.0"]`),
		Source:    "openssf",
		RiskType:  "malware",
		Severity:  "CRITICAL",
		Summary:   "test malicious finding",
		CreatedBy: "feed",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding() error = %v", err)
	}
	maliciousFindings, err := adapter.FindMalicious(ctx, "npm", "evil-package", "1.0.0")
	if err != nil {
		t.Fatalf("FindMalicious() error = %v", err)
	}
	if len(maliciousFindings) != 1 || maliciousFindings[0].AdvisoryID != "MAL-0001" || maliciousFindings[0].RiskType != "malware" || maliciousFindings[0].Source != "openssf" {
		t.Fatalf("FindMalicious() = %+v, want persisted malicious finding", maliciousFindings)
	}
	maliciousLookups := []PackageLookup{{Ecosystem: "npm", Name: "evil-package", Version: "1.0.0"}}
	maliciousBatch, err := adapter.FindMaliciousBatch(ctx, maliciousLookups)
	if err != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", err)
	}
	if len(maliciousBatch) != 1 || maliciousBatch[0].AdvisoryID != "MAL-0001" {
		t.Fatalf("FindMaliciousBatch() = %+v, want persisted malicious finding", maliciousBatch)
	}
	reputationFindings, err := adapter.FindReputationFindingsBatch(ctx, lookups, "socket")
	if err != nil {
		t.Fatalf("FindReputationFindingsBatch() error = %v", err)
	}
	if reputationFindings != nil {
		t.Fatalf("FindReputationFindingsBatch() = %+v, want nil devstore result", reputationFindings)
	}
	lifecycleNow := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	lifecycleFindings, err := adapter.FindLifecycleFindingsBatch(ctx, lookups, lifecycleNow)
	if err != nil {
		t.Fatalf("FindLifecycleFindingsBatch() error = %v", err)
	}
	if lifecycleFindings != nil {
		t.Fatalf("FindLifecycleFindingsBatch() = %+v, want nil devstore result", lifecycleFindings)
	}

	if err := adapter.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncStatus: "success",
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus() error = %v", err)
	}
	statuses, err := adapter.ListFeedSyncStatuses(ctx)
	if err != nil {
		t.Fatalf("ListFeedSyncStatuses() error = %v", err)
	}
	foundOSV := false
	for _, status := range statuses {
		if status.FeedName == "osv" {
			foundOSV = true
		}
	}
	if !foundOSV {
		t.Fatalf("ListFeedSyncStatuses() = %+v, want upserted osv status", statuses)
	}

	created, position, err := adapter.EnqueueRefresh(ctx, &db.RefreshJob{
		Ecosystem: "npm",
		Name:      "lodash",
		Source:    "socket",
	})
	if err != nil {
		t.Fatalf("EnqueueRefresh() error = %v", err)
	}
	if !created || position != 1 {
		t.Fatalf("EnqueueRefresh() = created %v, position %d; want true, 1", created, position)
	}
	queueAuditCalls := 0
	created, position, err = adapter.EnqueueRefreshWithAudit(ctx, &db.RefreshJob{
		Ecosystem: "pypi",
		Name:      "requests",
		Source:    "socket",
	}, func(gotCreated bool, gotPosition int) db.AdminAuditEntry {
		queueAuditCalls++
		if !gotCreated || gotPosition != 2 {
			t.Errorf("refresh audit callback = created %v, position %d; want true, 2", gotCreated, gotPosition)
		}
		return adapterTestAudit("refresh_enqueue")
	})
	if err != nil {
		t.Fatalf("EnqueueRefreshWithAudit() error = %v", err)
	}
	if !created || position != 2 || queueAuditCalls != 1 {
		t.Fatalf("EnqueueRefreshWithAudit() = created %v, position %d; audit calls %d", created, position, queueAuditCalls)
	}
	auditRows, err := backing.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(auditRows) != 1 || auditRows[0].Action != "refresh_enqueue" {
		t.Fatalf("admin audit rows = %+v, want persisted refresh_enqueue action", auditRows)
	}

	if err := adapter.InsertScanLog(ctx, &db.ScanLogEntry{
		ScanID:         "scan-adapter-test",
		RepoName:       "packmon",
		ScannedAt:      time.Now().UTC(),
		IdempotencyKey: "adapter-idem-key",
	}); err != nil {
		t.Fatalf("InsertScanLog() error = %v", err)
	}
	scanLog, err := adapter.GetScanLogByIdempotencyKey(ctx, "adapter-idem-key")
	if err != nil {
		t.Fatalf("GetScanLogByIdempotencyKey() error = %v", err)
	}
	if scanLog == nil || scanLog.ScanID != "scan-adapter-test" || scanLog.RepoName != "packmon" || scanLog.IdempotencyKey != "adapter-idem-key" {
		t.Fatalf("GetScanLogByIdempotencyKey() = %+v, want inserted scan log", scanLog)
	}

	imported, deleted, err := adapter.ImportVulnerabilityFeedWithAudit(ctx, "osv", []db.Vulnerability{{
		ID:       "CVE-2024-0002",
		Summary:  "imported vulnerability",
		Severity: "MEDIUM",
		Sources:  []db.VulnerabilitySource{{Source: "osv", SourceID: "OSV-2"}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "imported-package",
			VersionsAffected: json.RawMessage(`["2.0.0"]`),
		}},
	}}, nil, nil, func(imported, deleted int) db.AdminAuditEntry {
		if imported != 1 || deleted != 0 {
			t.Errorf("vulnerability import audit counts = %d/%d, want 1/0", imported, deleted)
		}
		return adapterTestAudit("feed_import_osv")
	})
	if err != nil {
		t.Fatalf("ImportVulnerabilityFeedWithAudit() error = %v", err)
	}
	if imported != 1 || deleted != 0 {
		t.Fatalf("ImportVulnerabilityFeedWithAudit() = %d/%d, want 1/0", imported, deleted)
	}
	importedVulnerabilities, err := adapter.FindVulnerabilities(ctx, "npm", "imported-package", "2.0.0")
	if err != nil || len(importedVulnerabilities) != 1 || importedVulnerabilities[0].AdvisoryID != "CVE-2024-0002" {
		t.Fatalf("imported vulnerability lookup = %+v, %v", importedVulnerabilities, err)
	}

	imported, deleted, err = adapter.ImportMaliciousFeedWithAudit(ctx, "openssf", []db.MaliciousFinding{{
		ID:        "MAL-0002",
		Ecosystem: "pypi",
		Name:      "evil-wheel",
		Versions:  json.RawMessage(`["2.0.0"]`),
		Source:    "openssf",
		RiskType:  "malware",
		Severity:  "CRITICAL",
		Summary:   "imported malicious finding",
		CreatedBy: "feed",
	}}, nil, nil, func(imported, deleted int) db.AdminAuditEntry {
		if imported != 1 || deleted != 0 {
			t.Errorf("malicious import audit counts = %d/%d, want 1/0", imported, deleted)
		}
		return adapterTestAudit("feed_import_openssf")
	})
	if err != nil {
		t.Fatalf("ImportMaliciousFeedWithAudit() error = %v", err)
	}
	if imported != 1 || deleted != 0 {
		t.Fatalf("ImportMaliciousFeedWithAudit() = %d/%d, want 1/0", imported, deleted)
	}
	importedMalicious, err := adapter.FindMalicious(ctx, "pypi", "evil-wheel", "2.0.0")
	if err != nil || len(importedMalicious) != 1 || importedMalicious[0].AdvisoryID != "MAL-0002" {
		t.Fatalf("imported malicious lookup = %+v, %v", importedMalicious, err)
	}

	updated, err := adapter.ImportVulnCheckWithAudit(ctx, "vulncheck", []db.VulnCheckEntry{{
		CVEID:         "CVE-2024-0001",
		ExploitExists: true,
	}}, nil, func(imported, deleted int) db.AdminAuditEntry {
		if imported != 0 || deleted != 0 {
			t.Errorf("VulnCheck audit counts = %d/%d, want devstore 0/0", imported, deleted)
		}
		return adapterTestAudit("feed_import_vulncheck")
	})
	if err != nil {
		t.Fatalf("ImportVulnCheckWithAudit() error = %v", err)
	}
	if updated != 0 {
		t.Fatalf("ImportVulnCheckWithAudit() = %d, want devstore 0", updated)
	}
	updated, err = adapter.ImportCISAKEVWithAudit(ctx, "cisakev", []string{"CVE-2024-0001"}, nil, func(imported, deleted int) db.AdminAuditEntry {
		if imported != 0 || deleted != 0 {
			t.Errorf("CISA KEV import audit counts = %d/%d, want devstore 0/0", imported, deleted)
		}
		return adapterTestAudit("feed_import_cisakev")
	})
	if err != nil {
		t.Fatalf("ImportCISAKEVWithAudit() error = %v", err)
	}
	if updated != 0 {
		t.Fatalf("ImportCISAKEVWithAudit() = %d, want devstore 0", updated)
	}
	updated, cleared, err := adapter.ReplaceCISAKEVWithAudit(ctx, "cisakev", []string{"CVE-2024-0001"}, nil, func(imported, deleted int) db.AdminAuditEntry {
		if imported != 0 || deleted != 0 {
			t.Errorf("CISA KEV replace audit counts = %d/%d, want devstore 0/0", imported, deleted)
		}
		return adapterTestAudit("feed_replace_cisakev")
	})
	if err != nil {
		t.Fatalf("ReplaceCISAKEVWithAudit() error = %v", err)
	}
	if updated != 0 || cleared != 0 {
		t.Fatalf("ReplaceCISAKEVWithAudit() = %d/%d, want devstore 0/0", updated, cleared)
	}
	updated, cleared, err = adapter.ImportEPSSWithAudit(ctx, "epss", []db.EPSSEntry{{
		CVEID:      "CVE-2024-0001",
		Score:      0.42,
		Percentile: 0.9,
	}}, nil, func(imported, deleted int) db.AdminAuditEntry {
		if imported != 0 || deleted != 0 {
			t.Errorf("EPSS audit counts = %d/%d, want devstore 0/0", imported, deleted)
		}
		return adapterTestAudit("feed_import_epss")
	})
	if err != nil {
		t.Fatalf("ImportEPSSWithAudit() error = %v", err)
	}
	if updated != 0 || cleared != 0 {
		t.Fatalf("ImportEPSSWithAudit() = %d/%d, want devstore 0/0", updated, cleared)
	}

	updated, err = adapter.EnrichVulnCheck(ctx, []db.VulnCheckEntry{{
		CVEID:         "CVE-2024-0001",
		ExploitExists: true,
	}})
	if err != nil {
		t.Fatalf("EnrichVulnCheck() error = %v", err)
	}
	if updated != 0 {
		t.Fatalf("EnrichVulnCheck() = %d, want devstore 0", updated)
	}
	updated, err = adapter.SetCISAKEV(ctx, []string{"CVE-2024-0001"})
	if err != nil {
		t.Fatalf("SetCISAKEV() error = %v", err)
	}
	if updated != 0 {
		t.Fatalf("SetCISAKEV() = %d, want devstore 0", updated)
	}
	cleared, err = adapter.ClearCISAKEV(ctx, []string{"CVE-2024-0001"})
	if err != nil {
		t.Fatalf("ClearCISAKEV() error = %v", err)
	}
	if cleared != 0 {
		t.Fatalf("ClearCISAKEV() = %d, want 0", cleared)
	}
	updated, cleared, err = adapter.ReplaceCISAKEV(ctx, []string{"CVE-2024-0001"})
	if err != nil {
		t.Fatalf("ReplaceCISAKEV() error = %v", err)
	}
	if updated != 0 || cleared != 0 {
		t.Fatalf("ReplaceCISAKEV() = %d/%d, want devstore 0/0", updated, cleared)
	}
	updated, cleared, err = adapter.ReplaceEPSSScores(ctx, []db.EPSSEntry{{
		CVEID:      "CVE-2024-0001",
		Score:      0.13,
		Percentile: 0.5,
	}})
	if err != nil {
		t.Fatalf("ReplaceEPSSScores() error = %v", err)
	}
	if updated != 0 || cleared != 0 {
		t.Fatalf("ReplaceEPSSScores() = %d/%d, want devstore 0/0", updated, cleared)
	}

	if err := adapter.InsertAdminAuditLog(ctx, ptr(adapterTestAudit("adapter_direct_audit"))); err != nil {
		t.Fatalf("InsertAdminAuditLog() error = %v", err)
	}

	export, err := adapter.ExportSync(ctx, db.SyncExportOptions{})
	if err != nil {
		t.Fatalf("ExportSync() error = %v", err)
	}
	if export == nil {
		t.Fatal("ExportSync() = nil export, want snapshot")
	}

	if _, err := adapter.GetPackageCheckStatus(ctx, "npm", "lodash", "socket"); err != nil {
		t.Fatalf("GetPackageCheckStatus() error = %v", err)
	}

	if err := adapter.DeleteVulnerabilityForSource(ctx, "CVE-2024-0002", "osv"); err != nil {
		t.Fatalf("DeleteVulnerabilityForSource() error = %v", err)
	}
	if err := adapter.DeleteVulnerability(ctx, "CVE-2024-0001"); err != nil {
		t.Fatalf("DeleteVulnerability() error = %v", err)
	}
	if err := adapter.DeleteMaliciousFindingForSource(ctx, "MAL-0002", "openssf"); err != nil {
		t.Fatalf("DeleteMaliciousFindingForSource() error = %v", err)
	}
	if err := adapter.DeleteMaliciousFinding(ctx, "MAL-0001"); err != nil {
		t.Fatalf("DeleteMaliciousFinding() error = %v", err)
	}
}

// reputationFinderBackedStore augments the dev store with the optional
// reputation finder capability so both adapter paths are exercised.
type reputationFinderBackedStore struct {
	*devstore.Store
	calls int
}

func (s *reputationFinderBackedStore) FindReputationFindings(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	s.calls++
	return []domain.Finding{{Name: "flagged-package"}}, nil
}

func TestDBStoreAdapterFindReputationFindingsPaths(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	plain := NewDBStoreAdapter(devstore.NewStore())
	findings, err := plain.FindReputationFindings(ctx, "npm", "lodash", "socket")
	if err != nil || findings != nil {
		t.Fatalf("FindReputationFindings(non-finder store) = %+v, %v; want nil, nil", findings, err)
	}

	backing := &reputationFinderBackedStore{Store: devstore.NewStore()}
	finder := NewDBStoreAdapter(backing)
	findings, err = finder.FindReputationFindings(ctx, "npm", "lodash", "socket")
	if err != nil {
		t.Fatalf("FindReputationFindings(finder store) error = %v", err)
	}
	if backing.calls != 1 || len(findings) != 1 || findings[0].Name != "flagged-package" {
		t.Fatalf("FindReputationFindings(finder store) = %+v (calls %d), want delegated finding", findings, backing.calls)
	}
}
