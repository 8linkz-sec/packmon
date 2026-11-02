package v1

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/devstore"
	"github.com/8linkz-sec/packmon/internal/domain"
)

type adapterContextKey struct{}

type adapterContractStore struct {
	db.Store
	wantCtx context.Context
	err     error
	calls   map[string]int
	args    map[string]any
}

func newAdapterContractStore(ctx context.Context) *adapterContractStore {
	return &adapterContractStore{
		Store:   devstore.NewStore(),
		wantCtx: ctx,
		calls:   make(map[string]int),
		args:    make(map[string]any),
	}
}

func (s *adapterContractStore) record(name string, ctx context.Context, value any) {
	s.calls[name]++
	if ctx != s.wantCtx {
		s.args[name+".wrong_context"] = ctx
	}
	s.args[name] = value
}

func (s *adapterContractStore) FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	s.record("FindVulnerabilities", ctx, []string{ecosystem, name, version})
	return []domain.Finding{{AdvisoryID: "vulnerability-result"}}, s.err
}

func (s *adapterContractStore) FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	s.record("FindMalicious", ctx, []string{ecosystem, name, version})
	return []domain.Finding{{AdvisoryID: "malicious-result"}}, s.err
}

func (s *adapterContractStore) FindVulnerabilitiesBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	s.record("FindVulnerabilitiesBatch", ctx, packages)
	return []domain.Finding{{AdvisoryID: "batch-vulnerability-1"}, {AdvisoryID: "batch-vulnerability-2"}}, s.err
}

func (s *adapterContractStore) FindMaliciousBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	s.record("FindMaliciousBatch", ctx, packages)
	return []domain.Finding{{AdvisoryID: "batch-malicious-1"}, {AdvisoryID: "batch-malicious-2"}}, s.err
}

func (s *adapterContractStore) FindReputationFindingsBatch(ctx context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error) {
	s.record("FindReputationFindingsBatch", ctx, struct {
		Packages []db.PackageQuery
		Source   string
	}{packages, source})
	return []domain.Finding{{AdvisoryID: "batch-reputation-1"}, {AdvisoryID: "batch-reputation-2"}}, s.err
}

func (s *adapterContractStore) FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error) {
	s.record("FindLifecycleFindingsBatch", ctx, struct {
		Packages []db.PackageQuery
		Now      time.Time
	}{packages, now})
	return []domain.Finding{{AdvisoryID: "batch-lifecycle-1"}, {AdvisoryID: "batch-lifecycle-2"}}, s.err
}

func (s *adapterContractStore) ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error) {
	s.record("ListFeedSyncStatuses", ctx, nil)
	return []db.FeedSyncStatus{{FeedName: "first"}, {FeedName: "second"}}, s.err
}

func (s *adapterContractStore) EnqueueRefresh(ctx context.Context, job *db.RefreshJob) (bool, int, error) {
	s.record("EnqueueRefresh", ctx, job)
	return true, 21, s.err
}

func (s *adapterContractStore) EnqueueRefreshWithAudit(ctx context.Context, job *db.RefreshJob, audit db.RefreshEnqueueAuditBuilder) (bool, int, error) {
	s.record("EnqueueRefreshWithAudit", ctx, job)
	if s.err != nil {
		return false, 0, s.err
	}
	if audit != nil {
		s.args["EnqueueRefreshWithAudit.audit"] = audit(false, 22)
	}
	return false, 22, nil
}

func (s *adapterContractStore) InsertScanLog(ctx context.Context, entry *db.ScanLogEntry) error {
	s.record("InsertScanLog", ctx, entry)
	return s.err
}

func (s *adapterContractStore) UpsertVulnerability(ctx context.Context, vuln *db.Vulnerability) error {
	s.record("UpsertVulnerability", ctx, vuln)
	return s.err
}

func (s *adapterContractStore) DeleteVulnerability(ctx context.Context, id string) error {
	s.record("DeleteVulnerability", ctx, id)
	return s.err
}

func (s *adapterContractStore) UpsertMaliciousFinding(ctx context.Context, finding *db.MaliciousFinding) error {
	s.record("UpsertMaliciousFinding", ctx, finding)
	return s.err
}

func (s *adapterContractStore) DeleteMaliciousFinding(ctx context.Context, id string) error {
	s.record("DeleteMaliciousFinding", ctx, id)
	return s.err
}

func (s *adapterContractStore) auditedImport(name string, ctx context.Context, value any, audit db.FeedImportAuditBuilder, imported, deleted int) (int, int, error) {
	s.record(name, ctx, value)
	if s.err != nil {
		return 0, 0, s.err
	}
	if audit != nil {
		s.args[name+".audit"] = audit(imported, deleted)
	}
	return imported, deleted, nil
}

func (s *adapterContractStore) ImportVulnerabilityFeedWithAudit(ctx context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	return s.auditedImport("ImportVulnerabilityFeedWithAudit", ctx, []any{feed, items, deleteIDs, status}, audit, 11, 12)
}

func (s *adapterContractStore) ImportMaliciousFeedWithAudit(ctx context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	return s.auditedImport("ImportMaliciousFeedWithAudit", ctx, []any{feed, items, deleteIDs, status}, audit, 13, 14)
}

func (s *adapterContractStore) ImportVulnCheckWithAudit(ctx context.Context, feed string, entries []db.VulnCheckEntry, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, error) {
	imported, _, err := s.auditedImport("ImportVulnCheckWithAudit", ctx, []any{feed, entries, status}, audit, 15, 0)
	return imported, err
}

func (s *adapterContractStore) ImportCISAKEVWithAudit(ctx context.Context, feed string, ids []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, error) {
	imported, _, err := s.auditedImport("ImportCISAKEVWithAudit", ctx, []any{feed, ids, status}, audit, 16, 0)
	return imported, err
}

func (s *adapterContractStore) ReplaceCISAKEVWithAudit(ctx context.Context, feed string, ids []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	return s.auditedImport("ReplaceCISAKEVWithAudit", ctx, []any{feed, ids, status}, audit, 17, 18)
}

func (s *adapterContractStore) ImportEPSSWithAudit(ctx context.Context, feed string, entries []db.EPSSEntry, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	return s.auditedImport("ImportEPSSWithAudit", ctx, []any{feed, entries, status}, audit, 19, 20)
}

func (s *adapterContractStore) EnrichVulnCheck(ctx context.Context, entries []db.VulnCheckEntry) (int, error) {
	s.record("EnrichVulnCheck", ctx, entries)
	return 23, s.err
}

func (s *adapterContractStore) SetCISAKEV(ctx context.Context, ids []string) (int, error) {
	s.record("SetCISAKEV", ctx, ids)
	return 24, s.err
}

func (s *adapterContractStore) ClearCISAKEV(ctx context.Context, ids []string) (int, error) {
	s.record("ClearCISAKEV", ctx, ids)
	return 25, s.err
}

func (s *adapterContractStore) ReplaceCISAKEV(ctx context.Context, ids []string) (int, int, error) {
	s.record("ReplaceCISAKEV", ctx, ids)
	return 26, 27, s.err
}

func (s *adapterContractStore) ReplaceEPSSScores(ctx context.Context, entries []db.EPSSEntry) (int, int, error) {
	s.record("ReplaceEPSSScores", ctx, entries)
	return 28, 29, s.err
}

func (s *adapterContractStore) UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error {
	s.record("UpsertFeedSyncStatus", ctx, status)
	return s.err
}

func (s *adapterContractStore) InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error {
	s.record("InsertAdminAuditLog", ctx, entry)
	return s.err
}

func (s *adapterContractStore) ExportSync(ctx context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	s.record("ExportSync", ctx, opts)
	return &db.SyncExport{SyncedXID: 37}, s.err
}

func (s *adapterContractStore) FindReputationFindings(ctx context.Context, ecosystem, name, source string) ([]domain.Finding, error) {
	s.record("FindReputationFindings", ctx, []string{ecosystem, name, source})
	return []domain.Finding{{AdvisoryID: "reputation-result"}}, s.err
}

func (s *adapterContractStore) GetPackageCheckStatus(ctx context.Context, ecosystem, name, source string) (*db.PackageCheckStatus, error) {
	s.record("GetPackageCheckStatus", ctx, []string{ecosystem, name, source})
	return &db.PackageCheckStatus{Ecosystem: ecosystem, Name: name, Source: source, CheckCount: 31}, s.err
}

func (s *adapterContractStore) GetScanLogByIdempotencyKey(ctx context.Context, key string) (*db.ScanLogEntry, error) {
	s.record("GetScanLogByIdempotencyKey", ctx, key)
	return &db.ScanLogEntry{ScanID: "scan-result", IdempotencyKey: key}, s.err
}

type adapterLegacyDeletionStore struct {
	db.Store
	wantCtx       context.Context
	err           error
	vulnerability string
	malicious     string
}

func (s *adapterLegacyDeletionStore) DeleteVulnerability(ctx context.Context, id string) error {
	if ctx != s.wantCtx {
		return errors.New("unexpected vulnerability context")
	}
	s.vulnerability = id
	return s.err
}

func (s *adapterLegacyDeletionStore) DeleteMaliciousFinding(ctx context.Context, id string) error {
	if ctx != s.wantCtx {
		return errors.New("unexpected malicious context")
	}
	s.malicious = id
	return s.err
}

type adapterScopedDeletionStore struct {
	*adapterLegacyDeletionStore
	scopedVulnerability []string
	scopedMalicious     []string
}

func (s *adapterScopedDeletionStore) DeleteVulnerabilityForSource(ctx context.Context, id, source string) error {
	if ctx != s.wantCtx {
		return errors.New("unexpected scoped vulnerability context")
	}
	s.scopedVulnerability = []string{id, source}
	return s.err
}

func (s *adapterScopedDeletionStore) DeleteMaliciousFindingForSource(ctx context.Context, id, source string) error {
	if ctx != s.wantCtx {
		return errors.New("unexpected scoped malicious context")
	}
	s.scopedMalicious = []string{id, source}
	return s.err
}

func TestDBStoreAdapterSourceDeletionSelectsScopedAndLegacyContracts(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(context.Background(), adapterContextKey{}, "source-delete")
	errSentinel := errors.New("delete failed")

	legacy := &adapterLegacyDeletionStore{Store: devstore.NewStore(), wantCtx: ctx, err: errSentinel}
	legacyAdapter := NewDBStoreAdapter(legacy)
	if err := legacyAdapter.DeleteVulnerabilityForSource(ctx, "CVE-legacy", "ghsa"); err != errSentinel {
		t.Fatalf("legacy DeleteVulnerabilityForSource() error = %v, want sentinel", err)
	}
	if err := legacyAdapter.DeleteMaliciousFindingForSource(ctx, "MAL-legacy", "socket"); err != errSentinel {
		t.Fatalf("legacy DeleteMaliciousFindingForSource() error = %v, want sentinel", err)
	}
	if legacy.vulnerability != "CVE-legacy" || legacy.malicious != "MAL-legacy" {
		t.Fatalf("legacy IDs = %q/%q, want exact IDs", legacy.vulnerability, legacy.malicious)
	}

	scopedBase := &adapterLegacyDeletionStore{Store: devstore.NewStore(), wantCtx: ctx, err: errSentinel}
	scoped := &adapterScopedDeletionStore{adapterLegacyDeletionStore: scopedBase}
	scopedAdapter := NewDBStoreAdapter(scoped)
	if err := scopedAdapter.DeleteVulnerabilityForSource(ctx, "CVE-scoped", "osv"); err != errSentinel {
		t.Fatalf("scoped DeleteVulnerabilityForSource() error = %v, want sentinel", err)
	}
	if err := scopedAdapter.DeleteMaliciousFindingForSource(ctx, "MAL-scoped", "openssf"); err != errSentinel {
		t.Fatalf("scoped DeleteMaliciousFindingForSource() error = %v, want sentinel", err)
	}
	if !reflect.DeepEqual(scoped.scopedVulnerability, []string{"CVE-scoped", "osv"}) || !reflect.DeepEqual(scoped.scopedMalicious, []string{"MAL-scoped", "openssf"}) {
		t.Fatalf("scoped arguments = %+v/%+v", scoped.scopedVulnerability, scoped.scopedMalicious)
	}
	if scopedBase.vulnerability != "" || scopedBase.malicious != "" {
		t.Fatalf("scoped deletion fell back to generic methods: %q/%q", scopedBase.vulnerability, scopedBase.malicious)
	}
}

func TestDBStoreAdapterPreservesLookupBatchTimeContextAndResults(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(context.Background(), adapterContextKey{}, "lookups")
	store := newAdapterContractStore(ctx)
	adapter := NewDBStoreAdapter(store)
	lookups := []PackageLookup{{Ecosystem: "npm", Name: "one", Version: "1.0.0"}, {Ecosystem: "pypi", Name: "two", Version: "2.0.0"}}
	wantQueries := []db.PackageQuery{{Ecosystem: "npm", Name: "one", Version: "1.0.0"}, {Ecosystem: "pypi", Name: "two", Version: "2.0.0"}}
	now := time.Date(2026, 11, 2, 14, 15, 16, 17, time.FixedZone("sentinel", 3600))

	checks := []struct {
		name string
		got  []domain.Finding
		want []domain.Finding
	}{
		{"vulnerabilities", requireAdapterFindings(t, func() ([]domain.Finding, error) { return adapter.FindVulnerabilities(ctx, "npm", "one", "1.0.0") }), []domain.Finding{{AdvisoryID: "vulnerability-result"}}},
		{"malicious", requireAdapterFindings(t, func() ([]domain.Finding, error) { return adapter.FindMalicious(ctx, "pypi", "two", "2.0.0") }), []domain.Finding{{AdvisoryID: "malicious-result"}}},
		{"vulnerability batch", requireAdapterFindings(t, func() ([]domain.Finding, error) { return adapter.FindVulnerabilitiesBatch(ctx, lookups) }), []domain.Finding{{AdvisoryID: "batch-vulnerability-1"}, {AdvisoryID: "batch-vulnerability-2"}}},
		{"malicious batch", requireAdapterFindings(t, func() ([]domain.Finding, error) { return adapter.FindMaliciousBatch(ctx, lookups) }), []domain.Finding{{AdvisoryID: "batch-malicious-1"}, {AdvisoryID: "batch-malicious-2"}}},
		{"reputation batch", requireAdapterFindings(t, func() ([]domain.Finding, error) { return adapter.FindReputationFindingsBatch(ctx, lookups, "socket") }), []domain.Finding{{AdvisoryID: "batch-reputation-1"}, {AdvisoryID: "batch-reputation-2"}}},
		{"lifecycle batch", requireAdapterFindings(t, func() ([]domain.Finding, error) { return adapter.FindLifecycleFindingsBatch(ctx, lookups, now) }), []domain.Finding{{AdvisoryID: "batch-lifecycle-1"}, {AdvisoryID: "batch-lifecycle-2"}}},
		{"optional reputation", requireAdapterFindings(t, func() ([]domain.Finding, error) {
			return adapter.FindReputationFindings(ctx, "cargo", "three", "socket")
		}), []domain.Finding{{AdvisoryID: "reputation-result"}}},
	}
	for _, check := range checks {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s result = %+v, want %+v", check.name, check.got, check.want)
		}
	}
	for name, want := range map[string]any{
		"FindVulnerabilities":    []string{"npm", "one", "1.0.0"},
		"FindMalicious":          []string{"pypi", "two", "2.0.0"},
		"FindReputationFindings": []string{"cargo", "three", "socket"},
	} {
		if !reflect.DeepEqual(store.args[name], want) {
			t.Errorf("%s arguments = %+v, want %+v", name, store.args[name], want)
		}
	}
	if !reflect.DeepEqual(store.args["FindVulnerabilitiesBatch"], wantQueries) || !reflect.DeepEqual(store.args["FindMaliciousBatch"], wantQueries) {
		t.Fatalf("batch queries were not preserved: vuln=%+v malicious=%+v", store.args["FindVulnerabilitiesBatch"], store.args["FindMaliciousBatch"])
	}
	wantReputationBatch := struct {
		Packages []db.PackageQuery
		Source   string
	}{wantQueries, "socket"}
	if !reflect.DeepEqual(store.args["FindReputationFindingsBatch"], wantReputationBatch) {
		t.Fatalf("reputation batch args = %+v, want %+v", store.args["FindReputationFindingsBatch"], wantReputationBatch)
	}
	wantLifecycle := struct {
		Packages []db.PackageQuery
		Now      time.Time
	}{wantQueries, now}
	if !reflect.DeepEqual(store.args["FindLifecycleFindingsBatch"], wantLifecycle) {
		t.Fatalf("lifecycle args = %+v, want %+v", store.args["FindLifecycleFindingsBatch"], wantLifecycle)
	}

	statuses, err := adapter.ListFeedSyncStatuses(ctx)
	if err != nil || !reflect.DeepEqual(statuses, []db.FeedSyncStatus{{FeedName: "first"}, {FeedName: "second"}}) {
		t.Fatalf("ListFeedSyncStatuses() = %+v, %v", statuses, err)
	}
	opts := db.SyncExportOptions{SinceXID: 32}
	exported, err := adapter.ExportSync(ctx, opts)
	if err != nil || exported == nil || exported.SyncedXID != 37 || !reflect.DeepEqual(store.args["ExportSync"], opts) {
		t.Fatalf("ExportSync() = %+v, %v; args=%+v", exported, err, store.args["ExportSync"])
	}
	status, err := adapter.GetPackageCheckStatus(ctx, "npm", "one", "socket")
	if err != nil || status == nil || status.CheckCount != 31 {
		t.Fatalf("GetPackageCheckStatus() = %+v, %v", status, err)
	}
	scan, err := adapter.GetScanLogByIdempotencyKey(ctx, "idem")
	if err != nil || scan == nil || scan.ScanID != "scan-result" || scan.IdempotencyKey != "idem" {
		t.Fatalf("GetScanLogByIdempotencyKey() = %+v, %v", scan, err)
	}
	for key := range store.args {
		if len(key) > len(".wrong_context") && key[len(key)-len(".wrong_context"):] == ".wrong_context" {
			t.Errorf("%s received the wrong context", key)
		}
	}
}

func requireAdapterFindings(t *testing.T, lookup func() ([]domain.Finding, error)) []domain.Finding {
	t.Helper()
	findings, err := lookup()
	if err != nil {
		t.Fatalf("adapter lookup error = %v", err)
	}
	return findings
}

func TestDBStoreAdapterPreservesMutationAuditAndMultiValueResults(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(context.Background(), adapterContextKey{}, "mutations")
	store := newAdapterContractStore(ctx)
	adapter := NewDBStoreAdapter(store)
	job := &db.RefreshJob{ID: 1, Ecosystem: "npm", Name: "one", Source: "socket"}
	created, position, err := adapter.EnqueueRefresh(ctx, job)
	if err != nil || !created || position != 21 || store.args["EnqueueRefresh"] != job {
		t.Fatalf("EnqueueRefresh() = %v, %d, %v; arg=%p", created, position, err, store.args["EnqueueRefresh"])
	}
	auditCalls := 0
	created, position, err = adapter.EnqueueRefreshWithAudit(ctx, job, func(gotCreated bool, gotPosition int) db.AdminAuditEntry {
		auditCalls++
		if gotCreated || gotPosition != 22 {
			t.Errorf("queue audit args = %v/%d, want false/22", gotCreated, gotPosition)
		}
		return db.AdminAuditEntry{Action: "queue-audit"}
	})
	if err != nil || created || position != 22 || auditCalls != 1 {
		t.Fatalf("EnqueueRefreshWithAudit() = %v, %d, %v; audit calls=%d", created, position, err, auditCalls)
	}
	if got := store.args["EnqueueRefreshWithAudit.audit"].(db.AdminAuditEntry).Action; got != "queue-audit" {
		t.Fatalf("persisted queue audit action = %q", got)
	}

	scan := &db.ScanLogEntry{ScanID: "scan"}
	vuln := &db.Vulnerability{ID: "CVE-test"}
	malicious := &db.MaliciousFinding{ID: "MAL-test"}
	status := &db.FeedSyncStatus{FeedName: "test"}
	directAudit := &db.AdminAuditEntry{Action: "direct"}
	for name, call := range map[string]func() error{
		"InsertScanLog":          func() error { return adapter.InsertScanLog(ctx, scan) },
		"UpsertVulnerability":    func() error { return adapter.UpsertVulnerability(ctx, vuln) },
		"DeleteVulnerability":    func() error { return adapter.DeleteVulnerability(ctx, "CVE-delete") },
		"UpsertMaliciousFinding": func() error { return adapter.UpsertMaliciousFinding(ctx, malicious) },
		"DeleteMaliciousFinding": func() error { return adapter.DeleteMaliciousFinding(ctx, "MAL-delete") },
		"UpsertFeedSyncStatus":   func() error { return adapter.UpsertFeedSyncStatus(ctx, status) },
		"InsertAdminAuditLog":    func() error { return adapter.InsertAdminAuditLog(ctx, directAudit) },
	} {
		if err := call(); err != nil {
			t.Fatalf("%s() error = %v", name, err)
		}
	}
	if store.args["InsertScanLog"] != scan || store.args["UpsertVulnerability"] != vuln || store.args["UpsertMaliciousFinding"] != malicious || store.args["UpsertFeedSyncStatus"] != status || store.args["InsertAdminAuditLog"] != directAudit {
		t.Fatalf("pointer arguments were not preserved: %+v", store.args)
	}
	if store.args["DeleteVulnerability"] != "CVE-delete" || store.args["DeleteMaliciousFinding"] != "MAL-delete" {
		t.Fatalf("delete IDs were not preserved: vulnerability=%v malicious=%v", store.args["DeleteVulnerability"], store.args["DeleteMaliciousFinding"])
	}

	assertAuditedImport := func(name string, wantArgs any, wantImported, wantDeleted int, call func(db.FeedImportAuditBuilder) (int, int, error)) {
		t.Helper()
		calls := 0
		imported, deleted, err := call(func(gotImported, gotDeleted int) db.AdminAuditEntry {
			calls++
			if gotImported != wantImported || gotDeleted != wantDeleted {
				t.Errorf("%s audit counts = %d/%d, want %d/%d", name, gotImported, gotDeleted, wantImported, wantDeleted)
			}
			return db.AdminAuditEntry{Action: name}
		})
		if err != nil || imported != wantImported || deleted != wantDeleted || calls != 1 {
			t.Fatalf("%s = %d/%d, %v; audit calls=%d", name, imported, deleted, err, calls)
		}
		if got := store.args[name+".audit"].(db.AdminAuditEntry).Action; got != name {
			t.Fatalf("%s stored audit action = %q", name, got)
		}
		if !reflect.DeepEqual(store.args[name], wantArgs) {
			t.Fatalf("%s arguments = %+v, want %+v", name, store.args[name], wantArgs)
		}
	}
	assertAuditedImport("ImportVulnerabilityFeedWithAudit", []any{"osv", []db.Vulnerability{{ID: "CVE-import"}}, []string{"CVE-delete"}, status}, 11, 12, func(audit db.FeedImportAuditBuilder) (int, int, error) {
		return adapter.ImportVulnerabilityFeedWithAudit(ctx, "osv", []db.Vulnerability{{ID: "CVE-import"}}, []string{"CVE-delete"}, status, audit)
	})
	assertAuditedImport("ImportMaliciousFeedWithAudit", []any{"openssf", []db.MaliciousFinding{{ID: "MAL-import"}}, []string{"MAL-delete"}, status}, 13, 14, func(audit db.FeedImportAuditBuilder) (int, int, error) {
		return adapter.ImportMaliciousFeedWithAudit(ctx, "openssf", []db.MaliciousFinding{{ID: "MAL-import"}}, []string{"MAL-delete"}, status, audit)
	})
	assertAuditedImport("ImportVulnCheckWithAudit", []any{"vulncheck", []db.VulnCheckEntry{{CVEID: "CVE-vc"}}, status}, 15, 0, func(audit db.FeedImportAuditBuilder) (int, int, error) {
		got, err := adapter.ImportVulnCheckWithAudit(ctx, "vulncheck", []db.VulnCheckEntry{{CVEID: "CVE-vc"}}, status, audit)
		return got, 0, err
	})
	assertAuditedImport("ImportCISAKEVWithAudit", []any{"cisakev", []string{"CVE-kev"}, status}, 16, 0, func(audit db.FeedImportAuditBuilder) (int, int, error) {
		got, err := adapter.ImportCISAKEVWithAudit(ctx, "cisakev", []string{"CVE-kev"}, status, audit)
		return got, 0, err
	})
	assertAuditedImport("ReplaceCISAKEVWithAudit", []any{"cisakev", []string{"CVE-replace"}, status}, 17, 18, func(audit db.FeedImportAuditBuilder) (int, int, error) {
		return adapter.ReplaceCISAKEVWithAudit(ctx, "cisakev", []string{"CVE-replace"}, status, audit)
	})
	assertAuditedImport("ImportEPSSWithAudit", []any{"epss", []db.EPSSEntry{{CVEID: "CVE-epss"}}, status}, 19, 20, func(audit db.FeedImportAuditBuilder) (int, int, error) {
		return adapter.ImportEPSSWithAudit(ctx, "epss", []db.EPSSEntry{{CVEID: "CVE-epss"}}, status, audit)
	})

	if got, err := adapter.EnrichVulnCheck(ctx, []db.VulnCheckEntry{{CVEID: "CVE-enrich"}}); err != nil || got != 23 {
		t.Fatalf("EnrichVulnCheck() = %d, %v", got, err)
	}
	if got, err := adapter.SetCISAKEV(ctx, []string{"CVE-set"}); err != nil || got != 24 {
		t.Fatalf("SetCISAKEV() = %d, %v", got, err)
	}
	if got, err := adapter.ClearCISAKEV(ctx, []string{"CVE-clear"}); err != nil || got != 25 {
		t.Fatalf("ClearCISAKEV() = %d, %v", got, err)
	}
	if updated, cleared, err := adapter.ReplaceCISAKEV(ctx, []string{"CVE-replace"}); err != nil || updated != 26 || cleared != 27 {
		t.Fatalf("ReplaceCISAKEV() = %d/%d, %v", updated, cleared, err)
	}
	if updated, cleared, err := adapter.ReplaceEPSSScores(ctx, []db.EPSSEntry{{CVEID: "CVE-replace-epss"}}); err != nil || updated != 28 || cleared != 29 {
		t.Fatalf("ReplaceEPSSScores() = %d/%d, %v", updated, cleared, err)
	}
	for name, want := range map[string]any{
		"EnrichVulnCheck":   []db.VulnCheckEntry{{CVEID: "CVE-enrich"}},
		"SetCISAKEV":        []string{"CVE-set"},
		"ClearCISAKEV":      []string{"CVE-clear"},
		"ReplaceCISAKEV":    []string{"CVE-replace"},
		"ReplaceEPSSScores": []db.EPSSEntry{{CVEID: "CVE-replace-epss"}},
	} {
		if !reflect.DeepEqual(store.args[name], want) {
			t.Errorf("%s arguments = %+v, want %+v", name, store.args[name], want)
		}
	}
}

func TestDBStoreAdapterPropagatesBackingStoreErrors(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(context.Background(), adapterContextKey{}, "errors")
	errSentinel := errors.New("adapter backing store sentinel")
	store := newAdapterContractStore(ctx)
	store.err = errSentinel
	adapter := NewDBStoreAdapter(store)
	lookups := []PackageLookup{{Ecosystem: "npm", Name: "one", Version: "1"}}
	status := &db.FeedSyncStatus{}
	audit := func(int, int) db.AdminAuditEntry { return db.AdminAuditEntry{} }

	checks := map[string]func() error{
		"FindVulnerabilities":         func() error { _, err := adapter.FindVulnerabilities(ctx, "npm", "one", "1"); return err },
		"FindMalicious":               func() error { _, err := adapter.FindMalicious(ctx, "npm", "one", "1"); return err },
		"FindVulnerabilitiesBatch":    func() error { _, err := adapter.FindVulnerabilitiesBatch(ctx, lookups); return err },
		"FindMaliciousBatch":          func() error { _, err := adapter.FindMaliciousBatch(ctx, lookups); return err },
		"FindReputationFindingsBatch": func() error { _, err := adapter.FindReputationFindingsBatch(ctx, lookups, "socket"); return err },
		"FindLifecycleFindingsBatch":  func() error { _, err := adapter.FindLifecycleFindingsBatch(ctx, lookups, time.Time{}); return err },
		"ListFeedSyncStatuses":        func() error { _, err := adapter.ListFeedSyncStatuses(ctx); return err },
		"EnqueueRefresh":              func() error { _, _, err := adapter.EnqueueRefresh(ctx, &db.RefreshJob{}); return err },
		"EnqueueRefreshWithAudit":     func() error { _, _, err := adapter.EnqueueRefreshWithAudit(ctx, &db.RefreshJob{}, nil); return err },
		"InsertScanLog":               func() error { return adapter.InsertScanLog(ctx, &db.ScanLogEntry{}) },
		"UpsertVulnerability":         func() error { return adapter.UpsertVulnerability(ctx, &db.Vulnerability{}) },
		"DeleteVulnerability":         func() error { return adapter.DeleteVulnerability(ctx, "id") },
		"UpsertMaliciousFinding":      func() error { return adapter.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{}) },
		"DeleteMaliciousFinding":      func() error { return adapter.DeleteMaliciousFinding(ctx, "id") },
		"ImportVulnerabilityFeedWithAudit": func() error {
			_, _, err := adapter.ImportVulnerabilityFeedWithAudit(ctx, "osv", nil, nil, status, audit)
			return err
		},
		"ImportMaliciousFeedWithAudit": func() error {
			_, _, err := adapter.ImportMaliciousFeedWithAudit(ctx, "openssf", nil, nil, status, audit)
			return err
		},
		"ImportVulnCheckWithAudit": func() error {
			_, err := adapter.ImportVulnCheckWithAudit(ctx, "vulncheck", nil, status, audit)
			return err
		},
		"ImportCISAKEVWithAudit": func() error { _, err := adapter.ImportCISAKEVWithAudit(ctx, "cisakev", nil, status, audit); return err },
		"ReplaceCISAKEVWithAudit": func() error {
			_, _, err := adapter.ReplaceCISAKEVWithAudit(ctx, "cisakev", nil, status, audit)
			return err
		},
		"ImportEPSSWithAudit":        func() error { _, _, err := adapter.ImportEPSSWithAudit(ctx, "epss", nil, status, audit); return err },
		"EnrichVulnCheck":            func() error { _, err := adapter.EnrichVulnCheck(ctx, nil); return err },
		"SetCISAKEV":                 func() error { _, err := adapter.SetCISAKEV(ctx, nil); return err },
		"ClearCISAKEV":               func() error { _, err := adapter.ClearCISAKEV(ctx, nil); return err },
		"ReplaceCISAKEV":             func() error { _, _, err := adapter.ReplaceCISAKEV(ctx, nil); return err },
		"ReplaceEPSSScores":          func() error { _, _, err := adapter.ReplaceEPSSScores(ctx, nil); return err },
		"UpsertFeedSyncStatus":       func() error { return adapter.UpsertFeedSyncStatus(ctx, status) },
		"InsertAdminAuditLog":        func() error { return adapter.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{}) },
		"ExportSync":                 func() error { _, err := adapter.ExportSync(ctx, db.SyncExportOptions{}); return err },
		"FindReputationFindings":     func() error { _, err := adapter.FindReputationFindings(ctx, "npm", "one", "socket"); return err },
		"GetPackageCheckStatus":      func() error { _, err := adapter.GetPackageCheckStatus(ctx, "npm", "one", "socket"); return err },
		"GetScanLogByIdempotencyKey": func() error { _, err := adapter.GetScanLogByIdempotencyKey(ctx, "idem"); return err },
	}
	for name, call := range checks {
		if err := call(); err != errSentinel {
			t.Errorf("%s() error = %v, want exact sentinel", name, err)
		}
	}
}
