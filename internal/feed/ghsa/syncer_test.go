package ghsa

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/feed"
)

type ghsaStoreStub struct {
	db.Store
	upserts         int
	statuses        []*db.FeedSyncStatus
	status          *db.FeedSyncStatus
	vulns           []*db.Vulnerability
	deleted         []string
	deletedSources  []string
	upsertErr       error
	deleteErr       error
	statusUpsertErr error
	rejectCanceled  bool
}

func (s *ghsaStoreStub) UpsertVulnerability(_ context.Context, vuln *db.Vulnerability) error {
	if s.upsertErr != nil {
		return s.upsertErr
	}
	s.upserts++
	s.vulns = append(s.vulns, vuln)
	return nil
}

func (s *ghsaStoreStub) DeleteVulnerability(_ context.Context, id string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, id)
	return nil
}

func (s *ghsaStoreStub) DeleteVulnerabilityForSource(_ context.Context, id, source string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, id)
	s.deletedSources = append(s.deletedSources, source)
	return nil
}

func (s *ghsaStoreStub) UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error {
	if s.rejectCanceled && ctx.Err() != nil {
		return ctx.Err()
	}
	if s.statusUpsertErr != nil {
		return s.statusUpsertErr
	}
	s.statuses = append(s.statuses, status)
	copyValue := *status
	s.status = &copyValue
	return nil
}

func (s *ghsaStoreStub) GetFeedSyncStatus(context.Context, string) (*db.FeedSyncStatus, error) {
	if s.status == nil {
		return nil, nil
	}
	copyValue := *s.status
	return &copyValue, nil
}

func TestMapToVulnerability_PreservesGitHubActionsPackage(t *testing.T) {
	t.Parallel()

	advisory := &ghsaAdvisory{
		ID:      "GHSA-test-1234-5678",
		Summary: "GitHub Action advisory",
		Affected: []ghsaAffected{
			{
				Package: ghsaPackage{
					Ecosystem: "GitHub Actions",
					Name:      "actions/setup-node",
				},
				Ranges: []ghsaRange{
					{
						Type: "ECOSYSTEM",
						Events: []ghsaEvent{
							{Introduced: "0"},
							{Fixed: "4.0.0"},
						},
					},
				},
				Versions: []string{"3.8.1"},
			},
		},
		DatabaseSpecific: &ghsaDatabaseSpecific{
			Severity: "HIGH",
		},
	}

	vuln, err := mapToVulnerability(advisory, []byte(`{}`))
	if err != nil {
		t.Fatalf("mapToVulnerability() error = %v", err)
	}
	if len(vuln.AffectedPackages) != 1 {
		t.Fatalf("AffectedPackages count = %d, want 1", len(vuln.AffectedPackages))
	}

	if vuln.AffectedPackages[0].Ecosystem != string(domain.EcosystemGitHubActions) {
		t.Fatalf("AffectedPackages[0].Ecosystem = %q, want %q", vuln.AffectedPackages[0].Ecosystem, domain.EcosystemGitHubActions)
	}
	if vuln.AffectedPackages[0].Name != "actions/setup-node" {
		t.Fatalf("AffectedPackages[0].Name = %q, want %q", vuln.AffectedPackages[0].Name, "actions/setup-node")
	}
}

func TestMapToVulnerabilityMergesDuplicateGitHubActionsRanges(t *testing.T) {
	t.Parallel()

	raw := []byte(`{
		"id":"GHSA-codeql-action",
		"summary":"CodeQL Action advisory",
		"affected":[
			{
				"package":{"ecosystem":"GitHub Actions","name":"github/codeql-action"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.26.11"},{"fixed":"3.28.3"}]}]
			},
			{
				"package":{"ecosystem":"GitHub Actions","name":"github/codeql-action"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.26.11"}]}],
				"database_specific":{"last_known_affected_version_range":"< 3.0.0"}
			}
		],
		"database_specific":{"severity":"HIGH"}
	}`)
	var advisory ghsaAdvisory
	if err := json.Unmarshal(raw, &advisory); err != nil {
		t.Fatalf("unmarshal advisory: %v", err)
	}

	vuln, err := mapToVulnerability(&advisory, raw)
	if err != nil {
		t.Fatalf("mapToVulnerability() error = %v", err)
	}
	if len(vuln.AffectedPackages) != 1 {
		t.Fatalf("AffectedPackages count = %d, want 1 merged package", len(vuln.AffectedPackages))
	}

	var ranges []ghsaRange
	if err := json.Unmarshal(vuln.AffectedPackages[0].VersionRanges, &ranges); err != nil {
		t.Fatalf("unmarshal version ranges: %v", err)
	}
	if len(ranges) != 2 {
		t.Fatalf("merged ranges count = %d, want 2: %s", len(ranges), vuln.AffectedPackages[0].VersionRanges)
	}
	if ranges[0].Events[1].Fixed != "3.28.3" {
		t.Fatalf("first merged range = %+v, want fixed 3.28.3 preserved", ranges[0])
	}
	if len(ranges[1].Events) != 2 || ranges[1].Events[1].Fixed != "3.0.0" {
		t.Fatalf("second merged range = %+v, want fixed 3.0.0 derived from last_known_affected_version_range", ranges[1])
	}
}

func TestNewSyncerDefaultsAndName(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(nil, "")
	if syncer.Name() != FeedName {
		t.Fatalf("Name() = %q, want %q", syncer.Name(), FeedName)
	}
	if syncer.dataDir == "" {
		t.Fatal("dataDir is empty, want default temp dir")
	}
}

func TestSyncerDoesNotOwnStoreOutsideSyncContract(t *testing.T) {
	t.Parallel()

	syncerType := reflect.TypeOf(Syncer{})
	storeType := reflect.TypeOf((*db.Store)(nil)).Elem()
	for i := 0; i < syncerType.NumField(); i++ {
		field := syncerType.Field(i)
		if field.Type == storeType {
			t.Fatalf("Syncer field %s stores db.Store; use Sync(ctx, store) as the only persistence input", field.Name)
		}
	}

	source, err := os.ReadFile("syncer.go")
	if err != nil {
		t.Fatalf("read syncer.go: %v", err)
	}
	if regexp.MustCompile(`(?m)^\s*store\s+db\.Store\b`).Match(source) {
		t.Fatal("syncer.go declares a store db.Store field; use Sync(ctx, store) as the only persistence input")
	}
	if strings.Contains(string(source), "s.store") {
		t.Fatal("syncer.go references s.store; use the store passed to Sync(ctx, store)")
	}
}

func TestMapToVulnerabilityHandlesAliasesReferencesAndWithdrawn(t *testing.T) {
	t.Parallel()

	withdrawn := "2026-05-30T12:00:00Z"
	advisory := &ghsaAdvisory{
		ID:        "GHSA-map-1234-5678",
		Summary:   "summary",
		Details:   "details",
		Withdrawn: &withdrawn,
		Aliases:   []string{"CVE-2026-0001"},
		References: []ghsaReference{
			{Type: "WEB", URL: ""},
			{Type: "ADVISORY", URL: "https://github.com/advisories/GHSA-map-1234-5678"},
		},
		DatabaseSpecific: &ghsaDatabaseSpecific{
			CVEs:     []string{"CVE-2026-0002"},
			Severity: "critical",
		},
		Affected: []ghsaAffected{
			{Package: ghsaPackage{Ecosystem: "unknown", Name: "ignored"}},
			{Package: ghsaPackage{Ecosystem: "pip", Name: "package"}, Versions: []string{"1.0.0"}},
		},
	}

	vuln, err := mapToVulnerability(advisory, []byte(`{"id":"GHSA-map-1234-5678"}`))
	if err != nil {
		t.Fatalf("mapToVulnerability() error = %v", err)
	}
	if vuln.Severity != "CRITICAL" || vuln.Withdrawn == nil {
		t.Fatalf("mapped vulnerability severity/withdrawn = %q/%v", vuln.Severity, vuln.Withdrawn)
	}
	if len(vuln.References) != 1 || len(vuln.AffectedPackages) != 1 {
		t.Fatalf("mapped refs/packages = %+v / %+v", vuln.References, vuln.AffectedPackages)
	}
	aliasSet := map[string]bool{}
	for _, alias := range vuln.Aliases {
		aliasSet[alias.AliasID] = true
	}
	for _, want := range []string{"GHSA-map-1234-5678", "CVE-2026-0001", "CVE-2026-0002"} {
		if !aliasSet[want] {
			t.Fatalf("aliases = %+v, missing %s", vuln.Aliases, want)
		}
	}

	badWithdrawn := "not a timestamp"
	_, err = mapToVulnerability(&ghsaAdvisory{ID: "GHSA-bad-withdrawn", Withdrawn: &badWithdrawn}, nil)
	if err == nil || !strings.Contains(err.Error(), "withdrawn") {
		t.Fatalf("mapToVulnerability(invalid withdrawn) error = %v, want withdrawn parse error", err)
	}
}

func TestProcessChangedFilesDoesNotReadOutsideRepo(t *testing.T) {
	t.Parallel()

	repoDir := t.TempDir()
	outsidePath := filepath.Join(filepath.Dir(repoDir), "outside.json")
	if err := os.WriteFile(outsidePath, []byte(`{"id":"GHSA-outside-1234-5678"}`), 0o600); err != nil {
		t.Fatalf("write outside advisory: %v", err)
	}

	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, "")
	_, _, err := syncer.processChangedFiles(context.Background(), store, repoDir, []string{
		reviewedDir + "/../../../outside.json",
	})
	if err != nil {
		t.Fatalf("processChangedFiles() error = %v", err)
	}
	if store.upserts != 0 {
		t.Fatalf("upserts = %d, want 0 for path outside repo", store.upserts)
	}
	if len(store.deleted) != 0 {
		t.Fatalf("deleted IDs = %v, want none for path outside repo", store.deleted)
	}
}

func TestProcessChangedFilesFiltersAndUpsertsReviewedJSON(t *testing.T) {
	t.Parallel()

	repoDir := t.TempDir()
	advisoryPath := filepath.Join(repoDir, reviewedDir, "2026", "05", "GHSA-test.json")
	if err := os.MkdirAll(filepath.Dir(advisoryPath), 0o750); err != nil {
		t.Fatalf("mkdir advisory dir: %v", err)
	}
	if err := os.WriteFile(advisoryPath, []byte(`{
		"id":"GHSA-test-1234-5678",
		"summary":"test advisory",
		"affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}],
		"database_specific":{"severity":"MODERATE"}
	}`), 0o600); err != nil {
		t.Fatalf("write advisory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, reviewedDir, "2026", "05", "note.txt"), []byte("ignore"), 0o600); err != nil {
		t.Fatalf("write note: %v", err)
	}

	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, "")
	synced, total, err := syncer.processChangedFiles(context.Background(), store, repoDir, []string{
		reviewedDir + "/2026/05/GHSA-test.json",
		reviewedDir + "/2026/05/note.txt",
		"advisories/unreviewed/GHSA-other.json",
		reviewedDir + "/2026/05/missing.json",
	})
	if err != nil {
		t.Fatalf("processChangedFiles: %v", err)
	}
	if synced != 2 || total != 2 || store.upserts != 1 {
		t.Fatalf("synced=%d total=%d upserts=%d", synced, total, store.upserts)
	}
	if got := store.vulns[0].Severity; got != "MEDIUM" {
		t.Fatalf("severity = %q, want MEDIUM", got)
	}
	if len(store.deleted) != 1 || store.deleted[0] != "missing" {
		t.Fatalf("deleted IDs = %v, want [missing]", store.deleted)
	}
	if len(store.deletedSources) != 1 || store.deletedSources[0] != "ghsa" {
		t.Fatalf("deleted sources = %v, want [ghsa]", store.deletedSources)
	}
}

func TestProcessChangedFilesDeletesRemovedReviewedJSON(t *testing.T) {
	t.Parallel()

	repoDir := t.TempDir()
	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, "")
	synced, total, err := syncer.processChangedFiles(context.Background(), store, repoDir, []string{
		reviewedDir + "/2026/05/GHSA-deleted-1234-5678.json",
	})
	if err != nil {
		t.Fatalf("processChangedFiles(deleted): %v", err)
	}
	if synced != 1 || total != 1 {
		t.Fatalf("deleted changed file synced=%d total=%d, want 1/1", synced, total)
	}
	if len(store.deleted) != 1 || store.deleted[0] != "GHSA-deleted-1234-5678" {
		t.Fatalf("deleted IDs = %v", store.deleted)
	}
	if len(store.deletedSources) != 1 || store.deletedSources[0] != "ghsa" {
		t.Fatalf("deleted sources = %v, want [ghsa]", store.deletedSources)
	}

	store = &ghsaStoreStub{deleteErr: errors.New("delete failed")}
	_, _, err = syncer.processChangedFiles(context.Background(), store, repoDir, []string{
		reviewedDir + "/2026/05/GHSA-delete-failed.json",
	})
	if err == nil || !errors.Is(err, store.deleteErr) {
		t.Fatalf("processChangedFiles(delete error) = %v", err)
	}
}

func TestProcessChangedFilesDoesNotDeleteOnOversizedReadError(t *testing.T) {
	t.Parallel()

	repoDir := t.TempDir()
	advisoryRelPath := reviewedDir + "/2026/05/GHSA-huge-1234-5678.json"
	advisoryPath := filepath.Join(repoDir, filepath.FromSlash(advisoryRelPath))
	if err := os.MkdirAll(filepath.Dir(advisoryPath), 0o750); err != nil {
		t.Fatalf("mkdir advisory dir: %v", err)
	}
	if err := os.WriteFile(advisoryPath, []byte(`{"id":"GHSA-huge-1234-5678"}`), 0o600); err != nil {
		t.Fatalf("write advisory: %v", err)
	}
	if err := os.Truncate(advisoryPath, feed.MaxGitAdvisoryJSONSize+1); err != nil {
		t.Fatalf("truncate advisory: %v", err)
	}

	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, "")
	synced, total, err := syncer.processChangedFiles(context.Background(), store, repoDir, []string{advisoryRelPath})
	if err == nil || !strings.Contains(err.Error(), "1 GHSA advisory import errors") {
		t.Fatalf("processChangedFiles() error = %v, want aggregate import error", err)
	}
	if synced != 0 || total != 1 || store.upserts != 0 {
		t.Fatalf("synced=%d total=%d upserts=%d, want 0/1/0", synced, total, store.upserts)
	}
	if len(store.deleted) != 0 {
		t.Fatalf("deleted IDs = %v, want none for oversized read error", store.deleted)
	}
}

func TestProcessChangedFilesReportsMalformedWithdrawnTimestamp(t *testing.T) {
	t.Parallel()

	repoDir := t.TempDir()
	advisoryRelPath := reviewedDir + "/2026/05/GHSA-bad-withdrawn-1234.json"
	advisoryPath := filepath.Join(repoDir, filepath.FromSlash(advisoryRelPath))
	if err := os.MkdirAll(filepath.Dir(advisoryPath), 0o750); err != nil {
		t.Fatalf("mkdir advisory dir: %v", err)
	}
	if err := os.WriteFile(advisoryPath, []byte(`{
		"id":"GHSA-bad-withdrawn-1234",
		"summary":"bad withdrawn advisory",
		"withdrawn":"not a timestamp",
		"database_specific":{"severity":"LOW"}
	}`), 0o600); err != nil {
		t.Fatalf("write advisory: %v", err)
	}

	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, "")
	synced, total, err := syncer.processChangedFiles(context.Background(), store, repoDir, []string{advisoryRelPath})
	if err == nil || !strings.Contains(err.Error(), "1 GHSA advisory import errors") {
		t.Fatalf("processChangedFiles() error = %v, want aggregate import error", err)
	}
	if synced != 0 || total != 1 || store.upserts != 0 {
		t.Fatalf("synced=%d total=%d upserts=%d, want 0/1/0", synced, total, store.upserts)
	}
}

func TestWalkAdvisoriesRejectsOversizedAdvisoryJSON(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	advisoryPath := filepath.Join(root, "2026", "05", "GHSA-huge-1234-5678.json")
	if err := os.MkdirAll(filepath.Dir(advisoryPath), 0o750); err != nil {
		t.Fatalf("mkdir advisory dir: %v", err)
	}
	if err := os.WriteFile(advisoryPath, []byte(`{"id":"GHSA-huge-1234-5678"}`), 0o600); err != nil {
		t.Fatalf("write advisory: %v", err)
	}
	if err := os.Truncate(advisoryPath, feed.MaxGitAdvisoryJSONSize+1); err != nil {
		t.Fatalf("truncate advisory: %v", err)
	}

	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, "")
	synced, total, err := syncer.walkAdvisories(context.Background(), store, root)
	if err == nil || !strings.Contains(err.Error(), "1 GHSA advisory import errors") {
		t.Fatalf("walkAdvisories() error = %v, want aggregate import error", err)
	}
	if synced != 0 || total != 1 || store.upserts != 0 {
		t.Fatalf("synced=%d total=%d upserts=%d, want 0/1/0", synced, total, store.upserts)
	}
}

func TestWalkAdvisoriesReportsInvalidFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	files := map[string]string{
		"valid.json":      `{"id":"GHSA-valid-1234-5678","summary":"valid","database_specific":{"severity":"LOW"}}`,
		"missing-id.json": `{"summary":"missing id"}`,
		"invalid.json":    `{not json`,
		"note.txt":        `ignore`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, "")
	synced, total, err := syncer.walkAdvisories(context.Background(), store, root)
	if err == nil || !strings.Contains(err.Error(), "2 GHSA advisory import errors") {
		t.Fatalf("walkAdvisories() error = %v, want aggregate import error", err)
	}
	if synced != 1 || total != 3 || store.upserts != 1 {
		t.Fatalf("synced=%d total=%d upserts=%d", synced, total, store.upserts)
	}

	store = &ghsaStoreStub{upsertErr: errors.New("db down")}
	synced, total, err = syncer.walkAdvisories(context.Background(), store, root)
	if err == nil || !strings.Contains(err.Error(), "3 GHSA advisory import errors") {
		t.Fatalf("walkAdvisories(upsert error) = %v, want aggregate import error", err)
	}
	if synced != 0 || total != 3 || store.upserts != 0 {
		t.Fatalf("upsert error synced=%d total=%d upserts=%d, want 0/3/0", synced, total, store.upserts)
	}
}

func TestProcessChangedFilesReportsSkippedImportErrors(t *testing.T) {
	t.Parallel()

	repoDir := t.TempDir()
	validPath := filepath.Join(repoDir, reviewedDir, "2026", "05", "GHSA-valid.json")
	invalidPath := filepath.Join(repoDir, reviewedDir, "2026", "05", "GHSA-invalid.json")
	missingIDPath := filepath.Join(repoDir, reviewedDir, "2026", "05", "GHSA-missing-id.json")
	if err := os.MkdirAll(filepath.Dir(validPath), 0o750); err != nil {
		t.Fatalf("mkdir advisory dir: %v", err)
	}
	if err := os.WriteFile(validPath, []byte(`{"id":"GHSA-valid-1234-5678","database_specific":{"severity":"LOW"}}`), 0o600); err != nil {
		t.Fatalf("write valid advisory: %v", err)
	}
	if err := os.WriteFile(invalidPath, []byte(`{not json`), 0o600); err != nil {
		t.Fatalf("write invalid advisory: %v", err)
	}
	if err := os.WriteFile(missingIDPath, []byte(`{"summary":"missing id"}`), 0o600); err != nil {
		t.Fatalf("write missing id advisory: %v", err)
	}

	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, "")
	synced, total, err := syncer.processChangedFiles(context.Background(), store, repoDir, []string{
		reviewedDir + "/2026/05/GHSA-valid.json",
		reviewedDir + "/2026/05/GHSA-invalid.json",
		reviewedDir + "/2026/05/GHSA-missing-id.json",
	})
	if err == nil || !strings.Contains(err.Error(), "2 GHSA advisory import errors") {
		t.Fatalf("processChangedFiles() error = %v, want aggregate import error", err)
	}
	if synced != 1 || total != 3 || store.upserts != 1 {
		t.Fatalf("synced=%d total=%d upserts=%d, want 1/3/1", synced, total, store.upserts)
	}
}

func TestGHSASyncStatusAndRepairHelpers(t *testing.T) {
	t.Parallel()

	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, "")
	syncer.recordSyncSuccessWithCommit(context.Background(), store, time.Second, 10, 8, "abc123", true)
	syncer.recordSyncFailure(context.Background(), store, time.Now(), context.Canceled)

	if len(store.statuses) != 2 {
		t.Fatalf("statuses length = %d, want 2", len(store.statuses))
	}
	if store.statuses[0].LastSyncStatus != "success" || store.statuses[0].LastCommitHash != "abc123" {
		t.Fatalf("success status = %+v", store.statuses[0])
	}
	if !ghsaMetadataIsCurrentForTest(store.statuses[0].Metadata) {
		t.Fatalf("success metadata = %s, want current", store.statuses[0].Metadata)
	}
	if store.statuses[1].LastSyncStatus != "error" || store.statuses[1].LastError == "" {
		t.Fatalf("failure status = %+v", store.statuses[1])
	}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	store.rejectCanceled = true
	syncer.recordSyncFailure(canceledCtx, store, time.Now(), context.Canceled)
	if len(store.statuses) != 3 {
		t.Fatalf("statuses length after canceled context = %d, want 3", len(store.statuses))
	}

	repairStore := &ghsaRepairStoreStub{repaired: 3}
	if got, ok := syncer.repairAffectedPackages(context.Background(), repairStore); got != 3 || !ok {
		t.Fatalf("repairAffectedPackages() = %d/%t, want 3/true", got, ok)
	}
	repairStore.err = errors.New("repair failed")
	if got, ok := syncer.repairAffectedPackages(context.Background(), repairStore); got != 0 || ok {
		t.Fatalf("repairAffectedPackages(error) = %d/%t, want 0/false", got, ok)
	}
	if got, ok := syncer.repairAffectedPackages(context.Background(), store); got != 0 || !ok {
		t.Fatalf("repairAffectedPackages(non-repairer) = %d/%t, want 0/true", got, ok)
	}

	store.statusUpsertErr = errors.New("status db down")
	syncer.recordSyncSuccessWithCommit(context.Background(), store, time.Second, 1, 1, "def456", true)
	syncer.recordSyncFailure(context.Background(), store, time.Now(), context.Canceled)
}

func TestRecordSyncFailurePreservesLastUsableSync(t *testing.T) {
	t.Parallel()

	lastSync := time.Date(2026, 5, 1, 12, 30, 0, 0, time.UTC)
	store := &ghsaStoreStub{status: &db.FeedSyncStatus{
		FeedName:       FeedName,
		LastSyncStatus: db.FeedSyncStatusSuccess,
		LastSyncAt:     &lastSync,
		EntriesSynced:  17,
		EntriesTotal:   23,
		LastCommitHash: "abc123",
	}}
	syncer := NewSyncer(nil, "")

	syncer.recordSyncFailure(context.Background(), store, time.Now().Add(-time.Second), errors.New("upstream unavailable"))

	if store.status == nil {
		t.Fatal("recordSyncFailure did not write feed status")
	}
	if store.status.LastSyncStatus != db.FeedSyncStatusError {
		t.Fatalf("LastSyncStatus = %q, want error", store.status.LastSyncStatus)
	}
	if store.status.LastSyncAt == nil || !store.status.LastSyncAt.Equal(lastSync) {
		t.Fatalf("LastSyncAt = %v, want preserved %v", store.status.LastSyncAt, lastSync)
	}
	if store.status.EntriesSynced != 17 || store.status.EntriesTotal != 23 {
		t.Fatalf("entries = %d/%d, want preserved 17/23", store.status.EntriesSynced, store.status.EntriesTotal)
	}
	if store.status.LastCommitHash != "abc123" {
		t.Fatalf("LastCommitHash = %q, want preserved abc123", store.status.LastCommitHash)
	}
}

func TestSyncExistingCheckoutWithoutImportBaselineDoesFullWalk(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dataDir := t.TempDir()
	repoDir := filepath.Join(dataDir, "advisory-database")
	initGHSAGitRepo(t, repoDir)
	advisoryPath := filepath.Join(repoDir, reviewedDir, "2026", "05", "GHSA-sync.json")
	if err := os.MkdirAll(filepath.Dir(advisoryPath), 0o750); err != nil {
		t.Fatalf("mkdir advisory dir: %v", err)
	}
	if err := os.WriteFile(advisoryPath, []byte(`{"id":"GHSA-sync-1234-5678","database_specific":{"severity":"LOW"}}`), 0o600); err != nil {
		t.Fatalf("write advisory: %v", err)
	}
	commitGHSAGitRepo(t, repoDir)

	// An existing checkout without any recorded import must not be treated as
	// "already synced": the checkout state says nothing about the database.
	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, dataDir)
	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 1 || result.EntriesTotal != 1 {
		t.Fatalf("Sync() result = %+v, want full walk importing the advisory", result)
	}
	if store.upserts != 1 {
		t.Fatalf("upserts = %d, want 1 imported advisory", store.upserts)
	}
	if len(store.statuses) == 0 || store.status.LastSyncStatus != "success" || store.status.LastCommitHash == "" {
		t.Fatalf("statuses = %+v, want success with commit", store.statuses)
	}
}

func TestSyncImportsAdvisoriesMissedWhenCheckoutIsAheadOfImportBaseline(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dataDir := t.TempDir()
	repoDir := filepath.Join(dataDir, "advisory-database")
	initGHSAGitRepo(t, repoDir)
	firstAdvisory := filepath.Join(repoDir, reviewedDir, "2026", "05", "GHSA-early.json")
	if err := os.MkdirAll(filepath.Dir(firstAdvisory), 0o750); err != nil {
		t.Fatalf("mkdir advisory dir: %v", err)
	}
	if err := os.WriteFile(firstAdvisory, []byte(`{"id":"GHSA-early-1234-5678","database_specific":{"severity":"LOW"}}`), 0o600); err != nil {
		t.Fatalf("write first advisory: %v", err)
	}
	commitGHSAGitRepo(t, repoDir)
	baseline := headGHSAGit(t, repoDir)

	// A new advisory lands after the last successful import. The checkout is
	// already at the newest commit (e.g. a clone from an interrupted attempt),
	// so a diff against the checkout HEAD would report "no changes" and lose
	// the advisory forever.
	lateAdvisory := filepath.Join(repoDir, reviewedDir, "2026", "07", "GHSA-late.json")
	if err := os.MkdirAll(filepath.Dir(lateAdvisory), 0o750); err != nil {
		t.Fatalf("mkdir late advisory dir: %v", err)
	}
	if err := os.WriteFile(lateAdvisory, []byte(`{"id":"GHSA-late-1234-5678","database_specific":{"severity":"HIGH"}}`), 0o600); err != nil {
		t.Fatalf("write late advisory: %v", err)
	}
	commitGHSAGitRepo(t, repoDir)

	store := &ghsaStoreStub{status: &db.FeedSyncStatus{
		FeedName:       FeedName,
		LastSyncStatus: db.FeedSyncStatusSuccess,
		EntriesTotal:   1,
		LastCommitHash: baseline,
	}}
	syncer := NewSyncer(nil, dataDir)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced < 1 {
		t.Fatalf("Sync() result = %+v, want the missed advisory imported", result)
	}
	imported := false
	for _, vuln := range store.vulns {
		if vuln.ID == "GHSA-late-1234-5678" {
			imported = true
		}
	}
	if !imported {
		t.Fatalf("imported vulns = %+v, want GHSA-late-1234-5678", store.vulns)
	}
	if store.status.LastSyncStatus != "success" || store.status.LastCommitHash == baseline {
		t.Fatalf("recorded status = %+v, want success at the new commit", store.status)
	}
}

func TestResolveDeltaEntriesTotalCarriesForwardPreviousTotal(t *testing.T) {
	t.Parallel()

	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, "")
	status := &db.FeedSyncStatus{FeedName: FeedName, EntriesTotal: 41028}

	if got := syncer.resolveDeltaEntriesTotal(context.Background(), store, status, 0); got != 41028 {
		t.Fatalf("resolveDeltaEntriesTotal(no changes) = %d, want previous total 41028", got)
	}
	if got := syncer.resolveDeltaEntriesTotal(context.Background(), store, status, 12); got != 41028 {
		t.Fatalf("resolveDeltaEntriesTotal(12 changed) = %d, want previous total 41028", got)
	}
}

func TestResolveDeltaEntriesTotalRecoversZeroBaselineFromStoredEntries(t *testing.T) {
	t.Parallel()

	store := &ghsaCountingStoreStub{count: 41028}
	syncer := NewSyncer(nil, "")
	status := &db.FeedSyncStatus{FeedName: FeedName, EntriesTotal: 0}

	if got := syncer.resolveDeltaEntriesTotal(context.Background(), store, status, 0); got != 41028 {
		t.Fatalf("resolveDeltaEntriesTotal(zero baseline) = %d, want store count 41028", got)
	}
	if len(store.countedSources) != 1 || store.countedSources[0] != FeedName {
		t.Fatalf("counted sources = %v, want single %q count", store.countedSources, FeedName)
	}

	store.countErr = errors.New("count failed")
	if got := syncer.resolveDeltaEntriesTotal(context.Background(), store, status, 3); got != 3 {
		t.Fatalf("resolveDeltaEntriesTotal(count error) = %d, want processed fallback 3", got)
	}
}

func TestResolveDeltaEntriesTotalFallsBackToProcessedCount(t *testing.T) {
	t.Parallel()

	store := &ghsaStoreStub{}
	syncer := NewSyncer(nil, "")

	if got := syncer.resolveDeltaEntriesTotal(context.Background(), store, nil, 5); got != 5 {
		t.Fatalf("resolveDeltaEntriesTotal(no status, non-counting store) = %d, want processed 5", got)
	}
}

func TestSyncDeltaWithNoChangesPreservesPreviousEntriesTotal(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dataDir := t.TempDir()
	repoDir := filepath.Join(dataDir, "advisory-database")
	initGHSAGitRepo(t, repoDir)
	advisoryPath := filepath.Join(repoDir, reviewedDir, "2026", "05", "GHSA-sync.json")
	if err := os.MkdirAll(filepath.Dir(advisoryPath), 0o750); err != nil {
		t.Fatalf("mkdir advisory dir: %v", err)
	}
	if err := os.WriteFile(advisoryPath, []byte(`{"id":"GHSA-sync-1234-5678","database_specific":{"severity":"LOW"}}`), 0o600); err != nil {
		t.Fatalf("write advisory: %v", err)
	}
	commitGHSAGitRepo(t, repoDir)
	commitHash := headGHSAGit(t, repoDir)

	// A failed previous attempt leaves an error status whose preserved
	// EntriesTotal must survive the follow-up delta sync that finds no
	// changed files (the retry-after-timeout production scenario).
	store := &ghsaStoreStub{status: &db.FeedSyncStatus{
		FeedName:       FeedName,
		LastSyncStatus: db.FeedSyncStatusError,
		EntriesTotal:   7,
		LastCommitHash: commitHash,
	}}
	syncer := NewSyncer(nil, dataDir)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 0 || result.EntriesTotal != 7 {
		t.Fatalf("Sync() result = %+v, want 0 synced with preserved total 7", result)
	}
	if store.status.EntriesTotal != 7 || store.status.LastSyncStatus != "success" {
		t.Fatalf("recorded status = %+v, want success with preserved total 7", store.status)
	}
}

func TestSyncRepairsUnchangedCommitOnlyWhenRepairMetadataIsStale(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	for _, tt := range []struct {
		name            string
		metadata        json.RawMessage
		wantRepairCalls int
	}{
		{
			name:            "current metadata skips repair",
			metadata:        ghsaCurrentSyncMetadataJSON(t),
			wantRepairCalls: 0,
		},
		{
			name:            "missing metadata runs repair",
			wantRepairCalls: 1,
		},
		{
			name:            "old metadata runs repair",
			metadata:        json.RawMessage(`{"importer_version":1,"affected_package_repair_version":0}`),
			wantRepairCalls: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dataDir := t.TempDir()
			repoDir := filepath.Join(dataDir, "advisory-database")
			initGHSAGitRepo(t, repoDir)
			advisoryPath := filepath.Join(repoDir, reviewedDir, "2026", "05", "GHSA-sync.json")
			if err := os.MkdirAll(filepath.Dir(advisoryPath), 0o750); err != nil {
				t.Fatalf("mkdir advisory dir: %v", err)
			}
			if err := os.WriteFile(advisoryPath, []byte(`{"id":"GHSA-sync-1234-5678","database_specific":{"severity":"LOW"}}`), 0o600); err != nil {
				t.Fatalf("write advisory: %v", err)
			}
			commitGHSAGitRepo(t, repoDir)
			commitHash := headGHSAGit(t, repoDir)

			store := &ghsaRepairingStoreStub{repaired: 2}
			store.status = &db.FeedSyncStatus{
				FeedName:       FeedName,
				LastSyncStatus: db.FeedSyncStatusSuccess,
				EntriesTotal:   7,
				LastCommitHash: commitHash,
				Metadata:       tt.metadata,
			}
			syncer := NewSyncer(nil, dataDir)

			result, err := syncer.Sync(context.Background(), store)
			if err != nil {
				t.Fatalf("Sync() error = %v", err)
			}
			if result.EntriesSynced != 0 || result.EntriesTotal != 7 {
				t.Fatalf("Sync() result = %+v, want unchanged result with preserved total", result)
			}
			if store.repairCalls != tt.wantRepairCalls {
				t.Fatalf("repair calls = %d, want %d", store.repairCalls, tt.wantRepairCalls)
			}
			if !ghsaMetadataIsCurrentForTest(store.status.Metadata) {
				t.Fatalf("stored metadata = %s, want current GHSA importer/repair versions", store.status.Metadata)
			}
		})
	}
}

func TestMapSeverityFallbacks(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]string{
		"critical": "CRITICAL",
		"HIGH":     "HIGH",
		"low":      "LOW",
	} {
		if got := mapSeverity(&ghsaAdvisory{DatabaseSpecific: &ghsaDatabaseSpecific{Severity: raw}}); got != want {
			t.Fatalf("mapSeverity(%q) = %q, want %q", raw, got, want)
		}
	}
	if got := mapSeverity(&ghsaAdvisory{DatabaseSpecific: &ghsaDatabaseSpecific{Severity: "moderate"}}); got != "MEDIUM" {
		t.Fatalf("mapSeverity(moderate) = %q", got)
	}
	if got := mapSeverity(&ghsaAdvisory{Severity: []ghsaSeverity{{Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}); got != "CRITICAL" {
		t.Fatalf("mapSeverity(cvss) = %q", got)
	}
	if got := mapSeverity(&ghsaAdvisory{}); got != "UNKNOWN" {
		t.Fatalf("mapSeverity(empty) = %q", got)
	}
}

type ghsaCountingStoreStub struct {
	ghsaStoreStub
	count          int
	countErr       error
	countedSources []string
}

func (s *ghsaCountingStoreStub) CountVulnerabilitiesBySource(_ context.Context, source string) (int, error) {
	s.countedSources = append(s.countedSources, source)
	if s.countErr != nil {
		return 0, s.countErr
	}
	return s.count, nil
}

type ghsaRepairStoreStub struct {
	db.Store
	repaired int
	err      error
}

func (s *ghsaRepairStoreStub) RepairGHSAAffectedPackages(context.Context) (int, error) {
	return s.repaired, s.err
}

type ghsaRepairingStoreStub struct {
	ghsaStoreStub
	repaired    int
	repairErr   error
	repairCalls int
}

func (s *ghsaRepairingStoreStub) RepairGHSAAffectedPackages(context.Context) (int, error) {
	s.repairCalls++
	return s.repaired, s.repairErr
}

func ghsaCurrentSyncMetadataJSON(t *testing.T) json.RawMessage {
	t.Helper()
	return json.RawMessage(`{"importer_version":1,"affected_package_repair_version":1}`)
}

func ghsaMetadataIsCurrentForTest(raw json.RawMessage) bool {
	var metadata struct {
		ImporterVersion              int `json:"importer_version"`
		AffectedPackageRepairVersion int `json:"affected_package_repair_version"`
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return false
	}
	return metadata.ImporterVersion == 1 && metadata.AffectedPackageRepairVersion == 1
}

func initGHSAGitRepo(t *testing.T, repoDir string) {
	t.Helper()
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	runGHSAGit(t, repoDir, "init", "-b", "main")
	runGHSAGit(t, repoDir, "config", "user.email", "packmon-test@example.test")
	runGHSAGit(t, repoDir, "config", "user.name", "Packmon Test")
	runGHSAGit(t, repoDir, "remote", "add", "origin", repoDir)
}

func commitGHSAGitRepo(t *testing.T, repoDir string) {
	t.Helper()
	runGHSAGit(t, repoDir, "add", ".")
	runGHSAGit(t, repoDir, "commit", "-m", "test data")
	runGHSAGit(t, repoDir, "update-ref", "refs/remotes/origin/HEAD", "HEAD")
}

func headGHSAGit(t *testing.T, repoDir string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-parse HEAD: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func runGHSAGit(t *testing.T, repoDir string, args ...string) {
	t.Helper()
	// #nosec G204 -- test helper executes git with fixed test-provided args.
	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}
