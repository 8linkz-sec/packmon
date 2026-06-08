package ghsa

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

type ghsaStoreStub struct {
	db.Store
	upserts         int
	statuses        []*db.FeedSyncStatus
	status          *db.FeedSyncStatus
	vulns           []*db.Vulnerability
	deleted         []string
	upsertErr       error
	deleteErr       error
	statusUpsertErr error
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

func (s *ghsaStoreStub) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
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

	vuln := mapToVulnerability(advisory, []byte(`{}`))
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

	vuln := mapToVulnerability(&advisory, raw)
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

	syncer := NewSyncer(&ghsaStoreStub{}, nil, "")
	if syncer.Name() != FeedName {
		t.Fatalf("Name() = %q, want %q", syncer.Name(), FeedName)
	}
	if syncer.dataDir == "" {
		t.Fatal("dataDir is empty, want default temp dir")
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

	vuln := mapToVulnerability(advisory, []byte(`{"id":"GHSA-map-1234-5678"}`))
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

		badWithdrawn := "not a timestamp"
		vuln = mapToVulnerability(&ghsaAdvisory{ID: "GHSA-bad-withdrawn", Withdrawn: &badWithdrawn}, nil)
		if vuln.Withdrawn != nil {
			t.Fatalf("invalid withdrawn parsed as %v, want nil", vuln.Withdrawn)
		}
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
	syncer := NewSyncer(store, nil, "")
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
	syncer := NewSyncer(store, nil, "")
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
}

func TestProcessChangedFilesDeletesRemovedReviewedJSON(t *testing.T) {
	t.Parallel()

	repoDir := t.TempDir()
	store := &ghsaStoreStub{}
	syncer := NewSyncer(store, nil, "")
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

	store = &ghsaStoreStub{deleteErr: errors.New("delete failed")}
	_, _, err = syncer.processChangedFiles(context.Background(), store, repoDir, []string{
		reviewedDir + "/2026/05/GHSA-delete-failed.json",
	})
	if err == nil || !errors.Is(err, store.deleteErr) {
		t.Fatalf("processChangedFiles(delete error) = %v", err)
	}
}

func TestWalkAdvisoriesContinuesPastInvalidFiles(t *testing.T) {
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
	syncer := NewSyncer(store, nil, "")
	synced, total, err := syncer.walkAdvisories(context.Background(), store, root)
	if err != nil {
		t.Fatalf("walkAdvisories: %v", err)
	}
	if synced != 1 || total != 3 || store.upserts != 1 {
		t.Fatalf("synced=%d total=%d upserts=%d", synced, total, store.upserts)
	}

	store = &ghsaStoreStub{upsertErr: errors.New("db down")}
	synced, total, err = syncer.walkAdvisories(context.Background(), store, root)
	if err != nil {
		t.Fatalf("walkAdvisories(upsert error): %v", err)
	}
	if synced != 0 || total != 3 || store.upserts != 0 {
		t.Fatalf("upsert error synced=%d total=%d upserts=%d, want 0/3/0", synced, total, store.upserts)
	}
}

func TestGHSASyncStatusAndRepairHelpers(t *testing.T) {
	t.Parallel()

	store := &ghsaStoreStub{}
	syncer := NewSyncer(store, nil, "")
	syncer.recordSyncSuccessWithCommit(context.Background(), time.Now(), time.Second, 10, 8, "abc123")
	syncer.recordSyncFailure(context.Background(), time.Now(), context.Canceled)

	if len(store.statuses) != 2 {
		t.Fatalf("statuses length = %d, want 2", len(store.statuses))
	}
	if store.statuses[0].LastSyncStatus != "success" || store.statuses[0].LastCommitHash != "abc123" {
		t.Fatalf("success status = %+v", store.statuses[0])
	}
	if store.statuses[1].LastSyncStatus != "error" || store.statuses[1].LastError == "" {
		t.Fatalf("failure status = %+v", store.statuses[1])
	}

	repairStore := &ghsaRepairStoreStub{repaired: 3}
	if got := syncer.repairAffectedPackages(context.Background(), repairStore); got != 3 {
		t.Fatalf("repairAffectedPackages() = %d, want 3", got)
	}
	repairStore.err = errors.New("repair failed")
	if got := syncer.repairAffectedPackages(context.Background(), repairStore); got != 0 {
		t.Fatalf("repairAffectedPackages(error) = %d, want 0", got)
	}
	if got := syncer.repairAffectedPackages(context.Background(), store); got != 0 {
		t.Fatalf("repairAffectedPackages(non-repairer) = %d, want 0", got)
	}

	store.statusUpsertErr = errors.New("status db down")
	syncer.recordSyncSuccessWithCommit(context.Background(), time.Now(), time.Second, 1, 1, "def456")
	syncer.recordSyncFailure(context.Background(), time.Now(), context.Canceled)
}

func TestSyncUsesExistingGitCheckoutAndRecordsUnchangedStatus(t *testing.T) {
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

	store := &ghsaStoreStub{}
	syncer := NewSyncer(store, nil, dataDir)
	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 0 || result.EntriesTotal != 0 {
		t.Fatalf("Sync() result = %+v, want unchanged delta with no processed files", result)
	}
	if len(store.statuses) == 0 || store.status.LastSyncStatus != "success" || store.status.LastCommitHash == "" {
		t.Fatalf("statuses = %+v, want success with commit", store.statuses)
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

type ghsaRepairStoreStub struct {
	db.Store
	repaired int
	err      error
}

func (s *ghsaRepairStoreStub) RepairGHSAAffectedPackages(context.Context) (int, error) {
	return s.repaired, s.err
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
