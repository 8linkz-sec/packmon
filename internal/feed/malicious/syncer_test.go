package malicious

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

type maliciousTestStore struct {
	db.Store
	findings          []db.MaliciousFinding
	deletedIDs        []string
	deletedSources    []string
	statuses          []db.FeedSyncStatus
	status            *db.FeedSyncStatus
	upsertErr         error
	statusErr         error
	getStatusErr      error
	prunedSource      string
	prunedIDs         []string
	pruneErr          error
	stalePrunedSource string
	stalePrunedBefore time.Time
	stalePruneErr     error
	maxNotInPruneIDs  int
	rejectCanceled    bool
}

func (s *maliciousTestStore) UpsertMaliciousFinding(_ context.Context, finding *db.MaliciousFinding) error {
	if s.upsertErr != nil {
		return s.upsertErr
	}
	s.findings = append(s.findings, *finding)
	return nil
}

func (s *maliciousTestStore) DeleteMaliciousFinding(_ context.Context, id string) error {
	s.deletedIDs = append(s.deletedIDs, id)
	return nil
}

func (s *maliciousTestStore) DeleteMaliciousFindingForSource(_ context.Context, id, source string) error {
	s.deletedIDs = append(s.deletedIDs, id)
	s.deletedSources = append(s.deletedSources, source)
	return nil
}

func (s *maliciousTestStore) UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error {
	if s.rejectCanceled && ctx.Err() != nil {
		return ctx.Err()
	}
	if s.statusErr != nil {
		return s.statusErr
	}
	s.statuses = append(s.statuses, *status)
	copyValue := *status
	s.status = &copyValue
	return nil
}

func (s *maliciousTestStore) GetFeedSyncStatus(context.Context, string) (*db.FeedSyncStatus, error) {
	if s.getStatusErr != nil {
		return nil, s.getStatusErr
	}
	if s.status == nil {
		return nil, nil
	}
	copyValue := *s.status
	return &copyValue, nil
}

func (s *maliciousTestStore) DeleteMaliciousFindingsNotInSource(_ context.Context, source string, ids []string) (int, error) {
	if s.pruneErr != nil {
		return 0, s.pruneErr
	}
	if s.maxNotInPruneIDs > 0 && len(ids) > s.maxNotInPruneIDs {
		return 0, errors.New("legacy malicious prune received an unbounded active ID list")
	}
	s.prunedSource = source
	s.prunedIDs = append([]string(nil), ids...)
	return 0, nil
}

func (s *maliciousTestStore) PruneMaliciousFindingsForSourceUpdatedBefore(_ context.Context, source string, updatedBefore time.Time) (int, error) {
	if s.stalePruneErr != nil {
		return 0, s.stalePruneErr
	}
	s.stalePrunedSource = source
	s.stalePrunedBefore = updatedBefore
	return 0, nil
}

func TestSyncerNameDefaultsAndStatusRecording(t *testing.T) {
	t.Parallel()

	store := &maliciousTestStore{}
	syncer := NewSyncer(nil, "")
	if syncer.Name() != FeedName {
		t.Fatalf("Name() = %q, want %q", syncer.Name(), FeedName)
	}
	if syncer.dataDir == "" {
		t.Fatal("dataDir should default when empty")
	}

	start := time.Now().Add(-time.Second)
	syncer.recordSyncSuccessWithCommit(context.Background(), store, 250*time.Millisecond, 10, 7, "abc123")
	syncer.recordSyncFailure(context.Background(), store, start, context.Canceled)

	if len(store.statuses) != 2 {
		t.Fatalf("statuses = %d, want 2", len(store.statuses))
	}
	if got := store.statuses[0]; got.LastSyncStatus != "success" || got.EntriesTotal != 10 || got.EntriesSynced != 7 || got.LastCommitHash != "abc123" {
		t.Fatalf("success status = %+v", got)
	}
	if got := store.statuses[1]; got.LastSyncStatus != "error" || got.LastError == "" {
		t.Fatalf("failure status = %+v", got)
	}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	store.rejectCanceled = true
	syncer.recordSyncFailure(canceledCtx, store, start, context.Canceled)
	if len(store.statuses) != 3 {
		t.Fatalf("statuses after canceled context = %d, want 3", len(store.statuses))
	}

	erroringStore := &maliciousTestStore{statusErr: errors.New("status write failed")}
	erroringSyncer := NewSyncer(nil, t.TempDir())
	erroringSyncer.recordSyncSuccessWithCommit(context.Background(), erroringStore, time.Millisecond, 1, 1, "def456")
	erroringSyncer.recordSyncFailure(context.Background(), erroringStore, start, context.Canceled)
	if len(erroringStore.statuses) != 0 {
		t.Fatalf("erroring store recorded statuses = %+v, want none", erroringStore.statuses)
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

func TestRecordSyncFailurePreservesLastUsableSync(t *testing.T) {
	t.Parallel()

	lastSync := time.Date(2026, 5, 1, 12, 30, 0, 0, time.UTC)
	metadata := importerMetadata()
	store := &maliciousTestStore{status: &db.FeedSyncStatus{
		FeedName:       FeedName,
		LastSyncStatus: db.FeedSyncStatusSuccess,
		LastSyncAt:     &lastSync,
		EntriesSynced:  11,
		EntriesTotal:   13,
		LastCommitHash: "def456",
		Metadata:       metadata,
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
	if store.status.EntriesSynced != 11 || store.status.EntriesTotal != 13 {
		t.Fatalf("entries = %d/%d, want preserved 11/13", store.status.EntriesSynced, store.status.EntriesTotal)
	}
	if store.status.LastCommitHash != "def456" {
		t.Fatalf("LastCommitHash = %q, want preserved def456", store.status.LastCommitHash)
	}
	if string(store.status.Metadata) != string(metadata) {
		t.Fatalf("Metadata = %s, want preserved %s", store.status.Metadata, metadata)
	}
}

func TestMapToMaliciousFindingsMapsEverySupportedAffectedPackage(t *testing.T) {
	t.Parallel()

	published := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	entry := &malEntry{
		ID:        "MAL-2026-0001",
		Summary:   "Typosquat package exfiltrates credentials",
		Details:   "Backdoor installed through dependency confusion",
		Published: published,
		References: []malReference{
			{URL: "https://example.test/malware"},
			{URL: ""},
		},
		Affected: []malAffected{
			{
				Package:  malPackage{Ecosystem: "npm", Name: "leftpad"},
				Versions: []string{"1.0.0"},
				Ranges: []malRange{{Type: "SEMVER", Events: []malEvent{
					{Introduced: "0"},
					{Fixed: "1.2.0"},
				}}},
			},
			{
				Package: malPackage{Ecosystem: "PyPI", Name: "requests2"},
			},
		},
	}

	findings := mapToMaliciousFindings(entry, "malicious/npm/leftpad/MAL-2026-0001.json")

	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	first := findings[0]
	if first.ID != "MAL-2026-0001" || first.Ecosystem != "npm" || first.Name != "leftpad" {
		t.Fatalf("first finding identity = %+v", first)
	}
	if first.Severity != "CRITICAL" || first.RiskType != "typosquatting" || first.Source != "openssf" {
		t.Fatalf("first finding classification = %+v", first)
	}
	if first.Published == nil || !first.Published.Equal(published) {
		t.Fatalf("Published = %v, want %v", first.Published, published)
	}
	var versions []string
	if err := json.Unmarshal(first.Versions, &versions); err != nil {
		t.Fatalf("versions JSON: %v", err)
	}
	if got, want := versions, []string{"1.0.0"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("versions = %#v, want explicit versions only %#v", got, want)
	}
	var ranges []malRange
	if err := json.Unmarshal(first.VersionRanges, &ranges); err != nil {
		t.Fatalf("version ranges JSON: %v", err)
	}
	if len(ranges) != 1 || ranges[0].Type != "SEMVER" || len(ranges[0].Events) != 2 ||
		ranges[0].Events[0].Introduced != "0" || ranges[0].Events[1].Fixed != "1.2.0" {
		t.Fatalf("version ranges = %#v, want introduced/fixed OSV range preserved", ranges)
	}
	var refs []string
	if err := json.Unmarshal(first.ReferenceURLs, &refs); err != nil {
		t.Fatalf("reference URLs JSON: %v", err)
	}
	if len(refs) != 1 || refs[0] != "https://example.test/malware" {
		t.Fatalf("reference URLs = %#v", refs)
	}

	second := findings[1]
	if second.ID != "MAL-2026-0001-1" || second.Ecosystem != "pypi" || second.Name != "requests2" {
		t.Fatalf("second finding identity = %+v", second)
	}
}

func TestMapToMaliciousFindingsSkipsUnsupportedEcosystemsAndDerivesID(t *testing.T) {
	t.Parallel()

	entry := &malEntry{
		Summary: "cryptominer package",
		Affected: []malAffected{
			{Package: malPackage{Ecosystem: "unknown", Name: "ignored"}},
			{Package: malPackage{Ecosystem: "pypi", Name: "evil-pkg"}},
		},
	}

	findings := mapToMaliciousFindings(entry, filepath.Join("osv", "pypi", "evil-pkg", "MAL-2.json"))

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if got := findings[0].ID; got != "openssf-evil-pkg-MAL-2-1" {
		t.Fatalf("derived ID = %q", got)
	}
	if findings[0].RiskType != "malware" {
		t.Fatalf("risk type = %q, want malware", findings[0].RiskType)
	}
}

func TestClassifyRiskTypeHeuristics(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"typosquat steals tokens":         "typosquatting",
		"supply-chain takeover":           "supply_chain",
		"dependency confusion attack":     "supply_chain",
		"trojan downloader":               "malware",
		"cryptominer in install script":   "malware",
		"credential exfiltration payload": "malware",
		"unknown bad behavior":            "malware",
	}
	for summary, want := range tests {
		if got := classifyRiskType(&malEntry{Summary: summary}); got != want {
			t.Fatalf("classifyRiskType(%q) = %q, want %q", summary, got, want)
		}
	}
	if got := classifyRiskType(&malEntry{Summary: "generic bad behavior", DatabaseSpecific: json.RawMessage(`{"risk_type":"typosquatting"}`)}); got != "typosquatting" {
		t.Fatalf("classifyRiskType(database_specific) = %q, want typosquatting", got)
	}

	affSpecific := mapToMaliciousFindings(&malEntry{
		Summary: "generic bad behavior",
		Affected: []malAffected{{
			Package:          malPackage{Ecosystem: "npm", Name: "leftpad"},
			DatabaseSpecific: json.RawMessage(`{"categories":["dependency_confusion"]}`),
		}},
	}, "MAL-aff-risk.json")
	if len(affSpecific) != 1 || affSpecific[0].RiskType != "supply_chain" {
		t.Fatalf("affected risk type findings = %+v, want supply_chain", affSpecific)
	}

	if got := mapToMaliciousFindings(&malEntry{}, "MAL-empty.json"); got != nil {
		t.Fatalf("mapToMaliciousFindings(no affected) = %#v, want nil", got)
	}
	if got := deriveIDFromPath("MAL-single.json"); got != "openssf-MAL-single" {
		t.Fatalf("deriveIDFromPath(single) = %q", got)
	}
}

func TestProcessMaliciousEntryUpsertsActiveEntryAndTracksSeenID(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	relativePath := filepath.Join("npm", "leftpad", "MAL-helper.json")
	writeFile(t, filepath.Join(root, relativePath), `{
		"id":"MAL-helper",
		"summary":"backdoor package",
		"affected":[{"package":{"ecosystem":"npm","name":"leftpad"}}]
	}`)

	rootDir, err := os.OpenRoot(root)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() {
		_ = rootDir.Close()
	}()

	store := &maliciousTestStore{}
	syncer := NewSyncer(nil, t.TempDir())
	seen := map[string]struct{}{}
	synced, active, err := syncer.processMaliciousEntry(context.Background(), store, rootDir, relativePath, seen)
	if err != nil {
		t.Fatalf("processMaliciousEntry() error = %v", err)
	}

	if synced != 1 {
		t.Fatalf("synced = %d, want 1", synced)
	}
	if active != 1 {
		t.Fatalf("active = %d, want 1", active)
	}
	if len(store.findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(store.findings))
	}
	if got := store.findings[0]; got.ID != "MAL-helper" || got.Ecosystem != "npm" || got.Name != "leftpad" {
		t.Fatalf("stored finding = %+v", got)
	}
	if _, ok := seen["MAL-helper"]; !ok {
		t.Fatalf("seen IDs = %#v, missing MAL-helper", seen)
	}
}

func TestProcessMaliciousEntryTombstonesWithdrawnEntryAndRemovesSeenID(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	relativePath := filepath.Join("withdrawn", "pypi", "fastapi", "MAL-helper-withdrawn.json")
	writeFile(t, filepath.Join(root, relativePath), `{
		"id":"MAL-helper-withdrawn",
		"summary":"Malicious code in fastapi (PyPI)",
		"withdrawn":"2026-05-26T13:04:03Z",
		"affected":[{"package":{"ecosystem":"PyPI","name":"fastapi"},"versions":["0.136.3"]}]
	}`)

	rootDir, err := os.OpenRoot(root)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() {
		_ = rootDir.Close()
	}()

	store := &maliciousTestStore{}
	syncer := NewSyncer(nil, t.TempDir())
	seen := map[string]struct{}{"MAL-helper-withdrawn": {}}
	synced, active, err := syncer.processMaliciousEntry(context.Background(), store, rootDir, relativePath, seen)
	if err != nil {
		t.Fatalf("processMaliciousEntry() error = %v", err)
	}

	if synced != 1 {
		t.Fatalf("synced = %d, want 1", synced)
	}
	if active != 0 {
		t.Fatalf("active = %d, want 0", active)
	}
	if len(store.findings) != 0 {
		t.Fatalf("findings = %+v, want none", store.findings)
	}
	if len(store.deletedIDs) != 1 || store.deletedIDs[0] != "MAL-helper-withdrawn" {
		t.Fatalf("deleted IDs = %+v, want [MAL-helper-withdrawn]", store.deletedIDs)
	}
	if len(store.deletedSources) != 1 || store.deletedSources[0] != FeedName {
		t.Fatalf("deleted sources = %+v, want [%s]", store.deletedSources, FeedName)
	}
	if _, ok := seen["MAL-helper-withdrawn"]; ok {
		t.Fatalf("withdrawn ID should be removed from seen IDs: %#v", seen)
	}
}

func TestWalkEntriesTombstonesWithdrawnReports(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "withdrawn", "pypi", "fastapi", "MAL-2026-4750.json"), `{
		"id":"MAL-2026-4750",
		"summary":"Malicious code in fastapi (PyPI)",
		"withdrawn":"2026-05-26T13:04:03Z",
		"affected":[{"package":{"ecosystem":"PyPI","name":"fastapi"},"versions":["0.136.3"]}]
	}`)

	store := &maliciousTestStore{}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(os.Stdout, nil)), t.TempDir())
	seen := map[string]struct{}{}
	synced, total, active, err := syncer.walkEntries(context.Background(), store, root, seen)
	if err != nil {
		t.Fatalf("walkEntries() error = %v", err)
	}

	if total != 1 || synced != 1 || active != 0 {
		t.Fatalf("walkEntries() = synced %d total %d active %d, want 1/1/0", synced, total, active)
	}
	if len(store.findings) != 0 {
		t.Fatalf("withdrawn report was upserted as active finding: %+v", store.findings)
	}
	if len(store.deletedIDs) != 1 || store.deletedIDs[0] != "MAL-2026-4750" {
		t.Fatalf("deleted IDs = %+v, want [MAL-2026-4750]", store.deletedIDs)
	}
	if len(store.deletedSources) != 1 || store.deletedSources[0] != FeedName {
		t.Fatalf("deleted sources = %+v, want [%s]", store.deletedSources, FeedName)
	}
	if _, ok := seen["MAL-2026-4750"]; ok {
		t.Fatalf("withdrawn ID should not be included in active seen IDs: %#v", seen)
	}
}

func TestWalkEntriesSkipsUnsupportedFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "npm", "leftpad", "MAL-1.json"), `{
		"id":"MAL-1",
		"summary":"backdoor package",
		"affected":[{"package":{"ecosystem":"npm","name":"leftpad"}}]
	}`)
	writeFile(t, filepath.Join(root, "unsupported", "pkg", "MAL-2.json"), `{
		"id":"MAL-2",
		"summary":"ignored",
		"affected":[{"package":{"ecosystem":"unknown","name":"pkg"}}]
	}`)
	writeFile(t, filepath.Join(root, "npm", "ignored", "README.txt"), `not json`)

	store := &maliciousTestStore{}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(os.Stdout, nil)), t.TempDir())
	seen := map[string]struct{}{}
	synced, total, active, err := syncer.walkEntries(context.Background(), store, root, seen)
	if err != nil {
		t.Fatalf("walkEntries() error = %v", err)
	}

	if total != 2 {
		t.Fatalf("total JSON entries = %d, want 2", total)
	}
	if synced != 1 {
		t.Fatalf("synced = %d, want 1", synced)
	}
	if active != 1 {
		t.Fatalf("active = %d, want 1", active)
	}
	if _, ok := seen["MAL-1"]; !ok {
		t.Fatalf("seen IDs = %#v, missing MAL-1", seen)
	}
	if len(store.findings) != 1 {
		t.Fatalf("upserted findings = %d, want 1", len(store.findings))
	}
	if got := store.findings[0]; got.ID != "MAL-1" || got.Ecosystem != "npm" || got.Name != "leftpad" {
		t.Fatalf("stored finding = %+v", got)
	}
}

func TestWalkEntriesErrorBranches(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(nil, t.TempDir())
	if _, _, _, err := syncer.walkEntries(context.Background(), &maliciousTestStore{}, filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("walkEntries(missing root) error = nil, want error")
	}

	canceledRoot := t.TempDir()
	writeFile(t, filepath.Join(canceledRoot, "npm", "leftpad", "MAL-canceled.json"), `{
		"id":"MAL-canceled",
		"summary":"backdoor package",
		"affected":[{"package":{"ecosystem":"npm","name":"leftpad"}}]
	}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err := syncer.walkEntries(ctx, &maliciousTestStore{}, canceledRoot, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("walkEntries(canceled) error = %v, want context.Canceled", err)
	}

	parseRoot := t.TempDir()
	writeFile(t, filepath.Join(parseRoot, "npm", "broken", "MAL-broken.json"), `{`)
	_, _, _, err = syncer.walkEntries(context.Background(), &maliciousTestStore{}, parseRoot, nil)
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("walkEntries(parse error) error = %v", err)
	}

	upsertRoot := t.TempDir()
	writeFile(t, filepath.Join(upsertRoot, "npm", "leftpad", "MAL-upsert.json"), `{
		"id":"MAL-upsert",
		"summary":"backdoor package",
		"affected":[{"package":{"ecosystem":"npm","name":"leftpad"}}]
	}`)
	erroringStore := &maliciousTestStore{upsertErr: errors.New("upsert failed")}
	synced, total, active, err := syncer.walkEntries(context.Background(), erroringStore, upsertRoot, nil)
	if err == nil || !strings.Contains(err.Error(), "upsert") {
		t.Fatalf("walkEntries(upsert error) error = %v", err)
	}
	if synced != 0 || total != 1 || active != 0 {
		t.Fatalf("walkEntries(upsert error) = synced %d total %d active %d, want 0/1/0", synced, total, active)
	}
	if len(erroringStore.findings) != 0 {
		t.Fatalf("erroring store findings = %+v, want none", erroringStore.findings)
	}
}

func TestWalkEntriesRejectsOversizedEntryJSON(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	entryPath := filepath.Join(root, "npm", "leftpad", "MAL-huge.json")
	writeFile(t, entryPath, `{"id":"MAL-huge"}`)
	if err := os.Truncate(entryPath, feed.MaxGitAdvisoryJSONSize+1); err != nil {
		t.Fatalf("truncate entry: %v", err)
	}

	store := &maliciousTestStore{}
	syncer := NewSyncer(nil, "")
	synced, total, active, err := syncer.walkEntries(context.Background(), store, root, map[string]struct{}{})
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum advisory JSON size") {
		t.Fatalf("walkEntries() error = %v, want size-limit error", err)
	}
	if synced != 0 || total != 1 || active != 0 {
		t.Fatalf("synced=%d total=%d active=%d, want 0/1/0", synced, total, active)
	}
	if len(store.findings) != 0 || len(store.deletedIDs) != 0 {
		t.Fatalf("findings=%+v deleted=%+v, want no writes", store.findings, store.deletedIDs)
	}
}

func TestSyncUsesExistingGitCheckoutAndWalksEntries(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dataDir := t.TempDir()
	repoDir := filepath.Join(dataDir, "malicious-packages")
	initGitRepo(t, repoDir)
	writeFile(t, filepath.Join(repoDir, maliciousDir, "npm", "leftpad", "MAL-sync.json"), `{
		"id":"MAL-sync",
		"summary":"supply chain malware",
		"affected":[{"package":{"ecosystem":"npm","name":"leftpad"}}]
	}`)
	gitCommitAll(t, repoDir)

	store := &maliciousTestStore{}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(os.Stdout, nil)), dataDir)
	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 1 || result.EntriesTotal != 1 {
		t.Fatalf("Sync() result = %+v, want 1/1", result)
	}
	if len(store.findings) != 1 || store.findings[0].ID != "MAL-sync" {
		t.Fatalf("findings = %+v, want MAL-sync", store.findings)
	}
	if store.prunedSource != "" || len(store.prunedIDs) != 0 {
		t.Fatalf("legacy prune source/ids = %q/%v, want no full active ID prune", store.prunedSource, store.prunedIDs)
	}
	if store.stalePrunedSource != FeedName || store.stalePrunedBefore.IsZero() {
		t.Fatalf("stale prune source/cutoff = %q/%v, want %q with cutoff", store.stalePrunedSource, store.stalePrunedBefore, FeedName)
	}
	if len(store.statuses) == 0 || store.statuses[len(store.statuses)-1].LastSyncStatus != "success" {
		t.Fatalf("statuses = %+v, want success", store.statuses)
	}

	sameCommit := store.status.LastCommitHash
	store.findings = nil
	result, err = syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync(unchanged) error = %v", err)
	}
	if result.EntriesSynced != 0 || result.EntriesTotal != 1 || store.status.LastCommitHash != sameCommit {
		t.Fatalf("Sync(unchanged) result/status = %+v/%+v", result, store.status)
	}
	if len(store.findings) != 0 {
		t.Fatalf("unchanged sync upserted findings = %+v", store.findings)
	}
}

func TestSyncPrunesStaleOpenSSFFindingsByCutoffWithoutFullSeenIDList(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dataDir := t.TempDir()
	repoDir := filepath.Join(dataDir, "malicious-packages")
	initGitRepo(t, repoDir)
	for _, id := range []string{"MAL-prune-a", "MAL-prune-b", "MAL-prune-c"} {
		writeFile(t, filepath.Join(repoDir, maliciousDir, "npm", strings.ToLower(id), id+".json"), `{
			"id":"`+id+`",
			"summary":"backdoor package",
			"affected":[{"package":{"ecosystem":"npm","name":"`+strings.ToLower(id)+`"}}]
		}`)
	}
	gitCommitAll(t, repoDir)

	store := &maliciousTestStore{maxNotInPruneIDs: 1}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(os.Stdout, nil)), dataDir)
	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 3 || result.EntriesTotal != 3 {
		t.Fatalf("Sync() result = %+v, want 3/3", result)
	}
	if store.prunedSource != "" || len(store.prunedIDs) != 0 {
		t.Fatalf("legacy prune source/ids = %q/%v, want no full active ID prune", store.prunedSource, store.prunedIDs)
	}
	if store.stalePrunedSource != FeedName || store.stalePrunedBefore.IsZero() {
		t.Fatalf("stale prune source/cutoff = %q/%v, want %q with cutoff", store.stalePrunedSource, store.stalePrunedBefore, FeedName)
	}
	if len(store.findings) != 3 {
		t.Fatalf("upserted findings = %d, want 3", len(store.findings))
	}
}

func TestSyncFailsClosedWhenFeedRootsAreMissing(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dataDir := t.TempDir()
	repoDir := filepath.Join(dataDir, "malicious-packages")
	initGitRepo(t, repoDir)
	writeFile(t, filepath.Join(repoDir, "README.md"), "not the OpenSSF feed layout")
	gitCommitAll(t, repoDir)

	store := &maliciousTestStore{}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(os.Stdout, nil)), dataDir)
	result, err := syncer.Sync(context.Background(), store)
	if err == nil || !strings.Contains(err.Error(), "feed roots") {
		t.Fatalf("Sync() error = %v, want feed root error", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil on failed feed validation", result)
	}
	if store.prunedSource != "" || len(store.prunedIDs) != 0 || store.stalePrunedSource != "" {
		t.Fatalf("prune calls = legacy %q/%v stale %q, want no prune on invalid feed", store.prunedSource, store.prunedIDs, store.stalePrunedSource)
	}
	if len(store.statuses) == 0 || store.statuses[len(store.statuses)-1].LastSyncStatus != "error" {
		t.Fatalf("statuses = %+v, want error status", store.statuses)
	}
}

func TestSyncFailureEmitsStartAndTerminalFailureLog(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dataDir := t.TempDir()
	repoDir := filepath.Join(dataDir, "malicious-packages")
	initGitRepo(t, repoDir)
	writeFile(t, filepath.Join(repoDir, "README.md"), "not the OpenSSF feed layout")
	gitCommitAll(t, repoDir)

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := &maliciousTestStore{}
	syncer := NewSyncer(logger, dataDir)
	result, err := syncer.Sync(context.Background(), store)
	if err == nil || !strings.Contains(err.Error(), "feed roots") {
		t.Fatalf("Sync() error = %v, want feed root error", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil on failed sync", result)
	}

	output := logs.String()
	startIndex := strings.Index(output, "starting OpenSSF malicious packages sync")
	if startIndex < 0 {
		t.Fatalf("logs missing start message:\n%s", output)
	}
	failureIndex := strings.Index(output, "OpenSSF malicious packages sync failed")
	if failureIndex < 0 {
		t.Fatalf("logs missing terminal failure message after start:\n%s", output)
	}
	if failureIndex <= startIndex {
		t.Fatalf("terminal failure log appears before start log:\n%s", output)
	}
	if !strings.Contains(output, "status=error") || !strings.Contains(output, "error=") {
		t.Fatalf("terminal failure log missing status/error fields:\n%s", output)
	}
	if strings.Contains(output, repoDir) {
		t.Fatalf("logs include full repository path %q:\n%s", repoDir, output)
	}
}

func TestSyncFailsClosedWhenFeedRootsHaveNoEntries(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dataDir := t.TempDir()
	repoDir := filepath.Join(dataDir, "malicious-packages")
	initGitRepo(t, repoDir)
	writeFile(t, filepath.Join(repoDir, maliciousDir, "npm", "leftpad", "README.txt"), "not json")
	gitCommitAll(t, repoDir)

	store := &maliciousTestStore{}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(os.Stdout, nil)), dataDir)
	result, err := syncer.Sync(context.Background(), store)
	if err == nil || !strings.Contains(err.Error(), "no entries") {
		t.Fatalf("Sync() error = %v, want no entries error", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil on failed feed validation", result)
	}
	if store.prunedSource != "" || len(store.prunedIDs) != 0 || store.stalePrunedSource != "" {
		t.Fatalf("prune calls = legacy %q/%v stale %q, want no prune on empty feed", store.prunedSource, store.prunedIDs, store.stalePrunedSource)
	}
	if len(store.statuses) == 0 || store.statuses[len(store.statuses)-1].LastSyncStatus != "error" {
		t.Fatalf("statuses = %+v, want error status", store.statuses)
	}
}

func TestSyncFailsClosedWhenFeedHasNoSupportedActiveEntries(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dataDir := t.TempDir()
	repoDir := filepath.Join(dataDir, "malicious-packages")
	initGitRepo(t, repoDir)
	writeFile(t, filepath.Join(repoDir, maliciousDir, "unknown", "ignored", "MAL-unsupported.json"), `{
		"id":"MAL-unsupported",
		"summary":"unsupported ecosystem should not prune all OpenSSF findings",
		"affected":[{"package":{"ecosystem":"unsupported","name":"ignored"}}]
	}`)
	gitCommitAll(t, repoDir)

	store := &maliciousTestStore{}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(os.Stdout, nil)), dataDir)
	result, err := syncer.Sync(context.Background(), store)
	if err == nil || !strings.Contains(err.Error(), "no active supported entries") {
		t.Fatalf("Sync() error = %v, want supported-entry validation error", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil on failed feed validation", result)
	}
	if store.prunedSource != "" || len(store.prunedIDs) != 0 || store.stalePrunedSource != "" {
		t.Fatalf("prune calls = legacy %q/%v stale %q, want no prune with no active supported entries", store.prunedSource, store.prunedIDs, store.stalePrunedSource)
	}
	if len(store.statuses) == 0 || store.statuses[len(store.statuses)-1].LastSyncStatus != "error" {
		t.Fatalf("statuses = %+v, want error status", store.statuses)
	}
}

func TestSyncResyncsSameCommitWhenImporterMetadataMissing(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dataDir := t.TempDir()
	repoDir := filepath.Join(dataDir, "malicious-packages")
	initGitRepo(t, repoDir)
	writeFile(t, filepath.Join(repoDir, maliciousDir, "npm", "leftpad", "MAL-sync.json"), `{
		"id":"MAL-sync",
		"summary":"supply chain malware",
		"affected":[{"package":{"ecosystem":"npm","name":"leftpad"}}]
	}`)
	gitCommitAll(t, repoDir)

	store := &maliciousTestStore{status: &db.FeedSyncStatus{
		FeedName:       FeedName,
		LastSyncStatus: "success",
		LastCommitHash: gitRevParse(t, repoDir, "HEAD"),
	}}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(os.Stdout, nil)), dataDir)
	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	if result.EntriesSynced != 1 || result.EntriesTotal != 1 {
		t.Fatalf("Sync() result = %+v, want 1/1", result)
	}
	if len(store.findings) != 1 || store.findings[0].ID != "MAL-sync" {
		t.Fatalf("findings = %+v, want MAL-sync", store.findings)
	}
}

func TestSyncContinuesWhenStatusLookupFails(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dataDir := t.TempDir()
	repoDir := filepath.Join(dataDir, "malicious-packages")
	initGitRepo(t, repoDir)
	writeFile(t, filepath.Join(repoDir, maliciousDir, "npm", "leftpad", "MAL-status.json"), `{
		"id":"MAL-status",
		"summary":"supply chain malware",
		"affected":[{"package":{"ecosystem":"npm","name":"leftpad"}}]
	}`)
	gitCommitAll(t, repoDir)

	store := &maliciousTestStore{getStatusErr: errors.New("status unavailable")}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(os.Stdout, nil)), dataDir)
	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 1 || result.EntriesTotal != 1 {
		t.Fatalf("Sync() result = %+v, want 1/1", result)
	}
	if len(store.findings) != 1 || store.findings[0].ID != "MAL-status" {
		t.Fatalf("findings = %+v, want MAL-status", store.findings)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func initGitRepo(t *testing.T, repoDir string) {
	t.Helper()
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	runGit(t, repoDir, "init", "-b", "main")
	runGit(t, repoDir, "config", "user.email", "packmon-test@example.test")
	runGit(t, repoDir, "config", "user.name", "Packmon Test")
	runGit(t, repoDir, "remote", "add", "origin", repoDir)
}

func gitCommitAll(t *testing.T, repoDir string) {
	t.Helper()
	runGit(t, repoDir, "add", ".")
	runGit(t, repoDir, "commit", "-m", "test data")
	runGit(t, repoDir, "update-ref", "refs/remotes/origin/HEAD", "HEAD")
}

func runGit(t *testing.T, repoDir string, args ...string) {
	t.Helper()
	// #nosec G204 -- test helper executes git with fixed test-provided args.
	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func gitRevParse(t *testing.T, repoDir, rev string) string {
	t.Helper()
	// #nosec G204 -- test helper executes git with fixed test-provided args.
	cmd := exec.Command("git", "rev-parse", rev)
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git rev-parse %s: %v", rev, err)
	}
	return strings.TrimSpace(string(out))
}
