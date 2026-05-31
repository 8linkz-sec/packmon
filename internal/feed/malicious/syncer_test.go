package malicious

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

type maliciousTestStore struct {
	db.Store
	findings     []db.MaliciousFinding
	statuses     []db.FeedSyncStatus
	status       *db.FeedSyncStatus
	upsertErr    error
	statusErr    error
	getStatusErr error
}

func (s *maliciousTestStore) UpsertMaliciousFinding(_ context.Context, finding *db.MaliciousFinding) error {
	if s.upsertErr != nil {
		return s.upsertErr
	}
	s.findings = append(s.findings, *finding)
	return nil
}

func (s *maliciousTestStore) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
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

func TestSyncerNameDefaultsAndStatusRecording(t *testing.T) {
	t.Parallel()

	store := &maliciousTestStore{}
	syncer := NewSyncer(store, nil, "")
	if syncer.Name() != FeedName {
		t.Fatalf("Name() = %q, want %q", syncer.Name(), FeedName)
	}
	if syncer.dataDir == "" {
		t.Fatal("dataDir should default when empty")
	}

	start := time.Now().Add(-time.Second)
	syncer.recordSyncSuccessWithCommit(context.Background(), start, 250*time.Millisecond, 10, 7, "abc123")
	syncer.recordSyncFailure(context.Background(), start, context.Canceled)

	if len(store.statuses) != 2 {
		t.Fatalf("statuses = %d, want 2", len(store.statuses))
	}
	if got := store.statuses[0]; got.LastSyncStatus != "success" || got.EntriesTotal != 10 || got.EntriesSynced != 7 || got.LastCommitHash != "abc123" {
		t.Fatalf("success status = %+v", got)
	}
	if got := store.statuses[1]; got.LastSyncStatus != "error" || got.LastError == "" {
		t.Fatalf("failure status = %+v", got)
	}

	erroringStore := &maliciousTestStore{statusErr: errors.New("status write failed")}
	erroringSyncer := NewSyncer(erroringStore, nil, t.TempDir())
	erroringSyncer.recordSyncSuccessWithCommit(context.Background(), start, time.Millisecond, 1, 1, "def456")
	erroringSyncer.recordSyncFailure(context.Background(), start, context.Canceled)
	if len(erroringStore.statuses) != 0 {
		t.Fatalf("erroring store recorded statuses = %+v, want none", erroringStore.statuses)
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
				Ranges: []malRange{{Events: []malEvent{
					{Introduced: "0"},
					{Introduced: "1.1.0"},
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
	if got, want := versions, []string{"1.0.0", "1.1.0"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("versions = %#v, want %#v", got, want)
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

	if got := mapToMaliciousFindings(&malEntry{}, "MAL-empty.json"); got != nil {
		t.Fatalf("mapToMaliciousFindings(no affected) = %#v, want nil", got)
	}
	if got := deriveIDFromPath("MAL-single.json"); got != "openssf-MAL-single" {
		t.Fatalf("deriveIDFromPath(single) = %q", got)
	}
}

func TestWalkEntriesSkipsMalformedAndUnsupportedFiles(t *testing.T) {
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
	writeFile(t, filepath.Join(root, "npm", "broken", "MAL-3.json"), `{`)
	writeFile(t, filepath.Join(root, "npm", "ignored", "README.txt"), `not json`)

	store := &maliciousTestStore{}
	syncer := NewSyncer(store, slog.New(slog.NewTextHandler(os.Stdout, nil)), t.TempDir())
	synced, total, err := syncer.walkEntries(context.Background(), store, root)
	if err != nil {
		t.Fatalf("walkEntries() error = %v", err)
	}

	if total != 3 {
		t.Fatalf("total JSON entries = %d, want 3", total)
	}
	if synced != 1 {
		t.Fatalf("synced = %d, want 1", synced)
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

	syncer := NewSyncer(&maliciousTestStore{}, nil, t.TempDir())
	if _, _, err := syncer.walkEntries(context.Background(), &maliciousTestStore{}, filepath.Join(t.TempDir(), "missing")); err == nil {
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
	_, _, err := syncer.walkEntries(ctx, &maliciousTestStore{}, canceledRoot)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("walkEntries(canceled) error = %v, want context.Canceled", err)
	}

	upsertRoot := t.TempDir()
	writeFile(t, filepath.Join(upsertRoot, "npm", "leftpad", "MAL-upsert.json"), `{
		"id":"MAL-upsert",
		"summary":"backdoor package",
		"affected":[{"package":{"ecosystem":"npm","name":"leftpad"}}]
	}`)
	erroringStore := &maliciousTestStore{upsertErr: errors.New("upsert failed")}
	synced, total, err := syncer.walkEntries(context.Background(), erroringStore, upsertRoot)
	if err != nil {
		t.Fatalf("walkEntries(upsert error) error = %v", err)
	}
	if synced != 0 || total != 1 {
		t.Fatalf("walkEntries(upsert error) = synced %d total %d, want 0/1", synced, total)
	}
	if len(erroringStore.findings) != 0 {
		t.Fatalf("erroring store findings = %+v, want none", erroringStore.findings)
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
	syncer := NewSyncer(store, slog.New(slog.NewTextHandler(os.Stdout, nil)), dataDir)
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
	syncer := NewSyncer(store, slog.New(slog.NewTextHandler(os.Stdout, nil)), dataDir)
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
	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}
