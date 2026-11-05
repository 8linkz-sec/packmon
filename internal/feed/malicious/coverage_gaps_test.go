package malicious

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type maliciousBareStore struct{ db.Store }

type maliciousDeleteErrorStore struct{ *maliciousTestStore }

func (maliciousDeleteErrorStore) DeleteMaliciousFindingForSource(context.Context, string, string) error {
	return errors.New("delete failed")
}

func TestMaliciousRootMetadataPruneAndTombstoneBranches(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	root, found, err := inspectMaliciousRoot(base, maliciousDir)
	if err != nil || found || root == "" {
		t.Fatalf("inspectMaliciousRoot(missing) = %q, %v, %v", root, found, err)
	}
	if err := os.WriteFile(filepath.Join(base, osvDir), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectMaliciousRoot(base, osvDir); err == nil {
		t.Fatal("inspectMaliciousRoot(file) error = nil")
	}

	if hasCurrentImporterMetadata(&db.FeedSyncStatus{Metadata: json.RawMessage("{")}) {
		t.Fatal("hasCurrentImporterMetadata(invalid) = true")
	}
	if pruned, err := NewSyncer(nil, "").pruneStaleFindings(context.Background(), maliciousBareStore{}, timeNowForTest()); err != nil || pruned != 0 {
		t.Fatalf("pruneStaleFindings(unsupported) = %d, %v", pruned, err)
	}

	findings := []*db.MaliciousFinding{{ID: ""}, {ID: "MAL-1"}}
	if ids := findingIDsForTombstone(&malEntry{}, "ignored.json", findings); len(ids) != 1 || ids[0] != "MAL-1" {
		t.Fatalf("findingIDsForTombstone(findings) = %+v", ids)
	}
	if ids := findingIDsForTombstone(&malEntry{ID: "MAL-explicit"}, "ignored.json", nil); len(ids) != 1 || ids[0] != "MAL-explicit" {
		t.Fatalf("findingIDsForTombstone(explicit) = %+v", ids)
	}
	if ids := findingIDsForTombstone(&malEntry{}, "", nil); len(ids) != 1 || ids[0] != "openssf-." {
		t.Fatalf("findingIDsForTombstone(derived) = %+v", ids)
	}
}

func timeNowForTest() time.Time { return time.Now().UTC() }

func TestMaliciousWalkMissingAndCancelledBranches(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(nil, "")
	missing := filepath.Join(t.TempDir(), "missing")
	if _, _, _, err := syncer.walkEntries(context.Background(), &maliciousTestStore{}, missing, nil); err == nil {
		t.Fatal("walkEntries(missing) error = nil")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "entry.json"), []byte(`{"id":"MAL-test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := syncer.walkEntries(ctx, &maliciousTestStore{}, root, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("walkEntries(cancelled) error = %v", err)
	}
	if _, _, _, err := syncer.walkSnapshotEntries(context.Background(), missing, func([]*db.MaliciousFinding, []string) error { return nil }); err == nil {
		t.Fatal("walkSnapshotEntries(missing) error = nil")
	}
}

func TestMaliciousLegacySnapshotAndUnsupportedEntryBranches(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(nil, "")
	if _, _, err := syncer.syncRepositorySnapshot(context.Background(), maliciousBareStore{}, t.TempDir(), time.Now()); err == nil {
		t.Fatal("syncRepositorySnapshot(missing legacy roots) error = nil")
	}

	if _, _, err := inspectMaliciousRoot("\x00", maliciousDir); err == nil {
		t.Fatal("inspectMaliciousRoot(invalid path) error = nil")
	}

	rootPath := t.TempDir()
	entryName := "unsupported.json"
	if err := os.WriteFile(filepath.Join(rootPath, entryName), []byte(`{"id":"MAL-unsupported","affected":[{"package":{"ecosystem":"unsupported","name":"pkg"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if synced, active, err := syncer.processMaliciousEntry(context.Background(), &maliciousTestStore{}, root, entryName, nil); err != nil || synced != 0 || active != 0 {
		t.Fatalf("processMaliciousEntry(unsupported) = %d/%d, %v", synced, active, err)
	}
	if synced, entries, active, err := syncer.walkSnapshotEntries(context.Background(), rootPath, func(findings []*db.MaliciousFinding, withdrawn []string) error {
		if len(findings) != 0 || len(withdrawn) != 0 {
			t.Fatalf("unsupported snapshot yielded findings=%d withdrawn=%d", len(findings), len(withdrawn))
		}
		return nil
	}); err != nil || synced != 0 || entries != 1 || active != 0 {
		t.Fatalf("walkSnapshotEntries(unsupported) = %d/%d/%d, %v", synced, entries, active, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := syncer.walkSnapshotEntries(ctx, rootPath, func([]*db.MaliciousFinding, []string) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("walkSnapshotEntries(cancelled) error = %v", err)
	}

	repo := t.TempDir()
	malRoot := filepath.Join(repo, maliciousDir)
	if err := os.MkdirAll(malRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(malRoot, "active.json"), []byte(`{"id":"MAL-active","affected":[{"package":{"ecosystem":"npm","name":"bad"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	yieldErr := errors.New("yield failed")
	if _, err := syncer.walkSnapshotRoots(context.Background(), repo, func([]db.MaliciousFinding, []string) error { return yieldErr }); !errors.Is(err, yieldErr) {
		t.Fatalf("walkSnapshotRoots(yield error) = %v", err)
	}

	badRepo := t.TempDir()
	badRoot := filepath.Join(badRepo, maliciousDir)
	if err := os.MkdirAll(badRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badRoot, "bad.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.walkLegacyRoots(context.Background(), &maliciousTestStore{}, badRepo); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("walkLegacyRoots(malformed) error = %v", err)
	}
	if _, err := syncer.walkSnapshotRoots(context.Background(), badRepo, func([]db.MaliciousFinding, []string) error { return nil }); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("walkSnapshotRoots(malformed) error = %v", err)
	}
}

func TestMaliciousSnapshotBatchAndReachableErrorBranches(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(nil, "")
	if _, err := syncer.walkSnapshotRoots(context.Background(), "\x00", func([]db.MaliciousFinding, []string) error { return nil }); err == nil {
		t.Fatal("walkSnapshotRoots(invalid path) error = nil")
	}

	legacyRepo := t.TempDir()
	legacyRoot := filepath.Join(legacyRepo, maliciousDir)
	if err := os.MkdirAll(legacyRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	activeBody := `{"id":"MAL-active","affected":[{"package":{"ecosystem":"npm","name":"bad"}}]}`
	if err := os.WriteFile(filepath.Join(legacyRoot, "active.json"), []byte(activeBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := syncer.syncRepositorySnapshot(context.Background(), &maliciousTestStore{stalePruneErr: errors.New("prune failed")}, legacyRepo, time.Now()); err == nil || !strings.Contains(err.Error(), "prune stale") {
		t.Fatalf("syncRepositorySnapshot(prune error) = %v", err)
	}

	root, err := os.OpenRoot(legacyRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	addErr := errors.New("add failed")
	if _, _, _, err := syncer.walkSnapshotEntries(context.Background(), legacyRoot, func([]*db.MaliciousFinding, []string) error { return addErr }); !errors.Is(err, addErr) {
		t.Fatalf("walkSnapshotEntries(add error) = %v", err)
	}

	withdrawnBody := `{"id":"MAL-withdrawn","withdrawn":"2026-11-05T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"bad"}}]}`
	if err := os.WriteFile(filepath.Join(legacyRoot, "withdrawn.json"), []byte(withdrawnBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := syncer.processMaliciousEntry(context.Background(), maliciousDeleteErrorStore{&maliciousTestStore{}}, root, "withdrawn.json", nil); err == nil || !strings.Contains(err.Error(), "tombstone") {
		t.Fatalf("processMaliciousEntry(delete error) = %v", err)
	}

	batchRepo := t.TempDir()
	batchRoot := filepath.Join(batchRepo, maliciousDir)
	if err := os.MkdirAll(batchRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	affected := make([]malAffected, db.MaliciousSnapshotBatchSize)
	for i := range affected {
		affected[i] = malAffected{Package: malPackage{Ecosystem: "npm", Name: "package"}}
	}
	body, err := json.Marshal(malEntry{ID: "MAL-batch", Affected: affected})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(batchRoot, "batch.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	yieldErr := errors.New("batch yield failed")
	if _, err := syncer.walkSnapshotRoots(context.Background(), batchRepo, func([]db.MaliciousFinding, []string) error { return yieldErr }); !errors.Is(err, yieldErr) {
		t.Fatalf("walkSnapshotRoots(batch yield error) = %v", err)
	}
}
