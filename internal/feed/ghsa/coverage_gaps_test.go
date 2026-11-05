package ghsa

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestGHSAWalkAndDeltaEarlyErrorBranches(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(nil, "")
	missing := filepath.Join(t.TempDir(), "missing")
	if _, _, err := syncer.walkAdvisories(context.Background(), &ghsaStoreStub{}, missing); err == nil || !strings.Contains(err.Error(), "open advisory root") {
		t.Fatalf("walkAdvisories(missing) error = %v", err)
	}
	if _, _, err := syncer.processChangedFiles(context.Background(), &ghsaStoreStub{}, missing, nil); err == nil || !strings.Contains(err.Error(), "open repo root") {
		t.Fatalf("processChangedFiles(missing) error = %v", err)
	}

	repo := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := syncer.processChangedFiles(ctx, &ghsaStoreStub{}, repo, []string{reviewedDir + "/GHSA-test.json"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("processChangedFiles(cancelled) error = %v", err)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ignored.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	if synced, total, err := syncer.walkAdvisories(context.Background(), &ghsaStoreStub{}, root); err != nil || synced != 0 || total != 0 {
		t.Fatalf("walkAdvisories(non-json) = %d/%d, %v", synced, total, err)
	}
}

func TestGHSAMetadataRangeAndReferenceBranches(t *testing.T) {
	t.Parallel()

	if ghsaSyncMetadataIsCurrent(&db.FeedSyncStatus{}) {
		t.Fatal("ghsaSyncMetadataIsCurrent(empty) = true")
	}
	if ghsaSyncMetadataIsCurrent(&db.FeedSyncStatus{Metadata: []byte("{")}) {
		t.Fatal("ghsaSyncMetadataIsCurrent(invalid) = true")
	}
	if hasRangeClosure([]ghsaEvent{{Introduced: "0"}}) {
		t.Fatal("hasRangeClosure(open range) = true")
	}
	if !hasRangeClosure([]ghsaEvent{{LastAffected: "1.2.3"}}) {
		t.Fatal("hasRangeClosure(last affected) = false")
	}
	if _, ok := closureEventFromLastKnownAffectedRange(nil); ok {
		t.Fatal("closureEventFromLastKnownAffectedRange(nil) ok = true")
	}
	if _, ok := closureEventFromLastKnownAffectedRange(&ghsaAffectedDatabaseSpecific{LastKnownAffectedVersionRange: "nonsense"}); ok {
		t.Fatal("closureEventFromLastKnownAffectedRange(invalid) ok = true")
	}

	vuln, err := mapToVulnerability(&ghsaAdvisory{
		ID:         "GHSA-test-empty-ref",
		References: []ghsaReference{{Type: "WEB", URL: ""}},
		Affected: []ghsaAffected{{
			Package: ghsaPackage{Ecosystem: "unsupported", Name: "ignored"},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vuln.References) != 0 || len(vuln.AffectedPackages) != 0 {
		t.Fatalf("mapToVulnerability() = %+v", vuln)
	}
}

func TestGHSAChangedFileRejectsEmptyAdvisoryID(t *testing.T) {
	t.Parallel()

	repo := t.TempDir()
	if _, _, err := NewSyncer(nil, "").processChangedFiles(context.Background(), &ghsaStoreStub{}, repo, []string{reviewedDir + "/.json"}); err == nil || !strings.Contains(err.Error(), "derive deleted advisory ID") {
		t.Fatalf("processChangedFiles(empty advisory id) error = %v", err)
	}
}

func TestGHSAWalkAndDeltaImportFailureBranches(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(nil, "")
	root := t.TempDir()
	badWithdrawn := `{"id":"GHSA-bad-withdrawn","withdrawn":"not-a-time"}`
	if err := os.WriteFile(filepath.Join(root, "bad-withdrawn.json"), []byte(badWithdrawn), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if synced, total, err := syncer.walkAdvisories(context.Background(), &ghsaStoreStub{}, root); err == nil || synced != 0 || total != 1 {
		t.Fatalf("walkAdvisories(mapping/read errors) = %d/%d, %v", synced, total, err)
	}

	cancelRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(cancelRoot, "entry.json"), []byte(`{"id":"GHSA-test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := syncer.walkAdvisories(ctx, &ghsaStoreStub{}, cancelRoot); !errors.Is(err, context.Canceled) {
		t.Fatalf("walkAdvisories(cancelled) error = %v", err)
	}

	repo := t.TempDir()
	changed := reviewedDir + "/2026/GHSA-upsert.json"
	path := filepath.Join(repo, filepath.FromSlash(changed))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"id":"GHSA-upsert"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if synced, total, err := syncer.processChangedFiles(context.Background(), &ghsaStoreStub{upsertErr: errors.New("write failed")}, repo, []string{changed}); err == nil || synced != 0 || total != 1 {
		t.Fatalf("processChangedFiles(upsert error) = %d/%d, %v", synced, total, err)
	}
	missing := reviewedDir + "/2026/GHSA-deleted.json"
	if _, _, err := syncer.processChangedFiles(context.Background(), &ghsaStoreStub{deleteErr: errors.New("delete failed")}, repo, []string{missing}); err == nil || !strings.Contains(err.Error(), "delete removed advisory") {
		t.Fatalf("processChangedFiles(delete error) = %v", err)
	}
}
