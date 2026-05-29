package ghsa

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

type ghsaStoreStub struct {
	db.Store
	upserts int
}

func (s *ghsaStoreStub) UpsertVulnerability(context.Context, *db.Vulnerability) error {
	s.upserts++
	return nil
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
}
