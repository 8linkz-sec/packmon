package ghsa

import (
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

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
