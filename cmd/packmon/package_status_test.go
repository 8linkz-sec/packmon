package main

import (
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestPackageStatusLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		in       dependencyPackageStatus
		scope    string
		relation string
		flags    string
	}{
		{
			name: "explicit labels take precedence",
			in: dependencyPackageStatus{
				Ecosystem: domain.EcosystemGitHubActions,
				Dev:       true,
				Direct:    true,
				Optional:  true,
				Peer:      true,
				Scope:     "custom scope",
				Relation:  "custom relation",
				Flags:     "custom flags",
			},
			scope:    "custom scope",
			relation: "custom relation",
			flags:    "custom flags",
		},
		{
			name: "github action takes precedence over all derived labels",
			in: dependencyPackageStatus{
				Ecosystem:  domain.EcosystemGitHubActions,
				SourceType: "sbom",
				Dev:        true,
				Direct:     true,
				Indirect:   true,
			},
			scope:    "ci",
			relation: "workflow",
		},
		{
			name: "sbom takes precedence over development",
			in: dependencyPackageStatus{
				SourceType: "sbom",
				Dev:        true,
				Direct:     true,
				Optional:   true,
			},
			scope:    "sbom",
			relation: "direct",
			flags:    "optional",
		},
		{
			name: "direct takes precedence over indirect",
			in: dependencyPackageStatus{
				Dev:      true,
				Direct:   true,
				Indirect: true,
				Peer:     true,
			},
			scope:    "dev",
			relation: "direct",
			flags:    "peer",
		},
		{
			name: "runtime declared dependency with both flags",
			in: dependencyPackageStatus{
				Optional: true,
				Peer:     true,
			},
			scope:    "runtime",
			relation: "declared",
			flags:    "optional, peer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := packageStatusScope(tt.in); got != tt.scope {
				t.Fatalf("packageStatusScope() = %q, want %q", got, tt.scope)
			}
			if got := packageStatusRelation(tt.in); got != tt.relation {
				t.Fatalf("packageStatusRelation() = %q, want %q", got, tt.relation)
			}
			if got := packageStatusFlags(tt.in); got != tt.flags {
				t.Fatalf("packageStatusFlags() = %q, want %q", got, tt.flags)
			}
		})
	}
}

func TestPackageStatusAdaptersPreserveFields(t *testing.T) {
	t.Parallel()

	listAll := listAllPackage{
		Ecosystem:  domain.EcosystemNPM,
		SourceType: "sbom",
		Dev:        true,
		Direct:     true,
		Indirect:   true,
		Optional:   true,
		Peer:       true,
		Scope:      "scope",
		Relation:   "relation",
		Flags:      "flags",
	}
	if got, want := packageStatusFromListAllPackage(listAll), (dependencyPackageStatus{
		Ecosystem:  domain.EcosystemNPM,
		SourceType: "sbom",
		Dev:        true,
		Direct:     true,
		Indirect:   true,
		Optional:   true,
		Peer:       true,
		Scope:      "scope",
		Relation:   "relation",
		Flags:      "flags",
	}); got != want {
		t.Fatalf("packageStatusFromListAllPackage() = %+v, want %+v", got, want)
	}

	outdated := outdatedPackage{
		Ecosystem:  domain.EcosystemGo,
		SourceType: "sbom",
		Dev:        true,
		Direct:     true,
		Indirect:   true,
		Optional:   true,
		Peer:       true,
	}
	if got, want := packageStatusFromOutdatedPackage(outdated), (dependencyPackageStatus{
		Ecosystem:  domain.EcosystemGo,
		SourceType: "sbom",
		Dev:        true,
		Direct:     true,
		Indirect:   true,
		Optional:   true,
		Peer:       true,
	}); got != want {
		t.Fatalf("packageStatusFromOutdatedPackage() = %+v, want %+v", got, want)
	}
}
