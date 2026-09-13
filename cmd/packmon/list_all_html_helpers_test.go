package main

import (
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestListAllHTMLFindingStatusesMergeEqualRankFixes(t *testing.T) {
	base := domain.Finding{Name: "pkg", Version: "1.0.0", Ecosystem: domain.Ecosystem("npm"), Type: domain.FindingTypeVulnerability, AdvisoryID: "CVE-1"}
	fixed := base
	fixed.FixedVersion = "1.0.1"
	for _, findings := range [][]domain.Finding{{base, fixed}, {fixed, base}} {
		state := listAllHTMLFindingStatuses(findings)[listAllFindingKey(base)]
		if state.Status != "Vulnerable" || state.Rank != 10 || !state.HasFixedVersion {
			t.Fatalf("equal-rank state = %+v, want vulnerable rank 10 with fix", state)
		}
		row := listAllRow{Name: "pkg", Installed: "1.0.0", Ecosystem: "npm"}
		if got := listAllHTMLPackageStatus(row, listAllHTMLFindingStatuses(findings)); got != "Update available" {
			t.Fatalf("package status = %q, want Update available", got)
		}
	}
}

func TestListAllHTMLFindingStatusesKeepHigherRankState(t *testing.T) {
	vuln := domain.Finding{Name: "pkg", Version: "1.0.0", Ecosystem: domain.Ecosystem("npm"), Type: domain.FindingTypeVulnerability, AdvisoryID: "CVE-1", FixedVersion: "1.0.1"}
	for _, tc := range []struct {
		name   string
		type_  domain.FindingType
		status string
		rank   int
	}{
		{name: "malicious", type_: domain.FindingTypeMalicious, status: "Malicious", rank: 50},
		{name: "lifecycle", type_: domain.FindingTypeLifecycle, status: "Lifecycle", rank: 20},
		{name: "supply chain", type_: domain.FindingTypeSupplyChainRisk, status: "Supply-chain risk", rank: 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			higher := vuln
			higher.Type = tc.type_
			higher.FixedVersion = ""
			for _, findings := range [][]domain.Finding{{vuln, higher}, {higher, vuln}} {
				state := listAllHTMLFindingStatuses(findings)[listAllFindingKey(vuln)]
				if state.Status != tc.status || state.Rank != tc.rank || state.HasFixedVersion {
					t.Fatalf("higher-rank state = %+v, want %s rank %d without leaked fix", state, tc.status, tc.rank)
				}
			}
		})
	}
}

func TestListAllHTMLPackageStatusExplicitContracts(t *testing.T) {
	for _, tc := range []struct {
		row  listAllRow
		want string
	}{
		{listAllRow{Update: "pinned"}, "Digest pinned"},
		{listAllRow{Update: "unknown"}, "Unknown"},
		{listAllRow{Latest: "unknown"}, "Unknown"},
		{listAllRow{Update: "local"}, "Local build"},
		{listAllRow{Update: "yes"}, "Update available"},
		{listAllRow{}, "Up-to-Date"},
	} {
		if got := listAllHTMLPackageStatus(tc.row, nil); got != tc.want {
			t.Fatalf("status(%+v) = %q, want %q", tc.row, got, tc.want)
		}
	}
	if got := listAllHTMLPackageSource(listAllRow{Ecosystem: string(domain.EcosystemChocolatey)}); got != "chocolatey" {
		t.Fatalf("Chocolatey source = %q", got)
	}
	label, message := listAllHTMLCopyContext("", listAllRow{})
	if label != "Copy full value value for package unknown version" || message != "Copied full value value for package" {
		t.Fatalf("copy context = %q, %q", label, message)
	}
}
