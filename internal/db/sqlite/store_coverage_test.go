package sqlite

import (
	"context"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

func TestLocalPackagePredicateBranches(t *testing.T) {
	t.Parallel()

	where, args, versions := localPackagePredicate(nil)
	if where != "" || args != nil || versions != nil {
		t.Fatalf("empty predicate = %q %+v %+v, want zero values", where, args, versions)
	}
	where, args, versions = localPackagePredicate([]db.PackageQuery{
		{Ecosystem: " ", Name: "left-pad"},
		{Ecosystem: "npm", Name: " "},
	})
	if where != "" || args != nil || versions != nil {
		t.Fatalf("blank predicate = %q %+v %+v, want zero values", where, args, versions)
	}

	where, args, versions = localPackagePredicate([]db.PackageQuery{
		{Ecosystem: "nuget", Name: "Newtonsoft.Json", Version: "13.0.1"},
		{Ecosystem: "nuget", Name: "newtonsoft.json", Version: "13.0.3"},
		{Ecosystem: "npm", Name: "left-pad"},
	})
	if strings.Count(where, "ecosystem = ?") != 2 {
		t.Fatalf("where = %q, want two unique package clauses", where)
	}
	if len(args) != 4 {
		t.Fatalf("args = %+v, want two ecosystem/name pairs", args)
	}
	nugetVersions := versions[localPackageKey{ecosystem: "nuget", name: "newtonsoft.json"}]
	if len(nugetVersions) != 2 || nugetVersions[0] != "13.0.1" || nugetVersions[1] != "13.0.3" {
		t.Fatalf("nuget versions = %+v", nugetVersions)
	}
}

func TestLocalFindingAndReferenceHelperBranches(t *testing.T) {
	t.Parallel()

	vuln := localVulnerabilityFinding("CVE-2026-0001", "npm", "left-pad", "1.0.0", "", `[{"type":"WEB","url":"https://osv.dev/vulnerability/CVE-2026-0001"}]`, "HIGH", "")
	if vuln.Title != "CVE-2026-0001" || vuln.URL != "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" {
		t.Fatalf("local vulnerability finding = %+v", vuln)
	}
	mal := localMaliciousFinding("MAL-1", "npm", "evil", "1.0.0", `["not a url","https://github.com/acme/evil"]`, "malware", "CRITICAL", "")
	if mal.Title != "malicious package: evil (malware)" || mal.URL != "https://github.com/acme/evil" {
		t.Fatalf("local malicious finding = %+v", mal)
	}

	refs := resourceLinksFromVulnerabilityReferences("GHSA-abcd-efgh-ijkl", `[
		{"type":"PACKAGE","url":"https://example.test/pkg"},
		{"type":"WEB","url":"https://github.com/acme/repo/security/advisories/GHSA-abcd-efgh-ijkl"},
		{"type":"WEB","url":"https://cve.org/CVERecord?id=CVE-2026-0001"},
		{"type":"WEB","url":"bad url"}
	]`)
	if len(refs) != 3 || refs[0].Label != "GHSA" || refs[1].Label != "GHSA" || refs[2].Label != "CVE" {
		t.Fatalf("refs = %+v", refs)
	}
	for _, tt := range []struct {
		id    string
		label string
	}{
		{id: "RUSTSEC-2026-0001", label: "RustSec"},
		{id: "CVE-2026-0002", label: "NVD"},
		{id: "OTHER-1", label: ""},
	} {
		if got := canonicalResourceLink(tt.id); got.Label != tt.label {
			t.Fatalf("canonicalResourceLink(%q) = %+v, want label %q", tt.id, got, tt.label)
		}
	}
	for _, raw := range []string{"", "://bad", "https://www.rustsec.org/advisories/RUSTSEC-2026-0001.html", "https://example.test/path"} {
		_ = resourceLinkFromURL(raw)
	}
	if got := firstURLFromJSON(`["not a url","https://nvd.nist.gov/vuln/detail/CVE-2026-0001"]`); got != "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" {
		t.Fatalf("firstURLFromJSON = %q", got)
	}
	if got := firstURLFromJSON(`not json`); got != "" {
		t.Fatalf("firstURLFromJSON(invalid) = %q", got)
	}
}

func TestStoreBatchEmptyAndSchemaHelperBranches(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	if findings, err := store.FindVulnerabilitiesBatch(ctx, nil); err != nil || findings != nil {
		t.Fatalf("FindVulnerabilitiesBatch(empty) = %+v, %v", findings, err)
	}
	if findings, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{{Ecosystem: "", Name: ""}}); err != nil || findings != nil {
		t.Fatalf("FindMaliciousBatch(blank) = %+v, %v", findings, err)
	}
	if findings, err := store.findReputationFindings(ctx, "npm", "left-pad", ""); err != nil || findings != nil {
		t.Fatalf("findReputationFindings(no version) = %+v, %v", findings, err)
	}
	exists, err := tableExists(store.DB(), "vulnerabilities_local")
	if err != nil || !exists {
		t.Fatalf("tableExists(vulnerabilities_local) = %v, %v", exists, err)
	}
	exists, err = tableExists(store.DB(), "missing_table")
	if err != nil || exists {
		t.Fatalf("tableExists(missing) = %v, %v", exists, err)
	}
	hasColumn, err := tableHasColumn(store.DB(), "vulnerabilities_local", "severity")
	if err != nil || !hasColumn {
		t.Fatalf("tableHasColumn(severity) = %v, %v", hasColumn, err)
	}
	hasColumn, err = tableHasColumn(store.DB(), "vulnerabilities_local", "missing_column")
	if err != nil || hasColumn {
		t.Fatalf("tableHasColumn(missing) = %v, %v", hasColumn, err)
	}
	finding := domain.Finding{AdvisoryID: "sanity"}
	if finding.AdvisoryID == "" {
		t.Fatal("domain finding sanity check failed")
	}
}
