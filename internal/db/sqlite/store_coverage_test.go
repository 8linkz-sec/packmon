package sqlite

import (
	"context"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestLocalPackagePredicateBranches(t *testing.T) {
	t.Parallel()

	chunks := localPackagePredicateChunks(nil, localPackagePredicateChunkSize)
	if len(chunks) != 0 {
		t.Fatalf("empty predicate chunks = %+v, want none", chunks)
	}
	chunks = localPackagePredicateChunks([]db.PackageQuery{
		{Ecosystem: " ", Name: "left-pad"},
		{Ecosystem: "npm", Name: " "},
	}, localPackagePredicateChunkSize)
	if len(chunks) != 0 {
		t.Fatalf("blank predicate chunks = %+v, want none", chunks)
	}

	chunks = localPackagePredicateChunks([]db.PackageQuery{
		{Ecosystem: "nuget", Name: "Newtonsoft.Json", Version: "13.0.1"},
		{Ecosystem: "nuget", Name: "newtonsoft.json", Version: "13.0.3"},
		{Ecosystem: "npm", Name: "left-pad"},
	}, 3)
	if len(chunks) != 1 {
		t.Fatalf("predicate chunks = %+v, want one chunk", chunks)
	}
	where, args, versions := chunks[0].where, chunks[0].args, chunks[0].versionsByPackage
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

	vuln := localVulnerabilityFinding("CVE-2026-0001", "npm", "left-pad", "1.0.0", "", `[{"type":"WEB","url":"https://osv.dev/vulnerability/CVE-2026-0001"}]`, "HIGH", "", "local")
	if vuln.Title != "CVE-2026-0001" || vuln.URL != "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" {
		t.Fatalf("local vulnerability finding = %+v", vuln)
	}
	if len(vuln.Resources) != 2 || vuln.Resources[0].Label != "NVD" || vuln.Resources[1].Label != "OSV" {
		t.Fatalf("local vulnerability resources = %+v, want NVD and OSV", vuln.Resources)
	}
	mal := localMaliciousFinding("MAL-1", "npm", "evil", "1.0.0", `["not a url","https://github.com/acme/evil"]`, "malware", "CRITICAL", "", "local")
	if mal.Title != "malicious package: evil (malware)" || mal.URL != "https://github.com/acme/evil" {
		t.Fatalf("local malicious finding = %+v", mal)
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
	if findings, err := store.FindReputationFindingsBatch(ctx, nil, db.ReputationSourceReversingLabs); err != nil || findings != nil {
		t.Fatalf("FindReputationFindingsBatch(empty) = %+v, %v", findings, err)
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
