//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/packageid"
)

// TestPostgresStoreCorrectnessAgainstDocker groups store-correctness
// regressions behind one PostgreSQL container. The subtests run sequentially
// and use disjoint fixtures; dashboard assertions compare deltas.
func TestPostgresStoreCorrectnessAgainstDocker(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	t.Run("dashboard buckets historical reputation risk as LOW", func(t *testing.T) {
		testDashboardBucketsHistoricalReputationRiskAsLow(ctx, t, store)
	})
	t.Run("scan totals above int32 are not narrowed", func(t *testing.T) {
		testScanTotalsAboveInt32AreNotNarrowed(ctx, t, store)
	})
	t.Run("canonical package name SQL mirrors packageid", func(t *testing.T) {
		testCanonicalPackageNameSQLMirrorsPackageID(ctx, t, store)
	})
	t.Run("GHSA repair writes canonical package names", func(t *testing.T) {
		testGHSARepairWritesCanonicalPackageNames(ctx, t, store)
	})
	t.Run("GHSA repair tolerates non-array affected and events", func(t *testing.T) {
		testGHSARepairToleratesNonArrayAffectedAndEvents(ctx, t, store)
	})
	t.Run("malicious batch keeps empty version beside concrete versions", func(t *testing.T) {
		testMaliciousBatchKeepsEmptyVersionBesideConcreteVersions(ctx, t, store)
	})
	t.Run("vulnerability batch keeps empty version beside concrete versions", func(t *testing.T) {
		testVulnerabilityBatchKeepsEmptyVersionBesideConcreteVersions(ctx, t, store)
	})
	t.Run("manual advisory writes and deletes use the normalized ID", func(t *testing.T) {
		testManualAdvisoryUsesNormalizedID(ctx, t, store)
	})
	t.Run("manual vulnerability edit replaces severity details and packages", func(t *testing.T) {
		testManualVulnerabilityEditReplacesState(ctx, t, store)
	})
	t.Run("manual edit delta sends the complete affected set", func(t *testing.T) {
		testManualEditDeltaSendsCompleteAffectedSet(ctx, t, store)
	})
	t.Run("affected-complete flag on every advisory-paged delta page", func(t *testing.T) {
		testSyncAffectedCompleteOnDeltaPages(ctx, t, store)
	})
	t.Run("delta pages keep each advisory whole", func(t *testing.T) {
		testDeltaPagesKeepEachAdvisoryWhole(ctx, t, store)
	})
	t.Run("multi-page delta replaces whole advisories changed between pages", func(t *testing.T) {
		testMultiPageDeltaReplacesWholeAdvisoriesChangedBetweenPages(ctx, t, store)
	})
	t.Run("delta delivers advisories without affected packages", func(t *testing.T) {
		testDeltaDeliversAdvisoriesWithoutAffectedPackages(ctx, t, store)
	})
	t.Run("delta splits an advisory larger than the page budget", func(t *testing.T) {
		testDeltaSplitsAnAdvisoryLargerThanThePageBudget(ctx, t, store)
	})
	t.Run("split advisory changed mid-split stays upsert-only", func(t *testing.T) {
		testSplitAdvisoryChangedMidSplitStaysUpsertOnly(ctx, t, store)
	})
	t.Run("malicious and reputation pages stay within their byte budgets", func(t *testing.T) {
		testOtherDatasetPagesStayWithinTheirByteBudgets(ctx, t, store)
	})
	t.Run("sync xid conditions match their model", func(t *testing.T) {
		testSyncXIDConditionsMatchTheirModel(ctx, t, store)
	})
	t.Run("delta delivers a row committed after the snapshot", func(t *testing.T) {
		testDeltaDeliversRowCommittedAfterTheSnapshot(ctx, t, store)
	})
	t.Run("package name repair marks merged vulnerabilities changed", func(t *testing.T) {
		testPackageNameRepairDeltaIncludesMergedVulnerability(ctx, t, store)
	})
	// Runs last: it asserts that a second repair over the shared database
	// finds nothing left to repair.
	t.Run("package name repair uses canonical names", func(t *testing.T) {
		testPackageNameRepairUsesCanonicalNames(ctx, t, store)
	})
}

func testManualVulnerabilityEditReplacesState(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const id = "manual:replace-edit"
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID: id, FindingType: "vulnerability", Ecosystem: "npm", Name: "replace-edit-a",
		Severity: "HIGH", Summary: "original summary", Description: "original details",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(create) error = %v", err)
	}
	current, err := store.GetManualAdvisory(ctx, id)
	if err != nil || current == nil {
		t.Fatalf("GetManualAdvisory(create) = %+v, %v; want advisory", current, err)
	}

	edit := &db.ManualAdvisory{
		ID: id, FindingType: "vulnerability", Ecosystem: "pypi", Name: "Replace_Edit.B",
		Severity: "LOW", Summary: "edited summary", Description: "", UpdatedAt: current.UpdatedAt,
	}
	if err := store.UpsertManualAdvisoryWithAudit(ctx, edit, &db.AdminAuditEntry{Action: "manual_advisory_update"}); err != nil {
		t.Fatalf("UpsertManualAdvisoryWithAudit(edit) error = %v", err)
	}

	listed := manualAdvisoriesWithID(ctx, t, store, id)
	if len(listed) != 1 {
		t.Fatalf("manual advisories for %s after edit = %+v, want exactly the edited package", id, listed)
	}
	got := listed[0]
	if got.Severity != "LOW" || got.Summary != "edited summary" || got.Description != "" || got.Ecosystem != "pypi" || got.Name != "replace-edit-b" {
		t.Fatalf("manual advisory after edit = %+v, want LOW, edited summary, cleared description, pypi/replace-edit-b", got)
	}

	oldPackage, err := store.FindVulnerabilities(ctx, "npm", "replace-edit-a", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(old package) error = %v", err)
	}
	if findingsContainAdvisory(oldPackage, id) {
		t.Fatalf("FindVulnerabilities(old package) = %+v, want coverage moved away", oldPackage)
	}
	newPackage, err := store.FindVulnerabilities(ctx, "pypi", "replace-edit-b", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(new package) error = %v", err)
	}
	if len(newPackage) != 1 || newPackage[0].AdvisoryID != id || newPackage[0].Severity != domain.SeverityLow {
		t.Fatalf("FindVulnerabilities(new package) = %+v, want one LOW %s finding", newPackage, id)
	}

	// Feed merges keep their retention rules: a later, lower feed severity and
	// an empty feed description do not replace stored feed data.
	now := time.Now().UTC()
	feed := func(severity, details string) *db.Vulnerability {
		return &db.Vulnerability{
			ID: "GHSA-feed-retention", Summary: "feed summary", Details: details, Severity: severity,
			Published: now, Modified: now,
			Sources: []db.VulnerabilitySource{{Source: "ghsa", SourceID: "GHSA-feed-retention"}},
			AffectedPackages: []db.AffectedPackage{{
				Ecosystem: "npm", Name: "feed-retention", VersionRanges: json.RawMessage(`[]`), VersionsAffected: json.RawMessage(`[]`),
			}},
		}
	}
	if err := store.UpsertVulnerability(ctx, feed("HIGH", "feed details")); err != nil {
		t.Fatalf("UpsertVulnerability(feed HIGH) error = %v", err)
	}
	if err := store.UpsertVulnerability(ctx, feed("LOW", "")); err != nil {
		t.Fatalf("UpsertVulnerability(feed LOW) error = %v", err)
	}
	var feedSeverity, feedDetails string
	if err := store.pool.QueryRow(ctx, `SELECT severity, COALESCE(details, '') FROM vulnerabilities WHERE id = 'GHSA-feed-retention'`).Scan(&feedSeverity, &feedDetails); err != nil {
		t.Fatalf("read feed vulnerability: %v", err)
	}
	if feedSeverity != "HIGH" || feedDetails != "feed details" {
		t.Fatalf("feed vulnerability after weaker resync = %q/%q, want HIGH/feed details retained", feedSeverity, feedDetails)
	}
}

func manualAdvisoriesWithID(ctx context.Context, t *testing.T, store *Store, id string) []db.ManualAdvisory {
	t.Helper()

	all, err := store.ListManualAdvisories(ctx, 500)
	if err != nil {
		t.Fatalf("ListManualAdvisories() error = %v", err)
	}
	var matching []db.ManualAdvisory
	for _, advisory := range all {
		if advisory.ID == id {
			matching = append(matching, advisory)
		}
	}
	return matching
}

func testManualAdvisoryUsesNormalizedID(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const padded = "  manual:padded-id \t"
	const normalized = "manual:padded-id"

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID: padded, FindingType: "vulnerability", Ecosystem: "npm", Name: "padded-id-pkg",
		Severity: "HIGH", Summary: "padded manual vulnerability",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(vulnerability) error = %v", err)
	}
	if err := store.UpsertManualAdvisoryWithAudit(ctx, &db.ManualAdvisory{
		ID: padded, FindingType: "malicious", Ecosystem: "npm", Name: "padded-id-pkg",
		Severity: "CRITICAL", RiskType: "malware", Summary: "padded manual malicious",
	}, &db.AdminAuditEntry{Action: "manual_advisory_update"}); err != nil {
		t.Fatalf("UpsertManualAdvisoryWithAudit(type change) error = %v", err)
	}

	active := manualAdvisoriesWithID(ctx, t, store, normalized)
	if len(active) != 1 || active[0].FindingType != "malicious" {
		t.Fatalf("manual advisories for %s after type change = %+v, want only the malicious advisory", normalized, active)
	}
	vulns, err := store.FindVulnerabilities(ctx, "npm", "padded-id-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if findingsContainAdvisory(vulns, normalized) {
		t.Fatalf("FindVulnerabilities() after type change = %+v, want the manual vulnerability withdrawn", vulns)
	}

	if got, err := store.GetManualAdvisory(ctx, padded); err != nil || got == nil || got.ID != normalized {
		t.Fatalf("GetManualAdvisory(padded) = %+v, %v; want the normalized advisory", got, err)
	}

	if err := store.DeleteManualAdvisoryWithAudit(ctx, padded, &db.AdminAuditEntry{Action: "manual_advisory_delete"}); err != nil {
		t.Fatalf("DeleteManualAdvisoryWithAudit(padded) error = %v, want the normalized advisory deleted", err)
	}
	if remaining := manualAdvisoriesWithID(ctx, t, store, normalized); len(remaining) != 0 {
		t.Fatalf("manual advisories for %s after delete = %+v, want none", normalized, remaining)
	}

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID: normalized, FindingType: "vulnerability", Ecosystem: "npm", Name: "padded-id-pkg",
		Severity: "LOW", Summary: "recreated manual vulnerability",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(recreate) error = %v", err)
	}
	if err := store.DeleteManualAdvisory(ctx, " "+normalized+" "); err != nil {
		t.Fatalf("DeleteManualAdvisory(padded) error = %v, want the normalized advisory deleted", err)
	}
	if remaining := manualAdvisoriesWithID(ctx, t, store, normalized); len(remaining) != 0 {
		t.Fatalf("manual advisories for %s after plain delete = %+v, want none", normalized, remaining)
	}
}

func testMaliciousBatchKeepsEmptyVersionBesideConcreteVersions(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "MAL-batch-empty-version",
		Ecosystem: "npm",
		Name:      "batch-empty-version",
		Versions:  json.RawMessage(`["1.0.0"]`),
		Source:    "openssf",
		RiskType:  "malware",
		Severity:  "CRITICAL",
		Summary:   "affects only 1.0.0",
		CreatedBy: "feed",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding() error = %v", err)
	}

	single, err := store.FindMalicious(ctx, "npm", "batch-empty-version", "")
	if err != nil {
		t.Fatalf("FindMalicious(empty version) error = %v", err)
	}
	if len(single) != 1 {
		t.Fatalf("FindMalicious(empty version) = %+v, want the all-versions match", single)
	}

	onlyEmpty, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "batch-empty-version"}})
	if err != nil {
		t.Fatalf("FindMaliciousBatch(empty only) error = %v", err)
	}
	if len(onlyEmpty) != 1 || onlyEmpty[0].Version != "" {
		t.Fatalf("FindMaliciousBatch(empty only) = %+v, want one versionless finding", onlyEmpty)
	}

	mixed, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "batch-empty-version", Version: ""},
		{Ecosystem: "npm", Name: "batch-empty-version", Version: "2.0.0"},
	})
	if err != nil {
		t.Fatalf("FindMaliciousBatch(empty + 2.0.0) error = %v", err)
	}
	if len(mixed) != 1 || mixed[0].Version != "" || mixed[0].AdvisoryID != "MAL-batch-empty-version" {
		t.Fatalf("FindMaliciousBatch(empty + 2.0.0) = %+v, want only the versionless finding (2.0.0 is unaffected)", mixed)
	}
}

func testVulnerabilityBatchKeepsEmptyVersionBesideConcreteVersions(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:        "GHSA-batc-hemp-tyvr",
		Summary:   "affects only 1.0.0",
		Severity:  "HIGH",
		Published: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		Modified:  time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		Sources:   []db.VulnerabilitySource{{Source: "ghsa", SourceID: "GHSA-batc-hemp-tyvr"}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "vuln-batch-empty-version",
			VersionRanges:    json.RawMessage(`[]`),
			VersionsAffected: json.RawMessage(`["1.0.0"]`),
		}},
	}); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}

	single, err := store.FindVulnerabilities(ctx, "npm", "vuln-batch-empty-version", "")
	if err != nil {
		t.Fatalf("FindVulnerabilities(empty version) error = %v", err)
	}
	if len(single) != 1 {
		t.Fatalf("FindVulnerabilities(empty version) = %+v, want the all-versions match", single)
	}

	for _, batch := range [][]db.PackageQuery{
		{{Ecosystem: "npm", Name: "vuln-batch-empty-version"}},
		{{Ecosystem: "npm", Name: "vuln-batch-empty-version"}, {Ecosystem: "npm", Name: "vuln-batch-empty-version", Version: "2.0.0"}},
		{{Ecosystem: "npm", Name: "vuln-batch-empty-version", Version: "2.0.0"}, {Ecosystem: "npm", Name: "vuln-batch-empty-version"}, {Ecosystem: "npm", Name: "vuln-batch-empty-version"}},
	} {
		got, err := store.FindVulnerabilitiesBatch(ctx, batch)
		if err != nil {
			t.Fatalf("FindVulnerabilitiesBatch(%+v) error = %v", batch, err)
		}
		if len(got) != 1 || got[0].Version != "" || got[0].AdvisoryID != "GHSA-batc-hemp-tyvr" {
			t.Fatalf("FindVulnerabilitiesBatch(%+v) = %+v, want only the versionless finding (2.0.0 is unaffected)", batch, got)
		}
	}
}

func testGHSARepairToleratesNonArrayAffectedAndEvents(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	malformed := map[string]string{
		"GHSA-repair-affected-null":   `{"affected": null}`,
		"GHSA-repair-affected-object": `{"affected": {"package": {"ecosystem": "npm", "name": "object-affected"}}}`,
		"GHSA-repair-affected-scalar": `{"affected": "not-an-array"}`,
		"GHSA-repair-events-null": `{"affected": [{"package": {"ecosystem": "npm", "name": "events-null"},
			"ranges": [{"type": "SEMVER", "events": null}],
			"database_specific": {"last_known_affected_version_range": "<= 1.0.0"}}]}`,
		"GHSA-repair-events-object": `{"affected": [{"package": {"ecosystem": "npm", "name": "events-object"},
			"ranges": [{"type": "SEMVER", "events": {"introduced": "0"}}],
			"database_specific": {"last_known_affected_version_range": "< 2.0.0"}}]}`,
		"GHSA-repair-events-scalar": `{"affected": [{"package": {"ecosystem": "npm", "name": "events-scalar"},
			"ranges": [{"type": "SEMVER", "events": 7}, "range-scalar"]}]}`,
		"GHSA-repair-versions-numeric": `{"affected": [{"package": {"ecosystem": "npm", "name": "versions-numeric"},
			"versions": [1, 2]}]}`,
	}
	for id, raw := range malformed {
		upsertGHSARepairFixture(ctx, t, store, id, raw)
	}
	upsertGHSARepairFixture(ctx, t, store, "GHSA-repair-valid-beside-malformed", `{"affected": [
		{"package": {"ecosystem": "npm", "name": "repair-only-valid"},
		 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
		 "database_specific": {"last_known_affected_version_range": "< 4.0.0"}}
	]}`)

	if _, err := store.RepairGHSAAffectedPackages(ctx); err != nil {
		t.Fatalf("RepairGHSAAffectedPackages() with malformed advisories error = %v, want the valid advisory repaired", err)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "repair-only-valid", "3.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(repair-only-valid@3.0.0) error = %v", err)
	}
	if !findingsContainAdvisory(findings, "GHSA-repair-valid-beside-malformed") {
		t.Fatalf("FindVulnerabilities(repair-only-valid@3.0.0) = %+v, want advisory repaired beside malformed ones", findings)
	}
	fixedFindings, err := store.FindVulnerabilities(ctx, "npm", "repair-only-valid", "4.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(repair-only-valid@4.0.0) error = %v", err)
	}
	if findingsContainAdvisory(fixedFindings, "GHSA-repair-valid-beside-malformed") {
		t.Fatalf("FindVulnerabilities(repair-only-valid@4.0.0) = %+v, want fixed bound from last_known_affected_version_range", fixedFindings)
	}

	// Packages whose reconstructed ranges or versions the schema rejects are
	// skipped, like the feed path rejects them; the advisory's other rows stay.
	for _, pkg := range []string{"events-null", "events-object", "events-scalar", "versions-numeric"} {
		got := affectedPackageNames(ctx, t, store, "GHSA-repair-"+pkg, "npm")
		if containsString(got, pkg) {
			t.Fatalf("affected packages for GHSA-repair-%s = %v, want malformed %s skipped", pkg, got, pkg)
		}
		if !containsString(got, "ghsa-repair-anchor-ghsa-repair-"+pkg) {
			t.Fatalf("affected packages for GHSA-repair-%s = %v, want the feed-written anchor row kept", pkg, got)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func testCanonicalPackageNameSQLMirrorsPackageID(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	cases := []struct{ ecosystem, name string }{
		{"nuget", "Newtonsoft.Json"},
		{"NuGet", "NuGet.Mixed_Case"},
		{"pypi", "My.Pkg_Name"},
		{"PyPI", "a..B__c---d"},
		{"pypi", "  Spaced_Name \t"},
		{"actions", "Actions/Checkout"},
		{"GitHub Actions", "GitHub/CodeQL-Action"},
		{"npm", "@Scope/Name"},
		{"npm", " @Scope/Padded "},
		{"go", "github.com/Org/Repo"},
		{"maven", "org.Example:Artifact_ID"},
	}
	for _, tc := range cases {
		var got string
		if err := store.pool.QueryRow(ctx,
			`SELECT `+canonicalPackageNameSQL+` FROM (VALUES ($1::text, $2::text)) AS input(ecosystem, raw_name)`,
			tc.ecosystem, tc.name,
		).Scan(&got); err != nil {
			t.Fatalf("canonicalPackageNameSQL(%q, %q) error = %v", tc.ecosystem, tc.name, err)
		}
		if want := packageid.NormalizeName(tc.ecosystem, tc.name); got != want {
			t.Fatalf("canonicalPackageNameSQL(%q, %q) = %q, want packageid.NormalizeName %q", tc.ecosystem, tc.name, got, want)
		}
	}
}

func upsertGHSARepairFixture(ctx context.Context, t *testing.T, store *Store, id, rawJSON string) {
	t.Helper()

	now := time.Now().UTC()
	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:        id,
		Summary:   "GHSA repair fixture " + id,
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Sources: []db.VulnerabilitySource{{
			Source:   "ghsa",
			SourceID: id,
			RawJSON:  json.RawMessage(rawJSON),
		}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "ghsa-repair-anchor-" + strings.ToLower(id),
			VersionRanges:    json.RawMessage(`[]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}); err != nil {
		t.Fatalf("UpsertVulnerability(%s) error = %v", id, err)
	}
}

func affectedPackageNames(ctx context.Context, t *testing.T, store *Store, vulnerabilityID, ecosystem string) []string {
	t.Helper()

	rows, err := store.pool.Query(ctx, `
		SELECT name FROM affected_packages
		WHERE vulnerability_id = $1 AND ecosystem = $2
		ORDER BY name`, vulnerabilityID, ecosystem)
	if err != nil {
		t.Fatalf("query affected package names: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan affected package name: %v", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate affected package names: %v", err)
	}
	return names
}

func testGHSARepairWritesCanonicalPackageNames(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	upsertGHSARepairFixture(ctx, t, store, "GHSA-repair-canonical", `{
		"id": "GHSA-repair-canonical",
		"affected": [
			{"package": {"ecosystem": "PyPI", "name": "My.Pkg_Name"},
			 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]},
			{"package": {"ecosystem": "PyPI", "name": "my-pkg-name"},
			 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.0.0"}, {"fixed": "3.1.0"}]}]},
			{"package": {"ecosystem": "NuGet", "name": "Newtonsoft.Json"},
			 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "13.0.1"}]}]}
		]
	}`)

	if _, err := store.RepairGHSAAffectedPackages(ctx); err != nil {
		t.Fatalf("RepairGHSAAffectedPackages() error = %v", err)
	}

	if got := affectedPackageNames(ctx, t, store, "GHSA-repair-canonical", "pypi"); len(got) != 1 || got[0] != "my-pkg-name" {
		t.Fatalf("pypi affected package names = %v, want only canonical my-pkg-name", got)
	}
	if got := affectedPackageNames(ctx, t, store, "GHSA-repair-canonical", "nuget"); len(got) != 1 || got[0] != "newtonsoft.json" {
		t.Fatalf("nuget affected package names = %v, want only canonical newtonsoft.json", got)
	}

	for _, lookup := range []struct{ ecosystem, name, version string }{
		{"pypi", "My.Pkg_Name", "1.0.0"},
		{"pypi", "my_pkg.name", "3.0.5"},
		{"nuget", "Newtonsoft.Json", "12.0.0"},
	} {
		findings, err := store.FindVulnerabilities(ctx, lookup.ecosystem, lookup.name, lookup.version)
		if err != nil {
			t.Fatalf("FindVulnerabilities(%s/%s@%s) error = %v", lookup.ecosystem, lookup.name, lookup.version, err)
		}
		if !findingsContainAdvisory(findings, "GHSA-repair-canonical") {
			t.Fatalf("FindVulnerabilities(%s/%s@%s) = %+v, want repaired GHSA-repair-canonical", lookup.ecosystem, lookup.name, lookup.version, findings)
		}
	}
}

func findingsContainAdvisory(findings []domain.Finding, advisoryID string) bool {
	for _, finding := range findings {
		if finding.AdvisoryID == advisoryID {
			return true
		}
	}
	return false
}

func testScanTotalsAboveInt32AreNotNarrowed(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	now := time.Now().UTC()
	for i, scanID := range []string{"scan-bigint-1", "scan-bigint-2"} {
		if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
			ScanID:         scanID,
			ScannedAt:      now.Add(time.Duration(i) * time.Millisecond),
			BlockThreshold: "CRITICAL",
			FeedStatus:     "healthy",
			PackagesCount:  math.MaxInt32,
			FindingsCount:  math.MaxInt32,
		}); err != nil {
			t.Fatalf("InsertScanLog(%s) error = %v", scanID, err)
		}
	}
	const want = int64(2 * math.MaxInt32)

	totals, err := store.ScanTotals(ctx)
	if err != nil {
		t.Fatalf("ScanTotals() error = %v, want BIGINT totals above int32", err)
	}
	if totals.PackagesScanned < want || totals.Findings < want {
		t.Fatalf("ScanTotals() = %+v, want both totals >= %d", totals, want)
	}

	daily, err := store.CountScansByDay(ctx, 1)
	if err != nil {
		t.Fatalf("CountScansByDay(1) error = %v, want BIGINT daily findings sum", err)
	}
	if len(daily) != 1 || int64(daily[0].FindingsCount) < want || daily[0].ScanCount < 2 {
		t.Fatalf("CountScansByDay(1) = %+v, want today's findings sum >= %d over >= 2 scans", daily, want)
	}
}

func testDashboardBucketsHistoricalReputationRiskAsLow(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	before, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats(before) error = %v", err)
	}

	now := time.Now().UTC()
	rep := db.PackageReputation{
		Ecosystem:     "pypi",
		Name:          "polars-runtime-32",
		Version:       "1.40.1",
		Source:        db.ReputationSourceReversingLabs,
		Status:        "risk",
		Severity:      "HIGH",
		Summary:       "ReversingLabs: malware incident history",
		LastCheckedAt: &now,
	}
	if err := store.UpsertPackageReputation(ctx, &rep); err != nil {
		t.Fatalf("UpsertPackageReputation(risk/HIGH) error = %v", err)
	}

	// The stored provider severity stays HIGH; only the finding (and so the
	// dashboard bucket) is informational LOW.
	var storedSeverity string
	if err := store.pool.QueryRow(ctx, `
		SELECT severity FROM package_reputation_cache
		WHERE ecosystem = 'pypi' AND name = 'polars-runtime-32' AND version = '1.40.1'`).Scan(&storedSeverity); err != nil {
		t.Fatalf("read stored reputation severity: %v", err)
	}
	if storedSeverity != "HIGH" {
		t.Fatalf("stored reputation severity = %q, want HIGH preserved", storedSeverity)
	}

	findings, err := store.FindReputationFindingsBatch(ctx, []db.PackageQuery{{
		Ecosystem: "pypi", Name: "polars-runtime-32", Version: "1.40.1",
	}}, db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindingsBatch() error = %v", err)
	}
	if len(findings) != 1 || findings[0].RiskType != domain.RiskTypeMalwareHistory || findings[0].Severity != domain.SeverityLow {
		t.Fatalf("FindReputationFindingsBatch() = %+v, want one LOW malware_history finding", findings)
	}

	after, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats(after) error = %v", err)
	}
	if delta := after.BySeverity["HIGH"] - before.BySeverity["HIGH"]; delta != 0 {
		t.Fatalf("dashboard HIGH bucket delta = %d, want 0 for informational malware_history", delta)
	}
	if delta := after.BySeverity[string(findings[0].Severity)] - before.BySeverity[string(findings[0].Severity)]; delta != 1 {
		t.Fatalf("dashboard %s bucket delta = %d, want 1 matching the emitted finding severity", findings[0].Severity, delta)
	}
	if delta := after.TotalSupplyChainRisk - before.TotalSupplyChainRisk; delta != 1 {
		t.Fatalf("dashboard supply-chain total delta = %d, want 1", delta)
	}
}
