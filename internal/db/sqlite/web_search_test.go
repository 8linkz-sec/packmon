package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

// newSearchTestStore opens a store and seeds one row in each local table, so the
// dashboard and search collectors all have something to find.
func newSearchTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := New(filepath.Join(t.TempDir(), "packmon.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	for _, statement := range []string{
		`INSERT INTO vulnerabilities_local (row_key, id, ecosystem, name, severity, source)
		 VALUES ('vk1', 'GHSA-1', 'npm', 'fixture-vuln', 'HIGH', 'osv')`,
		`INSERT INTO malicious_local (id, ecosystem, name, risk_type, severity, source)
		 VALUES ('MAL-1', 'npm', 'fixture-malicious', 'malware', 'CRITICAL', 'socket')`,
		`INSERT INTO reputation_findings_local (id, ecosystem, name, version, type, risk_type, severity)
		 VALUES ('REP-1', 'npm', 'fixture-rep-malicious', '1.0.0', 'malicious', 'malware', 'CRITICAL')`,
		`INSERT INTO reputation_findings_local (id, ecosystem, name, version, type, risk_type, severity)
		 VALUES ('REP-2', 'npm', 'fixture-rep-supply', '1.0.0', 'supply_chain_risk', 'supply_chain', 'MEDIUM')`,
		`INSERT INTO lifecycle_releases_local (id, ecosystem, name, product_slug, cycle, latest, is_eol)
		 VALUES ('LC-1', 'npm', 'fixture-eol', 'nodejs', '14', '14.21.3', 1)`,
	} {
		if _, err := store.DB().Exec(statement); err != nil {
			t.Fatalf("seed row: %v\n%s", err, statement)
		}
	}
	return store
}

// SearchPackages requires at least one filter -- an empty query, severity and
// type deliberately return nothing. Every fixture therefore shares this prefix so
// a single name query can reach all four collectors.
const searchFixturePrefix = "fixture"

// dbPackageSearchParams builds the search parameters in one place so the tests
// stay readable.
func dbPackageSearchParams(query, severity, findingType string, limit, offset int) db.PackageSearchParams {
	return db.PackageSearchParams{
		Query:       query,
		Severity:    severity,
		FindingType: findingType,
		Limit:       limit,
		Offset:      offset,
	}
}

// TestSearchPackagesFindsEverySourceTable covers the local package search across
// all four collectors. Each table is a separate query merged into one result set,
// so a collector that never runs silently hides a whole class of finding from the
// local dashboard.
func TestSearchPackagesFindsEverySourceTable(t *testing.T) {
	t.Parallel()

	store := newSearchTestStore(t)
	ctx := context.Background()

	results, err := store.SearchPackages(ctx, dbPackageSearchParams(searchFixturePrefix, "", "", 50, 0))
	if err != nil {
		t.Fatalf("SearchPackages: %v", err)
	}

	found := map[string]bool{}
	for _, result := range results {
		found[result.Name] = true
	}
	for _, name := range []string{
		"fixture-vuln", "fixture-malicious", "fixture-rep-malicious",
		"fixture-rep-supply", "fixture-eol",
	} {
		if !found[name] {
			t.Errorf("search did not find %q; results were %v", name, found)
		}
	}
}

// TestSearchPackagesFiltersByFindingType pins the type filter. Each collector
// declares which types it can answer for, so a wrong gate either returns rows the
// user filtered out or drops rows they asked for.
func TestSearchPackagesFiltersByFindingType(t *testing.T) {
	t.Parallel()

	store := newSearchTestStore(t)
	ctx := context.Background()

	malicious, err := store.SearchPackages(ctx, dbPackageSearchParams(searchFixturePrefix, "", "malicious", 50, 0))
	if err != nil {
		t.Fatalf("SearchPackages(malicious): %v", err)
	}
	for _, result := range malicious {
		if !strings.Contains(result.FindingTypes, "malicious") {
			t.Errorf("malicious filter returned %q with types %q", result.Name, result.FindingTypes)
		}
	}
	if len(malicious) == 0 {
		t.Error("the malicious filter returned nothing although a malicious row exists")
	}

	supplyChain, err := store.SearchPackages(ctx, dbPackageSearchParams(searchFixturePrefix, "", "supply_chain_risk", 50, 0))
	if err != nil {
		t.Fatalf("SearchPackages(supply_chain_risk): %v", err)
	}
	names := map[string]bool{}
	for _, result := range supplyChain {
		names[result.Name] = true
		if !strings.Contains(result.FindingTypes, "supply_chain_risk") {
			t.Errorf("supply-chain filter returned %q with types %q", result.Name, result.FindingTypes)
		}
	}
	// Both the reputation and the lifecycle collector answer for this type.
	if !names["fixture-rep-supply"] || !names["fixture-eol"] {
		t.Errorf("supply-chain filter results = %v, want both the reputation and lifecycle rows", names)
	}
}

// TestSearchPackagesFiltersByNameAndSeverity covers the two remaining filters,
// which every collector applies independently -- one collector ignoring a filter
// would leak rows the user excluded.
func TestSearchPackagesFiltersByNameAndSeverity(t *testing.T) {
	t.Parallel()

	store := newSearchTestStore(t)
	ctx := context.Background()

	byName, err := store.SearchPackages(ctx, dbPackageSearchParams("fixture-vuln", "", "", 50, 0))
	if err != nil {
		t.Fatalf("SearchPackages(name): %v", err)
	}
	for _, result := range byName {
		if !strings.Contains(strings.ToLower(result.Name), "fixture-vuln") {
			t.Errorf("name filter returned %q", result.Name)
		}
	}
	if len(byName) == 0 {
		t.Error("the name filter returned nothing although the fixture exists")
	}

	bySeverity, err := store.SearchPackages(ctx, dbPackageSearchParams(searchFixturePrefix, "CRITICAL", "", 50, 0))
	if err != nil {
		t.Fatalf("SearchPackages(severity): %v", err)
	}
	names := map[string]bool{}
	for _, result := range bySeverity {
		names[result.Name] = true
	}
	if names["fixture-vuln"] {
		t.Error("the CRITICAL filter returned a HIGH-severity package")
	}
	if !names["fixture-malicious"] {
		t.Error("the CRITICAL filter dropped a CRITICAL package")
	}
}

// TestSearchPackagesHonoursLimitAndOffset covers paging over the merged result
// set. The collectors each over-fetch so the merged set can still serve a later
// page; a wrong budget makes page two come back empty.
func TestSearchPackagesHonoursLimitAndOffset(t *testing.T) {
	t.Parallel()

	store := newSearchTestStore(t)
	ctx := context.Background()

	all, err := store.SearchPackages(ctx, dbPackageSearchParams(searchFixturePrefix, "", "", 50, 0))
	if err != nil {
		t.Fatalf("SearchPackages: %v", err)
	}
	if len(all) < 3 {
		t.Fatalf("fixture produced %d results, want at least 3 for a paging test", len(all))
	}

	first, err := store.SearchPackages(ctx, dbPackageSearchParams(searchFixturePrefix, "", "", 2, 0))
	if err != nil {
		t.Fatalf("SearchPackages(page 1): %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("page 1 holds %d results, want 2", len(first))
	}

	second, err := store.SearchPackages(ctx, dbPackageSearchParams(searchFixturePrefix, "", "", 2, 2))
	if err != nil {
		t.Fatalf("SearchPackages(page 2): %v", err)
	}
	if len(second) == 0 {
		t.Fatal("page 2 is empty although more results exist")
	}
	for _, a := range first {
		for _, b := range second {
			if a.Ecosystem == b.Ecosystem && a.Name == b.Name && a.Version == b.Version {
				t.Errorf("package %s appears on both pages", a.Name)
			}
		}
	}
}

// TestDashboardStatsCountsEverySourceTable covers the local dashboard aggregate.
// Malicious findings come from two tables and supply-chain risk from two more, so
// a missing term understates exactly the numbers an operator acts on.
func TestDashboardStatsCountsEverySourceTable(t *testing.T) {
	t.Parallel()

	store := newSearchTestStore(t)

	stats, err := store.DashboardStats(context.Background())
	if err != nil {
		t.Fatalf("DashboardStats: %v", err)
	}
	if stats == nil {
		t.Fatal("DashboardStats returned nothing")
	}

	if stats.TotalVulnerabilities != 1 {
		t.Errorf("TotalVulnerabilities = %d, want 1", stats.TotalVulnerabilities)
	}
	// One row in malicious_local plus one reputation row of type malicious.
	if stats.TotalMalicious != 2 {
		t.Errorf("TotalMalicious = %d, want both tables counted", stats.TotalMalicious)
	}
	// One reputation supply-chain row plus one end-of-life lifecycle row.
	if stats.TotalSupplyChainRisk != 2 {
		t.Errorf("TotalSupplyChainRisk = %d, want both tables counted", stats.TotalSupplyChainRisk)
	}
	// The vulnerability and malicious fixtures are distinct packages.
	if stats.TotalPackages != 2 {
		t.Errorf("TotalPackages = %d, want the union of the two package tables", stats.TotalPackages)
	}
}

// TestDashboardStatsOnAnEmptyDatabaseReportsZeros covers a freshly initialised
// local cache: the dashboard must render zeros rather than fail, because that is
// the state before the first sync.
func TestDashboardStatsOnAnEmptyDatabaseReportsZeros(t *testing.T) {
	t.Parallel()

	store, err := New(filepath.Join(t.TempDir(), "packmon.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	stats, err := store.DashboardStats(context.Background())
	if err != nil {
		t.Fatalf("DashboardStats: %v", err)
	}
	if stats.TotalPackages != 0 || stats.TotalVulnerabilities != 0 ||
		stats.TotalMalicious != 0 || stats.TotalSupplyChainRisk != 0 {
		t.Fatalf("stats = %+v, want all zeros on an empty database", stats)
	}
	if stats.BySeverity == nil {
		t.Error("BySeverity is nil, want an initialised map the template can range over")
	}
}
