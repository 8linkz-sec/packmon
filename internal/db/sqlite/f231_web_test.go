package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF231CountScansByDayDefaultsToSevenDays(t *testing.T) {
	store := newSQLiteTestStore(t)
	fixedNow := time.Date(2026, 11, 5, 17, 30, 0, 0, time.UTC)
	originalNowUTC := nowUTC
	nowUTC = func() time.Time { return fixedNow }
	t.Cleanup(func() { nowUTC = originalNowUTC })

	for _, days := range []int{0, -4} {
		got, err := store.CountScansByDay(context.Background(), days)
		if err != nil {
			t.Fatalf("CountScansByDay(%d) error = %v", days, err)
		}
		if len(got) != 7 {
			t.Fatalf("CountScansByDay(%d) days = %d, want default 7", days, len(got))
		}
		if !got[0].Date.Equal(time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)) ||
			!got[6].Date.Equal(time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("CountScansByDay(%d) range = %v..%v, want inclusive seven-day UTC range", days, got[0].Date, got[6].Date)
		}
	}
}

func TestF231SearchPaginationNormalizesOutOfRangeOffsets(t *testing.T) {
	rows := []db.PackageSearchResult{
		{Ecosystem: "npm", Name: "bravo"},
		{Ecosystem: "npm", Name: "alpha"},
	}

	negative := limitLocalSearchResults(append([]db.PackageSearchResult(nil), rows...), 1, -5)
	if len(negative) != 1 || negative[0].Name != "alpha" {
		t.Fatalf("limitLocalSearchResults(negative offset) = %+v, want first sorted row", negative)
	}
	beyond := limitLocalSearchResults(append([]db.PackageSearchResult(nil), rows...), 10, len(rows))
	if len(beyond) != 0 || beyond == nil {
		t.Fatalf("limitLocalSearchResults(offset at end) = %#v, want non-nil empty page", beyond)
	}
}

func TestF231SecondarySearchCollectorFailuresArePropagated(t *testing.T) {
	tests := []struct {
		name     string
		contains string
		run      func(*Store) error
	}{
		{
			name:     "reputation supply-chain query",
			contains: "FROM reputation_findings_local",
			run: func(store *Store) error {
				return store.collectReputationSearchResults(context.Background(), map[searchKey]*db.PackageSearchResult{}, localPackageSearchOptions{})
			},
		},
		{
			name:     "lifecycle informational query",
			contains: "FROM lifecycle_findings",
			run: func(store *Store) error {
				return store.collectLifecycleSearchResults(context.Background(), map[searchKey]*db.PackageSearchResult{}, localPackageSearchOptions{})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			database, rule := openFaultyDB(t, tc.contains, 1)
			seedLegacySchemaOn(t, database, schemaSQL)
			store := &Store{db: database, dbPath: ":memory:"}

			err := tc.run(store)
			if !errors.Is(err, errInjectedFault) {
				t.Fatalf("collector error = %v, want injected second-query fault", err)
			}
			if !rule.didFire() {
				t.Fatal("the injected fault did not fire")
			}
		})
	}
}

func TestF231CollectSearchResultsRejectsMalformedRows(t *testing.T) {
	store := newSQLiteTestStore(t)
	results := map[searchKey]*db.PackageSearchResult{}
	err := store.collectSearchResults(context.Background(), results, "", `
		SELECT NULL, 'fixture', '', 1, 0, '', 'malicious'`)
	if err == nil || !strings.Contains(err.Error(), "scan package search row") {
		t.Fatalf("collectSearchResults() error = %v, want row scan context", err)
	}
	if len(results) != 0 {
		t.Fatalf("collectSearchResults() retained %d malformed rows", len(results))
	}
}

func TestF231CollectSeverityCountsRejectsMalformedRows(t *testing.T) {
	store := newSQLiteTestStore(t)
	counts := map[string]int{"HIGH": 2}
	err := store.collectSeverityCounts(context.Background(), counts, `SELECT 'LOW', 'not-a-count'`)
	if err == nil || !strings.Contains(err.Error(), "scan severity row") {
		t.Fatalf("collectSeverityCounts() error = %v, want row scan context", err)
	}
	if len(counts) != 1 || counts["HIGH"] != 2 {
		t.Fatalf("collectSeverityCounts() changed accumulator on malformed row: %#v", counts)
	}
}

func TestF231DashboardStatsPropagatesEveryQueryStageFailure(t *testing.T) {
	tests := []struct {
		name     string
		contains string
		skip     int
		want     string
	}{
		{name: "total vulnerabilities", contains: "COUNT(DISTINCT id)", want: "total vulnerabilities"},
		{name: "local malicious", contains: "SELECT COUNT(*) FROM malicious_local", want: "total malicious"},
		{name: "reputation malicious", contains: "FROM reputation_findings_local WHERE type = 'malicious'", want: "reputation malicious"},
		{name: "supply chain", contains: "SELECT COUNT(*) FROM reputation_findings_local WHERE type = 'supply_chain_risk'", want: "supply-chain risk"},
		{name: "lifecycle", contains: "WHERE NOT (", want: "total lifecycle"},
		{name: "vulnerability severities", contains: "GROUP BY severity", want: "dashboard severities"},
		{name: "malicious severities", contains: "GROUP BY severity", skip: 1, want: "dashboard severities"},
		{name: "reputation severities", contains: "GROUP BY severity", skip: 2, want: "dashboard severities"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			database, rule := openFaultyDB(t, tc.contains, tc.skip)
			seedLegacySchemaOn(t, database, schemaSQL)
			store := &Store{db: database, dbPath: ":memory:"}

			stats, err := store.DashboardStats(context.Background())
			if stats != nil {
				t.Fatalf("DashboardStats() stats = %+v, want nil on query failure", stats)
			}
			if !errors.Is(err, errInjectedFault) {
				t.Fatalf("DashboardStats() error = %v, want injected fault", err)
			}
			if !rule.didFire() {
				t.Fatal("the injected fault did not fire")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("DashboardStats() error = %v, want %q", err, tc.want)
			}
		})
	}
}
