package web

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// baseDBStore implements only the mandatory DBStore surface. It stands for a
// store without the optional reputation and lifecycle capabilities.
type baseDBStore struct {
	stats     *db.DashboardStatsResult
	daily     []db.DailyScanStats
	scans     []db.ScanLogEntry
	search    []db.PackageSearchResult
	vulns     []domain.Finding
	malicious []domain.Finding
	feeds     []db.FeedSyncStatus
	recent    []db.RecentVulnerability
	err       error

	gotSearchParams db.PackageSearchParams
	gotVulnArgs     [3]string
}

func (s *baseDBStore) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
	return s.stats, s.err
}

func (s *baseDBStore) CountScansByDay(_ context.Context, _ int) ([]db.DailyScanStats, error) {
	return s.daily, s.err
}

func (s *baseDBStore) ListRecentScans(_ context.Context, _, _ int) ([]db.ScanLogEntry, error) {
	return s.scans, s.err
}

func (s *baseDBStore) SearchPackages(_ context.Context, params db.PackageSearchParams) ([]db.PackageSearchResult, error) {
	s.gotSearchParams = params
	return s.search, s.err
}

func (s *baseDBStore) FindVulnerabilities(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	s.gotVulnArgs = [3]string{ecosystem, name, version}
	return s.vulns, s.err
}

func (s *baseDBStore) FindMalicious(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	return s.malicious, s.err
}

func (s *baseDBStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	return s.feeds, s.err
}

func (s *baseDBStore) ListRecentVulnerabilities(_ context.Context, _, _ int) ([]db.RecentVulnerability, error) {
	return s.recent, s.err
}

// capableDBStore adds the three optional capabilities on top.
type capableDBStore struct {
	*baseDBStore
	reputation      []domain.Finding
	reputationBatch []domain.Finding
	lifecycleBatch  []domain.Finding
}

func (s capableDBStore) FindReputationFindings(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	return s.reputation, nil
}

func (s capableDBStore) FindReputationFindingsBatch(_ context.Context, _ []db.PackageQuery, _ string) ([]domain.Finding, error) {
	return s.reputationBatch, nil
}

func (s capableDBStore) FindLifecycleFindingsBatch(_ context.Context, _ []db.PackageQuery, _ time.Time) ([]domain.Finding, error) {
	return s.lifecycleBatch, nil
}

// TestDBStoreAdapterRejectsNilStore keeps a missing store from being wrapped
// into a non-nil interface value, which would turn every later call into a nil
// dereference deep inside a request handler.
func TestDBStoreAdapterRejectsNilStore(t *testing.T) {
	t.Parallel()

	if got := NewDBStoreAdapter(nil); got != nil {
		t.Fatalf("NewDBStoreAdapter(nil) = %#v, want nil", got)
	}
}

// TestDBStoreAdapterDegradesWithoutOptionalCapabilities is the behaviour that
// matters most here: a store lacking reputation or lifecycle support must yield
// a named error, not panic. The public package page calls these on every render.
func TestDBStoreAdapterDegradesWithoutOptionalCapabilities(t *testing.T) {
	t.Parallel()

	adapter := NewDBStoreAdapter(&baseDBStore{})
	if adapter == nil {
		t.Fatal("NewDBStoreAdapter returned nil for a valid store")
	}
	ctx := context.Background()

	if _, err := adapter.FindReputationFindings(ctx, "npm", "left-pad", "socket"); !errors.Is(err, errMissingReputationLookup) {
		t.Fatalf("FindReputationFindings error = %v, want errMissingReputationLookup", err)
	}
	if _, err := adapter.FindReputationFindingsBatch(ctx, nil, "socket"); !errors.Is(err, errMissingReputationBatchLookup) {
		t.Fatalf("FindReputationFindingsBatch error = %v, want errMissingReputationBatchLookup", err)
	}
	if _, err := adapter.FindLifecycleFindingsBatch(ctx, nil, time.Now()); !errors.Is(err, errMissingLifecycleBatchLookup) {
		t.Fatalf("FindLifecycleFindingsBatch error = %v, want errMissingLifecycleBatchLookup", err)
	}
}

// TestDBStoreAdapterUsesOptionalCapabilitiesWhenPresent is the counterpart: a
// capable store must actually be used, not silently treated as incapable.
func TestDBStoreAdapterUsesOptionalCapabilitiesWhenPresent(t *testing.T) {
	t.Parallel()

	want := []domain.Finding{{Name: "left-pad", Ecosystem: domain.EcosystemNPM}}
	adapter := NewDBStoreAdapter(capableDBStore{
		baseDBStore:     &baseDBStore{},
		reputation:      want,
		reputationBatch: want,
		lifecycleBatch:  want,
	})
	ctx := context.Background()

	for name, call := range map[string]func() ([]domain.Finding, error){
		"FindReputationFindings": func() ([]domain.Finding, error) {
			return adapter.FindReputationFindings(ctx, "npm", "left-pad", "socket")
		},
		"FindReputationFindingsBatch": func() ([]domain.Finding, error) {
			return adapter.FindReputationFindingsBatch(ctx, []db.PackageQuery{{Name: "left-pad"}}, "socket")
		},
		"FindLifecycleFindingsBatch": func() ([]domain.Finding, error) {
			return adapter.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{{Name: "left-pad"}}, time.Now())
		},
	} {
		got, err := call()
		if err != nil {
			t.Fatalf("%s error = %v", name, err)
		}
		if len(got) != 1 || got[0].Name != "left-pad" {
			t.Fatalf("%s = %+v, want the store's findings", name, got)
		}
	}
}

// TestDBStoreAdapterPassesThroughArgumentsAndErrors checks that the adapter
// really delegates rather than inventing values, in both directions.
func TestDBStoreAdapterPassesThroughArgumentsAndErrors(t *testing.T) {
	t.Parallel()

	store := &baseDBStore{
		stats:     &db.DashboardStatsResult{},
		daily:     []db.DailyScanStats{{}},
		scans:     []db.ScanLogEntry{{ScanID: "scan-1"}},
		vulns:     []domain.Finding{{Name: "left-pad"}},
		malicious: []domain.Finding{{Name: "evil"}},
		feeds:     []db.FeedSyncStatus{{FeedName: "osv"}},
		recent:    []db.RecentVulnerability{{}},
	}
	adapter := NewDBStoreAdapter(store)
	ctx := context.Background()

	if _, err := adapter.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0"); err != nil {
		t.Fatalf("FindVulnerabilities error = %v", err)
	}
	if store.gotVulnArgs != [3]string{"npm", "left-pad", "1.0.0"} {
		t.Fatalf("FindVulnerabilities forwarded %v, want the caller's arguments", store.gotVulnArgs)
	}
	if scans, err := adapter.ListRecentScans(ctx, 10, 0); err != nil || len(scans) != 1 || scans[0].ScanID != "scan-1" {
		t.Fatalf("ListRecentScans = %+v, %v", scans, err)
	}
	if feeds, err := adapter.ListFeedSyncStatuses(ctx); err != nil || len(feeds) != 1 {
		t.Fatalf("ListFeedSyncStatuses = %+v, %v", feeds, err)
	}
	for name, call := range map[string]func() error{
		"DashboardStats":            func() error { _, err := adapter.DashboardStats(ctx); return err },
		"CountScansByDay":           func() error { _, err := adapter.CountScansByDay(ctx, 7); return err },
		"FindMalicious":             func() error { _, err := adapter.FindMalicious(ctx, "npm", "evil", "1.0.0"); return err },
		"ListRecentVulnerabilities": func() error { _, err := adapter.ListRecentVulnerabilities(ctx, 7, 10); return err },
	} {
		if err := call(); err != nil {
			t.Fatalf("%s error = %v", name, err)
		}
	}

	// The same calls must surface a store failure instead of swallowing it.
	failing := NewDBStoreAdapter(&baseDBStore{err: errors.New("store down")})
	if _, err := failing.DashboardStats(ctx); err == nil {
		t.Fatal("DashboardStats error = nil, want the store failure propagated")
	}
	if _, err := failing.SearchPackages(ctx, PackageSearchParams{}); err == nil {
		t.Fatal("SearchPackages error = nil, want the store failure propagated")
	}
}

// TestDBStoreAdapterMapsSearchParamsAndResults pins the one method that does
// more than delegate: it translates between the web and database DTOs.
func TestDBStoreAdapterMapsSearchParamsAndResults(t *testing.T) {
	t.Parallel()

	store := &baseDBStore{
		search: []db.PackageSearchResult{{
			Ecosystem:          "npm",
			Name:               "left-pad",
			Version:            "1.0.0",
			FindingsCount:      3,
			VulnerabilityCount: 2,
			VulnerabilityIDs:   "GHSA-1",
			FindingTypes:       "vulnerability",
			Sources:            "osv",
		}},
	}
	adapter := NewDBStoreAdapter(store)

	got, err := adapter.SearchPackages(context.Background(), PackageSearchParams{
		Query:       "left",
		Severity:    "HIGH",
		FindingType: "vulnerability",
		Limit:       25,
		Offset:      50,
	})
	if err != nil {
		t.Fatalf("SearchPackages error = %v", err)
	}

	if store.gotSearchParams.Query != "left" || store.gotSearchParams.Severity != "HIGH" ||
		store.gotSearchParams.FindingType != "vulnerability" ||
		store.gotSearchParams.Limit != 25 || store.gotSearchParams.Offset != 50 {
		t.Fatalf("forwarded params = %+v, want every filter preserved", store.gotSearchParams)
	}
	if len(got) != 1 {
		t.Fatalf("SearchPackages returned %d results, want 1", len(got))
	}
	result := got[0]
	if result.Name != "left-pad" || result.Ecosystem != "npm" || result.Version != "1.0.0" ||
		result.FindingsCount != 3 || result.VulnerabilityCount != 2 ||
		result.VulnerabilityIDs != "GHSA-1" || result.FindingTypes != "vulnerability" || result.Sources != "osv" {
		t.Fatalf("mapped result = %+v, want every field carried over", result)
	}
}

// TestDBStoreAdapterMapsEmptySearchResultsToNil documents the empty case, so a
// template ranging over the result cannot trip over a zero-length slice policy
// change unnoticed.
func TestDBStoreAdapterMapsEmptySearchResultsToNil(t *testing.T) {
	t.Parallel()

	adapter := NewDBStoreAdapter(&baseDBStore{})
	got, err := adapter.SearchPackages(context.Background(), PackageSearchParams{Query: "none"})
	if err != nil {
		t.Fatalf("SearchPackages error = %v", err)
	}
	if got != nil {
		t.Fatalf("SearchPackages = %+v, want nil for an empty result set", got)
	}
}
