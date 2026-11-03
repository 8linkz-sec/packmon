package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF205UnknownFindingTypeReturnsEmptyWithoutDatabaseAccess(t *testing.T) {
	t.Parallel()

	store := &Store{}
	got, err := store.SearchPackages(context.Background(), db.PackageSearchParams{
		Query:       "ignored",
		Severity:    " high ",
		FindingType: "not-a-finding-type",
		Limit:       10,
		Offset:      -1,
	})
	if err != nil {
		t.Fatalf("SearchPackages() error = %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("SearchPackages() = %#v, want a non-nil empty result", got)
	}
}

func TestF205BlankSearchReturnsEmptyWithoutDatabaseAccess(t *testing.T) {
	t.Parallel()

	got, err := (&Store{}).SearchPackages(context.Background(), db.PackageSearchParams{})
	if err != nil {
		t.Fatalf("SearchPackages() error = %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("SearchPackages() = %#v, want a non-nil empty result", got)
	}
}

func TestF205PackageSearchTasksSkipUnknownCollector(t *testing.T) {
	t.Parallel()

	tasks := (&Store{}).packageSearchTasks([]packageSearchCollector{
		packageSearchCollector("unknown"),
	}, "%pkg%", "HIGH", 25)
	if len(tasks) != 0 {
		t.Fatalf("packageSearchTasks() returned %d tasks, want unknown collector skipped", len(tasks))
	}
}

func TestF205RunPackageSearchCollectorsSequentialContracts(t *testing.T) {
	t.Parallel()

	t.Run("merges in task order", func(t *testing.T) {
		t.Parallel()

		tasks := []packageSearchTask{
			{
				collector: packageSearchCollectorVulnerability,
				run: func(context.Context) (map[string]*db.PackageSearchResult, error) {
					return map[string]*db.PackageSearchResult{
						"npm\x00pkg\x00": {
							Ecosystem:          "npm",
							Name:               "pkg",
							FindingsCount:      1,
							VulnerabilityCount: 1,
							VulnerabilityIDs:   "CVE-2026-0001",
							Sources:            "osv",
							FindingTypes:       "vulnerability",
						},
					}, nil
				},
			},
			{
				collector: packageSearchCollectorMalicious,
				run: func(context.Context) (map[string]*db.PackageSearchResult, error) {
					return map[string]*db.PackageSearchResult{
						"npm\x00pkg\x00": {
							Ecosystem:     "npm",
							Name:          "pkg",
							FindingsCount: 2,
							Sources:       "manual",
							FindingTypes:  "malicious",
						},
					}, nil
				},
			},
		}

		got, err := runPackageSearchCollectors(context.Background(), tasks, false)
		if err != nil {
			t.Fatalf("runPackageSearchCollectors() error = %v", err)
		}
		result := got["npm\x00pkg\x00"]
		if result == nil {
			t.Fatal("runPackageSearchCollectors() omitted merged package")
		}
		if result.FindingsCount != 3 || result.VulnerabilityCount != 1 {
			t.Fatalf("merged counts = (%d, %d), want (3, 1)", result.FindingsCount, result.VulnerabilityCount)
		}
		if result.Sources != "manual, osv" || result.FindingTypes != "malicious, vulnerability" {
			t.Fatalf("merged labels = (%q, %q), want sorted unions", result.Sources, result.FindingTypes)
		}
	})

	t.Run("stops on first error", func(t *testing.T) {
		t.Parallel()

		wantErr := errors.New("first collector failed")
		secondRan := false
		tasks := []packageSearchTask{
			{
				collector: packageSearchCollectorVulnerability,
				run: func(context.Context) (map[string]*db.PackageSearchResult, error) {
					return nil, wantErr
				},
			},
			{
				collector: packageSearchCollectorMalicious,
				run: func(context.Context) (map[string]*db.PackageSearchResult, error) {
					secondRan = true
					return nil, nil
				},
			},
		}

		got, err := runPackageSearchCollectors(context.Background(), tasks, false)
		if !errors.Is(err, wantErr) {
			t.Fatalf("runPackageSearchCollectors() error = %v, want %v", err, wantErr)
		}
		if got != nil {
			t.Fatalf("runPackageSearchCollectors() results = %#v, want nil on error", got)
		}
		if secondRan {
			t.Fatal("runPackageSearchCollectors() ran a collector after the first sequential error")
		}
	})
}

func TestF205RunPackageSearchCollectorsReturnsEarliestContextError(t *testing.T) {
	t.Parallel()

	tasks := []packageSearchTask{
		{
			collector: packageSearchCollectorVulnerability,
			run: func(context.Context) (map[string]*db.PackageSearchResult, error) {
				return nil, context.DeadlineExceeded
			},
		},
		{
			collector: packageSearchCollectorMalicious,
			run: func(context.Context) (map[string]*db.PackageSearchResult, error) {
				return nil, context.Canceled
			},
		},
	}

	got, err := runPackageSearchCollectors(context.Background(), tasks, true)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runPackageSearchCollectors() error = %v, want earliest ordered context error", err)
	}
	if got != nil {
		t.Fatalf("runPackageSearchCollectors() results = %#v, want nil on error", got)
	}
}

func TestF205FinishPackageSearchResultsOffsetBoundaries(t *testing.T) {
	t.Parallel()

	results := map[string]*db.PackageSearchResult{
		"npm\x00pkg\x00": {Ecosystem: "npm", Name: "pkg", FindingsCount: 1},
	}

	negative := finishPackageSearchResults(results, 10, -5)
	want := []db.PackageSearchResult{{Ecosystem: "npm", Name: "pkg", FindingsCount: 1}}
	if !reflect.DeepEqual(negative, want) {
		t.Fatalf("finishPackageSearchResults(negative offset) = %#v, want %#v", negative, want)
	}

	exhausted := finishPackageSearchResults(results, 10, len(results))
	if exhausted == nil || len(exhausted) != 0 {
		t.Fatalf("finishPackageSearchResults(exhausted offset) = %#v, want a non-nil empty result", exhausted)
	}
}
