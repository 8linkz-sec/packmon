package main

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestNoopStorePackageSearchAggregatesAndPagesResults(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()
	withdrawn := time.Now().UTC()

	for _, vuln := range []db.Vulnerability{
		{
			ID:       "GHSA-alpha-a",
			Severity: "high",
			Sources:  []db.VulnerabilitySource{{Source: "ghsa"}},
			AffectedPackages: []db.AffectedPackage{
				{Ecosystem: "npm", Name: "alpha"},
				{Ecosystem: "npm", Name: "alpha"},
			},
		},
		{
			ID:       "GHSA-alpha-b",
			Severity: "HIGH",
			Sources:  []db.VulnerabilitySource{{Source: "manual"}},
			AffectedPackages: []db.AffectedPackage{
				{Ecosystem: "npm", Name: "alpha"},
			},
		},
		{
			ID:       "GHSA-beta",
			Severity: "HIGH",
			Sources:  []db.VulnerabilitySource{{Source: "osv"}},
			AffectedPackages: []db.AffectedPackage{
				{Ecosystem: "npm", Name: "beta"},
			},
		},
		{
			ID:        "GHSA-withdrawn",
			Severity:  "HIGH",
			Withdrawn: &withdrawn,
			AffectedPackages: []db.AffectedPackage{
				{Ecosystem: "npm", Name: "alpha"},
			},
		},
	} {
		vuln := vuln
		if err := store.UpsertVulnerability(ctx, &vuln); err != nil {
			t.Fatalf("UpsertVulnerability(%s) error = %v", vuln.ID, err)
		}
	}

	for _, finding := range []db.MaliciousFinding{
		{ID: "M-alpha", Ecosystem: "npm", Name: "alpha", Severity: "HIGH", Source: "openssf"},
		{ID: "M-gamma", Ecosystem: "npm", Name: "gamma", Severity: "HIGH", Source: "manual"},
		{ID: "M-low", Ecosystem: "npm", Name: "alpha-low", Severity: "LOW", Source: "openssf"},
	} {
		finding := finding
		if err := store.UpsertMaliciousFinding(ctx, &finding); err != nil {
			t.Fatalf("UpsertMaliciousFinding(%s) error = %v", finding.ID, err)
		}
	}

	results, err := store.SearchPackages(ctx, db.PackageSearchParams{
		Severity: " high ",
		Limit:    2,
		Offset:   1,
	})
	if err != nil {
		t.Fatalf("SearchPackages() error = %v", err)
	}

	want := []db.PackageSearchResult{
		{
			Ecosystem:          "npm",
			Name:               "beta",
			FindingsCount:      1,
			VulnerabilityCount: 1,
			VulnerabilityIDs:   "GHSA-beta",
			FindingTypes:       "vulnerability",
			Sources:            "osv",
		},
		{
			Ecosystem:     "npm",
			Name:          "gamma",
			FindingsCount: 1,
			FindingTypes:  "malicious",
			Sources:       "manual",
		},
	}
	if !reflect.DeepEqual(results, want) {
		t.Fatalf("SearchPackages() = %+v, want %+v", results, want)
	}

	vulnerabilityOnly, err := store.SearchPackages(ctx, db.PackageSearchParams{
		Query:       "ALP",
		Severity:    "HIGH",
		FindingType: "vulnerability",
		Limit:       10,
	})
	if err != nil {
		t.Fatalf("SearchPackages(vulnerability) error = %v", err)
	}
	if len(vulnerabilityOnly) != 1 {
		t.Fatalf("SearchPackages(vulnerability) len = %d, want 1: %+v", len(vulnerabilityOnly), vulnerabilityOnly)
	}
	got := vulnerabilityOnly[0]
	if got.Name != "alpha" || got.FindingsCount != 2 || got.VulnerabilityCount != 2 ||
		got.VulnerabilityIDs != "GHSA-alpha-a, GHSA-alpha-b" ||
		got.FindingTypes != "vulnerability" ||
		got.Sources != "ghsa, manual" {
		t.Fatalf("SearchPackages(vulnerability) = %+v, want deduped vulnerability aggregate", got)
	}
}
