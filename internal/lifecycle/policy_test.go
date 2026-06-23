package lifecycle

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestFindingForReleaseUsesCanonicalLifecyclePolicy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)
	eolFrom := now.Add(-24 * time.Hour)
	eolSoon := now.Add(30 * 24 * time.Hour)
	eoasFrom := now.Add(-24 * time.Hour)

	tests := []struct {
		name         string
		row          ReleaseRow
		wantType     domain.FindingType
		wantSeverity domain.Severity
		wantRisk     string
	}{
		{
			name: "exact eol blocks as supply-chain risk",
			row: ReleaseRow{
				ProductSlug: "django",
				ProductName: "Django",
				Release: Release{
					Cycle:   "3.2",
					EOLFrom: &eolFrom,
				},
			},
			wantType:     domain.FindingTypeSupplyChainRisk,
			wantSeverity: domain.SeverityCritical,
			wantRisk:     "eol",
		},
		{
			name: "eol soon is lifecycle medium",
			row: ReleaseRow{
				ProductSlug: "django",
				ProductName: "Django",
				Release: Release{
					Cycle:   "4.2",
					EOLFrom: &eolSoon,
				},
			},
			wantType:     domain.FindingTypeLifecycle,
			wantSeverity: domain.SeverityMedium,
			wantRisk:     "eol_soon",
		},
		{
			name: "security support only is lifecycle low",
			row: ReleaseRow{
				ProductSlug: "django",
				ProductName: "Django",
				Release: Release{
					Cycle:    "5.0",
					EOASFrom: &eoasFrom,
				},
			},
			wantType:     domain.FindingTypeLifecycle,
			wantSeverity: domain.SeverityLow,
			wantRisk:     "security_support_only",
		},
	}

	pkg := PackageQuery{Ecosystem: "pypi", Name: "django", Version: "3.2.25"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FindingForRelease(pkg, tt.row, now)
			if !ok {
				t.Fatalf("FindingForRelease() ok = false")
			}
			if got.Type != tt.wantType || got.Severity != tt.wantSeverity || got.RiskType != tt.wantRisk {
				t.Fatalf("FindingForRelease() = type %q severity %q risk %q", got.Type, got.Severity, got.RiskType)
			}
			if got.AdvisoryID == "" || got.URL != "https://endoflife.date/django" || got.Source != Source {
				t.Fatalf("FindingForRelease() identifiers = %+v", got)
			}
		})
	}
}

func TestLongestMatchingReleasesPicksMostSpecificCyclePerProduct(t *testing.T) {
	t.Parallel()

	rows := []ReleaseRow{
		{ProductSlug: "django", Release: Release{Cycle: "3"}},
		{ProductSlug: "django", Release: Release{Cycle: "3.2"}},
		{ProductSlug: "other", Release: Release{Cycle: "3"}},
		{ProductSlug: "other", Release: Release{Cycle: "4"}},
	}

	got := LongestMatchingReleases(rows, "3.2.25")
	if len(got) != 2 {
		t.Fatalf("LongestMatchingReleases() len = %d, want 2: %+v", len(got), got)
	}

	byProduct := map[string]string{}
	for _, row := range got {
		byProduct[row.ProductSlug] = row.Release.Cycle
	}
	if byProduct["django"] != "3.2" || byProduct["other"] != "3" {
		t.Fatalf("LongestMatchingReleases() = %+v", byProduct)
	}
}

func TestLifecyclePolicyIsNotDuplicatedInStoreAdapters(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"../db/postgres/lifecycle.go",
		"../db/sqlite/lifecycle.go",
	} {
		source, err := os.ReadFile(path) // #nosec G304 -- test reads fixed repository source paths.
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(source)
		for _, forbidden := range []string{
			"func lifecycleCycleMatches",
			"func lifecycleFindingForRelease",
			"func buildLifecycleFinding",
			"func dateOnOrBefore",
			"func dateWithin",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s still defines %s; use internal/lifecycle policy helpers", path, forbidden)
			}
		}
	}
}

func TestLifecyclePackageDoesNotDependOnDBDTOs(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"mapping.go", "policy.go"} {
		source, err := os.ReadFile(path) // #nosec G304 -- test reads fixed package source paths.
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(source), "internal/db") {
			t.Fatalf("%s imports internal/db; lifecycle policy and mappings should expose lifecycle-owned DTOs", path)
		}
	}
}

func TestLifecyclePolicyUsesNamedEOLSoonWindow(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("policy.go") // #nosec G304 -- test reads a fixed package source path.
	if err != nil {
		t.Fatalf("read policy.go: %v", err)
	}
	if strings.Contains(string(source), "90*24*time.Hour") || strings.Contains(string(source), "90 * 24 * time.Hour") {
		t.Fatal("policy.go inlines the EOL-soon window; use the shared lifecycle policy constant")
	}
}

func TestLifecycleSearchQueriesUsePolicyParameters(t *testing.T) {
	t.Parallel()

	checks := map[string][]string{
		"../db/postgres/admin_stats.go": {
			"INTERVAL '90 days'",
			"'CRITICAL' AS severity",
			"THEN 'MEDIUM'",
			"THEN 'LOW'",
		},
		"../db/sqlite/web.go": {
			"+90 days",
			"'CRITICAL' AS severity",
			"THEN 'MEDIUM'",
			"THEN 'LOW'",
		},
	}
	for path, forbidden := range checks {
		source, err := os.ReadFile(path) // #nosec G304 -- test reads fixed repository source paths.
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(source)
		for _, marker := range forbidden {
			if strings.Contains(text, marker) {
				t.Fatalf("%s still hard-codes lifecycle search policy marker %q", path, marker)
			}
		}
	}
}
