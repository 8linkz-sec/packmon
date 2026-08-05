package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// recordingLocalChecker captures what the adapter forwarded, so the tests can
// assert the translation rather than the underlying store's behaviour.
type recordingLocalChecker struct {
	ecosystem string
	name      string
	version   string
	packages  []db.PackageQuery
	source    string
	now       time.Time
	finding   domain.Finding
	err       error
}

func (c *recordingLocalChecker) result() ([]domain.Finding, error) {
	if c.err != nil {
		return nil, c.err
	}
	return []domain.Finding{c.finding}, nil
}

func (c *recordingLocalChecker) FindVulnerabilities(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	c.ecosystem, c.name, c.version = ecosystem, name, version
	return c.result()
}

func (c *recordingLocalChecker) FindMalicious(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	c.ecosystem, c.name, c.version = ecosystem, name, version
	return c.result()
}

func (c *recordingLocalChecker) FindVulnerabilitiesBatch(_ context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	c.packages = packages
	return c.result()
}

func (c *recordingLocalChecker) FindMaliciousBatch(_ context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	c.packages = packages
	return c.result()
}

func (c *recordingLocalChecker) FindReputationFindingsBatch(_ context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error) {
	c.packages, c.source = packages, source
	return c.result()
}

func (c *recordingLocalChecker) FindLifecycleFindingsBatch(_ context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error) {
	c.packages, c.now = packages, now
	return c.result()
}

// TestDBLocalCheckerAdapterForwardsSingleLookups covers the two per-package
// lookups. The adapter is the only bridge between the scanner's own port types
// and the database checker, so a swapped or dropped argument here would make
// every local scan query the wrong package.
func TestDBLocalCheckerAdapterForwardsSingleLookups(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		call func(*DBLocalCheckerAdapter, context.Context) ([]domain.Finding, error)
	}{
		{
			name: "vulnerabilities",
			call: func(a *DBLocalCheckerAdapter, ctx context.Context) ([]domain.Finding, error) {
				return a.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0")
			},
		},
		{
			name: "malicious",
			call: func(a *DBLocalCheckerAdapter, ctx context.Context) ([]domain.Finding, error) {
				return a.FindMalicious(ctx, "npm", "left-pad", "1.0.0")
			},
		},
	} {
		checker := &recordingLocalChecker{finding: domain.Finding{Name: "left-pad"}}
		adapter := NewDBLocalCheckerAdapter(checker)

		findings, err := tc.call(adapter, context.Background())
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if len(findings) != 1 || findings[0].Name != "left-pad" {
			t.Errorf("%s: findings = %+v, want the checker's result passed through", tc.name, findings)
		}
		if checker.ecosystem != "npm" || checker.name != "left-pad" || checker.version != "1.0.0" {
			t.Errorf("%s: forwarded (%q, %q, %q), want (npm, left-pad, 1.0.0)",
				tc.name, checker.ecosystem, checker.name, checker.version)
		}
	}
}

// TestDBLocalCheckerAdapterTranslatesBatchLookups covers the batch variants,
// where the adapter additionally converts the scanner's PackageLookup into the
// store's PackageQuery. Order and field mapping both matter: findings are
// correlated back to packages by these values.
func TestDBLocalCheckerAdapterTranslatesBatchLookups(t *testing.T) {
	t.Parallel()

	lookups := []PackageLookup{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"},
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name string
		call func(*DBLocalCheckerAdapter, context.Context) ([]domain.Finding, error)
	}{
		{
			name: "vulnerabilities",
			call: func(a *DBLocalCheckerAdapter, ctx context.Context) ([]domain.Finding, error) {
				return a.FindVulnerabilitiesBatch(ctx, lookups)
			},
		},
		{
			name: "malicious",
			call: func(a *DBLocalCheckerAdapter, ctx context.Context) ([]domain.Finding, error) {
				return a.FindMaliciousBatch(ctx, lookups)
			},
		},
		{
			name: "reputation",
			call: func(a *DBLocalCheckerAdapter, ctx context.Context) ([]domain.Finding, error) {
				return a.FindReputationFindingsBatch(ctx, lookups, "openssf")
			},
		},
		{
			name: "lifecycle",
			call: func(a *DBLocalCheckerAdapter, ctx context.Context) ([]domain.Finding, error) {
				return a.FindLifecycleFindingsBatch(ctx, lookups, now)
			},
		},
	} {
		checker := &recordingLocalChecker{finding: domain.Finding{Name: "left-pad"}}
		adapter := NewDBLocalCheckerAdapter(checker)

		if _, err := tc.call(adapter, context.Background()); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if len(checker.packages) != 2 {
			t.Errorf("%s: forwarded %d queries, want 2", tc.name, len(checker.packages))
			continue
		}
		if checker.packages[0] != (db.PackageQuery{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}) {
			t.Errorf("%s: first query = %+v, want the first lookup translated in order",
				tc.name, checker.packages[0])
		}
		if checker.packages[1] != (db.PackageQuery{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}) {
			t.Errorf("%s: second query = %+v, want the second lookup translated in order",
				tc.name, checker.packages[1])
		}
	}
}

// TestDBLocalCheckerAdapterPassesTheExtraBatchArguments pins the two batch calls
// that carry more than a package list. The reputation source selects which feed
// is consulted and the lifecycle timestamp decides what counts as end-of-life,
// so neither may be dropped in translation.
func TestDBLocalCheckerAdapterPassesTheExtraBatchArguments(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

	reputation := &recordingLocalChecker{}
	if _, err := NewDBLocalCheckerAdapter(reputation).
		FindReputationFindingsBatch(context.Background(), nil, "openssf"); err != nil {
		t.Fatalf("FindReputationFindingsBatch: %v", err)
	}
	if reputation.source != "openssf" {
		t.Errorf("reputation source = %q, want openssf", reputation.source)
	}

	lifecycle := &recordingLocalChecker{}
	if _, err := NewDBLocalCheckerAdapter(lifecycle).
		FindLifecycleFindingsBatch(context.Background(), nil, now); err != nil {
		t.Fatalf("FindLifecycleFindingsBatch: %v", err)
	}
	if !lifecycle.now.Equal(now) {
		t.Errorf("lifecycle now = %v, want %v", lifecycle.now, now)
	}
}

// TestDBLocalCheckerAdapterPropagatesErrors keeps a store failure visible. A
// swallowed error would present an incomplete local scan as a clean one.
func TestDBLocalCheckerAdapterPropagatesErrors(t *testing.T) {
	t.Parallel()

	lookupErr := errors.New("local database unavailable")
	adapter := NewDBLocalCheckerAdapter(&recordingLocalChecker{err: lookupErr})
	ctx := context.Background()

	for name, call := range map[string]func() ([]domain.Finding, error){
		"FindVulnerabilities": func() ([]domain.Finding, error) {
			return adapter.FindVulnerabilities(ctx, "npm", "x", "1.0.0")
		},
		"FindMalicious": func() ([]domain.Finding, error) {
			return adapter.FindMalicious(ctx, "npm", "x", "1.0.0")
		},
		"FindVulnerabilitiesBatch": func() ([]domain.Finding, error) {
			return adapter.FindVulnerabilitiesBatch(ctx, nil)
		},
		"FindMaliciousBatch": func() ([]domain.Finding, error) {
			return adapter.FindMaliciousBatch(ctx, nil)
		},
		"FindReputationFindingsBatch": func() ([]domain.Finding, error) {
			return adapter.FindReputationFindingsBatch(ctx, nil, "openssf")
		},
		"FindLifecycleFindingsBatch": func() ([]domain.Finding, error) {
			return adapter.FindLifecycleFindingsBatch(ctx, nil, time.Now())
		},
	} {
		if _, err := call(); !errors.Is(err, lookupErr) {
			t.Errorf("%s error = %v, want the store failure", name, err)
		}
	}
}

// TestPackageLookupsToDBHandlesAnEmptyList covers the conversion's edge case:
// an empty batch must produce an empty, non-nil query slice rather than a nil
// that a store might treat as "all packages".
func TestPackageLookupsToDBHandlesAnEmptyList(t *testing.T) {
	t.Parallel()

	for _, input := range [][]PackageLookup{nil, {}} {
		got := packageLookupsToDB(input)
		if got == nil {
			t.Errorf("packageLookupsToDB(%v) = nil, want an empty slice", input)
		}
		if len(got) != 0 {
			t.Errorf("packageLookupsToDB(%v) = %+v, want no queries", input, got)
		}
	}
}
