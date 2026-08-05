package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// newClosedStore returns a store whose database has been closed. Every query
// against it fails at the driver, which is how these tests reach the error
// branches after each SQL call without a fake driver.
func newClosedStore(t *testing.T) *Store {
	t.Helper()

	store, err := New(filepath.Join(t.TempDir(), "packmon.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return store
}

// TestClosedStoreNeverReportsAnEmptyFindingSet is the security-relevant contract
// behind all of these branches. If a lookup against an unusable database
// returned no findings and no error, a local scan would present a broken cache
// as a clean result -- the worst possible failure mode for a security scanner.
func TestClosedStoreNeverReportsAnEmptyFindingSet(t *testing.T) {
	t.Parallel()

	store := newClosedStore(t)
	ctx := context.Background()
	packages := []db.PackageQuery{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}}

	for name, call := range map[string]func() ([]domain.Finding, error){
		"FindVulnerabilities": func() ([]domain.Finding, error) {
			return store.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0")
		},
		"FindVulnerabilitiesBatch": func() ([]domain.Finding, error) {
			return store.FindVulnerabilitiesBatch(ctx, packages)
		},
		"FindMalicious": func() ([]domain.Finding, error) {
			return store.FindMalicious(ctx, "npm", "evil-pkg", "1.0.0")
		},
		"FindMaliciousBatch": func() ([]domain.Finding, error) {
			return store.FindMaliciousBatch(ctx, packages)
		},
		// The local cache only holds ReversingLabs reputation data, so this is
		// the one source that actually reaches the database -- see the sibling
		// test for the deliberate short-circuit on every other source.
		"FindReputationFindings": func() ([]domain.Finding, error) {
			return store.FindReputationFindings(ctx, "npm", "left-pad", "reversinglabs")
		},
		"FindReputationFindingsBatch": func() ([]domain.Finding, error) {
			return store.FindReputationFindingsBatch(ctx, packages, "reversinglabs")
		},
		"FindLifecycleFindingsBatch": func() ([]domain.Finding, error) {
			return store.FindLifecycleFindingsBatch(ctx, packages, time.Now().UTC())
		},
	} {
		findings, err := call()
		if err == nil {
			t.Errorf("%s on a closed database = %d findings, nil; want an error", name, len(findings))
		}
	}
}

// TestClosedStoreReportsReadFailures covers the remaining read paths. Each backs
// a dashboard or report surface, and each must fail loudly rather than render an
// empty page that looks like real data.
func TestClosedStoreReportsReadFailures(t *testing.T) {
	t.Parallel()

	store := newClosedStore(t)
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"HasAdvisoryData": func() error {
			_, err := store.HasAdvisoryData(ctx)
			return err
		},
		"ListRecentScans": func() error {
			_, err := store.ListRecentScans(ctx, 10, 0)
			return err
		},
		"CountScansByDay": func() error {
			_, err := store.CountScansByDay(ctx, 7)
			return err
		},
		"SearchPackages": func() error {
			_, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "left", Limit: 10})
			return err
		},
		"DashboardStats": func() error {
			_, err := store.DashboardStats(ctx)
			return err
		},
		"GetRecentScans": func() error {
			_, err := store.GetRecentScans(ctx, "", 10)
			return err
		},
		"LocalDatabaseCounts": func() error {
			_, err := store.LocalDatabaseCounts(ctx)
			return err
		},
		"GetSyncMeta": func() error {
			_, err := store.GetSyncMeta(ctx, "last_sync")
			return err
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s on a closed database = nil error, want a failure", name)
		}
	}
}

// TestClosedStoreReportsWriteFailures covers the write paths. A silently dropped
// history row or sync marker would make the CLI believe it recorded state it
// never did, which then shows up as a wrong freshness warning.
func TestClosedStoreReportsWriteFailures(t *testing.T) {
	t.Parallel()

	store := newClosedStore(t)
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"InsertScan": func() error {
			return store.InsertScan(ctx, ScanEntry{
				RepoName:      "packmon",
				ScannedAt:     time.Now().UTC(),
				PackagesCount: 1,
			})
		},
		"ClearHistory": func() error {
			_, err := store.ClearHistory(ctx, nil, "")
			return err
		},
		"EnforceRetention": func() error {
			return store.EnforceRetention(ctx, 10)
		},
		"SetSyncMeta": func() error {
			return store.SetSyncMeta(ctx, "last_sync", time.Now().UTC().Format(time.RFC3339))
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s on a closed database = nil error, want a failure", name)
		}
	}
}

// TestClosedStoreReportsStreamFailures covers the local export streams, which
// back `packmon db export`. A stream that ends without error on a broken cache
// would write a truncated export the user would take as complete.
func TestClosedStoreReportsStreamFailures(t *testing.T) {
	t.Parallel()

	store := newClosedStore(t)
	ctx := context.Background()

	emitted := 0
	for name, call := range map[string]func() error{
		"StreamLocalVulnerabilities": func() error {
			return store.StreamLocalVulnerabilities(ctx, func(LocalVulnerabilityEntry) error {
				emitted++
				return nil
			})
		},
		"StreamLocalMalicious": func() error {
			return store.StreamLocalMalicious(ctx, func(LocalMaliciousEntry) error {
				emitted++
				return nil
			})
		},
		"StreamLocalReputation": func() error {
			return store.StreamLocalReputation(ctx, func(LocalReputationEntry) error {
				emitted++
				return nil
			})
		},
		"StreamLocalLifecycle": func() error {
			return store.StreamLocalLifecycle(ctx, func(LocalLifecycleEntry) error {
				emitted++
				return nil
			})
		},
		"StreamLocalScanHistory": func() error {
			return store.StreamLocalScanHistory(ctx, func(ScanEntry) error {
				emitted++
				return nil
			})
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s on a closed database = nil error, want a failure", name)
		}
	}
	if emitted != 0 {
		t.Fatalf("the streams emitted %d rows from a closed database", emitted)
	}
}

// TestReputationLookupsShortCircuitForForeignSources pins a deliberate exception
// to the rule above. `reputation_findings_local` has no source column: the local
// cache only ever holds ReversingLabs data. Asking it for another source is
// therefore answered with "nothing" without a query -- and must stay that way
// even when the database is unusable, because there was never anything to read.
func TestReputationLookupsShortCircuitForForeignSources(t *testing.T) {
	t.Parallel()

	store := newClosedStore(t)
	ctx := context.Background()
	packages := []db.PackageQuery{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}}

	for _, source := range []string{"openssf", "socket", "osv"} {
		findings, err := store.FindReputationFindings(ctx, "npm", "left-pad", source)
		if err != nil || len(findings) != 0 {
			t.Errorf("FindReputationFindings(%q) = %d findings, %v; want no query at all",
				source, len(findings), err)
		}
		findings, err = store.FindReputationFindingsBatch(ctx, packages, source)
		if err != nil || len(findings) != 0 {
			t.Errorf("FindReputationFindingsBatch(%q) = %d findings, %v; want no query at all",
				source, len(findings), err)
		}
	}

	// An empty package list is likewise answered without touching the database.
	if findings, err := store.FindReputationFindingsBatch(ctx, nil, "reversinglabs"); err != nil || len(findings) != 0 {
		t.Errorf("FindReputationFindingsBatch(no packages) = %d findings, %v; want no query", len(findings), err)
	}
}

// TestStreamsPropagateAConsumerFailure is the other half of the stream contract:
// when the caller's emit function fails -- a full disk while writing the export
// -- the stream must stop and surface that error rather than keep reading rows.
func TestStreamsPropagateAConsumerFailure(t *testing.T) {
	t.Parallel()

	store := newSearchTestStore(t)
	ctx := context.Background()
	consumerErr := errTestConsumer("export destination is full")

	for name, call := range map[string]func() error{
		"StreamLocalVulnerabilities": func() error {
			return store.StreamLocalVulnerabilities(ctx, func(LocalVulnerabilityEntry) error { return consumerErr })
		},
		"StreamLocalMalicious": func() error {
			return store.StreamLocalMalicious(ctx, func(LocalMaliciousEntry) error { return consumerErr })
		},
		"StreamLocalReputation": func() error {
			return store.StreamLocalReputation(ctx, func(LocalReputationEntry) error { return consumerErr })
		},
		"StreamLocalLifecycle": func() error {
			return store.StreamLocalLifecycle(ctx, func(LocalLifecycleEntry) error { return consumerErr })
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s ignored a failing consumer", name)
		}
	}
}

type errTestConsumer string

func (e errTestConsumer) Error() string { return string(e) }
