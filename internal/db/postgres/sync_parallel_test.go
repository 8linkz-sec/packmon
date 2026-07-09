package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestExportSyncDatasetsRunsEnabledQueriesInParallel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	started := make(chan string, 4)
	release := make(chan struct{})
	snapshot := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	opts := db.SyncExportOptions{Limit: 1}
	cursor := db.SyncCursor{}

	resultCh := make(chan syncDatasetResult, 1)
	go func() {
		result, err := exportSyncDatasets(ctx, opts, cursor, snapshot, 42, syncDatasetExporters{
			vulnerabilities: func(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) ([]db.SyncVulnerability, error) {
				if err := waitForParallelExportRelease(ctx, started, release, "vulnerabilities"); err != nil {
					return nil, err
				}
				return []db.SyncVulnerability{{ID: "CVE-2026-0001", Ecosystem: "npm", Name: "vuln-pkg"}}, nil
			},
			malicious: func(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) ([]db.SyncMalicious, error) {
				if err := waitForParallelExportRelease(ctx, started, release, "malicious"); err != nil {
					return nil, err
				}
				return []db.SyncMalicious{{ID: "MAL-2026-0001", Ecosystem: "npm", Name: "bad-pkg"}}, nil
			},
			reputation: func(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) ([]db.SyncReputationFinding, error) {
				if err := waitForParallelExportRelease(ctx, started, release, "reputation"); err != nil {
					return nil, err
				}
				return []db.SyncReputationFinding{{ID: "reputation:npm:removed-pkg:1.0.0", Ecosystem: "npm", Name: "removed-pkg", Version: "1.0.0"}}, nil
			},
			lifecycle: func(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) ([]db.SyncLifecycleRelease, error) {
				if err := waitForParallelExportRelease(ctx, started, release, "lifecycle"); err != nil {
					return nil, err
				}
				return []db.SyncLifecycleRelease{{ID: "endoflife:npm:old-pkg:old-pkg:1", Ecosystem: "npm", Name: "old-pkg", ProductSlug: "old-pkg", Cycle: "1"}}, nil
			},
		})
		resultCh <- syncDatasetResult{datasets: result, err: err}
	}()

	seen := make(map[string]bool, 4)
	for len(seen) < 4 {
		select {
		case name := <-started:
			seen[name] = true
		case <-time.After(250 * time.Millisecond):
			close(release)
			t.Fatalf("started exporters = %v, want all four exporters before release", seen)
		}
	}
	close(release)

	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("exportSyncDatasets() error = %v", result.err)
		}
		if len(result.datasets.vulnerabilities) != 1 ||
			len(result.datasets.malicious) != 1 ||
			len(result.datasets.reputation) != 1 ||
			len(result.datasets.lifecycle) != 1 {
			t.Fatalf("exportSyncDatasets() result lengths = vulns:%d malicious:%d reputation:%d lifecycle:%d, want one row each",
				len(result.datasets.vulnerabilities),
				len(result.datasets.malicious),
				len(result.datasets.reputation),
				len(result.datasets.lifecycle),
			)
		}
	case <-ctx.Done():
		t.Fatal("exportSyncDatasets() did not return after blocked exporters were released")
	}
}

type syncDatasetResult struct {
	datasets syncDatasets
	err      error
}

func waitForParallelExportRelease(ctx context.Context, started chan<- string, release <-chan struct{}, name string) error {
	select {
	case started <- name:
	case <-ctx.Done():
		return fmt.Errorf("%s exporter start: %w", name, ctx.Err())
	}

	select {
	case <-release:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s exporter release: %w", name, ctx.Err())
	}
}
