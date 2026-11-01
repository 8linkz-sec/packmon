package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/parser"
	"github.com/8linkz-sec/packmon/internal/scanner"
)

const coverageParityAdvisory = "GHSA-cove-rage-move"

// coverageParityStore simulates a server-side coverage move of one advisory:
// the check path matches the advisory against its current affected packages,
// and the sync path exports it like the PostgreSQL exporter does -- a
// single-page delta includes a changed advisory with its complete current
// affected set and says so with VulnerabilityAffectedComplete.
type coverageParityStore struct {
	stubStore

	coverageMu sync.Mutex
	affected   []string
	changedAt  time.Time
}

func (s *coverageParityStore) moveCoverage(names ...string) {
	s.coverageMu.Lock()
	defer s.coverageMu.Unlock()
	s.affected = names
	s.changedAt = time.Now().UTC()
}

func (s *coverageParityStore) FindVulnerabilitiesBatch(_ context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	s.coverageMu.Lock()
	defer s.coverageMu.Unlock()
	var findings []domain.Finding
	for _, pkg := range packages {
		if pkg.Ecosystem != string(domain.EcosystemNPM) || !slices.Contains(s.affected, pkg.Name) {
			continue
		}
		findings = append(findings, domain.Finding{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Ecosystem:  domain.EcosystemNPM,
			Type:       domain.FindingTypeVulnerability,
			Severity:   domain.SeverityHigh,
			AdvisoryID: coverageParityAdvisory,
			Title:      "coverage move fixture",
			Source:     "manual",
		})
	}
	return findings, nil
}

func (s *coverageParityStore) ExportSync(_ context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	s.coverageMu.Lock()
	defer s.coverageMu.Unlock()
	// Like the PostgreSQL exporter, only a single-page delta (since window)
	// promises complete affected sets; this store never paginates.
	export := &db.SyncExport{
		SyncedAt:                      time.Now().UTC().Add(-time.Second),
		VulnerabilityAffectedComplete: opts.Since != nil,
	}
	if opts.Since != nil && s.changedAt.Before(*opts.Since) {
		return export, nil
	}
	for _, name := range s.affected {
		export.Vulnerabilities = append(export.Vulnerabilities, db.SyncVulnerability{
			ID:               coverageParityAdvisory,
			Ecosystem:        string(domain.EcosystemNPM),
			Name:             name,
			VersionRanges:    `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`,
			VersionsAffected: `[]`,
			References:       `[]`,
			Severity:         string(domain.SeverityHigh),
			Summary:          "coverage move fixture",
			Source:           "manual",
		})
	}
	return export, nil
}

// TestCoverageParityLocalScanMatchesRemoteCheckAfterCoverageMove syncs an
// advisory affecting left-pad into the local SQLite database, then moves its
// coverage to right-pad on the server (a manual advisory edit or a
// package-name repair). After the next delta sync, a local scan must report
// the advisory for exactly the packages a remote /api/v1/check reports it for.
func TestCoverageParityLocalScanMatchesRemoteCheckAfterCoverageMove(t *testing.T) {
	t.Parallel()

	store := &coverageParityStore{}
	store.moveCoverage("left-pad")
	h := newTestHandler(store)
	h.store = store

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/check", h.HandleCheck)
	mux.HandleFunc("/api/v1/sync", h.HandleSync)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"version":"1.0.0"},
			"node_modules/left-pad": {"version":"1.3.0"},
			"node_modules/right-pad": {"version":"1.0.0"}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	local, err := sqlite.New(filepath.Join(t.TempDir(), "packmon.db"))
	if err != nil {
		t.Fatalf("sqlite.New() error = %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(local) })

	ctx := context.Background()
	syncLocal := func(full bool) {
		t.Helper()
		if err := sqlite.Sync(ctx, local, sqlite.SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true, Full: full}); err != nil {
			t.Fatalf("sqlite.Sync(full=%v) error = %v", full, err)
		}
	}
	affectedPackages := func(mode scanner.Mode) []string {
		t.Helper()
		sc := scanner.New(parser.NewRegistry(), scanner.Config{
			Path:              projectDir,
			Mode:              mode,
			ServerURL:         server.URL,
			AllowInsecureHTTP: true,
			FailOn:            domain.SeverityCritical,
			MaxDepth:          3,
			Timeout:           10 * time.Second,
		})
		if mode == scanner.ModeLocal {
			sc.SetLocalChecker(scanner.NewDBLocalCheckerAdapter(local))
		}
		result, _ := sc.Run(ctx)
		if result == nil {
			t.Fatalf("scan(%s) returned no result", mode)
		}
		if result.ScanError != "" {
			t.Fatalf("scan(%s) error = %s", mode, result.ScanError)
		}
		var names []string
		for _, finding := range result.Findings {
			if finding.AdvisoryID == coverageParityAdvisory && !slices.Contains(names, finding.Name) {
				names = append(names, finding.Name)
			}
		}
		slices.Sort(names)
		return names
	}
	requireParity := func(stage string, want ...string) {
		t.Helper()
		if got := affectedPackages(scanner.ModeRemote); !slices.Equal(got, want) {
			t.Fatalf("%s: remote check reports %s for %q, want %q", stage, coverageParityAdvisory, got, want)
		}
		if got := affectedPackages(scanner.ModeLocal); !slices.Equal(got, want) {
			t.Fatalf("%s: local scan reports %s for %q, want %q (remote check parity)", stage, coverageParityAdvisory, got, want)
		}
	}

	syncLocal(true)
	requireParity("before the coverage move", "left-pad")

	store.moveCoverage("right-pad")
	syncLocal(false)
	requireParity("after the coverage move and a delta sync", "right-pad")
}
