package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

const (
	coverageParityAdvisory     = "GHSA-cove-rage-move"
	coverageParityNextAdvisory = "GHSA-cove-rage-next"
)

// coverageParityStore simulates server-side coverage moves of advisories: the
// check path matches each advisory against its current affected packages, and
// the sync path exports them like the PostgreSQL exporter does -- a delta
// includes each changed advisory with its complete current affected set and
// says so with VulnerabilityAffectedComplete. With pageByAdvisory, a delta
// serves one advisory per page behind an advisory cursor, like the exporter
// does when a page reaches the row limit, so the delta spans several pages.
type coverageParityStore struct {
	stubStore

	pageByAdvisory bool

	coverageMu sync.Mutex
	affected   map[string][]string
	changedAt  map[string]time.Time
	syncPages  int
}

func (s *coverageParityStore) moveCoverage(advisory string, names ...string) {
	s.coverageMu.Lock()
	defer s.coverageMu.Unlock()
	if s.affected == nil {
		s.affected = make(map[string][]string)
		s.changedAt = make(map[string]time.Time)
	}
	s.affected[advisory] = names
	s.changedAt[advisory] = time.Now().UTC()
}

func (s *coverageParityStore) advisoryIDs() []string {
	ids := make([]string, 0, len(s.affected))
	for id := range s.affected {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (s *coverageParityStore) FindVulnerabilitiesBatch(_ context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	s.coverageMu.Lock()
	defer s.coverageMu.Unlock()
	var findings []domain.Finding
	for _, pkg := range packages {
		if pkg.Ecosystem != string(domain.EcosystemNPM) {
			continue
		}
		for _, id := range s.advisoryIDs() {
			if !slices.Contains(s.affected[id], pkg.Name) {
				continue
			}
			findings = append(findings, domain.Finding{
				Name:       pkg.Name,
				Version:    pkg.Version,
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: id,
				Title:      "coverage move fixture",
				Source:     "manual",
			})
		}
	}
	return findings, nil
}

func (s *coverageParityStore) ExportSync(_ context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	s.coverageMu.Lock()
	defer s.coverageMu.Unlock()
	s.syncPages++
	// Like the PostgreSQL exporter, only delta pages (since window) promise
	// complete affected sets; a full export is one unflagged page.
	export := &db.SyncExport{
		SyncedAt:                      time.Now().UTC().Add(-time.Second),
		VulnerabilityAffectedComplete: opts.Since != nil,
	}
	var ids []string
	for _, id := range s.advisoryIDs() {
		if opts.Since == nil || !s.changedAt[id].Before(*opts.Since) {
			ids = append(ids, id)
		}
	}
	if opts.Since != nil && s.pageByAdvisory {
		after, _ := db.DecodeSyncAdvisoryCursor(opts.Cursor.VulnerabilitiesCursor)
		ids = slices.DeleteFunc(ids, func(id string) bool { return after != "" && strings.Compare(id, after) <= 0 })
		if len(ids) > 1 {
			export.Truncated = true
			export.NextCursor = &db.SyncCursor{
				VulnerabilitiesCursor: db.EncodeSyncAdvisoryCursor(ids[0]),
				MaliciousDone:         true,
				ReputationDone:        true,
				LifecycleDone:         true,
			}
		}
		ids = ids[:min(len(ids), 1)]
	}
	for _, id := range ids {
		for _, name := range s.affected[id] {
			export.Vulnerabilities = append(export.Vulnerabilities, db.SyncVulnerability{
				ID:               id,
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
	}
	return export, nil
}

// coverageParityHarness serves /api/v1/check and /api/v1/sync from one
// coverageParityStore and scans one npm project remotely and locally.
type coverageParityHarness struct {
	t          *testing.T
	store      *coverageParityStore
	serverURL  string
	projectDir string
	local      *sqlite.Store
}

func newCoverageParityHarness(t *testing.T, store *coverageParityStore) *coverageParityHarness {
	t.Helper()
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
	return &coverageParityHarness{t: t, store: store, serverURL: server.URL, projectDir: projectDir, local: local}
}

func (p *coverageParityHarness) sync(full bool) {
	p.t.Helper()
	if err := sqlite.Sync(context.Background(), p.local, sqlite.SyncConfig{ServerURL: p.serverURL, AllowInsecureHTTP: true, Full: full}); err != nil {
		p.t.Fatalf("sqlite.Sync(full=%v) error = %v", full, err)
	}
}

// affectedPackages maps each advisory to the packages a scan reports it for.
func (p *coverageParityHarness) affectedPackages(mode scanner.Mode) map[string][]string {
	p.t.Helper()
	sc := scanner.New(parser.NewRegistry(), scanner.Config{
		Path:              p.projectDir,
		Mode:              mode,
		ServerURL:         p.serverURL,
		AllowInsecureHTTP: true,
		FailOn:            domain.SeverityCritical,
		MaxDepth:          3,
		Timeout:           10 * time.Second,
	})
	if mode == scanner.ModeLocal {
		sc.SetLocalChecker(scanner.NewDBLocalCheckerAdapter(p.local))
	}
	result, _ := sc.Run(context.Background())
	if result == nil {
		p.t.Fatalf("scan(%s) returned no result", mode)
	}
	if result.ScanError != "" {
		p.t.Fatalf("scan(%s) error = %s", mode, result.ScanError)
	}
	names := make(map[string][]string)
	for _, finding := range result.Findings {
		if !strings.HasPrefix(finding.AdvisoryID, "GHSA-cove-rage-") || slices.Contains(names[finding.AdvisoryID], finding.Name) {
			continue
		}
		names[finding.AdvisoryID] = append(names[finding.AdvisoryID], finding.Name)
	}
	for id := range names {
		slices.Sort(names[id])
	}
	return names
}

func (p *coverageParityHarness) requireParity(stage string, want map[string][]string) {
	p.t.Helper()
	equal := func(got map[string][]string) bool {
		if len(got) != len(want) {
			return false
		}
		for id, names := range want {
			if !slices.Equal(got[id], names) {
				return false
			}
		}
		return true
	}
	if got := p.affectedPackages(scanner.ModeRemote); !equal(got) {
		p.t.Fatalf("%s: remote check reports %v, want %v", stage, got, want)
	}
	if got := p.affectedPackages(scanner.ModeLocal); !equal(got) {
		p.t.Fatalf("%s: local scan reports %v, want %v (remote check parity)", stage, got, want)
	}
}

// TestCoverageParityLocalScanMatchesRemoteCheckAfterCoverageMove syncs an
// advisory affecting left-pad into the local SQLite database, then moves its
// coverage to right-pad on the server (a manual advisory edit or a
// package-name repair). After the next delta sync, a local scan must report
// the advisory for exactly the packages a remote /api/v1/check reports it for.
func TestCoverageParityLocalScanMatchesRemoteCheckAfterCoverageMove(t *testing.T) {
	t.Parallel()

	store := &coverageParityStore{}
	store.moveCoverage(coverageParityAdvisory, "left-pad")
	p := newCoverageParityHarness(t, store)

	p.sync(true)
	p.requireParity("before the coverage move", map[string][]string{coverageParityAdvisory: {"left-pad"}})

	store.moveCoverage(coverageParityAdvisory, "right-pad")
	p.sync(false)
	p.requireParity("after the coverage move and a delta sync", map[string][]string{coverageParityAdvisory: {"right-pad"}})
}

// TestCoverageParityLocalScanMatchesRemoteCheckAfterMultiPageCoverageMove
// moves the coverage of two advisories at once and delivers the delta over
// several pages, one whole advisory per flagged page. Every page replaces the
// local affected rows of its advisories, so after the multi-page delta a local
// scan reports each advisory for exactly the packages a remote check does.
func TestCoverageParityLocalScanMatchesRemoteCheckAfterMultiPageCoverageMove(t *testing.T) {
	t.Parallel()

	store := &coverageParityStore{pageByAdvisory: true}
	store.moveCoverage(coverageParityAdvisory, "left-pad")
	store.moveCoverage(coverageParityNextAdvisory, "right-pad")
	p := newCoverageParityHarness(t, store)

	p.sync(true)
	p.requireParity("before the coverage moves", map[string][]string{
		coverageParityAdvisory:     {"left-pad"},
		coverageParityNextAdvisory: {"right-pad"},
	})

	store.moveCoverage(coverageParityAdvisory, "right-pad")
	store.moveCoverage(coverageParityNextAdvisory, "left-pad")
	store.coverageMu.Lock()
	pagesBefore := store.syncPages
	store.coverageMu.Unlock()
	p.sync(false)
	store.coverageMu.Lock()
	deltaPages := store.syncPages - pagesBefore
	store.coverageMu.Unlock()
	if deltaPages < 2 {
		t.Fatalf("delta sync used %d page(s), want a multi-page delta", deltaPages)
	}
	p.requireParity("after the coverage moves and a multi-page delta sync", map[string][]string{
		coverageParityAdvisory:     {"right-pad"},
		coverageParityNextAdvisory: {"left-pad"},
	})
}
