package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/parser"
	"github.com/8linkz-sec/packmon/internal/scanner"
)

// reputationParityStore simulates a server whose package reputation cache
// still holds a malicious ReversingLabs row. The check path returns it through
// FindReputationFindingsBatch and the sync path exports it unless the handler
// asks the store to exclude reputation. The row never changes, so like the
// PostgreSQL exporter it is part of a sync window only when no since bound is
// given.
type reputationParityStore struct {
	stubStore
}

func (s *reputationParityStore) ExportSync(_ context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	export := &db.SyncExport{SyncedAt: time.Now().UTC().Add(-time.Second)}
	if !opts.ExcludeReputation && opts.Since == nil {
		export.Reputation = []db.SyncReputationFinding{{
			ID:        "reversinglabs:npm/left-pad@1.3.0",
			Ecosystem: "npm",
			Name:      "left-pad",
			Version:   "1.3.0",
			Type:      string(domain.FindingTypeMalicious),
			RiskType:  "malware",
			Severity:  string(domain.SeverityCritical),
			Summary:   "ReversingLabs: malicious package version",
		}}
	}
	return export, nil
}

// TestReputationParityLocalScanMatchesRemoteCheckAfterReversingLabsDisabled
// syncs a malicious ReversingLabs row into the local SQLite database while
// ReversingLabs is enabled in self mode, then disables it on the server. Both a
// remote /api/v1/check scan and a local scan after the next delta sync must
// stop reporting the leftover reputation finding.
func TestReputationParityLocalScanMatchesRemoteCheckAfterReversingLabsDisabled(t *testing.T) {
	t.Parallel()

	store := &reputationParityStore{stubStore: stubStore{
		reputationFindings: []domain.Finding{{
			Name:       "left-pad",
			Version:    "1.3.0",
			Ecosystem:  domain.EcosystemNPM,
			Type:       domain.FindingTypeMalicious,
			Severity:   domain.SeverityCritical,
			AdvisoryID: "reversinglabs:npm/left-pad@1.3.0",
			Title:      "ReversingLabs: malicious package version",
			RiskType:   "malware",
			Source:     db.ReputationSourceReversingLabs,
		}},
	}}
	h := newTestHandler(store)
	h.store = store
	enableReversingLabs := func(enabled bool) {
		h.ConfigureReversingLabs(config.FeedsConfig{ReversingLabsEnabled: enabled, ReversingLabsMode: config.FeedModeSelf})
	}
	enableReversingLabs(true)

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
			"node_modules/left-pad": {"version":"1.3.0"}
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
	scan := func(mode scanner.Mode) *domain.ScanResult {
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
		return result
	}

	// Enabled: both paths report the reputation finding.
	syncLocal(true)
	if got := countReversingLabsFindings(scan(scanner.ModeRemote)); got != 1 {
		t.Fatalf("remote reputation findings while enabled = %d, want 1", got)
	}
	if got := countReversingLabsFindings(scan(scanner.ModeLocal)); got != 1 {
		t.Fatalf("local reputation findings while enabled = %d, want 1", got)
	}

	// Disabled: the leftover row must not produce a finding on either path.
	enableReversingLabs(false)
	syncLocal(false)
	if got := countReversingLabsFindings(scan(scanner.ModeRemote)); got != 0 {
		t.Fatalf("remote reputation findings while disabled = %d, want 0", got)
	}
	if got := countReversingLabsFindings(scan(scanner.ModeLocal)); got != 0 {
		t.Fatalf("local reputation findings while disabled = %d, want 0 (leftover synced row must be dropped)", got)
	}

	// Re-enabled: the next delta sync restores parity without a full sync.
	enableReversingLabs(true)
	syncLocal(false)
	if got := countReversingLabsFindings(scan(scanner.ModeRemote)); got != 1 {
		t.Fatalf("remote reputation findings after re-enable = %d, want 1", got)
	}
	if got := countReversingLabsFindings(scan(scanner.ModeLocal)); got != 1 {
		t.Fatalf("local reputation findings after re-enable = %d, want 1", got)
	}
}

func countReversingLabsFindings(result *domain.ScanResult) int {
	count := 0
	for _, finding := range result.Findings {
		if finding.Source == db.ReputationSourceReversingLabs {
			count++
		}
	}
	return count
}
