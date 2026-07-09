package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLocalDatabaseCountsAndExport(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	releaseDate := "2024-01-15"
	ltsFrom := "2024-02-01"
	eolFrom := "2026-01-15"
	eoes := true
	eoesFrom := "2025-12-31"
	cvss := 7.5
	epss := 0.42
	epssPercentile := 0.87

	resp := &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "GHSA-export",
			Ecosystem:        "npm",
			Name:             "left-pad",
			VersionRanges:    `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`,
			VersionsAffected: `[]`,
			References:       `[{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-export"}]`,
			Severity:         "HIGH",
			CVSSScore:        &cvss,
			EPSSScore:        &epss,
			EPSSPercentile:   &epssPercentile,
			CISAKEV:          true,
			Summary:          "export vulnerability",
			Source:           "osv",
		}},
		Malicious: []syncMalicious{{
			ID:            "MAL-export",
			Ecosystem:     "npm",
			Name:          "evil",
			VersionRanges: `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`,
			Versions:      `["1.0.0"]`,
			RiskType:      "malware",
			Severity:      "CRITICAL",
			Summary:       "export malware",
			Source:        "socket",
		}},
		Reputation: []syncReputation{{
			ID:        "reversinglabs:npm/history@1.0.0",
			Ecosystem: "npm",
			Name:      "history",
			Version:   "1.0.0",
			Type:      "supply_chain_risk",
			RiskType:  "malware_history",
			Severity:  "HIGH",
			Summary:   "historical signal only",
		}},
		Lifecycle: []syncLifecycleRelease{{
			ID:             "lifecycle:npm/node:20",
			Ecosystem:      "npm",
			Name:           "node",
			ProductSlug:    "nodejs",
			ProductLabel:   "Node.js",
			Cycle:          "20",
			Latest:         "20.11.1",
			ReleaseDate:    &releaseDate,
			IsLTS:          true,
			LTSFrom:        &ltsFrom,
			IsEOL:          true,
			EOLFrom:        &eolFrom,
			IsEOES:         &eoes,
			EOESFrom:       &eoesFrom,
			IsMaintained:   false,
			IsDiscontinued: false,
		}},
	}
	if _, err := applySync(ctx, store, true, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	scannedAt := time.Date(2026, 6, 24, 10, 30, 0, 0, time.UTC)
	if err := store.InsertScan(ctx, ScanEntry{
		RepoName:          "tester",
		Branch:            "main",
		Commit:            "abc123",
		ScannedAt:         scannedAt,
		PackagesCount:     4,
		FindingsCount:     3,
		FindingIDs:        []string{"GHSA-export", "MAL-export"},
		FindingSeverities: []string{"HIGH", "CRITICAL"},
	}); err != nil {
		t.Fatalf("InsertScan() error = %v", err)
	}

	counts, err := store.LocalDatabaseCounts(ctx)
	if err != nil {
		t.Fatalf("LocalDatabaseCounts() error = %v", err)
	}
	if *counts != (LocalDatabaseCounts{Vulnerabilities: 1, Malicious: 1, Reputation: 1, Lifecycle: 1, HistoryEntries: 1}) {
		t.Fatalf("LocalDatabaseCounts() = %+v", counts)
	}

	exported := collectLocalDatabaseExport(t, ctx, store)
	if len(exported.Vulnerabilities) != 1 || len(exported.Malicious) != 1 ||
		len(exported.Reputation) != 1 || len(exported.Lifecycle) != 1 || len(exported.ScanHistory) != 1 {
		t.Fatalf("export sizes = vulns:%d mal:%d rep:%d life:%d history:%d",
			len(exported.Vulnerabilities), len(exported.Malicious), len(exported.Reputation), len(exported.Lifecycle), len(exported.ScanHistory))
	}

	vuln := exported.Vulnerabilities[0]
	if vuln.ID != "GHSA-export" || vuln.Source != "osv" || !vuln.CISAKEV || vuln.CVSSScore == nil ||
		*vuln.CVSSScore != cvss || vuln.EPSSScore == nil || *vuln.EPSSScore != epss ||
		vuln.EPSSPercentile == nil || *vuln.EPSSPercentile != epssPercentile {
		t.Fatalf("exported vulnerability = %+v", vuln)
	}
	var versionRanges []map[string]any
	if err := json.Unmarshal(vuln.VersionRanges, &versionRanges); err != nil || len(versionRanges) != 1 {
		t.Fatalf("vulnerability version ranges = %s, %v", vuln.VersionRanges, err)
	}

	malicious := exported.Malicious[0]
	if malicious.ID != "MAL-export" || malicious.Source != "socket" || malicious.RiskType != "malware" ||
		string(malicious.Versions) != `["1.0.0"]` {
		t.Fatalf("exported malicious finding = %+v", malicious)
	}

	reputation := exported.Reputation[0]
	if reputation.ID != "reversinglabs:npm/history@1.0.0" || reputation.Severity != "LOW" ||
		reputation.RiskType != "malware_history" {
		t.Fatalf("exported reputation finding = %+v", reputation)
	}

	lifecycle := exported.Lifecycle[0]
	if lifecycle.ID != "lifecycle:npm/node:20" || lifecycle.ProductLabel != "Node.js" || !lifecycle.IsLTS ||
		!lifecycle.IsEOL || lifecycle.IsEOES == nil || !*lifecycle.IsEOES ||
		lifecycle.ReleaseDate == nil || *lifecycle.ReleaseDate != releaseDate ||
		lifecycle.LTSFrom == nil || *lifecycle.LTSFrom != ltsFrom ||
		lifecycle.EOLFrom == nil || *lifecycle.EOLFrom != eolFrom ||
		lifecycle.EOESFrom == nil || *lifecycle.EOESFrom != eoesFrom ||
		lifecycle.IsMaintained {
		t.Fatalf("exported lifecycle row = %+v", lifecycle)
	}

	history := exported.ScanHistory[0]
	if history.RepoName != "tester" || history.Branch != "main" || history.Commit != "abc123" ||
		history.PackagesCount != 4 || history.FindingsCount != 3 || !history.ScannedAt.Equal(scannedAt) ||
		!reflect.DeepEqual(history.FindingIDs, []string{"GHSA-export", "MAL-export"}) ||
		!reflect.DeepEqual(history.FindingSeverities, []string{"HIGH", "CRITICAL"}) {
		t.Fatalf("exported scan history = %+v", history)
	}
}

type localDatabaseExportRows struct {
	Vulnerabilities []LocalVulnerabilityEntry
	Malicious       []LocalMaliciousEntry
	Reputation      []LocalReputationEntry
	Lifecycle       []LocalLifecycleEntry
	ScanHistory     []ScanEntry
}

func collectLocalDatabaseExport(t *testing.T, ctx context.Context, store *Store) localDatabaseExportRows {
	t.Helper()

	exported := localDatabaseExportRows{
		Vulnerabilities: make([]LocalVulnerabilityEntry, 0),
		Malicious:       make([]LocalMaliciousEntry, 0),
		Reputation:      make([]LocalReputationEntry, 0),
		Lifecycle:       make([]LocalLifecycleEntry, 0),
		ScanHistory:     make([]ScanEntry, 0),
	}
	if err := store.StreamLocalVulnerabilities(ctx, func(item LocalVulnerabilityEntry) error {
		exported.Vulnerabilities = append(exported.Vulnerabilities, item)
		return nil
	}); err != nil {
		t.Fatalf("StreamLocalVulnerabilities() error = %v", err)
	}
	if err := store.StreamLocalMalicious(ctx, func(item LocalMaliciousEntry) error {
		exported.Malicious = append(exported.Malicious, item)
		return nil
	}); err != nil {
		t.Fatalf("StreamLocalMalicious() error = %v", err)
	}
	if err := store.StreamLocalReputation(ctx, func(item LocalReputationEntry) error {
		exported.Reputation = append(exported.Reputation, item)
		return nil
	}); err != nil {
		t.Fatalf("StreamLocalReputation() error = %v", err)
	}
	if err := store.StreamLocalLifecycle(ctx, func(item LocalLifecycleEntry) error {
		exported.Lifecycle = append(exported.Lifecycle, item)
		return nil
	}); err != nil {
		t.Fatalf("StreamLocalLifecycle() error = %v", err)
	}
	if err := store.StreamLocalScanHistory(ctx, func(item ScanEntry) error {
		exported.ScanHistory = append(exported.ScanHistory, item)
		return nil
	}); err != nil {
		t.Fatalf("StreamLocalScanHistory() error = %v", err)
	}
	return exported
}

func TestLocalExportHelpers(t *testing.T) {
	t.Parallel()

	if got := localExportSource(""); got != "local" {
		t.Fatalf("localExportSource(empty) = %q, want local", got)
	}
	if got := localExportSource(" osv "); got != "osv" {
		t.Fatalf("localExportSource(trimmed) = %q, want osv", got)
	}
	if got := localDBStringPtr(sql.NullString{String: " ", Valid: true}); got != nil {
		t.Fatalf("localDBStringPtr(blank) = %v, want nil", *got)
	}
	if got := localDBStringPtr(sql.NullString{String: "value", Valid: true}); got == nil || *got != "value" {
		t.Fatalf("localDBStringPtr(value) = %v, want value", got)
	}
	if got := localDBBoolPtr(sql.NullInt64{}); got != nil {
		t.Fatalf("localDBBoolPtr(null) = %v, want nil", *got)
	}
	if got := localDBBoolPtr(sql.NullInt64{Int64: 0, Valid: true}); got == nil || *got {
		t.Fatalf("localDBBoolPtr(false) = %v, want false", got)
	}
	if got := localDBBoolPtr(sql.NullInt64{Int64: 1, Valid: true}); got == nil || !*got {
		t.Fatalf("localDBBoolPtr(true) = %v, want true", got)
	}
}

func TestLocalDatabaseExportDoesNotUseUnboundedRecentScanAggregation(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("local_export.go")
	if err != nil {
		t.Fatalf("read local_export.go: %v", err)
	}
	if strings.Contains(string(source), `GetRecentScans(ctx, "", -1)`) {
		t.Fatal("local export still calls GetRecentScans(ctx, \"\", -1); want streaming scan-history rows")
	}
}
