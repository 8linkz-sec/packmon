package sqlite

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

func TestApplySyncVulnerabilityAndMaliciousRowsAndTombstones(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	cvss := 9.8
	epss := 0.42
	resp := &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:            "GHSA-sync",
			Ecosystem:     "npm",
			Name:          "left-pad",
			VersionRanges: `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`,
			Severity:      "HIGH",
			CVSSScore:     &cvss,
			EPSSScore:     &epss,
			CISAKEV:       true,
			Summary:       "sync vuln",
		}},
		Malicious: []syncMalicious{{
			ID:        "MAL-sync",
			Ecosystem: "npm",
			Name:      "evil",
			Versions:  `["1.0.0"]`,
			RiskType:  "malware",
			Severity:  "CRITICAL",
			Summary:   "bad",
		}},
	}
	if err := applySync(ctx, store, true, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	vulns, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "GHSA-sync" || vulns[0].FixedVersion != ">= 2.0.0" {
		t.Fatalf("vulns = %+v, want synced vulnerability with fixed version", vulns)
	}
	mal, err := store.FindMalicious(ctx, "npm", "evil", "1.0.0")
	if err != nil {
		t.Fatalf("FindMalicious() error = %v", err)
	}
	if len(mal) != 1 || mal[0].Type != domain.FindingTypeMalicious {
		t.Fatalf("malicious = %+v, want synced malicious finding", mal)
	}

	if err := applySync(ctx, store, false, &syncResponse{
		Vulnerabilities: []syncVulnerability{{ID: "GHSA-sync", Withdrawn: true}},
		Malicious:       []syncMalicious{{ID: "MAL-sync", Withdrawn: true}},
	}); err != nil {
		t.Fatalf("applySync(tombstones) error = %v", err)
	}
	vulns, _ = store.FindVulnerabilities(ctx, "npm", "left-pad", "1.5.0")
	mal, _ = store.FindMalicious(ctx, "npm", "evil", "1.0.0")
	if len(vulns) != 0 || len(mal) != 0 {
		t.Fatalf("rows after tombstones: vulns=%+v malicious=%+v", vulns, mal)
	}
}

func TestApplySyncLifecycleRowsAndFindings(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	eolPast := now.AddDate(0, 0, -1)
	eoasPast := now.AddDate(0, 0, -7)
	eolSoon := now.AddDate(0, 0, 30)

	resp := &syncResponse{
		Lifecycle: []syncLifecycleRelease{
			{
				ID:           "endoflife:pypi:django:django:3.2",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "3.2",
				EOLFrom:      &eolPast,
			},
			{
				ID:           "endoflife:pypi:django:django:4",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "4",
				IsEOL:        true,
			},
			{
				ID:           "endoflife:pypi:django:django:4.2",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "4.2",
				IsEOAS:       true,
				EOASFrom:     &eoasPast,
			},
			{
				ID:           "endoflife:pypi:django:django:5.0",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "5.0",
				EOLFrom:      &eolSoon,
			},
			{
				ID:           "endoflife:pypi:django:django:6.0",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "6.0",
			},
		},
	}
	if err := applySync(ctx, store, true, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	findings, err := store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{
		{Ecosystem: "pypi", Name: "django", Version: "3.2.25"},
		{Ecosystem: "pypi", Name: "django", Version: "4.1.1"},
		{Ecosystem: "pypi", Name: "django", Version: "4.2.11"},
		{Ecosystem: "pypi", Name: "django", Version: "5.0.1"},
		{Ecosystem: "pypi", Name: "django", Version: "6.0.0"},
	}, now)
	if err != nil {
		t.Fatalf("FindLifecycleFindingsBatch() error = %v", err)
	}

	byVersion := make(map[string]domain.Finding, len(findings))
	for _, finding := range findings {
		byVersion[finding.Version] = finding
	}
	if len(byVersion) != 4 {
		t.Fatalf("FindLifecycleFindingsBatch() returned %d findings: %+v", len(findings), findings)
	}
	assertSQLiteLifecycleFinding(t, byVersion["3.2.25"], domain.FindingTypeSupplyChainRisk, domain.SeverityCritical, "eol")
	assertSQLiteLifecycleFinding(t, byVersion["4.1.1"], domain.FindingTypeSupplyChainRisk, domain.SeverityCritical, "eol")
	assertSQLiteLifecycleFinding(t, byVersion["4.2.11"], domain.FindingTypeLifecycle, domain.SeverityLow, "security_support_only")
	assertSQLiteLifecycleFinding(t, byVersion["5.0.1"], domain.FindingTypeLifecycle, domain.SeverityMedium, "eol_soon")
	if _, ok := byVersion["6.0.0"]; ok {
		t.Fatalf("6.0.0 produced lifecycle finding despite no lifecycle signal: %+v", byVersion["6.0.0"])
	}

	if err := applySync(ctx, store, false, &syncResponse{
		Lifecycle: []syncLifecycleRelease{{ID: "endoflife:pypi:django:django:4.2", Withdrawn: true}},
	}); err != nil {
		t.Fatalf("applySync(tombstone) error = %v", err)
	}
	findings, err = store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{
		{Ecosystem: "pypi", Name: "django", Version: "4.2.11"},
	}, now)
	if err != nil {
		t.Fatalf("FindLifecycleFindingsBatch(after tombstone) error = %v", err)
	}
	if len(findings) != 1 || findings[0].RiskType != "eol" {
		t.Fatalf("findings after 4.2 tombstone = %+v, want fallback 4.x EOL finding", findings)
	}
}

func TestFindLifecycleFindingsBatchNormalizesNuGetNames(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)

	resp := &syncResponse{
		Lifecycle: []syncLifecycleRelease{
			{
				ID:           "endoflife:nuget:newtonsoft.json:newtonsoft-json:13",
				Ecosystem:    "nuget",
				Name:         "newtonsoft.json",
				ProductSlug:  "newtonsoft-json",
				ProductLabel: "Newtonsoft.Json",
				Cycle:        "13",
				IsEOL:        true,
			},
		},
	}
	if err := applySync(ctx, store, true, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	findings, err := store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{
		{Ecosystem: "nuget", Name: "Newtonsoft.Json", Version: "13.0.3"},
	}, now)
	if err != nil {
		t.Fatalf("FindLifecycleFindingsBatch() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("FindLifecycleFindingsBatch() returned %d findings: %+v", len(findings), findings)
	}
	if findings[0].Name != "newtonsoft.json" {
		t.Fatalf("finding name = %q, want normalized NuGet name", findings[0].Name)
	}
	assertSQLiteLifecycleFinding(t, findings[0], domain.FindingTypeSupplyChainRisk, domain.SeverityCritical, "eol")
}

func assertSQLiteLifecycleFinding(t *testing.T, finding domain.Finding, typ domain.FindingType, severity domain.Severity, riskType string) {
	t.Helper()

	if finding.Type != typ || finding.Severity != severity || finding.RiskType != riskType {
		t.Fatalf("finding for %s = type %s severity %s risk %s, want type %s severity %s risk %s",
			finding.Version, finding.Type, finding.Severity, finding.RiskType, typ, severity, riskType)
	}
	if finding.Source != "endoflife.date" || finding.AdvisoryID == "" || finding.URL == "" {
		t.Fatalf("finding identity/source = %+v", finding)
	}
}

func TestSyncErrorBranches(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	if err := Sync(context.Background(), store, SyncConfig{}); err == nil || !strings.Contains(err.Error(), "no server URL") {
		t.Fatalf("Sync(no server) error = %v", err)
	}
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: "://bad"}); err == nil || !strings.Contains(err.Error(), "parse server URL") {
		t.Fatalf("Sync(bad URL) error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, strings.Repeat("x", 250), http.StatusBadGateway)
	}))
	defer server.Close()
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: server.URL, Full: true}); err == nil || !strings.Contains(err.Error(), "server returned 502") || !strings.Contains(err.Error(), "...") {
		t.Fatalf("Sync(server error) = %v", err)
	}

	truncated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"truncated":true}`))
	}))
	defer truncated.Close()
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: truncated.URL, Full: true}); err == nil || !strings.Contains(err.Error(), "truncated response missing synced_at") {
		t.Fatalf("Sync(truncated without snapshot) = %v", err)
	}

	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer invalidJSON.Close()
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: invalidJSON.URL, Full: true}); err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("Sync(invalid JSON) = %v", err)
	}
}

func TestSyncIncrementalUsesSinceAuthorizationAndEcosystems(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	const since = "2026-05-30T10:00:00Z"
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, since); err != nil {
		t.Fatalf("SetSyncMeta() error = %v", err)
	}

	var gotSince, gotAuth, gotEcosystem string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSince = r.URL.Query().Get("since")
		gotAuth = r.Header.Get("Authorization")
		gotEcosystem = r.URL.Query().Get("ecosystem")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"2026-05-30T11:00:00Z"}`))
	}))
	defer server.Close()

	if err := Sync(ctx, store, SyncConfig{
		ServerURL:  server.URL,
		APIKey:     "sync-key",
		Ecosystems: []string{"npm", "go"},
	}); err != nil {
		t.Fatalf("Sync(incremental) error = %v", err)
	}
	if gotSince != since || gotAuth != "Bearer sync-key" || gotEcosystem != "npm,go" {
		t.Fatalf("request since=%q auth=%q ecosystem=%q", gotSince, gotAuth, gotEcosystem)
	}
	lastSync, err := store.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta() error = %v", err)
	}
	if lastSync != "2026-05-30T11:00:00Z" {
		t.Fatalf("last sync = %q, want updated snapshot", lastSync)
	}
}

func TestFetchSyncPageReadErrorIncludesContext(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer read-key" || r.URL.Query().Get("offset") != "1000" || r.URL.Query().Get("snapshot") != "snap" {
			t.Fatalf("request headers/query = auth %q raw %q", r.Header.Get("Authorization"), r.URL.RawQuery)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       errReadCloser{},
			Header:     make(http.Header),
		}, nil
	})}

	_, err := fetchSyncPage(context.Background(), client, SyncConfig{
		ServerURL: "https://packmon.example",
		APIKey:    "read-key",
	}, "2026-05-30T10:00:00Z", syncPageLimit, "snap")
	if err == nil || !strings.Contains(err.Error(), "read response") {
		t.Fatalf("fetchSyncPage(read error) = %v", err)
	}
}

func TestSQLiteSyncHelpersAndWebNoops(t *testing.T) {
	t.Parallel()

	if got := truncate("short", 10); got != "short" {
		t.Fatalf("truncate short = %q", got)
	}
	if got := truncate("abcdef", 3); got != "abc..." {
		t.Fatalf("truncate long = %q", got)
	}
	if got := syncVulnerabilityRowKey("GHSA", "npm", "left-pad"); got != "GHSA|npm|left-pad" {
		t.Fatalf("syncVulnerabilityRowKey = %q", got)
	}

	store := newSQLiteTestStore(t)
	statuses, err := store.ListFeedSyncStatuses(context.Background())
	if err != nil || len(statuses) != 0 {
		t.Fatalf("ListFeedSyncStatuses() = %+v, %v; want empty nil", statuses, err)
	}
	recent, err := store.ListRecentVulnerabilities(context.Background(), 7, 10)
	if err != nil || len(recent) != 0 {
		t.Fatalf("ListRecentVulnerabilities() = %+v, %v; want empty nil", recent, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("forced read error")
}

func (errReadCloser) Close() error {
	return nil
}
