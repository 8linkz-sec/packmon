package sqlite

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

type syncRoundTripFunc func(*http.Request) (*http.Response, error)

func (f syncRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSyncHTTPClientRejectsHTTPSDowngradeRedirect(t *testing.T) {
	client := newSyncHTTPClient(time.Second)
	req, err := http.NewRequest(http.MethodGet, "http://packmon.example/api/v1/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := http.NewRequest(http.MethodGet, "https://packmon.example/api/v1/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")

	if err := client.CheckRedirect(req, []*http.Request{prev}); err == nil {
		t.Fatal("CheckRedirect allowed HTTPS-to-HTTP downgrade")
	}
}

func TestSyncHTTPClientStripsAuthorizationOnCrossOriginRedirect(t *testing.T) {
	client := newSyncHTTPClient(time.Second)
	req, err := http.NewRequest(http.MethodGet, "https://other.example/api/v1/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := http.NewRequest(http.MethodGet, "https://packmon.example/api/v1/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")

	if err := client.CheckRedirect(req, []*http.Request{prev}); err != nil {
		t.Fatalf("CheckRedirect same-scheme cross-origin error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization after cross-origin redirect = %q, want stripped", got)
	}
}

func TestSyncUsesConfiguredCABundle(t *testing.T) {
	store := newSQLiteTestStore(t)
	ctx := context.Background()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync" {
			t.Fatalf("path = %q, want /api/v1/sync", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"synced_at":"` + time.Now().UTC().Format(time.RFC3339) + `",
			"vulnerabilities":[{"id":"GHSA-ca","ecosystem":"npm","name":"left-pad","version_ranges":"[]","severity":"LOW"}]
		}`))
	}))
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	writeSyncServerCertPEM(t, server, caFile)

	if err := Sync(ctx, store, SyncConfig{
		ServerURL:  server.URL,
		CACertFile: caFile,
		Timeout:    5 * time.Second,
	}); err != nil {
		t.Fatalf("Sync() with configured CA bundle error = %v", err)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 1 || findings[0].AdvisoryID != "GHSA-ca" {
		t.Fatalf("synced findings = %+v, want GHSA-ca", findings)
	}
}

func writeSyncServerCertPEM(t *testing.T, server *httptest.Server, path string) {
	t.Helper()
	if server.TLS == nil || len(server.TLS.Certificates) == 0 {
		t.Fatal("test server has no TLS certificate")
	}
	var out []byte
	for _, cert := range server.TLS.Certificates {
		for _, der := range cert.Certificate {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write server certificate: %v", err)
	}
}

func TestApplySyncVulnerabilityAndMaliciousRowsAndTombstones(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	cvss := 9.8
	epss := 0.42
	epssPercentile := 0.88
	resp := &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "GHSA-sync",
			Ecosystem:        "npm",
			Name:             "left-pad",
			VersionRanges:    `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`,
			VersionsAffected: `[]`,
			References:       `[{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-sync"},{"type":"WEB","url":"https://osv.dev/vulnerability/GHSA-sync"}]`,
			Severity:         "HIGH",
			CVSSScore:        &cvss,
			EPSSScore:        &epss,
			EPSSPercentile:   &epssPercentile,
			CISAKEV:          true,
			Summary:          "sync vuln",
			Source:           "manual",
		}, {
			ID:               "GHSA-versions",
			Ecosystem:        "npm",
			Name:             "only-listed",
			VersionRanges:    `[]`,
			VersionsAffected: `["1.0.1"]`,
			Severity:         "MEDIUM",
			Summary:          "explicit versions",
		}},
		Malicious: []syncMalicious{{
			ID:            "MAL-sync",
			Ecosystem:     "npm",
			Name:          "evil",
			VersionRanges: `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`,
			Versions:      `["2.1.5-bad"]`,
			ReferenceURLs: `["https://example.test/malware/MAL-sync"]`,
			RiskType:      "malware",
			Severity:      "CRITICAL",
			Summary:       "bad",
			Source:        "manual",
		}},
	}
	if _, err := applySync(ctx, store, true, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	vulns, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "GHSA-sync" || vulns[0].FixedVersion != ">= 2.0.0" {
		t.Fatalf("vulns = %+v, want synced vulnerability with fixed version", vulns)
	}
	if vulns[0].URL == "" || len(vulns[0].Resources) < 2 {
		t.Fatalf("vuln resources = url %q resources %+v, want synced links", vulns[0].URL, vulns[0].Resources)
	}
	if vulns[0].Source != "manual" {
		t.Fatalf("vuln source = %q, want manual", vulns[0].Source)
	}
	var storedPercentile float64
	if err := store.DB().QueryRowContext(ctx, `SELECT epss_percentile FROM vulnerabilities_local WHERE id = ?`, "GHSA-sync").Scan(&storedPercentile); err != nil {
		t.Fatalf("read synced EPSS percentile: %v", err)
	}
	if storedPercentile != epssPercentile {
		t.Fatalf("stored EPSS percentile = %v, want %v", storedPercentile, epssPercentile)
	}
	batchVulns, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "left-pad", Version: "1.5.0"}})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch() error = %v", err)
	}
	if len(batchVulns) != 1 || batchVulns[0].Source != "manual" {
		t.Fatalf("batch vuln source = %+v, want manual source", batchVulns)
	}
	vulns, err = store.FindVulnerabilities(ctx, "npm", "only-listed", "1.0.1")
	if err != nil {
		t.Fatalf("FindVulnerabilities(versions_affected hit) error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "GHSA-versions" {
		t.Fatalf("versions_affected hit = %+v, want GHSA-versions", vulns)
	}
	vulns, err = store.FindVulnerabilities(ctx, "npm", "only-listed", "1.0.2")
	if err != nil {
		t.Fatalf("FindVulnerabilities(versions_affected miss) error = %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("versions_affected miss = %+v, want no findings", vulns)
	}
	mal, err := store.FindMalicious(ctx, "npm", "evil", "1.5.0")
	if err != nil {
		t.Fatalf("FindMalicious() error = %v", err)
	}
	if len(mal) != 1 || mal[0].Type != domain.FindingTypeMalicious {
		t.Fatalf("malicious range hit = %+v, want synced malicious finding", mal)
	}
	if mal[0].AdvisoryID != "MAL-sync" || mal[0].URL != "https://example.test/malware/MAL-sync" {
		t.Fatalf("malicious link fields = %+v, want advisory id and URL", mal[0])
	}
	if mal[0].Source != "manual" {
		t.Fatalf("malicious source = %q, want manual", mal[0].Source)
	}
	batchMal, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "evil", Version: "1.5.0"}})
	if err != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", err)
	}
	if len(batchMal) != 1 || batchMal[0].Source != "manual" {
		t.Fatalf("batch malicious source = %+v, want manual source", batchMal)
	}
	mal, err = store.FindMalicious(ctx, "npm", "evil", "2.0.0")
	if err != nil {
		t.Fatalf("FindMalicious(range miss) error = %v", err)
	}
	if len(mal) != 0 {
		t.Fatalf("malicious range miss = %+v, want no finding at fixed version", mal)
	}
	mal, err = store.FindMalicious(ctx, "npm", "evil", "2.1.5-bad")
	if err != nil {
		t.Fatalf("FindMalicious(explicit version hit) error = %v", err)
	}
	if len(mal) != 1 || mal[0].AdvisoryID != "MAL-sync" {
		t.Fatalf("malicious explicit hit = %+v, want synced malicious finding", mal)
	}

	if _, err := applySync(ctx, store, false, &syncResponse{
		Vulnerabilities: []syncVulnerability{{ID: "GHSA-sync", Withdrawn: true}},
		Malicious:       []syncMalicious{{ID: "MAL-sync", Withdrawn: true}},
	}); err != nil {
		t.Fatalf("applySync(tombstones) error = %v", err)
	}
	vulns, _ = store.FindVulnerabilities(ctx, "npm", "left-pad", "1.5.0")
	mal, _ = store.FindMalicious(ctx, "npm", "evil", "1.5.0")
	if len(vulns) != 0 || len(mal) != 0 {
		t.Fatalf("rows after tombstones: vulns=%+v malicious=%+v", vulns, mal)
	}
}

func TestApplySyncNormalizesCaseInsensitivePackageNames(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	resp := &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "PYSEC-normalized",
			Ecosystem:        "pypi",
			Name:             "My.Pkg_Name",
			VersionRanges:    `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`,
			VersionsAffected: `[]`,
			Severity:         "HIGH",
			Summary:          "pypi normalized vuln",
		}, {
			ID:               "GHSA-nuget-normalized",
			Ecosystem:        "nuget",
			Name:             "Newtonsoft.Json",
			VersionRanges:    `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"14.0.0"}]}]`,
			VersionsAffected: `[]`,
			Severity:         "HIGH",
			Summary:          "nuget normalized vuln",
		}},
		Malicious: []syncMalicious{{
			ID:        "MAL-pypi-normalized",
			Ecosystem: "pypi",
			Name:      "Django",
			Versions:  `["4.2.11"]`,
			RiskType:  "malware",
			Severity:  "CRITICAL",
		}, {
			ID:        "MAL-nuget-normalized",
			Ecosystem: "nuget",
			Name:      "NuGet.Mixed_Case",
			Versions:  `["1.0.0"]`,
			RiskType:  "malware",
			Severity:  "CRITICAL",
		}},
	}
	if _, err := applySync(ctx, store, true, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	vulns, err := store.FindVulnerabilities(ctx, "pypi", "my-pkg-name", "1.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(pypi normalized) error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "PYSEC-normalized" || vulns[0].Name != "my-pkg-name" {
		t.Fatalf("pypi normalized findings = %+v, want canonical package match", vulns)
	}
	vulns, err = store.FindVulnerabilities(ctx, "nuget", "newtonsoft.json", "13.0.3")
	if err != nil {
		t.Fatalf("FindVulnerabilities(nuget normalized) error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "GHSA-nuget-normalized" || vulns[0].Name != "newtonsoft.json" {
		t.Fatalf("nuget normalized findings = %+v, want canonical package match", vulns)
	}

	malicious, err := store.FindMalicious(ctx, "pypi", "django", "4.2.11")
	if err != nil {
		t.Fatalf("FindMalicious(pypi normalized) error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "MAL-pypi-normalized" || malicious[0].Name != "django" {
		t.Fatalf("pypi malicious = %+v, want canonical package match", malicious)
	}
	malicious, err = store.FindMalicious(ctx, "nuget", "nuget.mixed_case", "1.0.0")
	if err != nil {
		t.Fatalf("FindMalicious(nuget normalized) error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "MAL-nuget-normalized" || malicious[0].Name != "nuget.mixed_case" {
		t.Fatalf("nuget malicious = %+v, want canonical package match", malicious)
	}

	batch, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{
		{Ecosystem: "pypi", Name: "My_Pkg.Name", Version: "1.5.0"},
		{Ecosystem: "nuget", Name: "Newtonsoft.Json", Version: "13.0.3"},
	})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch(normalized) error = %v", err)
	}
	if len(batch) != 2 {
		t.Fatalf("FindVulnerabilitiesBatch(normalized) = %+v, want both normalized findings", batch)
	}
}

func TestApplySyncRejectsMalformedMaliciousVersions(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()

	_, err := applySync(ctx, store, true, &syncResponse{
		Malicious: []syncMalicious{{
			ID:        "MAL-sync-invalid-versions",
			Ecosystem: "npm",
			Name:      "evil",
			Versions:  `{"introduced":"1.0.0"}`,
			RiskType:  "malware",
			Severity:  "CRITICAL",
			Summary:   "invalid versions",
		}},
	})
	if err == nil {
		t.Fatal("applySync() error = nil, want invalid malicious versions error")
	}
	if !strings.Contains(err.Error(), "MAL-sync-invalid-versions") {
		t.Fatalf("applySync() error = %q, want malicious finding ID", err)
	}

	findings, findErr := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "evil", Version: "2.0.0"},
	})
	if findErr != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", findErr)
	}
	if len(findings) != 0 {
		t.Fatalf("FindMaliciousBatch() = %+v, want rejected row absent", findings)
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
	eolPastDate := eolPast.Format(time.DateOnly)
	eoasPastDate := eoasPast.Format(time.DateOnly)
	eolSoonDate := eolSoon.Format(time.DateOnly)

	resp := &syncResponse{
		Lifecycle: []syncLifecycleRelease{
			{
				ID:           "endoflife:pypi:django:django:3.2",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "3.2",
				EOLFrom:      &eolPastDate,
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
				EOASFrom:     &eoasPastDate,
			},
			{
				ID:           "endoflife:pypi:django:django:5.0",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "5.0",
				EOLFrom:      &eolSoonDate,
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
	if _, err := applySync(ctx, store, true, resp); err != nil {
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

	if _, err := applySync(ctx, store, false, &syncResponse{
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
	if _, err := applySync(ctx, store, true, resp); err != nil {
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

func TestFindLifecycleFindingsBatchDoesNotUsePerPackageLookup(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("lifecycle.go")
	if err != nil {
		t.Fatalf("read lifecycle source: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "func (s *Store) FindLifecycleFindingsBatch")
	if start < 0 {
		t.Fatal("FindLifecycleFindingsBatch not found")
	}
	next := strings.Index(text[start+1:], "\nfunc ")
	if next < 0 {
		t.Fatal("FindLifecycleFindingsBatch end not found")
	}
	body := text[start : start+1+next]
	if strings.Contains(body, "lifecycleRows(") {
		t.Fatalf("FindLifecycleFindingsBatch still calls lifecycleRows per package")
	}
}

func TestFindLifecycleFindingsBatchErrorIncludesPackageContext(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	_, err = store.FindLifecycleFindingsBatch(context.Background(), []db.PackageQuery{{
		Ecosystem: "npm",
		Name:      "django",
		Version:   "4.2.0",
	}}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("FindLifecycleFindingsBatch() error = nil, want closed-store error")
	}
	if !strings.Contains(err.Error(), "npm/django") {
		t.Fatalf("FindLifecycleFindingsBatch() error = %v, want package context", err)
	}
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
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: server.URL, Full: true, AllowInsecureHTTP: true}); err == nil || !strings.Contains(err.Error(), "server returned 502") || !strings.Contains(err.Error(), "...") {
		t.Fatalf("Sync(server error) = %v", err)
	}

	truncated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"truncated":true}`))
	}))
	defer truncated.Close()
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: truncated.URL, Full: true, AllowInsecureHTTP: true}); err == nil || !strings.Contains(err.Error(), "truncated response missing synced_at") {
		t.Fatalf("Sync(truncated without snapshot) = %v", err)
	}

	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer invalidJSON.Close()
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: invalidJSON.URL, Full: true, AllowInsecureHTTP: true}); err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("Sync(invalid JSON) = %v", err)
	}
}

func TestSyncRejectsPlainHTTPWithoutExplicitOptIn(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("Sync sent request over plain HTTP without opt-in")
	}))
	defer server.Close()

	err := Sync(context.Background(), store, SyncConfig{ServerURL: server.URL, APIKey: "secret"})
	if err == nil || !strings.Contains(err.Error(), "refusing to use insecure server URL") {
		t.Fatalf("Sync(insecure HTTP) error = %v", err)
	}
}

func TestSyncServerURLErrorsRedactSecretBearingURLValues(t *testing.T) {
	t.Parallel()

	rawURL := "http://user:server-secret@example.test/private?token=query-secret" //nolint:gosec // fake credential-bearing URL verifies redaction.
	store := newSQLiteTestStore(t)
	err := Sync(context.Background(), store, SyncConfig{ServerURL: rawURL})
	if err == nil || !strings.Contains(err.Error(), "refusing to use insecure server URL") {
		t.Fatalf("Sync(insecure secret URL) error = %v", err)
	}
	assertNoSecretURLLeak(t, err.Error())

	client := &http.Client{Transport: syncRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, &url.Error{
			Op:  "Get",
			URL: req.URL.String(),
			Err: errors.New("dial tcp: token=query-secret"),
		}
	})}
	_, err = fetchSyncPage(context.Background(), client, SyncConfig{
		ServerURL:         rawURL,
		AllowInsecureHTTP: true,
	}, "", "", syncCursor{}, 0, "", "")
	if err == nil || !strings.Contains(err.Error(), "sync: server request") {
		t.Fatalf("fetchSyncPage(secret URL request error) = %v", err)
	}
	assertNoSecretURLLeak(t, err.Error())
}

func assertNoSecretURLLeak(t *testing.T, message string) {
	t.Helper()
	for _, leaked := range []string{"server-secret", "query-secret", "/private", "token=query-secret"} {
		if strings.Contains(message, leaked) {
			t.Fatalf("error leaked %q in %q", leaked, message)
		}
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
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSyncXID, "500"); err != nil {
		t.Fatalf("SetSyncMeta(xid) error = %v", err)
	}

	var gotSince, gotSinceXID, gotAuth, gotEcosystem string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSince = r.URL.Query().Get("since")
		gotSinceXID = r.URL.Query().Get("since_xid")
		gotAuth = r.Header.Get("Authorization")
		gotEcosystem = r.URL.Query().Get("ecosystem")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"2026-05-30T11:00:00Z","synced_xid":600}`))
	}))
	defer server.Close()

	if err := Sync(ctx, store, SyncConfig{
		ServerURL:         server.URL,
		APIKey:            "sync-key",
		Ecosystems:        []string{"npm", "go"},
		AllowInsecureHTTP: true,
	}); err != nil {
		t.Fatalf("Sync(incremental) error = %v", err)
	}
	if gotSince != since || gotSinceXID != "500" || gotAuth != "Bearer sync-key" || gotEcosystem != "npm,go" {
		t.Fatalf("request since=%q since_xid=%q auth=%q ecosystem=%q", gotSince, gotSinceXID, gotAuth, gotEcosystem)
	}
	lastSync, err := store.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta() error = %v", err)
	}
	if lastSync != "2026-05-30T11:00:00Z" {
		t.Fatalf("last sync = %q, want updated snapshot", lastSync)
	}
	lastXID, err := store.GetSyncMeta(ctx, syncMetaKeyLastSyncXID)
	if err != nil {
		t.Fatalf("GetSyncMeta(xid) error = %v", err)
	}
	if lastXID != "600" {
		t.Fatalf("last sync xid = %q, want 600", lastXID)
	}
}

func TestSyncRejectsFilteredFullSync(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("filtered full sync should fail before contacting server")
	}))
	defer server.Close()

	err := Sync(context.Background(), store, SyncConfig{
		ServerURL:         server.URL,
		Full:              true,
		Ecosystems:        []string{"npm"},
		AllowInsecureHTTP: true,
	})
	if err == nil || !strings.Contains(err.Error(), "filtered full sync") {
		t.Fatalf("Sync(filtered full) error = %v, want clear rejection", err)
	}
}

func TestSyncStatsReportFullClearAndTombstoneDeletes(t *testing.T) {
	store := newSQLiteTestStore(t)
	ctx := context.Background()
	seedLocalSyncRows(t, store)

	fullServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"2026-05-30T10:00:00Z"}`))
	}))
	defer fullServer.Close()

	var fullStats SyncStats
	if err := Sync(ctx, store, SyncConfig{
		ServerURL:         fullServer.URL,
		Full:              true,
		AllowInsecureHTTP: true,
		Stats:             &fullStats,
	}); err != nil {
		t.Fatalf("Sync(full) error = %v", err)
	}
	if fullStats.FullCleared != (SyncRemovalStats{Vulnerabilities: 1, Malicious: 1, Reputation: 1, Lifecycle: 1}) {
		t.Fatalf("full clear stats = %+v", fullStats.FullCleared)
	}
	if fullStats.TombstoneDeleted.Any() {
		t.Fatalf("tombstone stats after full clear = %+v, want zero", fullStats.TombstoneDeleted)
	}

	seedLocalSyncRows(t, store)
	tombstoneServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"synced_at":"2026-05-30T11:00:00Z",
			"vulnerabilities":[{"id":"GHSA-existing","withdrawn":true}],
			"malicious":[{"id":"MAL-existing","withdrawn":true}],
			"reputation":[{"id":"REP-existing","withdrawn":true}],
			"lifecycle":[{"id":"LIFE-existing","withdrawn":true}]
		}`))
	}))
	defer tombstoneServer.Close()

	var tombstoneStats SyncStats
	if err := Sync(ctx, store, SyncConfig{
		ServerURL:         tombstoneServer.URL,
		AllowInsecureHTTP: true,
		Stats:             &tombstoneStats,
	}); err != nil {
		t.Fatalf("Sync(tombstones) error = %v", err)
	}
	if tombstoneStats.TombstoneDeleted != (SyncRemovalStats{Vulnerabilities: 1, Malicious: 1, Reputation: 1, Lifecycle: 1}) {
		t.Fatalf("tombstone stats = %+v", tombstoneStats.TombstoneDeleted)
	}
	if tombstoneStats.FullCleared.Any() {
		t.Fatalf("full clear stats after tombstones = %+v, want zero", tombstoneStats.FullCleared)
	}
}

func seedLocalSyncRows(t *testing.T, store *Store) {
	t.Helper()
	if _, err := store.DB().ExecContext(context.Background(), `
		DELETE FROM vulnerabilities_local;
		DELETE FROM malicious_local;
		DELETE FROM reputation_findings_local;
		DELETE FROM lifecycle_releases_local;
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity)
		VALUES('GHSA-existing|npm|left-pad', 'GHSA-existing', 'npm', 'left-pad', '[]', 'LOW');
		INSERT INTO malicious_local(id, ecosystem, name, risk_type, severity)
		VALUES('MAL-existing', 'npm', 'evil', 'malware', 'CRITICAL');
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity)
		VALUES('REP-existing', 'npm', 'removed', '1.0.0', 'supply_chain_risk', 'removed_package', 'LOW');
		INSERT INTO lifecycle_releases_local(id, ecosystem, name, product_slug, product_label, cycle, is_eol)
		VALUES('LIFE-existing', 'npm', 'oldlib', 'oldlib', 'oldlib', '1.0', 1);
	`); err != nil {
		t.Fatalf("seed local sync rows: %v", err)
	}
}

func TestSyncFullFailureAfterFirstPagePreservesExistingLocalData(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	if _, err := applySync(ctx, store, true, &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "GHSA-existing",
			Ecosystem:        "npm",
			Name:             "existing",
			VersionRanges:    `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`,
			VersionsAffected: `[]`,
			Severity:         "HIGH",
			Summary:          "existing vulnerability",
		}},
	}); err != nil {
		t.Fatalf("applySync(existing) error = %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, "2026-05-30T09:00:00Z"); err != nil {
		t.Fatalf("SetSyncMeta(existing) error = %v", err)
	}

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			if got := r.URL.Query().Get("since"); got != "" {
				t.Fatalf("first full-sync request since = %q, want empty", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"synced_at":"2026-05-30T10:00:00Z",
				"truncated":true,
				"next_cursor":{"vulnerabilities":1},
				"vulnerabilities":[{
					"id":"GHSA-new",
					"ecosystem":"npm",
					"name":"new",
					"version_ranges":"[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"}]}]",
					"versions_affected":"[]",
					"severity":"CRITICAL",
					"summary":"new vulnerability"
				}]
			}`))
			return
		}
		http.Error(w, "second page failed", http.StatusBadGateway)
	}))
	defer server.Close()

	err := Sync(ctx, store, SyncConfig{ServerURL: server.URL, Full: true, AllowInsecureHTTP: true})
	if err == nil || !strings.Contains(err.Error(), "server returned 502") {
		t.Fatalf("Sync(second page failure) error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}

	existing, err := store.FindVulnerabilities(ctx, "npm", "existing", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(existing) error = %v", err)
	}
	if len(existing) != 1 || existing[0].AdvisoryID != "GHSA-existing" {
		t.Fatalf("existing findings after failed full sync = %+v, want preserved GHSA-existing", existing)
	}
	newRows, err := store.FindVulnerabilities(ctx, "npm", "new", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(new) error = %v", err)
	}
	if len(newRows) != 0 {
		t.Fatalf("new findings after failed full sync = %+v, want no partial page data", newRows)
	}
	lastSync, err := store.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta() error = %v", err)
	}
	if lastSync != "2026-05-30T09:00:00Z" {
		t.Fatalf("last sync after failed full sync = %q, want previous timestamp", lastSync)
	}
}

func TestSyncDoesNotMarkFutureSyncedAtFresh(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	previousSync := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano)
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, previousSync); err != nil {
		t.Fatalf("SetSyncMeta(last sync) error = %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSyncXID, "123"); err != nil {
		t.Fatalf("SetSyncMeta(last xid) error = %v", err)
	}

	futureSync := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("since"); got != previousSync {
			t.Fatalf("since = %q, want previous sync %q", got, previousSync)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"synced_at":"` + futureSync + `",
			"synced_xid":999,
			"vulnerabilities":[{
				"id":"GHSA-future-sync",
				"ecosystem":"npm",
				"name":"future-sync",
				"version_ranges":"[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"}]}]",
				"versions_affected":"[]",
				"severity":"LOW",
				"summary":"future synced_at should not mark freshness"
			}]
		}`))
	}))
	defer server.Close()

	if err := Sync(ctx, store, SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "future-sync", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 1 || findings[0].AdvisoryID != "GHSA-future-sync" {
		t.Fatalf("synced findings = %+v, want applied future-sync row", findings)
	}
	lastSync, err := store.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta(last sync) error = %v", err)
	}
	if lastSync != previousSync {
		t.Fatalf("last sync = %q, want preserved %q", lastSync, previousSync)
	}
	lastXID, err := store.GetSyncMeta(ctx, syncMetaKeyLastSyncXID)
	if err != nil {
		t.Fatalf("GetSyncMeta(last xid) error = %v", err)
	}
	if lastXID != "123" {
		t.Fatalf("last sync xid = %q, want preserved 123", lastXID)
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
	}, "2026-05-30T10:00:00Z", "500", syncCursor{}, syncPageLimit, "snap", "600")
	if err == nil || !strings.Contains(err.Error(), "read response") {
		t.Fatalf("fetchSyncPage(read error) = %v", err)
	}
}

func TestFetchSyncPageRejectsOversizedResponses(t *testing.T) {
	t.Parallel()

	for name, status := range map[string]int{
		"success": http.StatusOK,
		"error":   http.StatusBadGateway,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(strings.Repeat("x", maxSyncResponseSize+1)))
			}))
			defer server.Close()

			_, err := fetchSyncPage(context.Background(), server.Client(), SyncConfig{
				ServerURL:         server.URL,
				AllowInsecureHTTP: true,
			}, "", "", syncCursor{}, 0, "", "")
			if err == nil || !strings.Contains(err.Error(), "response too large") {
				t.Fatalf("fetchSyncPage(%s) error = %v, want response too large", name, err)
			}
		})
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
