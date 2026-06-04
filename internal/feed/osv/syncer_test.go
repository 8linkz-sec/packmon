package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
)

// -- Store stub ---------------------------------------------------------------

type osvStoreStub struct {
	db.Store

	mu               sync.Mutex
	vulns            []*db.Vulnerability
	malicious        []*db.MaliciousFinding
	deletedVulns     []string
	status           *db.FeedSyncStatus
	statusHistory    []db.FeedSyncStatus
	statusErr        error
	upsertErr        error
	vulnUpsertErrIDs map[string]error
}

func (s *osvStoreStub) UpsertVulnerability(_ context.Context, vuln *db.Vulnerability) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vulnUpsertErrIDs != nil {
		if err := s.vulnUpsertErrIDs[vuln.ID]; err != nil {
			return err
		}
	}
	s.vulns = append(s.vulns, vuln)
	return nil
}

func (s *osvStoreStub) UpsertMaliciousFinding(_ context.Context, finding *db.MaliciousFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.malicious = append(s.malicious, finding)
	return nil
}

func (s *osvStoreStub) DeleteVulnerability(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletedVulns = append(s.deletedVulns, id)
	return nil
}

func (s *osvStoreStub) GetFeedSyncStatus(_ context.Context, _ string) (*db.FeedSyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	return s.status, nil
}

func (s *osvStoreStub) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upsertErr != nil {
		return s.upsertErr
	}
	copy := *status
	s.status = &copy
	s.statusHistory = append(s.statusHistory, copy)
	return nil
}

// -- Helper: create an in-memory ZIP with JSON entries ------------------------

func createZIP(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := f.Write(data); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// -- Tests --------------------------------------------------------------------

func TestSync_ETagNotModified(t *testing.T) {
	t.Parallel()

	// The mock server responds 304 Not Modified for every ecosystem.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if etag := r.Header.Get("If-None-Match"); etag != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	store := &osvStoreStub{
		// Pre-load an existing feed status with ETags for all ecosystems.
		status: &db.FeedSyncStatus{
			FeedName: FeedName,
			Metadata: func() json.RawMessage {
				etags := make(map[string]string)
				for _, eco := range feed.OSVBucketEcosystems() {
					etags[eco] = `"some-etag"`
				}
				meta := struct {
					ETags map[string]string `json:"ecosystem_etags"`
				}{ETags: etags}
				b, _ := json.Marshal(meta)
				return b
			}(),
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Override the bucket base URL to point at our test server.
	origURL := bucketBaseURL
	syncer := NewSyncer(store, logger, WithHTTPClient(srv.Client()))

	// We need to intercept the URL. Since bucketBaseURL is a const, we
	// use the test server and make the download method call the test server.
	// The simplest way is to create a server that handles the all.zip path.
	// But the syncer builds URLs from bucketBaseURL which is a const.
	// Instead, we create a custom HTTP client that redirects all requests
	// to the test server.
	_ = origURL
	transport := &rewriteTransport{base: srv.URL, inner: http.DefaultTransport}
	syncer.client = &http.Client{Transport: transport, Timeout: 10 * time.Second}

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result == nil {
		t.Fatal("Sync() result = nil")
	}
	// When all ecosystems respond 304, nothing should be synced.
	if result.EntriesSynced != 0 {
		t.Errorf("EntriesSynced = %d, want 0", result.EntriesSynced)
	}
	// No vulnerabilities should have been upserted.
	if len(store.vulns) != 0 {
		t.Errorf("UpsertVulnerability called %d times, want 0", len(store.vulns))
	}
}

func TestSync_HTTPRateLimitRecordsFailure(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	store := &osvStoreStub{}
	syncer := NewSyncer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	syncer.client = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: http.DefaultTransport},
		Timeout:   10 * time.Second,
	}

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want rate-limit failure")
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil on failed sync", result)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.status == nil || store.status.LastSyncStatus != "error" {
		t.Fatalf("status = %+v, want error", store.status)
	}
	if !strings.Contains(store.status.LastError, "429") {
		t.Fatalf("LastError = %q, want HTTP 429 context", store.status.LastError)
	}
}

func TestSync_ParsesVulnerability(t *testing.T) {
	t.Parallel()

	entry := osvEntry{
		ID:        "GHSA-test-1234-5678",
		Summary:   "Test vulnerability",
		Details:   "Detailed description of the test vuln",
		Published: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Modified:  time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
		Severity: []osvSeverity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
		},
		Affected: []osvAffected{
			{
				Package: osvPackage{
					Ecosystem: "npm",
					Name:      "lodash",
				},
				Ranges: []osvRange{
					{
						Type: "SEMVER",
						Events: []osvEvent{
							{Introduced: "0"},
							{Fixed: "4.17.21"},
						},
					},
				},
			},
		},
		References: []osvReference{
			{Type: "ADVISORY", URL: "https://example.com/advisory"},
		},
	}
	entryJSON, _ := json.Marshal(entry)

	zipData := createZIP(t, map[string][]byte{
		"GHSA-test-1234-5678.json": entryJSON,
	})

	// Serve the ZIP for the first ecosystem ("npm"), 404 for all others.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only serve the npm ecosystem ZIP.
		if r.URL.Path == "/npm/all.zip" {
			w.Header().Set("ETag", `"new-etag"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zipData)
			return
		}
		// All other ecosystems: return 404 (will be treated as unavailable).
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	store := &osvStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	syncer := NewSyncer(store, logger)
	transport := &rewriteTransport{base: srv.URL, inner: http.DefaultTransport}
	syncer.client = &http.Client{Transport: transport, Timeout: 10 * time.Second}

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result == nil {
		t.Fatal("Sync() result = nil")
	}

	// Expect at least one vulnerability to be synced.
	if result.EntriesSynced < 1 {
		t.Errorf("EntriesSynced = %d, want >= 1", result.EntriesSynced)
	}

	// Verify the vulnerability was upserted correctly.
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.vulns) < 1 {
		t.Fatalf("UpsertVulnerability called %d times, want >= 1", len(store.vulns))
	}

	vuln := store.vulns[0]
	if vuln.ID != "GHSA-test-1234-5678" {
		t.Errorf("vuln.ID = %q, want %q", vuln.ID, "GHSA-test-1234-5678")
	}
	if vuln.Summary != "Test vulnerability" {
		t.Errorf("vuln.Summary = %q, want %q", vuln.Summary, "Test vulnerability")
	}
	if len(vuln.AffectedPackages) != 1 {
		t.Fatalf("AffectedPackages count = %d, want 1", len(vuln.AffectedPackages))
	}
	if vuln.AffectedPackages[0].Name != "lodash" {
		t.Errorf("AffectedPackages[0].Name = %q, want %q", vuln.AffectedPackages[0].Name, "lodash")
	}
	if len(vuln.References) != 1 {
		t.Fatalf("References count = %d, want 1", len(vuln.References))
	}
	if vuln.References[0].URL != "https://example.com/advisory" {
		t.Errorf("References[0].URL = %q, want %q", vuln.References[0].URL, "https://example.com/advisory")
	}
}

func TestSync_DoesNotPersistNewETagWhenArchiveImportPartiallyFails(t *testing.T) {
	t.Parallel()

	entry := osvEntry{
		ID:        "GHSA-import-fails",
		Summary:   "Import failure fixture",
		Published: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Modified:  time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
		Affected: []osvAffected{
			{Package: osvPackage{Ecosystem: "npm", Name: "broken"}},
		},
	}
	entryJSON, _ := json.Marshal(entry)
	zipData := createZIP(t, map[string][]byte{
		"GHSA-import-fails.json": entryJSON,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/all.zip" {
			w.Header().Set("ETag", `"new-etag"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zipData)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	oldMeta, _ := json.Marshal(struct {
		ETags map[string]string `json:"ecosystem_etags"`
	}{ETags: map[string]string{"npm": `"old-etag"`}})
	store := &osvStoreStub{
		status: &db.FeedSyncStatus{
			FeedName: FeedName,
			Metadata: oldMeta,
		},
		vulnUpsertErrIDs: map[string]error{"GHSA-import-fails": errors.New("db down")},
	}
	syncer := NewSyncer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	syncer.client = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: http.DefaultTransport},
		Timeout:   10 * time.Second,
	}

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want partial import failure")
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil on failed sync", result)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	for _, status := range store.statusHistory {
		if bytes.Contains(status.Metadata, []byte("new-etag")) {
			t.Fatalf("persisted new ETag despite failed import: %s", status.Metadata)
		}
	}
	if store.status == nil || store.status.LastSyncStatus != "error" {
		t.Fatalf("status = %+v, want error", store.status)
	}
}

func TestSync_ClassifiesRustSecMaliciousCategoryAsMaliciousFinding(t *testing.T) {
	t.Parallel()

	raw := []byte(`{
		"id":"RUSTSEC-2023-0115",
		"summary":"` + "`" + `acceptxmr-rs` + "`" + ` was removed from crates.io for malicious code",
		"details":"This crate was part of a typosquatting malware cluster published by the user Kraded to run an arbitrary malware payload on Windows hosts.",
		"modified":"2026-03-26T06:30:46Z",
		"published":"2023-11-15T12:00:00Z",
		"references":[
			{"type":"PACKAGE","url":"https://crates.io/crates/acceptxmr-rs"},
			{"type":"ADVISORY","url":"https://rustsec.org/advisories/RUSTSEC-2023-0115.html"}
		],
		"affected":[
			{
				"package":{"name":"acceptxmr-rs","ecosystem":"crates.io","purl":"pkg:cargo/acceptxmr-rs"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0.0.0-0"}]}],
				"database_specific":{
					"categories":["malicious"],
					"source":"https://github.com/rustsec/advisory-db/blob/osv/crates/RUSTSEC-2023-0115.json"
				}
			}
		]
	}`)

	zipData := createZIP(t, map[string][]byte{
		"RUSTSEC-2023-0115.json": raw,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crates.io/all.zip" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zipData)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	store := &osvStoreStub{}
	syncer := NewSyncer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	syncer.client = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: http.DefaultTransport},
		Timeout:   10 * time.Second,
	}

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced < 1 {
		t.Fatalf("EntriesSynced = %d, want at least one malicious finding", result.EntriesSynced)
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.vulns) != 0 {
		t.Fatalf("vulnerabilities = %d, want 0 for malicious RustSec category", len(store.vulns))
	}
	if len(store.deletedVulns) != 1 || store.deletedVulns[0] != "RUSTSEC-2023-0115" {
		t.Fatalf("deleted vulnerabilities = %+v, want RUSTSEC-2023-0115 cleanup", store.deletedVulns)
	}
	if len(store.malicious) != 1 {
		t.Fatalf("malicious findings = %d, want 1", len(store.malicious))
	}
	finding := store.malicious[0]
	if finding.ID != "RUSTSEC-2023-0115" {
		t.Fatalf("ID = %q, want RUSTSEC-2023-0115", finding.ID)
	}
	if finding.Ecosystem != "cargo" || finding.Name != "acceptxmr-rs" {
		t.Fatalf("package = %s/%s, want cargo/acceptxmr-rs", finding.Ecosystem, finding.Name)
	}
	if finding.Source != FeedName || finding.Severity != "CRITICAL" {
		t.Fatalf("source/severity = %s/%s, want osv/CRITICAL", finding.Source, finding.Severity)
	}
	if finding.RiskType != "typosquatting" {
		t.Fatalf("risk type = %q, want typosquatting", finding.RiskType)
	}
	if string(finding.Versions) != "" {
		t.Fatalf("versions = %s, want empty/all versions when RustSec version records are unavailable", finding.Versions)
	}
}

func TestSyncerName(t *testing.T) {
	t.Parallel()
	syncer := NewSyncer(nil, nil)
	if syncer.Name() != "osv" {
		t.Errorf("Name() = %q, want %q", syncer.Name(), "osv")
	}
}

func TestOSVMetadataHelpersHandleInvalidAndPersistedETags(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(&osvStoreStub{status: &db.FeedSyncStatus{Metadata: json.RawMessage(`not json`)}}, nil)
	if got := syncer.loadEcosystemETags(context.Background()); len(got) != 0 {
		t.Fatalf("loadEcosystemETags(invalid) = %+v, want empty map", got)
	}

	store := &osvStoreStub{status: &db.FeedSyncStatus{FeedName: FeedName}}
	syncer = NewSyncer(store, nil)
	syncer.saveEcosystemETags(context.Background(), map[string]string{"npm": `"etag"`})
	if store.status == nil || !bytes.Contains(store.status.Metadata, []byte(`"npm"`)) {
		t.Fatalf("saved metadata = %s", store.status.Metadata)
	}

	store.statusErr = io.ErrUnexpectedEOF
	if got := syncer.loadEcosystemETags(context.Background()); len(got) != 0 {
		t.Fatalf("loadEcosystemETags(error) = %+v, want empty map", got)
	}
	syncer.saveEcosystemETags(context.Background(), map[string]string{"go": "etag"})
}

func TestOSVMappingHelpersCoverMaliciousAndSeverityBranches(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		summary string
		details string
		want    string
	}{
		{summary: "typosquat package", want: "typosquatting"},
		{details: "dependency confusion attack", want: "supply_chain"},
		{details: "supply-chain compromise", want: "supply_chain"},
		{summary: "malware", want: "malware"},
	} {
		got := classifyMaliciousRiskType(&osvEntry{Summary: tt.summary, Details: tt.details})
		if got != tt.want {
			t.Fatalf("classifyMaliciousRiskType(%q,%q) = %q, want %q", tt.summary, tt.details, got, tt.want)
		}
	}
	if got := classifyMaliciousRiskType(&osvEntry{
		Summary:          "generic malicious package",
		DatabaseSpecific: json.RawMessage(`{"classification":"typo-squatting"}`),
	}); got != "typosquatting" {
		t.Fatalf("classifyMaliciousRiskType(database_specific) = %q, want typosquatting", got)
	}

	affected := osvAffected{
		Package:          osvPackage{Ecosystem: "npm", Name: "left-pad"},
		Versions:         []string{"1.0.0"},
		Ranges:           []osvRange{{Events: []osvEvent{{Introduced: "1.1.0"}, {Introduced: "0"}}}},
		DatabaseSpecific: json.RawMessage(`{"categories":["malicious"],"source":"https://example.test/source"}`),
	}
	if !affectedHasMaliciousCategory(affected) {
		t.Fatal("affectedHasMaliciousCategory() = false, want true")
	}
	if got := affectedSource(affected); got != "https://example.test/source" {
		t.Fatalf("affectedSource() = %q", got)
	}
	if versions := string(maliciousVersions(affected)); !strings.Contains(versions, "1.0.0") || !strings.Contains(versions, "1.1.0") {
		t.Fatalf("maliciousVersions() = %s", versions)
	}
	if got := string(marshalReferenceURLs([]osvReference{{URL: ""}, {URL: "https://example.test/ref"}})); got != `["https://example.test/ref"]` {
		t.Fatalf("marshalReferenceURLs() = %s", got)
	}

	findings := mapToMaliciousFindings(&osvEntry{
		ID:        "OSV-MAL",
		Summary:   "malware",
		Published: time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC),
		Affected:  []osvAffected{affected, affected},
	})
	if len(findings) != 2 || findings[1].ID != "OSV-MAL-1" {
		t.Fatalf("mapToMaliciousFindings() = %+v", findings)
	}
	affected.DatabaseSpecific = json.RawMessage(`{"categories":["malicious","dependency_confusion"],"source":"https://example.test/source"}`)
	findings = mapToMaliciousFindings(&osvEntry{ID: "OSV-MAL-RISK", Summary: "malware", Affected: []osvAffected{affected}})
	if len(findings) != 1 || findings[0].RiskType != "supply_chain" {
		t.Fatalf("mapToMaliciousFindings(affected risk) = %+v, want supply_chain", findings)
	}

	if got := mapSeverity(&osvEntry{DatabaseSpecific: json.RawMessage(`{"severity":"moderate"}`)}); got != "MEDIUM" {
		t.Fatalf("mapSeverity(database_specific) = %q, want MEDIUM", got)
	}
	if got := mapSeverity(&osvEntry{DatabaseSpecific: json.RawMessage(`{"severity":"unknown"}`)}); got != "UNKNOWN" {
		t.Fatalf("mapSeverity(unknown db severity) = %q, want UNKNOWN", got)
	}
	for raw, want := range map[string]string{
		`{"severity":"critical"}`: "CRITICAL",
		`{"severity":"HIGH"}`:     "HIGH",
		`{"severity":"LOW"}`:      "LOW",
		`not json`:                "UNKNOWN",
	} {
		if got := mapSeverity(&osvEntry{DatabaseSpecific: json.RawMessage(raw)}); got != want {
			t.Fatalf("mapSeverity(%s) = %q, want %q", raw, got, want)
		}
	}
	if affectedHasMaliciousCategory(osvAffected{DatabaseSpecific: json.RawMessage(`not json`)}) {
		t.Fatal("affectedHasMaliciousCategory(invalid json) = true")
	}
	if got := affectedSource(osvAffected{DatabaseSpecific: json.RawMessage(`not json`)}); got != "" {
		t.Fatalf("affectedSource(invalid json) = %q, want empty", got)
	}
	if got := maliciousVersions(osvAffected{}); got != nil {
		t.Fatalf("maliciousVersions(empty) = %s, want nil", string(got))
	}
}

func TestMapToVulnerabilityCoversAliasesWithdrawnAndUnsupportedEcosystem(t *testing.T) {
	t.Parallel()

	withdrawn := "2026-05-30T12:00:00Z"
	vuln := mapToVulnerability(&osvEntry{
		ID:        "OSV-2026-0001",
		Summary:   "summary",
		Details:   "details",
		Aliases:   []string{"CVE-2026-0001", "OSV-2026-0001"},
		Published: time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
		Modified:  time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
		Withdrawn: &withdrawn,
		Affected: []osvAffected{
			{Package: osvPackage{Ecosystem: "Maven:org.example", Name: "artifact"}},
			{Package: osvPackage{Ecosystem: "unsupported", Name: "ignored"}},
		},
		References: []osvReference{{Type: "ADVISORY", URL: ""}, {Type: "WEB", URL: "https://example.test"}},
	}, []byte(`{"id":"OSV-2026-0001"}`))

	if vuln.Withdrawn == nil || !vuln.Withdrawn.Equal(time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("Withdrawn = %v, want parsed timestamp", vuln.Withdrawn)
	}
	if len(vuln.Aliases) != 2 {
		t.Fatalf("aliases = %+v, want ID plus CVE without duplicate", vuln.Aliases)
	}
	if len(vuln.AffectedPackages) != 1 || vuln.AffectedPackages[0].Ecosystem != "maven" {
		t.Fatalf("affected packages = %+v, want only canonical maven package", vuln.AffectedPackages)
	}
	if len(vuln.References) != 1 || vuln.References[0].URL != "https://example.test" {
		t.Fatalf("references = %+v", vuln.References)
	}

	badWithdrawn := "not a timestamp"
	vuln = mapToVulnerability(&osvEntry{ID: "OSV-2026-0002", Withdrawn: &badWithdrawn}, nil)
	if vuln.Withdrawn != nil {
		t.Fatalf("invalid withdrawn parsed as %v, want nil", vuln.Withdrawn)
	}
}

func TestRecordSyncStatusBranches(t *testing.T) {
	t.Parallel()

	store := &osvStoreStub{}
	syncer := NewSyncer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	start := time.Now().Add(-time.Second)

	syncer.recordSyncSuccess(context.Background(), start, time.Second, 7, 5)
	if store.status == nil || store.status.LastSyncStatus != "success" || store.status.EntriesSynced != 5 {
		t.Fatalf("success status = %+v", store.status)
	}
	syncer.recordSyncFailure(context.Background(), start, io.ErrUnexpectedEOF)
	if store.status == nil || store.status.LastSyncStatus != "error" || !strings.Contains(store.status.LastError, "unexpected EOF") {
		t.Fatalf("failure status = %+v", store.status)
	}

	store.upsertErr = io.ErrClosedPipe
	syncer.recordSyncSuccess(context.Background(), start, time.Second, 1, 1)
	syncer.recordSyncFailure(context.Background(), start, io.ErrUnexpectedEOF)
}

// Verify compile-time interface compliance.
var _ feed.FeedSyncer = (*Syncer)(nil)

// -- Transport helper ---------------------------------------------------------

// rewriteTransport rewrites all request URLs to point at the test server,
// preserving the original path.
type rewriteTransport struct {
	base  string // e.g. "http://127.0.0.1:PORT"
	inner http.RoundTripper
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := t.base + req.URL.Path
	// #nosec G704 -- test transport rewrites requests to a local httptest server.
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return t.inner.RoundTrip(newReq)
}
