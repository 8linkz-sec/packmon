package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
)

// -- Store stub ---------------------------------------------------------------

type osvStoreStub struct {
	db.Store

	mu     sync.Mutex
	vulns  []*db.Vulnerability
	status *db.FeedSyncStatus
}

func (s *osvStoreStub) UpsertVulnerability(_ context.Context, vuln *db.Vulnerability) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vulns = append(s.vulns, vuln)
	return nil
}

func (s *osvStoreStub) GetFeedSyncStatus(_ context.Context, _ string) (*db.FeedSyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status, nil
}

func (s *osvStoreStub) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *status
	s.status = &copy
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

func TestSyncerName(t *testing.T) {
	t.Parallel()
	syncer := NewSyncer(nil, nil)
	if syncer.Name() != "osv" {
		t.Errorf("Name() = %q, want %q", syncer.Name(), "osv")
	}
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
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return t.inner.RoundTrip(newReq)
}
