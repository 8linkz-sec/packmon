package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

// -- Store stub ---------------------------------------------------------------

type osvStoreStub struct {
	db.Store

	mu               sync.Mutex
	vulns            []*db.Vulnerability
	malicious        []*db.MaliciousFinding
	deletedVulns     []string
	deletedSources   []string
	status           *db.FeedSyncStatus
	statusHistory    []db.FeedSyncStatus
	statusErr        error
	upsertErr        error
	vulnUpsertErrIDs map[string]error
	rejectCanceled   bool
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

func (s *osvStoreStub) DeleteVulnerabilityForSource(_ context.Context, id, source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletedVulns = append(s.deletedVulns, id)
	s.deletedSources = append(s.deletedSources, source)
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

func (s *osvStoreStub) UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rejectCanceled && ctx.Err() != nil {
		return ctx.Err()
	}
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

func zipEntry(t *testing.T, name string, data []byte) *zip.File {
	t.Helper()

	zipData := createZIP(t, map[string][]byte{name: data})
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("zip reader: %v", err)
	}
	if len(reader.File) != 1 {
		t.Fatalf("zip entries = %d, want 1", len(reader.File))
	}
	return reader.File[0]
}

// -- Tests --------------------------------------------------------------------

func TestOSVPackageUnmarshalsPURL(t *testing.T) {
	var pkg osvPackage
	if err := json.Unmarshal([]byte(`{"ecosystem":"npm","name":"left-pad","purl":"pkg:npm/left-pad"}`), &pkg); err != nil {
		t.Fatalf("Unmarshal(osvPackage) error = %v", err)
	}
	if pkg.PURL != "pkg:npm/left-pad" {
		t.Fatalf("pkg.PURL = %q, want %q", pkg.PURL, "pkg:npm/left-pad")
	}
}

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
			FeedName:       FeedName,
			LastSyncStatus: "success",
			EntriesSynced:  17,
			EntriesTotal:   23,
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
	syncer := NewSyncer(logger, WithHTTPClient(srv.Client()))

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
	if result.EntriesSynced != 17 {
		t.Errorf("EntriesSynced = %d, want preserved 17", result.EntriesSynced)
	}
	if result.EntriesTotal != 23 {
		t.Errorf("EntriesTotal = %d, want preserved 23", result.EntriesTotal)
	}
	// No vulnerabilities should have been upserted.
	if len(store.vulns) != 0 {
		t.Errorf("UpsertVulnerability called %d times, want 0", len(store.vulns))
	}
	if store.status == nil || store.status.EntriesSynced != 17 || store.status.EntriesTotal != 23 {
		t.Fatalf("status after 304 = %+v, want preserved counts", store.status)
	}
}

func TestSync_HTTPRateLimitRecordsFailure(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	store := &osvStoreStub{}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)))
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

func TestSync_TransportErrorRecordsFailureAndPreservesCachedState(t *testing.T) {
	t.Parallel()

	lastSyncAt := time.Date(2026, 6, 1, 12, 30, 0, 0, time.UTC)
	oldMeta, err := json.Marshal(struct {
		ETags map[string]string `json:"ecosystem_etags"`
	}{ETags: map[string]string{"npm": `"old-etag"`}})
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}

	store := &osvStoreStub{
		status: &db.FeedSyncStatus{
			FeedName:       FeedName,
			LastSyncAt:     &lastSyncAt,
			LastSyncStatus: db.FeedSyncStatusSuccess,
			EntriesSynced:  11,
			EntriesTotal:   17,
			LastETag:       `"legacy-feed-etag"`,
			Metadata:       oldMeta,
		},
	}
	dnsErr := &net.DNSError{Err: "no such host", Name: "osv-unreachable.test", IsNotFound: true}
	syncer := NewSyncer(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithBaseURL("https://osv-unreachable.test"),
		WithHTTPClient(&http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return nil, dnsErr
			}),
		}),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want transport failure")
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil on failed sync", result)
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if got := len(store.statusHistory); got != 1 {
		t.Fatalf("status history entries = %d, want one failed sync status only", got)
	}
	if store.status == nil || store.status.LastSyncStatus != db.FeedSyncStatusError {
		t.Fatalf("status = %+v, want error", store.status)
	}
	if !strings.Contains(store.status.LastError, "no such host") {
		t.Fatalf("LastError = %q, want DNS transport error context", store.status.LastError)
	}
	if store.status.LastSyncAt == nil || !store.status.LastSyncAt.Equal(lastSyncAt) {
		t.Fatalf("LastSyncAt = %v, want preserved %v", store.status.LastSyncAt, lastSyncAt)
	}
	if store.status.EntriesSynced != 11 || store.status.EntriesTotal != 17 {
		t.Fatalf("counts = synced %d total %d, want preserved 11/17", store.status.EntriesSynced, store.status.EntriesTotal)
	}
	if store.status.LastETag != `"legacy-feed-etag"` {
		t.Fatalf("LastETag = %q, want preserved legacy feed ETag", store.status.LastETag)
	}
	if !bytes.Equal(store.status.Metadata, oldMeta) {
		t.Fatalf("metadata = %s, want preserved %s", store.status.Metadata, oldMeta)
	}
	if len(store.vulns) != 0 || len(store.malicious) != 0 || len(store.deletedVulns) != 0 {
		t.Fatalf("store mutated despite transport failure: vulns=%d malicious=%d deleted=%d", len(store.vulns), len(store.malicious), len(store.deletedVulns))
	}
}

func TestDownloadLogsTempFilenameWithoutFullPath(t *testing.T) {
	t.Parallel()

	zipData := createZIP(t, map[string][]byte{"GHSA-test.json": []byte(`{"id":"GHSA-test"}`)})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zipData)
	}))
	defer srv.Close()

	var logs bytes.Buffer
	syncer := NewSyncer(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), WithHTTPClient(srv.Client()))
	tmpPath, _, err := syncer.download(context.Background(), srv.URL+"/npm/all.zip", "")
	if err != nil {
		t.Fatalf("download() error = %v", err)
	}
	defer func() { _ = os.Remove(tmpPath) }()

	logLine := logs.String()
	if strings.Contains(logLine, tmpPath) || strings.Contains(logLine, filepath.Dir(tmpPath)) || strings.Contains(logLine, `"path"`) {
		t.Fatalf("download log leaked temp path %q: %s", tmpPath, logLine)
	}
	if !strings.Contains(logLine, `"file":"`+filepath.Base(tmpPath)+`"`) {
		t.Fatalf("download log missing temp filename %q: %s", filepath.Base(tmpPath), logLine)
	}
}

func TestDownloadBoundsErrorBodyDrain(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			body := &countingReadCloser{remaining: 1 << 20}
			syncer := NewSyncer(
				slog.New(slog.NewTextHandler(io.Discard, nil)),
				WithHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: status,
						Header:     make(http.Header),
						Body:       body,
						Request:    req,
					}, nil
				})}),
			)

			tmpPath, _, err := syncer.download(context.Background(), "https://osv.example.test/npm/all.zip", "")
			if tmpPath != "" {
				t.Fatalf("download() tmpPath = %q, want empty on error", tmpPath)
			}
			var unavailable *errArchiveUnavailable
			if !errors.As(err, &unavailable) || unavailable.statusCode != status {
				t.Fatalf("download() error = %v, want archive unavailable status %d", err, status)
			}
			if body.read > maxErrorBodyDrain {
				t.Fatalf("drained %d bytes, want at most %d", body.read, maxErrorBodyDrain)
			}
			if !body.closed {
				t.Fatal("download() did not close error response body")
			}
		})
	}
}

func TestDownloadReportsTempArchiveCloseError(t *testing.T) {
	t.Parallel()

	zipData := createZIP(t, map[string][]byte{
		"GHSA-close-error.json": []byte(`{"id":"GHSA-close-error"}`),
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"close-error-etag"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zipData)
	}))
	defer srv.Close()

	closeErr := errors.New("forced temp archive close failure")
	temp := &failingCloseTempArchive{closeErr: closeErr}
	removeCalls := 0

	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)), WithHTTPClient(srv.Client()))
	tmpPath, etag, err := syncer.downloadWithTempArchiveFileHooks(context.Background(), srv.URL+"/npm/all.zip", "", tempArchiveFileHooks{
		create: func() (tempArchiveWriteFile, error) {
			return temp, nil
		},
		remove: func(path string) error {
			removeCalls++
			if path != temp.Name() {
				t.Fatalf("removed path = %q, want %q", path, temp.Name())
			}
			return nil
		},
	})
	if err == nil {
		t.Fatal("downloadWithTempArchiveFileHooks() error = nil, want temp archive close error")
	}
	if !errors.Is(err, closeErr) || !strings.Contains(err.Error(), "close temp archive") {
		t.Fatalf("downloadWithTempArchiveFileHooks() error = %v, want wrapped close temp archive error", err)
	}
	if tmpPath != "" {
		t.Fatalf("downloadWithTempArchiveFileHooks() tmpPath = %q, want empty on close error", tmpPath)
	}
	if etag != "" {
		t.Fatalf("downloadWithTempArchiveFileHooks() etag = %q, want empty on close error", etag)
	}
	if temp.closeCalls != 1 {
		t.Fatalf("temp archive Close calls = %d, want 1", temp.closeCalls)
	}
	if removeCalls != 1 {
		t.Fatalf("temp archive remove calls = %d, want 1", removeCalls)
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

	syncer := NewSyncer(logger)
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

func TestSyncDeletesWithdrawnVulnerability(t *testing.T) {
	t.Parallel()

	withdrawn := time.Date(2026, 6, 9, 15, 56, 0, 0, time.UTC).Format(time.RFC3339)
	entry := osvEntry{
		ID:        "PYSEC-2025-74",
		Summary:   "Withdrawn Jinja2 advisory",
		Published: time.Date(2025, 6, 10, 16, 15, 42, 0, time.UTC),
		Modified:  time.Date(2026, 6, 9, 17, 0, 5, 0, time.UTC),
		Withdrawn: &withdrawn,
		Aliases:   []string{"CVE-2025-49142", "GHSA-wjw6-95h5-4jpx"},
		Affected: []osvAffected{
			{
				Package: osvPackage{
					Ecosystem: "PyPI",
					Name:      "jinja2",
				},
			},
		},
	}
	entryJSON, _ := json.Marshal(entry)
	zipData := createZIP(t, map[string][]byte{
		"PYSEC-2025-74.json": entryJSON,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/PyPI/all.zip" {
			w.Header().Set("ETag", `"pypi-etag"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zipData)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	store := &osvStoreStub{}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	syncer.client = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: http.DefaultTransport},
		Timeout:   10 * time.Second,
	}

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 1 {
		t.Fatalf("EntriesSynced = %d, want 1 withdrawn deletion", result.EntriesSynced)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.deletedVulns) != 1 || store.deletedVulns[0] != "PYSEC-2025-74" {
		t.Fatalf("deleted vulnerabilities = %#v, want PYSEC-2025-74", store.deletedVulns)
	}
	if len(store.deletedSources) != 1 || store.deletedSources[0] != FeedName {
		t.Fatalf("deleted sources = %#v, want %s", store.deletedSources, FeedName)
	}
	if len(store.vulns) != 0 {
		t.Fatalf("upserted vulnerabilities = %d, want 0 for withdrawn entry", len(store.vulns))
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
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	syncer.client = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: http.DefaultTransport},
		Timeout:   10 * time.Second,
	}

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want partial import failure")
	}
	if feed.IsNonRetryableError(err) {
		t.Fatalf("Sync() error = %v, want retryable DB import failure", err)
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

func TestSync_MalformedArchiveEntryReturnsNonRetryableErrorAndDoesNotPersistNewETag(t *testing.T) {
	t.Parallel()

	zipData := createZIP(t, map[string][]byte{
		"GHSA-malformed.json": []byte(`{"id":"GHSA-malformed","modified":"not a timestamp"`),
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
	}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	syncer.client = &http.Client{
		Transport: &rewriteTransport{base: srv.URL, inner: http.DefaultTransport},
		Timeout:   10 * time.Second,
	}

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want malformed entry failure")
	}
	if !feed.IsNonRetryableError(err) {
		t.Fatalf("Sync() error = %v, want non-retryable malformed archive entry error", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil on failed sync", result)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	for _, status := range store.statusHistory {
		if bytes.Contains(status.Metadata, []byte("new-etag")) {
			t.Fatalf("persisted new ETag despite malformed entry: %s", status.Metadata)
		}
	}
	if store.status == nil || store.status.LastSyncStatus != db.FeedSyncStatusError {
		t.Fatalf("status = %+v, want error", store.status)
	}
	if !bytes.Equal(store.status.Metadata, oldMeta) {
		t.Fatalf("metadata = %s, want preserved %s", store.status.Metadata, oldMeta)
	}
	if len(store.vulns) != 0 || len(store.malicious) != 0 || len(store.deletedVulns) != 0 {
		t.Fatalf("store mutated despite malformed entry: vulns=%d malicious=%d deleted=%d", len(store.vulns), len(store.malicious), len(store.deletedVulns))
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
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)))
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
	if len(store.deletedSources) != 1 || store.deletedSources[0] != FeedName {
		t.Fatalf("deleted sources = %+v, want %s cleanup", store.deletedSources, FeedName)
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

func TestProcessOSVEntryReturnsOutcomeForEntryTypes(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)))

	t.Run("skipped MAL advisory", func(t *testing.T) {
		t.Parallel()

		store := &osvStoreStub{}
		result := syncer.processOSVEntry(context.Background(), store, zipEntry(t, "MAL-2026-0001.json", []byte(`{"id":"MAL-2026-0001"}`)))

		if result.outcome != osvEntryOutcomeSkipped {
			t.Fatalf("outcome = %s, want %s", result.outcome, osvEntryOutcomeSkipped)
		}
		if result.synced != 0 || result.errors != 0 {
			t.Fatalf("result = %+v, want no synced entries or errors", result)
		}
		if len(store.vulns) != 0 || len(store.malicious) != 0 || len(store.deletedVulns) != 0 {
			t.Fatalf("store mutated for skipped entry: vulns=%d malicious=%d deleted=%d", len(store.vulns), len(store.malicious), len(store.deletedVulns))
		}
	})

	t.Run("withdrawn vulnerability delete", func(t *testing.T) {
		t.Parallel()

		withdrawn := "2026-06-09T15:56:00Z"
		raw, err := json.Marshal(osvEntry{
			ID:        "PYSEC-2026-0001",
			Withdrawn: &withdrawn,
		})
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		store := &osvStoreStub{}
		result := syncer.processOSVEntry(context.Background(), store, zipEntry(t, "PYSEC-2026-0001.json", raw))

		if result.outcome != osvEntryOutcomeDeleted {
			t.Fatalf("outcome = %s, want %s", result.outcome, osvEntryOutcomeDeleted)
		}
		if result.synced != 1 || result.errors != 0 {
			t.Fatalf("result = %+v, want one synced delete and no errors", result)
		}
		if len(store.deletedVulns) != 1 || store.deletedVulns[0] != "PYSEC-2026-0001" {
			t.Fatalf("deleted vulnerabilities = %+v, want PYSEC-2026-0001", store.deletedVulns)
		}
		if len(store.deletedSources) != 1 || store.deletedSources[0] != FeedName {
			t.Fatalf("deleted sources = %+v, want %s", store.deletedSources, FeedName)
		}
	})

	t.Run("malicious category finding", func(t *testing.T) {
		t.Parallel()

		raw := []byte(`{
			"id":"RUSTSEC-2026-0001",
			"summary":"malware package",
			"published":"2026-01-01T00:00:00Z",
			"affected":[{
				"package":{"name":"badcrate","ecosystem":"crates.io"},
				"database_specific":{"categories":["malicious"]}
			}]
		}`)
		store := &osvStoreStub{}
		result := syncer.processOSVEntry(context.Background(), store, zipEntry(t, "RUSTSEC-2026-0001.json", raw))

		if result.outcome != osvEntryOutcomeMalicious {
			t.Fatalf("outcome = %s, want %s", result.outcome, osvEntryOutcomeMalicious)
		}
		if result.synced != 1 || result.errors != 0 {
			t.Fatalf("result = %+v, want one synced malicious finding and no errors", result)
		}
		if len(store.deletedVulns) != 1 || store.deletedVulns[0] != "RUSTSEC-2026-0001" {
			t.Fatalf("deleted vulnerabilities = %+v, want cleanup of superseded vulnerability", store.deletedVulns)
		}
		if len(store.deletedSources) != 1 || store.deletedSources[0] != FeedName {
			t.Fatalf("deleted sources = %+v, want %s cleanup", store.deletedSources, FeedName)
		}
		if len(store.malicious) != 1 || store.malicious[0].ID != "RUSTSEC-2026-0001" {
			t.Fatalf("malicious findings = %+v, want RUSTSEC-2026-0001", store.malicious)
		}
	})

	t.Run("vulnerability upsert", func(t *testing.T) {
		t.Parallel()

		raw, err := json.Marshal(osvEntry{
			ID:      "GHSA-2026-0001",
			Summary: "regular vulnerability",
			Affected: []osvAffected{
				{Package: osvPackage{Ecosystem: "npm", Name: "left-pad"}},
			},
		})
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		store := &osvStoreStub{}
		result := syncer.processOSVEntry(context.Background(), store, zipEntry(t, "GHSA-2026-0001.json", raw))

		if result.outcome != osvEntryOutcomeVulnerability {
			t.Fatalf("outcome = %s, want %s", result.outcome, osvEntryOutcomeVulnerability)
		}
		if result.synced != 1 || result.errors != 0 {
			t.Fatalf("result = %+v, want one synced vulnerability and no errors", result)
		}
		if len(store.vulns) != 1 || store.vulns[0].ID != "GHSA-2026-0001" {
			t.Fatalf("vulnerabilities = %+v, want GHSA-2026-0001", store.vulns)
		}
	})

	t.Run("parse error", func(t *testing.T) {
		t.Parallel()

		store := &osvStoreStub{}
		result := syncer.processOSVEntry(context.Background(), store, zipEntry(t, "broken.json", []byte(`not json`)))

		if result.outcome != osvEntryOutcomeError {
			t.Fatalf("outcome = %s, want %s", result.outcome, osvEntryOutcomeError)
		}
		if result.synced != 0 || result.errors != 1 {
			t.Fatalf("result = %+v, want one entry error and no synced entries", result)
		}
	})
}

func TestSyncerName(t *testing.T) {
	t.Parallel()
	syncer := NewSyncer(nil)
	if syncer.Name() != "osv" {
		t.Errorf("Name() = %q, want %q", syncer.Name(), "osv")
	}
}

func TestSyncerDoesNotOwnStoreOutsideSyncContract(t *testing.T) {
	t.Parallel()

	syncerType := reflect.TypeOf(Syncer{})
	storeType := reflect.TypeOf((*db.Store)(nil)).Elem()
	for i := 0; i < syncerType.NumField(); i++ {
		field := syncerType.Field(i)
		if field.Type == storeType {
			t.Fatalf("Syncer field %s stores db.Store; use Sync(ctx, store) as the only persistence input", field.Name)
		}
	}

	source, err := os.ReadFile("syncer.go")
	if err != nil {
		t.Fatalf("read syncer.go: %v", err)
	}
	if regexp.MustCompile(`(?m)^\s*store\s+db\.Store\b`).Match(source) {
		t.Fatal("syncer.go declares a store db.Store field; use Sync(ctx, store) as the only persistence input")
	}
	if strings.Contains(string(source), "s.store") {
		t.Fatal("syncer.go references s.store; use the store passed to Sync(ctx, store)")
	}
}

func TestOSVMetadataHelpersHandleInvalidAndPersistedETags(t *testing.T) {
	t.Parallel()

	invalidStore := &osvStoreStub{status: &db.FeedSyncStatus{Metadata: json.RawMessage(`not json`)}}
	syncer := NewSyncer(nil)
	if got := ecosystemETags(syncer.loadFeedStatus(context.Background(), invalidStore)); len(got) != 0 {
		t.Fatalf("ecosystemETags(invalid metadata) = %+v, want empty map", got)
	}

	store := &osvStoreStub{status: &db.FeedSyncStatus{FeedName: FeedName}}
	syncer = NewSyncer(nil)
	syncer.saveEcosystemETags(context.Background(), store, map[string]string{"npm": `"etag"`})
	if store.status == nil || !bytes.Contains(store.status.Metadata, []byte(`"npm"`)) {
		t.Fatalf("saved metadata = %s", store.status.Metadata)
	}

	store.statusErr = io.ErrUnexpectedEOF
	if got := ecosystemETags(syncer.loadFeedStatus(context.Background(), store)); len(got) != 0 {
		t.Fatalf("ecosystemETags(load status error) = %+v, want empty map", got)
	}
	syncer.saveEcosystemETags(context.Background(), store, map[string]string{"go": "etag"})
}

func TestLoadFeedStatusLogsReadFailureBeforeFullSyncFallback(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	syncer := NewSyncer(slog.New(slog.NewJSONHandler(&logs, nil)))
	store := &osvStoreStub{
		statusErr: errors.New(`GET https://user:secret@feeds.example.test/private/osv?token=query-secret failed from C:\Users\Admin\Packmon\feed.json`),
	}

	if got := syncer.loadFeedStatus(context.Background(), store); got != nil {
		t.Fatalf("loadFeedStatus() = %+v, want nil after status read failure", got)
	}

	logOutput := logs.String()
	for _, want := range []string{
		`"level":"WARN"`,
		`"msg":"failed to get feed sync status, proceeding with full sync"`,
		`"feed":"osv"`,
		`"error":`,
	} {
		if !strings.Contains(logOutput, want) {
			t.Fatalf("log output missing %s: %s", want, logOutput)
		}
	}
	for _, leaked := range []string{"user:secret", "query-secret", "/private/osv", `C:\Users\Admin\Packmon\feed.json`} {
		if strings.Contains(logOutput, leaked) {
			t.Fatalf("log output leaked %q: %s", leaked, logOutput)
		}
	}
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

func TestMapToVulnerabilityDerivesClosureFromLastKnownAffectedRange(t *testing.T) {
	t.Parallel()

	vuln := mapToVulnerability(&osvEntry{
		ID: "GHSA-62gx-5q78-wrvx",
		Affected: []osvAffected{{
			Package:          osvPackage{Ecosystem: "npm", Name: "obsidian-local-rest-api"},
			Ranges:           []osvRange{{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}}}},
			DatabaseSpecific: json.RawMessage(`{"last_known_affected_version_range": "< 4.1.3"}`),
		}},
	}, nil)
	if len(vuln.AffectedPackages) != 1 {
		t.Fatalf("affected packages = %+v, want 1", vuln.AffectedPackages)
	}
	var ranges []osvRange
	if err := json.Unmarshal(vuln.AffectedPackages[0].VersionRanges, &ranges); err != nil {
		t.Fatalf("unmarshal version ranges: %v", err)
	}
	if len(ranges) != 1 || len(ranges[0].Events) != 2 || ranges[0].Events[1].Fixed != "4.1.3" {
		t.Fatalf("ranges = %+v, want closure event with fixed 4.1.3 appended", ranges)
	}

	vuln = mapToVulnerability(&osvEntry{
		ID: "GHSA-le-case",
		Affected: []osvAffected{{
			Package:          osvPackage{Ecosystem: "npm", Name: "pkg"},
			Ranges:           []osvRange{{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}}}},
			DatabaseSpecific: json.RawMessage(`{"last_known_affected_version_range": "<= 2.0.0"}`),
		}},
	}, nil)
	if err := json.Unmarshal(vuln.AffectedPackages[0].VersionRanges, &ranges); err != nil {
		t.Fatalf("unmarshal version ranges: %v", err)
	}
	if len(ranges) != 1 || len(ranges[0].Events) != 2 || ranges[0].Events[1].LastAffected != "2.0.0" {
		t.Fatalf("ranges = %+v, want closure event with last_affected 2.0.0 appended", ranges)
	}

	vuln = mapToVulnerability(&osvEntry{
		ID: "GHSA-already-closed",
		Affected: []osvAffected{{
			Package:          osvPackage{Ecosystem: "npm", Name: "pkg"},
			Ranges:           []osvRange{{Type: "SEMVER", Events: []osvEvent{{Introduced: "0", Fixed: "1.5.0"}}}},
			DatabaseSpecific: json.RawMessage(`{"last_known_affected_version_range": "< 2.0.0"}`),
		}},
	}, nil)
	if err := json.Unmarshal(vuln.AffectedPackages[0].VersionRanges, &ranges); err != nil {
		t.Fatalf("unmarshal version ranges: %v", err)
	}
	if len(ranges) != 1 || len(ranges[0].Events) != 1 || ranges[0].Events[0].Fixed != "1.5.0" {
		t.Fatalf("ranges = %+v, want existing closure untouched", ranges)
	}
}

func TestRecordSyncStatusBranches(t *testing.T) {
	t.Parallel()

	store := &osvStoreStub{}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	start := time.Now().Add(-time.Second)

	syncer.recordSyncSuccess(context.Background(), store, time.Second, 7, 5)
	if store.status == nil || store.status.LastSyncStatus != "success" || store.status.EntriesSynced != 5 {
		t.Fatalf("success status = %+v", store.status)
	}
	lastSuccessfulSync := *store.status.LastSyncAt
	syncer.recordSyncFailure(context.Background(), store, start, io.ErrUnexpectedEOF)
	if store.status == nil || store.status.LastSyncStatus != "error" || !strings.Contains(store.status.LastError, "unexpected EOF") {
		t.Fatalf("failure status = %+v", store.status)
	}
	if store.status.LastSyncAt == nil || !store.status.LastSyncAt.Equal(lastSuccessfulSync) || store.status.EntriesTotal != 7 {
		t.Fatalf("failure status did not preserve data freshness/counts: %+v", store.status)
	}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	store.rejectCanceled = true
	syncer.recordSyncFailure(canceledCtx, store, start, context.Canceled)
	if got := len(store.statusHistory); got != 3 {
		t.Fatalf("status history after canceled context = %d, want 3", got)
	}

	store.upsertErr = io.ErrClosedPipe
	syncer.recordSyncSuccess(context.Background(), store, time.Second, 1, 1)
	syncer.recordSyncFailure(context.Background(), store, start, io.ErrUnexpectedEOF)
}

// Verify compile-time interface compliance.
var _ feed.FeedSyncer = (*Syncer)(nil)

// -- Transport helper ---------------------------------------------------------

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type countingReadCloser struct {
	remaining int64
	read      int64
	closed    bool
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 'x'
	}
	n := len(p)
	r.remaining -= int64(n)
	r.read += int64(n)
	return n, nil
}

func (r *countingReadCloser) Close() error {
	r.closed = true
	return nil
}

type failingCloseTempArchive struct {
	bytes.Buffer
	closeErr   error
	closeCalls int
}

func (f *failingCloseTempArchive) Close() error {
	f.closeCalls++
	return f.closeErr
}

func (f *failingCloseTempArchive) Name() string {
	return "failing-temp-archive.zip"
}

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
