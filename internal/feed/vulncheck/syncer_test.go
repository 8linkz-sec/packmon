package vulncheck

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestOptionsAndName(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unused")
	})}
	syncer := NewSyncer("key", nil, WithHTTPClient(client), WithBaseURL("https://example.test/"))

	if syncer.Name() != feedName {
		t.Fatalf("Name() = %q, want %q", syncer.Name(), feedName)
	}
	if syncer.httpClient != client {
		t.Fatal("WithHTTPClient did not replace client")
	}
	if syncer.baseURL != "https://example.test/" {
		t.Fatalf("baseURL = %q", syncer.baseURL)
	}
}

func TestSyncWithoutAPIKeyReturnsPermanentError(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer("", slog.New(slog.NewTextHandler(io.Discard, nil)))

	result, err := syncer.Sync(context.Background(), nil)
	if result != nil {
		t.Fatalf("Sync() result = %#v, want nil", result)
	}
	if err == nil {
		t.Fatal("Sync() error = nil, want permanent error")
	}
	if !feed.IsPermanentError(err) {
		t.Fatalf("Sync() error = %v, want permanent error", err)
	}
}

func TestSyncStreamsEntriesAndSkipsInvalidCVEs(t *testing.T) {
	t.Parallel()

	zipBody := vulnCheckZipBytes(t, `{
	  "data": [
	    {
	      "id": "CVE-2026-0001",
	      "cvss": {"base_score": 9.8, "vector_string": "CVSS:3.1/...", "version": "3.1"},
	      "exploits": [{"url": "https://example.test/poc", "name": "poc", "source": "xdb"}],
	      "url": "https://vulncheck.test/CVE-2026-0001"
	    },
	    {"id": "VC-2026-ignored"},
	    {"cve_id": "CVE-2026-0002", "url": "https://vulncheck.test/CVE-2026-0002"}
	  ]
	}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case nvd2Endpoint:
			if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
				t.Fatalf("Authorization = %q", got)
			}
			if got := r.Header.Get("User-Agent"); got == "" {
				t.Fatal("User-Agent header is empty")
			}
			writeBackupLinkResponse(t, w, r, "/bulk/vulncheck-nvd2.zip", zipBody, "vulncheck-nvd2.zip")
		case "/bulk/vulncheck-nvd2.zip":
			if got := r.Header.Get("Authorization"); got != "" {
				t.Fatalf("backup download leaked Authorization header = %q", got)
			}
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipBody)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	syncer := NewSyncer("test-key", slog.New(slog.NewTextHandler(io.Discard, nil)), WithBaseURL(server.URL))
	store := &vulncheckStoreStub{}
	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if result.EntriesTotal != 2 || result.EntriesSynced != 2 {
		t.Fatalf("sync result = %+v, want 2/2", result)
	}
	entries := store.entries
	if len(entries) != 2 {
		t.Fatalf("entries length = %d, want 2: %+v", len(entries), entries)
	}
	if entries[0].CVEID != "CVE-2026-0001" || entries[0].CVSSScore == nil || *entries[0].CVSSScore != 9.8 {
		t.Fatalf("first entry = %+v", entries[0])
	}
	if !entries[0].ExploitExists || len(entries[0].RawJSON) == 0 {
		t.Fatalf("first entry exploit/raw state = %+v", entries[0])
	}
	if entries[1].CVEID != "CVE-2026-0002" {
		t.Fatalf("second entry = %+v", entries[1])
	}
}

func TestSyncReportsBackupLinkHTTPAndParseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
		want       string
	}{
		{name: "auth", statusCode: http.StatusForbidden, body: `{}`, want: "authentication failed"},
		{name: "status", statusCode: http.StatusBadGateway, body: `{}`, want: "unexpected status 502"},
		{name: "json", statusCode: http.StatusOK, body: `not json`, want: "parse json"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()

			syncer := NewSyncer("test-key", slog.New(slog.NewTextHandler(io.Discard, nil)), WithBaseURL(server.URL))
			_, err := syncer.Sync(context.Background(), &vulncheckStoreStub{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Sync error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestSyncDownloadsAndEnrichesInBatches(t *testing.T) {
	t.Parallel()

	payload := struct {
		Data []backupCVE `json:"data"`
	}{Data: make([]backupCVE, 0, batchSize+1)}
	for i := 0; i < batchSize+1; i++ {
		payload.Data = append(payload.Data, backupCVE{ID: "CVE-2026-" + strconv.FormatInt(int64(1000+i), 10)})
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal backup response: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case nvd2Endpoint:
			writeBackupLinkResponse(t, w, r, "/bulk.json", body, "vulncheck-nvd2.json")
		case "/bulk.json":
			_, _ = w.Write(body)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	store := &vulncheckStoreStub{}
	syncer := NewSyncer("test-key", slog.New(slog.NewTextHandler(io.Discard, nil)), WithBaseURL(server.URL))
	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if result.EntriesTotal != batchSize+1 || result.EntriesSynced != batchSize+1 {
		t.Fatalf("sync result = %+v", result)
	}
	if len(store.batchSizes) != 2 || store.batchSizes[0] != batchSize || store.batchSizes[1] != 1 {
		t.Fatalf("batch sizes = %v", store.batchSizes)
	}
}

func TestSyncStreamsZipBackup(t *testing.T) {
	t.Parallel()

	zipBody := vulnCheckZipBytes(t, `{"data":[{"id":"CVE-2026-4242"}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case nvd2Endpoint:
			writeBackupLinkResponse(t, w, r, "/bulk.zip", zipBody, "vulncheck-nvd2.zip")
		case "/bulk.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipBody)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	store := &vulncheckStoreStub{}
	syncer := NewSyncer("test-key", slog.New(slog.NewTextHandler(io.Discard, nil)), WithBaseURL(server.URL))
	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync(zip): %v", err)
	}
	if result.EntriesTotal != 1 || result.EntriesSynced != 1 {
		t.Fatalf("sync result = %+v, want 1/1", result)
	}
	if len(store.batchSizes) != 1 || store.batchSizes[0] != 1 {
		t.Fatalf("batch sizes = %v, want [1]", store.batchSizes)
	}
}

func TestSyncRejectsMissingOrMismatchedBackupSHA256BeforeEnrich(t *testing.T) {
	t.Parallel()

	body := []byte(`{"data":[{"id":"CVE-2026-5150"}]}`)
	tests := []struct {
		name   string
		sha256 string
		want   string
	}{
		{name: "missing", sha256: "", want: "sha256"},
		{name: "mismatch", sha256: strings.Repeat("0", 64), want: "sha256 mismatch"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case nvd2Endpoint:
					link := map[string]string{"url": absoluteTestURL(r, "/bulk.json")}
					if tt.sha256 != "" {
						link["sha256"] = tt.sha256
					}
					resp := map[string][]map[string]string{"data": {link}}
					if err := json.NewEncoder(w).Encode(resp); err != nil {
						t.Fatalf("encode backup link response: %v", err)
					}
				case "/bulk.json":
					_, _ = w.Write(body)
				default:
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
			}))
			defer server.Close()

			store := &vulncheckStoreStub{}
			syncer := NewSyncer("test-key", slog.New(slog.NewTextHandler(io.Discard, nil)), WithBaseURL(server.URL))
			_, err := syncer.Sync(context.Background(), store)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Sync() error = %v, want %q", err, tt.want)
			}
			if len(store.batchSizes) != 0 {
				t.Fatalf("EnrichVulnCheck batches = %v, want none before digest verification", store.batchSizes)
			}
		})
	}
}

func TestSyncReportsContextAndEnrichErrors(t *testing.T) {
	t.Parallel()

	payload := struct {
		Data []backupCVE `json:"data"`
	}{Data: []backupCVE{{ID: "CVE-2026-0001"}}}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal backup response: %v", err)
	}
	syncCtx, cancelSync := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case nvd2Endpoint:
			writeBackupLinkResponse(t, w, r, "/bulk.json", body, "vulncheck-nvd2.json")
		case "/bulk.json":
			_, _ = w.Write(body)
			cancelSync()
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	syncer := NewSyncer("test-key", slog.New(slog.NewTextHandler(io.Discard, nil)), WithBaseURL(server.URL))
	if _, err := syncer.Sync(syncCtx, &vulncheckStoreStub{}); err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("Sync(cancelled) error = %v, want context cancellation", err)
	}

	store := &vulncheckStoreStub{err: errors.New("db down")}
	if _, err := syncer.Sync(context.Background(), store); err == nil || !strings.Contains(err.Error(), "enrich") {
		t.Fatalf("Sync(enrich error) = %v, want enrich error", err)
	}
}

func TestFetchAndDownloadBackupErrorBranches(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case nvd2Endpoint:
			_, _ = io.WriteString(w, `{"data":[{}]}`)
		case "/backup":
			http.Error(w, "down", http.StatusBadGateway)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	syncer := NewSyncer("test-key", slog.New(slog.NewTextHandler(io.Discard, nil)), WithBaseURL(server.URL))
	if _, err := syncer.fetchBackupSelection(context.Background()); err == nil || !strings.Contains(err.Error(), "download URL") {
		t.Fatalf("fetchBackupSelection(missing url) = %v", err)
	}
	if _, _, _, err := syncer.downloadBackupToTemp(context.Background(), server.URL+"/backup"); err == nil || !strings.Contains(err.Error(), "status 502") {
		t.Fatalf("downloadBackupToTemp(status) = %v", err)
	}
}

func TestVulnCheckBackupHelperBranches(t *testing.T) {
	t.Parallel()

	resolved, err := resolveBackupURL("https://api.example.test/root", "backup/file.json")
	if err != nil {
		t.Fatalf("resolveBackupURL(relative): %v", err)
	}
	if resolved != "https://api.example.test/root/backup/file.json" {
		t.Fatalf("resolved URL = %q", resolved)
	}
	if _, err := resolveBackupURL("https://api.example.test", "%zz"); err == nil || !strings.Contains(err.Error(), "parse backup URL") {
		t.Fatalf("resolveBackupURL(bad raw) = %v", err)
	}
	if _, err := resolveBackupURL("http://[::1", "/backup.json"); err == nil || !strings.Contains(err.Error(), "parse base URL") {
		t.Fatalf("resolveBackupURL(bad base) = %v", err)
	}

	if !isZipPayloadHeader([]byte("json"), "", "https://example.test/bulk.zip") {
		t.Fatal("zip URL suffix should be detected")
	}

	_, err = io.ReadAll(newMaxBytesReader(strings.NewReader("abcd"), 3))
	if err == nil || !strings.Contains(err.Error(), "exceeds 3") {
		t.Fatalf("maxBytesReader overflow = %v", err)
	}
}

func TestResolveBackupURLRejectsUnsafeCrossOriginTargets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		base string
		raw  string
	}{
		{name: "downgrade", base: "https://api.example.test", raw: "http://downloads.example.test/backup.json"},
		{name: "loopback", base: "https://api.example.test", raw: "https://127.0.0.1/backup.json"},
		{name: "link local", base: "https://api.example.test", raw: "https://169.254.169.254/latest/meta-data"},
		{name: "private", base: "https://api.example.test", raw: "https://10.0.0.1/backup.json"},
		{name: "localhost", base: "https://api.example.test", raw: "https://localhost/backup.json"},
		{name: "non http", base: "https://api.example.test", raw: "file:///etc/passwd"},
		{name: "cross origin non default port", base: "https://api.example.test", raw: "https://downloads.example.test:8443/backup.json"},
		{name: "unapproved public host", base: "https://api.example.test", raw: "https://downloads.example.test/backup.json"},
		{name: "userinfo", base: "https://api.example.test", raw: "https://user:pass@downloads.example.test/backup.json"}, //nolint:gosec // fake credential-bearing URL verifies rejection.
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, err := resolveBackupURL(tt.base, tt.raw); err == nil {
				t.Fatalf("resolveBackupURL(%q) = %q, want error", tt.raw, got)
			}
		})
	}
}

func TestResolveBackupURLAllowsRelativeAndPublicHTTPSDownloads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		base string
		raw  string
		want string
	}{
		{
			name: "relative test mirror",
			base: "http://127.0.0.1:45721/api",
			raw:  "/bulk.json",
			want: "http://127.0.0.1:45721/bulk.json",
		},
		{
			name: "documented s3 backup host",
			base: "https://api.example.test",
			raw:  "https://vulncheck-nvd2.s3.amazonaws.com/backup.json?X-Amz-Signature=test",
			want: "https://vulncheck-nvd2.s3.amazonaws.com/backup.json?X-Amz-Signature=test",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveBackupURL(tt.base, tt.raw)
			if err != nil {
				t.Fatalf("resolveBackupURL(%q): %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("resolveBackupURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestBackupDownloadRejectsUnsafeRedirectTargets(t *testing.T) {
	t.Parallel()

	redirectHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectHits++
		_, _ = io.WriteString(w, `[{"id":"CVE-2026-9999"}]`)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/bulk.json", http.StatusFound)
	}))
	defer source.Close()

	syncer := NewSyncer("test-key", slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err := syncer.streamBackupFile(context.Background(), source.URL+"/redirect", func([]db.VulnCheckEntry) error {
		return nil
	})
	if err == nil {
		t.Fatal("streamBackupFile(unsafe redirect) error = nil, want refusal")
	}
	if redirectHits != 0 {
		t.Fatalf("unsafe redirect target was requested %d times, want 0", redirectHits)
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("streamBackupFile(unsafe redirect) error = %v, want redirect refusal", err)
	}
}

func TestBackupDownloadHTTPErrorRedactsSignedURL(t *testing.T) {
	t.Parallel()

	const signedURL = "https://user-secret:pass-secret@downloads.example.test/backups/vulncheck.zip?X-Amz-Signature=query-secret&X-Amz-Security-Token=token-secret" //nolint:gosec // fake signed URL verifies redaction.
	syncer := NewSyncer("test-key", slog.New(slog.NewTextHandler(io.Discard, nil)), WithHTTPClient(&http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp " + r.URL.String() + ": no route to host")
		}),
	}))

	_, _, _, err := syncer.downloadBackupToTemp(context.Background(), signedURL)
	if err == nil {
		t.Fatal("downloadBackupToTemp() error = nil, want redacted HTTP error")
	}
	assertNoSignedURLLeak(t, err.Error())

	_, err = syncer.streamBackupFile(context.Background(), signedURL, func([]db.VulnCheckEntry) error { return nil })
	if err == nil {
		t.Fatal("streamBackupFile() error = nil, want redacted HTTP error")
	}
	assertNoSignedURLLeak(t, err.Error())
}

func TestStreamBackupJSONAndZipErrorBranches(t *testing.T) {
	t.Parallel()

	var emitted []db.VulnCheckEntry
	total, err := streamBackupJSON(strings.NewReader(`{"meta":{"ignored":true},"data":[{"id":"CVE-2026-0001"}],"after":{"ignored":true}}`), func(entries []db.VulnCheckEntry) error {
		emitted = append(emitted, entries...)
		return nil
	})
	if err != nil || total != 1 || len(emitted) != 1 {
		t.Fatalf("streamBackupJSON(object) total=%d emitted=%+v err=%v", total, emitted, err)
	}

	errorCases := []struct {
		name string
		body string
		want string
	}{
		{name: "scalar", body: `"bad"`, want: "expected object or array"},
		{name: "data not array", body: `{"data":{}}`, want: "data is not an array"},
		{name: "missing data", body: `{"meta":{}}`, want: "data array missing"},
		{name: "truncated object after data", body: `{"data":[{"id":"CVE-2026-0001"}]`, want: "object close"},
		{name: "trailing top-level data", body: `[{"id":"CVE-2026-0001"}] {"extra":true}`, want: "trailing"},
		{name: "bad cve", body: `[{"id":`, want: "parse cve"},
	}
	for _, tt := range errorCases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := streamBackupJSON(strings.NewReader(tt.body), func([]db.VulnCheckEntry) error { return nil }); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("streamBackupJSON(%s) = %v, want %q", tt.name, err, tt.want)
			}
		})
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	txt, err := zw.Create("readme.txt")
	if err != nil {
		t.Fatalf("create txt zip entry: %v", err)
	}
	if _, err := io.WriteString(txt, "not json"); err != nil {
		t.Fatalf("write txt zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close txt zip: %v", err)
	}
	if _, err := streamBackupZip(bytes.NewReader(buf.Bytes()), func([]db.VulnCheckEntry) error { return nil }); err == nil || !strings.Contains(err.Error(), "no JSON") {
		t.Fatalf("streamBackupZip(no json) = %v", err)
	}
}

func TestVulnCheckDownloadStreamAndZipFailureBranches(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `[{"id":"CVE-2026-0101"}]`)
		case "/bad.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = io.WriteString(w, "not a zip")
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	syncer := NewSyncer("test-key", slog.New(slog.NewTextHandler(io.Discard, nil)), WithBaseURL(server.URL))
	var emitted []db.VulnCheckEntry
	total, err := syncer.streamBackupFile(context.Background(), server.URL+"/backup.json", func(entries []db.VulnCheckEntry) error {
		emitted = append(emitted, entries...)
		return nil
	})
	if err != nil || total != 1 || len(emitted) != 1 {
		t.Fatalf("streamBackupFile(json) total=%d emitted=%+v err=%v", total, emitted, err)
	}
	if _, err := syncer.streamBackupFile(context.Background(), server.URL+"/bad.zip", func([]db.VulnCheckEntry) error { return nil }); err == nil || !strings.Contains(err.Error(), "parse zip") {
		t.Fatalf("streamBackupFile(bad zip) = %v, want parse zip error", err)
	}
	if _, _, _, err := syncer.downloadBackupToTemp(context.Background(), "://bad"); err == nil || !strings.Contains(err.Error(), "create backup request") {
		t.Fatalf("downloadBackupToTemp(bad URL) = %v", err)
	}
	if _, err := syncer.streamBackupFile(context.Background(), "://bad", func([]db.VulnCheckEntry) error { return nil }); err == nil || !strings.Contains(err.Error(), "create backup request") {
		t.Fatalf("streamBackupFile(bad URL) = %v", err)
	}

	if body, err := readLimited(strings.NewReader("ok")); err != nil || string(body) != "ok" {
		t.Fatalf("readLimited(success) = %q, %v", body, err)
	}
	if _, ok := vulnCheckEntryFromBackupCVE(backupCVE{ID: "VC-2026-ignored"}); ok {
		t.Fatal("vulnCheckEntryFromBackupCVE(non-CVE) = ok, want false")
	}
	if _, err := streamBackupJSON(strings.NewReader(`[{"id":"CVE-2026-0102"}]`), func([]db.VulnCheckEntry) error {
		return errors.New("emit failed")
	}); err == nil || !strings.Contains(err.Error(), "emit failed") {
		t.Fatalf("streamBackupJSON(emit error) = %v", err)
	}

	var badJSONZip bytes.Buffer
	zw := zip.NewWriter(&badJSONZip)
	file, err := zw.Create("vulncheck-nvd2.json")
	if err != nil {
		t.Fatalf("create bad json zip entry: %v", err)
	}
	if _, err := io.WriteString(file, `{bad json`); err != nil {
		t.Fatalf("write bad json zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close bad json zip: %v", err)
	}
	if _, err := streamBackupZip(bytes.NewReader(badJSONZip.Bytes()), func([]db.VulnCheckEntry) error { return nil }); err == nil || !strings.Contains(err.Error(), "parse zip JSON") {
		t.Fatalf("streamBackupZip(bad json) = %v", err)
	}
}

func absoluteTestURL(r *http.Request, path string) string {
	return "http://" + r.Host + path
}

func sha256Hex(body []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(body))
}

func writeBackupLinkResponse(t *testing.T, w http.ResponseWriter, r *http.Request, path string, body []byte, filename string) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(backupLinkResponse{Data: []backupLink{{
		Filename: filename,
		SHA256:   sha256Hex(body),
		URL:      absoluteTestURL(r, path),
	}}}); err != nil {
		t.Fatalf("encode backup link response: %v", err)
	}
}

func vulnCheckZipBytes(t *testing.T, payload string) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	file, err := zw.Create("vulncheck-nvd2.json")
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := io.WriteString(file, payload); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func assertNoSignedURLLeak(t *testing.T, message string) {
	t.Helper()

	for _, leaked := range []string{"user-secret", "pass-secret", "vulncheck.zip", "query-secret", "token-secret", "X-Amz-Signature", "X-Amz-Security-Token"} {
		if strings.Contains(message, leaked) {
			t.Fatalf("error leaked %q in %q", leaked, message)
		}
	}
	if !strings.Contains(message, "https://downloads.example.test/...") {
		t.Fatalf("error = %q, want redacted backup host", message)
	}
}

type vulncheckStoreStub struct {
	db.Store
	batchSizes []int
	entries    []db.VulnCheckEntry
	err        error
}

func (s *vulncheckStoreStub) EnrichVulnCheck(_ context.Context, entries []db.VulnCheckEntry) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	s.batchSizes = append(s.batchSizes, len(entries))
	s.entries = append(s.entries, entries...)
	return len(entries), nil
}
