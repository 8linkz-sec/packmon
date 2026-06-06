package vulncheck

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
	"strconv"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
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

func TestDownloadBulkMapsEntriesAndSkipsInvalidCVEs(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case nvd2Endpoint:
			if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
				t.Fatalf("Authorization = %q", got)
			}
			if got := r.Header.Get("User-Agent"); got == "" {
				t.Fatal("User-Agent header is empty")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":[{"filename":"vulncheck-nvd2.zip","url":"`+absoluteTestURL(r, "/bulk/vulncheck-nvd2.zip")+`"}]}`)
		case "/bulk/vulncheck-nvd2.zip":
			if got := r.Header.Get("Authorization"); got != "" {
				t.Fatalf("backup download leaked Authorization header = %q", got)
			}
			w.Header().Set("Content-Type", "application/zip")
			writeVulnCheckZip(t, w, `{
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
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	syncer := NewSyncer("test-key", slog.New(slog.NewTextHandler(io.Discard, nil)), WithBaseURL(server.URL))
	entries, err := syncer.downloadBulk(context.Background())
	if err != nil {
		t.Fatalf("downloadBulk: %v", err)
	}
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

func TestDownloadBulkReportsHTTPAndParseErrors(t *testing.T) {
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
			_, err := syncer.downloadBulk(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("downloadBulk error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestSyncDownloadsAndEnrichesInBatches(t *testing.T) {
	t.Parallel()

	payload := backupResponse{Data: make([]backupCVE, 0, batchSize+1)}
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
			_, _ = io.WriteString(w, `{"data":[{"url":"`+absoluteTestURL(r, "/bulk.json")+`"}]}`)
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case nvd2Endpoint:
			_, _ = io.WriteString(w, `{"data":[{"url":"`+absoluteTestURL(r, "/bulk.zip")+`"}]}`)
		case "/bulk.zip":
			w.Header().Set("Content-Type", "application/zip")
			writeVulnCheckZip(t, w, `{"data":[{"id":"CVE-2026-4242"}]}`)
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

func TestSyncReportsContextAndEnrichErrors(t *testing.T) {
	t.Parallel()

	payload := backupResponse{Data: []backupCVE{{ID: "CVE-2026-0001"}}}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal backup response: %v", err)
	}
	syncCtx, cancelSync := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case nvd2Endpoint:
			_, _ = io.WriteString(w, `{"data":[{"url":"`+absoluteTestURL(r, "/bulk.json")+`"}]}`)
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
	if _, err := syncer.fetchBackupURL(context.Background()); err == nil || !strings.Contains(err.Error(), "download URL") {
		t.Fatalf("fetchBackupURL(missing url) = %v", err)
	}
	if _, _, err := syncer.downloadBackupFile(context.Background(), server.URL+"/backup"); err == nil || !strings.Contains(err.Error(), "status 502") {
		t.Fatalf("downloadBackupFile(status) = %v", err)
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

	if !isZipPayload([]byte("PK\x03\x04x"), "", "") {
		t.Fatal("zip magic body should be detected")
	}
	if !isZipPayload([]byte("json"), "application/zip", "") {
		t.Fatal("zip content type should be detected")
	}
	if !isZipPayloadHeader([]byte("json"), "", "https://example.test/bulk.zip") {
		t.Fatal("zip URL suffix should be detected")
	}

	jsonEntries, err := decodeBackupPayload([]byte(`[{"id":"CVE-2026-0001"}]`), "application/json", "https://example.test/bulk.json")
	if err != nil || len(jsonEntries) != 1 {
		t.Fatalf("decodeBackupPayload(json) = %+v, %v", jsonEntries, err)
	}
	if _, err := decodeBackupJSON([]byte(`{"not":"an array"}`)); err == nil || !strings.Contains(err.Error(), "parse json") {
		t.Fatalf("decodeBackupJSON(object without data) = %v", err)
	}

	_, err = io.ReadAll(newMaxBytesReader(strings.NewReader("abcd"), 3))
	if err == nil || !strings.Contains(err.Error(), "exceeds 3") {
		t.Fatalf("maxBytesReader overflow = %v", err)
	}
}

func TestStreamBackupJSONAndZipErrorBranches(t *testing.T) {
	t.Parallel()

	var emitted []db.VulnCheckEntry
	total, err := streamBackupJSON(strings.NewReader(`{"meta":{"ignored":true},"data":[{"id":"CVE-2026-0001"}]}`), func(entries []db.VulnCheckEntry) error {
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
	if _, err := decodeBackupZip(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "no JSON") {
		t.Fatalf("decodeBackupZip(no json) = %v", err)
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
	body, contentType, err := syncer.downloadBackupFile(context.Background(), server.URL+"/backup.json")
	if err != nil {
		t.Fatalf("downloadBackupFile(success) error = %v", err)
	}
	if contentType != "application/json" || !bytes.Contains(body, []byte("CVE-2026-0101")) {
		t.Fatalf("downloadBackupFile() = %q %s", contentType, body)
	}

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
	if _, _, err := syncer.downloadBackupFile(context.Background(), "://bad"); err == nil || !strings.Contains(err.Error(), "create backup request") {
		t.Fatalf("downloadBackupFile(bad URL) = %v", err)
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
	if _, err := decodeBackupZip(badJSONZip.Bytes()); err == nil || !strings.Contains(err.Error(), "parse zip JSON") {
		t.Fatalf("decodeBackupZip(bad json) = %v", err)
	}
}

func absoluteTestURL(r *http.Request, path string) string {
	return "http://" + r.Host + path
}

func writeVulnCheckZip(t *testing.T, w io.Writer, payload string) {
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
	if _, err := w.Write(buf.Bytes()); err != nil {
		t.Fatalf("write zip response: %v", err)
	}
}

type vulncheckStoreStub struct {
	db.Store
	batchSizes []int
	err        error
}

func (s *vulncheckStoreStub) EnrichVulnCheck(_ context.Context, entries []db.VulnCheckEntry) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	s.batchSizes = append(s.batchSizes, len(entries))
	return len(entries), nil
}
