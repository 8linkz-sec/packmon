package vulncheck

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type vulncheckErrorReader struct{ err error }

func (r vulncheckErrorReader) Read([]byte) (int, error) { return 0, r.err }

type vulncheckPayloadThenErrorReader struct {
	sent bool
	err  error
}

func (r *vulncheckPayloadThenErrorReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, r.err
	}
	r.sent = true
	return copy(p, "[]"), nil
}

type vulncheckTempFile struct {
	writeErr error
	closeErr error
	name     string
}

func (f *vulncheckTempFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return len(p), nil
}
func (f *vulncheckTempFile) Close() error { return f.closeErr }
func (f *vulncheckTempFile) Name() string { return f.name }

func TestBackupDigestURLAndHostGapBranches(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "abcd", strings.Repeat("z", 64)} {
		if _, err := normalizeBackupSHA256(raw); err == nil {
			t.Fatalf("normalizeBackupSHA256(%q) error = nil", raw)
		}
	}
	if err := verifyBackupSHA256Digest("", ""); err == nil {
		t.Fatal("verifyBackupSHA256Digest(empty) error = nil")
	}
	if err := verifyBackupSHA256Digest("aa", "bb"); err == nil {
		t.Fatal("verifyBackupSHA256Digest(mismatch) error = nil")
	}

	if got := defaultPortForScheme("HTTP"); got != "80" {
		t.Fatalf("defaultPortForScheme(http) = %q", got)
	}
	if got := defaultPortForScheme("https"); got != "443" {
		t.Fatalf("defaultPortForScheme(https) = %q", got)
	}
	if got := defaultPortForScheme("ftp"); got != "" {
		t.Fatalf("defaultPortForScheme(ftp) = %q", got)
	}

	hosts := []string{"", "fe80::1%zone", "8.8.8.8", "service.internal", "singlelabel"}
	for _, host := range hosts {
		if err := validateCrossOriginBackupHost(host); err == nil {
			t.Fatalf("validateCrossOriginBackupHost(%q) error = nil", host)
		}
	}

	badBase, _ := url.Parse("ftp://api.example.test")
	httpsCandidate, _ := url.Parse("https://api.example.test/backup")
	if err := validateBackupURL(badBase, httpsCandidate); err == nil || !strings.Contains(err.Error(), "base URL scheme") {
		t.Fatalf("validateBackupURL(bad base) = %v", err)
	}
	base, _ := url.Parse("https://api.example.test")
	missingHost, _ := url.Parse("https:///backup")
	if err := validateBackupURL(base, missingHost); err == nil || !strings.Contains(err.Error(), "host is required") {
		t.Fatalf("validateBackupURL(missing host) = %v", err)
	}
}

func TestReadLimitedAndTempZipHookFailures(t *testing.T) {
	t.Parallel()

	readErr := errors.New("read failed")
	if _, err := readLimited(vulncheckErrorReader{err: readErr}); !errors.Is(err, readErr) {
		t.Fatalf("readLimited(error) = %v", err)
	}

	createErr := errors.New("create failed")
	if _, err := streamBackupZipWithStatsWithTempFiles(strings.NewReader("zip"), func([]db.VulnCheckEntry) error { return nil }, tempZipFileHooks{
		create:   func() (tempZipWriteFile, error) { return nil, createErr },
		openRead: func(string) (tempZipReadFile, error) { return nil, nil },
		remove:   func(string) error { return nil },
	}); !errors.Is(err, createErr) {
		t.Fatalf("streamBackupZip(create error) = %v", err)
	}

	writeErr := errors.New("write failed")
	closeErr := errors.New("close failed")
	tmp := &vulncheckTempFile{writeErr: writeErr, closeErr: closeErr, name: "failed.zip"}
	if _, err := streamBackupZipWithStatsWithTempFiles(strings.NewReader("zip"), func([]db.VulnCheckEntry) error { return nil }, tempZipFileHooks{
		create:   func() (tempZipWriteFile, error) { return tmp, nil },
		openRead: func(string) (tempZipReadFile, error) { return nil, nil },
		remove:   func(string) error { return nil },
	}); !errors.Is(err, writeErr) || !errors.Is(err, closeErr) {
		t.Fatalf("streamBackupZip(write+close error) = %v", err)
	}

	tmp = &vulncheckTempFile{writeErr: writeErr, name: "write-failed.zip"}
	if _, err := streamBackupZipWithStatsWithTempFiles(strings.NewReader("zip"), func([]db.VulnCheckEntry) error { return nil }, tempZipFileHooks{
		create:   func() (tempZipWriteFile, error) { return tmp, nil },
		openRead: func(string) (tempZipReadFile, error) { return nil, nil },
		remove:   func(string) error { return nil },
	}); !errors.Is(err, writeErr) {
		t.Fatalf("streamBackupZip(write error) = %v", err)
	}

	tmp = &vulncheckTempFile{name: "open-failed.zip"}
	openErr := errors.New("open failed")
	if _, err := streamBackupZipWithStatsWithTempFiles(strings.NewReader("zip"), func([]db.VulnCheckEntry) error { return nil }, tempZipFileHooks{
		create:   func() (tempZipWriteFile, error) { return tmp, nil },
		openRead: func(string) (tempZipReadFile, error) { return nil, openErr },
		remove:   func(string) error { return nil },
	}); !errors.Is(err, openErr) {
		t.Fatalf("streamBackupZip(open error) = %v", err)
	}
}

func TestBackupJSONAdditionalParseFailures(t *testing.T) {
	t.Parallel()

	tests := []struct{ body, want string }{
		{"", "parse json"},
		{"{\"ignored\":", "parse json field"},
		{"{\"data\":", "parse json data"},
		{"{\"data\":[", "parse cve"},
	}
	for _, tc := range tests {
		if _, err := streamBackupJSONWithStats(strings.NewReader(tc.body), func([]db.VulnCheckEntry) error { return nil }); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("streamBackupJSON(%q) error = %v, want %q", tc.body, err, tc.want)
		}
	}

	trailingErr := errors.New("trailing read failed")
	if _, err := streamBackupJSONWithStats(&vulncheckPayloadThenErrorReader{err: trailingErr}, func([]db.VulnCheckEntry) error { return nil }); !errors.Is(err, trailingErr) {
		t.Fatalf("streamBackupJSON(trailing read error) = %v", err)
	}
}

func TestDoBackupRequestHonorsExistingRedirectPolicy(t *testing.T) {
	t.Parallel()

	policyErr := errors.New("redirect denied")
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"/next"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error { return policyErr },
	}
	syncer := NewSyncer("key", nil, WithHTTPClient(client))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.doBackupRequest(req); !errors.Is(err, policyErr) {
		t.Fatalf("doBackupRequest() error = %v", err)
	}
}

func TestVulnCheckStatusAndEntryGapBranches(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer("key", nil)
	if got := syncer.loadFeedStatus(context.Background(), &vulncheckStoreStub{statusErr: errors.New("read failed")}); got != nil {
		t.Fatalf("loadFeedStatus(error) = %+v", got)
	}
	now := time.Now().UTC()
	if statusHasProcessedBackupDigest(&db.FeedSyncStatus{LastSyncAt: &now, LastETag: "invalid"}, strings.Repeat("a", 64)) {
		t.Fatal("statusHasProcessedBackupDigest(invalid stored digest) = true")
	}
	metadata := json.RawMessage(`{"rejected_count":1}`)
	store := &vulncheckStoreStub{}
	syncer.recordSyncSuccessWithDigest(context.Background(), store, time.Second, 2, 1, strings.Repeat("a", 64), metadata)
	metadata[0] = '['
	if store.status == nil || string(store.status.Metadata) != `{"rejected_count":1}` {
		t.Fatalf("recorded metadata = %s", store.status.Metadata)
	}
	syncer.recordSyncSuccessWithDigest(context.Background(), &vulncheckStoreStub{upsertErr: errors.New("write failed")}, time.Second, 0, 0, "", nil)

	if _, ok, reason := vulnCheckEntryFromBackupRaw(json.RawMessage("{")); ok || reason != "malformed_json" {
		t.Fatalf("vulnCheckEntryFromBackupRaw(malformed) = ok=%v reason=%q", ok, reason)
	}
	entry, ok, reason := vulnCheckEntryFromBackupCVEWithRaw(backupCVE{
		CVEID: "CVE-2026-0001",
		CVSS:  &cvssData{BaseScore: 9.8},
	}, nil)
	if !ok || reason != "" || entry.CVSSScore == nil || *entry.CVSSScore != 9.8 || len(entry.RawJSON) == 0 {
		t.Fatalf("vulnCheckEntryFromBackupCVEWithRaw(CVSS) = %+v, %v, %q", entry, ok, reason)
	}
	_, ok, reason = vulnCheckEntryFromBackupCVEWithRaw(backupCVE{
		CVEID:    "CVE-2026-0002",
		Exploits: []exploitRef{{URL: strings.Repeat("x", maxVulnCheckExploitURLBytes+1)}},
	}, nil)
	if ok || reason != "exploit_reference_too_large" {
		t.Fatalf("oversized exploit = ok=%v reason=%q", ok, reason)
	}
}

func TestFetchBackupSelectionResponseFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		status     int
		body       io.ReadCloser
		wantSubstr string
	}{
		{name: "forbidden", status: http.StatusForbidden, body: io.NopCloser(strings.NewReader("")), wantSubstr: "authentication failed"},
		{name: "unexpected", status: http.StatusBadGateway, body: io.NopCloser(strings.NewReader("")), wantSubstr: "unexpected status"},
		{name: "read", status: http.StatusOK, body: io.NopCloser(vulncheckErrorReader{err: errors.New("read failed")}), wantSubstr: "read body"},
		{name: "parse", status: http.StatusOK, body: io.NopCloser(strings.NewReader("{")), wantSubstr: "parse json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			syncer := NewSyncer("key", nil, WithBaseURL("https://example.test"), WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: tc.body}, nil
			})}))
			if _, err := syncer.fetchBackupSelection(context.Background()); err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("fetchBackupSelection() error = %v, want %q", err, tc.wantSubstr)
			}
		})
	}

	httpErr := errors.New("transport failed")
	syncer := NewSyncer("key", nil, WithBaseURL("https://example.test"), WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, httpErr
	})}))
	if _, err := syncer.fetchBackupSelection(context.Background()); !errors.Is(err, httpErr) {
		t.Fatalf("fetchBackupSelection(transport error) = %v", err)
	}
}

func TestFetchBackupSelectionRejectsUnsafeURLAndDigest(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"data":[{"url":"http://example.test/backup.zip","sha256":"` + strings.Repeat("a", 64) + `"}]}`,
		`{"data":[{"url":"https://example.test/backup.zip","sha256":"bad"}]}`,
	} {
		syncer := NewSyncer("key", nil, WithBaseURL("https://example.test"), WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})}))
		if _, err := syncer.fetchBackupSelection(context.Background()); err == nil {
			t.Fatalf("fetchBackupSelection(%s) error = nil", body)
		}
	}
}

func TestDownloadBackupRejectsRedirectLoop(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", server.URL)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(server.Close)
	syncer := NewSyncer("key", nil, WithHTTPClient(server.Client()))
	if _, _, _, err := syncer.downloadBackupToTemp(context.Background(), server.URL); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("downloadBackupToTemp(redirect loop) error = %v", err)
	}
}

func TestMaxBytesReaderExactLimitReturnsUnderlyingEOF(t *testing.T) {
	t.Parallel()

	reader := newMaxBytesReader(strings.NewReader("abc"), 3)
	body, err := io.ReadAll(reader)
	if err != nil || string(body) != "abc" {
		t.Fatalf("ReadAll(exact limit) = %q, %v", body, err)
	}
}
