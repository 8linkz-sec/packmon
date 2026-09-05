package scanner

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/ioutils"

	"github.com/8linkz-sec/packmon/internal/checkcontract"
	"github.com/8linkz-sec/packmon/internal/correlation"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/parser"
)

func TestLocalCheckerRequiresCompleteFindingCoverage(t *testing.T) {
	t.Parallel()

	checkerType := reflect.TypeOf((*LocalChecker)(nil)).Elem()
	for _, method := range []string{
		"FindVulnerabilities",
		"FindMalicious",
		"FindReputationFindingsBatch",
		"FindLifecycleFindingsBatch",
	} {
		if _, ok := checkerType.MethodByName(method); !ok {
			t.Fatalf("LocalChecker missing required local scan capability %s", method)
		}
	}
}

func TestGenerateScanIDUses128BitHex(t *testing.T) {
	t.Parallel()

	id := generateScanID()
	if len(id) != 32 {
		t.Fatalf("generateScanID() len = %d for %q, want 32 hex chars", len(id), id)
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("generateScanID() = %q, want valid hex: %v", id, err)
	}
}

func writeJSONForScannerTest(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

type scannerRoundTripFunc func(*http.Request) (*http.Response, error)

func (f scannerRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDecodeRemoteCheckResponseRejectsTrailingData(t *testing.T) {
	t.Parallel()

	resultJSON := `{"scan_id":"scan-1","mode":"remote","scanned_at":"2026-01-01T00:00:00Z","findings":[],"feed_versions":{}}`
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name: "no trailing data",
			body: resultJSON,
		},
		{
			name: "trailing whitespace",
			body: resultJSON + " \n\t\r",
		},
		{
			name:    "trailing object",
			body:    resultJSON + `{}`,
			wantErr: true,
		},
		{
			name:    "trailing value",
			body:    resultJSON + `true`,
			wantErr: true,
		},
		{
			name:    "trailing garbage",
			body:    resultJSON + ` garbage`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var result domain.ScanResult
			err := decodeRemoteCheckResponse(strings.NewReader(tt.body), &result)
			if tt.wantErr {
				if err == nil {
					t.Fatal("decodeRemoteCheckResponse() error = nil, want trailing-data error")
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeRemoteCheckResponse() error = %v", err)
			}
			if result.ScanID != "scan-1" {
				t.Fatalf("ScanID = %q, want scan-1", result.ScanID)
			}
		})
	}
}

func TestCheckRemoteSendsAPIKey(t *testing.T) {
	t.Parallel()

	authErrCh := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			authErrCh <- "Authorization header = " + got + ", want Bearer test-key"
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(domain.ScanResult{
			ScanID:       "scan-1",
			Mode:         "remote",
			ScannedAt:    time.Now().UTC(),
			Summary:      domain.ScanSummary{BySeverity: map[string]int{}, ByType: map[string]int{}, BySource: map[string]int{}},
			Findings:     []domain.Finding{},
			FeedVersions: map[string]string{},
		})
	}))
	defer ioutils.CloseSilently(server)

	sc := New(nil, Config{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		APIKey:            "test-key",
		Timeout:           5 * time.Second,
	})

	if _, _, _, _, err := sc.checkRemote(context.Background(), []domain.Package{{
		Name:      "lodash",
		Version:   "1.0.0",
		Ecosystem: domain.Ecosystem("npm"),
	}}); err != nil {
		t.Fatalf("checkRemote() error = %v", err)
	}

	select {
	case msg := <-authErrCh:
		t.Fatal(msg)
	default:
	}
}

func TestCheckRemoteSendsVersionedUserAgent(t *testing.T) {
	t.Parallel()

	uaCh := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uaCh <- r.UserAgent()
		writeJSONForScannerTest(t, w, domain.ScanResult{
			ScanID:       "scan-1",
			Mode:         "remote",
			ScannedAt:    time.Now().UTC(),
			Summary:      domain.ScanSummary{BySeverity: map[string]int{}, ByType: map[string]int{}, BySource: map[string]int{}},
			Findings:     []domain.Finding{},
			FeedVersions: map[string]string{},
		})
	}))
	defer ioutils.CloseSilently(server)

	sc := New(nil, Config{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		Version:           "1.2.3",
		Timeout:           5 * time.Second,
	})

	if _, _, _, _, err := sc.checkRemote(context.Background(), []domain.Package{{
		Name:      "lodash",
		Version:   "1.0.0",
		Ecosystem: domain.Ecosystem("npm"),
	}}); err != nil {
		t.Fatalf("checkRemote() error = %v", err)
	}

	if got := <-uaCh; got != "packmon-cli/1.2.3" {
		t.Fatalf("User-Agent = %q, want packmon-cli/1.2.3", got)
	}
}

func TestCheckRemoteSendsCorrelationIDAndMinimizedRepoMetadata(t *testing.T) {
	t.Parallel()

	requestErrCh := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(correlation.Header); !correlation.Valid(got) {
			requestErrCh <- "missing UUID-like X-Correlation-ID header"
			http.Error(w, "missing correlation", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			requestErrCh <- "read request: " + err.Error()
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if strings.Contains(string(body), `"branch"`) || strings.Contains(string(body), `"commit"`) {
			requestErrCh <- "branch or commit metadata was sent"
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var req domain.ScanRequest
		if err := json.Unmarshal(body, &req); err != nil {
			requestErrCh <- "decode request: " + err.Error()
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Repo == nil || req.Repo.Name != "packmon" {
			requestErrCh <- "repo name not sent"
			http.Error(w, "missing repo", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(domain.ScanResult{
			ScanID:       "scan-1",
			Mode:         "remote",
			ScannedAt:    time.Now().UTC(),
			Summary:      domain.ScanSummary{BySeverity: map[string]int{}, ByType: map[string]int{}, BySource: map[string]int{}},
			Findings:     []domain.Finding{},
			FeedVersions: map[string]string{},
		})
	}))
	defer ioutils.CloseSilently(server)

	sc := New(nil, Config{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		Timeout:           5 * time.Second,
		Repo:              &domain.RepoInfo{Name: "packmon", Branch: "main", Commit: "abcdef"},
	})

	if _, _, _, _, err := sc.checkRemote(context.Background(), []domain.Package{{
		Name:      "lodash",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemNPM,
	}}); err != nil {
		t.Fatalf("checkRemote() error = %v", err)
	}

	select {
	case msg := <-requestErrCh:
		t.Fatal(msg)
	default:
	}
}

func TestCheckRemoteOmitsRepoMetadataWhenDisabled(t *testing.T) {
	t.Parallel()

	requestErrCh := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req domain.ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			requestErrCh <- "decode request: " + err.Error()
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Repo != nil {
			requestErrCh <- fmt.Sprintf("repo metadata sent: %+v", *req.Repo)
			http.Error(w, "repo metadata sent", http.StatusBadRequest)
			return
		}

		writeJSONForScannerTest(t, w, domain.ScanResult{
			ScanID:       "scan-1",
			Mode:         "remote",
			ScannedAt:    time.Now().UTC(),
			Summary:      domain.ScanSummary{BySeverity: map[string]int{}, ByType: map[string]int{}, BySource: map[string]int{}},
			Findings:     []domain.Finding{},
			FeedVersions: map[string]string{},
		})
	}))
	defer ioutils.CloseSilently(server)

	sc := New(nil, Config{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		Timeout:           5 * time.Second,
		OmitRepoMetadata:  true,
		Repo:              &domain.RepoInfo{Name: "packmon", Branch: "main", Commit: "abcdef"},
	})

	if _, _, _, _, err := sc.checkRemote(context.Background(), []domain.Package{{
		Name:      "lodash",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemNPM,
	}}); err != nil {
		t.Fatalf("checkRemote() error = %v", err)
	}

	select {
	case msg := <-requestErrCh:
		t.Fatal(msg)
	default:
	}
}

func TestCheckRemoteOmitsClientOnlyPackageMetadata(t *testing.T) {
	t.Parallel()

	bodyCh := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyCh <- string(body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(domain.ScanResult{
			ScanID:       "scan-1",
			Mode:         "remote",
			ScannedAt:    time.Now().UTC(),
			Summary:      domain.ScanSummary{BySeverity: map[string]int{}, ByType: map[string]int{}, BySource: map[string]int{}},
			Findings:     []domain.Finding{},
			FeedVersions: map[string]string{},
		})
	}))
	defer ioutils.CloseSilently(server)

	sc := New(nil, Config{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		Timeout:           5 * time.Second,
	})
	if _, _, _, _, err := sc.checkRemote(context.Background(), []domain.Package{{
		Name:      "child",
		Version:   "1.0.1",
		Ecosystem: domain.EcosystemNPM,
		Dev:       true,
		Direct:    true,
		Indirect:  true,
		Optional:  true,
		Peer:      true,
		Via:       []string{"root", "parent"},
		Parents: []domain.PackageParent{{
			Name:      "parent",
			Version:   "1.0.0",
			Ecosystem: domain.EcosystemNPM,
		}},
	}}); err != nil {
		t.Fatalf("checkRemote() error = %v", err)
	}

	body := <-bodyCh
	for _, field := range []string{`"parents"`, `"dev"`, `"direct"`, `"indirect"`, `"optional"`, `"peer"`, `"via"`} {
		if strings.Contains(body, field) {
			t.Fatalf("remote request leaked client-only package metadata %s:\n%s", field, body)
		}
	}
	if !strings.Contains(body, `"name":"child"`) {
		t.Fatalf("remote request missing package identity:\n%s", body)
	}
}

func TestCheckRemoteChunksRequestsAtServerLimit(t *testing.T) {
	t.Parallel()

	const totalPackages = checkcontract.MaxPackagesPerCheck + 1
	pkgs := make([]domain.Package, totalPackages)
	for i := range pkgs {
		pkgs[i] = domain.Package{
			Name:      "pkg-" + strconv.Itoa(i),
			Version:   "1.0.0",
			Ecosystem: domain.EcosystemNPM,
		}
	}

	requestSizes := make(chan int, 2)
	requestErrCh := make(chan string, 1)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req domain.ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			requestErrCh <- "decode request: " + err.Error()
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		requestSizes <- len(req.Packages)
		call := calls.Add(1)
		switch call {
		case 1:
			if len(req.Packages) != checkcontract.MaxPackagesPerCheck {
				requestErrCh <- fmt.Sprintf("first chunk packages = %d, want %d", len(req.Packages), checkcontract.MaxPackagesPerCheck)
				http.Error(w, "bad chunk", http.StatusBadRequest)
				return
			}
			writeJSONForScannerTest(t, w, domain.ScanResult{
				ScanID:        "chunk-1",
				Mode:          "remote",
				ScannedAt:     time.Now().UTC(),
				FindingsCount: 1,
				Findings: []domain.Finding{{
					Name:       "pkg-1",
					Version:    "1.0.0",
					Ecosystem:  domain.EcosystemNPM,
					Type:       domain.FindingTypeVulnerability,
					Severity:   domain.SeverityLow,
					AdvisoryID: "GHSA-chunk-1",
				}},
				FeedStatus:   "healthy",
				FeedVersions: map[string]string{"osv": "snapshot-1"},
			})
		case 2:
			if len(req.Packages) != 1 {
				requestErrCh <- fmt.Sprintf("second chunk packages = %d, want 1", len(req.Packages))
				http.Error(w, "bad chunk", http.StatusBadRequest)
				return
			}
			writeJSONForScannerTest(t, w, domain.ScanResult{
				ScanID:           "chunk-2",
				Mode:             "remote",
				ScannedAt:        time.Now().UTC(),
				FindingsCount:    1,
				FindingsBlocking: true,
				Findings: []domain.Finding{{
					Name:       "pkg-" + strconv.Itoa(checkcontract.MaxPackagesPerCheck),
					Version:    "1.0.0",
					Ecosystem:  domain.EcosystemNPM,
					Type:       domain.FindingTypeVulnerability,
					Severity:   domain.SeverityCritical,
					AdvisoryID: "GHSA-chunk-2",
				}},
				FeedStatus:   "degraded",
				FeedVersions: map[string]string{"ghsa": "snapshot-2"},
			})
		default:
			requestErrCh <- fmt.Sprintf("unexpected chunk request %d", call)
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer ioutils.CloseSilently(server)

	sc := New(nil, Config{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		Timeout:           5 * time.Second,
	})
	findings, feedVersions, feedStatus, remoteBlocking, err := sc.checkRemote(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("checkRemote(chunked) error = %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("remote requests = %d, want 2", got)
	}
	if first, second := <-requestSizes, <-requestSizes; first != checkcontract.MaxPackagesPerCheck || second != 1 {
		t.Fatalf("request sizes = %d,%d; want %d,1", first, second, checkcontract.MaxPackagesPerCheck)
	}
	select {
	case msg := <-requestErrCh:
		t.Fatal(msg)
	default:
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want two merged findings", findings)
	}
	if feedVersions["osv"] != "snapshot-1" || feedVersions["ghsa"] != "snapshot-2" {
		t.Fatalf("feedVersions = %+v, want merged chunk versions", feedVersions)
	}
	if feedStatus != "degraded" {
		t.Fatalf("feedStatus = %q, want degraded", feedStatus)
	}
	if !remoteBlocking {
		t.Fatal("remoteBlocking = false, want true when any chunk reports blocking")
	}
}

func TestMergeRemoteFeedStatusPreservesWorstStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		current string
		next    string
		want    string
	}{
		{
			name:    "healthy current takes degraded next",
			current: "healthy",
			next:    "degraded",
			want:    "degraded",
		},
		{
			name:    "degraded current ignores healthy next",
			current: "degraded",
			next:    "healthy",
			want:    "degraded",
		},
		{
			name:    "error next wins over degraded",
			current: "degraded",
			next:    "error",
			want:    "error",
		},
		{
			name:    "error current wins over healthy",
			current: "error",
			next:    "healthy",
			want:    "error",
		},
		{
			name:    "unknown next normalizes to degraded",
			current: "healthy",
			next:    "feed lagging",
			want:    "degraded",
		},
		{
			name:    "blank current starts healthy",
			current: "",
			next:    "error",
			want:    "error",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := mergeRemoteFeedStatus(tt.current, tt.next); got != tt.want {
				t.Fatalf("mergeRemoteFeedStatus(%q, %q) = %q, want %q", tt.current, tt.next, got, tt.want)
			}
		})
	}
}

func TestNormalizeScanFeedStatusBoundsRemoteValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status string
		want   string
	}{
		{status: "", want: "healthy"},
		{status: " healthy ", want: "healthy"},
		{status: "degraded", want: "degraded"},
		{status: "error", want: "error"},
		{status: "remote warning: stale feed", want: "degraded"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.status, func(t *testing.T) {
			t.Parallel()

			if got := normalizeScanFeedStatus(tt.status); got != tt.want {
				t.Fatalf("normalizeScanFeedStatus(%q) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestCheckRemoteValidationAndResponseErrors(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{Timeout: time.Second})
	if _, _, _, _, err := sc.checkRemote(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "no server URL") {
		t.Fatalf("checkRemote(no URL) error = %v", err)
	}

	sc = New(nil, Config{ServerURL: "http://example.test", Timeout: time.Second})
	if _, _, _, _, err := sc.checkRemote(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "refusing to use insecure") {
		t.Fatalf("checkRemote(insecure) error = %v", err)
	}
	sc = New(nil, Config{ServerURL: "http://user:server-secret@example.test/private?token=query-secret", Timeout: time.Second}) //nolint:gosec // fake secret-bearing URL verifies redaction.
	if _, _, _, _, err := sc.checkRemote(context.Background(), nil); err == nil {
		t.Fatal("checkRemote(insecure secret URL) error = nil")
	} else if strings.Contains(err.Error(), "server-secret") || strings.Contains(err.Error(), "query-secret") || strings.Contains(err.Error(), "/private") {
		t.Fatalf("checkRemote(insecure secret URL) leaked raw server URL: %v", err)
	}

	badStatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, strings.Repeat("x", 300), http.StatusTeapot)
	}))
	defer ioutils.CloseSilently(badStatus)
	sc = New(nil, Config{ServerURL: badStatus.URL, AllowInsecureHTTP: true, Timeout: time.Second})
	if _, _, _, _, err := sc.checkRemote(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "server returned 418") {
		t.Fatalf("checkRemote(status) error = %v", err)
	}

	unauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid api key", http.StatusUnauthorized)
	}))
	defer ioutils.CloseSilently(unauthorized)
	sc = New(nil, Config{ServerURL: unauthorized.URL, AllowInsecureHTTP: true, Timeout: time.Second})
	if _, _, _, _, err := sc.checkRemote(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "check PACKMON_API_KEY") {
		t.Fatalf("checkRemote(unauthorized) error = %v, want api-key hint", err)
	}

	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unknown user agent", http.StatusForbidden)
	}))
	defer ioutils.CloseSilently(forbidden)
	sc = New(nil, Config{ServerURL: forbidden.URL, AllowInsecureHTTP: true, Timeout: time.Second})
	if _, _, _, _, err := sc.checkRemote(context.Background(), nil); err == nil {
		t.Fatal("checkRemote(forbidden) error = nil")
	} else if !strings.Contains(err.Error(), "User-Agent policy") {
		t.Fatalf("checkRemote(forbidden) error = %v, want request-policy hint", err)
	} else if strings.Contains(err.Error(), "PACKMON_API_KEY") || strings.Contains(err.Error(), "--api-key") || strings.Contains(err.Error(), "api_key_env") {
		t.Fatalf("checkRemote(forbidden) error = %v, want no api-key hint", err)
	}

	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer ioutils.CloseSilently(invalidJSON)
	sc = New(nil, Config{ServerURL: invalidJSON.URL, AllowInsecureHTTP: true, Timeout: time.Second})
	if _, _, _, _, err := sc.checkRemote(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("checkRemote(json) error = %v", err)
	}
}

func TestCheckRemoteServerErrorsRedactBodySecretsAndIncludeCorrelationID(t *testing.T) {
	t.Parallel()

	const responseCorrelationID = "123e4567-e89b-42d3-a456-426614174000"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(correlation.Header, responseCorrelationID)
		http.Error(w, "failed Authorization: Bearer leaked-remote-token api_key=leaked-query-token", http.StatusInternalServerError)
	}))
	defer ioutils.CloseSilently(server)

	sc := New(nil, Config{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		Timeout:           time.Second,
	})
	_, _, _, _, err := sc.checkRemote(context.Background(), []domain.Package{{
		Name:      "lodash",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemNPM,
	}})
	if err == nil {
		t.Fatal("checkRemote() error = nil, want server error")
	}
	msg := err.Error()
	for _, want := range []string{
		"server returned 500",
		"correlation_id=" + responseCorrelationID,
		"Bearer [redacted]",
		"api_key=[redacted]",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("checkRemote() error missing %q: %s", want, msg)
		}
	}
	for _, leaked := range []string{"leaked-remote-token", "leaked-query-token"} {
		if strings.Contains(msg, leaked) {
			t.Fatalf("checkRemote() error leaked %q: %s", leaked, msg)
		}
	}
}

func TestCheckRemoteServerErrorUsesRequestCorrelationIDFallback(t *testing.T) {
	t.Parallel()

	requestCorrelationIDs := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCorrelationIDs <- r.Header.Get(correlation.Header)
		w.Header().Set(correlation.Header, "not-a-valid-correlation-id")
		http.Error(w, "server unavailable", http.StatusBadGateway)
	}))
	defer ioutils.CloseSilently(server)

	sc := New(nil, Config{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		Timeout:           time.Second,
	})
	_, _, _, _, err := sc.checkRemote(context.Background(), []domain.Package{{
		Name:      "lodash",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemNPM,
	}})
	if err == nil {
		t.Fatal("checkRemote() error = nil, want server error")
	}
	requestCorrelationID := <-requestCorrelationIDs
	if !correlation.Valid(requestCorrelationID) {
		t.Fatalf("request correlation ID = %q, want valid ID", requestCorrelationID)
	}
	if want := "correlation_id=" + requestCorrelationID; !strings.Contains(err.Error(), want) {
		t.Fatalf("checkRemote() error missing %q: %s", want, err.Error())
	}
}

func TestCheckRemoteServerErrorTruncatesUTF8Safely(t *testing.T) {
	t.Parallel()

	body := strings.Repeat("x", 199) + "ä" + strings.Repeat("y", 50)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, body, http.StatusInternalServerError)
	}))
	defer ioutils.CloseSilently(server)

	sc := New(nil, Config{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		Timeout:           time.Second,
	})
	_, _, _, _, err := sc.checkRemote(context.Background(), []domain.Package{{
		Name:      "lodash",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemNPM,
	}})
	if err == nil {
		t.Fatal("checkRemote() error = nil, want server error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "server returned 500") {
		t.Fatalf("checkRemote() error = %q, want server status", msg)
	}
	if !utf8.ValidString(msg) || strings.ContainsRune(msg, utf8.RuneError) {
		t.Fatalf("checkRemote() error is not valid UTF-8: %q", msg)
	}
}

func TestCheckRemoteRejectsOversizedResponseBody(t *testing.T) {
	t.Parallel()

	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"scan_id":"`))
		chunk := strings.Repeat("x", 1<<20)
		for written := int64(0); written <= maxRemoteCheckResponseSize; written += int64(len(chunk)) {
			_, _ = w.Write([]byte(chunk))
		}
	}))
	defer ioutils.CloseSilently(oversized)

	sc := New(nil, Config{
		ServerURL:         oversized.URL,
		AllowInsecureHTTP: true,
		Timeout:           5 * time.Second,
	})
	if _, _, _, _, err := sc.checkRemote(context.Background(), []domain.Package{{
		Name:      "lodash",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemNPM,
	}}); err == nil || !strings.Contains(err.Error(), "response body exceeds") {
		t.Fatalf("checkRemote(oversized response) error = %v", err)
	}
}

func TestScannerRunRemoteTransportErrorRedactsSecretServerURL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/lodash": {"version":"1.0.0"}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	rawURL := "https://user-secret:pass-secret@packmon.example.test/org/private/path-secret?token=query-secret#frag-secret" //nolint:gosec // fake secret-bearing URL verifies transport error redaction.
	sc := New(parser.NewRegistry(), Config{
		Path:      dir,
		Mode:      ModeRemote,
		ServerURL: rawURL,
		FailOn:    domain.SeverityCritical,
		Timeout:   time.Second,
	})
	sc.client.Transport = scannerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, &url.Error{
			Op:  "Post",
			URL: req.URL.String(),
			Err: errors.New("dial tcp: token=query-secret"),
		}
	})

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOperational {
		t.Fatalf("exit = %d, want operational; result=%+v", exitCode, result)
	}
	if result.FeedStatus != "error" {
		t.Fatalf("FeedStatus = %q, want error", result.FeedStatus)
	}
	if !strings.Contains(result.ScanError, "remote check failed") {
		t.Fatalf("ScanError = %q, want remote failure detail", result.ScanError)
	}

	userVisible := result.ScanError + "\n" + result.FeedStatus
	for _, leaked := range []string{
		"user-secret",
		"pass-secret",
		"query-secret",
		"frag-secret",
		"/org/private/path-secret",
		"token=query-secret",
	} {
		if strings.Contains(userVisible, leaked) {
			t.Fatalf("remote transport error leaked %q in %q", leaked, userVisible)
		}
	}
}

func TestScannerRunComputesRemoteBlockingWithClientThreshold(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/remote-only": {"version":"1.0.0"}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	serverScannedAt := time.Date(2026, 6, 22, 12, 30, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(domain.ScanResult{
			ScanID:           "remote-blocking",
			Mode:             "remote",
			ScannedAt:        serverScannedAt,
			DurationMs:       321,
			PackagesScanned:  1,
			FindingsCount:    1,
			FindingsBlocking: true,
			Summary:          domain.ScanSummary{BySeverity: map[string]int{}, ByType: map[string]int{}, BySource: map[string]int{}},
			Findings: []domain.Finding{{
				Name:       "remote-only",
				Version:    "1.0.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityLow,
				AdvisoryID: "GHSA-remote-policy",
				Title:      "server policy blocks this finding",
			}},
			FeedVersions: map[string]string{},
		})
	}))
	defer ioutils.CloseSilently(server)

	sc := New(parser.NewRegistry(), Config{
		Path:              dir,
		Mode:              ModeRemote,
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		FailOn:            domain.SeverityNone,
		Timeout:           time.Second,
	})

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitUnderThreshold {
		t.Fatalf("exit = %d, want under-threshold; result=%+v", exitCode, result)
	}
	if result.FindingsBlocking {
		t.Fatalf("FindingsBlocking = true, want client threshold to override remote policy")
	}
	if result.ScanID != "remote-blocking" {
		t.Fatalf("ScanID = %q, want server scan ID", result.ScanID)
	}
	if !result.ScannedAt.Equal(serverScannedAt) {
		t.Fatalf("ScannedAt = %s, want server timestamp %s", result.ScannedAt, serverScannedAt)
	}
	if result.DurationMs != 321 {
		t.Fatalf("DurationMs = %d, want server duration 321", result.DurationMs)
	}
}

func TestScannerFiltersDevDependenciesByDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lockFile := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(lockFile, []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"version":"1.0.0"},
			"node_modules/prod": {"version":"1.0.0"},
			"node_modules/dev-only": {"version":"2.0.0","dev":true}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	sc := New(parser.NewRegistry(), Config{
		Path:     dir,
		Mode:     ModeLocal,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 3,
		Timeout:  5 * time.Second,
	})
	checker := &captureLocalChecker{}
	sc.SetLocalChecker(checker)

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOK {
		t.Fatalf("Run exit = %d, result = %+v", exitCode, result)
	}
	if len(checker.packages) != 1 {
		t.Fatalf("checked packages = %d, want 1: %#v", len(checker.packages), checker.packages)
	}
	if checker.packages[0].Name != "prod" {
		t.Fatalf("checked package = %q, want prod", checker.packages[0].Name)
	}
}

func TestScannerIncludesDevDependenciesWhenRequested(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lockFile := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(lockFile, []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"version":"1.0.0"},
			"node_modules/prod": {"version":"1.0.0"},
			"node_modules/dev-only": {"version":"2.0.0","dev":true}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	sc := New(parser.NewRegistry(), Config{
		Path:       dir,
		Mode:       ModeLocal,
		FailOn:     domain.SeverityCritical,
		MaxDepth:   3,
		Timeout:    5 * time.Second,
		IncludeDev: true,
	})
	checker := &captureLocalChecker{}
	sc.SetLocalChecker(checker)

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOK {
		t.Fatalf("Run exit = %d, result = %+v", exitCode, result)
	}
	if len(checker.packages) != 2 {
		t.Fatalf("checked packages = %d, want 2: %#v", len(checker.packages), checker.packages)
	}
}

func TestScannerRunIncludesSBOMPackages(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "bom.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{
		"bomFormat":"CycloneDX",
		"components":[{"type":"library","name":"django","version":"4.2.11","purl":"pkg:pypi/django@4.2.11"}]
	}`), 0o600); err != nil {
		t.Fatalf("write SBOM: %v", err)
	}

	sc := New(parser.NewRegistry(), Config{
		Path:      dir,
		Mode:      ModeLocal,
		FailOn:    domain.SeverityCritical,
		MaxDepth:  3,
		Timeout:   5 * time.Second,
		SBOMFiles: []string{sbomPath},
	})
	checker := &captureLocalChecker{}
	sc.SetLocalChecker(checker)

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOK {
		t.Fatalf("Run exit = %d, result = %+v", exitCode, result)
	}
	if result.PackagesScanned != 1 {
		t.Fatalf("PackagesScanned = %d, want 1", result.PackagesScanned)
	}
	if len(checker.packages) != 1 || checker.packages[0].Name != "django" || checker.packages[0].Ecosystem != domain.EcosystemPyPI {
		t.Fatalf("checked packages = %#v, want django pypi", checker.packages)
	}
}

func TestScannerRunSkipsRemoteWhenFiltersRemoveAllPackages(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"version":"1.0.0"},
			"node_modules/dev-only": {"version":"1.0.0","dev":true}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		http.Error(w, "remote should not be called for an empty package set", http.StatusInternalServerError)
	}))
	defer ioutils.CloseSilently(server)

	sc := New(parser.NewRegistry(), Config{
		Path:              dir,
		Mode:              ModeRemote,
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		Ecosystems:        []string{"npm"},
		FailOn:            domain.SeverityCritical,
		MaxDepth:          2,
		Timeout:           time.Second,
	})

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOK {
		t.Fatalf("exit = %d, result = %+v, want clean empty scan", exitCode, result)
	}
	if result.PackagesScanned != 0 || result.FindingsCount != 0 {
		t.Fatalf("result = %+v, want zero packages and zero findings", result)
	}
	if called.Load() {
		t.Fatal("remote check was called with an empty package set")
	}
}

func TestScannerRunMalformedExplicitSBOMIsParserErrorWithLockfilePackages(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}
	sbomPath := filepath.Join(dir, "bad.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX",`), 0o600); err != nil {
		t.Fatalf("write malformed SBOM: %v", err)
	}

	sc := New(parser.NewRegistry(), Config{
		Path:      dir,
		Mode:      ModeLocal,
		FailOn:    domain.SeverityCritical,
		MaxDepth:  2,
		Timeout:   time.Second,
		SBOMFiles: []string{sbomPath},
	})
	checker := &captureLocalChecker{}
	sc.SetLocalChecker(checker)

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitParser {
		t.Fatalf("exit = %d, result = %+v, want parser error", exitCode, result)
	}
	if len(result.ParseErrors) != 1 || !strings.Contains(result.ParseErrors[0], "bad.cdx.json") {
		t.Fatalf("ParseErrors = %#v, want malformed SBOM error", result.ParseErrors)
	}
	if len(checker.packages) != 0 {
		t.Fatalf("local checker was called despite malformed explicit SBOM: %#v", checker.packages)
	}
}

func TestScannerRunFailsOnPartialParseErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(`{{{not yaml`), 0o600); err != nil {
		t.Fatalf("write pnpm-lock: %v", err)
	}

	sc := New(parser.NewRegistry(), Config{
		Path:     dir,
		Mode:     ModeLocal,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 2,
		Timeout:  5 * time.Second,
	})
	checker := &captureLocalChecker{}
	sc.SetLocalChecker(checker)

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitParser {
		t.Fatalf("exit = %d, result = %+v, want parser error", exitCode, result)
	}
	if len(result.ParseErrors) != 1 || !strings.Contains(result.ParseErrors[0], "pnpm-lock.yaml") {
		t.Fatalf("ParseErrors = %#v, want pnpm parse error", result.ParseErrors)
	}
	if result.PackagesScanned != 1 || len(checker.packages) != 1 {
		t.Fatalf("packages scanned=%d checked=%d, want 1/1", result.PackagesScanned, len(checker.packages))
	}
}

func TestScannerRunListAllDevOnlyPartialParseError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/dev-only": {"version":"1.0.0","dev":true}}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(`{{{not yaml`), 0o600); err != nil {
		t.Fatalf("write pnpm-lock: %v", err)
	}

	sc := New(parser.NewRegistry(), Config{
		Path:                 dir,
		Mode:                 ModeLocal,
		FailOn:               domain.SeverityCritical,
		MaxDepth:             2,
		Timeout:              5 * time.Second,
		InventoryAllPackages: true,
	})
	checker := &captureLocalChecker{}
	sc.SetLocalChecker(checker)

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitParser {
		t.Fatalf("exit = %d, result = %+v, want parser error", exitCode, result)
	}
	if len(result.ParseErrors) != 1 || !strings.Contains(result.ParseErrors[0], "pnpm-lock.yaml") {
		t.Fatalf("ParseErrors = %#v, want pnpm parse error", result.ParseErrors)
	}
	if result.PackagesScanned != 0 || len(checker.packages) != 0 {
		t.Fatalf("packages scanned=%d checked=%d, want no checkable prod packages", result.PackagesScanned, len(checker.packages))
	}
}

func TestScannerRunPartialParseErrorOverridesUnderThresholdFindings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(`{{{not yaml`), 0o600); err != nil {
		t.Fatalf("write pnpm-lock: %v", err)
	}

	sc := New(parser.NewRegistry(), Config{
		Path:     dir,
		Mode:     ModeLocal,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 2,
		Timeout:  5 * time.Second,
	})
	sc.SetLocalChecker(&fixedFindingLocalChecker{findings: []domain.Finding{{
		Name:      "prod",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemNPM,
		Type:      domain.FindingTypeVulnerability,
		Severity:  domain.SeverityLow,
		Source:    "test",
	}}})

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitParser {
		t.Fatalf("exit = %d, result = %+v, want parser error over under-threshold finding", exitCode, result)
	}
	if len(result.Findings) != 1 || len(result.ParseErrors) != 1 {
		t.Fatalf("result findings=%d parseErrors=%d, want 1/1", len(result.Findings), len(result.ParseErrors))
	}
}

func TestScannerOperationalErrorsUseMachineFeedStatusAndScanError(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	sc := New(nil, Config{
		Path:     root,
		Mode:     ModeLocal,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 2,
	})
	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOperational {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOperational)
	}
	if result.FeedStatus != "error" {
		t.Fatalf("FeedStatus = %q, want error", result.FeedStatus)
	}
	if !strings.Contains(result.ScanError, "local advisory data unavailable") {
		t.Fatalf("ScanError = %q, want local advisory detail", result.ScanError)
	}
}

func TestScannerEmptyScanHasHealthyFeedStatus(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{
		Path:     t.TempDir(),
		Mode:     ModeLocal,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 2,
	})
	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOK {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
	}
	if result.FeedStatus != "healthy" {
		t.Fatalf("FeedStatus = %q, want healthy", result.FeedStatus)
	}
	if result.ScanError != "" {
		t.Fatalf("ScanError = %q, want empty", result.ScanError)
	}
}

func TestCheckLocalIncludesRequiredLifecycleFindings(t *testing.T) {
	t.Parallel()

	checker := &lifecycleLocalChecker{
		lifecycleFindings: []domain.Finding{
			{
				Name:       "django",
				Version:    "4.2.11",
				Ecosystem:  domain.EcosystemPyPI,
				Type:       domain.FindingTypeLifecycle,
				Severity:   domain.SeverityLow,
				AdvisoryID: "endoflife:django:4.2:security_support_only",
				Title:      "Django 4.2 is in security support only",
				RiskType:   "security_support_only",
				Source:     "endoflife.date",
			},
		},
	}
	sc := New(nil, Config{})
	sc.SetLocalChecker(checker)

	findings, err := sc.checkLocal(context.Background(), []domain.Package{
		{Name: "django", Version: "4.2.11", Ecosystem: domain.EcosystemPyPI},
	})
	if err != nil {
		t.Fatalf("checkLocal() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Type != domain.FindingTypeLifecycle {
		t.Fatalf("findings = %+v, want lifecycle finding", findings)
	}
	if len(checker.lifecycleQueries) != 1 || checker.lifecycleQueries[0].Name != "django" {
		t.Fatalf("lifecycle queries = %+v, want django query", checker.lifecycleQueries)
	}

	sc.SetLocalChecker(&captureLocalChecker{})
	if findings, err := sc.checkLocal(context.Background(), []domain.Package{
		{Name: "django", Version: "4.2.11", Ecosystem: domain.EcosystemPyPI},
	}); err != nil || len(findings) != 0 {
		t.Fatalf("checkLocal(old checker) findings=%+v err=%v, want none nil", findings, err)
	}
}

func TestAlwaysBlockingFindingKeepsLifecycleSeverityGated(t *testing.T) {
	t.Parallel()

	if domain.FindingAlwaysBlocks(domain.Finding{Type: domain.FindingTypeLifecycle, RiskType: "eol_soon"}) {
		t.Fatal("lifecycle findings should not be always blocking")
	}
	if !domain.FindingAlwaysBlocks(domain.Finding{Type: domain.FindingTypeSupplyChainRisk, RiskType: "eol"}) {
		t.Fatal("EOL supply-chain risk findings should be always blocking")
	}
}

type noopLocalCoverage struct{}

func (noopLocalCoverage) FindReputationFindingsBatch(context.Context, []PackageLookup, string) ([]domain.Finding, error) {
	return nil, nil
}

func (noopLocalCoverage) FindLifecycleFindingsBatch(context.Context, []PackageLookup, time.Time) ([]domain.Finding, error) {
	return nil, nil
}

type captureLocalChecker struct {
	noopLocalCoverage
	packages []domain.Package
}

func (c *captureLocalChecker) FindVulnerabilities(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	c.packages = append(c.packages, domain.Package{Ecosystem: domain.Ecosystem(ecosystem), Name: name, Version: version})
	return nil, nil
}

func (c *captureLocalChecker) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}

type fixedFindingLocalChecker struct {
	noopLocalCoverage
	findings []domain.Finding
}

func (c *fixedFindingLocalChecker) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	return c.findings, nil
}

func (c *fixedFindingLocalChecker) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}

type captureBatchLocalChecker struct {
	noopLocalCoverage
	vulnQueries        []PackageLookup
	maliciousQueries   []PackageLookup
	reputationQueries  []PackageLookup
	reputationFindings []domain.Finding
}

func (c *captureBatchLocalChecker) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	panic("single vulnerability lookup should not be used when batch is available")
}

func (c *captureBatchLocalChecker) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	panic("single malicious lookup should not be used when batch is available")
}

func (c *captureBatchLocalChecker) FindVulnerabilitiesBatch(_ context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	c.vulnQueries = append(c.vulnQueries, packages...)
	return []domain.Finding{{Name: packages[0].Name, Version: packages[0].Version, Ecosystem: domain.Ecosystem(packages[0].Ecosystem), Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh}}, nil
}

func (c *captureBatchLocalChecker) FindMaliciousBatch(_ context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	c.maliciousQueries = append(c.maliciousQueries, packages...)
	return []domain.Finding{{Name: packages[1].Name, Version: packages[1].Version, Ecosystem: domain.Ecosystem(packages[1].Ecosystem), Type: domain.FindingTypeMalicious, Severity: domain.SeverityCritical}}, nil
}

func (c *captureBatchLocalChecker) FindReputationFindingsBatch(_ context.Context, packages []PackageLookup, source string) ([]domain.Finding, error) {
	if source != reversingLabsReputationSource {
		return nil, fmt.Errorf("source = %q, want %q", source, reversingLabsReputationSource)
	}
	c.reputationQueries = append(c.reputationQueries, packages...)
	return c.reputationFindings, nil
}

func TestCheckLocalUsesBatchCheckerWhenAvailable(t *testing.T) {
	t.Parallel()

	checker := &captureBatchLocalChecker{}
	sc := New(nil, Config{})
	sc.SetLocalChecker(checker)

	findings, err := sc.checkLocal(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "evil", Version: "2.0.0", Ecosystem: domain.EcosystemNPM},
	})
	if err != nil {
		t.Fatalf("checkLocal() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want batch vulnerability + malicious findings", findings)
	}
	if len(checker.vulnQueries) != 2 || len(checker.maliciousQueries) != 2 {
		t.Fatalf("batch queries = vuln %+v malicious %+v, want both package queries", checker.vulnQueries, checker.maliciousQueries)
	}
}

func TestCheckLocalUsesExplicitReputationBatchChecker(t *testing.T) {
	t.Parallel()

	checker := &captureBatchLocalChecker{
		reputationFindings: []domain.Finding{{
			Name:       "left-pad",
			Version:    "1.0.0",
			Ecosystem:  domain.EcosystemNPM,
			Type:       domain.FindingTypeSupplyChainRisk,
			RiskType:   "removed_package",
			Severity:   domain.SeverityCritical,
			AdvisoryID: "reversinglabs:npm/left-pad@1.0.0",
			Source:     reversingLabsReputationSource,
		}},
	}
	sc := New(nil, Config{})
	sc.SetLocalChecker(checker)

	findings, err := sc.checkLocal(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "evil", Version: "2.0.0", Ecosystem: domain.EcosystemNPM},
	})
	if err != nil {
		t.Fatalf("checkLocal() error = %v", err)
	}
	if len(checker.reputationQueries) != 2 {
		t.Fatalf("reputation queries = %+v, want both package queries", checker.reputationQueries)
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %+v, want vulnerability, malicious, and reputation findings", findings)
	}
	if findings[2].Type != domain.FindingTypeSupplyChainRisk || findings[2].Source != reversingLabsReputationSource {
		t.Fatalf("reputation finding = %+v, want explicit ReversingLabs supply-chain risk", findings[2])
	}
}

type lifecycleLocalChecker struct {
	noopLocalCoverage
	lifecycleFindings []domain.Finding
	lifecycleQueries  []PackageLookup
}

func (c *lifecycleLocalChecker) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}

func (c *lifecycleLocalChecker) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}

func (c *lifecycleLocalChecker) FindLifecycleFindingsBatch(_ context.Context, packages []PackageLookup, _ time.Time) ([]domain.Finding, error) {
	c.lifecycleQueries = append(c.lifecycleQueries, packages...)
	return c.lifecycleFindings, nil
}

type errorLocalChecker struct {
	noopLocalCoverage
	vulnErr      error
	maliciousErr error
}

func (c errorLocalChecker) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	if c.vulnErr != nil {
		return nil, c.vulnErr
	}
	return nil, nil
}

func (c errorLocalChecker) FindMalicious(_ context.Context, ecosystem, name, _ string) ([]domain.Finding, error) {
	if c.maliciousErr != nil {
		return nil, c.maliciousErr
	}
	return []domain.Finding{{Name: name, Ecosystem: domain.Ecosystem(ecosystem), Type: domain.FindingTypeMalicious}}, nil
}

func TestCheckLocalErrorsAndMaliciousVersion(t *testing.T) {
	t.Parallel()

	pkgs := []domain.Package{{Name: "evil", Version: "1.2.3", Ecosystem: domain.EcosystemNPM}}

	sc := New(nil, Config{})
	sc.SetLocalChecker(errorLocalChecker{vulnErr: errors.New("vuln db down")})
	if _, err := sc.checkLocal(context.Background(), pkgs); err == nil || !strings.Contains(err.Error(), "local vuln check") {
		t.Fatalf("checkLocal(vuln error) = %v", err)
	}

	sc.SetLocalChecker(errorLocalChecker{maliciousErr: errors.New("mal db down")})
	if _, err := sc.checkLocal(context.Background(), pkgs); err == nil || !strings.Contains(err.Error(), "local malicious check") {
		t.Fatalf("checkLocal(malicious error) = %v", err)
	}

	sc.SetLocalChecker(errorLocalChecker{})
	findings, err := sc.checkLocal(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("checkLocal() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Version != "1.2.3" {
		t.Fatalf("findings = %+v, want malicious finding with package version", findings)
	}
}

// severityLocalChecker reports a single vulnerability finding of a fixed
// severity for every package, used to exercise the blocking/non-blocking
// exit-code logic.
type severityLocalChecker struct {
	noopLocalCoverage
	severity domain.Severity
}

func (c severityLocalChecker) FindVulnerabilities(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	return []domain.Finding{{
		Name:      name,
		Version:   version,
		Ecosystem: domain.Ecosystem(ecosystem),
		Type:      domain.FindingType("vulnerability"),
		Severity:  c.severity,
		Title:     "test finding",
		Source:    "test",
	}}, nil
}

func (c severityLocalChecker) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}

func TestScannerReturnsUnderThresholdForNonBlockingFindings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lockFile := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(lockFile, []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	sc := New(parser.NewRegistry(), Config{
		Path:     dir,
		Mode:     ModeLocal,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 3,
		Timeout:  5 * time.Second,
	})
	// A HIGH finding with a CRITICAL threshold is non-blocking.
	sc.SetLocalChecker(severityLocalChecker{severity: domain.SeverityHigh})

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitUnderThreshold {
		t.Fatalf("exit = %d, want %d (non-blocking findings); result = %+v", exitCode, ExitUnderThreshold, result)
	}
	if result.FindingsBlocking {
		t.Fatal("expected findings to be non-blocking")
	}
	if result.BlockThreshold != domain.SeverityCritical {
		t.Fatalf("BlockThreshold = %q, want %q", result.BlockThreshold, domain.SeverityCritical)
	}
	if result.FindingsCount == 0 {
		t.Fatal("expected at least one finding")
	}
}

func TestScannerRunAnnotatesFindingsWithPackageSourceLocations(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	sc := New(parser.NewRegistry(), Config{
		Path:     dir,
		Mode:     ModeLocal,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 3,
		Timeout:  5 * time.Second,
	})
	sc.SetLocalChecker(severityLocalChecker{severity: domain.SeverityHigh})

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitUnderThreshold {
		t.Fatalf("exit = %d, result = %+v", exitCode, result)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	if got := result.Findings[0].Locations; len(got) != 1 || got[0].URI != "package-lock.json" {
		t.Fatalf("finding locations = %+v, want package-lock.json", got)
	}
}

func TestScannerRunNoLockFilesReturnsCleanResult(t *testing.T) {
	t.Parallel()

	sc := New(parser.NewRegistry(), Config{
		Path:     t.TempDir(),
		Mode:     ModeAuto,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 2,
	})
	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOK {
		t.Fatalf("exit = %d, result = %+v", exitCode, result)
	}
	if result.PackagesScanned != 0 || result.FindingsCount != 0 || result.FeedVersions == nil {
		t.Fatalf("result = %+v, want clean empty scan with feed_versions map", result)
	}
	if result.BlockThreshold != domain.SeverityCritical {
		t.Fatalf("BlockThreshold = %q, want %q", result.BlockThreshold, domain.SeverityCritical)
	}
}

func TestScannerRunAutoRemoteSuccessReportsRemoteMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/check" {
			http.NotFound(w, r)
			return
		}
		writeJSONForScannerTest(t, w, domain.ScanResult{
			ScanID:       "remote-scan",
			Mode:         "remote",
			ScannedAt:    time.Now().UTC(),
			Summary:      domain.ScanSummary{BySeverity: map[string]int{}, ByType: map[string]int{}, BySource: map[string]int{}},
			Findings:     []domain.Finding{},
			FeedVersions: map[string]string{},
		})
	}))
	defer ioutils.CloseSilently(server)

	sc := New(parser.NewRegistry(), Config{
		Path:              dir,
		Mode:              ModeAuto,
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		FailOn:            domain.SeverityCritical,
		MaxDepth:          3,
		Timeout:           5 * time.Second,
	})
	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOK {
		t.Fatalf("exit = %d, result = %+v", exitCode, result)
	}
	if result.Mode != ModeRemote {
		t.Fatalf("Mode = %q, want %q for successful auto remote scan", result.Mode, ModeRemote)
	}
}

func TestScannerOperationalErrorSeparatesFeedStatusAndScanError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	sc := New(parser.NewRegistry(), Config{
		Path:     dir,
		Mode:     ModeLocal,
		FailOn:   domain.SeverityHigh,
		MaxDepth: 3,
	})

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOperational {
		t.Fatalf("exit = %d, want operational error; result = %+v", exitCode, result)
	}
	if result.FeedStatus != "error" {
		t.Fatalf("FeedStatus = %q, want machine-readable error", result.FeedStatus)
	}
	if !strings.Contains(result.ScanError, "local advisory data unavailable") {
		t.Fatalf("ScanError = %q, want operational detail", result.ScanError)
	}
	if strings.Contains(result.FeedStatus, "local advisory data unavailable") {
		t.Fatalf("FeedStatus contains operational detail: %q", result.FeedStatus)
	}
	if result.BlockThreshold != domain.SeverityHigh {
		t.Fatalf("BlockThreshold = %q, want %q", result.BlockThreshold, domain.SeverityHigh)
	}
}

func TestScannerRunParserAndLocalModeErrors(t *testing.T) {
	t.Parallel()

	badDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(badDir, "package-lock.json"), []byte(`not json`), 0o600); err != nil {
		t.Fatalf("write bad lock: %v", err)
	}
	sc := New(parser.NewRegistry(), Config{
		Path:     badDir,
		Mode:     ModeLocal,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 2,
	})
	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitParser || result.FeedStatus != "error" || !strings.Contains(result.ScanError, "invalid JSON") {
		t.Fatalf("parser result exit=%d result=%+v", exitCode, result)
	}

	localDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(localDir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	sc = New(parser.NewRegistry(), Config{
		Path:     localDir,
		Mode:     ModeLocal,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 2,
	})
	result, exitCode = sc.Run(context.Background())
	if exitCode != ExitOperational || result.FeedStatus != "error" || !strings.Contains(result.ScanError, "local advisory data unavailable") {
		t.Fatalf("local no checker exit=%d result=%+v", exitCode, result)
	}
	if result.PackagesScanned != 1 {
		t.Fatalf("local no checker packages = %d, want 1", result.PackagesScanned)
	}
}

type sortingLocalChecker struct {
	noopLocalCoverage
}

func (sortingLocalChecker) FindVulnerabilities(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	return []domain.Finding{{
		Name:       name + "-low",
		Version:    version,
		Ecosystem:  domain.Ecosystem(ecosystem),
		Type:       domain.FindingTypeVulnerability,
		Severity:   domain.SeverityLow,
		AdvisoryID: "LOW-1",
		Source:     "test",
	}, {
		Name:       name + "-critical",
		Version:    version,
		Ecosystem:  domain.Ecosystem(ecosystem),
		Type:       domain.FindingTypeVulnerability,
		Severity:   domain.SeverityCritical,
		AdvisoryID: "CRIT-1",
		Source:     "test",
	}}, nil
}

func (sortingLocalChecker) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}

func TestScannerRunSortsFindingsAndReturnsBlockingExit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	sc := New(parser.NewRegistry(), Config{
		Path:     dir,
		Mode:     ModeLocal,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 2,
	})
	sc.SetLocalChecker(sortingLocalChecker{})

	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitBlocking || !result.FindingsBlocking {
		t.Fatalf("exit=%d result=%+v, want blocking", exitCode, result)
	}
	if len(result.Findings) != 2 || result.Findings[0].Severity != domain.SeverityCritical {
		t.Fatalf("findings order = %+v, want critical first", result.Findings)
	}
}

type manualCountLocalChecker struct {
	noopLocalCoverage
}

func (manualCountLocalChecker) FindVulnerabilities(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	return []domain.Finding{
		{
			Name:      name,
			Version:   version,
			Ecosystem: domain.Ecosystem(ecosystem),
			Type:      domain.FindingTypeVulnerability,
			Severity:  domain.SeverityHigh,
			Source:    "manual",
		},
		{
			Name:      name,
			Version:   version,
			Ecosystem: domain.Ecosystem(ecosystem),
			Type:      domain.FindingTypeVulnerability,
			Severity:  domain.SeverityHigh,
			Source:    "osv",
		},
	}, nil
}

func (manualCountLocalChecker) FindMalicious(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	return []domain.Finding{
		{
			Name:      name,
			Version:   version,
			Ecosystem: domain.Ecosystem(ecosystem),
			Type:      domain.FindingTypeMalicious,
			Severity:  domain.SeverityCritical,
			Source:    "manual",
		},
	}, nil
}

func TestScannerRunCountsManualAdvisoryFindings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	sc := New(parser.NewRegistry(), Config{
		Path:     dir,
		Mode:     ModeLocal,
		FailOn:   domain.SeverityCritical,
		MaxDepth: 2,
	})
	sc.SetLocalChecker(manualCountLocalChecker{})

	result, exitCode := sc.Run(context.Background())

	if exitCode != ExitBlocking {
		t.Fatalf("exit = %d, want blocking: %+v", exitCode, result)
	}
	if result.ManualAdvisoriesCount != 2 {
		t.Fatalf("manual_advisories_count = %d, want 2", result.ManualAdvisoriesCount)
	}
}

// ---------------------------------------------------------------------------
// hasBlockingFindings tests
// ---------------------------------------------------------------------------

func TestHasBlockingFindings_MalwareAlwaysBlocks(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{FailOn: domain.SeverityCritical})

	findings := []domain.Finding{
		{
			Type:     domain.FindingTypeMalicious,
			Severity: domain.SeverityLow,
			Source:   "openssf",
		},
	}

	if !sc.hasBlockingFindings(findings) {
		t.Fatal("malware findings must always block, regardless of fail-on threshold")
	}
}

func TestHasBlockingFindings_VulnAboveThreshold(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{FailOn: domain.SeverityHigh})

	tests := []struct {
		name     string
		severity domain.Severity
		want     bool
	}{
		{"CRITICAL blocks with HIGH threshold", domain.SeverityCritical, true},
		{"HIGH blocks with HIGH threshold", domain.SeverityHigh, true},
		{"MEDIUM does NOT block with HIGH threshold", domain.SeverityMedium, false},
		{"LOW does NOT block with HIGH threshold", domain.SeverityLow, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := []domain.Finding{
				{Type: domain.FindingTypeVulnerability, Severity: tt.severity, Source: "osv"},
			}
			got := sc.hasBlockingFindings(findings)
			if got != tt.want {
				t.Fatalf("hasBlockingFindings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasBlockingFindings_NoneThresholdNeverBlocks(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{FailOn: domain.SeverityNone})

	findings := []domain.Finding{
		{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityCritical, Source: "osv"},
	}

	if sc.hasBlockingFindings(findings) {
		t.Fatal("with FailOn=NONE, vulnerability findings should never block")
	}
}

func TestHasBlockingFindings_MalwareBlocksEvenWithNoneThreshold(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{FailOn: domain.SeverityNone})

	findings := []domain.Finding{
		{Type: domain.FindingTypeMalicious, Severity: domain.SeverityUnknown, Source: "socket"},
	}

	if !sc.hasBlockingFindings(findings) {
		t.Fatal("malware must block even with NONE threshold")
	}
}

func TestSupplyChainRiskBlocksEvenWithNoneThreshold(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{FailOn: domain.SeverityNone})
	findings := []domain.Finding{
		{Type: domain.FindingTypeSupplyChainRisk, Severity: domain.SeverityCritical, Source: "reversinglabs"},
	}

	if !sc.hasBlockingFindings(findings) {
		t.Fatal("supply-chain risk findings must block regardless of vulnerability threshold")
	}
}

func TestHasBlockingFindings_NoFindings(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{FailOn: domain.SeverityLow})

	if sc.hasBlockingFindings(nil) {
		t.Fatal("nil findings should not block")
	}
	if sc.hasBlockingFindings([]domain.Finding{}) {
		t.Fatal("empty findings should not block")
	}
}

// ---------------------------------------------------------------------------
// resolveMode tests
// ---------------------------------------------------------------------------

func TestResolveMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfgMode Mode
		want    Mode
	}{
		{"explicit remote", ModeRemote, ModeRemote},
		{"explicit local", ModeLocal, ModeLocal},
		{"explicit auto", ModeAuto, ModeAuto},
		{"empty string defaults to auto", Mode(""), ModeAuto},
		{"unknown string defaults to auto", Mode("unknown"), ModeAuto},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := New(nil, Config{Mode: tt.cfgMode})
			if got := sc.resolveMode(); got != tt.want {
				t.Fatalf("resolveMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseModeNormalizesAndValidatesScanModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw     string
		want    Mode
		wantErr bool
	}{
		{raw: "", want: ModeAuto},
		{raw: " AUTO ", want: ModeAuto},
		{raw: "remote", want: ModeRemote},
		{raw: " Local ", want: ModeLocal},
		{raw: "sideways", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := ParseMode(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseMode() error = nil, want invalid mode error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMode() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseMode(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildSummary tests (scanner package level)
// ---------------------------------------------------------------------------

func TestBuildSummary_Scanner(t *testing.T) {
	t.Parallel()

	findings := []domain.Finding{
		{Severity: domain.SeverityCritical, Type: domain.FindingTypeVulnerability, Source: "osv"},
		{Severity: domain.SeverityHigh, Type: domain.FindingTypeMalicious, Source: "openssf"},
		{Severity: domain.SeverityCritical, Type: domain.FindingTypeVulnerability, Source: "ghsa"},
	}

	s := domain.BuildScanSummary(findings)

	if s.BySeverity["CRITICAL"] != 2 {
		t.Fatalf("BySeverity[CRITICAL] = %d, want 2", s.BySeverity["CRITICAL"])
	}
	if s.BySeverity["HIGH"] != 1 {
		t.Fatalf("BySeverity[HIGH] = %d, want 1", s.BySeverity["HIGH"])
	}
	if s.ByType["vulnerability"] != 2 {
		t.Fatalf("ByType[vulnerability] = %d, want 2", s.ByType["vulnerability"])
	}
	if s.ByType["malicious"] != 1 {
		t.Fatalf("ByType[malicious] = %d, want 1", s.ByType["malicious"])
	}
	if s.BySource["osv"] != 1 {
		t.Fatalf("BySource[osv] = %d, want 1", s.BySource["osv"])
	}
}
