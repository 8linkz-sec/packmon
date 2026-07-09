package v1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/requestctx"
	"github.com/8linkz-sec/packmon/internal/synccontract"
)

type readOnlyCheckStore struct{}

var _ Store = (*readOnlyCheckStore)(nil)

func (s *readOnlyCheckStore) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}

func (s *readOnlyCheckStore) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}

func (s *readOnlyCheckStore) FindVulnerabilitiesBatch(context.Context, []PackageLookup) ([]domain.Finding, error) {
	return nil, nil
}

func (s *readOnlyCheckStore) FindMaliciousBatch(context.Context, []PackageLookup) ([]domain.Finding, error) {
	return nil, nil
}

func (s *readOnlyCheckStore) FindReputationFindingsBatch(context.Context, []PackageLookup, string) ([]domain.Finding, error) {
	return nil, nil
}

func (s *readOnlyCheckStore) FindLifecycleFindingsBatch(context.Context, []PackageLookup, time.Time) ([]domain.Finding, error) {
	return nil, nil
}

func (s *readOnlyCheckStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	return nil, nil
}

func testSyncCursorKey(values ...string) string {
	payload, _ := json.Marshal(values)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func (s *readOnlyCheckStore) EnqueueRefresh(context.Context, *db.RefreshJob) (bool, int, error) {
	return false, 0, nil
}

func (s *readOnlyCheckStore) EnqueueRefreshWithAudit(context.Context, *db.RefreshJob, func(created bool, position int) *db.AdminAuditEntry) (bool, int, error) {
	return false, 0, db.ErrAdminAuditLog
}

func (s *readOnlyCheckStore) InsertScanLog(context.Context, *db.ScanLogEntry) error {
	return nil
}

func (s *readOnlyCheckStore) InsertAdminAuditLog(context.Context, *db.AdminAuditEntry) error {
	return nil
}

func (s *readOnlyCheckStore) GetScanLogByIdempotencyKey(context.Context, string) (*db.ScanLogEntry, error) {
	return nil, nil
}

func (s *readOnlyCheckStore) ExportSync(context.Context, db.SyncExportOptions) (*db.SyncExport, error) {
	return &db.SyncExport{SyncedAt: time.Now().UTC()}, nil
}

func TestHandlerCheckStoreDoesNotRequireReputationSchedulerWrites(t *testing.T) {
	t.Parallel()

	h := NewHandlerWithBlockThreshold(&readOnlyCheckStore{}, nil, domain.SeverityCritical)
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeSelf,
		ReversingLabsAPIKey:  "rl-token",
	})
	if _, err := h.collectFindings(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
	}); err != nil {
		t.Fatalf("collectFindings() error = %v", err)
	}
}

func TestNewHandlerRuntimeAndThresholdFallbacks(t *testing.T) {
	t.Parallel()

	h := NewHandlerWithRuntime(&stubStore{}, nil, config.NewRuntimeSettings("medium", 0, 0))
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeSelf,
	})
	if h.blockThreshold != domain.SeverityMedium {
		t.Fatalf("blockThreshold = %q, want MEDIUM", h.blockThreshold)
	}
	if !h.reversingLabsEnabled.Load() {
		t.Fatal("ReversingLabs should be enabled from config")
	}

	h = NewHandlerWithRuntime(&stubStore{}, nil, config.NewRuntimeSettings("nonsense", 0, 0))
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeExternal,
	})
	if h.blockThreshold != defaultBlockThreshold {
		t.Fatalf("invalid threshold fallback = %q, want %q", h.blockThreshold, defaultBlockThreshold)
	}
	if h.reversingLabsEnabled.Load() {
		t.Fatal("ReversingLabs external mode should not enable API scheduling")
	}

	if h := NewHandlerWithRuntime(&stubStore{}, nil, nil); h.blockThreshold != defaultBlockThreshold {
		t.Fatalf("nil runtime threshold = %q, want default", h.blockThreshold)
	}

	h = NewHandlerWithBlockThreshold(&stubStore{}, nil, domain.Severity("BOGUS"))
	if h.blockThreshold != defaultBlockThreshold {
		t.Fatalf("invalid explicit threshold = %q, want %q", h.blockThreshold, defaultBlockThreshold)
	}

	var nilHandler *Handler
	nilHandler.ConfigureReversingLabs(config.FeedsConfig{ReversingLabsEnabled: true, ReversingLabsMode: config.FeedModeSelf})
}

func TestEncodeJSONResponseEscapesHTML(t *testing.T) {
	t.Parallel()

	body, err := encodeJSONResponse(map[string]string{"summary": `<script>alert("x")</script>&`})
	if err != nil {
		t.Fatalf("encodeJSONResponse: %v", err)
	}
	text := string(body)
	if strings.Contains(text, "<script>") || strings.Contains(text, "</script>") || strings.Contains(text, "&") {
		t.Fatalf("encoded JSON contains raw HTML-sensitive bytes: %s", text)
	}
	for _, want := range []string{`\u003cscript\u003e`, `\u003c/script\u003e`, `\u0026`} {
		if !strings.Contains(text, want) {
			t.Fatalf("encoded JSON missing escaped marker %q in %s", want, text)
		}
	}
}

func TestFeedImportDispatchTableMapsKnownFeedsToTypedRequests(t *testing.T) {
	t.Parallel()

	expectedFeeds := make(map[string]struct{})
	for _, feed := range config.FeedExternalModeNames() {
		expectedFeeds[feed] = struct{}{}
	}

	cases := []struct {
		feed string
		want func(any) bool
	}{
		{feed: "osv", want: func(req any) bool { _, ok := req.(*vulnerabilityImportRequest); return ok }},
		{feed: "ghsa", want: func(req any) bool { _, ok := req.(*vulnerabilityImportRequest); return ok }},
		{feed: "openssf", want: func(req any) bool { _, ok := req.(*maliciousImportRequest); return ok }},
		{feed: "socket", want: func(req any) bool { _, ok := req.(*maliciousImportRequest); return ok }},
		{feed: "vulncheck", want: func(req any) bool { _, ok := req.(*vulnCheckImportRequest); return ok }},
		{feed: "cisakev", want: func(req any) bool { _, ok := req.(*cisaKEVImportRequest); return ok }},
		{feed: "epss", want: func(req any) bool { _, ok := req.(*epssImportRequest); return ok }},
	}

	for _, tt := range cases {
		capability, ok := feedImportCapabilityForFeed(tt.feed)
		if !ok {
			t.Fatalf("feedImportCapabilityForFeed(%q) missing", tt.feed)
		}
		if capability.name != tt.feed {
			t.Fatalf("feedImportCapabilityForFeed(%q).name = %q", tt.feed, capability.name)
		}
		req := capability.dispatch.newRequest()
		if !tt.want(req) {
			t.Fatalf("feed import capability %q request type = %T", tt.feed, req)
		}
		if _, ok := expectedFeeds[tt.feed]; !ok {
			t.Fatalf("feed import capability %q is not backed by config external-mode metadata", tt.feed)
		}
		delete(expectedFeeds, tt.feed)
	}
	if len(expectedFeeds) > 0 {
		t.Fatalf("feed import capabilities missing config external-mode feeds: %v", expectedFeeds)
	}

	if _, ok := feedImportCapabilityForFeed("malicious"); ok {
		t.Fatal("malicious alias must normalize before capability lookup")
	}
	if got := FeedImportPathFeedNames(); !containsString(got, "malicious") {
		t.Fatalf("FeedImportPathFeedNames() = %v, want malicious alias documented", got)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestHandleFeedImportValidationAndDeleteBranches(t *testing.T) {
	t.Parallel()

	h := newTestFeedImportHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(`{"vulnerabilities":[{}]}`))
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleImport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing vulnerability id status = %d, want 400", rr.Code)
	}

	store := &stubStore{}
	h = newTestFeedImportHandler(store)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(`{
		"malicious":[{"id":"SOCK-1","ecosystem":"npm","name":"evil","severity":"HIGH"}],
		"delete_malicious_ids":["", "SOCK-old"],
		"status":{"entries_synced":5,"entries_total":9}
	}`))
	req.SetPathValue("feed", "socket")
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.HandleImport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("socket import status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedMalicious) != 1 || store.upsertedMalicious[0].Source != "socket" {
		t.Fatalf("upserted malicious = %+v, want socket source", store.upsertedMalicious)
	}
	if len(store.deletedMaliciousIDs) != 0 {
		t.Fatalf("legacy malicious deletes = %#v, want source-scoped delete", store.deletedMaliciousIDs)
	}
	if len(store.deletedMaliciousScoped) != 1 || store.deletedMaliciousScoped[0].id != "SOCK-old" || store.deletedMaliciousScoped[0].source != "socket" {
		t.Fatalf("scoped malicious deletes = %#v, want SOCK-old/socket", store.deletedMaliciousScoped)
	}
	if len(store.upsertedStatuses) != 1 || store.upsertedStatuses[0].EntriesSynced != 5 || store.upsertedStatuses[0].EntriesTotal != 9 {
		t.Fatalf("status import = %+v", store.upsertedStatuses)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(`{`))
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.HandleImport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON status = %d, want 400", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds//import", strings.NewReader(`{}`))
	req.SetPathValue("feed", "")
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.HandleImport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty feed status = %d, want 400", rr.Code)
	}

	for _, feed := range []string{"vulncheck", "cisakev", "epss"} {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+feed+"/import", strings.NewReader(`{`))
		req.SetPathValue("feed", feed)
		req.Header.Set("Content-Type", "application/json")
		rr = httptest.NewRecorder()
		h.HandleImport(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s invalid JSON status = %d, want 400", feed, rr.Code)
		}
	}
}

func TestHandleFeedImportRejectsInvalidEnrichmentScores(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		feed string
		body string
	}{
		{
			name: "epss score above one",
			feed: "epss",
			body: `{"entries":[{"cve_id":"CVE-2026-0001","score":1.5,"percentile":0.5}]}`,
		},
		{
			name: "epss percentile below zero",
			feed: "epss",
			body: `{"entries":[{"cve_id":"CVE-2026-0001","score":0.5,"percentile":-0.1}]}`,
		},
		{
			name: "vulncheck cvss above ten",
			feed: "vulncheck",
			body: `{"entries":[{"cve_id":"CVE-2026-0001","cvss_score":99,"exploit_exists":true}]}`,
		},
		{
			name: "vulncheck cvss below zero",
			feed: "vulncheck",
			body: `{"entries":[{"cve_id":"CVE-2026-0001","cvss_score":-0.1}]}`,
		},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &stubStore{}
			h := newTestFeedImportHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", tt.feed)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.epssEntries) != 0 || store.epssReplaceCalls != 0 || len(store.vulnCheckEntries) != 0 {
				t.Fatalf("store mutated on invalid import: epss=%+v replace=%d vulncheck=%+v", store.epssEntries, store.epssReplaceCalls, store.vulnCheckEntries)
			}
		})
	}
}

func TestHandleFeedImportRejectsInvalidVulnerabilityIdentity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{
			name: "invalid severity",
			body: `{"vulnerabilities":[{"id":"GHSA-invalid","severity":"INFO"}]}`,
		},
		{
			name: "none severity",
			body: `{"vulnerabilities":[{"id":"GHSA-invalid","severity":"NONE"}]}`,
		},
		{
			name: "invalid ecosystem",
			body: `{"vulnerabilities":[{"id":"GHSA-invalid","affected_packages":[{"ecosystem":"npmm","name":"left-pad"}]}]}`,
		},
		{
			name: "empty package name",
			body: `{"vulnerabilities":[{"id":"GHSA-invalid","affected_packages":[{"ecosystem":"npm","name":"   "}]}]}`,
		},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &stubStore{}
			h := newTestFeedImportHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", "osv")
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.upsertedVulns) != 0 {
				t.Fatalf("store mutated on invalid vulnerability import: vulns=%+v statuses=%+v", store.upsertedVulns, store.upsertedStatuses)
			}
			assertSingleRejectedFeedStatus(t, store.upsertedStatuses, "osv")
		})
	}
}

func TestHandleFeedImportRejectsInvalidVulnerabilityVersionData(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{
			name: "version ranges object",
			body: `{"vulnerabilities":[{"id":"GHSA-invalid","affected_packages":[{"ecosystem":"npm","name":"left-pad","version_ranges":{"introduced":"0"}}]}]}`,
		},
		{
			name: "version range without events",
			body: `{"vulnerabilities":[{"id":"GHSA-invalid","affected_packages":[{"ecosystem":"npm","name":"left-pad","version_ranges":[{"type":"SEMVER"}]}]}]}`,
		},
		{
			name: "version range event scalar",
			body: `{"vulnerabilities":[{"id":"GHSA-invalid","affected_packages":[{"ecosystem":"npm","name":"left-pad","version_ranges":[{"type":"SEMVER","events":["0"]}]}]}]}`,
		},
		{
			name: "version range empty event",
			body: `{"vulnerabilities":[{"id":"GHSA-invalid","affected_packages":[{"ecosystem":"npm","name":"left-pad","version_ranges":[{"type":"SEMVER","events":[{}]}]}]}`,
		},
		{
			name: "version range blank event boundary",
			body: `{"vulnerabilities":[{"id":"GHSA-invalid","affected_packages":[{"ecosystem":"npm","name":"left-pad","version_ranges":[{"type":"SEMVER","events":[{"introduced":" "}]}]}]}`,
		},
		{
			name: "versions affected object",
			body: `{"vulnerabilities":[{"id":"GHSA-invalid","affected_packages":[{"ecosystem":"npm","name":"left-pad","versions_affected":{"all":true}}]}]}`,
		},
		{
			name: "versions affected non-string",
			body: `{"vulnerabilities":[{"id":"GHSA-invalid","affected_packages":[{"ecosystem":"npm","name":"left-pad","versions_affected":["1.0.0",2]}]}]}`,
		},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &stubStore{}
			h := newTestFeedImportHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", "osv")
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.upsertedVulns) != 0 {
				t.Fatalf("store mutated on invalid version data: vulns=%+v statuses=%+v", store.upsertedVulns, store.upsertedStatuses)
			}
			assertSingleRejectedFeedStatus(t, store.upsertedStatuses, "osv")
		})
	}
}

func TestHandleFeedImportRejectsInvalidMaliciousIdentity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{
			name: "invalid ecosystem",
			body: `{"malicious":[{"id":"MAL-invalid","ecosystem":"npmm","name":"evil"}]}`,
		},
		{
			name: "empty name",
			body: `{"malicious":[{"id":"MAL-invalid","ecosystem":"npm","name":"  "}]}`,
		},
		{
			name: "invalid severity",
			body: `{"malicious":[{"id":"MAL-invalid","ecosystem":"npm","name":"evil","severity":"INFO"}]}`,
		},
		{
			name: "versions object",
			body: `{"malicious":[{"id":"MAL-invalid","ecosystem":"npm","name":"evil","versions":{"all":true}}]}`,
		},
		{
			name: "versions non-string",
			body: `{"malicious":[{"id":"MAL-invalid","ecosystem":"npm","name":"evil","versions":["1.0.0",2]}]}`,
		},
		{
			name: "versions empty string",
			body: `{"malicious":[{"id":"MAL-invalid","ecosystem":"npm","name":"evil","versions":[""]}]}`,
		},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &stubStore{}
			h := newTestFeedImportHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", "socket")
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.upsertedMalicious) != 0 {
				t.Fatalf("store mutated on invalid malicious import: malicious=%+v statuses=%+v", store.upsertedMalicious, store.upsertedStatuses)
			}
			assertSingleRejectedFeedStatus(t, store.upsertedStatuses, "socket")
		})
	}
}

func TestHandleFeedImportValidationErrorsIncludeRecordContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		feed string
		body string
		want []string
	}{
		{
			name: "vulnerability array index and id",
			feed: "osv",
			body: `{
				"vulnerabilities":[
					{"id":"GHSA-valid","severity":"HIGH"},
					{"id":"GHSA-bad","severity":"INFO"}
				]
			}`,
			want: []string{"vulnerabilities[1]", "GHSA-bad", "severity"},
		},
		{
			name: "malicious array index and id",
			feed: "socket",
			body: `{
				"malicious":[
					{"id":"MAL-valid","ecosystem":"npm","name":"evil","severity":"HIGH"},
					{"id":"MAL-bad","ecosystem":"npm","name":"evil","severity":"INFO"}
				]
			}`,
			want: []string{"malicious[1]", "MAL-bad", "severity"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &stubStore{}
			h := newTestFeedImportHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", tt.feed)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			for _, want := range tt.want {
				if !strings.Contains(rr.Body.String(), want) {
					t.Fatalf("response missing %q: %s", want, rr.Body.String())
				}
			}
			if len(store.upsertedVulns) != 0 || len(store.upsertedMalicious) != 0 {
				t.Fatalf("store mutated on invalid import: vulns=%+v malicious=%+v statuses=%+v", store.upsertedVulns, store.upsertedMalicious, store.upsertedStatuses)
			}
			assertSingleRejectedFeedStatus(t, store.upsertedStatuses, tt.feed)
		})
	}
}

func TestHandleFeedImportRequiresConfiguredSecret(t *testing.T) {
	t.Parallel()

	body := `{"malicious":[{"id":"MAL-secret","ecosystem":"npm","name":"evil"}]}`
	for _, tt := range []struct {
		name   string
		secret string
		want   int
	}{
		{name: "missing", want: http.StatusForbidden},
		{name: "wrong", secret: "wrong-secret", want: http.StatusForbidden},
		{name: "matching", secret: "import-secret", want: http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &stubStore{}
			h := newTestFeedImportHandler(store)
			h.ConfigureFeedImportSecret("import-secret", true)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(body))
			req.SetPathValue("feed", "socket")
			req.Header.Set("Content-Type", "application/json")
			if tt.secret != "" {
				req.Header.Set(HeaderFeedImportSecret, tt.secret)
			}
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.want, rr.Body.String())
			}
			if tt.want != http.StatusOK {
				if len(store.upsertedMalicious) != 0 || len(store.auditEntries) != 0 {
					t.Fatalf("unauthorized import mutated state: malicious=%+v audit=%+v", store.upsertedMalicious, store.auditEntries)
				}
				return
			}
			if len(store.upsertedMalicious) != 1 {
				t.Fatalf("upserted malicious = %d, want 1", len(store.upsertedMalicious))
			}
			if len(store.auditEntries) != 1 {
				t.Fatalf("audit entries = %d, want 1", len(store.auditEntries))
			}
		})
	}
}

func TestHandleFeedImportInvalidSecretLogIncludesClientIP(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	h := newLogCaptureFeedImportHandler(&stubStore{}, &logs)
	h.ConfigureFeedImportSecret("expected-import-secret", true)

	req := withCorrelationID(httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(`{"malicious":[]}`)), "corr-feed-import-auth")
	req.RemoteAddr = "10.0.0.1:49152"
	req.SetPathValue("feed", "socket")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderFeedImportSecret, "wrong-import-secret")
	req = req.WithContext(requestctx.ContextWithClientIP(req.Context(), "203.0.113.45"))
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rr.Code, rr.Body.String())
	}
	requireLogField(t, &logs, "reason", "missing_or_invalid_secret")
	requireLogField(t, &logs, "correlation_id", "corr-feed-import-auth")
	requireLogField(t, &logs, "client_ip", "203.0.113.45")
	for _, forbidden := range []string{"wrong-import-secret", "expected-import-secret", "10.0.0.1"} {
		if strings.Contains(logs.String(), forbidden) {
			t.Fatalf("feed import authorization log leaked %q: %s", forbidden, logs.String())
		}
	}
}

func TestConfigureFeedImportSecretTrimsSecret(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := NewFeedImportHandler(store, nil)
	h.ConfigureFeedImportSecret(" \t import-secret \n ", false)

	if h.feedImportSecret != "import-secret" {
		t.Fatalf("feedImportSecret = %q, want trimmed secret", h.feedImportSecret)
	}
	if h.feedImportRequired {
		t.Fatal("feedImportRequired = true, want false")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(`{"malicious":[{"id":"MAL-config-secret","ecosystem":"npm","name":"evil"}]}`))
	req.SetPathValue("feed", "socket")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderFeedImportSecret, "import-secret")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedMalicious) != 1 {
		t.Fatalf("upserted malicious = %d, want 1", len(store.upsertedMalicious))
	}
	if len(store.auditEntries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(store.auditEntries))
	}
}

func TestConfigureFeedImportSecretRequiredMode(t *testing.T) {
	t.Parallel()

	body := `{"malicious":[{"id":"MAL-config-mode","ecosystem":"npm","name":"evil"}]}`
	for _, tt := range []struct {
		name         string
		wantRequired bool
		wantStatus   int
		wantImported int
	}{
		{
			name:         "production without secret fails closed",
			wantRequired: true,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "development without secret permits import",
			wantRequired: false,
			wantStatus:   http.StatusOK,
			wantImported: 1,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &stubStore{}
			h := NewFeedImportHandler(store, nil)
			h.ConfigureFeedImportSecret("", tt.wantRequired)
			if h.feedImportRequired != tt.wantRequired {
				t.Fatalf("feedImportRequired = %v, want %v", h.feedImportRequired, tt.wantRequired)
			}
			if h.feedImportSecret != "" {
				t.Fatalf("feedImportSecret = %q, want empty", h.feedImportSecret)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(body))
			req.SetPathValue("feed", "socket")
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if len(store.upsertedMalicious) != tt.wantImported {
				t.Fatalf("upserted malicious = %d, want %d", len(store.upsertedMalicious), tt.wantImported)
			}
			if tt.wantStatus != http.StatusOK && len(store.auditEntries) != 0 {
				t.Fatalf("audit entries = %d, want none after rejected import", len(store.auditEntries))
			}
			if tt.wantStatus == http.StatusOK && len(store.auditEntries) != 1 {
				t.Fatalf("audit entries = %d, want 1", len(store.auditEntries))
			}
		})
	}
}

func TestHandleFeedImportValidatesBeforeMutatingState(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(`{
		"vulnerabilities":[
			{"id":"GHSA-valid","summary":"would be persisted by the old loop"},
			{"id":"manual:owned","summary":"reserved namespace"}
		]
	}`))
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("mixed valid/manual import status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedVulns) != 0 {
		t.Fatalf("store mutated before full validation: vulns=%+v statuses=%+v", store.upsertedVulns, store.upsertedStatuses)
	}
	assertSingleRejectedFeedStatus(t, store.upsertedStatuses, "osv")

	store = &stubStore{}
	h = newTestFeedImportHandler(store)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(`{
		"malicious":[{"id":"MAL-valid","ecosystem":"npm","name":"evil"}],
		"status":{"last_sync_status":"totally-fine"}
	}`))
	req.SetPathValue("feed", "socket")
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown status import status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedMalicious) != 0 {
		t.Fatalf("store mutated before status validation: malicious=%+v statuses=%+v", store.upsertedMalicious, store.upsertedStatuses)
	}
	assertSingleRejectedFeedStatus(t, store.upsertedStatuses, "socket")

	for _, status := range []string{
		`{"entries_synced":-1}`,
		`{"entries_total":-1}`,
		`{"last_sync_duration_ms":-1}`,
		`{"entries_synced":5,"entries_total":3}`,
	} {
		store = &stubStore{}
		h = newTestFeedImportHandler(store)
		req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(`{
			"malicious":[{"id":"MAL-valid","ecosystem":"npm","name":"evil"}],
			"status":`+status+`
		}`))
		req.SetPathValue("feed", "socket")
		req.Header.Set("Content-Type", "application/json")
		rr = httptest.NewRecorder()

		h.HandleImport(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid status %s response = %d, want 400: %s", status, rr.Code, rr.Body.String())
		}
		if len(store.upsertedMalicious) != 0 {
			t.Fatalf("store mutated before numeric status validation: malicious=%+v statuses=%+v", store.upsertedMalicious, store.upsertedStatuses)
		}
		assertSingleRejectedFeedStatus(t, store.upsertedStatuses, "socket")
	}
}

func TestHandleFeedImportBoundsPersistedStatusFields(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	body, err := json.Marshal(map[string]any{
		"malicious": []map[string]any{{
			"id":        "MAL-with-error",
			"ecosystem": "npm",
			"name":      "evil",
		}},
		"status": map[string]any{
			"last_sync_status": "error",
			"last_error":       "GET https://user-secret:pass-secret@feeds.example.test/private/path?token=query-secret Authorization: Bearer bearer-secret-token path C:\\Users\\Admin\\AppData\\Local\\Packmon\\feed.json\n" + strings.Repeat("x", 3000),
			"last_etag":        strings.Repeat("e", 800),
			"last_commit_hash": strings.Repeat("c", 300),
		},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(string(body)))
	req.SetPathValue("feed", "socket")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status import = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedStatuses) != 1 {
		t.Fatalf("statuses = %d, want 1", len(store.upsertedStatuses))
	}
	if got := len(store.upsertedStatuses[0].LastError); got != 2048 {
		t.Fatalf("persisted last_error len = %d, want 2048", got)
	}
	for _, leaked := range []string{"user-secret", "pass-secret", "query-secret", "bearer-secret-token", `C:\Users\Admin\AppData\Local\Packmon\feed.json`, "\n"} {
		if strings.Contains(store.upsertedStatuses[0].LastError, leaked) {
			t.Fatalf("persisted last_error leaked %q in %q", leaked, store.upsertedStatuses[0].LastError)
		}
	}
	if got := len(store.upsertedStatuses[0].LastETag); got != 512 {
		t.Fatalf("persisted last_etag len = %d, want 512", got)
	}
	if got := len(store.upsertedStatuses[0].LastCommitHash); got != 128 {
		t.Fatalf("persisted last_commit_hash len = %d, want 128", got)
	}
}

func TestHandleFeedImportRejectsOversizedStatusMetadata(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(map[string]any{
		"malicious": []map[string]any{{
			"id":        "MAL-with-metadata",
			"ecosystem": "npm",
			"name":      "evil",
		}},
		"status": map[string]any{
			"metadata": map[string]any{"payload": strings.Repeat("m", 5000)},
		},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(string(body)))
	req.SetPathValue("feed", "socket")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("oversized metadata status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedMalicious) != 0 {
		t.Fatalf("store mutated for oversized metadata: malicious=%+v statuses=%+v", store.upsertedMalicious, store.upsertedStatuses)
	}
	assertSingleRejectedFeedStatus(t, store.upsertedStatuses, "socket")
}

func TestHandleFeedImportRejectsEmptyCISAKEVClear(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/cisakev/import", strings.NewReader(`{"cve_ids":[],"clear_missing":true}`))
	req.SetPathValue("feed", "cisakev")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(store.cisaKEVIDs) != 0 || len(store.clearedCISAKEVIDs) != 0 {
		t.Fatalf("store mutated for empty CISA KEV clear: set=%+v clear=%+v statuses=%+v",
			store.cisaKEVIDs,
			store.clearedCISAKEVIDs,
			store.upsertedStatuses,
		)
	}
	assertSingleRejectedFeedStatus(t, store.upsertedStatuses, "cisakev")
}

type importErrorStore struct {
	stubStore
	vulnCheckErr error
	cisaErr      error
	cisaClearErr error
	epssErr      error
	statusErr    error
}

func (s *importErrorStore) EnrichVulnCheck(context.Context, []db.VulnCheckEntry) (int, error) {
	return 0, s.vulnCheckErr
}

func (s *importErrorStore) SetCISAKEV(context.Context, []string) (int, error) {
	return 0, s.cisaErr
}

func (s *importErrorStore) ClearCISAKEV(context.Context, []string) (int, error) {
	return 0, s.cisaClearErr
}

func (s *importErrorStore) ReplaceCISAKEV(context.Context, []string) (int, int, error) {
	if s.cisaErr != nil {
		return 0, 0, s.cisaErr
	}
	if s.cisaClearErr != nil {
		return 1, 0, s.cisaClearErr
	}
	return 1, 1, nil
}

func (s *importErrorStore) ReplaceEPSSScores(context.Context, []db.EPSSEntry) (int, int, error) {
	return 0, 0, s.epssErr
}

func (s *importErrorStore) ImportVulnCheckWithAudit(context.Context, string, []db.VulnCheckEntry, *db.FeedSyncStatus, func(imported, deleted int) *db.AdminAuditEntry) (int, error) {
	if s.vulnCheckErr != nil {
		return 0, s.vulnCheckErr
	}
	if s.statusErr != nil {
		return 0, s.statusErr
	}
	return 1, nil
}

func (s *importErrorStore) ImportCISAKEVWithAudit(_ context.Context, _ string, ids []string, _ *db.FeedSyncStatus, _ func(imported, deleted int) *db.AdminAuditEntry) (int, error) {
	if s.cisaErr != nil {
		return 0, s.cisaErr
	}
	if s.statusErr != nil {
		return 0, s.statusErr
	}
	return len(ids), nil
}

func (s *importErrorStore) ReplaceCISAKEVWithAudit(_ context.Context, _ string, ids []string, _ *db.FeedSyncStatus, _ func(imported, deleted int) *db.AdminAuditEntry) (int, int, error) {
	if s.cisaErr != nil {
		return 0, 0, s.cisaErr
	}
	if s.cisaClearErr != nil {
		return 0, 0, s.cisaClearErr
	}
	if s.statusErr != nil {
		return 0, 0, s.statusErr
	}
	return len(ids), len(ids), nil
}

func (s *importErrorStore) ImportEPSSWithAudit(_ context.Context, _ string, entries []db.EPSSEntry, _ *db.FeedSyncStatus, _ func(imported, deleted int) *db.AdminAuditEntry) (int, int, error) {
	if s.epssErr != nil {
		return 0, 0, s.epssErr
	}
	if s.statusErr != nil {
		return 0, 0, s.statusErr
	}
	return len(entries), 0, nil
}

func (s *importErrorStore) UpsertFeedSyncStatus(context.Context, *db.FeedSyncStatus) error {
	return s.statusErr
}

func TestImportHelperStoreErrorBranches(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	status := &feedSyncStatusInput{LastSyncAt: &now, LastSyncStatus: "success", EntriesSynced: 1, EntriesTotal: 1}
	audit := func(imported, deleted int) *db.AdminAuditEntry {
		return &db.AdminAuditEntry{Action: "feed_import"}
	}

	store := &importErrorStore{vulnCheckErr: errors.New("vulncheck down")}
	h := NewFeedImportHandler(store, nil)
	if _, err := h.importVulnCheck(ctx, "vulncheck", &vulnCheckImportRequest{Entries: []vulnCheckImportEntry{{CVEID: "CVE-2026-0001"}}}, audit); err == nil {
		t.Fatal("importVulnCheck(store error) = nil")
	}

	store = &importErrorStore{cisaErr: errors.New("kev down")}
	h = NewFeedImportHandler(store, nil)
	if _, err := h.importCISAKEV(ctx, "cisakev", &cisaKEVImportRequest{CVEIDs: []string{"CVE-2026-0001"}}, audit); err == nil {
		t.Fatal("importCISAKEV(set error) = nil")
	}

	store = &importErrorStore{cisaClearErr: errors.New("clear down")}
	h = NewFeedImportHandler(store, nil)
	if _, err := h.importCISAKEV(ctx, "cisakev", &cisaKEVImportRequest{CVEIDs: []string{"CVE-2026-0001"}, ClearMissing: true}, audit); err == nil {
		t.Fatal("importCISAKEV(clear error) = nil")
	}

	store = &importErrorStore{epssErr: errors.New("epss down")}
	h = NewFeedImportHandler(store, nil)
	score := 0.5
	percentile := 0.7
	if _, err := h.importEPSS(ctx, "epss", &epssImportRequest{Entries: []epssImportEntry{{CVEID: "CVE-2026-0001", Score: &score, Percentile: &percentile}}}, audit); err == nil {
		t.Fatal("importEPSS(store error) = nil")
	}

	store = &importErrorStore{statusErr: errors.New("status down")}
	h = NewFeedImportHandler(store, nil)
	if _, err := h.importVulnCheck(ctx, "vulncheck", &vulnCheckImportRequest{Entries: []vulnCheckImportEntry{{CVEID: "CVE-2026-0001"}}, Status: status}, audit); err == nil {
		t.Fatal("importVulnCheck(status error) = nil")
	}
}

func TestHandlePackageDetailErrors(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash", nil)
	rr := httptest.NewRecorder()
	h.HandlePackageDetail(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status = %d, want 405", rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q, want GET, HEAD", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/", nil)
	req.SetPathValue("ecosystem", "npm")
	rr = httptest.NewRecorder()
	h.HandlePackageDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing package status = %d, want 400", rr.Code)
	}

	h = newTestHandler(&stubStore{vulnErr: errors.New("db down")})
	req = httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/lodash", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "lodash")
	rr = httptest.NewRecorder()
	h.HandlePackageDetail(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("vuln error status = %d, want 500", rr.Code)
	}

	h = newTestHandler(&stubStore{malErr: errors.New("db down")})
	req = httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/lodash", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "lodash")
	rr = httptest.NewRecorder()
	h.HandlePackageDetail(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("malicious error status = %d, want 500", rr.Code)
	}

	h = newTestHandler(&stubStore{})
	req = httptest.NewRequest(http.MethodGet, "/api/v1/packages/notvalid/lodash", nil)
	req.SetPathValue("ecosystem", "notvalid")
	req.SetPathValue("rest", "lodash")
	rr = httptest.NewRecorder()
	h.HandlePackageDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid ecosystem status = %d, want 400: %s", rr.Code, rr.Body.String())
	}

	h = newTestHandler(&stubStore{})
	req = httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/lodash", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "lodash")
	rr = httptest.NewRecorder()
	h.HandlePackageDetail(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("not found status = %d, want 404", rr.Code)
	}
}

func TestHandlePackageRejectsUnsupportedMethodWithAllow(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/packages/npm/lodash", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "lodash")
	rr := httptest.NewRecorder()

	h.HandlePackage(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != "GET, HEAD, POST" {
		t.Fatalf("Allow = %q, want GET, HEAD, POST", got)
	}
}

func TestGETResourcesAllowHEADWithoutBody(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	t.Run("feed status", func(t *testing.T) {
		t.Parallel()

		store := &stubStore{feedStatusesErr: errors.New("HEAD should not list feed statuses")}
		h := newTestHandler(store)
		req := httptest.NewRequest(http.MethodHead, "/api/v1/feeds/status", nil)
		rr := httptest.NewRecorder()
		h.HandleFeedStatus(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("HEAD feed status = %d, want 200", rr.Code)
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("HEAD feed status wrote body %q", rr.Body.String())
		}
		if got := rr.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Fatalf("HEAD feed status Content-Type = %q", got)
		}
		if store.feedStatusListCalls != 0 {
			t.Fatalf("HEAD feed status listed feed rows %d times", store.feedStatusListCalls)
		}
	})

	t.Run("package detail", func(t *testing.T) {
		t.Parallel()

		store := &stubStore{
			vulnErr: errors.New("HEAD should not query vulnerabilities"),
			malErr:  errors.New("HEAD should not query malicious findings"),
		}
		h := newTestHandler(store)
		req := httptest.NewRequest(http.MethodHead, "/api/v1/packages/npm/lodash", nil)
		req.SetPathValue("ecosystem", "npm")
		req.SetPathValue("rest", "lodash")
		rr := httptest.NewRecorder()
		h.HandlePackageDetail(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("HEAD package detail = %d, want 200: %s", rr.Code, rr.Body.String())
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("HEAD package detail wrote body %q", rr.Body.String())
		}
		if got := rr.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Fatalf("HEAD package detail Content-Type = %q", got)
		}
		if store.findVulnerabilitiesCalls != 0 || store.findMaliciousCalls != 0 {
			t.Fatalf("HEAD package detail queried store: vulns=%d malicious=%d", store.findVulnerabilitiesCalls, store.findMaliciousCalls)
		}
	})

	t.Run("sync", func(t *testing.T) {
		t.Parallel()

		store := &syncExportStore{
			stubStore: stubStore{auditErr: errors.New("HEAD should not audit sync export")},
			export:    &db.SyncExport{SyncedAt: now},
			err:       errors.New("HEAD should not export sync data"),
		}
		h := newTestHandler(&store.stubStore)
		h.store = store
		req := httptest.NewRequest(http.MethodHead, "/api/v1/sync", nil)
		rr := httptest.NewRecorder()
		h.HandleSync(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("HEAD sync = %d, want 200: %s", rr.Code, rr.Body.String())
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("HEAD sync wrote body %q", rr.Body.String())
		}
		if got := rr.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Fatalf("HEAD sync Content-Type = %q", got)
		}
		if store.calls != 0 {
			t.Fatalf("HEAD sync exported data %d times", store.calls)
		}
		if len(store.auditEntries) != 0 {
			t.Fatalf("HEAD sync wrote audit entries: %+v", store.auditEntries)
		}
	})
}

func TestRefreshAndPackageDispatcherErrors(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{vulnFindings: []domain.Finding{{
		Name:       "github.com/acme/refresh",
		Version:    "1.0.0",
		Ecosystem:  domain.EcosystemGo,
		Type:       domain.FindingTypeVulnerability,
		Severity:   domain.SeverityHigh,
		AdvisoryID: "GHSA-refresh-name",
	}}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/go/github.com/acme/refresh", nil)
	req.SetPathValue("ecosystem", "go")
	req.SetPathValue("rest", "github.com/acme/refresh")
	rr := httptest.NewRecorder()
	h.HandlePackageDetail(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh-suffixed package detail status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var detail PackageDetailResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode package detail response: %v", err)
	}
	if detail.Ecosystem != "go" || detail.Name != "github.com/acme/refresh" || len(detail.Findings) != 1 {
		t.Fatalf("package detail = %+v, want go github.com/acme/refresh with one finding", detail)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/refresh", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "refresh")
	rr = httptest.NewRecorder()
	h.HandlePackageOrRefresh(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("non refresh dispatcher status = %d, want 405", rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("non refresh dispatcher Allow = %q, want GET, HEAD", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm//refresh", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "/refresh")
	rr = httptest.NewRecorder()
	h.HandlePackageOrRefresh(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty package refresh status = %d, want 400", rr.Code)
	}

	existingStore := &refreshStore{created: false, position: 4}
	h = newTestHandler(&existingStore.stubStore)
	h.store = existingStore
	h.ConfigureSocketRefresh(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.handleRefresh(rr, req, "npm", "lodash")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("existing refresh status = %d, want 202: %s", rr.Code, rr.Body.String())
	}
	var resp RefreshResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	if resp.New || resp.Position != 4 || !strings.Contains(resp.Message, "already queued") {
		t.Fatalf("existing refresh response = %+v", resp)
	}

	errorStore := &refreshStore{err: errors.New("queue down")}
	h = newTestHandler(&errorStore.stubStore)
	h.store = errorStore
	h.ConfigureSocketRefresh(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.handleRefresh(rr, req, "npm", "lodash")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("refresh enqueue error status = %d, want 500", rr.Code)
	}
}

type refreshStore struct {
	stubStore
	created  bool
	position int
	err      error
}

func (s *refreshStore) EnqueueRefresh(_ context.Context, job *db.RefreshJob) (bool, int, error) {
	if job != nil {
		s.enqueuedRefreshJobs = append(s.enqueuedRefreshJobs, *job)
	}
	if s.err != nil {
		return false, 0, s.err
	}
	return s.created, s.position, nil
}

func TestHandleSyncValidationAndOptions(t *testing.T) {
	t.Parallel()

	store := &syncExportStore{export: &db.SyncExport{SyncedAt: time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)}}
	h := newTestHandler(&store.stubStore)
	h.store = store
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync?since=2026-05-29T12:00:00Z&snapshot=2026-05-30T12:00:00Z&ecosystem=npm,go&limit=5000&offset=25", nil)
	rr := httptest.NewRecorder()
	h.HandleSync(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sync status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if store.opts.Since == nil || !store.opts.Since.Equal(time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("Since option = %v", store.opts.Since)
	}
	if store.opts.Limit != 5000 || store.opts.Offset != 25 {
		t.Fatalf("limit/offset = %d/%d, want 5000/25", store.opts.Limit, store.opts.Offset)
	}
	if len(store.opts.Ecosystems) != 2 || store.opts.Ecosystems[0] != "npm" || store.opts.Ecosystems[1] != "go" {
		t.Fatalf("ecosystems = %#v", store.opts.Ecosystems)
	}

	reputationCursor := testSyncCursorKey("npm", "left-pad", "1.0.0")
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sync?since_xid=500&snapshot_xid=700&vulnerabilities_offset=1000&malicious_offset=1&reputation_offset=2&lifecycle_offset=3&reputation_cursor="+reputationCursor+"&reputation_done=true", nil)
	rr = httptest.NewRecorder()
	h.HandleSync(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sync cursor status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if store.opts.Cursor.Vulnerabilities != 1000 || store.opts.Cursor.Malicious != 1 || store.opts.Cursor.Reputation != 2 || store.opts.Cursor.Lifecycle != 3 {
		t.Fatalf("sync cursor options = %+v", store.opts.Cursor)
	}
	if store.opts.SinceXID != 500 || store.opts.SnapshotXID != 700 || store.opts.Cursor.ReputationCursor != reputationCursor || !store.opts.Cursor.ReputationDone {
		t.Fatalf("sync xid/keyset cursor options = since_xid %d snapshot_xid %d cursor %+v", store.opts.SinceXID, store.opts.SnapshotXID, store.opts.Cursor)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil)
	rr = httptest.NewRecorder()
	h.HandleSync(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sync default snapshot status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if !store.opts.SnapshotAt.IsZero() {
		t.Fatalf("default SnapshotAt = %v, want zero so store uses database clock", store.opts.SnapshotAt)
	}

	errorCases := []string{
		"/api/v1/sync?since=bad",
		"/api/v1/sync?snapshot=bad",
		"/api/v1/sync?since_xid=bad",
		"/api/v1/sync?snapshot_xid=bad",
		"/api/v1/sync?limit=0",
		"/api/v1/sync?limit=abc",
		"/api/v1/sync?limit=" + strconv.Itoa(synccontract.MaxLimit+1),
		"/api/v1/sync?offset=-1",
		"/api/v1/sync?offset=abc",
		"/api/v1/sync?offset=10001",
		"/api/v1/sync?ecosystem=npmm",
		"/api/v1/sync?vulnerabilities_offset=-1",
		"/api/v1/sync?vulnerabilities_offset=10001",
		"/api/v1/sync?malicious_offset=abc",
	}
	for _, target := range errorCases {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rr := httptest.NewRecorder()
		h.HandleSync(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", target, rr.Code)
		}
	}

	store.err = errors.New("export failed")
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil)
	rr = httptest.NewRecorder()
	h.HandleSync(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("export error status = %d, want 500", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/sync", nil)
	rr = httptest.NewRecorder()
	h.HandleSync(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("sync POST status = %d, want 405", rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q, want GET, HEAD", got)
	}
}

func TestHandleSyncRejectsXIDsAbovePostgresBigint(t *testing.T) {
	t.Parallel()

	store := &syncExportStore{export: &db.SyncExport{SyncedAt: time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)}}
	h := newTestHandler(&store.stubStore)
	h.store = store

	for _, target := range []string{
		"/api/v1/sync?since_xid=9223372036854775808",
		"/api/v1/sync?snapshot_xid=9223372036854775808",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rr := httptest.NewRecorder()

		h.HandleSync(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", target, rr.Code)
		}
	}
}

func TestHandleSyncRejectsMalformedKeysetCursorsBeforeStore(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"/api/v1/sync?vulnerabilities_cursor=not-base64",
		"/api/v1/sync?malicious_cursor=W10",
		"/api/v1/sync?reputation_cursor=eyJub3QiOiJhcnJheSJ9",
		"/api/v1/sync?lifecycle_cursor=WyJnb3JtIiwiZ28iLCIxLjIzIl0",
	} {
		target := target
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			store := &syncExportStore{export: &db.SyncExport{SyncedAt: time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)}}
			h := newTestHandler(&store.stubStore)
			h.store = store
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rr := httptest.NewRecorder()

			h.HandleSync(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			var body errorJSON
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("error response body is not JSON: %v; body=%q", err, rr.Body.String())
			}
			if body.Code != "invalid_request" || !strings.Contains(body.Error, "cursor") {
				t.Fatalf("error body = %+v, want invalid_request cursor validation error", body)
			}
			if store.calls != 0 {
				t.Fatalf("ExportSync calls = %d, want 0 for malformed cursor", store.calls)
			}
		})
	}
}

func TestHandleSyncWritesAttributedAccessAudit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	store := &syncExportStore{export: &db.SyncExport{SyncedAt: now}}
	h := newTestHandler(&store.stubStore)
	h.store = store
	auditCursor := testSyncCursorKey("npm", "secret-package-name", "1.0.0")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync?since=2026-05-29T12:00:00Z&since_xid=500&snapshot=2026-05-30T12:00:00Z&snapshot_xid=700&ecosystem=npm,go&limit=250&offset=25&vulnerabilities_offset=1000&malicious_offset=1&reputation_cursor="+auditCursor+"&reputation_done=true", nil)
	req.RemoteAddr = "203.0.113.77:49152"
	req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), "corr-sync-audit"))
	req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(req.Context(), requestctx.APIKeyIdentity{
		ID:   42,
		Name: "ci-sync",
	}))
	rr := httptest.NewRecorder()

	h.HandleSync(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("sync status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.auditEntries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(store.auditEntries))
	}
	entry := store.auditEntries[0]
	if entry.Action != "sync_export" {
		t.Fatalf("audit action = %q, want sync_export", entry.Action)
	}
	if entry.IP != "203.0.113.77" {
		t.Fatalf("audit IP = %q, want trusted client IP", entry.IP)
	}
	if strings.Contains(string(entry.Details), auditCursor) {
		t.Fatalf("audit details logged raw cursor containing package data: %s", entry.Details)
	}
	var details map[string]any
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("decode audit details: %v", err)
	}
	want := map[string]any{
		"method":                     http.MethodGet,
		"since":                      "2026-05-29T12:00:00Z",
		"since_xid":                  float64(500),
		"snapshot":                   "2026-05-30T12:00:00Z",
		"snapshot_xid":               float64(700),
		"limit":                      float64(250),
		"offset":                     float64(25),
		"vulnerabilities_offset":     float64(1000),
		"malicious_offset":           float64(1),
		"reputation_cursor_provided": true,
		"reputation_done":            true,
		"correlation_id":             "corr-sync-audit",
		"api_key_id":                 float64(42),
		"api_key_name":               "ci-sync",
	}
	for key, wantValue := range want {
		if got := details[key]; got != wantValue {
			t.Fatalf("audit detail %s = %#v, want %#v (all details: %#v)", key, got, wantValue, details)
		}
	}
	ecosystems, ok := details["ecosystems"].([]any)
	if !ok || len(ecosystems) != 2 || ecosystems[0] != "npm" || ecosystems[1] != "go" {
		t.Fatalf("audit ecosystems = %#v, want [npm go]", details["ecosystems"])
	}
	if _, ok := details["client_ip"]; ok {
		t.Fatalf("audit details duplicated client_ip despite typed IP column: %#v", details)
	}
}

func TestHandleSyncAuditsAttemptBeforeExportFailure(t *testing.T) {
	t.Parallel()

	store := &syncExportStore{err: errors.New("export unavailable")}
	h := newTestHandler(&store.stubStore)
	h.store = store
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync?limit=10", nil)
	req.RemoteAddr = "198.51.100.44:49152"
	req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), "corr-sync-fail"))
	rr := httptest.NewRecorder()

	h.HandleSync(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("sync status = %d, want 500", rr.Code)
	}
	if len(store.auditEntries) != 1 {
		t.Fatalf("audit entries = %d, want attempted sync export audit", len(store.auditEntries))
	}
	if store.auditEntries[0].Action != "sync_export" || store.auditEntries[0].IP != "198.51.100.44" {
		t.Fatalf("audit entry = %+v, want sync_export from trusted IP", store.auditEntries[0])
	}
}

func TestAPIHelperBranches(t *testing.T) {
	t.Parallel()

	if got := splitCSV(" npm, ,go ,, "); len(got) != 2 || got[0] != "npm" || got[1] != "go" {
		t.Fatalf("splitCSV() = %#v", got)
	}
	if got, err := parseSyncEcosystems(" NPM,go "); err != nil || len(got) != 2 || got[0] != "npm" || got[1] != "go" {
		t.Fatalf("parseSyncEcosystems() = %#v, %v", got, err)
	}
	if _, err := parseSyncEcosystems("npmm"); err == nil {
		t.Fatal("parseSyncEcosystems(invalid) error = nil, want error")
	}
	if got := splitCSV("   "); got != nil {
		t.Fatalf("splitCSV(empty) = %#v, want nil", got)
	}
	if _, err := parseRFC3339Timestamp("not a timestamp"); err == nil {
		t.Fatal("parseRFC3339Timestamp(invalid) error = nil")
	}
	if ts, err := parseRFC3339Timestamp("2026-05-30T12:00:00.123456789Z"); err != nil || ts.Nanosecond() != 123456789 {
		t.Fatalf("parseRFC3339Timestamp(nano) = %v, %v", ts, err)
	}
	if len(generateID()) != 16 {
		t.Fatal("generateID should return 16 hex chars")
	}

	h := newTestHandler(&stubStore{feedStatusesErr: errors.New("db down")})
	status, versions := h.feedState(context.Background(), "")
	if status != "degraded" || len(versions) != 0 {
		t.Fatalf("feedState(error) = %q %#v, want degraded empty versions", status, versions)
	}
	if got := overallFeedStatus([]db.FeedSyncStatus{{FeedName: "vulncheck", LastSyncStatus: "disabled"}}); got != "degraded" {
		t.Fatalf("overallFeedStatus(disabled only) = %q, want degraded", got)
	}

	importHandler := NewFeedImportHandler(&stubStore{}, nil)
	if _, err := importHandler.importVulnerabilities(context.Background(), "osv", &vulnerabilityImportRequest{
		Vulnerabilities: []vulnerabilityImportItem{{}},
	}, nil); err == nil {
		t.Fatal("importVulnerabilities without id error = nil")
	}
	if err := normalizeImportedMalicious("openssf", &db.MaliciousFinding{}); err == nil {
		t.Fatal("normalizeImportedMalicious without id error = nil")
	}

	var decoded struct {
		Name string `json:"name"`
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok"} trailing`))
	if err := readJSONWithLimit(req, &decoded, 1024); err == nil {
		t.Fatal("readJSONWithLimit trailing data error = nil")
	}
	for _, body := range []string{
		`{"name":"ok"}{"name":"second"}`,
		`{"name":"ok"}]`,
		`{"name":"ok"}}`,
	} {
		t.Run("trailing "+body, func(t *testing.T) {
			var target struct {
				Name string `json:"name"`
			}
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			err := readJSONWithLimit(req, &target, 1024)
			if err == nil || !strings.Contains(err.Error(), "unexpected trailing data") {
				t.Fatalf("readJSONWithLimit(%q) error = %v, want trailing data error", body, err)
			}
		})
	}
	for _, tc := range []struct {
		name      string
		body      string
		want      string
		forbidden []string
	}{
		{
			name:      "empty body",
			body:      "",
			want:      "empty JSON body",
			forbidden: []string{"EOF"},
		},
		{
			name:      "malformed JSON",
			body:      `{"name":@}`,
			want:      "malformed JSON body",
			forbidden: []string{"invalid character", "@"},
		},
		{
			name:      "unexpected EOF",
			body:      `{"name":"attacker-controlled-value`,
			want:      "malformed JSON body",
			forbidden: []string{"unexpected EOF", "attacker-controlled-value"},
		},
		{
			name:      "invalid field type",
			body:      `{"name":{"secret":"attacker-controlled-value"}}`,
			want:      "json body has invalid field type",
			forbidden: []string{"cannot unmarshal", "attacker-controlled-value"},
		},
	} {
		t.Run("sanitized "+tc.name, func(t *testing.T) {
			var target struct {
				Name string `json:"name"`
			}
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			err := readJSONWithLimit(req, &target, 1024)
			if err == nil {
				t.Fatalf("readJSONWithLimit(%s) error = nil", tc.name)
			}
			got := err.Error()
			if got != tc.want {
				t.Fatalf("readJSONWithLimit(%s) error = %q, want %q", tc.name, got, tc.want)
			}
			if len(got) > 120 {
				t.Fatalf("readJSONWithLimit(%s) error = %q, want bounded sanitized error", tc.name, got)
			}
			for _, forbidden := range tc.forbidden {
				if strings.Contains(got, forbidden) {
					t.Fatalf("readJSONWithLimit(%s) error = %q, contains raw decoder text %q", tc.name, got, forbidden)
				}
			}
		})
	}
	longField := strings.Repeat("secret-field-name-", 200)
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"`+longField+`":"value"}`))
	if err := readJSONWithLimit(req, &decoded, 1024*1024); err == nil {
		t.Fatal("readJSONWithLimit unknown field error = nil")
	} else if strings.Contains(err.Error(), longField) || len(err.Error()) > 120 || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("readJSONWithLimit unknown field error = %q, want bounded sanitized unknown-field error", err.Error())
	}
	var huge struct {
		Name string `json:"name"`
	}
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"toolong"}`))
	if err := readJSONWithLimit(req, &huge, 4); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readJSONWithLimit small limit error = %v", err)
	}
}

func TestValidateCheckPackagesNormalizesCaseInsensitiveNames(t *testing.T) {
	t.Parallel()

	packages := []domain.Package{
		{Name: " My.Pkg_Name ", Version: " 1.0.0 ", Ecosystem: domain.EcosystemPyPI},
		{Name: " Newtonsoft.Json ", Version: " 13.0.3 ", Ecosystem: domain.Ecosystem("NuGet")},
		{Name: " @Scope/Name ", Version: " 2.0.0 ", Ecosystem: domain.EcosystemNPM},
	}

	if err := validateCheckPackages(packages); err != nil {
		t.Fatalf("validateCheckPackages() error = %v", err)
	}
	if got := packages[0].Name; got != "my-pkg-name" {
		t.Fatalf("pypi package name = %q, want PEP 503 normalized name", got)
	}
	if got := packages[1].Name; got != "newtonsoft.json" {
		t.Fatalf("nuget package name = %q, want lowercase name", got)
	}
	if got := packages[2].Name; got != "@Scope/Name" {
		t.Fatalf("npm package name = %q, want case preserved", got)
	}
}

func TestWriteJSONWithBrokenEncoderReturnsServerError(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]any{"bad": func() {}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 after encode error", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want application/json; charset=utf-8", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
	var envelope errorJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("body is not valid JSON after unsupported value: %v; body=%s", err, rec.Body.String())
	}
	if envelope.Error != "internal server error" {
		t.Fatalf("error = %q, want internal server error", envelope.Error)
	}
}

func TestWriteJSONForRequestLogsEncodeFailureThroughRequestLogger(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/feeds/status", nil)
	const correlationID = "123e4567-e89b-42d3-a456-426614174000"
	req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), correlationID))
	req = requestWithLogger(req, logger)

	rec := httptest.NewRecorder()
	writeJSONForRequest(rec, req, http.StatusOK, map[string]any{"bad": func() {}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 after encode error", rec.Code)
	}
	logged := logs.String()
	for _, want := range []string{
		"failed to encode JSON response",
		`"correlation_id":"` + correlationID + `"`,
		`"path":"/api/v1/feeds/status"`,
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("request logger output missing %q: %s", want, logged)
		}
	}
}

func TestWriteStreamingJSONForRequestWritesHeadersAndHandlesHEAD(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil)
	rec := httptest.NewRecorder()
	writeStreamingJSONForRequest(rec, req, http.StatusAccepted, map[string]string{"summary": "<ok>&"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want application/json; charset=utf-8", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
	if body := rec.Body.String(); !strings.Contains(body, `\u003cok\u003e\u0026`) {
		t.Fatalf("streamed body = %q, want HTML-sensitive bytes escaped", body)
	}

	req = httptest.NewRequest(http.MethodHead, "/api/v1/sync", nil)
	rec = httptest.NewRecorder()
	writeStreamingJSONForRequest(rec, req, http.StatusNoContent, map[string]string{"summary": "ok"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("HEAD status = %d, want 204", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD body length = %d, want 0", rec.Body.Len())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("HEAD Content-Type = %q, want application/json; charset=utf-8", got)
	}
}

func assertSingleRejectedFeedStatus(t *testing.T, statuses []db.FeedSyncStatus, feed string) {
	t.Helper()

	if len(statuses) != 1 {
		t.Fatalf("feed statuses = %+v, want exactly one rejected status", statuses)
	}
	status := statuses[0]
	if status.FeedName != feed || status.LastSyncStatus != "rejected" || status.EntriesSynced != 0 {
		t.Fatalf("rejected feed status = %+v, want feed %q with zero synced entries", status, feed)
	}
	if status.LastSyncAt != nil {
		t.Fatalf("rejected LastSyncAt = %v, want nil", status.LastSyncAt)
	}
	if strings.TrimSpace(status.LastError) == "" {
		t.Fatalf("rejected LastError is empty: %+v", status)
	}
	if len(status.Metadata) == 0 {
		t.Fatalf("rejected Metadata is empty: %+v", status)
	}
}
