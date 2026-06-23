package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

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

func TestHandleFeedImportValidationAndDeleteBranches(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(`{"vulnerabilities":[{}]}`))
	req.SetPathValue("feed", "osv")
	rr := httptest.NewRecorder()
	h.HandleFeedImport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing vulnerability id status = %d, want 400", rr.Code)
	}

	store := &stubStore{}
	h = newTestHandler(store)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(`{
		"malicious":[{"id":"SOCK-1","ecosystem":"npm","name":"evil","severity":"HIGH"}],
		"delete_malicious_ids":["", "SOCK-old"],
		"status":{"entries_synced":5,"entries_total":9}
	}`))
	req.SetPathValue("feed", "socket")
	rr = httptest.NewRecorder()
	h.HandleFeedImport(rr, req)
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
	rr = httptest.NewRecorder()
	h.HandleFeedImport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON status = %d, want 400", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds//import", strings.NewReader(`{}`))
	req.SetPathValue("feed", "")
	rr = httptest.NewRecorder()
	h.HandleFeedImport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty feed status = %d, want 400", rr.Code)
	}

	for _, feed := range []string{"vulncheck", "cisakev", "epss"} {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+feed+"/import", strings.NewReader(`{`))
		req.SetPathValue("feed", feed)
		rr = httptest.NewRecorder()
		h.HandleFeedImport(rr, req)
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
			h := newTestHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", tt.feed)
			rr := httptest.NewRecorder()

			h.HandleFeedImport(rr, req)

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
			h := newTestHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", "osv")
			rr := httptest.NewRecorder()

			h.HandleFeedImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.upsertedVulns) != 0 || len(store.upsertedStatuses) != 0 {
				t.Fatalf("store mutated on invalid vulnerability import: vulns=%+v statuses=%+v", store.upsertedVulns, store.upsertedStatuses)
			}
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
			h := newTestHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", "osv")
			rr := httptest.NewRecorder()

			h.HandleFeedImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.upsertedVulns) != 0 || len(store.upsertedStatuses) != 0 {
				t.Fatalf("store mutated on invalid version data: vulns=%+v statuses=%+v", store.upsertedVulns, store.upsertedStatuses)
			}
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
			h := newTestHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", "socket")
			rr := httptest.NewRecorder()

			h.HandleFeedImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.upsertedMalicious) != 0 || len(store.upsertedStatuses) != 0 {
				t.Fatalf("store mutated on invalid malicious import: malicious=%+v statuses=%+v", store.upsertedMalicious, store.upsertedStatuses)
			}
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
			h := newTestHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", tt.feed)
			rr := httptest.NewRecorder()

			h.HandleFeedImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			for _, want := range tt.want {
				if !strings.Contains(rr.Body.String(), want) {
					t.Fatalf("response missing %q: %s", want, rr.Body.String())
				}
			}
			if len(store.upsertedVulns) != 0 || len(store.upsertedMalicious) != 0 || len(store.upsertedStatuses) != 0 {
				t.Fatalf("store mutated on invalid import: vulns=%+v malicious=%+v statuses=%+v", store.upsertedVulns, store.upsertedMalicious, store.upsertedStatuses)
			}
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
			h := newTestHandler(store)
			h.ConfigureFeedImportSecret("import-secret", true)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(body))
			req.SetPathValue("feed", "socket")
			if tt.secret != "" {
				req.Header.Set(HeaderFeedImportSecret, tt.secret)
			}
			rr := httptest.NewRecorder()

			h.HandleFeedImport(rr, req)

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

func TestHandleFeedImportValidatesBeforeMutatingState(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(`{
		"vulnerabilities":[
			{"id":"GHSA-valid","summary":"would be persisted by the old loop"},
			{"id":"manual:owned","summary":"reserved namespace"}
		]
	}`))
	req.SetPathValue("feed", "osv")
	rr := httptest.NewRecorder()

	h.HandleFeedImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("mixed valid/manual import status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedVulns) != 0 || len(store.upsertedStatuses) != 0 {
		t.Fatalf("store mutated before full validation: vulns=%+v statuses=%+v", store.upsertedVulns, store.upsertedStatuses)
	}

	store = &stubStore{}
	h = newTestHandler(store)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(`{
		"malicious":[{"id":"MAL-valid","ecosystem":"npm","name":"evil"}],
		"status":{"last_sync_status":"totally-fine"}
	}`))
	req.SetPathValue("feed", "socket")
	rr = httptest.NewRecorder()

	h.HandleFeedImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown status import status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedMalicious) != 0 || len(store.upsertedStatuses) != 0 {
		t.Fatalf("store mutated before status validation: malicious=%+v statuses=%+v", store.upsertedMalicious, store.upsertedStatuses)
	}

	for _, status := range []string{
		`{"entries_synced":-1}`,
		`{"entries_total":-1}`,
		`{"last_sync_duration_ms":-1}`,
		`{"entries_synced":5,"entries_total":3}`,
	} {
		store = &stubStore{}
		h = newTestHandler(store)
		req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(`{
			"malicious":[{"id":"MAL-valid","ecosystem":"npm","name":"evil"}],
			"status":`+status+`
		}`))
		req.SetPathValue("feed", "socket")
		rr = httptest.NewRecorder()

		h.HandleFeedImport(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid status %s response = %d, want 400: %s", status, rr.Code, rr.Body.String())
		}
		if len(store.upsertedMalicious) != 0 || len(store.upsertedStatuses) != 0 {
			t.Fatalf("store mutated before numeric status validation: malicious=%+v statuses=%+v", store.upsertedMalicious, store.upsertedStatuses)
		}
	}
}

func TestHandleFeedImportBoundsPersistedStatusFields(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
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
	rr := httptest.NewRecorder()

	h.HandleFeedImport(rr, req)

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
	if got := len(store.upsertedStatuses[0].LastEtag); got != 512 {
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
	h := newTestHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(string(body)))
	req.SetPathValue("feed", "socket")
	rr := httptest.NewRecorder()

	h.HandleFeedImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("oversized metadata status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedMalicious) != 0 || len(store.upsertedStatuses) != 0 {
		t.Fatalf("store mutated for oversized metadata: malicious=%+v statuses=%+v", store.upsertedMalicious, store.upsertedStatuses)
	}
}

func TestHandleFeedImportRejectsEmptyCISAKEVClear(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/cisakev/import", strings.NewReader(`{"cve_ids":[],"clear_missing":true}`))
	req.SetPathValue("feed", "cisakev")
	rr := httptest.NewRecorder()

	h.HandleFeedImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(store.cisaKEVIDs) != 0 || len(store.clearedCISAKEVIDs) != 0 || len(store.upsertedStatuses) != 0 {
		t.Fatalf("store mutated for empty CISA KEV clear: set=%+v clear=%+v statuses=%+v",
			store.cisaKEVIDs,
			store.clearedCISAKEVIDs,
			store.upsertedStatuses,
		)
	}
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

func (s *importErrorStore) ReplaceEPSSScores(context.Context, []db.EPSSEntry) (int, int, error) {
	return 0, 0, s.epssErr
}

func (s *importErrorStore) UpsertFeedSyncStatus(context.Context, *db.FeedSyncStatus) error {
	return s.statusErr
}

func TestImportHelperStoreErrorBranches(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	status := &feedSyncStatusInput{LastSyncAt: &now, LastSyncStatus: "success", EntriesSynced: 1, EntriesTotal: 1}

	store := &importErrorStore{vulnCheckErr: errors.New("vulncheck down")}
	h := NewFeedImportHandler(store, nil)
	if _, err := h.importVulnCheck(ctx, "vulncheck", &vulnCheckImportRequest{Entries: []db.VulnCheckEntry{{CVEID: "CVE-2026-0001"}}}); err == nil {
		t.Fatal("importVulnCheck(store error) = nil")
	}

	store = &importErrorStore{cisaErr: errors.New("kev down")}
	h = NewFeedImportHandler(store, nil)
	if _, err := h.importCISAKEV(ctx, "cisakev", &cisaKEVImportRequest{CVEIDs: []string{"CVE-2026-0001"}}); err == nil {
		t.Fatal("importCISAKEV(set error) = nil")
	}

	store = &importErrorStore{cisaClearErr: errors.New("clear down")}
	h = NewFeedImportHandler(store, nil)
	if _, err := h.importCISAKEV(ctx, "cisakev", &cisaKEVImportRequest{CVEIDs: []string{"CVE-2026-0001"}, ClearMissing: true}); err == nil {
		t.Fatal("importCISAKEV(clear error) = nil")
	}

	store = &importErrorStore{epssErr: errors.New("epss down")}
	h = NewFeedImportHandler(store, nil)
	if _, err := h.importEPSS(ctx, "epss", &epssImportRequest{Entries: []db.EPSSEntry{{CVEID: "CVE-2026-0001", Score: 0.5}}}); err == nil {
		t.Fatal("importEPSS(store error) = nil")
	}

	store = &importErrorStore{statusErr: errors.New("status down")}
	h = NewFeedImportHandler(store, nil)
	if _, err := h.importVulnCheck(ctx, "vulncheck", &vulnCheckImportRequest{Entries: []db.VulnCheckEntry{{CVEID: "CVE-2026-0001"}}, Status: status}); err == nil {
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

func TestGETResourcesAllowHEADWithoutBody(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	t.Run("feed status", func(t *testing.T) {
		t.Parallel()

		h := newTestHandler(&stubStore{feedStatuses: []db.FeedSyncStatus{{
			FeedName:       "osv",
			LastSyncStatus: "success",
			LastSyncAt:     &now,
			EntriesTotal:   1,
		}}})
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
	})

	t.Run("package detail", func(t *testing.T) {
		t.Parallel()

		h := newTestHandler(&stubStore{vulnFindings: []domain.Finding{{
			Name:       "lodash",
			Version:    "4.17.15",
			Ecosystem:  domain.EcosystemNPM,
			Type:       domain.FindingTypeVulnerability,
			Severity:   domain.SeverityHigh,
			AdvisoryID: "GHSA-head",
		}}})
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
	})

	t.Run("sync", func(t *testing.T) {
		t.Parallel()

		store := &syncExportStore{export: &db.SyncExport{SyncedAt: now}}
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
	})
}

func TestRefreshAndPackageDispatcherErrors(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/lodash/refresh", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "lodash/refresh")
	rr := httptest.NewRecorder()
	h.HandlePackageDetail(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("refresh GET package-detail status = %d, want 405", rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("refresh GET Allow = %q, want POST", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/refresh", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "refresh")
	rr = httptest.NewRecorder()
	h.HandlePackageOrRefresh(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("non refresh dispatcher status = %d, want 405", rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("non refresh dispatcher Allow = %q, want GET", got)
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
	h.ConfigureReversingLabs(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", strings.NewReader(`{}`))
	rr = httptest.NewRecorder()
	h.handleRefresh(rr, req, "npm", "lodash")
	if rr.Code != http.StatusOK {
		t.Fatalf("existing refresh status = %d, want 200: %s", rr.Code, rr.Body.String())
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
	h.ConfigureReversingLabs(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", strings.NewReader(`{}`))
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

	h := newTestHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil)
	rr := httptest.NewRecorder()
	h.HandleSync(rr, req)
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("non exporter status = %d, want 501", rr.Code)
	}

	store := &syncExportStore{export: &db.SyncExport{SyncedAt: time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)}}
	h = newTestHandler(&store.stubStore)
	h.store = store
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sync?since=2026-05-29T12:00:00Z&snapshot=2026-05-30T12:00:00Z&ecosystem=npm,go&limit=50000&offset=25", nil)
	rr = httptest.NewRecorder()
	h.HandleSync(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sync status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if store.opts.Since == nil || !store.opts.Since.Equal(time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("Since option = %v", store.opts.Since)
	}
	if store.opts.Limit != syncMaxLimit || store.opts.Offset != 25 {
		t.Fatalf("limit/offset = %d/%d, want capped %d/25", store.opts.Limit, store.opts.Offset, syncMaxLimit)
	}
	if len(store.opts.Ecosystems) != 2 || store.opts.Ecosystems[0] != "npm" || store.opts.Ecosystems[1] != "go" {
		t.Fatalf("ecosystems = %#v", store.opts.Ecosystems)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sync?since_xid=500&snapshot_xid=700&vulnerabilities_offset=1000&malicious_offset=1&reputation_offset=2&lifecycle_offset=3&reputation_cursor=after-rep&reputation_done=true", nil)
	rr = httptest.NewRecorder()
	h.HandleSync(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sync cursor status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if store.opts.Cursor.Vulnerabilities != 1000 || store.opts.Cursor.Malicious != 1 || store.opts.Cursor.Reputation != 2 || store.opts.Cursor.Lifecycle != 3 {
		t.Fatalf("sync cursor options = %+v", store.opts.Cursor)
	}
	if store.opts.SinceXID != 500 || store.opts.SnapshotXID != 700 || store.opts.Cursor.ReputationCursor != "after-rep" || !store.opts.Cursor.ReputationDone {
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
		"/api/v1/sync?offset=-1",
		"/api/v1/sync?offset=abc",
		"/api/v1/sync?offset=1000001",
		"/api/v1/sync?ecosystem=npmm",
		"/api/v1/sync?vulnerabilities_offset=-1",
		"/api/v1/sync?vulnerabilities_offset=1000001",
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
	if !feedHasFreshEntries(db.FeedSyncStatus{LastSyncStatus: "running", LastSyncAt: ptrFeedTime(time.Now().UTC()), EntriesTotal: 1}) {
		t.Fatal("running feed with cached entries should count as fresh")
	}
	if feedHasFreshEntries(db.FeedSyncStatus{LastSyncStatus: "running"}) {
		t.Fatal("running feed without entries should not count as fresh")
	}
	if len(generateID()) != 16 {
		t.Fatal("generateID should return 16 hex chars")
	}

	h := newTestHandler(&stubStore{feedStatusesErr: errors.New("db down")})
	status, versions := h.feedState(context.Background())
	if status != "degraded" || len(versions) != 0 {
		t.Fatalf("feedState(error) = %q %#v, want degraded empty versions", status, versions)
	}
	if got := overallFeedStatus([]db.FeedSyncStatus{{FeedName: "vulncheck", LastSyncStatus: "disabled"}}); got != "degraded" {
		t.Fatalf("overallFeedStatus(disabled only) = %q, want degraded", got)
	}

	importHandler := NewFeedImportHandler(&stubStore{}, nil)
	if _, err := importHandler.importVulnerabilities(context.Background(), "osv", &vulnerabilityImportRequest{
		Vulnerabilities: []db.Vulnerability{{}},
	}); err == nil {
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
	var envelope errorJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("body is not valid JSON after unsupported value: %v; body=%s", err, rec.Body.String())
	}
	if envelope.Error != "internal server error" {
		t.Fatalf("error = %q, want internal server error", envelope.Error)
	}
}
