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

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

func TestNewHandlerWithConfigAndThresholdFallbacks(t *testing.T) {
	t.Parallel()

	h := NewHandlerWithConfig(&stubStore{}, nil, &config.Config{
		Server: config.ServerConfig{BlockThreshold: "medium"},
		Feeds: config.FeedsConfig{
			ReversingLabsEnabled: true,
			ReversingLabsMode:    config.FeedModeSelf,
		},
	})
	if h.blockThreshold != domain.SeverityMedium {
		t.Fatalf("blockThreshold = %q, want MEDIUM", h.blockThreshold)
	}
	if !h.reversingLabsEnabled.Load() {
		t.Fatal("ReversingLabs should be enabled from config")
	}

	h = NewHandlerWithConfig(&stubStore{}, nil, &config.Config{
		Server: config.ServerConfig{BlockThreshold: "nonsense"},
		Feeds: config.FeedsConfig{
			ReversingLabsEnabled: true,
			ReversingLabsMode:    config.FeedModeExternal,
		},
	})
	if h.blockThreshold != defaultBlockThreshold {
		t.Fatalf("invalid threshold fallback = %q, want %q", h.blockThreshold, defaultBlockThreshold)
	}
	if h.reversingLabsEnabled.Load() {
		t.Fatal("ReversingLabs external mode should not enable API scheduling")
	}

	if h := NewHandlerWithConfig(&stubStore{}, nil, nil); h.blockThreshold != defaultBlockThreshold {
		t.Fatalf("nil config threshold = %q, want default", h.blockThreshold)
	}

	h = NewHandlerWithBlockThreshold(&stubStore{}, nil, domain.Severity("BOGUS"))
	if h.blockThreshold != defaultBlockThreshold {
		t.Fatalf("invalid explicit threshold = %q, want %q", h.blockThreshold, defaultBlockThreshold)
	}

	var nilHandler *Handler
	nilHandler.ConfigureReversingLabs(config.FeedsConfig{ReversingLabsEnabled: true, ReversingLabsMode: config.FeedModeSelf})
}

func TestHandleFeedImportValidationAndDeleteBranches(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(`{"vulnerabilities":[{}]}`))
	req.SetPathValue("feed", "osv")
	rr := httptest.NewRecorder()
	h.HandleFeedImport(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("missing vulnerability id status = %d, want 500", rr.Code)
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
	if len(store.deletedMaliciousIDs) != 1 || store.deletedMaliciousIDs[0] != "SOCK-old" {
		t.Fatalf("deleted malicious IDs = %#v", store.deletedMaliciousIDs)
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
	req = httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/lodash", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "lodash")
	rr = httptest.NewRecorder()
	h.HandlePackageDetail(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("not found status = %d, want 404", rr.Code)
	}
}

func TestRefreshAndPackageDispatcherErrors(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/lodash/refresh", nil)
	rr := httptest.NewRecorder()
	h.HandleRefresh(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("refresh GET status = %d, want 405", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/refresh", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "refresh")
	rr = httptest.NewRecorder()
	h.HandlePackageOrRefresh(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("non refresh dispatcher status = %d, want 405", rr.Code)
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

	errorCases := []string{
		"/api/v1/sync?since=bad",
		"/api/v1/sync?snapshot=bad",
		"/api/v1/sync?limit=0",
		"/api/v1/sync?limit=abc",
		"/api/v1/sync?offset=-1",
		"/api/v1/sync?offset=abc",
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
	if got := packageCoverageKey(" NuGet ", "Newtonsoft.Json", " 13.0.3 "); got.ecosystem != "nuget" || got.name != "newtonsoft.json" || got.version != "13.0.3" {
		t.Fatalf("packageCoverageKey() = %+v, want normalized NuGet key", got)
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

	h = newTestHandler(&stubStore{})
	if _, err := h.importVulnerabilities(context.Background(), "osv", &vulnerabilityImportRequest{
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
	var huge struct {
		Name string `json:"name"`
	}
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"toolong"}`))
	if err := readJSONWithLimit(req, &huge, 4); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readJSONWithLimit small limit error = %v", err)
	}
}

func TestWriteJSONWithBrokenEncoderDoesNotPanic(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]any{"bad": func() {}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even after encode error", rec.Code)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err == nil {
		t.Fatalf("body unexpectedly valid JSON after unsupported value: %s", rec.Body.String())
	}
}
