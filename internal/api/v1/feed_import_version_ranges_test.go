package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleFeedImportVersionRangesMatchStoreRule drives the handler-side
// version_ranges check with the inputs the store pre-check and the database
// CHECK constraint (migration 050) disagree on most easily: exact key names,
// null/non-string/blank boundaries and missing events. A rejected range must
// produce a field-specific 400 from the handler, never reach the store (where
// it would only get the generic store-rejection message).
func TestHandleFeedImportVersionRangesMatchStoreRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ranges     string
		wantDetail string // empty: the range is valid and the import succeeds
	}{
		{name: "empty array", ranges: `[]`},
		{name: "osv single-key events", ranges: `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`},
		{name: "ghsa blank sibling keys", ranges: `[{"type":"ECOSYSTEM","events":[{"introduced":"0","fixed":"","last_affected":""}]}]`},
		{name: "null sibling key", ranges: `[{"events":[{"introduced":"0","fixed":null}]}]`},
		{name: "limit only", ranges: `[{"events":[{"limit":"*"}]}]`},
		{name: "extra keys", ranges: `[{"type":"GIT","repo":"https://example.invalid","events":[{"introduced":"abc","note":1}]}]`},
		{name: "case-variant boundary key", ranges: `[{"events":[{"Introduced":"0"}]}]`, wantDetail: "version_ranges[0].events[0] must set introduced, fixed, last_affected, or limit"},
		{name: "case-variant events key", ranges: `[{"Events":[{"introduced":"0"}]}]`, wantDetail: "version_ranges[0].events must not be empty"},
		{name: "range without events", ranges: `[{}]`, wantDetail: "version_ranges[0].events must not be empty"},
		{name: "null range", ranges: `[null]`, wantDetail: "version_ranges[0] must be a range object"},
		{name: "object events", ranges: `[{"events":{}}]`, wantDetail: "version_ranges[0].events must be an array of event objects"},
		{name: "null event", ranges: `[{"events":[null]}]`, wantDetail: "version_ranges[0].events[0] must be an event object"},
		{name: "null boundary", ranges: `[{"events":[{"introduced":null}]}]`, wantDetail: "version_ranges[0].events[0] must set introduced, fixed, last_affected, or limit"},
		{name: "numeric boundary", ranges: `[{"events":[{"introduced":1}]}]`, wantDetail: "version_ranges[0].events[0].introduced must be a string"},
		{name: "numeric sibling", ranges: `[{"events":[{"introduced":"0","fixed":5}]}]`, wantDetail: "version_ranges[0].events[0].fixed must be a string"},
		{name: "blank boundary", ranges: `[{"events":[{"introduced":"  "}]}]`, wantDetail: "version_ranges[0].events[0] must set introduced, fixed, last_affected, or limit"},
		{name: "null type", ranges: `[{"type":null,"events":[{"introduced":"0"}]}]`},
		{name: "numeric type", ranges: `[{"type":1,"events":[{"introduced":"0"}]}]`, wantDetail: "version_ranges[0].type must be a string"},
		{name: "not an array", ranges: `{"introduced":"0"}`, wantDetail: "version_ranges must be an array of range objects"},
	}
	for _, tt := range tests {
		for _, feed := range []string{"osv", "openssf"} {
			t.Run(feed+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				body := `{"vulnerabilities":[{"id":"GHSA-range","summary":"s","severity":"HIGH","affected_packages":[{"ecosystem":"npm","name":"left-pad","version_ranges":` + tt.ranges + `}]}]}`
				wantPrefix := "vulnerability import affected_packages[0]."
				if feed == "openssf" {
					body = `{"malicious":[{"id":"MAL-range","ecosystem":"npm","name":"evil","version_ranges":` + tt.ranges + `}]}`
					wantPrefix = "malicious import "
				}
				store := &stubStore{}
				h := newTestFeedImportHandler(store)
				req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+feed+"/import", strings.NewReader(body))
				req.SetPathValue("feed", feed)
				req.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()

				h.HandleImport(rr, req)

				if tt.wantDetail == "" {
					if rr.Code != http.StatusOK {
						t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
					}
					return
				}
				if rr.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
				}
				var errBody errorJSON
				if err := json.Unmarshal(rr.Body.Bytes(), &errBody); err != nil {
					t.Fatalf("error body is not JSON: %v; body=%q", err, rr.Body.String())
				}
				if !strings.Contains(errBody.Error, wantPrefix+tt.wantDetail) {
					t.Fatalf("error = %q, want it to contain %q", errBody.Error, wantPrefix+tt.wantDetail)
				}
				if errBody.Error == feedImportStoreRejectedMessage {
					t.Fatal("range rejection fell through to the generic store message")
				}
				if len(store.upsertedMalicious) != 0 || len(store.auditEntries) != 0 {
					t.Fatalf("rejected import reached the store: malicious=%d audits=%d", len(store.upsertedMalicious), len(store.auditEntries))
				}
			})
		}
	}
}
