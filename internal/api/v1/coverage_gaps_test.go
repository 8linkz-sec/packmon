package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/8linkz-sec/packmon/internal/requestctx"
)

// TestSyncExportLogAttrsRedactsAndBoundsDiagnostics covers the log attributes
// emitted when a sync export fails. They travel into the server log, so the
// correlation ID and key name must be bounded and the attribute list must stay
// well-formed even without an authenticated identity.
func TestSyncExportLogAttrsRedactsAndBoundsDiagnostics(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync/export", nil)
	req.RemoteAddr = "203.0.113.7:44321"

	attrs := syncExportLogAttrs(req, "correlation-123", http.ErrBodyNotAllowed)
	if len(attrs)%2 != 0 {
		t.Fatalf("syncExportLogAttrs returned %d values, want key/value pairs", len(attrs))
	}
	pairs := attrsToMap(t, attrs)
	if pairs["correlation_id"] != "correlation-123" {
		t.Fatalf("correlation_id = %v, want the supplied ID", pairs["correlation_id"])
	}
	if _, ok := pairs["error"]; !ok {
		t.Fatal("attributes carry no error value")
	}
	if _, ok := pairs["api_key_id"]; ok {
		t.Fatal("attributes carry an API key identity for an unauthenticated request")
	}
}

// TestSyncExportLogAttrsIncludesAPIKeyIdentityWhenPresent is the counterpart:
// with an authenticated request the log has to name which key hit the failure,
// otherwise an operator cannot tell which client is broken.
func TestSyncExportLogAttrsIncludesAPIKeyIdentityWhenPresent(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync/export", nil)
	ctx := requestctx.ContextWithAPIKeyIdentity(req.Context(), requestctx.APIKeyIdentity{
		ID:   77,
		Name: "n8n-import",
	})
	req = req.WithContext(ctx)

	pairs := attrsToMap(t, syncExportLogAttrs(req, "cid", http.ErrBodyNotAllowed))
	if pairs["api_key_id"] != 77 {
		t.Fatalf("api_key_id = %v, want 77", pairs["api_key_id"])
	}
	if pairs["api_key_name"] != "n8n-import" {
		t.Fatalf("api_key_name = %v, want n8n-import", pairs["api_key_name"])
	}
}

func attrsToMap(t *testing.T, attrs []any) map[string]any {
	t.Helper()

	if len(attrs)%2 != 0 {
		t.Fatalf("attribute slice has odd length %d", len(attrs))
	}
	out := make(map[string]any, len(attrs)/2)
	for i := 0; i < len(attrs); i += 2 {
		key, ok := attrs[i].(string)
		if !ok {
			t.Fatalf("attribute key at %d is %T, want string", i, attrs[i])
		}
		out[key] = attrs[i+1]
	}
	return out
}

// TestVulnerabilityImportAliasesToDBMapsEveryEntry covers the import mapping for
// advisory aliases. A dropped alias means a CVE that the scanner can no longer
// match to its GHSA identifier.
func TestVulnerabilityImportAliasesToDBMapsEveryEntry(t *testing.T) {
	t.Parallel()

	if got := vulnerabilityImportAliasesToDB(nil); got != nil {
		t.Fatalf("vulnerabilityImportAliasesToDB(nil) = %v, want nil", got)
	}
	if got := vulnerabilityImportAliasesToDB([]vulnerabilityImportAlias{}); got != nil {
		t.Fatalf("vulnerabilityImportAliasesToDB(empty) = %v, want nil", got)
	}

	got := vulnerabilityImportAliasesToDB([]vulnerabilityImportAlias{
		{AliasID: "CVE-2026-1"},
		{AliasID: "GHSA-aaaa-bbbb-cccc"},
	})
	if len(got) != 2 {
		t.Fatalf("mapped %d aliases, want 2", len(got))
	}
	if got[0].AliasID != "CVE-2026-1" || got[1].AliasID != "GHSA-aaaa-bbbb-cccc" {
		t.Fatalf("mapped aliases = %+v, want both IDs preserved in order", got)
	}
}

// TestVulnerabilityImportReferencesToDBMapsEveryField covers the reference
// mapping. References become the advisory links in the report, so a dropped
// field turns into a finding without a source to check.
func TestVulnerabilityImportReferencesToDBMapsEveryField(t *testing.T) {
	t.Parallel()

	if got := vulnerabilityImportReferencesToDB(nil); got != nil {
		t.Fatalf("vulnerabilityImportReferencesToDB(nil) = %v, want nil", got)
	}

	got := vulnerabilityImportReferencesToDB([]vulnerabilityImportReference{{
		Type:   "ADVISORY",
		URL:    "https://example.test/advisory",
		Source: "osv",
	}})
	if len(got) != 1 {
		t.Fatalf("mapped %d references, want 1", len(got))
	}
	if got[0].Type != "ADVISORY" || got[0].URL != "https://example.test/advisory" || got[0].Source != "osv" {
		t.Fatalf("mapped reference = %+v, want every field preserved", got[0])
	}
}

// TestVulnerabilityImportSourcesToDBClonesRawJSON guards against the imported
// payload and the stored row sharing a backing array, which would let a later
// mutation of one silently change the other.
func TestVulnerabilityImportSourcesToDBClonesRawJSON(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`{"a":1}`)
	got := vulnerabilityImportSourcesToDB([]vulnerabilityImportSource{{
		Source:   "osv",
		SourceID: "GHSA-1",
		URL:      "https://example.test",
		RawJSON:  raw,
	}})
	if len(got) != 1 {
		t.Fatalf("mapped %d sources, want 1", len(got))
	}
	if string(got[0].RawJSON) != `{"a":1}` {
		t.Fatalf("RawJSON = %s, want the payload preserved", got[0].RawJSON)
	}

	raw[2] = 'X'
	if string(got[0].RawJSON) == string(raw) {
		t.Fatal("mapped RawJSON still aliases the import payload")
	}
}
