package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestErrorResponseWritesCodeAndMessage(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	errorResponse(rec, http.StatusBadRequest, "bad input")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("errorResponse status = %d, want 400", rec.Code)
	}
	var body errorJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal(error body) error = %v", err)
	}
	if body.Error != "bad input" || body.Code != "invalid_request" {
		t.Fatalf("errorResponse body = %+v, want bad input/invalid_request", body)
	}
}

func TestMethodNotAllowedSetsAllowHeaderAndEnvelope(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	methodNotAllowed(rec, http.MethodGet, http.MethodHead)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("methodNotAllowed status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Fatalf("methodNotAllowed Allow header = %q, want %q", allow, "GET, HEAD")
	}
	var body errorJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal(error body) error = %v", err)
	}
	if body.Error != "method not allowed" {
		t.Fatalf("methodNotAllowed body = %+v, want method-not-allowed message", body)
	}

	noAllow := httptest.NewRecorder()
	methodNotAllowedWithMessage(noAllow, "custom message")
	if allow := noAllow.Header().Get("Allow"); allow != "" {
		t.Fatalf("methodNotAllowedWithMessage(no methods) Allow header = %q, want empty", allow)
	}
}

func TestWriteJSONForRequestSkipsBodyOnHead(t *testing.T) {
	t.Parallel()

	head := httptest.NewRecorder()
	writeJSONForRequest(head, httptest.NewRequest(http.MethodHead, "/api/v1/feeds/status", nil), http.StatusOK, map[string]string{"status": "ok"})
	if head.Code != http.StatusOK {
		t.Fatalf("writeJSONForRequest(HEAD) status = %d, want 200", head.Code)
	}
	if head.Body.Len() != 0 {
		t.Fatalf("writeJSONForRequest(HEAD) body = %q, want empty body", head.Body.String())
	}

	get := httptest.NewRecorder()
	writeJSONForRequest(get, httptest.NewRequest(http.MethodGet, "/api/v1/feeds/status", nil), http.StatusOK, map[string]string{"status": "ok"})
	if get.Code != http.StatusOK || get.Body.Len() == 0 {
		t.Fatalf("writeJSONForRequest(GET) = %d %q, want JSON body", get.Code, get.Body.String())
	}
}

func TestHandleNotFoundWritesJSONEnvelope(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	HandleNotFound(rec, httptest.NewRequest(http.MethodGet, "/api/v1/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("HandleNotFound status = %d, want 404", rec.Code)
	}
	var body errorJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal(not found body) error = %v", err)
	}
	if body.Error != "not found" || body.Code != "not_found" {
		t.Fatalf("HandleNotFound body = %+v, want not found envelope", body)
	}
}

func TestFeedImportDecodeErrorHelpers(t *testing.T) {
	t.Parallel()

	if err := feedImportJSONDecodeError("body", nil); err != nil {
		t.Fatalf("feedImportJSONDecodeError(nil) = %v, want nil", err)
	}
	if err := feedImportJSONDecodeError("body", errors.New("boom")); err == nil {
		t.Fatal("feedImportJSONDecodeError(non-nil) = nil, want wrapped decode error")
	}
	err := feedImportControlledDecodeError("body", "unexpected trailing data")
	if err == nil {
		t.Fatal("feedImportControlledDecodeError() = nil, want error")
	}
	var decodeErr *feedImportDecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("feedImportControlledDecodeError() type = %T, want *feedImportDecodeError", err)
	}
}
