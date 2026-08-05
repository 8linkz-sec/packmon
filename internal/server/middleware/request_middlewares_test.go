package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/correlation"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

func TestCorrelationPreservesValidIDAndStoresItInContext(t *testing.T) {
	t.Parallel()

	const id = "12345678-1234-4234-9234-123456789abc"
	var seen string
	handler := Correlation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = CorrelationIDFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/check", nil)
	req.Header.Set(HeaderCorrelationID, id)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get(HeaderCorrelationID); got != id {
		t.Fatalf("response correlation id = %q, want %q", got, id)
	}
	if seen != id {
		t.Fatalf("context correlation id = %q, want %q", seen, id)
	}
}

func TestCorrelationGeneratesIDForMissingOrInvalidHeader(t *testing.T) {
	t.Parallel()

	handler := Correlation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := CorrelationIDFromContext(r.Context()); !correlation.Valid(got) {
			t.Fatalf("generated context correlation id = %q, want UUID-like value", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, header := range []string{"", "not-a-uuid"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/check", nil)
		req.Header.Set(HeaderCorrelationID, header)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get(HeaderCorrelationID); !correlation.Valid(got) {
			t.Fatalf("response correlation id for header %q = %q, want UUID-like value", header, got)
		}
	}

	if got := CorrelationIDFromContext(context.Background()); got != "" {
		t.Fatalf("CorrelationIDFromContext(empty) = %q, want empty", got)
	}
}

func TestCorrelationLogsEntropyFailureAndUsesFallbackID(t *testing.T) {
	oldGenerator := newCorrelationID
	newCorrelationID = func() (string, error) {
		return "", errors.New("entropy down")
	}
	t.Cleanup(func() { newCorrelationID = oldGenerator })

	oldDefault := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldDefault) })

	handler := Correlation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := CorrelationIDFromContext(r.Context()); !correlation.Valid(got) {
			t.Fatalf("fallback context correlation id = %q, want UUID-like value", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/check", nil))

	if got := rec.Header().Get(HeaderCorrelationID); !correlation.Valid(got) {
		t.Fatalf("fallback response correlation id = %q, want UUID-like value", got)
	}
	for _, want := range []string{"failed to generate correlation id", "entropy down"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("entropy failure log missing %q: %s", want, logs.String())
		}
	}
}

func TestUserAgentMiddlewareProductionRules(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	tests := []struct {
		name string
		path string
		ua   string
		dev  bool
		want int
	}{
		{"known cli allowed", "/api/v1/check", "packmon-cli/1.0", false, http.StatusNoContent},
		{"known n8n allowed", "/api/v1/check", "packmon-n8n/1.0", false, http.StatusNoContent},
		{"unknown rejected", "/api/v1/check", "curl/8.0", false, http.StatusForbidden},
		{"dev allows unknown", "/api/v1/check", "curl/8.0", true, http.StatusNoContent},
		{"health exempt", "/healthz", "curl/8.0", false, http.StatusNoContent},
		{"web exempt", "/search", "curl/8.0", false, http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := UserAgent(logger, tt.dev)(next)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Header.Set("User-Agent", tt.ua)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if tt.want == http.StatusForbidden {
				assertJSONErrorResponse(t, rec, http.StatusForbidden, "unknown user agent")
			}
		})
	}

	if !isKnownAgent("packmon-cli/test") || !isKnownAgent("packmon-n8n/test") {
		t.Fatal("isKnownAgent should accept documented agent prefixes")
	}
	if isKnownAgent("curl/8.0") {
		t.Fatal("isKnownAgent should reject unknown agent")
	}
	if !isUserAgentExempt("/admin/login") || !isUserAgentExempt("/static/tailwind.css") {
		t.Fatal("isUserAgentExempt should allow admin and non-API web paths")
	}
	if isUserAgentExempt("/api/v1/check") {
		t.Fatal("isUserAgentExempt should not exempt API paths")
	}
}

func TestMiddlewareJSONErrorIncludesMachineReadableCode(t *testing.T) {
	t.Parallel()

	handler := UserAgent(slog.New(slog.NewTextHandler(io.Discard, nil)), false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error response body is not JSON: %v; body=%q", err, rec.Body.String())
	}
	if body.Error != "unknown user agent" {
		t.Fatalf("error = %q, want human message", body.Error)
	}
	if body.Code != "forbidden" {
		t.Fatalf("code = %q, want forbidden", body.Code)
	}
}

func TestMiddlewareJSONErrorCodeForStatusMapsKnownTaxonomy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status int
		want   string
	}{
		{http.StatusBadRequest, "invalid_request"},
		{http.StatusUnauthorized, "auth_failed"},
		{http.StatusForbidden, "forbidden"},
		{http.StatusConflict, "conflict"},
		{http.StatusTooManyRequests, "rate_limited"},
		{http.StatusNotFound, "not_found"},
		{http.StatusMethodNotAllowed, "unsupported"},
		{http.StatusUnsupportedMediaType, "unsupported"},
		{http.StatusNotImplemented, "unsupported"},
		{http.StatusInternalServerError, "internal_error"},
	}
	for _, tt := range tests {
		if got := jsonErrorCodeForStatus(tt.status); got != tt.want {
			t.Fatalf("jsonErrorCodeForStatus(%d) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestLoggingCapturesStatusAndCorrelationIDWithoutClientIdentifiers(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.12, 10.0.0.1")
	req.Header.Set("User-Agent", "packmon-cli/test")
	req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), "corr-1"))

	handler := TrustedClientIP([]string{"10.0.0.1"})(Logging(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	})))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	logLine := logs.String()
	for _, want := range []string{`"level":"WARN"`, `"status":404`, `"correlation_id":"corr-1"`, `"path":"(unmatched-route)"`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("log line missing %s: %s", want, logLine)
		}
	}
	for _, forbidden := range []string{`"remote_addr"`, `"client_ip"`, `"user_agent"`, "203.0.113.12", "10.0.0.1:12345", "packmon-cli/test"} {
		if strings.Contains(logLine, forbidden) {
			t.Fatalf("request completion log contains client identifier %q: %s", forbidden, logLine)
		}
	}
}

func TestLoggingUsesRoutePathLabelAndOmitsUserAgent(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rawPath := "/api/v1/packages/npm/C:%5CUsers%5CAdmin%5Csecret-token/refresh"
	rawUA := "packmon-cli/test\nAuthorization: Bearer super-secret-token " + strings.Repeat("b", 400)
	req := httptest.NewRequest(http.MethodGet, rawPath, nil)
	req.Header.Set("User-Agent", rawUA)

	handler := Logging(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	logLine := logs.String()
	for _, leaked := range []string{`"user_agent"`, "super-secret-token", "\nAuthorization", "secret-token", "Users", "Admin", strings.Repeat("b", 300)} {
		if strings.Contains(logLine, leaked) {
			t.Fatalf("request log leaked %q in %s", leaked, logLine)
		}
	}
	for _, want := range []string{`"path":"/api/v1/packages/{ecosystem}/{name...}/refresh"`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("request log missing %q: %s", want, logLine)
		}
	}
}

func TestUserAgentRejectionLogUsesTrustedClientIPAndBoundedValues(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := TrustedClientIP([]string{"10.0.0.1"})(Correlation(UserAgent(logger, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/secret-token/refresh", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.77, 10.0.0.1")
	req.Header.Set("User-Agent", "curl/8.0 Authorization: Bearer super-secret-token "+strings.Repeat("x", 400))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	logLine := logs.String()
	for _, want := range []string{`"client_ip":"203.0.113.77"`, `"correlation_id":`, `Bearer [redacted]`, `[truncated]`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("user-agent rejection log missing %s: %s", want, logLine)
		}
	}
	if !strings.Contains(logLine, `"path":"/api/v1/packages/{ecosystem}/{name...}/refresh"`) {
		t.Fatalf("user-agent rejection log missing route path label: %s", logLine)
	}
	for _, leaked := range []string{"10.0.0.1:12345", "super-secret-token", "secret-token", strings.Repeat("x", 300)} {
		if strings.Contains(logLine, leaked) {
			t.Fatalf("user-agent rejection log leaked %q in %s", leaked, logLine)
		}
	}
}

func TestLoggingDefaultsStatusToOKAndDebugsStaticAssets(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	req := httptest.NewRequest(http.MethodGet, "/static/style.css", nil)

	handler := Logging(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	logLine := logs.String()
	for _, want := range []string{`"level":"DEBUG"`, `"status":200`, `"path":"/static/..."`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("log line missing %s: %s", want, logLine)
		}
	}
}

func TestRecoveryReturnsInternalServerErrorOnPanic(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	longPath := "/boom/" + strings.Repeat("a", 700)
	req := httptest.NewRequest(http.MethodGet, longPath, nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.88, 10.0.0.1")
	req.Header.Set("User-Agent", "packmon-cli/test")
	req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), "corr-2"))

	handler := TrustedClientIP([]string{"10.0.0.1"})(Recovery(logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	assertJSONErrorResponse(t, rec, http.StatusInternalServerError, "internal server error")
	logLine := logs.String()
	for _, want := range []string{`"level":"ERROR"`, `"msg":"panic recovered"`, `"correlation_id":"corr-2"`, `"path":"(unmatched-route)"`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("log line missing %s: %s", want, logLine)
		}
	}
	for _, forbidden := range []string{`"stack"`, `"client_ip"`, `"remote_addr"`, `"user_agent"`, "request_middlewares_test.go", "203.0.113.88", "10.0.0.1:12345", "packmon-cli/test", strings.Repeat("a", 600)} {
		if strings.Contains(logLine, forbidden) {
			t.Fatalf("log line contains %s: %s", forbidden, logLine)
		}
	}
}

func TestRecoveryLogsNonStringPanicAsStableStringFields(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/secret-token/refresh", nil)
	req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), "corr-non-string"))

	handler := Recovery(logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(map[string]any{
			"api_key": "api-secret-123456",
			"headers": []string{
				"Authorization: Bearer super-secret-token",
			},
		})
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assertJSONErrorResponse(t, rec, http.StatusInternalServerError, "internal server error")

	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("panic log is not JSON: %v; log=%q", err, logs.String())
	}
	panicType, ok := entry["panic_type"].(string)
	if !ok || !strings.HasPrefix(panicType, "map[") {
		t.Fatalf("panic_type = %#v, want Go type string for map panic", entry["panic_type"])
	}
	panicValue, ok := entry["panic"].(string)
	if !ok || panicValue == "" {
		t.Fatalf("panic = %#v, want bounded string field", entry["panic"])
	}
	logLine := logs.String()
	for _, want := range []string{`"path":"/api/v1/packages/{ecosystem}/{name...}/refresh"`, `"correlation_id":"corr-non-string"`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("panic log missing %s: %s", want, logLine)
		}
	}
	for _, leaked := range []string{`"panic":{`, `"panic":[`, "api-secret-123456", "super-secret-token", "Authorization", "secret-token"} {
		if strings.Contains(logLine, leaked) {
			t.Fatalf("panic log leaked %q in %s", leaked, logLine)
		}
	}
}

func assertJSONErrorResponse(t *testing.T, rec *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d", rec.Code, status)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want application/json; charset=utf-8", got)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error response body is not JSON: %v; body=%q", err, rec.Body.String())
	}
	if body.Error != message {
		t.Fatalf("error response message = %q, want %q", body.Error, message)
	}
}
