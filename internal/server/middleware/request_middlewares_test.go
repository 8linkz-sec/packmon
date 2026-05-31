package middleware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
		if got := CorrelationIDFromContext(r.Context()); !uuidPattern.MatchString(got) {
			t.Fatalf("generated context correlation id = %q, want UUID-like value", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, header := range []string{"", "not-a-uuid"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/check", nil)
		req.Header.Set(HeaderCorrelationID, header)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get(HeaderCorrelationID); !uuidPattern.MatchString(got) {
			t.Fatalf("response correlation id for header %q = %q, want UUID-like value", header, got)
		}
	}

	if got := CorrelationIDFromContext(context.Background()); got != "" {
		t.Fatalf("CorrelationIDFromContext(empty) = %q, want empty", got)
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

func TestLoggingCapturesStatusAndCorrelationID(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.Header.Set("User-Agent", "packmon-cli/test")
	req = req.WithContext(context.WithValue(req.Context(), correlationKey{}, "corr-1"))

	handler := Logging(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	logLine := logs.String()
	for _, want := range []string{`"level":"WARN"`, `"status":404`, `"correlation_id":"corr-1"`, `"path":"/missing"`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("log line missing %s: %s", want, logLine)
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
	for _, want := range []string{`"level":"DEBUG"`, `"status":200`, `"path":"/static/style.css"`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("log line missing %s: %s", want, logLine)
		}
	}
}

func TestRecoveryReturnsInternalServerErrorOnPanic(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	req = req.WithContext(context.WithValue(req.Context(), correlationKey{}, "corr-2"))

	handler := Recovery(logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal server error") {
		t.Fatalf("body = %q, want internal server error", rec.Body.String())
	}
	logLine := logs.String()
	for _, want := range []string{`"level":"ERROR"`, `"msg":"panic recovered"`, `"correlation_id":"corr-2"`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("log line missing %s: %s", want, logLine)
		}
	}
}
