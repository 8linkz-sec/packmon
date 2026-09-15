package web

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleNotFoundPreservesPublicAndReservedRouteBoundaries verifies that
// browser-facing misses receive the branded page, while API and operations
// paths retain a plain HTTP 404 rather than being masked by the public UI.
func TestHandleNotFoundPreservesPublicAndReservedRouteBoundaries(t *testing.T) {
	t.Parallel()

	handler := HandleNotFound(testRenderer(), slog.New(slog.DiscardHandler))
	for _, tc := range []struct {
		name       string
		path       string
		accept     string
		wantStatus int
		wantHTML   bool
	}{
		{name: "browser miss", path: "/missing", accept: "text/html", wantStatus: http.StatusNotFound, wantHTML: true},
		{name: "json client", path: "/missing", accept: "application/json", wantStatus: http.StatusNotFound},
		{name: "api route", path: "/api/v1/missing", accept: "text/html", wantStatus: http.StatusNotFound},
		{name: "admin route", path: "/admin/missing", accept: "text/html", wantStatus: http.StatusNotFound},
		{name: "metrics route", path: "/metrics/missing", accept: "text/html", wantStatus: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, tc.path, nil)
			request.Header.Set("Accept", tc.accept)
			handler(recorder, request)

			if recorder.Code != tc.wantStatus {
				t.Fatalf("GET %s = %d, want %d", tc.path, recorder.Code, tc.wantStatus)
			}
			if gotHTML := recorder.Header().Get("Content-Type") == "text/html; charset=utf-8"; gotHTML != tc.wantHTML {
				t.Errorf("GET %s HTML content type = %v, want %v", tc.path, gotHTML, tc.wantHTML)
			}
		})
	}
}

// TestHandleNotFoundRedirectsStaticDirectory preserves the canonical trailing
// slash before the static handler takes over.
func TestHandleNotFoundRedirectsStaticDirectory(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	HandleNotFound(testRenderer(), slog.New(slog.DiscardHandler))(
		recorder, httptest.NewRequest(http.MethodGet, "/static", nil),
	)

	if recorder.Code != http.StatusMovedPermanently {
		t.Fatalf("GET /static = %d, want %d", recorder.Code, http.StatusMovedPermanently)
	}
	if got := recorder.Header().Get("Location"); got != "/static/" {
		t.Errorf("Location = %q, want /static/", got)
	}
}

// TestAcceptsGzipEncodingHonorsQualityValues verifies that an explicitly
// disabled gzip token cannot be re-enabled by whitespace or case variations.
func TestAcceptsGzipEncodingHonorsQualityValues(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value string
		want  bool
	}{
		{value: "gzip", want: true},
		{value: "gzip; q=0.5", want: true},
		{value: "br, GZip ; q = 0", want: false},
		{value: "gzip; q=0.0", want: false},
		{value: "gzip; q=invalid", want: true},
		{value: "gzip; level=9", want: true},
	} {
		if got := acceptsGzipEncoding(tc.value); got != tc.want {
			t.Errorf("acceptsGzipEncoding(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}
