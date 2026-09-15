package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type failingSecurityTxtWriter struct {
	header http.Header
}

func (w *failingSecurityTxtWriter) Header() http.Header {
	return w.header
}

func (w *failingSecurityTxtWriter) WriteHeader(int) {}

func (w *failingSecurityTxtWriter) Write([]byte) (int, error) {
	return 0, errors.New("security.txt write failed")
}

type securityTxtLogEvent struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

type securityTxtLogHandler struct {
	events []securityTxtLogEvent
}

func (h *securityTxtLogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *securityTxtLogHandler) Handle(_ context.Context, record slog.Record) error {
	event := securityTxtLogEvent{level: record.Level, msg: record.Message, attrs: make(map[string]any)}
	record.Attrs(func(attr slog.Attr) bool {
		event.attrs[attr.Key] = attr.Value.Any()
		return true
	})
	h.events = append(h.events, event)
	return nil
}

func (h *securityTxtLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *securityTxtLogHandler) WithGroup(string) slog.Handler { return h }

// TestHandlePrivacyServesOnlyItsOwnPath covers the exact-path guard. These
// handlers are registered on a prefix pattern, so without the check every
// unmatched sub-path would render the privacy page and mask a real 404.
func TestHandlePrivacyServesOnlyItsOwnPath(t *testing.T) {
	t.Parallel()

	handler := HandlePrivacy(testRenderer(), slog.New(slog.DiscardHandler))

	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodGet, "/privacy", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /privacy = %d, want 200", recorder.Code)
	}
	if recorder.Body.Len() == 0 {
		t.Fatal("GET /privacy returned an empty body")
	}

	for _, path := range []string{"/privacy/extra", "/privacy/", "/privacyx"} {
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, recorder.Code)
		}
	}
}

// TestHandleTermsServesOnlyItsOwnPath is the same guard on the terms page.
func TestHandleTermsServesOnlyItsOwnPath(t *testing.T) {
	t.Parallel()

	handler := HandleTerms(testRenderer(), slog.New(slog.DiscardHandler))

	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodGet, "/terms", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /terms = %d, want 200", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodGet, "/terms/extra", nil))
	if recorder.Code != http.StatusNotFound {
		t.Errorf("GET /terms/extra = %d, want 404", recorder.Code)
	}
}

// TestStaticPageHandlersReturnInternalErrorWhenRenderingFails keeps the public
// static endpoints from reporting a successful page when their embedded
// templates cannot be loaded.
func TestStaticPageHandlersReturnInternalErrorWhenRenderingFails(t *testing.T) {
	t.Parallel()

	brokenRenderer := NewRendererWithLayoutLinks(fstest.MapFS{}, false, LayoutLinks{})
	for _, tc := range []struct {
		name    string
		path    string
		handler func(*Renderer, *slog.Logger) http.HandlerFunc
	}{
		{name: "privacy", path: "/privacy", handler: HandlePrivacy},
		{name: "terms", path: "/terms", handler: HandleTerms},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tc.handler(brokenRenderer, slog.New(slog.DiscardHandler))(
				recorder, httptest.NewRequest(http.MethodGet, tc.path, nil),
			)

			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("GET %s = %d, want 500", tc.path, recorder.Code)
			}
			if got := recorder.Body.String(); got != "internal server error\n" {
				t.Errorf("GET %s body = %q, want generic internal-error response", tc.path, got)
			}
		})
	}
}

// TestHandleSecurityTxtServesAnRFC9116Document covers the security contact file.
// It is served unauthenticated by design, and RFC 9116 requires an Expires field
// -- a document without one is treated as invalid by scanners.
func TestHandleSecurityTxtServesAnRFC9116Document(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	HandleSecurityTxt(slog.New(slog.DiscardHandler))(
		recorder, httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil),
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want plain text", got)
	}

	body := recorder.Body.String()
	for _, field := range []string{"Contact:", "Policy:", "Preferred-Languages:", "Expires:"} {
		if !strings.Contains(body, field) {
			t.Errorf("security.txt is missing the %s field:\n%s", field, body)
		}
	}

	// The Expires value has to be a real future timestamp, not a placeholder.
	var expires string
	for _, line := range strings.Split(body, "\n") {
		if after, ok := strings.CutPrefix(line, "Expires:"); ok {
			expires = strings.TrimSpace(after)
		}
	}
	parsed, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		t.Fatalf("Expires = %q is not RFC3339: %v", expires, err)
	}
	if !parsed.After(time.Now()) {
		t.Fatalf("Expires = %v is not in the future", parsed)
	}
}

// TestHandleSecurityTxtRejectsOtherPaths keeps the handler from answering for
// every /.well-known/ path it is mounted under.
func TestHandleSecurityTxtRejectsOtherPaths(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	HandleSecurityTxt(slog.New(slog.DiscardHandler))(
		recorder, httptest.NewRequest(http.MethodGet, "/.well-known/other", nil),
	)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

// TestHandleSecurityTxtLogsWriteFailures ensures an unavailable client cannot
// turn the public discovery handler into a panic. The response writer error is
// intentionally swallowed after logging because no usable HTTP response remains.
func TestHandleSecurityTxtLogsWriteFailures(t *testing.T) {
	t.Parallel()

	writer := &failingSecurityTxtWriter{header: make(http.Header)}
	logs := &securityTxtLogHandler{}
	HandleSecurityTxt(slog.New(logs))(
		writer, httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil),
	)

	if got := writer.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want plain text", got)
	}
	if got := writer.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q, want caching policy", got)
	}
	if len(logs.events) != 1 {
		t.Fatalf("log events = %d, want 1", len(logs.events))
	}
	event := logs.events[0]
	if event.level != slog.LevelError {
		t.Errorf("log level = %v, want ERROR", event.level)
	}
	if event.msg != "security.txt: write failed" {
		t.Errorf("log message = %q, want write-failure context", event.msg)
	}
	if got, ok := event.attrs["error"].(error); !ok || got.Error() != "security.txt write failed" {
		t.Errorf("log error = %#v, want failing writer error", event.attrs["error"])
	}
}

// TestGzipResponseWriterCompressesOnlySuccessfulResponses covers the static
// asset compressor. Setting Content-Encoding on an error response would make the
// client try to gunzip a plain-text error body.
func TestGzipResponseWriterCompressesOnlySuccessfulResponses(t *testing.T) {
	t.Parallel()

	t.Run("200 is compressed", func(t *testing.T) {
		t.Parallel()

		recorder := httptest.NewRecorder()
		recorder.Header().Set("Content-Length", "11")
		writer := &gzipResponseWriter{ResponseWriter: recorder}

		if _, err := writer.Write([]byte("body-content")); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		if got := recorder.Header().Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		// A stale Content-Length would describe the uncompressed body.
		if got := recorder.Header().Get("Content-Length"); got != "" {
			t.Errorf("Content-Length = %q, want it removed for a compressed body", got)
		}

		reader, err := gzip.NewReader(bytes.NewReader(recorder.Body.Bytes()))
		if err != nil {
			t.Fatalf("body is not gzip: %v", err)
		}
		decoded, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read gzip body: %v", err)
		}
		if string(decoded) != "body-content" {
			t.Fatalf("decoded body = %q, want body-content", decoded)
		}
	})

	t.Run("non-200 is passed through", func(t *testing.T) {
		t.Parallel()

		recorder := httptest.NewRecorder()
		writer := &gzipResponseWriter{ResponseWriter: recorder}
		writer.WriteHeader(http.StatusNotFound)
		if _, err := writer.Write([]byte("not found")); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		if got := recorder.Header().Get("Content-Encoding"); got != "" {
			t.Errorf("Content-Encoding = %q, want none on an error response", got)
		}
		if recorder.Body.String() != "not found" {
			t.Errorf("body = %q, want the uncompressed error text", recorder.Body.String())
		}
	})
}

// TestGzipResponseWriterIgnoresRepeatedHeaderWrites covers the idempotence guard.
// http.Error and a handler both calling WriteHeader must not install a second
// gzip writer over the first one's output.
func TestGzipResponseWriterIgnoresRepeatedHeaderWrites(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	writer := &gzipResponseWriter{ResponseWriter: recorder}

	writer.WriteHeader(http.StatusOK)
	first := writer.writer
	writer.WriteHeader(http.StatusInternalServerError)

	if writer.writer != first {
		t.Fatal("a second WriteHeader replaced the gzip writer")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want the first status to win", recorder.Code)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestGzipResponseWriterCloseIsSafeWithoutCompression covers the path where no
// gzip writer was ever created, which every non-200 response takes.
func TestGzipResponseWriterCloseIsSafeWithoutCompression(t *testing.T) {
	t.Parallel()

	writer := &gzipResponseWriter{ResponseWriter: httptest.NewRecorder()}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() on an uncompressed writer = %v, want nil", err)
	}
}

// TestShouldGzipStaticAssetOnlyCompressesTextAssets pins the eligibility rules.
// Compressing a range request would corrupt it, and re-compressing images wastes
// CPU for no gain.
func TestShouldGzipStaticAssetOnlyCompressesTextAssets(t *testing.T) {
	t.Parallel()

	newRequest := func(method, path, acceptEncoding, rangeHeader string) *http.Request {
		req := httptest.NewRequest(method, path, nil)
		if acceptEncoding != "" {
			req.Header.Set("Accept-Encoding", acceptEncoding)
		}
		if rangeHeader != "" {
			req.Header.Set("Range", rangeHeader)
		}
		return req
	}

	for _, tc := range []struct {
		name string
		req  *http.Request
		want bool
	}{
		{name: "css", req: newRequest(http.MethodGet, "/static/app.css", "gzip", ""), want: true},
		{name: "js", req: newRequest(http.MethodGet, "/static/app.js", "gzip, deflate", ""), want: true},
		{name: "upper-case extension", req: newRequest(http.MethodGet, "/static/APP.CSS", "gzip", ""), want: true},
		{name: "image", req: newRequest(http.MethodGet, "/static/logo.svg", "gzip", ""), want: false},
		{name: "no accept-encoding", req: newRequest(http.MethodGet, "/static/app.css", "", ""), want: false},
		{name: "identity only", req: newRequest(http.MethodGet, "/static/app.css", "identity", ""), want: false},
		{name: "range request", req: newRequest(http.MethodGet, "/static/app.css", "gzip", "bytes=0-99"), want: false},
		{name: "head request", req: newRequest(http.MethodHead, "/static/app.css", "gzip", ""), want: false},
		{name: "post request", req: newRequest(http.MethodPost, "/static/app.css", "gzip", ""), want: false},
	} {
		if got := shouldGzipStaticAsset(tc.req); got != tc.want {
			t.Errorf("%s: shouldGzipStaticAsset = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestRenderNotFoundPageSetsTheStatusBeforeTheBody covers the 404 renderer. It
// buffers the page first so a template failure can still turn into a 500 --
// writing the status first would leave a 404 with an error body.
func TestRenderNotFoundPageSetsTheStatusBeforeTheBody(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	renderNotFoundPage(recorder, httptest.NewRequest(http.MethodGet, "/missing", nil),
		testRenderer(), slog.New(slog.DiscardHandler), NotFoundData{}, "no-store")

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want HTML", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want the supplied value", got)
	}
	if recorder.Body.Len() == 0 {
		t.Error("404 page body is empty")
	}
}

// TestRenderNotFoundPageOmitsCacheControlWhenUnset covers the other branch: the
// header must not appear at all rather than as an empty value.
func TestRenderNotFoundPageOmitsCacheControlWhenUnset(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	renderNotFoundPage(recorder, httptest.NewRequest(http.MethodGet, "/missing", nil),
		testRenderer(), slog.New(slog.DiscardHandler), NotFoundData{}, "")

	if _, ok := recorder.Header()["Cache-Control"]; ok {
		t.Fatalf("Cache-Control = %q, want the header absent", recorder.Header().Get("Cache-Control"))
	}
}
