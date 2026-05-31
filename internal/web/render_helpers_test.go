package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

func TestRenderHelperFunctions(t *testing.T) {
	fixed := time.Date(2026, 5, 30, 12, 34, 0, 0, time.FixedZone("CEST", 2*60*60))
	if got := formatTime(time.Time{}); got != "-" {
		t.Fatalf("formatTime(zero) = %q, want -", got)
	}
	if got := formatTime(fixed); got != "2026-05-30 10:34 UTC" {
		t.Fatalf("formatTime() = %q, want UTC rendering", got)
	}

	agoTests := []struct {
		name string
		when time.Time
		want string
	}{
		{"zero", time.Time{}, "never"},
		{"seconds", time.Now().Add(-5 * time.Second), "just now"},
		{"one minute", time.Now().Add(-1 * time.Minute), "1 minute ago"},
		{"minutes", time.Now().Add(-5 * time.Minute), "5 minutes ago"},
		{"one hour", time.Now().Add(-1 * time.Hour), "1 hour ago"},
		{"hours", time.Now().Add(-5 * time.Hour), "5 hours ago"},
		{"one day", time.Now().Add(-24 * time.Hour), "1 day ago"},
		{"days", time.Now().Add(-72 * time.Hour), "3 days ago"},
	}
	for _, tt := range agoTests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatTimeAgo(tt.when); got != tt.want {
				t.Fatalf("formatTimeAgo() = %q, want %q", got, tt.want)
			}
		})
	}

	fixedTests := map[string]string{
		"":       "",
		" 1.2.3": ">= 1.2.3",
		">= 2":   ">= 2",
		"< 3":    "< 3",
		"= 4":    "= 4",
	}
	for input, want := range fixedTests {
		if got := formatFixedIn(input); got != want {
			t.Fatalf("formatFixedIn(%q) = %q, want %q", input, got, want)
		}
	}

	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "unknown"} {
		if got := severityClass(severity); got == "" {
			t.Fatalf("severityClass(%q) returned empty class", severity)
		}
	}
	for _, status := range []string{"healthy", "warning", "error", "configured", "running", "pending", "disabled", "unknown"} {
		if got := statusClass(status); got == "" {
			t.Fatalf("statusClass(%q) returned empty class", status)
		}
	}

	truncateTests := map[string]string{
		"abc":       "abc",
		"abcdef|3":  "abc",
		"abcdef|4":  "a...",
		"abcdef|10": "abcdef",
	}
	if got := truncate("abc", 10); got != truncateTests["abc"] {
		t.Fatalf("truncate short = %q", got)
	}
	if got := truncate("abcdef", 3); got != truncateTests["abcdef|3"] {
		t.Fatalf("truncate max 3 = %q", got)
	}
	if got := truncate("abcdef", 4); got != truncateTests["abcdef|4"] {
		t.Fatalf("truncate max 4 = %q", got)
	}
	if got := truncate("abcdef", 10); got != truncateTests["abcdef|10"] {
		t.Fatalf("truncate max 10 = %q", got)
	}
	if got := seq(4); !reflect.DeepEqual(got, []int{0, 1, 2, 3}) {
		t.Fatalf("seq(4) = %#v", got)
	}
}

func TestDefaultFuncMapIncludesTemplateHelpers(t *testing.T) {
	funcs := defaultFuncMap()
	if funcs["formatTime"] == nil || funcs["formatTimeAgo"] == nil || funcs["statusClass"] == nil {
		t.Fatalf("defaultFuncMap missing expected helper: %#v", funcs)
	}
	if got := funcs["add"].(func(int, int) int)(2, 3); got != 5 {
		t.Fatalf("add helper = %d, want 5", got)
	}
	if got := funcs["sub"].(func(int, int) int)(7, 4); got != 3 {
		t.Fatalf("sub helper = %d, want 3", got)
	}
}

func TestRendererReturnsTemplateErrors(t *testing.T) {
	renderer := testRenderer()

	var out strings.Builder
	if err := renderer.Render(&out, "missing.html", nil); err == nil || !strings.Contains(err.Error(), "read page") {
		t.Fatalf("Render(missing) error = %v, want read page error", err)
	}
	if err := renderer.RenderPartial(&out, "feeds.html", "missing-block", nil); err == nil || !strings.Contains(err.Error(), "missing-block") {
		t.Fatalf("RenderPartial(missing block) error = %v, want missing block error", err)
	}
}

func TestSortStringsOrdersInPlace(t *testing.T) {
	values := []string{"osv", "ghsa", "reversinglabs", "cisa"}
	sortStrings(values)
	if !reflect.DeepEqual(values, []string{"cisa", "ghsa", "osv", "reversinglabs"}) {
		t.Fatalf("sortStrings() = %#v", values)
	}

	sortStrings(nil)
	sortStrings([]string{"only"})
}

type scansStore struct {
	*mockStore
	daily []db.DailyScanStats
	scans []db.ScanLogEntry
}

func (s scansStore) CountScansByDay(_ context.Context, days int) ([]db.DailyScanStats, error) {
	if days != 7 {
		panic("unexpected days")
	}
	return s.daily, nil
}

func (s scansStore) ListRecentScans(_ context.Context, limit int) ([]db.ScanLogEntry, error) {
	if limit != 50 {
		panic("unexpected limit")
	}
	return s.scans, nil
}

func TestHandleScansRendersTrendsAndRecentScans(t *testing.T) {
	now := time.Now().UTC()
	store := scansStore{
		mockStore: &mockStore{},
		daily: []db.DailyScanStats{
			{Date: now.AddDate(0, 0, -1), ScanCount: 2, FindingsCount: 0},
			{Date: now, ScanCount: 3, FindingsCount: 10},
			{Date: now.AddDate(0, 0, -2), ScanCount: 1, FindingsCount: 1},
		},
		scans: []db.ScanLogEntry{
			{ScanID: "scan-1", RepoName: "repo", Branch: "main", ScannedAt: now, PackagesCount: 4, FindingsCount: 2, DurationMs: 123},
		},
	}
	handler := HandleScans(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HandleScans status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Scan Activity", "Recent Scans", "repo", "scan-1"} {
		if !strings.Contains(body, want) {
			t.Fatalf("HandleScans response missing %q:\n%s", want, body)
		}
	}
}

func TestHandleScansStoreErrorsRenderEmptyPage(t *testing.T) {
	handler := HandleScans(&mockStore{
		dailyErr: errors.New("daily unavailable"),
		scansErr: errors.New("scans unavailable"),
	}, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HandleScans error status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "No scan activity yet.") || !strings.Contains(body, "No scans recorded yet.") {
		t.Fatalf("HandleScans error response missing expected sections:\n%s", body)
	}
}
