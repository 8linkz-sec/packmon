package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/db"
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
		{"future minute", time.Now().Add(2*time.Minute + 5*time.Second), "in 2 minutes"},
		{"future hour", time.Now().Add(2*time.Hour + 5*time.Minute), "in 2 hours"},
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
	if got := truncate("ääääää", 4); got != "ä..." || !utf8.ValidString(got) {
		t.Fatalf("truncate UTF-8 = %q valid=%v, want %q", got, utf8.ValidString(got), "ä...")
	}
	if got := seq(4); !reflect.DeepEqual(got, []int{0, 1, 2, 3}) {
		t.Fatalf("seq(4) = %#v", got)
	}
	if got := findingTypeLabels("supply_chain_risk, malicious, vulnerability, lifecycle, unknown"); !reflect.DeepEqual(got, []string{"Supply-chain risk", "Malicious package", "Vulnerability", "Lifecycle", "unknown"}) {
		t.Fatalf("findingTypeLabels() = %#v", got)
	}
}

func TestDefaultFuncMapIncludesTemplateHelpers(t *testing.T) {
	funcs := defaultFuncMap(LayoutLinks{PrivacyURL: "/privacy", LegalURL: "/legal"})
	if funcs["formatTime"] == nil || funcs["formatTimeAgo"] == nil || funcs["statusClass"] == nil || funcs["findingLabels"] == nil || funcs["dict"] == nil {
		t.Fatalf("defaultFuncMap missing expected helper: %#v", funcs)
	}
	dictFn, ok := funcs["dict"].(func(...any) (map[string]any, error))
	if !ok {
		t.Fatalf("dict helper has unexpected type %T", funcs["dict"])
	}
	dict, err := dictFn("Variant", "warning", "Icon", true)
	if err != nil {
		t.Fatalf("dict helper error = %v", err)
	}
	if dict["Variant"] != "warning" || dict["Icon"] != true {
		t.Fatalf("dict helper = %#v, want populated map", dict)
	}
	if _, err := dictFn("odd"); err == nil {
		t.Fatal("dict helper odd argument count error = nil, want error")
	}
	if _, err := dictFn(3, "bad"); err == nil {
		t.Fatal("dict helper non-string key error = nil, want error")
	}
	if got := funcs["add"].(func(int, int) int)(2, 3); got != 5 {
		t.Fatalf("add helper = %d, want 5", got)
	}
	if got := funcs["sub"].(func(int, int) int)(7, 4); got != 3 {
		t.Fatalf("sub helper = %d, want 3", got)
	}
	if got := funcs["privacyURL"].(func() string)(); got != "/privacy" {
		t.Fatalf("privacyURL helper = %q, want /privacy", got)
	}
	if got := funcs["legalURL"].(func() string)(); got != "/legal" {
		t.Fatalf("legalURL helper = %q, want /legal", got)
	}
}

func TestRenderHelperFutureAndBoundaryBranches(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cases := []struct {
		name string
		when time.Time
		want string
	}{
		{"future less than minute", now.Add(30 * time.Second), "in less than a minute"},
		{"future one minute", now.Add(time.Minute + time.Second), "in 1 minute"},
		{"future one hour", now.Add(time.Hour + time.Minute), "in 1 hour"},
		{"future one day", now.Add(24*time.Hour + time.Minute), "in 1 day"},
		{"future days", now.Add(72*time.Hour + time.Minute), "in 3 days"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatTimeAgo(tt.when); got != tt.want {
				t.Fatalf("formatTimeAgo() = %q, want %q", got, tt.want)
			}
		})
	}
	if got := seq(0); len(got) != 0 {
		t.Fatalf("seq(0) = %#v, want empty", got)
	}
}

func TestRendererCacheAndParseErrorBranches(t *testing.T) {
	t.Parallel()

	okFS := fstest.MapFS{
		"templates/layout.html": {Data: []byte(`{{define "layout"}}<main>{{template "content" .}}</main>{{end}}`)},
		"templates/page.html":   {Data: []byte(`{{define "content"}}{{.Name}}{{end}}`)},
	}
	renderer := NewRenderer(okFS, false)
	var out strings.Builder
	if err := renderer.Render(&out, "page.html", map[string]string{"Name": "first"}); err != nil {
		t.Fatalf("Render(first) error = %v", err)
	}
	if err := renderer.Render(&out, "page.html", map[string]string{"Name": "second"}); err != nil {
		t.Fatalf("Render(cached) error = %v", err)
	}
	if len(renderer.cache) != 1 {
		t.Fatalf("cache len = %d, want 1", len(renderer.cache))
	}

	err := NewRenderer(fstest.MapFS{}, false).Render(&out, "page.html", nil)
	if err == nil || !strings.Contains(err.Error(), "read layout") {
		t.Fatalf("Render(missing layout) error = %v", err)
	}
	err = NewRenderer(fstest.MapFS{
		"templates/layout.html": {Data: []byte(`{{define`)},
		"templates/page.html":   {Data: []byte(`{{define "content"}}ok{{end}}`)},
	}, true).Render(&out, "page.html", nil)
	if err == nil || !strings.Contains(err.Error(), "parse layout") {
		t.Fatalf("Render(bad layout) error = %v", err)
	}
	err = NewRenderer(fstest.MapFS{
		"templates/layout.html": {Data: []byte(`{{define "layout"}}{{template "content" .}}{{end}}`)},
		"templates/page.html":   {Data: []byte(`{{define`)},
	}, true).Render(&out, "page.html", nil)
	if err == nil || !strings.Contains(err.Error(), "parse page") {
		t.Fatalf("Render(bad page) error = %v", err)
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
	fullScanID := "scan-1234567890abcdef1234567890abcdef"
	store := scansStore{
		mockStore: &mockStore{},
		daily: []db.DailyScanStats{
			{Date: now.AddDate(0, 0, -1), ScanCount: 2, FindingsCount: 0},
			{Date: now, ScanCount: 3, FindingsCount: 10},
			{Date: now.AddDate(0, 0, -2), ScanCount: 1, FindingsCount: 1},
		},
		scans: []db.ScanLogEntry{
			{ScanID: fullScanID, RepoName: "student-repo-secret", Branch: "main", ScannedAt: now, PackagesCount: 4, FindingsCount: 2, DurationMs: 123},
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
	for _, want := range []string{
		"Scan Activity",
		"Recent Scans",
		"Date (UTC)",
		"Relative findings",
		`<progress value="100" max="100"`,
		`class="scan-findings-meter scan-findings-meter--risk"`,
		`aria-label="10 findings; relative bar 100% of the highest finding day in this table"`,
		fullScanID,
		`title="` + fullScanID + `"`,
		"break-all",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("HandleScans response missing %q:\n%s", want, body)
		}
	}
	for _, notWant := range []string{"student-repo-secret", ">Repo<", `<th class="pb-2"></th>`} {
		if strings.Contains(body, notWant) {
			t.Fatalf("HandleScans response contains %q:\n%s", notWant, body)
		}
	}
	if strings.Contains(body, "scan-1234...") {
		t.Fatalf("HandleScans response contains truncated scan ID:\n%s", body)
	}
}

func TestHandleScansStoreErrorsRenderLoadErrors(t *testing.T) {
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
	body := rec.Body.String()
	for _, want := range []string{
		"Scan activity could not be loaded",
		"Recent scans could not be loaded",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("HandleScans error response missing %q:\n%s", want, body)
		}
	}
	for _, notWant := range []string{
		"No scan activity yet.",
		"No scans recorded yet.",
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("HandleScans error response rendered empty state %q:\n%s", notWant, body)
		}
	}
}
