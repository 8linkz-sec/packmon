package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestHandleScansWithOptionsDefaultsAdminNavigationAndKeepsRoutePagination(t *testing.T) {
	now := time.Now().UTC()
	scans := make([]db.ScanLogEntry, 2*recentScansPageSize+1)
	for i := range scans {
		scans[i] = db.ScanLogEntry{
			ScanID:    fmt.Sprintf("admin-scan-%02d", i),
			ScannedAt: now.Add(-time.Duration(i) * time.Minute),
		}
	}
	store := &mockStore{
		dailyStats:  []db.DailyScanStats{{Date: now, ScanCount: 1}},
		recentScans: scans,
	}
	handler := HandleScansWithOptions(store, testRenderer(), discardLogger(), ScansOptions{
		AdminPage: true,
		CSRFToken: "csrf-scans-contract",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/scans?offset=50", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("admin scans status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if store.lastScansLimit != recentScansPageSize+1 || store.lastScansOffset != recentScansPageSize {
		t.Fatalf("admin scans requested limit/offset = %d/%d, want %d/%d", store.lastScansLimit, store.lastScansOffset, recentScansPageSize+1, recentScansPageSize)
	}

	body := rec.Body.String()
	for _, want := range []string{
		`action="/admin/logout"`,
		`name="_csrf" value="csrf-scans-contract"`,
		`href="/admin/scans?offset=100"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin scans response missing %q:\n%s", want, body)
		}
	}
	if !regexp.MustCompile(`(?s)<a\s+href="/admin/scans"\s+aria-current="page"[^>]*>Scans</a>`).MatchString(body) {
		t.Fatalf("admin scans response does not mark the Scans admin-nav anchor current:\n%s", body)
	}
	if !regexp.MustCompile(`(?s)<a href="/admin/scans" class="[^"]*">Newer scans</a>`).MatchString(body) {
		t.Fatalf("admin scans response does not preserve the admin route on the Newer scans pagination anchor:\n%s", body)
	}
}

func TestScansPageURLUsesCanonicalPathForEmptyOrFirstPage(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		offset int
		want   string
	}{
		{name: "empty path defaults to scans", want: "/scans"},
		{name: "empty path with later page", offset: recentScansPageSize, want: "/scans?offset=50"},
		{name: "provided path on first page", path: "/admin/scans", want: "/admin/scans"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scansPageURL(tt.path, tt.offset); got != tt.want {
				t.Fatalf("scansPageURL(%q, %d) = %q, want %q", tt.path, tt.offset, got, tt.want)
			}
		})
	}
}
