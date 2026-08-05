package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

// TestAdminFeedLastSyncStatusClassCoversEveryStatus pins the badge class for
// every sync status the feed page can render. A status without a class falls
// through to the warning badge, which would show a healthy feed as degraded.
func TestAdminFeedLastSyncStatusClassCoversEveryStatus(t *testing.T) {
	t.Parallel()

	for status, want := range map[string]string{
		db.FeedSyncStatusSuccess:        "pm-badge-status-healthy",
		db.FeedSyncStatusRunning:        "pm-badge-status-running",
		db.FeedSyncStatusPending:        "pm-badge-status-pending",
		db.FeedSyncStatusError:          "pm-badge-status-error",
		db.FeedSyncStatusPermanentError: "pm-badge-status-error",
		db.FeedSyncStatusRejected:       "pm-badge-status-error",
		db.FeedSyncStatusExternal:       "pm-badge-status-configured",
		db.FeedSyncStatusDisabled:       "pm-badge-status-disabled",
		db.FeedSyncStatusSkipped:        "pm-badge-status-disabled",
		"":                              "pm-badge-status-default",
	} {
		if got := adminFeedLastSyncStatusClass(status); got != want {
			t.Errorf("adminFeedLastSyncStatusClass(%q) = %q, want %q", status, got, want)
		}
	}

	// Casing and padding must not fall through to the warning badge.
	if got := adminFeedLastSyncStatusClass("  SUCCESS  "); got != "pm-badge-status-healthy" {
		t.Errorf("adminFeedLastSyncStatusClass(padded) = %q, want the healthy badge", got)
	}
	// A status the UI does not know about must be visible, not silently healthy.
	if got := adminFeedLastSyncStatusClass("something-new"); got != "pm-badge-status-warning" {
		t.Errorf("adminFeedLastSyncStatusClass(unknown) = %q, want the warning badge", got)
	}
}

// TestAdminFeedFormRowUpdatedAtClassIsNeutral documents that the updated-at cell
// carries no status colour, so a stale timestamp cannot masquerade as a health
// signal.
func TestAdminFeedFormRowUpdatedAtClassIsNeutral(t *testing.T) {
	t.Parallel()

	if got := (adminFeedFormRow{}).UpdatedAtClass(); got != "pm-badge-status-default" {
		t.Fatalf("UpdatedAtClass() = %q, want the neutral badge", got)
	}
}

// TestAdminPostRedirectPathReturnsSectionForEveryForm keeps a failed admin POST
// on the page the user submitted from. Falling back to /admin/ would lose the
// section context and the error message anchor.
func TestAdminPostRedirectPathReturnsSectionForEveryForm(t *testing.T) {
	t.Parallel()

	for path, want := range map[string]string{
		"/admin/feeds/save":         "/admin/feeds",
		"/admin/feeds/sync":         "/admin/feeds",
		"/admin/queue/retry":        "/admin/queue",
		"/admin/keys/create":        "/admin/keys",
		"/admin/advisories/save":    "/admin/advisories",
		"/admin/settings/password":  "/admin/settings",
		"/admin/unknown/submission": "/admin/",
		"/admin/":                   "/admin/",
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if got := adminPostRedirectPath(req, adminPostGate{}); got != want {
			t.Errorf("adminPostRedirectPath(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestAdminPostRedirectPathPrefersBootstrapGate covers the override: while the
// bootstrap password is unchanged, every form has to funnel back to the gate
// rather than to its own section.
func TestAdminPostRedirectPathPrefersBootstrapGate(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/admin/feeds/save", nil)
	gate := adminPostGate{bootstrapRedirectPath: "/admin/settings"}
	if got := adminPostRedirectPath(req, gate); got != "/admin/settings" {
		t.Fatalf("adminPostRedirectPath(bootstrap gate) = %q, want the gate path", got)
	}
}

// TestAdminPostRedirectPathToleratesMissingRequest guards the nil paths, which a
// panic here would turn into a 500 on an already-failing form submission.
func TestAdminPostRedirectPathToleratesMissingRequest(t *testing.T) {
	t.Parallel()

	if got := adminPostRedirectPath(nil, adminPostGate{}); got != "/admin/" {
		t.Fatalf("adminPostRedirectPath(nil request) = %q, want /admin/", got)
	}
	if got := adminPostRedirectPath(&http.Request{}, adminPostGate{}); got != "/admin/" {
		t.Fatalf("adminPostRedirectPath(nil URL) = %q, want /admin/", got)
	}
}

// TestRedirectAdminFormErrorRejectsOffSiteTargets is the security-relevant half:
// the error redirect must never leave the admin area, and must never be turned
// into a protocol-relative URL pointing at another host.
func TestRedirectAdminFormErrorRejectsOffSiteTargets(t *testing.T) {
	t.Parallel()

	for _, target := range []string{"", "//evil.example", "https://evil.example", "/other/section"} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/feeds/save", nil)
		redirectAdminFormError(recorder, req, target, "boom")

		location := recorder.Header().Get("Location")
		if !strings.HasPrefix(location, "/admin/") {
			t.Errorf("redirectAdminFormError(%q) redirected to %q, want an /admin/ path", target, location)
		}
		if strings.HasPrefix(location, "//") {
			t.Errorf("redirectAdminFormError(%q) produced a protocol-relative target %q", target, location)
		}
	}
}
