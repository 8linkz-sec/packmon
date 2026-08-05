package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSafeAdminReturnTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want string
	}{
		{raw: "/admin/settings", want: "/admin/settings"},
		{raw: "/admin/feeds?partial=runtime", want: "/admin/feeds"},
		{raw: "/admin/feeds?partial=runtime&err=stale", want: "/admin/feeds?err=stale"},
		{raw: "/admin", want: "/admin"},
		{raw: "/admin/login", want: ""},
		{raw: "/search", want: ""},
		{raw: "https://evil.example/admin/settings", want: ""},
		{raw: "//evil.example/admin/settings", want: ""},
		{raw: "/admin/../search", want: ""},
		{raw: "/admin/settings#fragment", want: "/admin/settings"},
	}

	for _, tt := range tests {
		if got := SafeAdminReturnTarget(tt.raw); got != tt.want {
			t.Fatalf("SafeAdminReturnTarget(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestSafeSameOriginRedirectTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw      string
		fallback string
		want     string
	}{
		{raw: "/admin/queue?msg=Saved", fallback: "/", want: "/admin/queue?msg=Saved"},
		{raw: "/admin/settings#fragment", fallback: "/", want: "/admin/settings"},
		{raw: "https://evil.example/admin", fallback: "/admin/", want: "/admin/"},
		{raw: "//evil.example/admin", fallback: "/admin/", want: "/admin/"},
		{raw: "admin", fallback: "/admin/", want: "/admin/"},
		{raw: "", fallback: "https://evil.example/admin", want: "/"},
	}

	for _, tt := range tests {
		if got := SafeSameOriginRedirectTarget(tt.raw, tt.fallback); got != tt.want {
			t.Fatalf("SafeSameOriginRedirectTarget(%q, %q) = %q, want %q", tt.raw, tt.fallback, got, tt.want)
		}
	}
}

func TestRedirectSameOriginUsesSanitizedLocation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "safe admin path", target: "/admin/queue?msg=Saved", want: "/admin/queue?msg=Saved"},
		{name: "unsafe absolute url", target: "https://evil.example/admin", want: "/"},
		{name: "unsafe protocol relative url", target: "//evil.example/admin", want: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/admin", nil)

			RedirectSameOrigin(rec, req, tt.target, http.StatusSeeOther)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
			}
			if got := rec.Header().Get("Location"); got != tt.want {
				t.Fatalf("Location = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAdminLoginRedirectTarget(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/admin/settings?tab=password", nil)
	if got := AdminLoginRedirectTarget(req); got != "/admin/login?next=%2Fadmin%2Fsettings%3Ftab%3Dpassword" {
		t.Fatalf("AdminLoginRedirectTarget() = %q", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/settings/password", nil)
	if got := AdminLoginRedirectTarget(req); got != "/admin/login" {
		t.Fatalf("AdminLoginRedirectTarget(POST) = %q, want /admin/login", got)
	}
}
