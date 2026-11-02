package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestAdminLoginRedirectTargetRejectsMissingOrUnsafeRequestTargets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  *http.Request
		want string
	}{
		{name: "nil request", want: "/admin/login"},
		{name: "nil URL", req: &http.Request{Method: http.MethodGet}, want: "/admin/login"},
		{name: "head request", req: httptest.NewRequest(http.MethodHead, "/admin/queue?msg=Saved", nil), want: "/admin/login?next=%2Fadmin%2Fqueue%3Fmsg%3DSaved"},
		{name: "unsafe request URI", req: &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "//evil.example/admin"}}, want: "/admin/login"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AdminLoginRedirectTarget(tt.req); got != tt.want {
				t.Fatalf("AdminLoginRedirectTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAdminLoginURLRejectsUnsafeTarget(t *testing.T) {
	t.Parallel()

	for name, target := range map[string]string{
		"empty":             "",
		"external absolute": "https://evil.example/admin",
		"protocol relative": "//evil.example/admin",
		"public path":       "/search",
		"login loop":        "/admin/login",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := AdminLoginURL(target); got != AdminLoginPath {
				t.Fatalf("AdminLoginURL(%q) = %q, want %q", target, got, AdminLoginPath)
			}
		})
	}
}

func TestSameOriginTargetRejectsMalformedEscapes(t *testing.T) {
	t.Parallel()

	if got := SafeAdminReturnTarget("/admin/%zz"); got != "" {
		t.Fatalf("SafeAdminReturnTarget() = %q, want empty", got)
	}
	if got := SafeSameOriginRedirectTarget("/admin/%zz", "/"); got != "/" {
		t.Fatalf("SafeSameOriginRedirectTarget() = %q, want /", got)
	}
}

func TestAdminReturnTargetsNormalizeAdversarialInputs(t *testing.T) {
	t.Parallel()

	adminCases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "whitespace dot query and fragment", raw: "  /admin/./settings?tab=security#ignored  ", want: "/admin/settings?tab=security"},
		{name: "encoded traversal leaves admin", raw: "/admin%2F..%2Fsearch", want: ""},
		{name: "encoded login loop", raw: "/admin%2Flogin", want: ""},
		{name: "encoded dot and repeated separator", raw: "/admin/%2e/queue//", want: "/admin/queue"},
		{name: "encoded backslash is preserved", raw: "/admin/%5Cprivate", want: "/admin/%5Cprivate"},
		{name: "literal control is rejected", raw: "/admin/settings\x00private", want: ""},
	}
	for _, tc := range adminCases {
		t.Run("admin "+tc.name, func(t *testing.T) {
			t.Parallel()
			got := SafeAdminReturnTarget(tc.raw)
			if got != tc.want {
				t.Fatalf("SafeAdminReturnTarget(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			if got == "" {
				return
			}
			parsed, err := url.Parse(got)
			if err != nil || parsed.IsAbs() || parsed.Host != "" {
				t.Fatalf("normalized admin target is not same-origin: %q (%v)", got, err)
			}
			if parsed.Path != "/admin" && !strings.HasPrefix(parsed.Path, "/admin/") {
				t.Fatalf("normalized admin target escaped admin namespace: %q", got)
			}
			if parsed.Path == AdminLoginPath {
				t.Fatalf("normalized admin target created a login loop: %q", got)
			}
			if again := SafeAdminReturnTarget(got); again != got {
				t.Fatalf("admin normalization is not idempotent: first %q, second %q", got, again)
			}
		})
	}

	sameOriginCases := []struct {
		name     string
		raw      string
		fallback string
		want     string
	}{
		{name: "whitespace repeated dot and fragment", raw: "  /admin//./settings?x=1#ignored  ", fallback: "/", want: "/admin/settings?x=1"},
		{name: "encoded leading separators", raw: "/%2F%2Fevil.example/admin", fallback: "/", want: "/evil.example/admin"},
		{name: "encoded backslash is preserved", raw: "/%5Cevil.example/admin", fallback: "/", want: "/%5Cevil.example/admin"},
		{name: "encoded dot keeps trailing slash", raw: "/admin/%2e/queue/", fallback: "/", want: "/admin/queue/"},
		{name: "literal control selects safe fallback", raw: "/admin/settings\x00private", fallback: "/admin/safe", want: "/admin/safe"},
		{name: "literal control and unsafe fallback select root", raw: "/admin/settings\x00private", fallback: "https://evil.example", want: "/"},
	}
	for _, tc := range sameOriginCases {
		t.Run("same origin "+tc.name, func(t *testing.T) {
			t.Parallel()
			got := SafeSameOriginRedirectTarget(tc.raw, tc.fallback)
			if got != tc.want {
				t.Fatalf("SafeSameOriginRedirectTarget(%q, %q) = %q, want %q", tc.raw, tc.fallback, got, tc.want)
			}
			parsed, err := url.Parse(got)
			if err != nil || parsed.IsAbs() || parsed.Host != "" {
				t.Fatalf("normalized redirect target is not same-origin: %q (%v)", got, err)
			}
			if again := SafeSameOriginRedirectTarget(got, "/different"); again != got {
				t.Fatalf("same-origin normalization is not idempotent: first %q, second %q", got, again)
			}
		})
	}
}

func TestRedirectSameOriginNormalizesAdversarialLocation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		target string
		want   string
	}{
		{name: "canonical whitespace and dot", target: "  /admin/./settings?x=1#ignored  ", want: "/admin/settings?x=1"},
		{name: "encoded leading separators", target: "/%2F%2Fevil.example/admin", want: "/evil.example/admin"},
		{name: "encoded backslash", target: "/%5Cevil.example/admin", want: "/%5Cevil.example/admin"},
		{name: "literal control", target: "/admin/settings\x00private", want: "/"},
		{name: "malformed escape", target: "/admin/%zz", want: "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/admin", nil)

			RedirectSameOrigin(rec, req, tc.target, http.StatusSeeOther)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
			}
			location := rec.Header().Get("Location")
			if location != tc.want {
				t.Fatalf("Location = %q, want %q", location, tc.want)
			}
			parsed, err := url.Parse(location)
			if err != nil || parsed.IsAbs() || parsed.Host != "" {
				t.Fatalf("Location is not same-origin: %q (%v)", location, err)
			}
		})
	}
}
