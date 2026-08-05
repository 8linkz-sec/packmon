package auth

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

const AdminLoginPath = "/admin/login"

// AdminLoginRedirectTarget returns the login URL for a request that needs an
// admin session, preserving only safe same-origin admin return targets.
func AdminLoginRedirectTarget(r *http.Request) string {
	if r == nil || r.URL == nil {
		return AdminLoginPath
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return AdminLoginPath
	}
	return AdminLoginURL(SafeAdminReturnTarget(r.URL.RequestURI()))
}

// AdminLoginURL returns /admin/login with a next query parameter when the
// supplied target is a safe same-origin admin path.
func AdminLoginURL(target string) string {
	target = SafeAdminReturnTarget(target)
	if target == "" {
		return AdminLoginPath
	}
	values := url.Values{}
	values.Set("next", target)
	return AdminLoginPath + "?" + values.Encode()
}

// RedirectSameOrigin redirects only to a same-origin absolute path. Unsafe
// absolute, protocol-relative, or malformed targets fall back to "/".
func RedirectSameOrigin(w http.ResponseWriter, r *http.Request, target string, code int) {
	target = SafeSameOriginRedirectTarget(target, "/")
	http.Redirect(w, r, target, code) // #nosec G710 -- target is normalized to a same-origin path by SafeSameOriginRedirectTarget.
}

// SafeSameOriginRedirectTarget returns a same-origin absolute-path redirect
// target, or a safe fallback when raw is unsafe.
func SafeSameOriginRedirectTarget(raw, fallback string) string {
	if target := safeSameOriginPath(raw); target != "" {
		return target
	}
	if target := safeSameOriginPath(fallback); target != "" {
		return target
	}
	return "/"
}

// SafeAdminReturnTarget validates a same-origin admin return target and strips
// fragments. Absolute URLs, protocol-relative URLs, login loops, and non-admin
// paths are rejected.
func SafeAdminReturnTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return ""
	}
	cleanPath := path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	if !isSafeAdminReturnPath(cleanPath) {
		return ""
	}
	query := parsed.Query()
	if cleanPath == "/admin/feeds" && query.Get("partial") != "" {
		query.Del("partial")
	}
	out := url.URL{Path: cleanPath, RawQuery: query.Encode()}
	return out.String()
}

func safeSameOriginPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return ""
	}
	cleanPath := path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	if strings.HasSuffix(parsed.Path, "/") && cleanPath != "/" {
		cleanPath += "/"
	}
	out := url.URL{Path: cleanPath, RawQuery: parsed.RawQuery}
	return out.String()
}

func isSafeAdminReturnPath(pathValue string) bool {
	if pathValue == AdminLoginPath {
		return false
	}
	return pathValue == "/admin" || strings.HasPrefix(pathValue, "/admin/")
}
