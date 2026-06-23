package logsafe

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	redactedURL      = "(redacted-url)"
	truncationMarker = "...[truncated]"
	unmatchedRoute   = "(unmatched-route)"
)

var (
	httpURLPattern          = regexp.MustCompile(`https?://[^\s<>"']+`)
	bearerTokenPattern      = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	secretAssignmentPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|token|secret|sig|signature|x-amz-signature)(\s*[:=]\s*)([^\s;&]+)`)
	windowsPathPattern      = regexp.MustCompile(`(?i)\b[A-Z]:\\(?:[^\\\s]+\\){2,}[^\\\s]+`)
	unixPathPattern         = regexp.MustCompile(`(^|[\s=:])/(?:[^/\s]+/){2,}[^/\s]+`)
)

// RedactURL returns a display-safe URL that keeps only scheme, host, and a
// generic path marker. Userinfo, path details, query strings, and fragments can
// carry bearer tokens for webhook and automation endpoints.
func RedactURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return redactedURL
	}

	display := url.URL{
		Scheme: parsed.Scheme,
		Host:   parsed.Host,
	}
	path := strings.Trim(parsed.EscapedPath(), "/")
	switch {
	case path != "":
		display.Path = "/..."
	case parsed.EscapedPath() == "/":
		display.Path = "/"
	}
	return display.String()
}

// RedactURLError formats URL-related HTTP errors without retaining the request
// URL embedded by net/http's *url.Error.
func RedactURLError(err error) string {
	return RedactURLRequestError(err, "webhook URL")
}

// RedactURLRequestError formats URL-related request errors without retaining
// the request URL embedded by net/http's *url.Error. The label should describe
// the configured endpoint, for example "server URL" or "webhook URL".
func RedactURLRequestError(err error, label string) string {
	if err == nil {
		return ""
	}
	label = strings.TrimSpace(label)
	if label == "" {
		label = "URL"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		op := strings.TrimSpace(urlErr.Op)
		if op == "" {
			op = "request"
		}
		if urlErr.Err == nil {
			return strings.TrimSpace(op + " " + label + " failed")
		}
		return strings.TrimSpace(op + " " + label + ": " + RedactDiagnosticMessage(urlErr.Err.Error()))
	}
	return RedactDiagnosticMessage(err.Error())
}

// RedactDiagnosticMessage removes secret-bearing details from mixed diagnostic
// text before it is shown to users. It preserves the failure class while hiding
// URL credentials/query strings, bearer-like tokens, and local filesystem paths.
func RedactDiagnosticMessage(raw string) string {
	msg := strings.TrimSpace(raw)
	if msg == "" {
		return ""
	}

	msg = httpURLPattern.ReplaceAllStringFunc(msg, redactURLInMessage)
	msg = bearerTokenPattern.ReplaceAllString(msg, "Bearer [redacted]")
	msg = secretAssignmentPattern.ReplaceAllString(msg, "$1$2[redacted]")
	msg = windowsPathPattern.ReplaceAllString(msg, "(redacted-path)")
	msg = unixPathPattern.ReplaceAllString(msg, "${1}(redacted-path)")
	return msg
}

// BoundedValue strips control characters, collapses whitespace, and truncates
// a log value to at most max bytes while preserving valid UTF-8.
func BoundedValue(raw string, max int) string {
	if max <= 0 {
		return ""
	}
	value := strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, raw)), " ")
	if len(value) <= max {
		return value
	}
	return truncateUTF8(value, max)
}

// BoundedDiagnosticValue redacts common secret-bearing diagnostic patterns
// before applying the generic log-value bound.
func BoundedDiagnosticValue(raw string, max int) string {
	return BoundedValue(RedactDiagnosticMessage(raw), max)
}

// RequestPathLabel returns a stable, low-cardinality request path label for
// logs. Dynamic path segments can contain package names, filesystem paths, or
// tokens, so labels preserve only the registered route shape.
func RequestPathLabel(raw string) string {
	path := strings.TrimSpace(raw)
	if path == "" || path == "/" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}

	switch path {
	case "/healthz", "/readyz", "/version", "/metrics",
		"/search", "/feeds", "/privacy",
		"/admin", "/admin/login", "/admin/logout",
		"/admin/feeds", "/admin/feeds/save", "/admin/feeds/reset", "/admin/feeds/sync",
		"/admin/queue", "/admin/queue/purge", "/admin/queue/priority", "/admin/queue/pause",
		"/admin/queue/resume", "/admin/queue/retry", "/admin/queue/clear",
		"/admin/keys", "/admin/keys/create", "/admin/keys/revoke", "/admin/keys/delete",
		"/admin/advisories", "/admin/advisories/create", "/admin/advisories/delete",
		"/admin/audit", "/admin/settings", "/admin/settings/system", "/admin/settings/password",
		"/.well-known/change-password":
		return path
	case "/api/v1/check", "/api/v1/feeds/status", "/api/v1/sync":
		return path
	}

	segments := splitPathSegments(path)
	switch {
	case len(segments) >= 1 && segments[0] == "static":
		return "/static/..."
	case isAPIFeedImportPath(segments):
		return "/api/v1/feeds/{feed}/import"
	case isAPIPackagePath(segments):
		if segments[len(segments)-1] == "refresh" && len(segments) >= 6 {
			return "/api/v1/packages/{ecosystem}/{name...}/refresh"
		}
		return "/api/v1/packages/{ecosystem}/{name...}"
	case isAPIV1Path(segments):
		return "/api/v1/..."
	case len(segments) >= 1 && segments[0] == "admin":
		return "/admin/..."
	case len(segments) >= 1 && segments[0] == "package":
		return "/package/{ecosystem}/{name...}"
	}
	return unmatchedRoute
}

func truncateUTF8(value string, max int) string {
	if max <= 0 {
		return ""
	}
	if max <= len(truncationMarker) {
		return truncationMarker[:max]
	}
	limit := max - len(truncationMarker)
	out := make([]rune, 0, limit)
	used := 0
	for _, r := range value {
		size := utf8.RuneLen(r)
		if size < 0 {
			size = len(string(r))
		}
		if used+size > limit {
			break
		}
		out = append(out, r)
		used += size
	}
	return string(out) + truncationMarker
}

func redactURLInMessage(raw string) string {
	core, suffix := splitTrailingURLPunctuation(raw)
	return RedactURL(core) + suffix
}

func splitTrailingURLPunctuation(raw string) (string, string) {
	core := raw
	suffix := ""
	for core != "" {
		r, size := utf8.DecodeLastRuneInString(core)
		if !strings.ContainsRune(".,;:)]}", r) {
			break
		}
		suffix = core[len(core)-size:] + suffix
		core = core[:len(core)-size]
	}
	return core, suffix
}

func splitPathSegments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "/")
	out := parts[:0]
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func isAPIV1Path(segments []string) bool {
	return len(segments) >= 3 && segments[0] == "api" && segments[1] == "v1"
}

func isAPIFeedImportPath(segments []string) bool {
	return len(segments) == 5 &&
		segments[0] == "api" &&
		segments[1] == "v1" &&
		segments[2] == "feeds" &&
		segments[4] == "import"
}

func isAPIPackagePath(segments []string) bool {
	return len(segments) >= 5 &&
		segments[0] == "api" &&
		segments[1] == "v1" &&
		segments[2] == "packages"
}
