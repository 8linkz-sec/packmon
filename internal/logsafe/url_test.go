package logsafe

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestRedactURLDropsSecretBearingComponents(t *testing.T) {
	t.Parallel()

	raw := "https://user-secret:pass-secret@hooks.example/services/path-token?sig=query-secret#frag-secret" //nolint:gosec // fake secret-bearing URL verifies redaction.
	got := RedactURL(raw)

	for _, leaked := range []string{"user-secret", "pass-secret", "path-token", "query-secret", "frag-secret"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("RedactURL leaked %q in %q", leaked, got)
		}
	}
	if got != "https://hooks.example/..." {
		t.Fatalf("RedactURL(%q) = %q, want host-only redacted path", raw, got)
	}
}

func TestRedactURLInvalidDoesNotEchoInput(t *testing.T) {
	t.Parallel()

	raw := "://query-secret"
	got := RedactURL(raw)
	if strings.Contains(got, "query-secret") {
		t.Fatalf("RedactURL invalid leaked input: %q", got)
	}
	if got == "" {
		t.Fatal("RedactURL invalid returned empty display value")
	}
}

func TestRedactURLRequestErrorDropsEmbeddedRequestURL(t *testing.T) {
	t.Parallel()

	err := &url.Error{ //nolint:gosec // fake credential-bearing URL verifies redaction.
		Op:  "Get",
		URL: "https://user-secret:pass-secret@server.example/private/path?token=query-secret",
		Err: errors.New("dial tcp token=query-secret"),
	}
	got := RedactURLRequestError(err, "server URL")

	for _, leaked := range []string{"user-secret", "pass-secret", "private/path", "query-secret", "token=query-secret"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("RedactURLRequestError leaked %q in %q", leaked, got)
		}
	}
	for _, want := range []string{"Get server URL", "token=[redacted]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("RedactURLRequestError missing %q in %q", want, got)
		}
	}
}

func TestRedactDiagnosticMessageRemovesURLsTokensAndPaths(t *testing.T) {
	t.Parallel()

	raw := `download failed: GET https://user-secret:pass-secret@downloads.example.test/backups/feed.tar.gz?X-Amz-Signature=query-secret&token=query-token returned 403; Authorization: Bearer bearer-secret-token; path C:\Users\Admin\AppData\Local\Packmon\feed.json; api_key=api-secret-12345`
	got := RedactDiagnosticMessage(raw)

	for _, leaked := range []string{
		"user-secret",
		"pass-secret",
		"feed.tar.gz",
		"query-secret",
		"query-token",
		"bearer-secret-token",
		"api-secret-12345",
		`C:\Users\Admin\AppData\Local\Packmon\feed.json`,
	} {
		if strings.Contains(got, leaked) {
			t.Fatalf("RedactDiagnosticMessage leaked %q in %q", leaked, got)
		}
	}
	for _, want := range []string{
		"download failed",
		"https://downloads.example.test/...",
		"Bearer [redacted]",
		"api_key=[redacted]",
		"(redacted-path)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("RedactDiagnosticMessage missing %q in %q", want, got)
		}
	}
}

func TestBoundedDiagnosticValueRedactsControlsAndTruncates(t *testing.T) {
	t.Parallel()

	raw := "packmon-cli/test\nAuthorization: Bearer super-secret-token " + strings.Repeat("x", 400)
	got := BoundedDiagnosticValue(raw, 96)

	if strings.Contains(got, "\n") || strings.Contains(got, "super-secret-token") {
		t.Fatalf("BoundedDiagnosticValue leaked raw content: %q", got)
	}
	if !strings.Contains(got, "Bearer [redacted]") {
		t.Fatalf("BoundedDiagnosticValue missing redaction marker: %q", got)
	}
	if !strings.Contains(got, "[truncated]") {
		t.Fatalf("BoundedDiagnosticValue missing truncation marker: %q", got)
	}
	if len(got) > 96 {
		t.Fatalf("BoundedDiagnosticValue length = %d, want <= 96", len(got))
	}
}

func TestRequestPathLabelDoesNotEchoAttackerControlledSegments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want string
	}{
		{"empty", "", "/"},
		{"root", "/", "/"},
		{"health", "/healthz", "/healthz"},
		{"static", "/static/tailwind.css", "/static/..."},
		{"api check", "/api/v1/check", "/api/v1/check"},
		{"feed import", "/api/v1/feeds/socket/import", "/api/v1/feeds/{feed}/import"},
		{"package detail", "/api/v1/packages/npm/secret-package-token", "/api/v1/packages/{ecosystem}/{name...}"},
		{"package refresh", "/api/v1/packages/npm/C:%5CUsers%5CAdmin%5Csecret-token/refresh", "/api/v1/packages/{ecosystem}/{name...}/refresh"},
		{"api unknown", "/api/v1/secret-token/path", "/api/v1/..."},
		{"admin exact", "/admin/settings/password", "/admin/settings/password"},
		{"admin unknown", "/admin/secret-token/path", "/admin/..."},
		{"web package", "/package/npm/secret-token", "/package/{ecosystem}/{name...}"},
		{"search", "/search", "/search"},
		{"unmatched", "/C:/Users/Admin/secret-token", "(unmatched-route)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RequestPathLabel(tt.path)
			if got != tt.want {
				t.Fatalf("RequestPathLabel(%q) = %q, want %q", tt.path, got, tt.want)
			}
			for _, leaked := range []string{"secret-token", "secret-package-token", "Users", "Admin", "tailwind.css", "socket"} {
				if strings.Contains(got, leaked) {
					t.Fatalf("RequestPathLabel(%q) leaked %q in %q", tt.path, leaked, got)
				}
			}
		})
	}
}
