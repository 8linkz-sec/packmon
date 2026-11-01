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

func TestRedactURLHandlesBlankRootAndNoPath(t *testing.T) {
	t.Parallel()

	if got := RedactURL(" "); got != "" {
		t.Fatalf("RedactURL(blank) = %q, want empty", got)
	}
	if got := RedactURL("https://api.example.test"); got != "https://api.example.test" {
		t.Fatalf("RedactURL(no path) = %q", got)
	}
	if got := RedactURL("https://api.example.test/"); got != "https://api.example.test/" {
		t.Fatalf("RedactURL(root path) = %q", got)
	}
}

func TestRedactURLErrorAndRequestErrorEdgeCases(t *testing.T) {
	t.Parallel()

	if got := RedactURLError(nil); got != "" {
		t.Fatalf("RedactURLError(nil) = %q, want empty", got)
	}
	if got := RedactURLRequestError(errors.New("Bearer secret-token-123456"), ""); got != "Bearer [redacted]" {
		t.Fatalf("RedactURLRequestError(non-url) = %q", got)
	}
	if got := RedactURLRequestError(&url.Error{Op: " ", Err: nil}, " "); got != "request URL failed" {
		t.Fatalf("RedactURLRequestError(no inner err) = %q", got)
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

// TestRedactDiagnosticMessageRemovesPostgresDSNCredentials covers database
// driver errors that echo the connection URL: its userinfo carries the
// database password.
func TestRedactDiagnosticMessageRemovesPostgresDSNCredentials(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"cannot connect to postgres://packmon:dsn-secret-pass@db.internal:5432/packmon?sslmode=require: refused",
		"cannot connect to POSTGRESQL://packmon:dsn-secret-pass@db.internal/packmon: refused",
	} {
		got := RedactDiagnosticMessage(raw)
		if strings.Contains(got, "dsn-secret-pass") || strings.Contains(got, "sslmode") {
			t.Fatalf("RedactDiagnosticMessage(%q) = %q, want DSN credentials and query removed", raw, got)
		}
		if !strings.Contains(got, "db.internal") || !strings.Contains(got, "refused") {
			t.Fatalf("RedactDiagnosticMessage(%q) = %q, want host and failure class kept", raw, got)
		}
	}
}

func TestRedactDiagnosticMessageBlankIsEmpty(t *testing.T) {
	t.Parallel()

	if got := RedactDiagnosticMessage(" \t\n "); got != "" {
		t.Fatalf("RedactDiagnosticMessage(blank) = %q, want empty", got)
	}
}

func TestRedactDiagnosticMessageRedactsSecretAssignments(t *testing.T) {
	t.Parallel()

	raw := strings.Join([]string{
		"password=password-secret-12345",
		"passwd: passwd-secret-12345",
		"pwd=pwd-secret-12345",
		"client_secret=client-secret-12345",
		"client-secret: oauth-secret-12345",
		"refresh_token=refresh-secret-12345",
		"private_key=private-key-secret-12345",
		"credential=credential-secret-12345",
	}, " ")

	got := RedactDiagnosticMessage(raw)
	for _, leaked := range []string{
		"password-secret-12345",
		"passwd-secret-12345",
		"pwd-secret-12345",
		"client-secret-12345",
		"oauth-secret-12345",
		"refresh-secret-12345",
		"private-key-secret-12345",
		"credential-secret-12345",
	} {
		if strings.Contains(got, leaked) {
			t.Fatalf("RedactDiagnosticMessage leaked %q in %q", leaked, got)
		}
	}
	for _, want := range []string{
		"password=[redacted]",
		"passwd: [redacted]",
		"pwd=[redacted]",
		"client_secret=[redacted]",
		"client-secret: [redacted]",
		"refresh_token=[redacted]",
		"private_key=[redacted]",
		"credential=[redacted]",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("RedactDiagnosticMessage missing %q in %q", want, got)
		}
	}
}

// TestRedactDiagnosticMessageRedactsWholeQuotedSecretValues covers libpq-style
// key/value DSNs, where a value with spaces is quoted: redacting only the first
// token used to leave the rest of the secret in the message.
func TestRedactDiagnosticMessageRedactsWholeQuotedSecretValues(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		raw    string
		leaked []string
		want   string
	}{
		{
			raw:    `cannot parse dsn: host=db password='first second third' sslmode=require`,
			leaked: []string{"first", "second", "third"},
			want:   `host=db password=[redacted] sslmode=require`,
		},
		{
			raw:    `cannot parse dsn: password="dq first dq-second" user=packmon`,
			leaked: []string{"dq first", "dq-second"},
			want:   `password=[redacted] user=packmon`,
		},
		{
			// libpq escapes a quote inside a quoted value with a backslash.
			raw:    `password='it\'s a secret' dbname=packmon`,
			leaked: []string{"it", "s a secret"},
			want:   `password=[redacted] dbname=packmon`,
		},
		{
			raw:    `password=unquoted-secret; next`,
			leaked: []string{"unquoted-secret"},
			want:   `password=[redacted]; next`,
		},
		{
			raw:    `password=plain&next=1`,
			leaked: []string{"plain"},
			want:   `password=[redacted]&next=1`,
		},
		// A quote does not end the value: characters after the closing quote
		// up to the next delimiter belong to the same value.
		{
			raw:    `password="ab"cd user=packmon`,
			leaked: []string{"ab", "cd"},
			want:   `password=[redacted] user=packmon`,
		},
		{
			raw:    `password=''secret user=packmon`,
			leaked: []string{"secret"},
			want:   `password=[redacted] user=packmon`,
		},
		{
			raw:    `password='a b'c d=1`,
			leaked: []string{"a b", "'c"},
			want:   `password=[redacted] d=1`,
		},
		// A backslash-escaped space does not end an unquoted value.
		{
			raw:    `password=foo\ bar user=packmon`,
			leaked: []string{"foo", "bar"},
			want:   `password=[redacted] user=packmon`,
		},
		// An unterminated quote redacts the rest of the message.
		{
			raw:    `password='never closed secret`,
			leaked: []string{"never", "closed", "secret"},
			want:   `password=[redacted]`,
		},
	} {
		got := RedactDiagnosticMessage(tt.raw)
		for _, leaked := range tt.leaked {
			if strings.Contains(got, leaked) {
				t.Fatalf("RedactDiagnosticMessage(%q) = %q, leaked %q", tt.raw, got, leaked)
			}
		}
		if !strings.Contains(got, tt.want) {
			t.Fatalf("RedactDiagnosticMessage(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

// TestRedactDiagnosticMessageRedactsQuotedKeySecrets covers JSON- and
// dict-style diagnostics, where the key itself is quoted: the separator used to
// be required directly after the key name, so these values were not redacted.
func TestRedactDiagnosticMessageRedactsQuotedKeySecrets(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		raw    string
		leaked []string
		want   string
	}{
		{
			raw:    `decode failed: {"password":"json-secret-1"}`,
			leaked: []string{"json-secret-1"},
			want:   `{"password":[redacted]}`,
		},
		{
			raw:    `body {"api_key": "json-secret-2"}`,
			leaked: []string{"json-secret-2"},
			want:   `{"api_key": [redacted]}`,
		},
		{
			raw:    `params {'token':'dict-secret-3'}`,
			leaked: []string{"dict-secret-3"},
			want:   `{'token':[redacted]}`,
		},
		{
			raw:    `{"client_secret" : "spaced-secret-4", "user": "bob"}`,
			leaked: []string{"spaced-secret-4"},
			want:   `{"client_secret" : [redacted], "user": "bob"}`,
		},
		{
			raw:    `{"Password"="assign-secret-5"}`,
			leaked: []string{"assign-secret-5"},
			want:   `{"Password"=[redacted]}`,
		},
		{
			// An unquoted scalar after a quoted key ends at the JSON delimiter.
			raw:    `{"pwd":12345678,"port":5432}`,
			leaked: []string{"12345678"},
			want:   `{"pwd":[redacted],"port":5432}`,
		},
		{
			// An escaped quote inside the value does not end it.
			raw:    `{"secret":"a\"b-escaped-6","x":1}`,
			leaked: []string{"b-escaped-6"},
			want:   `{"secret":[redacted],"x":1}`,
		},
		{
			// JSON embedded in a JSON string escapes its quotes.
			raw:    `{"body":"{\"token\":\"nested-secret-7\"}"}`,
			leaked: []string{"nested-secret-7"},
			want:   `{\"token\":[redacted]}`,
		},
		{
			// An unterminated quoted value redacts the rest of the message.
			raw:    `{"password":"never closed json-secret-8`,
			leaked: []string{"never", "json-secret-8"},
			want:   `{"password":[redacted]`,
		},
	} {
		got := RedactDiagnosticMessage(tt.raw)
		for _, leaked := range tt.leaked {
			if strings.Contains(got, leaked) {
				t.Fatalf("RedactDiagnosticMessage(%q) = %q, leaked %q", tt.raw, got, leaked)
			}
		}
		if !strings.Contains(got, tt.want) {
			t.Fatalf("RedactDiagnosticMessage(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

// TestRedactDiagnosticMessageRedactsOnlySecretJSONFields keeps non-secret
// fields of a JSON object readable while every secret value is redacted.
func TestRedactDiagnosticMessageRedactsOnlySecretJSONFields(t *testing.T) {
	t.Parallel()

	raw := `request rejected: {"user":"alice","password":"p-secret-1","host":"db.internal",` +
		`"api_key": "k-secret-2","port":5432,'token':'t-secret-3',"tokens":3,"note":"keep me",` +
		`"access_token":"a-secret-4"}`
	want := `request rejected: {"user":"alice","password":[redacted],"host":"db.internal",` +
		`"api_key": [redacted],"port":5432,'token':[redacted],"tokens":3,"note":"keep me",` +
		`"access_token":[redacted]}`
	if got := RedactDiagnosticMessage(raw); got != want {
		t.Fatalf("RedactDiagnosticMessage() =\n%q\nwant\n%q", got, want)
	}
}

// TestRedactDiagnosticMessageRedactsEscapedNewlines keeps a backslash-escaped
// newline inside the value: the escape used to match any character except a
// newline, so the quoted alternative failed and the tail of the value leaked.
func TestRedactDiagnosticMessageRedactsEscapedNewlines(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		raw    string
		leaked []string
		want   string
	}{
		{
			raw:    "password='ab\\\ncd-tail-1' user=packmon",
			leaked: []string{"ab", "cd-tail-1"},
			want:   "password=[redacted] user=packmon",
		},
		{
			raw:    "password=\"ab\\\ncd-tail-2\" user=packmon",
			leaked: []string{"ab", "cd-tail-2"},
			want:   "password=[redacted] user=packmon",
		},
		{
			raw:    "password=ab\\\ncd-tail-3 user=packmon",
			leaked: []string{"ab", "cd-tail-3"},
			want:   "password=[redacted] user=packmon",
		},
		{
			raw:    "{\"password\":\"ab\\\ncd-tail-4\",\"user\":\"packmon\"}",
			leaked: []string{"ab", "cd-tail-4"},
			want:   "{\"password\":[redacted],\"user\":\"packmon\"}",
		},
	} {
		got := RedactDiagnosticMessage(tt.raw)
		for _, leaked := range tt.leaked {
			if strings.Contains(got, leaked) {
				t.Fatalf("RedactDiagnosticMessage(%q) = %q, leaked %q", tt.raw, got, leaked)
			}
		}
		if !strings.Contains(got, tt.want) {
			t.Fatalf("RedactDiagnosticMessage(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

// TestRedactDiagnosticMessageRedactsURLsBeforeQuotedKeySecrets keeps URL
// redaction first, so a URL inside a JSON field loses its credentials and query
// while the neighbouring secret field is still redacted.
func TestRedactDiagnosticMessageRedactsURLsBeforeQuotedKeySecrets(t *testing.T) {
	t.Parallel()

	raw := `{"url":"https://user:url-pass-1@example.test/hook?token=url-token-2","password":"pw-secret-3"}` //nolint:gosec // fake secret-bearing JSON verifies redaction.
	got := RedactDiagnosticMessage(raw)
	for _, leaked := range []string{"url-pass-1", "url-token-2", "pw-secret-3", "/hook"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("RedactDiagnosticMessage(%q) = %q, leaked %q", raw, got, leaked)
		}
	}
	for _, want := range []string{`"url":"https://example.test/..."`, `"password":[redacted]`} {
		if !strings.Contains(got, want) {
			t.Fatalf("RedactDiagnosticMessage(%q) = %q, want %q", raw, got, want)
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

func TestRemoteErrorSnippetRedactsAndTruncatesUTF8(t *testing.T) {
	t.Parallel()

	body := []byte("Authorization: Bearer leaked-remote-token api_key=leaked-query-token " + strings.Repeat("x", 160) + "ä" + strings.Repeat("y", 50))
	got := RemoteErrorSnippet(body, 220)

	if !strings.Contains(got, "ä") || !strings.HasSuffix(got, "...") {
		t.Fatalf("RemoteErrorSnippet() = %q, want UTF-8 boundary and ellipsis", got)
	}
	for _, leaked := range []string{"leaked-remote-token", "leaked-query-token"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("RemoteErrorSnippet leaked %q in %q", leaked, got)
		}
	}
	for _, want := range []string{"Bearer [redacted]", "api_key=[redacted]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("RemoteErrorSnippet missing %q in %q", want, got)
		}
	}
}

func TestRemoteErrorSnippetHandlesShortAndNegativeLimits(t *testing.T) {
	t.Parallel()

	if got := RemoteErrorSnippet([]byte("short response"), 100); got != "short response" {
		t.Fatalf("RemoteErrorSnippet(short) = %q, want unmodified response", got)
	}
	if got := RemoteErrorSnippet([]byte("longer than a negative limit"), -1); got != "..." {
		t.Fatalf("RemoteErrorSnippet(negative limit) = %q, want ellipsis", got)
	}
}

func TestBoundedValueLimitsAndUTF8(t *testing.T) {
	t.Parallel()

	if got := BoundedValue("anything", 0); got != "" {
		t.Fatalf("BoundedValue(max 0) = %q, want empty", got)
	}
	if got := BoundedValue("a\n\tb", 20); got != "a b" {
		t.Fatalf("BoundedValue(control whitespace) = %q, want collapsed text", got)
	}
	if got := BoundedValue("abcdef", 3); got != "... "[:3] && got != "..." {
		t.Fatalf("BoundedValue(short max) = %q, want truncation marker prefix", got)
	}
	got := BoundedValue("alpha βeta gamma", 14)
	if strings.Contains(got, "\uFFFD") || len(got) > 14 || !strings.Contains(got, "[truncated]") {
		t.Fatalf("BoundedValue(utf8 truncate) = %q", got)
	}
}

func TestSplitTrailingURLPunctuation(t *testing.T) {
	t.Parallel()

	core, suffix := splitTrailingURLPunctuation("https://example.test/path).")
	if core != "https://example.test/path" || suffix != ")." {
		t.Fatalf("splitTrailingURLPunctuation() = %q %q", core, suffix)
	}
	core, suffix = splitTrailingURLPunctuation("https://example.test/path")
	if core != "https://example.test/path" || suffix != "" {
		t.Fatalf("splitTrailingURLPunctuation(no suffix) = %q %q", core, suffix)
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
		{"missing leading slash", "healthz", "/healthz"},
		{"trailing slash", "/healthz///", "/healthz"},
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

func TestTruncateUTF8AndSplitPathSegmentsBoundaryCases(t *testing.T) {
	t.Parallel()

	if got := truncateUTF8("anything", 0); got != "" {
		t.Fatalf("truncateUTF8(max 0) = %q, want empty", got)
	}
	if got := truncateUTF8("éclair", len(truncationMarker)+2); got != "é...[truncated]" {
		t.Fatalf("truncateUTF8(rune boundary) = %q, want complete rune plus marker", got)
	}

	path := "//api///v1//packages//npm//secret-package-token//refresh//"
	got := RequestPathLabel(path)
	if got != "/api/v1/packages/{ecosystem}/{name...}/refresh" {
		t.Fatalf("RequestPathLabel(%q) = %q, want package refresh label", path, got)
	}
	if strings.Contains(got, "secret-package-token") {
		t.Fatalf("RequestPathLabel(%q) leaked package segment in %q", path, got)
	}
}
