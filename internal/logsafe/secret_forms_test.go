package logsafe

import (
	"strings"
	"testing"
)

// assertUnchanged checks that every message passes redaction unchanged.
func assertUnchanged(t *testing.T, raws []string) {
	t.Helper()
	for _, raw := range raws {
		if got := RedactDiagnosticMessage(raw); got != raw {
			t.Errorf("RedactDiagnosticMessage(%q) = %q, want it unchanged", raw, got)
		}
	}
}

// assertExact checks the exact redaction result of every message.
func assertExact(t *testing.T, cases map[string]string) {
	t.Helper()
	for raw, want := range cases {
		if got := RedactDiagnosticMessage(raw); got != want {
			t.Errorf("RedactDiagnosticMessage(%q) =\n%q\nwant\n%q", raw, got, want)
		}
	}
}

// TestRedactDiagnosticMessageTracksQuotedFreeText covers AUDIT-064: an
// unquoted key in the middle of a quoted label ("x password: a") used to treat
// the label's closing quote as the opening quote of a value segment, which then
// paired with the opening quote of the next value and left that value's tail
// readable. The scan now tracks the quoted strings of the free text, so the
// label's closing quote ends the label's value.
func TestRedactDiagnosticMessageTracksQuotedFreeText(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{
			raw:    `"x password: a" PGPASSWORD:"0 s 0"`,
			leaked: []string{"s 0"},
			want:   `"x password: [redacted]" PGPASSWORD:[redacted]`,
		},
		{
			raw:    `'x password: a' PGPASSWORD:'0 qt-secret-1 0'`,
			leaked: []string{"qt-secret-1"},
			want:   `'x password: [redacted]' PGPASSWORD:[redacted]`,
		},
		{
			// An apostrophe inside the double-quoted label does not open a
			// value segment that runs past the label's closing quote.
			raw:    `"x password: it's" PGPASSWORD:'0 qt-secret-2 0'`,
			leaked: []string{"qt-secret-2"},
			want:   `PGPASSWORD:[redacted]`,
		},
		{
			raw:    `{"msg":"login password=qt-secret-3 failed","user":"bob"}`,
			leaked: []string{"qt-secret-3"},
			want:   `{"msg":"login password=[redacted] failed","user":"bob"}`,
		},
		{
			// A quoted value of an unquoted key is not mistaken for a string
			// the key sits in: password="a b" is redacted whole.
			raw:    `user="a b" password="qt c qt-secret-4" host=db`,
			leaked: []string{"qt c", "qt-secret-4"},
			want:   `user="a b" password=[redacted] host=db`,
		},
		{
			// An apostrophe inside a word does not open a quoted string, so the
			// libpq-quoted value after it is still redacted whole.
			raw:    `can't connect: host=db password='qt d qt-secret-5' sslmode=require`,
			leaked: []string{"qt d", "qt-secret-5"},
			want:   `host=db password=[redacted] sslmode=require`,
		},
		{
			// A quote followed by a letter does not close the string, it
			// quotes a segment of the value.
			raw:    `"x password=ab"qt-secret-6" next`,
			leaked: []string{"qt-secret-6"},
			want:   `"x password=[redacted] next`,
		},
	})

	// The same pairing for a quoted key cut off inside escaped JSON: a quote
	// less escaped than the key's quotes closes the enclosing string, so it
	// neither opens the key's value nor ends up inside it.
	assertRedactionCases(t, []redactionCase{
		{
			raw:    `error "\\\"token\\\":" credential:"0 qt-secret-9 0" "0"`,
			leaked: []string{"qt-secret-9"},
			want:   `credential:[redacted] "0"`,
		},
	})
	assertExact(t, map[string]string{ //nolint:gosec // fake secret-bearing JSON verifies redaction.
		`{"body":"{\"token\":qt-secret-10","user":"bob"}`: `{"body":"{\"token\":[redacted]","user":"bob"}`,
	})

	// A quote after an even number of backslashes is unescaped; it used to
	// count as escaped when only one backslash was checked, which redacted the
	// rest of the message (the safe direction).
	assertExact(t, map[string]string{
		`\\"password=qt-secret-7" next`: `\\"password=[redacted]" next`,
		`\"password=qt-secret-8 next`:   `\"password=[redacted] next`,
	})
}

// TestRedactDiagnosticMessageRedactsPrivateKeyBlocks covers PEM private keys:
// an unquoted value stopped at the first space or line break, so the base64
// body of the key stayed readable. The whole block, through its END marker or
// the end of the message, is replaced.
func TestRedactDiagnosticMessageRedactsPrivateKeyBlocks(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{
			raw:    "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIEpem-body-1\npem-line-2\n-----END RSA PRIVATE KEY----- next=1",
			leaked: []string{"pem-body-1", "pem-line-2"},
			want:   "PRIVATE_KEY=[redacted] next=1",
		},
		{
			raw:    `{"msg":"-----BEGIN PRIVATE KEY-----\nMIIEpem-body-3\n-----END PRIVATE KEY-----\n","user":"bob"}`,
			leaked: []string{"pem-body-3"},
			want:   `{"msg":"(redacted-private-key)\n","user":"bob"}`,
		},
		{
			// A block cut off before its END marker redacts the rest.
			raw:    "key file: -----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1 pem-body-4",
			leaked: []string{"b3BlbnNzaC1", "pem-body-4"},
			want:   "key file: (redacted-private-key)",
		},
		{
			raw:    "-----BEGIN ENCRYPTED PRIVATE KEY-----\npem-body-5\n-----END ENCRYPTED PRIVATE KEY----- tail",
			leaked: []string{"pem-body-5"},
			want:   "(redacted-private-key) tail",
		},
		{ //nolint:gosec // fake PGP key block verifies redaction.
			raw:    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYpem-body-6\n-----END PGP PRIVATE KEY BLOCK-----",
			leaked: []string{"pem-body-6"},
			want:   "(redacted-private-key)",
		},
	})

	assertUnchanged(t, []string{
		"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----",
		"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----",
	})
}

// TestRedactDiagnosticMessageRedactsTokensUnlessCount covers the plural
// tokens: it was exempt because it usually holds a count, so a list of tokens
// leaked. It is now a secret key unless its value is a bare number.
func TestRedactDiagnosticMessageRedactsTokensUnlessCount(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{raw: `{"tokens":["ghp_tokens1","ghp_tokens2"],"n":2}`, leaked: []string{"ghp_tokens"}, want: `{"tokens":[redacted],"n":2}`},
		{raw: `tokens=ghp_tokens3 n=1`, leaked: []string{"ghp_tokens3"}, want: `tokens=[redacted] n=1`},
		{raw: `{"tokens":"ghp_tokens4"}`, leaked: []string{"ghp_tokens4"}, want: `{"tokens":[redacted]}`},
		{raw: `{"refreshTokens":{"a":"ghp_tokens5"}}`, leaked: []string{"ghp_tokens5"}, want: `{"refreshTokens":[redacted]}`},
		{raw: `tokens=12abc`, leaked: []string{"12abc"}, want: `tokens=[redacted]`},
	})

	assertUnchanged(t, []string{
		`{"tokens":3,"tokens_count":12,"TOKENS":4,"max_tokens":-1}`,
		`tokens=3 tokens_count=12 TOKENS=4 max_tokens=4,096 tokens: 2.5`,
		`usage tokens=3, cost=1`,
	})
}

// TestRedactDiagnosticMessageRedactsMoreSecretKeyNames covers key names that
// were not recognized: *_key names after access, account, signing,
// encryption, and master; passphrase; the short words pass, pw, auth, cookie,
// and session as the last component of the name; and session ids.
func TestRedactDiagnosticMessageRedactsMoreSecretKeyNames(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{raw: `aws_access_key=kn-secret-1 region=eu`, leaked: []string{"kn-secret-1"}, want: `aws_access_key=[redacted] region=eu`},
		{raw: `{"accessKey":"kn-secret-2"}`, leaked: []string{"kn-secret-2"}, want: `{"accessKey":[redacted]}`},
		{
			raw:    `DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=kn-secret-3==;EndpointSuffix=core.windows.net`,
			leaked: []string{"kn-secret-3"},
			want:   `AccountName=acct;AccountKey=[redacted];EndpointSuffix=core.windows.net`,
		},
		{raw: `SharedAccessKey=kn-secret-4= next`, leaked: []string{"kn-secret-4"}, want: `SharedAccessKey=[redacted] next`},
		{raw: `{"signing_key":"kn-secret-5"}`, leaked: []string{"kn-secret-5"}, want: `{"signing_key":[redacted]}`},
		{raw: `encryption_key=kn-secret-6`, leaked: []string{"kn-secret-6"}, want: `encryption_key=[redacted]`},
		{raw: `MASTER_KEY: kn-secret-7`, leaked: []string{"kn-secret-7"}, want: `MASTER_KEY: [redacted]`},
		{raw: `{"passphrase":"kn secret-8"}`, leaked: []string{"kn secret-8"}, want: `{"passphrase":[redacted]}`},
		{raw: `GPG_PASSPHRASE=kn-secret-9`, leaked: []string{"kn-secret-9"}, want: `GPG_PASSPHRASE=[redacted]`},
		{raw: `DB_PASS=kn-secret-10 DB_HOST=db`, leaked: []string{"kn-secret-10"}, want: `DB_PASS=[redacted] DB_HOST=db`},
		{raw: `{"pass": "kn-secret-11"}`, leaked: []string{"kn-secret-11"}, want: `{"pass": [redacted]}`},
		{raw: `pw=kn-secret-12`, leaked: []string{"kn-secret-12"}, want: `pw=[redacted]`},
		{raw: `{"auth":"kn-secret-13"}`, leaked: []string{"kn-secret-13"}, want: `{"auth":[redacted]}`},
		{raw: `basic_auth=user:kn-secret-14`, leaked: []string{"kn-secret-14"}, want: `basic_auth=[redacted]`},
		{raw: `session=kn-secret-15 user=bob`, leaked: []string{"kn-secret-15"}, want: `session=[redacted] user=bob`},
		{raw: `{"session":"kn-secret-16"}`, leaked: []string{"kn-secret-16"}, want: `{"session":[redacted]}`},
		{raw: `session_id=kn-secret-17`, leaked: []string{"kn-secret-17"}, want: `session_id=[redacted]`},
		{raw: `JSESSIONID=kn-secret-18; PHPSESSID=kn-secret-19`, leaked: []string{"kn-secret-18", "kn-secret-19"}, want: `JSESSIONID=[redacted]; PHPSESSID=[redacted]`},
		{raw: `cookie=kn-secret-20 next=1`, leaked: []string{"kn-secret-20"}, want: `cookie=[redacted] next=1`},
		{
			// A Cookie or Set-Cookie header carries ';'-separated pairs, so
			// its value runs to the end of the line.
			raw:    "Cookie: sid=kn-secret-21; theme=kn-secret-22\nAccept: json",
			leaked: []string{"kn-secret-21", "kn-secret-22"},
			want:   "Cookie: [redacted]\nAccept: json",
		},
		{
			raw:    "Set-Cookie: sid=kn-secret-23; Path=/; HttpOnly",
			leaked: []string{"kn-secret-23"},
			want:   "Set-Cookie: [redacted]",
		},
	})
}

// TestRedactDiagnosticMessageRedactsAuthorizationCredentials covers the
// Authorization header: a Basic credential, a Bearer token shorter than eight
// characters, and a credential without a scheme used to stay readable. The
// scheme stays readable.
func TestRedactDiagnosticMessageRedactsAuthorizationCredentials(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{raw: "Authorization: Basic dXNlcjpwYXNz\nAccept: json", leaked: []string{"dXNlcjpwYXNz"}, want: "Authorization: Basic [redacted]\nAccept: json"},
		{raw: "authorization: basic YWJjZGVm next", leaked: []string{"YWJjZGVm"}, want: "authorization: basic [redacted] next"},
		{raw: "Proxy-Authorization: Basic cHJveHk6eA== next", leaked: []string{"cHJveHk6eA"}, want: "Proxy-Authorization: Basic [redacted] next"},
		{raw: "Authorization: Bearer ab1", leaked: []string{"ab1"}, want: "Authorization: Bearer [redacted]"},
		{raw: "Authorization: az-secret-1 next", leaked: []string{"az-secret-1"}, want: "Authorization: [redacted] next"},
		{raw: "sent Bearer ab2 to the server", leaked: []string{"ab2"}, want: "sent Bearer [redacted] to the server"},
		{raw: `{"Authorization":"Basic az-secret-3"}`, leaked: []string{"az-secret-3"}, want: `{"Authorization":[redacted]}`},
		{raw: `map[Authorization:[Basic az-secret-4]]`, leaked: []string{"az-secret-4"}, want: `map[Authorization:[redacted]`},
	})

	// Words that commonly follow "Bearer" in prose are not credentials.
	assertUnchanged(t, []string{
		"missing Bearer token",
		"invalid bearer auth scheme",
		`WWW-Authenticate: Bearer realm="packmon"`,
		"expected Bearer authentication",
	})
}

// TestRedactDiagnosticMessageRedactsQuotedKeysWithSeparators covers quoted
// keys that contain a space, '/', or ':': the key name had to be a run of
// letters, digits, '_', '-', and '.', so these values leaked.
func TestRedactDiagnosticMessageRedactsQuotedKeysWithSeparators(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{raw: `{"Client Secret":"qk-secret-1","user":"bob"}`, leaked: []string{"qk-secret-1"}, want: `{"Client Secret":[redacted],"user":"bob"}`},
		{raw: `{"auth/token": "qk-secret-2"}`, leaked: []string{"qk-secret-2"}, want: `{"auth/token": [redacted]}`},
		{raw: `{'db:password': 'qk secret-3'}`, leaked: []string{"qk secret-3"}, want: `{'db:password': [redacted]}`},
		{raw: `{\"Client Secret\":\"qk secret-4\",\"x\":1}`, leaked: []string{"qk secret-4"}, want: `{\"Client Secret\":[redacted],\"x\":1}`},
	})

	assertUnchanged(t, []string{
		`{"error message":"bad request","user name":"bob","a/b":"c","x:y":"z"}`,
	})
}

// TestRedactDiagnosticMessageRedactsSpaceSeparatedFlags covers command lines
// whose secret flag takes its value as the next argument: only the
// flag=value form was recognized.
func TestRedactDiagnosticMessageRedactsSpaceSeparatedFlags(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{raw: `cmd --password fl-secret-1 --verbose`, leaked: []string{"fl-secret-1"}, want: `cmd --password [redacted] --verbose`},
		{raw: `cmd -token fl-secret-2 -v`, leaked: []string{"fl-secret-2"}, want: `cmd -token [redacted] -v`},
		{raw: `cmd --db-password 'fl a fl-secret-3' x=1`, leaked: []string{"fl a", "fl-secret-3"}, want: `cmd --db-password [redacted] x=1`},
		{raw: `cmd --api-key fl-secret-4`, leaked: []string{"fl-secret-4"}, want: `cmd --api-key [redacted]`},
		{raw: `mysql -u root -p fl-secret-5 packmon`, leaked: []string{"fl-secret-5"}, want: `mysql -u root -p [redacted] packmon`},
		{raw: `cmd --pass fl-secret-6`, leaked: []string{"fl-secret-6"}, want: `cmd --pass [redacted]`},
		{raw: `"cmd --password fl-secret-7" next`, leaked: []string{"fl-secret-7"}, want: `"cmd --password [redacted]" next`},
	})

	// The flag's last name component must be the secret word, and a value
	// that starts with '-' is the next flag.
	assertUnchanged(t, []string{
		`docker login --password-stdin -u bob registry.example.test`,
		`cmd --token-file token.txt --tokens 5`,
		`cmd --password --verbose`,
		`cmd --password`,
		`cmd -P 5432 -u bob`,
	})

	// Judgment call: -p is a password flag (mysql, some CLIs) and a port or
	// parallelism flag elsewhere. Redaction errs toward hiding it.
	assertExact(t, map[string]string{
		`go test -p 4 ./...`: `go test -p [redacted] ./...`,
	})
}

// TestRedactDiagnosticMessageRedactsValuesWithSubDelimiters covers unquoted
// values that contain ';', '&', or ',': the value ended at the first ';' or
// '&', so the rest of it leaked. A ';' or '&' now ends the value only before
// whitespace, the end, or the next key=value pair.
func TestRedactDiagnosticMessageRedactsValuesWithSubDelimiters(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{raw: `password=a;sd-secret-1 user=x`, leaked: []string{"sd-secret-1"}, want: `password=[redacted] user=x`},
		{raw: `password=a&sd-secret-2 user=x`, leaked: []string{"sd-secret-2"}, want: `password=[redacted] user=x`},
		{raw: `password=a,sd-secret-3 user=x`, leaked: []string{"sd-secret-3"}, want: `password=[redacted] user=x`},
		{raw: `password=a&amp;sd-secret-4 user=x`, leaked: []string{"sd-secret-4"}, want: `password=[redacted] user=x`},
		{raw: `{"pwd":a;sd-secret-5,"port":1}`, leaked: []string{"sd-secret-5"}, want: `{"pwd":[redacted],"port":1}`},
	})

	assertExact(t, map[string]string{ //nolint:gosec // fake secret assignments verify redaction.
		`password=x&next=1`: `password=[redacted]&next=1`,
		`password=x; next`:  `password=[redacted]; next`,
		`password=x;`:       `password=[redacted];`,
		`grant_type=pw&client_secret=cs-6&code=c1`:    `grant_type=pw&client_secret=[redacted]&code=c1`,
		`host=db;password=pw-7;user=packmon`:          `host=db;password=[redacted];user=packmon`,
		`token=x%26y-secret-8 next`:                   `token=[redacted] next`,
		`token%3Dsd-secret-9%26next%3D1`:              `token%3D[redacted]%26next%3D1`,
		`{"pwd":12;34,"port":1}`:                      `{"pwd":[redacted],"port":1}`,
		`password=sd-secret-10;user=x;dbname=packmon`: `password=[redacted];user=x;dbname=packmon`,
	})
}

// TestRedactDiagnosticMessageRedactsEncodedForms covers HTML-escaped quotes
// (&quot;, &#34;, &#39;) around keys and values and URL-encoded separators
// (%3D, %3A) and quotes (%22): neither was recognized.
func TestRedactDiagnosticMessageRedactsEncodedForms(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{
			raw:    `{&quot;password&quot;:&quot;html secret-1&quot;,&quot;user&quot;:&quot;bob&quot;}`,
			leaked: []string{"html secret-1"},
			want:   `{&quot;password&quot;:[redacted],&quot;user&quot;:&quot;bob&quot;}`,
		},
		{
			raw:    `{&#34;token&#34;: &#34;html secret-2&#34;, &#34;n&#34;: 1}`,
			leaked: []string{"html secret-2"},
			want:   `{&#34;token&#34;: [redacted], &#34;n&#34;: 1}`,
		},
		{
			raw:    `{&#39;secret&#39;:&#39;html secret-3&#39;}`,
			leaked: []string{"html secret-3"},
			want:   `{&#39;secret&#39;:[redacted]}`,
		},
		{
			raw:    `&quot;token&quot;:{&quot;v&quot;:&quot;html secret-4&quot;}, next`,
			leaked: []string{"html secret-4"},
			want:   `&quot;token&quot;:[redacted], next`,
		},
		{
			// An escaped entity quote inside the value does not end it.
			raw:    `&quot;password&quot;:&quot;a\&quot;b html-secret-5&quot;,&quot;x&quot;:1`,
			leaked: []string{"html-secret-5"},
			want:   `&quot;password&quot;:[redacted],&quot;x&quot;:1`,
		},
		{
			raw:    `&quot;Client Secret&quot;:&quot;html secret-6`,
			leaked: []string{"html secret-6"},
			want:   `&quot;Client Secret&quot;:[redacted]`,
		},
		{raw: `body password%3Durl-secret-7&user=bob`, leaked: []string{"url-secret-7"}, want: `password%3D[redacted]&user=bob`},
		{raw: `body token%3aurl-secret-8 next`, leaked: []string{"url-secret-8"}, want: `token%3a[redacted] next`},
		{raw: `%7B%22password%22%3A%22url-secret-9%22%7D`, leaked: []string{"url-secret-9"}, want: `[redacted]`},
	})

	assertUnchanged(t, []string{
		`{&quot;user&quot;:&quot;bob&quot;,&quot;tokens&quot;:3}`,
		`a &amp; b &lt;c&gt; d%3De`,
	})
}

// TestRedactDiagnosticMessageKeepsCommonTextReadable documents the judgment
// calls for the short key words: they are matched only as the whole last
// component of a key name, and an unquoted short key needs '=' or a ':' that
// is not followed by whitespace, because "admin auth: <error>" is how Go wraps
// errors. Everyday text with these words stays readable.
func TestRedactDiagnosticMessageKeepsCommonTextReadable(t *testing.T) {
	t.Parallel()

	assertUnchanged(t, []string{
		`session started for user bob`,
		`pass 2 of 3 complete`,
		`postgres: get admin auth: connection refused`,
		`session: expired`,
		`bypass=true compass=north passage=x passport=y`,
		`auth_mode=basic auth_enabled=true cookie_name=sid session_count=3 pass_count=4 pw_hint=x`,
		`primary_key=id public_key=ssh-ed25519 foreign_key=x keyboard=de keys=3`,
		`scanned 120 packages in 3 passes; 2 sessions`,
		`npm:@types/node@20.1.0 pypi:passlib==1.7.4 go:golang.org/x/oauth2`,
	})
}

// TestRedactDiagnosticMessageLinearOnRepeatedKeys keeps the scan linear on
// adversarial input that repeats quoted labels, flags, and encoded keys: a
// quadratic scan would not finish 120 KB to 480 KB messages in test time.
func TestRedactDiagnosticMessageLinearOnRepeatedKeys(t *testing.T) {
	t.Parallel()

	for unit, forbidden := range map[string]string{
		`"x password: a" `:         `password: a`,
		`--password `:              "",
		`&quot;token&quot;:&quot;`: "",
		`password=a;b&c%26d `:      `a;b`,
		`'a password=b`:            `password=b`,
		`Authorization: Basic `:    "",
	} {
		raw := strings.Repeat(unit, 20000)
		if got := RedactDiagnosticMessage(raw); forbidden != "" && strings.Contains(got, forbidden) {
			t.Fatalf("RedactDiagnosticMessage(%q x 20000) left %q readable", unit, forbidden)
		}
	}
}

// TestRedactDiagnosticMessageSecretFormEdgeCases pins the boundaries of the
// separator, number, segment, line, and entity scans.
func TestRedactDiagnosticMessageSecretFormEdgeCases(t *testing.T) {
	t.Parallel()

	assertExact(t, map[string]string{ //nolint:gosec // fake secret assignments verify redaction.
		// Short keys: '=' with spaces, ':' without, and URL-encoded '='.
		`auth:edge-1 next`:             `auth:[redacted] next`,
		`session = edge-2`:             `session = [redacted]`,
		`pw%3Dedge-3 next`:             `pw%3D[redacted] next`,
		`auth   `:                      `auth`,
		`auth :edge`:                   `auth :edge`,
		`cookie = edge-5 next=1`:       `cookie = [redacted] next=1`,
		`cookie%3Dedge-6 next=1`:       `cookie%3D[redacted] next=1`,
		`see auth:` + "\n":             `see auth:`,
		`tokens=+5 tokens=1. tokens=-`: `tokens=+5 tokens=1. tokens=[redacted]`,
		`tokens=1..2 tokens=_1`:        `tokens=[redacted] tokens=[redacted]`,
		// A segment of the other quote kind inside a quoted string closes
		// normally, keeps escaped characters, and runs to the end when it
		// never closes.
		`"x password=a'b c'd" next`:   `"x password=[redacted]" next`,
		`"x password=a'b\'c d'e" n`:   `"x password=[redacted]" n`,
		`"x password=a'b c`:           `"x password=[redacted]`,
		`"x password=a'b\" c'd" next`: `"x password=[redacted]" next`,
		// A cookie header ends at a line break, a carriage return, or the
		// closing quote of the string it sits in; an escaped line break
		// continues it.
		"Cookie: a=1\r\nnext":      "Cookie: [redacted]\r\nnext",
		"Cookie: a=1\\\nb=2\nnext": "Cookie: [redacted]\nnext",
		`"Cookie: a=1; b=2" next`:  `"Cookie: [redacted]" next`,
		// Entity-quoted keys: a scalar value, a value at the end, an
		// unbalanced structure, and a structure with a quoted bracket.
		`&quot;pwd&quot;:12345,&quot;x&quot;:1`:                           `&quot;pwd&quot;:[redacted],&quot;x&quot;:1`,
		`&quot;pwd&quot;: `:                                               `&quot;pwd&quot;:`,
		`&quot;token&quot;:[&quot;a&quot;, edge-4`:                        `&quot;token&quot;:[redacted]`,
		`&quot;token&quot;:{&quot;a&quot;:&quot;}&quot;},&quot;n&quot;:1`: `&quot;token&quot;:[redacted],&quot;n&quot;:1`,
		`&quot;token&quot; x &quot;pwd&apos;:x`:                           `&quot;token&quot; x &quot;pwd&apos;:x`,
		`&quot;tokens&quot;:7`:                                            `&quot;tokens&quot;:7`,
	})
}
