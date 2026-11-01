package logsafe

import (
	"encoding/json"
	"strings"
	"testing"
)

type redactionCase struct {
	raw    string
	leaked []string
	want   string
}

func assertRedactionCases(t *testing.T, cases []redactionCase) {
	t.Helper()
	for _, tt := range cases {
		got := RedactDiagnosticMessage(tt.raw)
		for _, leaked := range tt.leaked {
			if strings.Contains(got, leaked) {
				t.Errorf("RedactDiagnosticMessage(%q) = %q, leaked %q", tt.raw, got, leaked)
			}
		}
		if !strings.Contains(got, tt.want) {
			t.Errorf("RedactDiagnosticMessage(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

// jsonQuote encodes s as a JSON string levels times, the way a JSON document
// embedded in a JSON string (and that one in another) is escaped.
func jsonQuote(t testing.TB, s string, levels int) string {
	t.Helper()
	for range levels {
		encoded, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("json.Marshal(%q): %v", s, err)
		}
		s = string(encoded)
	}
	return s
}

// TestRedactDiagnosticMessageRedactsComponentKeyNames covers keys that carry a
// secret word as one component of a longer name (camelCase, snake_case,
// SCREAMING_SNAKE, kebab-case, dotted, or a run-together prefix): the key name
// used to have to be exactly the secret word, so these values leaked.
func TestRedactDiagnosticMessageRedactsComponentKeyNames(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{raw: `{"authToken":"comp-secret-1"}`, leaked: []string{"comp-secret-1"}, want: `{"authToken":[redacted]}`},
		{raw: `{"githubToken": "comp-secret-2"}`, leaked: []string{"comp-secret-2"}, want: `{"githubToken": [redacted]}`},
		{raw: `{"db_password":"comp-secret-3","user":"bob"}`, leaked: []string{"comp-secret-3"}, want: `{"db_password":[redacted],"user":"bob"}`},
		{raw: `{"DB_PASSWORD":"comp-secret-4"}`, leaked: []string{"comp-secret-4"}, want: `{"DB_PASSWORD":[redacted]}`},
		{raw: `{"client_secret_value":"comp-secret-5"}`, leaked: []string{"comp-secret-5"}, want: `{"client_secret_value":[redacted]}`},
		{raw: `{"xApiKey":"comp-secret-6"}`, leaked: []string{"comp-secret-6"}, want: `{"xApiKey":[redacted]}`},
		{raw: `{"APIKey":"comp-secret-7"}`, leaked: []string{"comp-secret-7"}, want: `{"APIKey":[redacted]}`},
		{raw: `{'rsaPrivateKey': 'comp-secret-8'}`, leaked: []string{"comp-secret-8"}, want: `{'rsaPrivateKey': [redacted]}`},
		{raw: `{"x-amz-signature":"comp-secret-9"}`, leaked: []string{"comp-secret-9"}, want: `{"x-amz-signature":[redacted]}`},
		{raw: `{"oauth.client.secret":"comp-secret-10"}`, leaked: []string{"comp-secret-10"}, want: `{"oauth.client.secret":[redacted]}`},
		{raw: `env GITHUB_TOKEN=comp-secret-11 HOME=x`, leaked: []string{"comp-secret-11"}, want: `GITHUB_TOKEN=[redacted] HOME=x`},
		{raw: `env PGPASSWORD=comp-secret-12 PGHOST=db`, leaked: []string{"comp-secret-12"}, want: `PGPASSWORD=[redacted] PGHOST=db`},
		{raw: "header x-api-key: comp-secret-13\naccept: json", leaked: []string{"comp-secret-13"}, want: "x-api-key: [redacted]\naccept: json"},
		{raw: `spring.datasource.password=comp-secret-14 port=1`, leaked: []string{"comp-secret-14"}, want: `spring.datasource.password=[redacted] port=1`},
		{raw: `flags --db-password=comp-secret-15 --verbose`, leaked: []string{"comp-secret-15"}, want: `--db-password=[redacted] --verbose`},
		{raw: `MYSQL_PWD=comp-secret-16`, leaked: []string{"comp-secret-16"}, want: `MYSQL_PWD=[redacted]`},
		{raw: `token2=comp-secret-17 n=1`, leaked: []string{"comp-secret-17"}, want: `token2=[redacted] n=1`},
		{raw: `db_password: comp-secret-18`, leaked: []string{"comp-secret-18"}, want: `db_password: [redacted]`},
		{raw: `authToken=comp-secret-19`, leaked: []string{"comp-secret-19"}, want: `authToken=[redacted]`},
		{raw: `$env:APIKEY=comp-secret-20`, leaked: []string{"comp-secret-20"}, want: `$env:APIKEY=[redacted]`},
	})
}

// TestRedactDiagnosticMessageRedactsPluralSecretKeys covers the plural secret
// words credentials, secrets, passwords, and passwds, which usually hold a
// collection of secrets; tokens stays readable because it usually counts.
func TestRedactDiagnosticMessageRedactsPluralSecretKeys(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{raw: `{"credentials":"plural-1","user":"bob"}`, leaked: []string{"plural-1"}, want: `{"credentials":[redacted],"user":"bob"}`},
		{raw: `{"secrets": ["plural-a-2", "plural-b-2"], "n": 2}`, leaked: []string{"plural-a-2", "plural-b-2"}, want: `{"secrets": [redacted], "n": 2}`},
		{raw: `{"dbCredentials": {"user": "u", "pass": "plural-3"}, "x": 1}`, leaked: []string{"plural-3"}, want: `{"dbCredentials": [redacted], "x": 1}`},
		{raw: `{\"user_passwords\":\"plural-4\"}`, leaked: []string{"plural-4"}, want: `{\"user_passwords\":[redacted]}`},
		{raw: `PASSWDS=plural-5 next=1`, leaked: []string{"plural-5"}, want: `PASSWDS=[redacted] next=1`},
		{raw: `app.secrets: plural-6`, leaked: []string{"plural-6"}, want: `app.secrets: [redacted]`},
		{raw: `CREDENTIALS={"a": "plural-7"} next=1`, leaked: []string{"plural-7"}, want: `CREDENTIALS=[redacted] next=1`},
	})

	for _, raw := range []string{
		`{"tokens":3,"tokens_count":12,"TOKENS":4}`,
		`tokens=3 tokens_count=12 TOKENS=4`,
	} {
		if got := RedactDiagnosticMessage(raw); got != raw {
			t.Errorf("RedactDiagnosticMessage(%q) = %q, want it unchanged", raw, got)
		}
	}
}

// TestRedactDiagnosticMessageKeepsLookalikeKeysReadable keeps keys readable in
// which a secret word is only the start of a longer word: the secret word must
// end a component of the key name.
func TestRedactDiagnosticMessageKeepsLookalikeKeysReadable(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		`{"tokenizer":"bpe","tokens_count":12,"passwordless":true,"secretariat":"un","TOKENS":3}`,
		`tokenizer=bpe tokens_count=12 passwordless=true secretariat=un TOKENS=3 keyboard=de`,
		`{"api":"v1","key":"name","monkey":"x","signal":"term","keys":["a","b"]}`,
		`{\"tokenizer\":\"bpe\",\"tokens_count\":12,\"passwordless\":true}`,
	} {
		if got := RedactDiagnosticMessage(raw); got != raw {
			t.Errorf("RedactDiagnosticMessage(%q) = %q, want it unchanged", raw, got)
		}
	}
}

// TestRedactDiagnosticMessageRedactsStructuredSecretValues covers an object or
// array assigned to a secret key: it is redacted as a whole up to its balanced
// closing bracket, so no part of it is left after the first delimiter.
func TestRedactDiagnosticMessageRedactsStructuredSecretValues(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{
			raw:    `{"token": {"value": "struct-secret-1"}, "user": "bob"}`,
			leaked: []string{"struct-secret-1"},
			want:   `{"token": [redacted], "user": "bob"}`,
		},
		{
			raw:    `{"password": ["struct-a-2", "struct-b-2"], "x": 1}`,
			leaked: []string{"struct-a-2", "struct-b-2"},
			want:   `{"password": [redacted], "x": 1}`,
		},
		{
			// Brackets and quotes inside nested string values do not end it.
			raw:    `{"secret": {"a": {"b": ["struct-3"]}, "d": "}]\"}"}, "keep": 1}`,
			leaked: []string{"struct-3", `"d"`},
			want:   `{"secret": [redacted], "keep": 1}`,
		},
		{
			raw:    `{"pwd":[1,23456789],"port":5432}`,
			leaked: []string{"23456789"},
			want:   `{"pwd":[redacted],"port":5432}`,
		},
		{
			raw:    `{"body":"{\"token\": {\"value\": \"a } b struct-5\"}, \"user\": \"bob\"}"}`,
			leaked: []string{"struct-5"},
			want:   `{"body":"{\"token\": [redacted], \"user\": \"bob\"}"}`,
		},
		{
			raw:    `token={"value": "struct-secret-6"} next=1`,
			leaked: []string{"struct-secret-6"},
			want:   `token=[redacted] next=1`,
		},
		{
			raw:    `password: [struct-a-7, struct-b-7] user=x`,
			leaked: []string{"struct-a-7", "struct-b-7"},
			want:   `password: [redacted] user=x`,
		},
		{
			// An unbalanced structure redacts the rest of the message.
			raw:    `{"token": {"value": "never closed struct-8", "user": "bob"`,
			leaked: []string{"struct-8", "bob"},
			want:   `{"token": [redacted]`,
		},
		{
			// Already redacted text stays as it is.
			raw:    `password=[redacted] {"token":[redacted],"user":"bob"}`,
			leaked: nil,
			want:   `password=[redacted] {"token":[redacted],"user":"bob"}`,
		},
	})
}

// TestRedactDiagnosticMessageBoundsStructuredSecretValues treats a structure
// larger than the scan bound like an unbalanced one: the rest of the message is
// redacted.
func TestRedactDiagnosticMessageBoundsStructuredSecretValues(t *testing.T) {
	t.Parallel()

	raw := `{"token": [` + strings.Repeat(`"x", `, maxSecretStructureBytes/5) + `"tail-secret"], "user": "bob"}`
	got := RedactDiagnosticMessage(raw)
	if got != `{"token": [redacted]` {
		t.Fatalf("RedactDiagnosticMessage(oversized structure) = %q, want the rest redacted", got)
	}

	small := `{"token": [` + strings.Repeat(`"x", `, 16) + `"tail-secret"], "user": "bob"}`
	if got := RedactDiagnosticMessage(small); got != `{"token": [redacted], "user": "bob"}` {
		t.Fatalf("RedactDiagnosticMessage(small structure) = %q", got)
	}
}

// TestRedactDiagnosticMessageEndsAssignmentAtEnclosingQuote covers an unquoted
// key inside a quoted string: the string's closing quote ends the value, so a
// quoted label ("Password:") does not swallow the real key after it.
func TestRedactDiagnosticMessageEndsAssignmentAtEnclosingQuote(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{
			raw:    `prompt "Password:" PGPASSWORD="a b quote-secret-1" user=x`,
			leaked: []string{"a b", "quote-secret-1"},
			want:   `prompt "Password:" PGPASSWORD=[redacted] user=x`,
		},
		{
			raw:    `prompt "passwd: " PGPASSWORD:"0 quote-secret-2 0"`,
			leaked: []string{"quote-secret-2"},
			want:   `prompt "passwd: " PGPASSWORD:[redacted]`,
		},
		{
			raw:    `{"msg":"password=quote-secret-3","user":"bob"}`,
			leaked: []string{"quote-secret-3"},
			want:   `{"msg":"password=[redacted]","user":"bob"}`,
		},
		{
			raw:    `'token=quote-secret-4' next`,
			leaked: []string{"quote-secret-4"},
			want:   `'token=[redacted]' next`,
		},
		{
			// A NUL byte is part of the value like any other character.
			raw:    "password=\x00quote-secret-5 next",
			leaked: []string{"quote-secret-5"},
			want:   "password=[redacted] next",
		},
	})
}

// TestRedactDiagnosticMessageRedactsMultiplyEscapedJSON covers JSON embedded
// in a JSON string that is itself embedded in another one: its quotes carry
// three (or seven) backslashes, which used to defeat the key match.
func TestRedactDiagnosticMessageRedactsMultiplyEscapedJSON(t *testing.T) {
	t.Parallel()

	assertRedactionCases(t, []redactionCase{
		{
			raw:    `{"outer":"{\"inner\":\"{\\\"token\\\":\\\"a b dbl-1\\\",\\\"user\\\":\\\"bob\\\"}\"}"}`,
			leaked: []string{"a b", "dbl-1"},
			want:   `{"outer":"{\"inner\":\"{\\\"token\\\":[redacted],\\\"user\\\":\\\"bob\\\"}\"}"}`,
		},
		{
			raw:    `msg \\\"token\\\":\\\"a b dbl-2\\\" end`,
			leaked: []string{"a b", "dbl-2"},
			want:   `msg \\\"token\\\":[redacted] end`,
		},
		{
			// An escaped quote inside a doubly escaped value does not end it.
			raw:    `\\\"password\\\": \\\"a\\\\\\\"b dbl-3\\\", \\\"x\\\": 1`,
			leaked: []string{"b dbl-3"},
			want:   `\\\"password\\\": [redacted], \\\"x\\\": 1`,
		},
		{
			// An unterminated doubly escaped value redacts the rest.
			raw:    `\\\"secret\\\":\\\"never closed dbl-4`,
			leaked: []string{"never", "dbl-4"},
			want:   `\\\"secret\\\":[redacted]`,
		},
		{
			// A less escaped quote closes the string the cut-off value was
			// embedded in, so the value ends before it.
			raw:    `{"body":"{\"password\":\"cut-off dbl-5","user":"bob"}`,
			leaked: []string{"cut-off", "dbl-5"},
			want:   `{"body":"{\"password\":[redacted]","user":"bob"}`,
		},
		{
			raw:    `{"body":"{\"token\":{\"a\":\"cut-off dbl-6","user":"bob"}`,
			leaked: []string{"cut-off", "dbl-6"},
			want:   `{"body":"{\"token\":[redacted]","user":"bob"}`,
		},
		{
			// Key-like text inside a string value whose two quotes are
			// escaped differently is not a key, so it does not swallow the
			// real secret field after it.
			raw:    `{"note":"{\"x\":\"token\\\":\\\"\"}","password":"a \"b\" dbl-7"}`,
			leaked: []string{"dbl-7", `b\"`},
			want:   `"password":[redacted]}`,
		},
		{
			// Pretty-printed JSON inside a JSON string escapes the whitespace
			// around the separator; the structure after it is still whole.
			raw:    `{"body":"{\n\t\"token\":\t{\n\t\t\"value\": \"ws-6\"\n\t},\n\t\"user\":\"bob\"}"}`,
			leaked: []string{"ws-6"},
			want:   `{"body":"{\n\t\"token\":\t[redacted],\n\t\"user\":\"bob\"}"}`,
		},
		{
			// Outside an escaped string a backslash after the separator is
			// part of the value, so none of it is left behind.
			raw:    `{"password":\newpass-7,"x":1}`,
			leaked: []string{"ewpass-7", `\n`},
			want:   `{"password":[redacted],"x":1}`,
		},
		{
			// An escaped quoted value after an unquoted key runs to its
			// matching escaped closing quote as well.
			raw:    `login failed: password=\"a b dbl-5\" user=bob`,
			leaked: []string{"a b", "dbl-5"},
			want:   `password=[redacted] user=bob`,
		},
	})

	for levels := 2; levels <= 3; levels++ {
		inner := `{"user":"alice","token":"a \"q\" b lvl-secret","note":"keep me"}`
		raw := "upstream: " + jsonQuote(t, inner, levels)
		got := RedactDiagnosticMessage(raw)
		for _, leaked := range []string{"lvl-secret", "q\\"} {
			if strings.Contains(got, leaked) {
				t.Errorf("levels=%d: RedactDiagnosticMessage(%q) = %q, leaked %q", levels, raw, got, leaked)
			}
		}
		want := "upstream: " + strings.Replace(jsonQuote(t, `{"user":"alice","token":@,"note":"keep me"}`, levels), "@", "[redacted]", 1)
		if got != want {
			t.Errorf("levels=%d: RedactDiagnosticMessage() =\n%q\nwant\n%q", levels, got, want)
		}
	}
}

var fuzzSecretKeys = []string{
	"password", "authToken", "githubToken", "db_password", "DB_PASSWORD",
	"client_secret_value", "GITHUB_TOKEN", "PGPASSWORD", "x-api-key",
	"db.password", "api_key", "privateKey", "x-amz-signature", "credential",
	"Secret", "pwd", "refresh-token", "APIKey", "credentials", "dbSecrets",
	"USER_PASSWORDS", "passwds",
}

var fuzzSeparators = []string{":", ": ", " : ", "=", " = ", ":\t"}

// fuzzSecretValue builds a value of the given form that carries planted; the
// fuzzed filler is encoded so the value stays well-formed for its form.
func fuzzSecretValue(t testing.TB, form int, sep, filler, planted string) string {
	t.Helper()
	q := func(s string) string { return jsonQuote(t, s, 1) }
	switch form {
	case 0:
		return q(filler + " " + planted + " " + filler)
	case 1:
		return "{" + q("value") + sep + q(filler+planted) + "}"
	case 2:
		return "[" + q(filler) + ", " + q(planted+filler) + "]"
	case 3:
		return "{" + q("a") + sep + "[" + q(filler) + ", {" + q("b") + sep + q(planted) + "}], " + q("c") + sep + q(filler) + "}"
	case 4:
		return planted
	default:
		single := strings.NewReplacer(`'`, "", `\`, "").Replace(filler)
		return "'" + single + " " + planted + " " + single + "'"
	}
}

// FuzzRedactDiagnosticMessageSecretFields builds JSON-, dict-, and
// assignment-style diagnostics around a planted secret value, at up to three
// levels of JSON-string escaping, and checks the planted value never survives
// redaction. Arbitrary input must never panic.
func FuzzRedactDiagnosticMessageSecretFields(f *testing.F) {
	f.Add("user", "alice", "a b", uint8(0), uint8(0), uint8(0), uint8(0))
	f.Add("note", `x"}]\`, `{"[`, uint8(3), uint8(2), uint8(1), uint8(1))
	f.Add("token=", "password: ", "}", uint8(7), uint8(3), uint8(3), uint8(2))
	f.Add("tokenizer", `\"token\":\"`, `\\\"`, uint8(9), uint8(5), uint8(5), uint8(3))
	f.Add("Bearer", "Bearer ", "; & ,", uint8(12), uint8(4), uint8(4), uint8(4))
	f.Fuzz(func(t *testing.T, k1, v1, filler string, keyIdx, sepIdx, formIdx, layout uint8) {
		_ = RedactDiagnosticMessage(k1 + v1 + filler)

		const planted = "PLANTEDSECRET"
		if strings.Contains(k1+"\x00"+v1+"\x00"+filler, planted) {
			t.Skip("fuzzed text already contains the planted value")
		}
		key := fuzzSecretKeys[int(keyIdx)%len(fuzzSecretKeys)]
		sep := fuzzSeparators[int(sepIdx)%len(fuzzSeparators)]
		value := fuzzSecretValue(t, int(formIdx)%6, sep, filler, planted)
		q := func(s string) string { return jsonQuote(t, s, 1) }

		var raw string
		if layout%4 == 3 {
			// Assignment style after a JSON-quoted fuzzed prefix. An unquoted
			// value runs to the next whitespace outside its quoted segments,
			// so a prefix that holds an assignment of its own ("x password:
			// a") can pair its quotes with the next value; the prefix carries
			// no separators so it cannot.
			prefix := strings.NewReplacer(":", "", "=", "").Replace(v1)
			raw = "error " + q(prefix) + " " + key + sep + value + " " + q(k1)
		} else {
			doc := "{" + q(k1) + sep + q(v1) + ", " + q(key) + sep + value + ", " + q(k1) + sep + q(v1) + "}"
			raw = "upstream said: " + jsonQuote(t, doc, int(layout%4))
		}
		if got := RedactDiagnosticMessage(raw); strings.Contains(got, planted) {
			t.Fatalf("RedactDiagnosticMessage(%q) = %q, leaked the planted secret", raw, got)
		}
	})
}
