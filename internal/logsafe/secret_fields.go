package logsafe

import (
	"cmp"
	"slices"
	"strings"
)

const redactedValue = "[redacted]"

// maxSecretStructureBytes bounds the scan for the closing bracket of an object
// or array assigned to a secret key. A larger structure is treated like an
// unbalanced one: the rest of the message is redacted.
const maxSecretStructureBytes = 16 << 10

// secretKeyWords are the secret words a component of a key name may end with.
// The multi-word names are covered by their last word (access_token,
// client_secret, x-amz-signature), by run-together forms (apikey, privatekey,
// accesskey, sessionid), or by keySecretPairs (api_key, private_key,
// session_id). The plurals credentials, secrets, passwords, passwds, and
// passphrases usually hold a collection of secrets and count as well; tokens
// is a countKeyWord instead.
var secretKeyWords = []string{
	"password", "passwd", "pwd", "secret", "token", "credential",
	"signature", "sig", "apikey", "privatekey", "passphrase", "authorization",
	"accesskey", "accountkey", "signingkey", "encryptionkey", "masterkey",
	"sessionid", "sessid",
	"passwords", "passwds", "secrets", "credentials", "passphrases",
}

// countKeyWords are secret words that often name a count instead (LLM or
// rate-limit tokens): a key whose only secret word is one of them keeps a bare
// number value readable (see isBareNumber).
var countKeyWords = []string{"tokens"}

// shortKeyWords are common short words that name a secret only as the whole
// last component of a key name (pass, DB_PASS, basic_auth, Set-Cookie, but
// not bypass, auth_mode, or session_count). Unquoted, such a key also needs
// '=' or a ':' that is not followed by whitespace (see shortKeySeparator),
// because "admin auth: <error>" is how Go wraps errors.
var shortKeyWords = []string{"pass", "pw", "auth", "cookie", "session"}

// keySecretPairs makes a component secret when it follows one of the listed
// components: "key" after api, private, access, account, signing,
// encryption, or master (x-api-key, privateKey, AccountKey, SharedAccessKey,
// MASTER_KEY), and "id" after session (session_id).
var keySecretPairs = []struct {
	word     string
	prefixes []string
}{
	{"key", []string{"api", "private", "access", "account", "signing", "encryption", "master"}},
	{"id", []string{"session"}},
}

// authSchemes are the Authorization header schemes that stay readable in front
// of a redacted credential (Authorization: Basic [redacted]).
var authSchemes = []string{
	"basic", "bearer", "digest", "token", "negotiate", "ntlm", "oauth",
	"apikey", "sharedkey", "dpop", "aws4-hmac-sha256",
}

// keyMatch is how strongly a key name names a secret.
type keyMatch uint8

const (
	matchNone keyMatch = iota
	// matchCount: the key names a secret unless its value is a bare number.
	matchCount
	// matchShort: a short word is the whole last component (see shortKeyWords).
	matchShort
	matchSecret
)

// secretKey describes a key name for redaction.
type secretKey struct {
	// match is the strongest match of any component.
	match keyMatch
	// last is the match of the last component; a space-separated flag
	// (--password x) needs it, so --password-stdin and --token-file do not
	// take the next argument as their value.
	last keyMatch
	// scheme is set for auth and authorization keys, whose value may start
	// with a readable scheme (see authSchemes).
	scheme bool
	// cookie is set for cookie keys (Cookie, set-cookie): a cookie header
	// value runs to the end of the line, because it holds ';'-separated
	// pairs (see cookieHeaderValue).
	cookie bool
	// header is set for a cookie key capitalized as a header name (Cookie,
	// Set-Cookie).
	header bool
}

// classifySecretKey classifies a key name. The name is split into components
// at every character that is not an ASCII letter ('_', '-', '.', digits,
// spaces, '/', ':') and at camelCase boundaries ("authToken" -> auth, Token;
// "APIKey" -> API, Key). A component that ends with a secret word (db_password,
// GITHUB_TOKEN, PGPASSWORD, authToken, client_secret_value) or that pairs with
// the component before it (x-api-key, AccountKey, session_id) makes the key
// secret; a component that ends with a count word (tokens, maxTokens) makes it
// secret unless its value is a bare number; a short word as the whole last
// component (DB_PASS, basic_auth) makes it secret with a stricter separator.
// A component may carry letters before the secret word (PGPASSWORD,
// githubtoken) but not after it, so tokenizer, passwordless, and secretariat
// stay readable. A whole-word component is redacted even where it is harmless
// (token_count, has_signature): the rule errs toward over-redaction. Matching
// ignores case.
func classifySecretKey(name string) secretKey {
	var key secretKey
	prevStart, prevEnd := -1, -1
	lastStart, lastEnd := -1, -1
	forEachKeyComponent(name, func(start, end int) {
		m := componentMatch(name[start:end], name[max(prevStart, 0):max(prevEnd, 0)])
		key.match = max(key.match, m)
		key.last = m
		prevStart, prevEnd = start, end
		lastStart, lastEnd = start, end
	})
	if lastStart < 0 {
		return key
	}
	last := name[lastStart:lastEnd]
	for _, word := range shortKeyWords {
		if strings.EqualFold(last, word) {
			key.last = max(key.last, matchShort)
			key.match = max(key.match, matchShort)
		}
	}
	key.scheme = strings.EqualFold(last, "auth") || hasSuffixFold(last, "authorization")
	key.cookie = strings.EqualFold(last, "cookie")
	key.header = last == "Cookie"
	return key
}

// componentMatch matches one component of a key name; prev is the component
// before it, or "" for the first one.
func componentMatch(comp, prev string) keyMatch {
	for _, word := range secretKeyWords {
		if hasSuffixFold(comp, word) {
			return matchSecret
		}
	}
	if prev != "" {
		for _, pair := range keySecretPairs {
			if !strings.EqualFold(comp, pair.word) {
				continue
			}
			for _, prefix := range pair.prefixes {
				if hasSuffixFold(prev, prefix) {
					return matchSecret
				}
			}
		}
	}
	for _, word := range countKeyWords {
		if hasSuffixFold(comp, word) {
			return matchCount
		}
	}
	return matchNone
}

// forEachKeyComponent calls fn with the bounds of each letter component of
// name.
func forEachKeyComponent(name string, fn func(start, end int)) {
	start := -1
	for i := 0; i <= len(name); i++ {
		if i < len(name) && isASCIILetter(name[i]) {
			if start < 0 {
				start = i
			} else if isCamelBoundary(name, start, i) {
				fn(start, i)
				start = i
			}
			continue
		}
		if start >= 0 {
			fn(start, i)
			start = -1
		}
	}
}

// isCamelBoundary reports whether a new component starts at name[i] inside the
// letter run that started at runStart: a lower-to-upper change (authToken), or
// the last capital of an acronym followed by lower case (APIKey).
func isCamelBoundary(name string, runStart, i int) bool {
	if i <= runStart || !isASCIIUpper(name[i]) {
		return false
	}
	if isASCIILower(name[i-1]) {
		return true
	}
	return isASCIIUpper(name[i-1]) && i+1 < len(name) && isASCIILower(name[i+1])
}

func hasSuffixFold(s, suffix string) bool {
	return len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix)
}

func isASCIILetter(c byte) bool { return isASCIILower(c) || isASCIIUpper(c) }
func isASCIILower(c byte) bool  { return c >= 'a' && c <= 'z' }
func isASCIIUpper(c byte) bool  { return c >= 'A' && c <= 'Z' }

// isKeyChar reports whether c can be part of a key name.
func isKeyChar(c byte) bool {
	return isASCIILetter(c) || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
}

// isQuotedKeyChar reports whether c can be part of a quoted key name, which
// may also hold spaces, '/', and ':' ("Client Secret", "auth/token",
// "db:password").
func isQuotedKeyChar(c byte) bool {
	return isKeyChar(c) || c == ' ' || c == '/' || c == ':'
}

// isWordChar reports whether c is an ASCII letter, digit, or '_'.
func isWordChar(c byte) bool {
	return isASCIILetter(c) || c >= '0' && c <= '9' || c == '_'
}

// isSpace matches the whitespace of RE2's \s class.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

func isQuote(c byte) bool { return c == '"' || c == '\'' }

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// escapedAt reports whether msg[i] follows an odd number of backslashes.
func escapedAt(msg string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && msg[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}

// opensQuotedText reports whether the unescaped quote at msg[i] can open a
// quoted string in free text: it must not follow a word character, so the
// apostrophe in "can't" or "user's" opens nothing.
func opensQuotedText(msg string, i int) bool {
	return i == 0 || !isWordChar(msg[i-1])
}

// closesQuotedText reports whether the unescaped quote at msg[i] can close a
// quoted string: it must not be followed by a word character, so the
// apostrophe in 'can't' or the segment quote in "ab"cd" closes nothing.
func closesQuotedText(msg string, i int) bool {
	return i+1 == len(msg) || !isWordChar(msg[i+1])
}

// quotedText tracks whether the free text the unquoted-key scan has read so
// far left a quoted string open, and with which quote character. A key inside
// an open string ("x password: a" or {"msg":"password=a b"}) ends its value at
// the string's closing quote (see scanAssignmentValue). Redacted values are
// skipped, so the quotes of password="a b" never open a string. A line break
// ends any open string, so an unmatched quote in one line of multi-line
// output does not reach the next. The state is a heuristic: whatever it gets
// wrong, the baseline scan still redacts (see redactSecretsAndPaths).
type quotedText struct {
	open byte
}

// observe updates the state for the free-text byte msg[i].
func (q *quotedText) observe(msg string, i int) {
	c := msg[i]
	if c == '\n' || c == '\r' {
		q.open = 0
		return
	}
	if !isQuote(c) || escapedAt(msg, i) {
		return
	}
	switch {
	case q.open == 0 && opensQuotedText(msg, i):
		q.open = c
	case q.open == c && closesQuotedText(msg, i):
		q.open = 0
	}
}

// span is a byte range [start, end) of a message.
type span struct {
	start, end int
}

// redactSecretsAndPaths redacts msg after the URL and long-Bearer rewrites,
// which are the only rewrites before it: every other rule finds spans of
// this same text, and the union of all spans is replaced at once (see
// redactSpans). The baseline scan (see baselineSecretSpans) and the path
// patterns on the baseline result therefore see exactly the text they always
// saw, and every new rule (PEM private keys, short Bearer tokens, and the
// extended scan of quotedKeySecretSpans, entityQuotedKeySpans, and
// assignmentSecretSpans) can only add redaction: no value or path the
// baseline hides becomes readable. The extended scan reads ambiguous text in
// ways the baseline does not (a quote that closes a quoted label instead of
// opening a value); it runs with the private keys and short Bearer tokens
// masked (see maskSpans). Within each scan the unquoted keys are scanned
// after the quoted ones, with the values already found masked, so a quoted
// value is never cut at a ';' or space by an unquoted assignment. Paths are
// matched after the secret values, as they always were, once with the
// baseline values masked and once with all spans masked. Every scan is linear
// in the length of msg.
func redactSecretsAndPaths(msg string) string {
	baselineQuoted := baselineSecretSpans(msg, true)
	baseline := append(baselineQuoted, baselineSecretSpans(maskSpans(msg, baselineQuoted), false)...)

	keys := privateKeySpans(msg)
	bearers := bearerTokenSpans(msg)
	masked := maskSpans(msg, keys, bearers)
	quoted := quotedKeySecretSpans(masked)
	masked = maskSpans(masked, quoted)
	entity := entityQuotedKeySpans(masked)
	masked = maskSpans(masked, entity)
	assigned := assignmentSecretSpans(masked)

	baselineMasked := maskSpans(msg, baseline)
	paths := append(pathSpans(baselineMasked), pathSpans(maskSpans(masked, baseline))...)
	return redactSpans(msg,
		spanGroup{redactedPrivateKey, keys},
		spanGroup{redactedValue, slices.Concat(baseline, bearers, quoted, entity, assigned)},
		spanGroup{redactedPath, paths})
}

// pathSpans returns the local filesystem paths in msg: Windows paths, then
// Unix paths in msg with the Windows paths masked, as the two patterns ran
// one after the other.
func pathSpans(msg string) []span {
	var spans []span
	for _, m := range windowsPathPattern.FindAllStringIndex(msg, -1) {
		spans = append(spans, span{m[0], m[1]})
	}
	for _, m := range unixPathPattern.FindAllStringSubmatchIndex(maskSpans(msg, spans), -1) {
		spans = append(spans, span{m[3], m[1]})
	}
	return spans
}

// maskSpans returns msg with the bytes of spans replaced by NUL bytes. A later
// scan or path pattern sees a masked value like the "[redacted]" or
// "(redacted-path)" marker it becomes (no quote, whitespace, backslash, slash,
// or key character, and no word character at its edges), but at the original
// offsets, so the spans of all scans share one coordinate system.
func maskSpans(msg string, lists ...[]span) string {
	var masked []byte
	for _, list := range lists {
		for _, s := range list {
			if masked == nil {
				masked = []byte(msg)
			}
			for i := s.start; i < s.end; i++ {
				masked[i] = 0
			}
		}
	}
	if masked == nil {
		return msg
	}
	return string(masked)
}

// replaceSpans replaces the union of the spans with "[redacted]"; overlapping or
// touching spans become one marker.
func replaceSpans(msg string, lists ...[]span) string {
	return redactSpans(msg, spanGroup{redactedValue, slices.Concat(lists...)})
}

// spanGroup is a list of spans and the marker that replaces them. In the
// argument list of redactSpans, a later group's marker wins where spans of
// several groups overlap.
type spanGroup struct {
	marker string
	spans  []span
}

// redactSpans replaces the union of the spans of all groups: overlapping or
// touching spans become one marker, that of the latest group among them.
func redactSpans(msg string, groups ...spanGroup) string {
	type marked struct {
		span
		group int
	}
	var all []marked
	for g, group := range groups {
		for _, s := range group.spans {
			all = append(all, marked{s, g})
		}
	}
	if len(all) == 0 {
		return msg
	}
	slices.SortFunc(all, func(a, b marked) int { return cmp.Compare(a.start, b.start) })
	var out strings.Builder
	copied := 0
	for i := 0; i < len(all); {
		start, end, group := all[i].start, all[i].end, all[i].group
		for i++; i < len(all) && all[i].start <= end; i++ {
			end = max(end, all[i].end)
			group = max(group, all[i].group)
		}
		out.WriteString(msg[copied:start])
		out.WriteString(groups[group].marker)
		copied = end
	}
	out.WriteString(msg[copied:])
	return out.String()
}

// quotedKeySecretSpans returns the values of quoted secret keys in JSON- and
// dict-style text: "password":"x", 'token': 'x', or \"token\":\"x\" and
// \\\"token\\\":\\\"x\\\" inside JSON embedded once or more in a JSON string,
// with optional whitespace around ':' or '='. The key name runs between two
// equal quotes escaped by the same number of backslashes (see
// secretKeySeparator), may hold spaces, '/', and ':' ("Client Secret"), and
// must name a secret (see classifySecretKey); the value may start after any
// odd number of escaping backslashes. The value is one quoted string (see
// scanQuotedValue), one object or array (see scanStructuredValue), or an
// unquoted scalar that ends at whitespace or a JSON delimiter, so the
// neighbouring non-secret fields of an object stay readable.
func quotedKeySecretSpans(msg string) []span {
	return secretFieldSpans(msg, true)
}

// assignmentSecretSpans returns the values of unquoted secret keys followed
// by ':' or '=' (password=x, GITHUB_TOKEN=x, x-api-key: x), by a URL-encoded
// '=' or ':' (password%3Dx), or, for a command-line flag, by whitespace
// (--password x, -p x; see flagValueStart). The value runs to the next
// unquoted, unescaped whitespace, or to a ';' or '&' (or "%26") that is
// followed by whitespace, the end, or the next key=value pair, so password=a;b
// is redacted whole while a=1&token=x&b=2 keeps a and b readable (see
// endsValueAfter). It is a sequence of single- or double-quoted segments
// (libpq key/value DSNs quote values with spaces), backslash escapes, and
// plain characters, so text after a closing quote ("ab"cd) or an escaped space
// (foo\ bar) is redacted with it. A value that starts with an object or array,
// or with an escaped quote (\"a b\"), takes that whole structure or escaped
// string first. A key inside a quoted string of the free text ("x password:
// a", see quotedText) ends its value at that string's closing quote. An
// unterminated quote redacts the rest of the message. A backslash escapes any
// character, a newline included.
func assignmentSecretSpans(msg string) []span {
	return secretFieldSpans(msg, false)
}

// keyQuote describes the quotes around a quoted key: the quote character and
// the number of backslashes that escape each of them. It is the zero value for
// an unquoted key.
type keyQuote struct {
	char  byte
	level int
}

// secretFieldSpans scans msg once, left to right, for key names followed by a
// separator and returns the value of every secret key. Each key-name run is
// examined once and each value found is skipped as a whole, so the scan is
// linear in the length of msg.
func secretFieldSpans(msg string, quotedKeys bool) []span {
	var spans []span
	var text quotedText
	for i := 0; i < len(msg); {
		keyEnd := keyRunEnd(msg, i, quotedKeys)
		if keyEnd == i {
			if !quotedKeys {
				text.observe(msg, i)
			}
			i++
			continue
		}
		valueStart, valueEnd, key := secretFieldValue(msg, i, keyEnd, quotedKeys, text.open)
		if valueEnd == valueStart || key.match == matchNone ||
			key.match == matchCount && isBareNumber(msg[valueStart:valueEnd]) {
			i = keyEnd
			continue
		}
		spans = append(spans, span{valueStart, valueEnd})
		i = valueEnd
	}
	return spans
}

// keyRunEnd returns the end of the key name that starts at msg[i], or i when
// no key name starts there. An unquoted key name is a run of key characters
// (see isKeyChar); a quoted one starts right after a quote and may also hold
// spaces, '/', and ':' (see isQuotedKeyChar).
func keyRunEnd(msg string, i int, quotedKeys bool) int {
	isChar := isKeyChar
	if quotedKeys {
		if i == 0 || !isQuote(msg[i-1]) {
			return i
		}
		isChar = isQuotedKeyChar
	} else if i > 0 && isKeyChar(msg[i-1]) {
		return i
	}
	end := i
	for end < len(msg) && isChar(msg[end]) {
		end++
	}
	return end
}

// secretFieldValue returns the bounds of the value of the key msg[start:end]
// and the key's classification, or an empty value when the key has none.
// enclosing is the quote of the free-text string the key sits in, or 0.
func secretFieldValue(msg string, start, end int, quotedKeys bool, enclosing byte) (int, int, secretKey) {
	valueStart, quote, ok := secretKeySeparator(msg, start, end, quotedKeys)
	var key secretKey
	switch {
	case ok:
		key = classifySecretKey(msg[start:end])
		if !quotedKeys && cookieHeaderValue(msg, end, valueStart, key) {
			return valueStart, scanLineValue(msg, valueStart, enclosing), key
		}
		if !quotedKeys && key.match == matchShort && !shortKeySeparator(msg, end) {
			return 0, 0, secretKey{}
		}
	case !quotedKeys:
		valueStart, key, ok = flagValueStart(msg, start, end)
		if !ok {
			return 0, 0, secretKey{}
		}
	default:
		return 0, 0, secretKey{}
	}
	if key.match == matchNone {
		return 0, 0, key
	}
	if quotedKeys {
		return valueStart, scanQuotedKeyValue(msg, valueStart, quote), key
	}
	if key.scheme {
		if credential := skipAuthScheme(msg, valueStart); credential > valueStart {
			if credentialEnd := scanAssignmentValue(msg, credential, enclosing); credentialEnd > credential {
				return credential, credentialEnd, key
			}
		}
	}
	return valueStart, scanAssignmentValue(msg, valueStart, enclosing), key
}

// cookieHeaderValue reports whether the unquoted cookie key that ends at
// msg[end] is a Cookie or Set-Cookie header whose value starts at valueStart:
// the separator is ':', and the key is capitalized as a header name (Cookie:)
// or the value's first token, up to whitespace or ';', is a name=value pair
// (cookie: sid=x, as HTTP/2 and proxies write it). "invalid cookie: missing
// name" is prose and follows the short-word separator rule.
func cookieHeaderValue(msg string, end, valueStart int, key secretKey) bool {
	if !key.cookie || strings.TrimLeft(msg[end:valueStart], " \t\n\f\r")[0] != ':' {
		return false
	}
	if key.header {
		return true
	}
	for i := valueStart; i < len(msg) && !isSpace(msg[i]) && msg[i] != ';'; i++ {
		if msg[i] == '=' {
			return true
		}
	}
	return false
}

// shortKeySeparator reports whether the separator that secretKeySeparator
// matched after the unquoted short key ending at msg[end] counts: '=' (with
// optional whitespace), a URL-encoded separator, or a ':' that directly
// follows the key and is not followed by whitespace (auth:x, but not "admin
// auth: connection refused").
func shortKeySeparator(msg string, end int) bool {
	i := end
	for isSpace(msg[i]) {
		i++
	}
	if msg[i] != ':' {
		return true
	}
	return i == end && i+1 < len(msg) && !isSpace(msg[i+1])
}

// flagValueStart matches a command-line flag whose value is the next argument
// (--password x, -token x, -p x) and returns where the value starts. The flag
// starts with one or two dashes at the start of msg or after whitespace or a
// quote, its last name component must name a secret (see secretKey.last), and
// the value must not start with '-', which would be the next flag. "-p" is
// treated as a password flag although it means a port or parallelism for many
// tools: the redaction errs toward hiding the value.
func flagValueStart(msg string, start, end int) (int, secretKey, bool) {
	flag := msg[start:end]
	if !strings.HasPrefix(flag, "-") || start > 0 && !isSpace(msg[start-1]) && !isQuote(msg[start-1]) {
		return 0, secretKey{}, false
	}
	name := strings.TrimPrefix(strings.TrimPrefix(flag, "-"), "-")
	if name == "" || !isASCIILetter(name[0]) {
		return 0, secretKey{}, false
	}
	var key secretKey
	if flag == "-p" {
		key = secretKey{match: matchSecret, last: matchSecret}
	} else if key = classifySecretKey(name); key.last == matchNone {
		return 0, secretKey{}, false
	}
	i := end
	for i < len(msg) && (msg[i] == ' ' || msg[i] == '\t') {
		i++
	}
	if i == end || i == len(msg) || msg[i] == '-' || isSpace(msg[i]) {
		return 0, secretKey{}, false
	}
	key.cookie = false
	return i, key, true
}

// skipAuthScheme returns where the credential after a readable Authorization
// scheme (see authSchemes) starts in the value that starts at msg[i], or i
// when the value does not start with a scheme and whitespace.
func skipAuthScheme(msg string, i int) int {
	j := i
	for j < len(msg) && (isASCIILetter(msg[j]) || msg[j] >= '0' && msg[j] <= '9' || msg[j] == '-') {
		j++
	}
	if j == i || j == len(msg) || (msg[j] != ' ' && msg[j] != '\t') {
		return i
	}
	scheme := msg[i:j]
	for _, known := range authSchemes {
		if strings.EqualFold(scheme, known) {
			for j < len(msg) && (msg[j] == ' ' || msg[j] == '\t') {
				j++
			}
			return j
		}
	}
	return i
}

// secretKeySeparator matches the separator after the key name msg[start:end]
// and returns where the value starts. A quoted key needs the same quote
// character, escaped by the same number of backslashes, right before and
// right after it; text such as `token\":\"` inside a string value, whose two
// quotes differ, is not a key. An unquoted key needs the separator right after
// it, or a URL-encoded one (%3D or %3A, optionally after a URL-encoded quote
// %22 or %27). Whitespace may surround ':' or '='. When the key's quotes are
// escaped, the key sits in an escaped JSON string, so an escaped tab, newline,
// or carriage return (\t, \n, \r, after any number of backslashes) counts as
// whitespace too.
func secretKeySeparator(msg string, start, end int, quotedKeys bool) (int, keyQuote, bool) {
	var quote keyQuote
	i := end
	if quotedKeys {
		if start == 0 || !isQuote(msg[start-1]) {
			return 0, quote, false
		}
		open := start - 1
		for open > 0 && msg[open-1] == '\\' {
			open--
		}
		quote = keyQuote{char: msg[start-1], level: start - 1 - open}
		for i < len(msg) && msg[i] == '\\' {
			i++
		}
		if i == len(msg) || msg[i] != quote.char || i-end != quote.level {
			return 0, quote, false
		}
		i++
	} else {
		j := i
		if hasPrefixFold(msg[j:], "%22") || hasPrefixFold(msg[j:], "%27") {
			j += 3
		}
		if hasPrefixFold(msg[j:], "%3D") || hasPrefixFold(msg[j:], "%3A") {
			return j + 3, quote, true
		}
	}
	i = skipSeparatorSpace(msg, i, quote.level > 0)
	if i == len(msg) || (msg[i] != ':' && msg[i] != '=') {
		return 0, quote, false
	}
	return skipSeparatorSpace(msg, i+1, quote.level > 0), quote, true
}

// skipSeparatorSpace skips whitespace from i on and, when escaped is set,
// escaped whitespace (see secretKeySeparator).
func skipSeparatorSpace(msg string, i int, escaped bool) int {
	for i < len(msg) {
		if isSpace(msg[i]) {
			i++
			continue
		}
		if !escaped || msg[i] != '\\' {
			return i
		}
		j := i
		for j < len(msg) && msg[j] == '\\' {
			j++
		}
		if j == len(msg) || (msg[j] != 't' && msg[j] != 'n' && msg[j] != 'r') {
			return i
		}
		i = j + 1
	}
	return i
}

// endsValueAfter reports whether a ';' or '&' (or "%26") delimiter that ends
// right before msg[i] ends an unquoted value: it does when whitespace or the
// end of msg follows, or the next key=value pair (a key name and '=' or
// "%3D"). Otherwise it is part of the value (password=a;b, a&amp;b).
func endsValueAfter(msg string, i int) bool {
	if i == len(msg) || isSpace(msg[i]) {
		return true
	}
	j := i
	for j < len(msg) && isKeyChar(msg[j]) {
		j++
	}
	return j > i && j < len(msg) && (msg[j] == '=' || hasPrefixFold(msg[j:], "%3D"))
}

// isBareNumber reports whether a value is a plain number such as 3, -1, 2.5,
// or 4,096, optionally followed by sentence punctuation; a key whose only
// secret word is a count word keeps such a value readable.
func isBareNumber(value string) bool {
	value = strings.TrimRight(value, ",.;)")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "-"), "+")
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= '0' && c <= '9' {
			continue
		}
		if (c != '.' && c != ',' && c != '_') || i == 0 || i+1 == len(value) || value[i+1] < '0' || value[i+1] > '9' {
			return false
		}
	}
	return true
}

// scanQuotedKeyValue returns the end of the value of a quoted secret key that
// starts at i, or i when there is none. The key's quote character escaped by
// fewer backslashes than the key's own quotes, followed by a JSON delimiter,
// whitespace, or the end, closes the string the key is embedded in, so an
// unquoted scalar ends before it (see closesEmbeddedString).
func scanQuotedKeyValue(msg string, i int, quote keyQuote) int {
	if end, ok := scanLeadingQuotedOrStructured(msg, i, quote); ok {
		return end
	}
	j, run, checkedUntil := i, 0, 0
	for ; j < len(msg); j++ {
		c := msg[j]
		if c == '\\' {
			run++
			continue
		}
		if c == quote.char && run < quote.level && j >= checkedUntil {
			closes, next := closesEmbeddedStringAt(msg, j)
			if closes {
				return j - run
			}
			checkedUntil = next
		}
		if run%2 == 0 && (isSpace(c) || strings.IndexByte(",}]", c) >= 0 ||
			(c == ';' || c == '&') && endsValueAfter(msg, j+1)) {
			break
		}
		run = 0
	}
	return j
}

// scanAssignmentValue returns the end of the value of an unquoted secret key
// that starts at i, or i when there is none. A key inside a quoted string of
// the free text (enclosing, or 0) ends its value at that string's closing
// quote instead of opening a quoted segment. The value is empty only for a
// label, whose separator the closing quote follows after nothing but
// whitespace and which whitespace or the end follows (`"Password:"
// PGPASSWORD=x`, `"passwd: " next`), so the next key is still found; any
// other value that starts with the enclosing quote takes it as a quoted
// segment. A quote of the other kind inside such a string (the
// apostrophe in "password: it's") opens a segment that ends at the latest at
// the enclosing closing quote.
func scanAssignmentValue(msg string, i int, enclosing byte) int {
	if enclosing != 0 && i < len(msg) && msg[i] == enclosing && endsLabel(msg, i) {
		return i
	}
	j := i
	if i < len(msg) && (msg[i] == '{' || msg[i] == '[' || msg[i] == '\\') {
		if end, ok := scanLeadingQuotedOrStructured(msg, i, keyQuote{}); ok {
			j = end
		}
	}
	for j < len(msg) {
		c := msg[j]
		switch {
		case enclosing != 0 && c == enclosing && j > i && closesQuotedText(msg, j):
			return j
		case isQuote(c):
			end, closed := scanValueSegment(msg, j+1, c, enclosing)
			if !closed {
				return end
			}
			j = end
		case c == '\\':
			if j+1 == len(msg) {
				return j
			}
			j += 2
		case isSpace(c),
			(c == ';' || c == '&') && endsValueAfter(msg, j+1),
			c == '%' && hasPrefixFold(msg[j:], "%26") && endsValueAfter(msg, j+3):
			return j
		default:
			j++
		}
	}
	return j
}

// endsLabel reports whether the quote at msg[i] closes a quoted label: only
// whitespace separates it from the ':' or '=' before it, and whitespace or the
// end follows it.
func endsLabel(msg string, i int) bool {
	if i+1 < len(msg) && !isSpace(msg[i+1]) {
		return false
	}
	j := i - 1
	for j >= 0 && isSpace(msg[j]) {
		j--
	}
	return j >= 0 && (msg[j] == ':' || msg[j] == '=')
}

// scanValueSegment returns the end of a quoted segment of an unquoted value
// whose content starts at i and whose quote character is q. Inside a quoted
// string of the free text (enclosing) a segment of the other quote kind ends
// at the string's closing quote, which then also ends the value (closed is
// false): an apostrophe cannot pair with a quote outside the string.
func scanValueSegment(msg string, i int, q, enclosing byte) (int, bool) {
	if enclosing == 0 || q == enclosing {
		return scanQuotedValue(msg, i, q, 0, len(msg)), true
	}
	run := 0
	for j := i; j < len(msg); j++ {
		c := msg[j]
		switch {
		case c == '\\':
			run++
			continue
		case run%2 == 1:
		case c == q:
			return j + 1, true
		case c == enclosing && closesQuotedText(msg, j):
			return j, false
		}
		run = 0
	}
	return len(msg), true
}

// scanLineValue returns the end of a header value that runs to the end of the
// line (Cookie: a=1; b=2), or to the closing quote of the free-text string
// the key sits in (enclosing). A backslash-escaped line break continues it.
func scanLineValue(msg string, i int, enclosing byte) int {
	for j := i; j < len(msg); j++ {
		c := msg[j]
		switch {
		case c == '\\':
			j++
		case c == '\n' || c == '\r':
			return j
		case enclosing != 0 && c == enclosing && closesQuotedText(msg, j):
			return j
		}
	}
	return len(msg)
}

// scanLeadingQuotedOrStructured scans a value that starts at i with a quoted
// string (unescaped, or after an odd number of escaping backslashes: an even
// number escapes only themselves) or with an object or array, and returns its
// end. quote is the key's quoting (see scanStructuredValue): the key's quote
// character escaped by fewer backslashes than the key's own quotes and
// followed by a JSON delimiter, whitespace, or the end does not open the
// value, it closes the string the key is embedded in, so the value is empty
// (the key was cut off after its separator) and that quote is not paired with
// the next one. Any other such quote opens the value as before, so ambiguous
// text errs toward redaction.
func scanLeadingQuotedOrStructured(msg string, i int, quote keyQuote) (int, bool) {
	if i == len(msg) {
		return 0, false
	}
	if msg[i] == '{' || msg[i] == '[' {
		return scanStructuredValue(msg, i, quote), true
	}
	j := i
	for j < len(msg) && msg[j] == '\\' {
		j++
	}
	if j < len(msg) && msg[j] == quote.char && j-i < quote.level && closesEmbeddedString(msg, j) {
		return i, true
	}
	if j < len(msg) && isQuote(msg[j]) && (j-i)%2 == 0 && j > i {
		return 0, false
	}
	if j < len(msg) && isQuote(msg[j]) {
		return scanQuotedValue(msg, j+1, msg[j], j-i, len(msg)), true
	}
	return 0, false
}

// closesEmbeddedString reports whether the quote at msg[i] is followed, after
// any further backslashes and quotes (the closing quotes of the less escaped
// strings around it, as in \"\\"), by a JSON delimiter (',', '}', ']'),
// whitespace, or the end, as the closing quote of a string is.
func closesEmbeddedString(msg string, i int) bool {
	closes, _ := closesEmbeddedStringAt(msg, i)
	return closes
}

// closesEmbeddedStringAt is closesEmbeddedString that also returns where the
// run of backslashes and quotes after msg[i] ends; every quote before that
// position gets the same answer.
func closesEmbeddedStringAt(msg string, i int) (bool, int) {
	j := i + 1
	for j < len(msg) && (msg[j] == '\\' || isQuote(msg[j])) {
		j++
	}
	return j == len(msg) || isSpace(msg[j]) || strings.IndexByte(",}]", msg[j]) >= 0, j
}

// scanQuotedValue returns the end of a quoted string whose content starts at
// i, whose quote character is q, and whose opening quote was preceded by n
// escaping backslashes; it returns limit when the string is not closed before
// limit. n is 0 for a plain string, 1 for JSON embedded in a JSON string
// (\"a b\"), 3 for JSON embedded twice (\\\"a b\\\"), and in general 2^k-1
// at nesting depth k. At that depth a content backslash is written as n+1
// backslashes and the closing quote as n backslashes and the quote, so a quote
// q preceded by m backslashes closes the string exactly when m-n is a
// non-negative multiple of 2(n+1). With m < n it cannot be part of the string:
// it closes an enclosing, less escaped string, so the value ends before it (a
// value cut off inside JSON embedded in a JSON string). Any other quote (an
// escaped quote inside the value, or the other quote character) and any other
// escape (\n) belong to the value. For n=0 this is the usual rule: an even
// number of backslashes.
func scanQuotedValue(msg string, i int, q byte, n, limit int) int {
	run := 0
	for ; i < limit; i++ {
		c := msg[i]
		if c == '\\' {
			run++
			continue
		}
		if c == q {
			if run < n {
				return i - run
			}
			if (run-n)%(2*(n+1)) == 0 {
				return i + 1
			}
		}
		run = 0
	}
	return limit
}

// scanStructuredValue returns the end of the object or array that starts at
// msg[i] ('{' or '['): the position after the bracket that brings the nesting
// depth back to zero. Brackets inside quoted strings, at any escaping depth
// (see scanQuotedValue), do not count, and '{' and '[' are counted alike, so
// mismatched kinds still end the value. The key's quote character escaped by
// fewer backslashes than the key's own quotes closes the string the structure
// is embedded in, so the structure ends before it. RE2 cannot balance
// brackets, hence this scanner. An unbalanced structure, or one that does not
// close within maxSecretStructureBytes, redacts the rest of the message.
func scanStructuredValue(msg string, i int, quote keyQuote) int {
	limit := min(len(msg), i+maxSecretStructureBytes)
	depth, run := 0, 0
	for j := i; j < limit; j++ {
		c := msg[j]
		switch {
		case c == '\\':
			run++
			continue
		case c == quote.char && run < quote.level:
			return j - run
		case isQuote(c):
			j = scanQuotedValue(msg, j+1, c, run, limit) - 1
		case c == '{' || c == '[':
			depth++
		case c == '}' || c == ']':
			depth--
			if depth == 0 {
				return j + 1
			}
		}
		run = 0
	}
	return len(msg)
}
