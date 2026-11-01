package logsafe

import (
	"regexp"
	"strings"
)

const redactedPrivateKey = "(redacted-private-key)"

var (
	// privateKeyBlockPattern matches a PEM private key (RSA, EC, OPENSSH,
	// ENCRYPTED, PGP ... PRIVATE KEY [BLOCK]) through its END marker, or
	// through the end of a message that was cut off inside it. The base64 body
	// spans spaces and line breaks, so no key=value scan can bound it.
	privateKeyBlockPattern = regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\z)`)

	// longBearerTokenPattern is the baseline Bearer rule (tokens of
	// minBearerTokenLen or more characters), which rewrites the text before
	// any scan; bearerTokenPattern then finds the shorter tokens left behind.
	longBearerTokenPattern = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	bearerTokenPattern     = regexp.MustCompile(`(?i)\bBearer\s+([A-Za-z0-9._~+/=-]+)`)
)

// bearerProseWords are words shorter than minBearerTokenLen that follow
// "Bearer" in prose ("missing Bearer token", `Bearer realm="x"`) rather than
// a credential, so they stay readable.
var bearerProseWords = []string{
	"token", "tokens", "auth", "scheme", "realm", "header", "prefix",
	"missing", "invalid",
}

// minBearerTokenLen is the length from which the text after "Bearer" is always
// redacted, prose word or not.
const minBearerTokenLen = 8

// privateKeySpans returns every PEM private key block.
func privateKeySpans(msg string) []span {
	if !strings.Contains(msg, "-----") {
		return nil
	}
	var spans []span
	for _, m := range privateKeyBlockPattern.FindAllStringIndex(msg, -1) {
		spans = append(spans, span{m[0], m[1]})
	}
	return spans
}

// bearerTokenSpans returns the credentials after "Bearer" that the baseline
// rule (longBearerTokenPattern, already applied to msg) left behind: tokens
// shorter than minBearerTokenLen that are not a word of prose (see
// bearerProseWords). "Bearer" stays as it is.
func bearerTokenSpans(msg string) []span {
	var spans []span
	for _, m := range bearerTokenPattern.FindAllStringSubmatchIndex(msg, -1) {
		token := msg[m[2]:m[3]]
		if len(token) < minBearerTokenLen && isBearerProseWord(token) {
			continue
		}
		spans = append(spans, span{m[2], m[3]})
	}
	return spans
}

func isBearerProseWord(token string) bool {
	word := strings.TrimRight(token, "=")
	for _, prose := range bearerProseWords {
		if strings.EqualFold(word, prose) {
			return true
		}
	}
	return false
}

// entityQuotes are the HTML character references of the two quote characters
// that HTML-escaped JSON or dict text uses.
var entityQuotes = []struct {
	ref  string
	char byte
}{
	{"&quot;", '"'},
	{"&#34;", '"'},
	{"&#x22;", '"'},
	{"&apos;", '\''},
	{"&#39;", '\''},
	{"&#x27;", '\''},
}

// entityQuoteAt returns the quote character and length of the HTML character
// reference of a quote at msg[i], or 0 and 0. Matching ignores case.
func entityQuoteAt(msg string, i int) (byte, int) {
	if i >= len(msg) || msg[i] != '&' {
		return 0, 0
	}
	for _, quote := range entityQuotes {
		if hasPrefixFold(msg[i:], quote.ref) {
			return quote.char, len(quote.ref)
		}
	}
	return 0, 0
}

// entityQuotedKeySpans returns the values of secret keys quoted with HTML
// character references, as in HTML-escaped JSON
// (&quot;password&quot;:&quot;x&quot;, &#34;token&#34;: &#34;x&#34;). The key
// name follows the rules of quotedKeySecretSpans. The value is one
// entity-quoted string up to the matching entity quote that no backslash
// escapes, one object or array up to its balanced closing bracket (ignoring
// brackets inside entity-quoted strings), or a scalar that ends at whitespace,
// ',', '}', ']', or '&'. An unterminated string, or an unbalanced structure or
// one larger than maxSecretStructureBytes, redacts the rest of the message.
// Like the other scans it is linear in the length of msg.
func entityQuotedKeySpans(msg string) []span {
	if !strings.Contains(msg, "&") {
		return nil
	}
	var spans []span
	for i := 0; i < len(msg); {
		q, n := entityQuoteAt(msg, i)
		if n == 0 {
			i++
			continue
		}
		keyStart := i + n
		keyEnd := keyStart
		for keyEnd < len(msg) && isQuotedKeyChar(msg[keyEnd]) {
			keyEnd++
		}
		closeQ, closeN := entityQuoteAt(msg, keyEnd)
		if keyEnd == keyStart || closeQ != q {
			i = keyEnd
			continue
		}
		valueStart := keyEnd + closeN
		for valueStart < len(msg) && isSpace(msg[valueStart]) {
			valueStart++
		}
		if valueStart == len(msg) || (msg[valueStart] != ':' && msg[valueStart] != '=') {
			i = keyEnd
			continue
		}
		valueStart++
		for valueStart < len(msg) && isSpace(msg[valueStart]) {
			valueStart++
		}
		key := classifySecretKey(msg[keyStart:keyEnd])
		if key.match == matchNone {
			i = keyEnd
			continue
		}
		valueEnd := scanEntityQuotedValue(msg, valueStart)
		if valueEnd == valueStart || key.match == matchCount && isBareNumber(msg[valueStart:valueEnd]) {
			i = keyEnd
			continue
		}
		spans = append(spans, span{valueStart, valueEnd})
		i = valueEnd
	}
	return spans
}

// scanEntityQuotedValue returns the end of the value that starts at msg[i]
// after an entity-quoted key (see entityQuotedKeySpans).
func scanEntityQuotedValue(msg string, i int) int {
	if i == len(msg) {
		return i
	}
	if q, n := entityQuoteAt(msg, i); n > 0 {
		return scanEntityQuotedString(msg, i+n, q, len(msg))
	}
	if msg[i] == '{' || msg[i] == '[' {
		limit := min(len(msg), i+maxSecretStructureBytes)
		depth := 0
		for j := i; j < limit; j++ {
			if q, n := entityQuoteAt(msg, j); n > 0 {
				j = scanEntityQuotedString(msg, j+n, q, limit) - 1
				continue
			}
			switch msg[j] {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1
				}
			}
		}
		return len(msg)
	}
	j := i
	for j < len(msg) && !isSpace(msg[j]) && strings.IndexByte(",}]&", msg[j]) < 0 {
		j++
	}
	return j
}

// scanEntityQuotedString returns the end of an entity-quoted string whose
// content starts at i and whose quote character is q: the position after the
// first entity quote of the same character that an even number of
// backslashes precedes, or limit.
func scanEntityQuotedString(msg string, i int, q byte, limit int) int {
	run := 0
	for j := i; j < limit; j++ {
		if msg[j] == '\\' {
			run++
			continue
		}
		if c, n := entityQuoteAt(msg, j); n > 0 && c == q && run%2 == 0 {
			return min(j+n, limit)
		}
		run = 0
	}
	return limit
}
