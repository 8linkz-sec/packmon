package logsafe

import "strings"

const redactedValue = "[redacted]"

// maxSecretStructureBytes bounds the scan for the closing bracket of an object
// or array assigned to a secret key. A larger structure is treated like an
// unbalanced one: the rest of the message is redacted.
const maxSecretStructureBytes = 16 << 10

// secretKeyWords are the secret words a component of a key name may end with.
// The multi-word names are covered by their last word (access_token,
// client_secret, x-amz-signature), by the run-together forms apikey and
// privatekey, or by keySecretPrefixes (api_key, private_key). The plurals
// credentials, secrets, passwords, and passwds usually hold a collection of
// secrets and count as well; tokens does not, because it usually counts
// (LLM or rate-limit tokens).
var secretKeyWords = []string{
	"password", "passwd", "pwd", "secret", "token", "credential",
	"signature", "sig", "apikey", "privatekey",
	"passwords", "passwds", "secrets", "credentials",
}

// keySecretPrefixes are the components that make a following "key" component
// secret (api_key, x-api-key, privateKey).
var keySecretPrefixes = []string{"api", "private"}

// isSecretKeyName reports whether a key name names a secret. The name is split
// into components at every character that is not an ASCII letter ('_', '-',
// '.', and digits) and at camelCase boundaries ("authToken" -> auth, Token;
// "APIKey" -> API, Key). The key is secret when a component ends with a secret
// word (db_password, GITHUB_TOKEN, PGPASSWORD, authToken, client_secret_value)
// or is "key" right after an "api" or "private" component (x-api-key,
// privateKey). A component may carry letters before the secret word
// (PGPASSWORD, githubtoken) but not after it, so tokenizer, tokens_count,
// passwordless, and secretariat stay readable. A whole-word component is
// redacted even where it is harmless (token_count, has_signature): the rule
// errs toward over-redaction. Matching ignores case.
func isSecretKeyName(name string) bool {
	prevStart, prevEnd := -1, -1
	secret := false
	forEachKeyComponent(name, func(start, end int) bool {
		comp := name[start:end]
		for _, word := range secretKeyWords {
			if hasSuffixFold(comp, word) {
				secret = true
				return false
			}
		}
		if prevStart >= 0 && strings.EqualFold(comp, "key") {
			for _, prefix := range keySecretPrefixes {
				if hasSuffixFold(name[prevStart:prevEnd], prefix) {
					secret = true
					return false
				}
			}
		}
		prevStart, prevEnd = start, end
		return true
	})
	return secret
}

// forEachKeyComponent calls fn with the bounds of each letter component of
// name until fn returns false.
func forEachKeyComponent(name string, fn func(start, end int) bool) {
	start := -1
	for i := 0; i <= len(name); i++ {
		if i < len(name) && isASCIILetter(name[i]) {
			if start < 0 {
				start = i
			} else if isCamelBoundary(name, start, i) {
				if !fn(start, i) {
					return
				}
				start = i
			}
			continue
		}
		if start >= 0 {
			if !fn(start, i) {
				return
			}
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

// isSpace matches the whitespace of RE2's \s class.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

func isQuote(c byte) bool { return c == '"' || c == '\'' }

// redactQuotedKeySecrets redacts the values of quoted secret keys in JSON- and
// dict-style text: "password":"x", 'token': 'x', or \"token\":\"x\" and
// \\\"token\\\":\\\"x\\\" inside JSON embedded once or more in a JSON string,
// with optional whitespace around ':' or '='. The key name runs between two
// equal quotes escaped by the same number of backslashes (see
// secretKeySeparator) and must be a secret key name (see isSecretKeyName),
// and the value may start after any number of escaping backslashes. The value is
// one quoted string (see scanQuotedValue), one object or array (see
// scanStructuredValue), or an unquoted scalar that ends at whitespace or a
// JSON delimiter, so the neighbouring non-secret fields of an object stay
// readable. It runs before redactSecretAssignments, which does not match a key
// followed by a quote, so a quoted value is never cut at a ';' or space by an
// earlier unquoted assignment.
func redactQuotedKeySecrets(msg string) string {
	return redactSecretFields(msg, true)
}

// redactSecretAssignments redacts the values of unquoted secret keys followed
// by ':' or '=' (password=x, GITHUB_TOKEN=x, x-api-key: x). The value runs to
// the next unquoted, unescaped whitespace, ';', or '&' (or the end): it is a
// sequence of single- or double-quoted segments (libpq key/value DSNs quote
// values with spaces), backslash escapes, and plain characters, so text after
// a closing quote ("ab"cd) or an escaped space (foo\ bar) is redacted with it.
// A value that starts with an object or array, or with an escaped quote
// (\"a b\"), takes that whole structure or escaped string first. A key right
// after an unescaped quote ("password=x") sits inside that quoted string, so
// the string's closing quote ends the value (see scanAssignmentValue). An
// unterminated quote redacts the rest of the message. A backslash escapes any
// character, a newline included.
func redactSecretAssignments(msg string) string {
	return redactSecretFields(msg, false)
}

// keyQuote describes the quotes around a quoted key: the quote character and
// the number of backslashes that escape each of them. It is the zero value for
// an unquoted key.
type keyQuote struct {
	char  byte
	level int
}

// redactSecretFields scans msg once, left to right, for key names followed by
// a separator and replaces the value of every secret key with "[redacted]".
// Each key-name run is examined once and each redacted value is skipped as a
// whole, so the scan is linear in the length of msg.
func redactSecretFields(msg string, quotedKeys bool) string {
	var out strings.Builder
	copied := 0
	for i := 0; i < len(msg); {
		if !isKeyChar(msg[i]) || (i > 0 && isKeyChar(msg[i-1])) {
			i++
			continue
		}
		keyEnd := i
		for keyEnd < len(msg) && isKeyChar(msg[keyEnd]) {
			keyEnd++
		}
		valueStart, quote, ok := secretKeySeparator(msg, i, keyEnd, quotedKeys)
		if !ok || !isSecretKeyName(msg[i:keyEnd]) {
			i = keyEnd
			continue
		}
		var valueEnd int
		if quotedKeys {
			valueEnd = scanQuotedKeyValue(msg, valueStart, quote)
		} else {
			valueEnd = scanAssignmentValue(msg, valueStart, enclosingQuote(msg, i))
		}
		if valueEnd == valueStart {
			i = keyEnd
			continue
		}
		out.WriteString(msg[copied:valueStart])
		out.WriteString(redactedValue)
		copied = valueEnd
		i = valueEnd
	}
	if copied == 0 {
		return msg
	}
	out.WriteString(msg[copied:])
	return out.String()
}

// secretKeySeparator matches the separator after the key name msg[start:end]
// and returns where the value starts. A quoted key needs the same quote
// character, escaped by the same number of backslashes, right before and
// right after it; text such as `token\":\"` inside a string value, whose two
// quotes differ, is not a key. An unquoted key needs the separator right after
// it. Whitespace may surround ':' or '='. When the key's quotes are escaped,
// the key sits in an escaped JSON string, so an escaped tab, newline, or
// carriage return (\t, \n, \r, after any number of backslashes) counts as
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

// scanQuotedKeyValue returns the end of the value of a quoted secret key that
// starts at i, or i when there is none.
func scanQuotedKeyValue(msg string, i int, quote keyQuote) int {
	if end, ok := scanLeadingQuotedOrStructured(msg, i, quote); ok {
		return end
	}
	j := i
	for j < len(msg) {
		c := msg[j]
		if c == '\\' {
			if j+1 == len(msg) {
				break
			}
			j += 2
			continue
		}
		if isSpace(c) || strings.IndexByte(",;&}]", c) >= 0 {
			break
		}
		j++
	}
	return j
}

// enclosingQuote returns the unescaped quote character right before the key
// that starts at msg[start], or 0 when there is none.
func enclosingQuote(msg string, start int) byte {
	if start == 0 || !isQuote(msg[start-1]) || (start > 1 && msg[start-2] == '\\') {
		return 0
	}
	return msg[start-1]
}

// scanAssignmentValue returns the end of the value of an unquoted secret key
// that starts at i, or i when there is none. A key right after an unescaped
// quote (enclosing, or 0) sits inside that quoted string, so the string's
// closing quote ends the value instead of opening a quoted segment: the label
// in `"Password:" PGPASSWORD=x` has an empty value, and the next key is still
// found.
func scanAssignmentValue(msg string, i int, enclosing byte) int {
	if enclosing != 0 && i < len(msg) && msg[i] == enclosing {
		return i
	}
	j := i
	if end, ok := scanLeadingQuotedOrStructured(msg, i, keyQuote{}); ok {
		j = end
	}
	for j < len(msg) {
		c := msg[j]
		switch {
		case enclosing != 0 && c == enclosing:
			return j
		case isQuote(c):
			j = scanQuotedValue(msg, j+1, c, 0, len(msg))
		case c == '\\':
			if j+1 == len(msg) {
				return j
			}
			j += 2
		case isSpace(c) || c == ';' || c == '&':
			return j
		default:
			j++
		}
	}
	return j
}

// scanLeadingQuotedOrStructured scans a value that starts at i with a quoted
// string (after any number of escaping backslashes) or with an object or
// array, and returns its end. quote is the key's quoting (see
// scanStructuredValue).
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
	if j < len(msg) && isQuote(msg[j]) {
		return scanQuotedValue(msg, j+1, msg[j], j-i, len(msg)), true
	}
	return 0, false
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
