package logsafe

import "strings"

// The baseline scan is the secret-field scan as it stood before the extended
// scan in secret_fields.go (component key names, structured and deeply
// escaped values, but none of the later interpretations). redactSecretValues
// redacts the union of both, so an extension that reads ambiguous text
// differently (a quote that closes a string rather than opening a value) can
// only add redaction: anything the baseline hides stays hidden. Keep this file
// unchanged unless a change only adds redaction.

// baselineSecretKeyWords and baselineKeySecretPrefixes are the key-name rules
// of the baseline scan (see baselineIsSecretKeyName).
var (
	baselineSecretKeyWords = []string{
		"password", "passwd", "pwd", "secret", "token", "credential",
		"signature", "sig", "apikey", "privatekey",
		"passwords", "passwds", "secrets", "credentials",
	}
	baselineKeySecretPrefixes = []string{"api", "private"}
)

// baselineIsSecretKeyName reports whether a component of name ends with a
// baseline secret word, or is "key" right after an "api" or "private"
// component.
func baselineIsSecretKeyName(name string) bool {
	prevStart, prevEnd := -1, -1
	secret := false
	forEachKeyComponent(name, func(start, end int) {
		comp := name[start:end]
		for _, word := range baselineSecretKeyWords {
			if hasSuffixFold(comp, word) {
				secret = true
			}
		}
		if prevStart >= 0 && strings.EqualFold(comp, "key") {
			for _, prefix := range baselineKeySecretPrefixes {
				if hasSuffixFold(name[prevStart:prevEnd], prefix) {
					secret = true
				}
			}
		}
		prevStart, prevEnd = start, end
	})
	return secret
}

// baselineSecretSpans scans msg once, left to right, for key names followed by
// a separator and returns the values of the secret keys: the values of quoted
// keys when quotedKeys is set, else those of unquoted keys. The unquoted scan
// runs on msg with the quoted spans masked (see maskSpans).
func baselineSecretSpans(msg string, quotedKeys bool) []span {
	var spans []span
	for i := 0; i < len(msg); {
		if !isKeyChar(msg[i]) || (i > 0 && isKeyChar(msg[i-1])) {
			i++
			continue
		}
		keyEnd := i
		for keyEnd < len(msg) && isKeyChar(msg[keyEnd]) {
			keyEnd++
		}
		valueStart, quote, ok := baselineSecretKeySeparator(msg, i, keyEnd, quotedKeys)
		if !ok || !baselineIsSecretKeyName(msg[i:keyEnd]) {
			i = keyEnd
			continue
		}
		var valueEnd int
		if quotedKeys {
			valueEnd = baselineScanQuotedKeyValue(msg, valueStart, quote)
		} else {
			valueEnd = baselineScanAssignmentValue(msg, valueStart, baselineEnclosingQuote(msg, i))
		}
		if valueEnd == valueStart {
			i = keyEnd
			continue
		}
		spans = append(spans, span{valueStart, valueEnd})
		i = valueEnd
	}
	return spans
}

// baselineSecretKeySeparator is secretKeySeparator without URL-encoded
// separators.
func baselineSecretKeySeparator(msg string, start, end int, quotedKeys bool) (int, keyQuote, bool) {
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

// baselineScanQuotedKeyValue returns the end of the value of a quoted secret
// key: a leading quoted string or structure, or a scalar that ends at
// whitespace or one of ",;&}]".
func baselineScanQuotedKeyValue(msg string, i int, quote keyQuote) int {
	if end, ok := baselineScanLeadingQuotedOrStructured(msg, i, quote); ok {
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

// baselineEnclosingQuote returns the quote character right before the key
// that starts at msg[start] when no backslash precedes it, or 0.
func baselineEnclosingQuote(msg string, start int) byte {
	if start == 0 || !isQuote(msg[start-1]) || (start > 1 && msg[start-2] == '\\') {
		return 0
	}
	return msg[start-1]
}

// baselineScanAssignmentValue returns the end of the value of an unquoted
// secret key: quoted segments, escapes, and plain characters up to whitespace,
// ';', or '&', or up to the enclosing quote (enclosing, or 0) of a key right
// after a quote.
func baselineScanAssignmentValue(msg string, i int, enclosing byte) int {
	if enclosing != 0 && i < len(msg) && msg[i] == enclosing {
		return i
	}
	j := i
	if end, ok := baselineScanLeadingQuotedOrStructured(msg, i, keyQuote{}); ok {
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

// baselineScanLeadingQuotedOrStructured scans a value that starts with a
// quoted string (after any number of escaping backslashes) or with an object
// or array.
func baselineScanLeadingQuotedOrStructured(msg string, i int, quote keyQuote) (int, bool) {
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
