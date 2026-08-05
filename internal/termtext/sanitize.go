package termtext

import (
	"fmt"
	"strings"
	"unicode"
)

// Sanitize renders untrusted text inert for terminals and CI logs while
// keeping control characters visible for debugging.
func Sanitize(value string) string {
	if value == "" {
		return ""
	}
	var out strings.Builder
	out.Grow(len(value))
	for _, r := range value {
		switch r {
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			switch {
			case r < 0x20 || r == 0x7f:
				fmt.Fprintf(&out, `\x%02X`, r)
			case r >= 0x80 && r <= 0x9f:
				fmt.Fprintf(&out, `\u%04X`, r)
			case unicode.In(r, unicode.Cf):
				fmt.Fprintf(&out, `\u%04X`, r)
			default:
				out.WriteRune(r)
			}
		}
	}
	return out.String()
}
