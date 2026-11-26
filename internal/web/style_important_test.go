package web

import (
	"regexp"
	"strings"
	"testing"
)

// reducedMotionAtRule is the only style.css block that may keep !important:
// its universal (*) reset has zero specificity, so it can only beat every
// component transition with !important. Every other override in style.css is
// unlayered and wins over the layered Tailwind output by the cascade alone;
// the per-file Sonar acceptance of css:S9423 relies on this guard.
const reducedMotionAtRule = "@media (prefers-reduced-motion: reduce)"

var cssCommentPattern = regexp.MustCompile(`(?s)/\*.*?\*/`)

func TestCustomStylesKeepImportantOnlyInReducedMotionReset(t *testing.T) {
	t.Parallel()

	styleCSS := cssCommentPattern.ReplaceAllString(readTextFile(t, "static", "style.css"), "")
	reducedMotion := cssAtRuleBlock(t, styleCSS, reducedMotionAtRule)
	if !strings.Contains(reducedMotion, "!important") {
		t.Fatalf("reduced-motion reset lost its !important declarations:\n%s", reducedMotion)
	}

	outside := strings.Replace(styleCSS, reducedMotion, "", 1)
	if count := strings.Count(outside, "!important"); count != 0 {
		t.Fatalf("style.css has %d !important declarations outside %q; resolve them by specificity instead:\n%s", count, reducedMotionAtRule, outside)
	}
}

// cssAtRuleBlock returns the at-rule that starts with header, from the header
// through its matching closing brace. A depth counter is enough for style.css:
// apart from rule delimiters its only braces are a balanced pair in a comment
// outside every at-rule.
func cssAtRuleBlock(t *testing.T, css, header string) string {
	t.Helper()

	start := strings.Index(css, header+" {")
	if start < 0 {
		t.Fatalf("style.css missing at-rule %q", header)
	}
	depth := 0
	for i := start; i < len(css); i++ {
		switch css[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return css[start : i+1]
			}
		}
	}
	t.Fatalf("style.css at-rule %q is not closed", header)
	return ""
}
