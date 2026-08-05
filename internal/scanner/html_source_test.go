package scanner

import (
	"os"
	"strings"
	"testing"
)

func TestHTMLReportTemplateSourceStaysReadable(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("html.go")
	if err != nil {
		t.Fatalf("read html.go: %v", err)
	}

	const maxTemplateLineLength = 300
	for i, line := range strings.Split(string(src), "\n") {
		if len(line) > maxTemplateLineLength {
			t.Fatalf("html.go:%d is %d characters; report templates should use readable local fragments", i+1, len(line))
		}
	}
}

func TestHTMLReportTemplateUsesNamedFragments(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("html.go")
	if err != nil {
		t.Fatalf("read html.go: %v", err)
	}
	text := string(src)

	for _, want := range []string{
		"const htmlReportCSS =",
		"const htmlTemplateBody =",
		"const htmlTemplate = htmlTemplateHead + htmlReportCSS + htmlTemplateBody + htmlReportLocaleScript + htmlTemplateEnd",
		"reporthtml.DarkBaseThemeCSS",
		"reporthtml.LightBaseThemeCSS",
		"reporthtml.ForcedColorsBaseThemeCSS",
		"reporthtml.PrintBaseThemeCSS",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("html.go should split the report template into readable named fragments; missing %q", want)
		}
	}

	for _, duplicated := range []string{
		`color-scheme:dark;--bg:#0d1117;--panel:#161b22;`,
		`color-scheme:light;--bg:#ffffff;--panel:#f6f8fa;`,
	} {
		if strings.Contains(text, duplicated) {
			t.Fatalf("html.go should consume shared report theme CSS instead of duplicating %q", duplicated)
		}
	}
}
