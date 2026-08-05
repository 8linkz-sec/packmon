package reporthtml

import (
	"strings"
	"testing"
)

func TestBaseThemeTokensCoverGeneratedReportSurfaces(t *testing.T) {
	t.Parallel()

	for name, css := range map[string]string{
		"dark":          DarkBaseThemeCSS,
		"light":         LightBaseThemeCSS,
		"forced-colors": ForcedColorsBaseThemeCSS,
		"print":         PrintBaseThemeCSS,
	} {
		t.Run(name, func(t *testing.T) {
			for _, want := range []string{
				"color-scheme:",
				"--bg:",
				"--panel:",
				"--border:",
				"--fg:",
				"--heading:",
				"--dim:",
			} {
				if !strings.Contains(css, want) {
					t.Fatalf("%s base theme CSS missing %q: %s", name, want, css)
				}
			}
		})
	}
}
