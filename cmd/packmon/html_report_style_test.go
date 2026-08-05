package main

import (
	"os"
	"strings"
	"testing"
)

func TestCLIHTMLReportsShareShellAndBaseStyles(t *testing.T) {
	t.Parallel()

	shared := readCLIHTMLReportSource(t, "html_report_style.go")
	outdated := readCLIHTMLReportSource(t, "outdated_html.go")
	listAll := readCLIHTMLReportSource(t, "list_all_html.go")

	for _, want := range []string{
		"cliHTMLReportHeadPrefix",
		"cliHTMLReportCSPMeta",
		"cliHTMLReportBaseCSS",
		"cliHTMLReportScaleCSS",
	} {
		if !strings.Contains(shared, want) {
			t.Fatalf("html_report_style.go missing shared report fragment %s", want)
		}
		if !strings.Contains(outdated, want) {
			t.Fatalf("outdated_html.go does not use shared report fragment %s", want)
		}
		if !strings.Contains(listAll, want) {
			t.Fatalf("list_all_html.go does not use shared report fragment %s", want)
		}
	}

	for _, want := range []string{
		"reporthtml.DarkBaseThemeCSS",
		"reporthtml.LightBaseThemeCSS",
		"reporthtml.ForcedColorsBaseThemeCSS",
		"reporthtml.PrintBaseThemeCSS",
	} {
		if !strings.Contains(outdated, want) {
			t.Fatalf("outdated_html.go does not use shared report theme fragment %s", want)
		}
		if !strings.Contains(listAll, want) {
			t.Fatalf("list_all_html.go does not use shared report theme fragment %s", want)
		}
	}

	for _, duplicated := range []string{
		`<meta http-equiv="Content-Security-Policy" content="default-src 'none';`,
		`*{box-sizing:border-box;}`,
		`body{margin:0;background:var(--bg);color:var(--fg);`,
		`.wrap{max-width:1600px;margin:0 auto;padding:var(--report-space-7) var(--report-space-5) var(--report-space-8);}`,
		`.footer{border-top:1px solid var(--border);margin-top:var(--report-space-7);padding-top:var(--report-space-3);color:var(--dim);font-size:var(--report-type-xs);}`,
		`color-scheme:dark;--bg:#0d1117;--panel:#161b22;`,
		`color-scheme:light;--bg:#ffffff;--panel:#f6f8fa;`,
	} {
		if strings.Contains(outdated, duplicated) || strings.Contains(listAll, duplicated) {
			t.Fatalf("report template files should not inline shared fragment %q", duplicated)
		}
	}
}

func TestCLIHTMLReportTemplatesStayReadable(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"html_report_style.go",
		"list_all_html.go",
		"outdated_html.go",
	} {
		assertReadableHTMLReportSourceLines(t, path, readCLIHTMLReportSource(t, path))
	}
}

func assertReadableHTMLReportSourceLines(t *testing.T, path, src string) {
	t.Helper()

	const maxTemplateLineLength = 300
	for i, line := range strings.Split(src, "\n") {
		if len(line) > maxTemplateLineLength {
			t.Fatalf("%s:%d is %d characters; report templates should use readable local fragments", path, i+1, len(line))
		}
	}
}

func readCLIHTMLReportSource(t *testing.T, path string) string {
	t.Helper()

	//nolint:gosec // G304: path built by the test itself, not from request data.
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(src)
}
