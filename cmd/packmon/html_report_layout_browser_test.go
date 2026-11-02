package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

type cliHTMLReportLayoutMeasurement struct {
	ViewportWidth    float64 `json:"viewportWidth"`
	DocumentWidth    float64 `json:"documentWidth"`
	WrapperLeft      float64 `json:"wrapperLeft"`
	WrapperRight     float64 `json:"wrapperRight"`
	HeadingBottom    float64 `json:"headingBottom"`
	MetaTop          float64 `json:"metaTop"`
	HeadingLines     float64 `json:"headingLines"`
	MetaLines        float64 `json:"metaLines"`
	MobileDisplay    string  `json:"mobileDisplay"`
	TableDisplay     string  `json:"tableDisplay"`
	TableClientWidth float64 `json:"tableClientWidth"`
	TableScrollWidth float64 `json:"tableScrollWidth"`
}

func TestGeneratedHTMLReportsReflowAtNarrowViewportWithEnlargedText(t *testing.T) {
	browser := findRequiredCLIHTMLReportBrowser(t)

	longHeading := strings.Repeat("very-long-list-all-heading-segment-", 12)
	listAllPath := filepath.Join(t.TempDir(), "list-all.html")
	if err := writeListAllHTML(listAllPath, longHeading, &domain.ScanResult{Mode: "local"}, listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "example-package-with-a-long-name",
			Installed: "1.0.0",
			Latest:    "2.0.0",
			Ecosystem: "npm",
			Source:    "package-lock.json",
			Scope:     "runtime",
			Relation:  "direct",
		}},
	}); err != nil {
		t.Fatalf("write list-all report: %v", err)
	}

	outdatedPath := filepath.Join(t.TempDir(), "outdated.html")
	if err := writeOutdatedHTML(outdatedPath, outdatedReport{
		Target:      strings.Repeat("very-long-outdated-metadata-segment-", 12),
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      "example-package-with-a-long-name",
			Installed: "1.0.0",
			Latest:    "2.0.0",
			Ecosystem: "npm",
			Scope:     "runtime",
			Relation:  "direct",
			LockFile:  "package-lock.json",
		}},
	}); err != nil {
		t.Fatalf("write outdated report: %v", err)
	}

	tests := []struct {
		name             string
		path             string
		wantHeadingWrap  bool
		wantMetaWrap     bool
		wantMobile       bool
		wantTableVisible bool
		wantTableScroll  bool
	}{
		{
			name:             "list-all keeps its wide table in an internal scroll region",
			path:             listAllPath,
			wantHeadingWrap:  true,
			wantTableVisible: true,
			wantTableScroll:  true,
		},
		{
			name:            "outdated switches to cards and wraps metadata",
			path:            outdatedPath,
			wantMetaWrap:    true,
			wantMobile:      true,
			wantTableScroll: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			measurement := measureCLIHTMLReportLayout(t, browser, tt.path)
			if measurement.ViewportWidth > 360 || measurement.ViewportWidth < 320 {
				t.Fatalf("viewport width = %.1f, want narrow browser viewport near 360px", measurement.ViewportWidth)
			}
			if measurement.DocumentWidth > measurement.ViewportWidth+1 {
				t.Fatalf("document width %.1f exceeds viewport width %.1f", measurement.DocumentWidth, measurement.ViewportWidth)
			}
			if measurement.WrapperLeft < -1 || measurement.WrapperRight > measurement.ViewportWidth+1 {
				t.Fatalf("wrapper bounds = [%.1f, %.1f], viewport width %.1f", measurement.WrapperLeft, measurement.WrapperRight, measurement.ViewportWidth)
			}
			if measurement.HeadingBottom > measurement.MetaTop+1 {
				t.Fatalf("heading bottom %.1f overlaps metadata top %.1f", measurement.HeadingBottom, measurement.MetaTop)
			}
			if tt.wantHeadingWrap && measurement.HeadingLines < 2 {
				t.Fatalf("heading lines = %.1f, want actual multi-line wrapping", measurement.HeadingLines)
			}
			if tt.wantMetaWrap && measurement.MetaLines < 2 {
				t.Fatalf("metadata lines = %.1f, want actual multi-line wrapping", measurement.MetaLines)
			}
			if got := measurement.MobileDisplay != "none"; got != tt.wantMobile {
				t.Fatalf("mobile-list visible = %t (display %q), want %t", got, measurement.MobileDisplay, tt.wantMobile)
			}
			if got := measurement.TableDisplay != "none"; got != tt.wantTableVisible {
				t.Fatalf("table-scroll visible = %t (display %q), want %t", got, measurement.TableDisplay, tt.wantTableVisible)
			}
			if tt.wantTableScroll && measurement.TableScrollWidth <= measurement.TableClientWidth+1 {
				t.Fatalf("table scroll width %.1f, client width %.1f; want internal horizontal scrolling", measurement.TableScrollWidth, measurement.TableClientWidth)
			}
		})
	}
}

func measureCLIHTMLReportLayout(t *testing.T, browser, reportPath string) cliHTMLReportLayoutMeasurement {
	t.Helper()
	harnessPath := writeCLIHTMLReportLayoutHarness(t, reportPath)
	dom := dumpNarrowCLIHTMLReportDOM(t, browser, cliHTMLReportFileURL(t, harnessPath))
	match := regexp.MustCompile(`data-packmon-layout-measurement="([^"]+)"`).FindStringSubmatch(dom)
	if len(match) != 2 {
		t.Fatalf("headless browser did not return layout measurement:\n%s", dom)
	}
	var measurement cliHTMLReportLayoutMeasurement
	if err := json.Unmarshal([]byte(html.UnescapeString(match[1])), &measurement); err != nil {
		t.Fatalf("decode layout measurement %q: %v", match[1], err)
	}
	return measurement
}

func writeCLIHTMLReportLayoutHarness(t *testing.T, reportPath string) string {
	t.Helper()
	report, err := os.ReadFile(reportPath) //nolint:gosec // G304: path is created by this test.
	if err != nil {
		t.Fatalf("read generated report: %v", err)
	}
	reportJSON, err := json.Marshal(string(report))
	if err != nil {
		t.Fatalf("encode generated report for layout harness: %v", err)
	}
	harness := fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><title>Packmon layout measurement</title></head>
<body style="margin:0"><iframe id="report" style="width:360px;height:1100px;border:0"></iframe>
<script>
var frame = document.getElementById("report");
frame.addEventListener("load", function () {
  var doc = frame.contentDocument;
  var wrap = doc.querySelector(".wrap");
  if (!wrap) return;
  doc.documentElement.style.fontSize = "200%%";
  var root = doc.documentElement;
  var heading = doc.querySelector("h1");
  var meta = doc.querySelector(".meta");
  var mobile = doc.querySelector(".mobile-list");
  var table = doc.querySelector(".table-scroll");
  function lineCount(element) {
    var lineHeight = parseFloat(frame.contentWindow.getComputedStyle(element).lineHeight);
    return lineHeight > 0 ? element.getBoundingClientRect().height / lineHeight : 0;
  }
  frame.dataset.packmonLayoutMeasurement = JSON.stringify({
    viewportWidth: root.clientWidth,
    documentWidth: root.scrollWidth,
    wrapperLeft: wrap.getBoundingClientRect().left,
    wrapperRight: wrap.getBoundingClientRect().right,
    headingBottom: heading.getBoundingClientRect().bottom,
    metaTop: meta.getBoundingClientRect().top,
    headingLines: lineCount(heading),
    metaLines: lineCount(meta),
    mobileDisplay: mobile ? frame.contentWindow.getComputedStyle(mobile).display : "none",
    tableDisplay: table ? frame.contentWindow.getComputedStyle(table).display : "none",
    tableClientWidth: table ? table.clientWidth : 0,
    tableScrollWidth: table ? table.scrollWidth : 0
  });
});
frame.srcdoc = %s;
</script></body></html>`, reportJSON)
	harnessPath := filepath.Join(t.TempDir(), "layout-harness.html")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatalf("write layout measurement harness: %v", err)
	}
	return harnessPath
}

func dumpNarrowCLIHTMLReportDOM(t *testing.T, browser, rawURL string) string {
	t.Helper()
	args := []string{
		"--headless=new",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-default-apps",
		"--disable-extensions",
		"--disable-gpu",
		"--disable-sync",
		"--host-resolver-rules=MAP * ~NOTFOUND",
		"--no-first-run",
		"--no-proxy-server",
		"--no-sandbox",
		"--force-device-scale-factor=1",
		"--user-data-dir=" + t.TempDir(),
		"--virtual-time-budget=500",
		"--window-size=360,1200",
		"--dump-dom",
		rawURL,
	}
	output, err := runCLIHTMLReportBrowser(t, browser, args)
	if err != nil && strings.Contains(string(output), "headless=new") {
		args[0] = "--headless"
		output, err = runCLIHTMLReportBrowser(t, browser, args)
	}
	if err != nil {
		t.Fatalf("headless browser layout measurement failed: %v\n%s", err, output)
	}
	return string(output)
}

func cliHTMLReportFileURL(t *testing.T, reportPath string) string {
	t.Helper()
	absPath, err := filepath.Abs(reportPath)
	if err != nil {
		t.Fatalf("resolve report path: %v", err)
	}
	slashed := filepath.ToSlash(absPath)
	if runtime.GOOS == "windows" && !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	return (&url.URL{Scheme: "file", Path: slashed}).String()
}

func findRequiredCLIHTMLReportBrowser(t *testing.T) string {
	t.Helper()
	for _, envName := range []string{"PACKMON_BROWSER_BIN", "CHROME_BIN", "EDGE_BIN"} {
		if candidate := strings.TrimSpace(os.Getenv(envName)); candidate != "" {
			if cliHTMLReportFileExists(candidate) {
				return candidate
			}
			if resolved, err := exec.LookPath(candidate); err == nil {
				return resolved
			}
			t.Fatalf("%s points to unavailable browser executable %q", envName, candidate)
		}
	}

	candidates := []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "msedge"}
	if runtime.GOOS == "windows" {
		candidates = append([]string{
			filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		}, candidates...)
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if cliHTMLReportFileExists(candidate) {
			return candidate
		}
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved
		}
	}
	t.Fatal("Chrome, Chromium, or Edge is required for generated HTML report layout coverage; set PACKMON_BROWSER_BIN")
	return ""
}
