package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type f040ResponsiveMeasurement struct {
	Narrow  f040ViewportMeasurement `json:"narrow"`
	Desktop f040ViewportMeasurement `json:"desktop"`
}

type f040ViewportMeasurement struct {
	ViewportWidth      float64 `json:"viewportWidth"`
	DocumentWidth      float64 `json:"documentWidth"`
	WrapperLeft        float64 `json:"wrapperLeft"`
	WrapperRight       float64 `json:"wrapperRight"`
	MobileDisplay      string  `json:"mobileDisplay"`
	TableDisplay       string  `json:"tableDisplay"`
	SummaryTabIndex    int     `json:"summaryTabIndex"`
	SummaryFocused     bool    `json:"summaryFocused"`
	DetailsOpened      bool    `json:"detailsOpened"`
	TableTabIndex      int     `json:"tableTabIndex"`
	TableRole          string  `json:"tableRole"`
	TableLabel         string  `json:"tableLabel"`
	TableFocused       bool    `json:"tableFocused"`
	OutlineStyle       string  `json:"outlineStyle"`
	OutlineWidth       float64 `json:"outlineWidth"`
	FocusTokenWidth    float64 `json:"focusTokenWidth"`
	LongValuesRendered bool    `json:"longValuesRendered"`
}

func TestOutdatedHTMLBrowserResponsiveFocusAndDisclosureBehavior(t *testing.T) {
	browser := findRequiredCLIHTMLReportBrowser(t)
	longToken := strings.Repeat("packmon-f040-unbreakable-token-", 24)
	reportPath := filepath.Join(t.TempDir(), "outdated-responsive.html")
	if err := writeOutdatedHTML(reportPath, outdatedReport{
		Target:      longToken + "target",
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      longToken + "name",
			Installed: longToken + "installed",
			Latest:    longToken + "latest",
			Ecosystem: "npm",
			Scope:     "runtime",
			Relation:  "direct",
			Via:       longToken + "via",
			Flags:     "optional",
			LockFile:  longToken + "lockfile.json",
		}},
	}); err != nil {
		t.Fatalf("write responsive outdated report: %v", err)
	}
	report, err := os.ReadFile(reportPath) //nolint:gosec // G304: test reads its own report.
	if err != nil {
		t.Fatalf("read responsive outdated report: %v", err)
	}
	reportJSON, err := json.Marshal(string(report))
	if err != nil {
		t.Fatalf("encode responsive report: %v", err)
	}
	longJSON, err := json.Marshal(longToken)
	if err != nil {
		t.Fatalf("encode long token: %v", err)
	}

	harness := fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"></head><body>
<iframe id="narrow" style="width:360px;height:1200px;border:0"></iframe>
<iframe id="desktop" style="width:1280px;height:1200px;border:0"></iframe>
<script>
var report=%s;
var longToken=%s;
var result={};
var pending=2;
function measure(frame,isNarrow){
  var doc=frame.contentDocument;
  if(isNarrow){doc.documentElement.style.fontSize="200%%";}
  var root=doc.documentElement;
  var wrap=doc.querySelector(".wrap");
  var mobile=doc.querySelector(".mobile-list");
  var table=doc.querySelector(".table-scroll");
  var summary=doc.querySelector("summary");
  var details=doc.querySelector("details");
  var summaryFocused=false;
  var detailsOpened=false;
  if(summary){
    summary.focus({preventScroll:true});
    summaryFocused=doc.activeElement===summary;
    var before=details.open;
    summary.click();
    detailsOpened=!before && details.open;
  }
  var tableFocused=false;
  var outlineStyle="";
  var outlineWidth=0;
  var focusTokenWidth=0;
  if(table){
    table.focus({preventScroll:true});
    tableFocused=doc.activeElement===table;
    var style=frame.contentWindow.getComputedStyle(table);
    outlineStyle=style.outlineStyle;
    outlineWidth=parseFloat(style.outlineWidth)||0;
    focusTokenWidth=parseFloat(frame.contentWindow.getComputedStyle(root).getPropertyValue("--report-focus-ring"))||0;
  }
  var text=doc.body.textContent||"";
  var measurement={
    viewportWidth:root.clientWidth,
    documentWidth:root.scrollWidth,
    wrapperLeft:wrap.getBoundingClientRect().left,
    wrapperRight:wrap.getBoundingClientRect().right,
    mobileDisplay:mobile?frame.contentWindow.getComputedStyle(mobile).display:"none",
    tableDisplay:table?frame.contentWindow.getComputedStyle(table).display:"none",
    summaryTabIndex:summary?summary.tabIndex:-2,
    summaryFocused:summaryFocused,
    detailsOpened:detailsOpened,
    tableTabIndex:table?table.tabIndex:-2,
    tableRole:table?table.getAttribute("role")||"":"",
    tableLabel:table?table.getAttribute("aria-label")||"":"",
    tableFocused:tableFocused,
    outlineStyle:outlineStyle,
    outlineWidth:outlineWidth,
    focusTokenWidth:focusTokenWidth,
    longValuesRendered:text.indexOf(longToken+"name")!==-1 && text.indexOf(longToken+"installed")!==-1 && text.indexOf(longToken+"latest")!==-1 && text.indexOf(longToken+"via")!==-1 && text.indexOf(longToken+"lockfile.json")!==-1
  };
  result[isNarrow?"narrow":"desktop"]=measurement;
  pending--;
  if(pending===0){document.body.setAttribute("data-packmon-f040-responsive",JSON.stringify(result));}
}
["narrow","desktop"].forEach(function(id){
  var frame=document.getElementById(id);
  frame.addEventListener("load",function(){measure(frame,id==="narrow");});
  frame.srcdoc=report;
});
</script></body></html>`, reportJSON, longJSON)
	harnessPath := filepath.Join(t.TempDir(), "responsive-harness.html")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatalf("write responsive harness: %v", err)
	}
	dom := f040DumpBrowserDOM(t, browser, cliHTMLReportFileURL(t, harnessPath), "1400,1500", 1200)
	var measurement f040ResponsiveMeasurement
	f040DecodeDatasetJSON(t, dom, "data-packmon-f040-responsive", &measurement)

	if measurement.Narrow.ViewportWidth < 320 || measurement.Narrow.ViewportWidth > 360 {
		t.Errorf("narrow viewport width = %.1f, want 320..360", measurement.Narrow.ViewportWidth)
	}
	for name, view := range map[string]f040ViewportMeasurement{"narrow": measurement.Narrow, "desktop": measurement.Desktop} {
		if view.DocumentWidth > view.ViewportWidth+1 {
			t.Errorf("%s document width %.1f exceeds viewport %.1f", name, view.DocumentWidth, view.ViewportWidth)
		}
		if view.WrapperLeft < -1 || view.WrapperRight > view.ViewportWidth+1 {
			t.Errorf("%s wrapper bounds [%.1f, %.1f] exceed viewport %.1f", name, view.WrapperLeft, view.WrapperRight, view.ViewportWidth)
		}
		if !view.LongValuesRendered {
			t.Errorf("%s browser view did not render every long fixture value", name)
		}
	}
	if measurement.Narrow.MobileDisplay == "none" || measurement.Narrow.TableDisplay != "none" {
		t.Errorf("narrow visibility mobile=%q table=%q", measurement.Narrow.MobileDisplay, measurement.Narrow.TableDisplay)
	}
	if measurement.Narrow.SummaryTabIndex < 0 || !measurement.Narrow.SummaryFocused {
		t.Errorf("narrow summary tabindex=%d focused=%t", measurement.Narrow.SummaryTabIndex, measurement.Narrow.SummaryFocused)
	}
	if !measurement.Narrow.DetailsOpened {
		t.Error("native summary click did not open its details element")
	}
	if measurement.Desktop.MobileDisplay != "none" || measurement.Desktop.TableDisplay == "none" {
		t.Errorf("desktop visibility mobile=%q table=%q", measurement.Desktop.MobileDisplay, measurement.Desktop.TableDisplay)
	}
	if measurement.Desktop.TableTabIndex != 0 || measurement.Desktop.TableRole != "region" || strings.TrimSpace(measurement.Desktop.TableLabel) == "" {
		t.Errorf("desktop table semantics tabindex=%d role=%q label=%q", measurement.Desktop.TableTabIndex, measurement.Desktop.TableRole, measurement.Desktop.TableLabel)
	}
	if !measurement.Desktop.TableFocused {
		t.Error("desktop table scroll region is not the active element after focus")
	}
	if measurement.Desktop.OutlineStyle == "none" || measurement.Desktop.OutlineStyle == "" {
		t.Errorf("desktop focused table outline style = %q", measurement.Desktop.OutlineStyle)
	}
	if measurement.Desktop.FocusTokenWidth <= 0 || measurement.Desktop.OutlineWidth+0.01 < measurement.Desktop.FocusTokenWidth {
		t.Errorf("desktop outline width %.2f is below focus token %.2f", measurement.Desktop.OutlineWidth, measurement.Desktop.FocusTokenWidth)
	}
}

func TestOutdatedHTMLBrowserPrintsLongReportAcrossPages(t *testing.T) {
	browser := findRequiredCLIHTMLReportBrowser(t)
	const firstSentinel = "PACKMON-F040-PRINT-FIRST"
	const middleSentinel = "PACKMON-F040-PRINT-MIDDLE"
	const lastSentinel = "PACKMON-F040-PRINT-LAST"
	rows := make([]outdatedRow, 180)
	for i := range rows {
		name := fmt.Sprintf("packmon-f040-print-row-%03d-%s", i, strings.Repeat("wide-value-", 5))
		switch i {
		case 0:
			name = firstSentinel
		case len(rows) / 2:
			name = middleSentinel
		case len(rows) - 1:
			name = lastSentinel
		}
		rows[i] = outdatedRow{Name: name, Installed: "1.0.0", Latest: "2.0.0", Ecosystem: "npm", Scope: "runtime", Relation: "direct", LockFile: "package-lock.json"}
	}
	reportPath := filepath.Join(t.TempDir(), "long-outdated.html")
	if err := writeOutdatedHTML(reportPath, outdatedReport{Total: len(rows), PackageWord: "packages", Outdated: rows, LockFiles: 1}); err != nil {
		t.Fatalf("write long outdated report: %v", err)
	}
	htmlData, err := os.ReadFile(reportPath) //nolint:gosec // G304: test reads its own report.
	if err != nil {
		t.Fatalf("read long outdated report: %v", err)
	}
	for _, sentinel := range []string{firstSentinel, middleSentinel, lastSentinel} {
		if !bytes.Contains(htmlData, []byte(sentinel)) {
			t.Fatalf("long report fixture missing source sentinel %q", sentinel)
		}
	}

	pdfPath := filepath.Join(t.TempDir(), "outdated.pdf")
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
		"--no-pdf-header-footer",
		"--user-data-dir=" + t.TempDir(),
		"--print-to-pdf=" + pdfPath,
		cliHTMLReportFileURL(t, reportPath),
	}
	output, err := runCLIHTMLReportBrowser(t, browser, args)
	if err != nil && strings.Contains(string(output), "headless=new") {
		args[0] = "--headless"
		output, err = runCLIHTMLReportBrowser(t, browser, args)
	}
	if err != nil {
		t.Fatalf("print outdated report to PDF: %v\n%s", err, output)
	}
	pdf, err := os.ReadFile(pdfPath) //nolint:gosec // G304: browser writes this test-owned output path.
	if err != nil {
		t.Fatalf("read printed PDF: %v", err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Fatalf("printed output has prefix %q, want %%PDF-", string(pdf[:min(len(pdf), 12)]))
	}
	if !bytes.HasSuffix(bytes.TrimSpace(pdf), []byte("%%EOF")) {
		t.Fatal("printed PDF is missing its terminal EOF marker")
	}
	if pages := len(regexp.MustCompile(`/Type\s*/Page\b`).FindAll(pdf, -1)); pages < 2 {
		t.Fatalf("printed PDF page-object count = %d, want at least 2", pages)
	}
}

type f040LocaleProbe struct {
	Sentinel string   `json:"sentinel"`
	Text     string   `json:"text"`
	Fallback *string  `json:"fallback"`
	Errors   []string `json:"errors"`
}

func TestOutdatedHTMLBrowserExecutesLocaleTimestampFallbackPolicy(t *testing.T) {
	browser := findRequiredCLIHTMLReportBrowser(t)
	const sentinel = "packmon-f040-locale-7a6df65f"
	tests := []struct {
		name         string
		display      string
		dateTime     string
		disableIntl  bool
		wantChanged  bool
		wantFallback bool
	}{
		{name: "native valid timestamp localizes", display: "2026-05-30 10:00 UTC", dateTime: "2026-05-30T10:00:00Z", wantChanged: true, wantFallback: true},
		{name: "invalid datetime preserves visible fallback", display: "invalid timestamp fallback", dateTime: `not-a-date" onerror="alert(1)`},
		{name: "missing Intl preserves UTC fallback", display: "2026-05-30 10:00 UTC", dateTime: "2026-05-30T10:00:00Z", disableIntl: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reportPath := filepath.Join(t.TempDir(), "locale-outdated.html")
			if err := writeOutdatedHTML(reportPath, outdatedReport{ScannedAt: tt.display, ScannedAtDateTime: tt.dateTime, Total: 1, PackageWord: "package"}); err != nil {
				t.Fatalf("write locale report: %v", err)
			}
			report, err := os.ReadFile(reportPath) //nolint:gosec // G304: test reads its own report.
			if err != nil {
				t.Fatalf("read locale report: %v", err)
			}
			if count := strings.Count(string(report), generatedHTMLReportLocaleScript); count != 1 {
				t.Fatalf("locale script count = %d, want exactly 1", count)
			}
			setup := `<script>
window.__packmonF040Errors=[];
window.addEventListener("error",function(event){window.__packmonF040Errors.push(String(event.message||event.error||"error"));});
window.addEventListener("unhandledrejection",function(event){window.__packmonF040Errors.push(String(event.reason||"unhandledrejection"));});
Object.defineProperty(navigator,"languages",{value:["en-US"],configurable:true});
Object.defineProperty(navigator,"language",{value:"en-US",configurable:true});
` + func() string {
				if tt.disableIntl {
					return `Object.defineProperty(window,"Intl",{value:undefined,configurable:true});` + "\n"
				}
				return ""
			}() + `</script>`
			probe := `<script>
(function(){
  var node=document.querySelector("time[data-report-time=\"scanned-at\"]");
  var result={sentinel:"` + sentinel + `",text:node?node.textContent:"",fallback:node&&node.hasAttribute("data-fallback-text")?node.getAttribute("data-fallback-text"):null,errors:window.__packmonF040Errors.slice()};
  var output=document.createElement("div");
  output.id="` + sentinel + `";
  output.setAttribute("data-packmon-f040-locale",JSON.stringify(result));
  document.body.appendChild(output);
})();
</script>`
			instrumented := strings.Replace(string(report), generatedHTMLReportLocaleScript, setup+generatedHTMLReportLocaleScript+probe, 1)
			if strings.Count(instrumented, generatedHTMLReportLocaleScript) != 1 {
				t.Fatal("instrumentation changed or duplicated the production locale script")
			}
			instrumentedPath := filepath.Join(t.TempDir(), "locale-instrumented.html")
			if err := os.WriteFile(instrumentedPath, []byte(instrumented), 0o600); err != nil {
				t.Fatalf("write instrumented locale report: %v", err)
			}
			dom := f040DumpBrowserDOM(t, browser, cliHTMLReportFileURL(t, instrumentedPath), "900,700", 700)
			var result f040LocaleProbe
			f040DecodeDatasetJSON(t, dom, "data-packmon-f040-locale", &result)
			if result.Sentinel != sentinel {
				t.Fatalf("locale probe sentinel = %q, want %q", result.Sentinel, sentinel)
			}
			if len(result.Errors) != 0 {
				t.Fatalf("locale script emitted browser errors: %q", result.Errors)
			}
			if tt.wantChanged {
				if strings.TrimSpace(result.Text) == "" || result.Text == tt.display {
					t.Fatalf("valid timestamp visible text = %q, want a nonempty localized value", result.Text)
				}
			} else if result.Text != tt.display {
				t.Fatalf("fallback visible text = %q, want %q", result.Text, tt.display)
			}
			if tt.wantFallback {
				if result.Fallback == nil || *result.Fallback != tt.display {
					t.Fatalf("fallback attribute = %v, want %q", result.Fallback, tt.display)
				}
			} else if result.Fallback != nil {
				t.Fatalf("fallback attribute = %q, want absent", *result.Fallback)
			}
		})
	}
}

func f040DumpBrowserDOM(t *testing.T, browser, rawURL, windowSize string, virtualBudget int) []byte {
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
		"--lang=en-US",
		"--no-first-run",
		"--no-proxy-server",
		"--no-sandbox",
		"--force-device-scale-factor=1",
		"--user-data-dir=" + t.TempDir(),
		"--virtual-time-budget=" + strconv.Itoa(virtualBudget),
		"--window-size=" + windowSize,
		"--dump-dom",
		rawURL,
	}
	output, err := runCLIHTMLReportBrowser(t, browser, args)
	if err != nil && strings.Contains(string(output), "headless=new") {
		args[0] = "--headless"
		output, err = runCLIHTMLReportBrowser(t, browser, args)
	}
	if err != nil {
		t.Fatalf("headless browser probe failed: %v\n%s", err, output)
	}
	return output
}

func f040DecodeDatasetJSON(t *testing.T, dom []byte, attribute string, dst any) {
	t.Helper()
	doc := parseF040HTMLDocument(t, dom)
	for _, node := range f040AllElements(doc) {
		if value, ok := f040NodeAttr(node, attribute); ok {
			if err := json.Unmarshal([]byte(value), dst); err != nil {
				t.Fatalf("decode %s=%q: %v", attribute, value, err)
			}
			return
		}
	}
	t.Fatalf("browser DOM missing %s:\n%s", attribute, dom)
}
