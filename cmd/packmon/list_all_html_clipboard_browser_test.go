package main

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

type listAllHTMLClipboardSnapshot struct {
	Copied             bool   `json:"copied"`
	CopyFailed         bool   `json:"copyFailed"`
	AriaLabel          string `json:"ariaLabel"`
	StatusText         string `json:"statusText"`
	StatusRole         string `json:"statusRole"`
	StatusLive         string `json:"statusLive"`
	FallbackCount      int    `json:"fallbackCount"`
	FallbackValue      string `json:"fallbackValue"`
	FallbackLabel      string `json:"fallbackLabel"`
	FallbackReadOnly   bool   `json:"fallbackReadOnly"`
	FallbackFocusCalls int    `json:"fallbackFocusCalls"`
	FallbackFocusExact bool   `json:"fallbackFocusExact"`
	FallbackFocusOpts  bool   `json:"fallbackFocusOpts"`
	FallbackSelectFrom int    `json:"fallbackSelectFrom"`
	FallbackSelectTo   int    `json:"fallbackSelectTo"`
}

type listAllHTMLClipboardProbeResult struct {
	Mode        string                       `json:"mode"`
	ButtonCount int                          `json:"buttonCount"`
	Writes      []string                     `json:"writes"`
	Immediate   listAllHTMLClipboardSnapshot `json:"immediate"`
	AfterReset  listAllHTMLClipboardSnapshot `json:"afterReset"`
}

func TestGeneratedListAllHTMLClipboardInteractionContract(t *testing.T) {
	browser := findRequiredCLIHTMLReportBrowser(t)
	const (
		fullDigest     = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		packageName    = "ghcr.io/acme/fixture"
		originalLabel  = "Copy full installed value for ghcr.io/acme/fixture " + fullDigest
		successMessage = "Copied full installed value for ghcr.io/acme/fixture"
		failureMessage = "Copy failed. Full value is selected for manual copy."
		fallbackLabel  = "Full value to copy manually"
	)

	tests := []struct {
		name       string
		mode       string
		wantWrites int
		wantOK     bool
	}{
		{name: "clipboard_success_copies_exact_full_value", mode: "resolve", wantWrites: 1, wantOK: true},
		{name: "clipboard_rejection_selects_exact_full_fallback", mode: "reject", wantWrites: 1},
		{name: "clipboard_unavailable_selects_exact_full_fallback", mode: "unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reportPath := filepath.Join(t.TempDir(), "list-all.html")
			if err := writeListAllHTML(reportPath, "Clipboard interaction contract", &domain.ScanResult{Mode: "local"}, listAllPackageReport{
				Rows: []listAllRow{{
					Name:       packageName,
					Installed:  fullDigest,
					Latest:     "-",
					Update:     "pinned",
					Ecosystem:  string(domain.EcosystemDocker),
					Source:     "Dockerfile",
					Scope:      "runtime",
					Relation:   "direct",
					LatestCopy: "",
				}},
			}); err != nil {
				t.Fatalf("write real list-all report: %v", err)
			}

			report, err := os.ReadFile(reportPath) //nolint:gosec // G304: reportPath is created by this test.
			if err != nil {
				t.Fatalf("read real list-all report: %v", err)
			}
			if got := strings.Count(string(report), cliHTMLReportCSPMeta); got != 1 {
				t.Fatalf("generated report CSP count = %d, want exactly one", got)
			}
			buttonNeedle := `<button type="button" class="copy-btn" data-copy="` + fullDigest + `"`
			if got := strings.Count(string(report), buttonNeedle); got != 1 {
				t.Fatalf("generated digest copy button count = %d, want exactly one", got)
			}

			instrumented := instrumentListAllHTMLClipboardReport(t, string(report), tt.mode)
			if got := strings.Count(instrumented, cliHTMLReportCSPMeta); got != 1 {
				t.Fatalf("instrumented report CSP count = %d, want the original CSP unchanged", got)
			}
			if err := os.WriteFile(reportPath, []byte(instrumented), 0o600); err != nil { // #nosec G703 -- reportPath is a t.TempDir path.
				t.Fatalf("write instrumented list-all report: %v", err)
			}

			probe := runListAllHTMLClipboardProbe(t, browser, reportPath)
			if probe.Mode != tt.mode {
				t.Fatalf("probe mode = %q, want %q", probe.Mode, tt.mode)
			}
			if probe.ButtonCount != 1 {
				t.Fatalf("browser copy button count = %d, want exactly one", probe.ButtonCount)
			}
			if len(probe.Writes) != tt.wantWrites {
				t.Fatalf("clipboard writes = %#v, want %d call(s)", probe.Writes, tt.wantWrites)
			}
			if tt.wantWrites == 1 && probe.Writes[0] != fullDigest {
				t.Fatalf("clipboard write = %q, want exact full digest %q", probe.Writes[0], fullDigest)
			}

			assertListAllHTMLCopyStatusRegion(t, probe.Immediate, successMessage, failureMessage, tt.wantOK)
			assertListAllHTMLCopyStatusRegion(t, probe.AfterReset, successMessage, failureMessage, tt.wantOK)

			if tt.wantOK {
				assertListAllHTMLClipboardSuccess(t, probe.Immediate, originalLabel, successMessage, false)
				assertListAllHTMLClipboardSuccess(t, probe.AfterReset, originalLabel, successMessage, true)
				return
			}

			failedLabel := failureMessage + " " + originalLabel
			assertListAllHTMLClipboardFailure(t, probe.Immediate, fullDigest, failedLabel, fallbackLabel, false)
			assertListAllHTMLClipboardFailure(t, probe.AfterReset, fullDigest, originalLabel, fallbackLabel, true)
		})
	}
}

func TestListAllHTMLKnownLatestDiffersRejectsUnknownOrMissingVersions(t *testing.T) {
	tests := []struct {
		name string
		row  listAllRow
	}{
		{name: "blank latest", row: listAllRow{Installed: "1.0.0"}},
		{name: "missing latest marker", row: listAllRow{Installed: "1.0.0", Latest: " - "}},
		{name: "unknown latest ignoring trim and case", row: listAllRow{Installed: "1.0.0", Latest: " UnKnOwN "}},
		{name: "blank installed", row: listAllRow{Latest: "2.0.0"}},
		{name: "missing installed marker", row: listAllRow{Installed: " - ", Latest: "2.0.0"}},
		{name: "unknown installed ignoring trim and case", row: listAllRow{Installed: " UnKnOwN ", Latest: "2.0.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if listAllHTMLKnownLatestDiffers(tt.row) {
				t.Fatalf("listAllHTMLKnownLatestDiffers(%+v) = true, want false", tt.row)
			}
		})
	}
}

func TestWriteListAllHTMLUnknownInstalledGitHubActionStaysVulnerable(t *testing.T) {
	t.Parallel()

	row := listAllRow{
		Name:      "actions/checkout",
		Installed: " UnKnOwN ",
		Latest:    "v4.2.2",
		Update:    "-",
		Ecosystem: string(domain.EcosystemGitHubActions),
		Source:    "workflow",
		Scope:     "ci",
		Relation:  "workflow",
	}
	result := &domain.ScanResult{Mode: "local", Findings: []domain.Finding{{
		Name:       row.Name,
		Version:    row.Installed,
		Ecosystem:  domain.EcosystemGitHubActions,
		Type:       domain.FindingTypeVulnerability,
		Severity:   domain.SeverityHigh,
		AdvisoryID: "GHSA-unknown-installed",
	}}}
	path := filepath.Join(t.TempDir(), "unknown-installed-action.html")
	if err := writeListAllHTML(path, "Unknown installed action", result, listAllPackageReport{Rows: []listAllRow{row}}); err != nil {
		t.Fatalf("writeListAllHTML() error = %v", err)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- test reads its generated report.
	if err != nil {
		t.Fatalf("read generated report: %v", err)
	}
	report := string(raw)
	if !strings.Contains(report, `<td class="package-status">Vulnerable</td>`) {
		t.Fatalf("generated report does not render the unknown-installed action as Vulnerable")
	}
	if strings.Contains(report, `id="available-updates"`) || strings.Contains(report, `>Update available</td>`) {
		t.Fatalf("generated report advertises an update for an unknown installed action version")
	}
}

func TestListAllUnknownStatusHintOperationalContracts(t *testing.T) {
	const (
		unaffected = "security findings for these packages are unaffected."
		apiKeyNote = " For additional reputation and malware-history coverage, configure the server-side ReversingLabs Spectra Assure key (PACKMON_REVERSINGLABS_API_KEY)."
	)
	tests := []struct {
		name   string
		report listAllPackageReport
		want   string
	}{
		{
			name: "offline takes precedence over operational counters",
			report: listAllPackageReport{
				Offline:            true,
				RefusedRequests:    2,
				OversizedResponses: 3,
				BreakerTripped:     true,
				SkippedRequests:    4,
			},
			want: "Unknown status means the latest version was not looked up in offline mode; " + unaffected + apiKeyNote,
		},
		{
			name: "clean run explains private and unsupported packages",
			want: "The unknown rows are packages the public registry does not carry (workspace or private packages) or sources Packmon intentionally does not query; no action is needed, and " + unaffected + apiKeyNote,
		},
		{
			name:   "refused requests explain retry options",
			report: listAllPackageReport{RefusedRequests: 2},
			want:   "Unknown status means the latest version could not be determined; " + unaffected + " 2 registry requests were refused or failed -- rerun the scan, raise --timeout, or configure a registry mirror." + apiKeyNote,
		},
		{
			name:   "oversized responses explain the memory bound",
			report: listAllPackageReport{OversizedResponses: 3},
			want:   "Unknown status means the latest version could not be determined; " + unaffected + " 3 registry responses exceeded the CLI's response size limit and were discarded -- a memory bound, not a rate limit or a timeout." + apiKeyNote,
		},
		{
			name:   "breaker reports skipped requests",
			report: listAllPackageReport{BreakerTripped: true, SkippedRequests: 4},
			want:   "Unknown status means the latest version could not be determined; " + unaffected + " Lookups were aborted after consecutive registry failures (4 skipped) -- check network connectivity and proxy settings." + apiKeyNote,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := listAllUnknownStatusHint(tt.report)
			if got != tt.want {
				t.Fatalf("listAllUnknownStatusHint() = %q, want exact %q", got, tt.want)
			}
			if strings.Count(got, unaffected) != 1 || strings.Count(got, "PACKMON_REVERSINGLABS_API_KEY") != 1 {
				t.Fatalf("listAllUnknownStatusHint() shared wording counts = unaffected:%d API-key:%d, want 1/1", strings.Count(got, unaffected), strings.Count(got, "PACKMON_REVERSINGLABS_API_KEY"))
			}
		})
	}
}

func TestListAllHTMLPackageStatusReportsUnpinned(t *testing.T) {
	for _, update := range []string{"unpinned", " UnPiNnEd "} {
		row := listAllRow{Installed: "1.0.0", Latest: "2.0.0", Update: update}
		if got := listAllHTMLPackageStatus(row, nil); got != "Unpinned" {
			t.Errorf("listAllHTMLPackageStatus(Update: %q) = %q, want Unpinned", update, got)
		}
	}
}

func assertListAllHTMLCopyStatusRegion(t *testing.T, snapshot listAllHTMLClipboardSnapshot, successMessage, failureMessage string, success bool) {
	t.Helper()
	if snapshot.StatusRole != "status" || snapshot.StatusLive != "polite" {
		t.Fatalf("copy status accessibility = role %q aria-live %q, want status/polite", snapshot.StatusRole, snapshot.StatusLive)
	}
	want := failureMessage
	if success {
		want = successMessage
	}
	if snapshot.StatusText != want {
		t.Fatalf("copy live status = %q, want %q", snapshot.StatusText, want)
	}
}

func assertListAllHTMLClipboardSuccess(t *testing.T, snapshot listAllHTMLClipboardSnapshot, originalLabel, successMessage string, afterReset bool) {
	t.Helper()
	if afterReset {
		if snapshot.Copied || snapshot.CopyFailed {
			t.Fatalf("reset success classes = copied:%t copy-failed:%t, want both false", snapshot.Copied, snapshot.CopyFailed)
		}
		if snapshot.AriaLabel != originalLabel {
			t.Fatalf("reset success aria-label = %q, want %q", snapshot.AriaLabel, originalLabel)
		}
	} else {
		if !snapshot.Copied || snapshot.CopyFailed {
			t.Fatalf("immediate success classes = copied:%t copy-failed:%t, want true/false", snapshot.Copied, snapshot.CopyFailed)
		}
		if snapshot.AriaLabel != successMessage {
			t.Fatalf("immediate success aria-label = %q, want %q", snapshot.AriaLabel, successMessage)
		}
	}
	if snapshot.FallbackCount != 0 || snapshot.FallbackValue != "" {
		t.Fatalf("success fallback = count %d value %q, want none", snapshot.FallbackCount, snapshot.FallbackValue)
	}
}

func assertListAllHTMLClipboardFailure(t *testing.T, snapshot listAllHTMLClipboardSnapshot, fullDigest, wantButtonLabel, fallbackLabel string, afterReset bool) {
	t.Helper()
	if afterReset {
		if snapshot.Copied || snapshot.CopyFailed {
			t.Fatalf("reset failure classes = copied:%t copy-failed:%t, want both false", snapshot.Copied, snapshot.CopyFailed)
		}
	} else if snapshot.Copied || !snapshot.CopyFailed {
		t.Fatalf("immediate failure classes = copied:%t copy-failed:%t, want false/true", snapshot.Copied, snapshot.CopyFailed)
	}
	if snapshot.AriaLabel != wantButtonLabel {
		t.Fatalf("failure aria-label = %q, want %q", snapshot.AriaLabel, wantButtonLabel)
	}
	if snapshot.FallbackCount != 1 || snapshot.FallbackValue != fullDigest {
		t.Fatalf("fallback = count %d value %q, want one exact full digest", snapshot.FallbackCount, snapshot.FallbackValue)
	}
	if snapshot.FallbackLabel != fallbackLabel || !snapshot.FallbackReadOnly {
		t.Fatalf("fallback accessibility = label %q readonly %t, want %q/true", snapshot.FallbackLabel, snapshot.FallbackReadOnly, fallbackLabel)
	}
	if snapshot.FallbackFocusCalls != 1 || !snapshot.FallbackFocusExact || !snapshot.FallbackFocusOpts || snapshot.FallbackSelectFrom != 0 || snapshot.FallbackSelectTo != len(fullDigest) {
		t.Fatalf("fallback focus/selection = calls:%d exact:%t prevent-scroll:%t range:%d..%d, want 1/true/true and 0..%d", snapshot.FallbackFocusCalls, snapshot.FallbackFocusExact, snapshot.FallbackFocusOpts, snapshot.FallbackSelectFrom, snapshot.FallbackSelectTo, len(fullDigest))
	}
}

func instrumentListAllHTMLClipboardReport(t *testing.T, report, mode string) string {
	t.Helper()
	modeJSON, err := json.Marshal(mode)
	if err != nil {
		t.Fatalf("encode clipboard mode: %v", err)
	}
	setup := fmt.Sprintf(`<script>
window.__packmonClipboardMode=%s;
window.__packmonClipboardWrites=[];
window.__packmonFallbackFocusCalls=[];
(function(){
  var originalFocus=HTMLElement.prototype.focus;
  HTMLElement.prototype.focus=function(){
    if(this.classList && this.classList.contains('copy-fallback')){
      window.__packmonFallbackFocusCalls.push({target:this,preventScroll:!!(arguments.length && arguments[0] && arguments[0].preventScroll===true)});
    }
    return originalFocus.apply(this,arguments);
  };
})();
if(window.__packmonClipboardMode==='unavailable'){
  Object.defineProperty(navigator,'clipboard',{configurable:true,value:undefined});
}else{
  Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:function(value){
    window.__packmonClipboardWrites.push(value);
    if(window.__packmonClipboardMode==='reject'){return Promise.reject(new Error('clipboard rejected by test'));}
    return Promise.resolve();
  }}});
}
</script>
`, modeJSON)
	productStart := "<script>\n(function(){\n  var status=document.getElementById('copy-status');"
	start := strings.Index(report, productStart)
	if start < 0 {
		t.Fatal("generated report does not contain the product clipboard script")
	}
	productEndNeedle := "})();\n</script>"
	endRelative := strings.Index(report[start:], productEndNeedle)
	if endRelative < 0 {
		t.Fatal("generated report clipboard script has no closing marker")
	}
	end := start + endRelative + len(productEndNeedle)
	productScript := report[start:end]

	driver := `<script>
(function(){
  var resultNode=document.createElement('pre');
  resultNode.id='packmon-copy-probe';
  resultNode.hidden=true;
  document.body.appendChild(resultNode);
  var buttons=document.querySelectorAll('button.copy-btn[data-copy]');
  var button=buttons.length===1 ? buttons[0] : null;
  function snapshot(){
    var status=document.getElementById('copy-status');
    var fallbacks=document.querySelectorAll('.copy-fallback');
    var fallback=fallbacks.length===1 ? fallbacks[0] : null;
    return {
      copied:!!(button && button.classList.contains('copied')),
      copyFailed:!!(button && button.classList.contains('copy-failed')),
      ariaLabel:button ? (button.getAttribute('aria-label') || '') : '',
      statusText:status ? status.textContent : '',
      statusRole:status ? (status.getAttribute('role') || '') : '',
      statusLive:status ? (status.getAttribute('aria-live') || '') : '',
      fallbackCount:fallbacks.length,
      fallbackValue:fallback ? fallback.value : '',
      fallbackLabel:fallback ? (fallback.getAttribute('aria-label') || '') : '',
      fallbackReadOnly:!!(fallback && fallback.readOnly),
      fallbackFocusCalls:window.__packmonFallbackFocusCalls.length,
      fallbackFocusExact:!!(fallback && window.__packmonFallbackFocusCalls.every(function(call){return call.target===fallback;})),
      fallbackFocusOpts:!!(window.__packmonFallbackFocusCalls.length && window.__packmonFallbackFocusCalls.every(function(call){return call.preventScroll;})),
      fallbackSelectFrom:fallback && fallback.selectionStart!==null ? fallback.selectionStart : -1,
      fallbackSelectTo:fallback && fallback.selectionEnd!==null ? fallback.selectionEnd : -1
    };
  }
  var result={mode:window.__packmonClipboardMode,buttonCount:buttons.length,writes:window.__packmonClipboardWrites,immediate:null,afterReset:null};
  if(button){button.click();}
  window.setTimeout(function(){
    result.immediate=snapshot();
    window.setTimeout(function(){
      result.afterReset=snapshot();
      resultNode.textContent=JSON.stringify(result);
      document.body.setAttribute('data-packmon-copy-probe','complete');
    },5250);
  },0);
})();
</script>`

	instrumented := report[:start] + setup + productScript + driver + report[end:]
	if strings.Count(instrumented, productScript) != 1 {
		t.Fatal("instrumentation changed or duplicated the product clipboard script")
	}
	return instrumented
}

func runListAllHTMLClipboardProbe(t *testing.T, browser, reportPath string) listAllHTMLClipboardProbeResult {
	t.Helper()
	rawURL := cliHTMLReportFileURL(t, reportPath)
	args := func(headless string) []string {
		return []string{
			headless,
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
			"--user-data-dir=" + t.TempDir(),
			"--virtual-time-budget=6500",
			"--dump-dom",
			rawURL,
		}
	}
	output, err := runCLIHTMLReportBrowser(t, browser, args("--headless=new"))
	if err != nil && strings.Contains(string(output), "headless=new") {
		output, err = runCLIHTMLReportBrowser(t, browser, args("--headless"))
	}
	if err != nil {
		t.Fatalf("headless clipboard interaction failed: %v\n%s", err, output)
	}
	dom := string(output)
	if !strings.Contains(dom, `data-packmon-copy-probe="complete"`) {
		t.Fatalf("clipboard interaction did not reach its post-reset snapshot:\n%s", dom)
	}
	match := regexp.MustCompile(`<pre id="packmon-copy-probe"[^>]*>([^<]+)</pre>`).FindStringSubmatch(dom)
	if len(match) != 2 {
		t.Fatalf("clipboard interaction result missing from browser DOM:\n%s", dom)
	}
	var result listAllHTMLClipboardProbeResult
	if err := json.Unmarshal([]byte(html.UnescapeString(match[1])), &result); err != nil {
		t.Fatalf("decode clipboard interaction result %q: %v", match[1], err)
	}
	return result
}
