package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestOutdatedHTMLReportCSPBlocksNetworkCapabilities verifies the CSP in a
// generated report in a real browser. A report must retain its inline scripts,
// but must not be able to fetch, load another script, or submit a form.
func TestOutdatedHTMLReportCSPBlocksNetworkCapabilities(t *testing.T) {
	browser := findCLIHTMLReportBrowser(t)

	reportPath := filepath.Join(t.TempDir(), "outdated.html")
	if err := writeOutdatedHTML(reportPath, outdatedReport{Total: 1, PackageWord: "package"}); err != nil {
		t.Fatalf("write outdated report: %v", err)
	}
	report, err := os.ReadFile(reportPath) //nolint:gosec // G304: path built by the test itself, not from request data.
	if err != nil {
		t.Fatalf("read generated report: %v", err)
	}
	report = []byte(strings.Replace(string(report), "</body>", cliHTMLReportCSPProbe+"</body>", 1))

	var fetches atomic.Int32
	var scripts atomic.Int32
	var submissions atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/report":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(report)
		case "/probe-fetch":
			fetches.Add(1)
		case "/probe-script.js":
			scripts.Add(1)
			_, _ = w.Write([]byte("window.__externalScriptLoaded = true"))
		case "/probe-submit":
			submissions.Add(1)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	dom := dumpCLIHTMLReportDOM(t, browser, server.URL+"/report")
	if !strings.Contains(dom, `data-csp-probe="inline-ran"`) {
		t.Fatalf("generated report did not run its permitted inline probe:\n%s", dom)
	}
	if got := fetches.Load(); got != 0 {
		t.Errorf("CSP allowed %d fetch request(s), want none", got)
	}
	if got := scripts.Load(); got != 0 {
		t.Errorf("CSP allowed %d external script request(s), want none", got)
	}
	if got := submissions.Load(); got != 0 {
		t.Errorf("CSP allowed %d form submission(s), want none", got)
	}
}

const cliHTMLReportCSPProbe = `<script>
document.body.dataset.cspProbe = "inline-ran";
fetch("/probe-fetch").catch(function () {});
var script = document.createElement("script");
script.src = "/probe-script.js";
document.head.appendChild(script);
var frame = document.createElement("iframe");
frame.name = "csp-probe-frame";
document.body.appendChild(frame);
var form = document.createElement("form");
form.method = "post";
form.action = "/probe-submit";
form.target = "csp-probe-frame";
document.body.appendChild(form);
form.submit();
</script>`

func findCLIHTMLReportBrowser(t *testing.T) string {
	t.Helper()

	for _, env := range []string{"PACKMON_BROWSER_BIN", "CHROME_BIN", "EDGE_BIN"} {
		if path := strings.TrimSpace(os.Getenv(env)); path != "" {
			if cliHTMLReportFileExists(path) {
				return path
			}
			if resolved, err := exec.LookPath(path); err == nil {
				return resolved
			}
			t.Skipf("%s points to unavailable browser executable %q", env, path)
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
	t.Skip("Chrome, Chromium, or Edge is required for generated HTML report CSP coverage; set PACKMON_BROWSER_BIN to run this test")
	return ""
}

func dumpCLIHTMLReportDOM(t *testing.T, browser, rawURL string) string {
	t.Helper()

	profileDir := t.TempDir()
	args := []string{
		"--headless=new",
		"--disable-background-networking",
		"--disable-default-apps",
		"--disable-extensions",
		"--disable-gpu",
		"--disable-sync",
		"--no-first-run",
		"--no-sandbox",
		"--user-data-dir=" + profileDir,
		"--virtual-time-budget=500",
		"--dump-dom",
		rawURL,
	}
	output, err := runCLIHTMLReportBrowser(t, browser, args)
	if err != nil && strings.Contains(string(output), "headless=new") {
		args[0] = "--headless"
		output, err = runCLIHTMLReportBrowser(t, browser, args)
	}
	if err != nil {
		t.Fatalf("headless browser failed: %v\n%s", err, output)
	}
	return html.UnescapeString(string(output))
}

func runCLIHTMLReportBrowser(t *testing.T, browser string, args []string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, browser, args...) //nolint:gosec // G204: browser resolved by the test's own lookup; args are test constants.
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return output, fmt.Errorf("timed out after 15s")
	}
	return output, err
}

func cliHTMLReportFileExists(path string) bool {
	info, err := os.Stat(path) //nolint:gosec // G703: candidate browser paths are test constants.
	return err == nil && !info.IsDir()
}
