//go:build e2e

package e2e

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
	"testing"
	"time"
)

func TestFeedAutoRefreshBehaviorInHeadlessBrowser(t *testing.T) {
	t.Parallel()

	browser := findHeadlessBrowser(t)
	script := readRepoFile(t, "internal", "web", "static", "auto-refresh.js")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(feedRefreshBrowserHarnessHTML()))
		case "/static/auto-refresh.js":
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			_, _ = w.Write(script)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	dom := dumpHeadlessBrowserDOM(t, browser, server.URL)
	for _, want := range []string{
		`data-test-result="pass"`,
		`data-events="1"`,
		`data-refreshed="true"`,
		`data-paused-state="false|Paused|true|true"`,
		`data-resumed-state="true|On (30s)|false|true"`,
	} {
		if !strings.Contains(dom, want) {
			t.Fatalf("browser DOM missing %q:\n%s", want, dom)
		}
	}
}

func feedRefreshBrowserHarnessHTML() string {
	return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Packmon feed refresh browser harness</title>
</head>
<body>
  <div
    data-auto-refresh-control
    data-auto-refresh-event="feed-status-refresh"
    data-auto-refresh-interval-ms="60000"
    data-auto-refresh-storage-key="packmon:e2e:auto-refresh"
    data-auto-refresh-label="Auto-refresh"
    data-auto-refresh-running-label="On (30s)"
    data-auto-refresh-paused-label="Paused"
    data-auto-refresh-running-class="is-running"
    data-auto-refresh-paused-class="is-paused"
  >
    <span data-auto-refresh-status>On (30s)</span>
    <button type="button" data-auto-refresh-toggle aria-controls="feed-status-container" aria-pressed="true">Auto-refresh</button>
    <button type="button" data-auto-refresh-now aria-controls="feed-status-container">Refresh now</button>
  </div>
  <div
    id="feed-status-container"
    aria-busy="false"
    hx-get="/feeds?partial=status"
    hx-trigger="feed-status-refresh from:body"
  ></div>
  <output id="result" data-test-result="pending"></output>
  <script src="/static/auto-refresh.js"></script>
  <script>
    window.addEventListener("DOMContentLoaded", function () {
      var events = 0;
      var container = document.getElementById("feed-status-container");
      var result = document.getElementById("result");
      var toggle = document.querySelector("[data-auto-refresh-toggle]");
      var refreshNow = document.querySelector("[data-auto-refresh-now]");
      var status = document.querySelector("[data-auto-refresh-status]");

      document.body.addEventListener("feed-status-refresh", function () {
        events += 1;
        container.dataset.refreshed = "true";
      });

      refreshNow.click();
      toggle.click();
      var pausedState = [
        toggle.getAttribute("aria-pressed"),
        status.textContent,
        window.localStorage.getItem("packmon:e2e:auto-refresh"),
        toggle.classList.contains("is-paused")
      ].join("|");
      refreshNow.click();
      toggle.click();
      var resumedState = [
        toggle.getAttribute("aria-pressed"),
        status.textContent,
        window.localStorage.getItem("packmon:e2e:auto-refresh"),
        toggle.classList.contains("is-running")
      ].join("|");

      result.dataset.testResult = events === 1 && container.dataset.refreshed === "true" ? "pass" : "fail";
      result.dataset.events = String(events);
      result.dataset.refreshed = container.dataset.refreshed || "false";
      result.dataset.pausedState = pausedState;
      result.dataset.resumedState = resumedState;
    });
  </script>
</body>
</html>`
}

func findHeadlessBrowser(t *testing.T) string {
	t.Helper()

	for _, env := range []string{"PACKMON_BROWSER_BIN", "CHROME_BIN", "EDGE_BIN"} {
		if path := strings.TrimSpace(os.Getenv(env)); path != "" {
			if fileExists(path) {
				return path
			}
			if resolved, err := exec.LookPath(path); err == nil {
				return resolved
			}
			t.Skipf("%s points to unavailable browser executable %q", env, path)
		}
	}

	candidates := []string{
		"google-chrome",
		"google-chrome-stable",
		"chromium",
		"chromium-browser",
		"microsoft-edge",
		"msedge",
	}
	if runtime.GOOS == "windows" {
		candidates = append([]string{
			filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
		}, candidates...)
	}
	if runtime.GOOS == "darwin" {
		candidates = append([]string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}, candidates...)
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if fileExists(candidate) {
			return candidate
		}
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved
		}
	}
	t.Skip("Chrome, Chromium, or Edge is required for browser e2e coverage; set PACKMON_BROWSER_BIN to run this test")
	return ""
}

func dumpHeadlessBrowserDOM(t *testing.T, browser, url string) string {
	t.Helper()

	profileDir := t.TempDir()
	args := []string{
		"--headless=new",
		"--disable-background-networking",
		"--disable-default-apps",
		"--disable-extensions",
		"--disable-gpu",
		"--disable-popup-blocking",
		"--disable-sync",
		"--no-first-run",
		"--no-sandbox",
		"--user-data-dir=" + profileDir,
		"--dump-dom",
		url,
	}
	output, err := runBrowser(t, browser, args)
	if err != nil && strings.Contains(string(output), "headless=new") {
		args[0] = "--headless"
		output, err = runBrowser(t, browser, args)
	}
	if err != nil {
		t.Fatalf("headless browser failed: %v\n%s", err, string(output))
	}
	return html.UnescapeString(string(output))
}

func runBrowser(t *testing.T, browser string, args []string) ([]byte, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, browser, args...)
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return output, fmt.Errorf("timed out after 15s")
	}
	return output, err
}

func readRepoFile(t *testing.T, path ...string) []byte {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve repository root: runtime caller unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	data, err := os.ReadFile(filepath.Join(append([]string{root}, path...)...))
	if err != nil {
		t.Fatalf("read repo file %s: %v", filepath.Join(path...), err)
	}
	return data
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
