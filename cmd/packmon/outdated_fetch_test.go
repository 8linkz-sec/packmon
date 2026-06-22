package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestFetchLatestVersionParsesSupportedRegistryResponses(t *testing.T) {
	originalClient := registryClient
	originalGitRemoteTags := gitRemoteTagsFn
	t.Cleanup(func() { registryClient = originalClient })
	t.Cleanup(func() { gitRemoteTagsFn = originalGitRemoteTags })

	responses := map[string]string{
		"registry.npmjs.org/pkg/latest":                             `{"version":"1.2.3"}`,
		"pypi.org/pypi/pkg/json":                                    `{"info":{"version":"2.3.4"}}`,
		"proxy.golang.org/github.com/acme/lib/@latest":              `{"Version":"v1.2.0"}`,
		"proxy.golang.org/github.com/!burnt!sushi/toml/@latest":     `{"Version":"v1.6.0"}`,
		"crates.io/api/v1/crates/pkg":                               `{"crate":{"max_stable_version":"3.4.5"}}`,
		"api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json": `{"versions":["12.0.1","13.0.3","13.0.2"]}`,
		"rubygems.org/api/v1/gems/pkg.json":                         `{"version":"4.5.6"}`,
		"repo.packagist.org/p2/vendor/package.json":                 `{"packages":{"vendor/package":[{"version":"dev-main"},{"version":"5.6.7"}]}}`,
		"search.maven.org/solrsearch/select?q=g%3A%22com.google.guava%22+AND+a%3A%22guava%22&rows=1&wt=json": `{"response":{"docs":[{"latestVersion":"33.4.8-jre"}]}}`,
		"pub.dev/api/packages/http":                              `{"latest":{"version":"1.5.0"}}`,
		"hex.pm/api/packages/jason":                              `{"latest_version":"1.5.0-alpha.2","latest_stable_version":"1.4.5"}`,
		"cran.r-project.org/web/packages/dplyr/DESCRIPTION":      "Package: dplyr\nVersion: 1.1.4\n",
		"trunk.cocoapods.org/api/v1/pods/Alamofire/specs/latest": `{"name":"Alamofire","version":"5.11.2"}`,
	}
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Accept") != "application/json" {
			t.Fatalf("Accept header = %q, want application/json", req.Header.Get("Accept"))
		}
		key := req.URL.Host + req.URL.EscapedPath()
		if req.URL.RawQuery != "" {
			key += "?" + req.URL.RawQuery
		}
		body, ok := responses[key]
		if !ok {
			t.Fatalf("unexpected registry request: %s %s", req.Method, req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}
	gitRemoteTagsFn = func(_ context.Context, remote string) ([]string, error) {
		switch remote {
		case "https://github.com/Alamofire/Alamofire.git":
			return []string{"5.9.0", "5.11.2", "5.10.0"}, nil
		case "https://github.com/actions/checkout.git":
			return []string{"v3", "v4", "v4.2.2"}, nil
		default:
			t.Fatalf("unexpected git remote: %s", remote)
			return nil, nil
		}
	}

	tests := []struct {
		ecosystem domain.Ecosystem
		name      string
		want      string
	}{
		{domain.EcosystemNPM, "pkg", "1.2.3"},
		{domain.EcosystemPyPI, "pkg", "2.3.4"},
		{domain.EcosystemGo, "github.com/acme/lib", "v1.2.0"},
		{domain.EcosystemGo, "github.com/BurntSushi/toml", "v1.6.0"},
		{domain.EcosystemCargo, "pkg", "3.4.5"},
		{domain.EcosystemNuGet, "Newtonsoft.Json", "13.0.3"},
		{domain.EcosystemGem, "pkg", "4.5.6"},
		{domain.EcosystemComposer, "vendor/package", "5.6.7"},
		{domain.EcosystemMaven, "com.google.guava:guava", "33.4.8-jre"},
		{domain.EcosystemPub, "http", "1.5.0"},
		{domain.EcosystemHex, "jason", "1.4.5"},
		{domain.EcosystemCRAN, "dplyr", "1.1.4"},
		{domain.EcosystemCocoaPods, "Alamofire", "5.11.2"},
		{domain.EcosystemSwiftPM, "github.com/Alamofire/Alamofire", "5.11.2"},
		{domain.EcosystemGitHubActions, "actions/checkout", "v4.2.2"},
	}

	for _, tt := range tests {
		t.Run(string(tt.ecosystem), func(t *testing.T) {
			if got := fetchLatestVersion(context.Background(), tt.ecosystem, tt.name); got != tt.want {
				t.Fatalf("fetchLatestVersion(%s, %q) = %q, want %q", tt.ecosystem, tt.name, got, tt.want)
			}
		})
	}

	if got := fetchLatestVersion(context.Background(), domain.Ecosystem("unknown"), "pkg"); got != "" {
		t.Fatalf("fetchLatestVersion(unsupported) = %q, want empty", got)
	}
}

func TestRegistryGetHandlesTransportAndStatusErrors(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})}
	if _, err := registryGet(context.Background(), "https://registry.example/pkg"); err == nil {
		t.Fatal("registryGet transport error = nil")
	}

	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}
	if _, err := registryGet(context.Background(), "https://registry.example/pkg"); err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("registryGet status error = %v", err)
	}

	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`not json`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}
	if got := fetchNPMLatest(context.Background(), "pkg"); got != "" {
		t.Fatalf("fetchNPMLatest(invalid json) = %q, want empty", got)
	}
}

func TestFetchPyPILatestHandlesLargeMetadataResponses(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	largePayload := `{"info":{"version":"2.47.0"},"releases":{"old":["` + strings.Repeat("x", 8*1024*1024+1024) + `"]}}`
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(largePayload)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	if got := fetchPyPILatest(context.Background(), "pydantic-core"); got != "2.47.0" {
		t.Fatalf("fetchPyPILatest(large metadata) = %q, want 2.47.0", got)
	}
}

func TestRunOutdatedReportsNoLockFiles(t *testing.T) {
	output := captureStdout(t, func() {
		if err := runOutdated([]string{t.TempDir()}, "", 2); err != nil {
			t.Fatalf("run outdated: %v", err)
		}
	})
	if !strings.Contains(output, "No lock files found.") {
		t.Fatalf("run outdated output = %q", output)
	}
}

func TestRunOutdatedPrintsOnlyOutdatedPackages(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		key := req.URL.Host + req.URL.EscapedPath()
		responses := map[string]string{
			"registry.npmjs.org/outdated/latest": `{"version":"2.0.0"}`,
			"registry.npmjs.org/current/latest":  `{"version":"1.0.0"}`,
		}
		body, ok := responses[key]
		if !ok {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	dir := t.TempDir()
	lockPath := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(lockPath, []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"version": "1.0.0"},
			"node_modules/outdated": {"version": "1.0.0"},
			"node_modules/current": {"version": "1.0.0"},
			"node_modules/unknown": {"version": "1.0.0"}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runOutdated([]string{dir}, "npm", 2); err != nil {
			t.Fatalf("run outdated: %v", err)
		}
	})

	for _, want := range []string{"PACKAGE", "outdated", "1.0.0", "2.0.0", "1 outdated, 1 up to date, 1 unknown (3 total)"} {
		if !strings.Contains(output, want) {
			t.Fatalf("run outdated output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "current  ") || strings.Contains(output, "unknown  ") {
		t.Fatalf("run outdated should not print current/unknown packages as outdated:\n%s", output)
	}
}

func TestScanCommandOutdatedHTMLFlagWritesReport(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		if name == "outdated" {
			return "2.0.0"
		}
		return ""
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/outdated": {"version": "1.0.0"}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")

	cmd := newScanCmd()
	cmd.SetArgs([]string{"--outdated", "--html", htmlPath, dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan command execute: %v", err)
	}

	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read outdated HTML report: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		"<!DOCTYPE html>",
		"Outdated Packages",
		"outdated",
		"1.0.0",
		"2.0.0",
		".wrap{max-width:1600px",
		".version{white-space:nowrap",
		"<th class=\"version\">Installed</th>",
		"<td class=\"version\">1.0.0</td>",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("outdated HTML missing %q:\n%s", want, out)
		}
	}
}

func TestScanCommandOutdatedIncludesDevByDefault(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		switch name {
		case "prod", "dev-only":
			return "2.0.0"
		default:
			return ""
		}
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/prod": {"version": "1.0.0"},
			"node_modules/dev-only": {"version": "1.0.0", "dev": true}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	output := captureStdout(t, func() {
		cmd := newScanCmd()
		cmd.SetArgs([]string{"--outdated", dir})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("scan command execute: %v", err)
		}
	})

	if !strings.Contains(output, "prod") {
		t.Fatalf("outdated output missing production package:\n%s", output)
	}
	if !strings.Contains(output, "dev-only") {
		t.Fatalf("outdated output should include dev packages by default:\n%s", output)
	}
}

func TestScanCommandOutdatedRendersScopeRelationViaAndFlags(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		switch name {
		case "tailwindcss":
			return "4.3.0"
		case "postcss":
			return "8.5.15"
		default:
			return ""
		}
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "test",
				"version": "1.0.0",
				"devDependencies": {"tailwindcss": "^3.4.17"}
			},
			"node_modules/tailwindcss": {
				"version": "3.4.17",
				"dev": true,
				"dependencies": {"postcss": "^8.4.47"}
			},
			"node_modules/postcss": {
				"version": "8.5.8",
				"dev": true,
				"peer": true
			}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")

	output := captureStdout(t, func() {
		cmd := newScanCmd()
		cmd.SetArgs([]string{"--outdated", "--html", htmlPath, dir})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("scan command execute: %v", err)
		}
	})
	for _, want := range []string{"SCOPE", "RELATION", "VIA", "FLAGS", "postcss", "dev", "transitive", "tailwindcss", "peer"} {
		if !strings.Contains(output, want) {
			t.Fatalf("outdated output missing %q:\n%s", want, output)
		}
	}

	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read outdated HTML report: %v", err)
	}
	html := string(data)
	for _, want := range []string{"Scope", "Relation", "Via", "Flags", "postcss", "dev", "transitive", "tailwindcss", "peer"} {
		if !strings.Contains(html, want) {
			t.Fatalf("outdated HTML missing %q:\n%s", want, html)
		}
	}
}

func TestRunOutdatedDoesNotReportNewerGoPseudoVersionAsOutdated(t *testing.T) {
	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		if name == "github.com/davecgh/go-spew" {
			return "v1.1.1"
		}
		return ""
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(`module example.com/app

go 1.26

require github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
`), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runOutdated([]string{dir}, "go", 2); err != nil {
			t.Fatalf("run outdated: %v", err)
		}
	})

	if strings.Contains(output, "github.com/davecgh/go-spew") {
		t.Fatalf("newer Go pseudo-version should not be reported as outdated:\n%s", output)
	}
	if !strings.Contains(output, "All 1 packages are up to date.") {
		t.Fatalf("run outdated output = %q, want up-to-date summary", output)
	}
}

func TestRunOutdatedReportsNoPackagesAfterParseErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`not json`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runOutdated([]string{dir}, "npm", 2); err != nil {
			t.Fatalf("run outdated: %v", err)
		}
	})
	if !strings.Contains(output, "No packages found.") {
		t.Fatalf("run outdated output = %q, want no packages", output)
	}
}

func TestRunOutdatedMalformedSBOMReturnsParserExit(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.cdx.json")
	if err := os.WriteFile(badPath, []byte(`{"bomFormat":"CycloneDX",`), 0o600); err != nil {
		t.Fatalf("write malformed SBOM: %v", err)
	}

	err := runOutdated([]string{dir}, "", 2, []string{badPath})
	if err == nil {
		t.Fatal("runOutdated(malformed SBOM) error = nil")
	}
	if code := exitCodeForError(err); code != ExitParser {
		t.Fatalf("exitCodeForError = %d, want %d; err=%v", code, ExitParser, err)
	}
}

func TestFetchLatestVersionReturnsEmptyForInvalidRegistryJSON(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`not json`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	for _, ecosystem := range []domain.Ecosystem{
		domain.EcosystemNPM,
		domain.EcosystemPyPI,
		domain.EcosystemGo,
		domain.EcosystemCargo,
		domain.EcosystemNuGet,
		domain.EcosystemGem,
		domain.EcosystemComposer,
		domain.EcosystemMaven,
		domain.EcosystemPub,
		domain.EcosystemHex,
		domain.EcosystemCocoaPods,
	} {
		t.Run(string(ecosystem), func(t *testing.T) {
			if got := fetchLatestVersion(context.Background(), ecosystem, "pkg"); got != "" {
				t.Fatalf("fetchLatestVersion(%s invalid JSON) = %q, want empty", ecosystem, got)
			}
		})
	}
}
