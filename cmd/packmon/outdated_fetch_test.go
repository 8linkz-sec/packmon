package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type countingReadCloser struct {
	remaining int64
	read      int64
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 'x'
	}
	n := len(p)
	r.remaining -= int64(n)
	r.read += int64(n)
	return n, nil
}

func (r *countingReadCloser) Close() error {
	return nil
}

func TestFetchLatestVersionParsesSupportedRegistryResponses(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

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
	resolver := packageUpdateResolver{
		gitRemoteTags: func(_ context.Context, remote string) ([]string, error) {
			switch remote {
			case "https://github.com/Alamofire/Alamofire.git":
				return []string{"5.9.0", "5.11.2", "5.10.0"}, nil
			case "https://github.com/actions/checkout.git":
				return []string{"v3", "v4", "v4.2.2"}, nil
			default:
				t.Fatalf("unexpected git remote: %s", remote)
				return nil, nil
			}
		},
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
			if got := resolver.latestVersion(context.Background(), tt.ecosystem, tt.name); got != tt.want {
				t.Fatalf("fetchLatestVersion(%s, %q) = %q, want %q", tt.ecosystem, tt.name, got, tt.want)
			}
		})
	}

	if got := resolver.latestVersion(context.Background(), domain.Ecosystem("unknown"), "pkg"); got != "" {
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

func TestRegistryGetDrainsBoundedErrorBodies(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	body := &countingReadCloser{remaining: 1 << 20}
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Body:       body,
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	if _, err := registryGet(context.Background(), "https://registry.example/pkg"); err == nil || !strings.Contains(err.Error(), "status 429") {
		t.Fatalf("registryGet() error = %v, want status 429", err)
	}
	if body.read == 0 {
		t.Fatal("registryGet() did not drain any bytes from non-OK response")
	}
	if body.read > 64<<10 {
		t.Fatalf("drained %d bytes, want at most 64 KiB", body.read)
	}
}

func TestFetchCratesLatestUsesPolicyUserAgentAndThrottle(t *testing.T) {
	originalClient := registryClient
	originalThrottle := cratesIOThrottle
	t.Cleanup(func() {
		registryClient = originalClient
		cratesIOThrottle = originalThrottle
	})

	now := time.Unix(1000, 0)
	var slept []time.Duration
	cratesIOThrottle = &registryThrottle{
		interval: time.Second,
		now: func() time.Time {
			return now
		},
		sleep: func(_ context.Context, d time.Duration) bool {
			slept = append(slept, d)
			now = now.Add(d)
			return true
		},
	}

	var userAgents []string
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "crates.io" {
			t.Fatalf("unexpected registry host: %s", req.URL.Host)
		}
		userAgents = append(userAgents, req.Header.Get("User-Agent"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"crate":{"max_stable_version":"1.2.3"}}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	if got := fetchCratesLatest(context.Background(), "crate-one"); got != "1.2.3" {
		t.Fatalf("fetchCratesLatest(first) = %q", got)
	}
	if got := fetchCratesLatest(context.Background(), "crate-two"); got != "1.2.3" {
		t.Fatalf("fetchCratesLatest(second) = %q", got)
	}
	if len(slept) != 1 || slept[0] != time.Second {
		t.Fatalf("crates.io throttle sleeps = %v, want one 1s sleep before second request", slept)
	}
	for _, ua := range userAgents {
		if !strings.Contains(ua, "packmon/") || !strings.Contains(ua, "github.com/8linkz-sec/packmon") {
			t.Fatalf("crates.io User-Agent = %q, want identifiable Packmon UA", ua)
		}
	}
}

func TestResolveLatestWithWorkerPoolDoesNotSpawnPerItemGoroutine(t *testing.T) {
	items := make([]int, maxConcurrentRegistryRequests*8)
	for i := range items {
		items[i] = i
	}
	started := make(chan struct{}, len(items))
	release := make(chan struct{})
	done := make(chan []packageLatestStatus, 1)

	before := runtime.NumGoroutine()
	go func() {
		done <- resolveLatestWithWorkerPool(context.Background(), items, func(context.Context, int) packageLatestStatus {
			started <- struct{}{}
			<-release
			return packageLatestStatus{Latest: "1.0.0", Update: "-"}
		})
	}()

	for i := 0; i < maxConcurrentRegistryRequests; i++ {
		<-started
	}
	time.Sleep(25 * time.Millisecond)
	during := runtime.NumGoroutine()
	close(release)
	results := <-done

	if len(results) != len(items) {
		t.Fatalf("results = %d, want %d", len(results), len(items))
	}
	if extra := during - before; extra > maxConcurrentRegistryRequests+8 {
		t.Fatalf("worker pool spawned %d extra goroutines for %d items; want bounded workers", extra, len(items))
	}
}

func TestLatestVersionResolversSkipPrivateSourceRefs(t *testing.T) {
	var called atomic.Bool
	lookup := directPackageUpdateLookupWithResolver(packageUpdateResolver{
		fetchLatest: func(context.Context, domain.Ecosystem, string) string {
			called.Store(true)
			return "9.9.9"
		},
	})

	cases := []struct {
		name      string
		ecosystem domain.Ecosystem
		sourceRef string
	}{
		{"npm", domain.EcosystemNPM, "https://npm.internal.example/@acme/private/-/private-1.0.0.tgz"},
		{"pypi", domain.EcosystemPyPI, "https://pypi.internal.example/simple"},
		{"cargo", domain.EcosystemCargo, "registry+https://cargo.internal.example/index"},
		{"gem", domain.EcosystemGem, "https://gems.internal.example/"},
		{"cocoapods", domain.EcosystemCocoaPods, "https://pods.internal.example/specs.git"},
		{"composer", domain.EcosystemComposer, "https://composer.internal.example/dist/acme/payroll-sdk.zip"},
		{"cran", domain.EcosystemCRAN, "source=GitHub"},
		{"pub", domain.EcosystemPub, "url=https://pub.internal.example"},
		{"maven", domain.EcosystemMaven, "https://maven.internal.example/repository/releases"},
	}

	for _, tt := range cases {
		t.Run("list-all "+tt.name, func(t *testing.T) {
			called.Store(false)
			status := resolveListAllLatestWithLookup(context.Background(), listAllPackage{
				Name:       "private",
				Version:    "1.0.0",
				Ecosystem:  tt.ecosystem,
				SourceRefs: []string{tt.sourceRef},
			}, lookup, nil)
			if !status.Unknown || status.Latest != "unknown" || status.Update != "-" {
				t.Fatalf("private source status = %+v, want unknown", status)
			}
			if called.Load() {
				t.Fatal("private source triggered a public latest-version lookup")
			}
		})
		t.Run("outdated "+tt.name, func(t *testing.T) {
			called.Store(false)
			status := resolveOutdatedLatestWithLookup(context.Background(), outdatedPackage{
				Name:       "private",
				Version:    "1.0.0",
				Ecosystem:  tt.ecosystem,
				SourceRefs: []string{tt.sourceRef},
			}, lookup)
			if !status.Unknown || status.Latest != "unknown" || status.Update != "-" {
				t.Fatalf("private source status = %+v, want unknown", status)
			}
			if called.Load() {
				t.Fatal("private source triggered a public latest-version lookup")
			}
		})
	}
}

func TestRunOutdatedSkipsPrivatePackageLockRegistrySource(t *testing.T) {
	var called atomic.Bool
	resolver := packageUpdateResolver{
		fetchLatest: func(context.Context, domain.Ecosystem, string) string {
			called.Store(true)
			return "9.9.9"
		},
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": {"version": "1.0.0"},
    "node_modules/@acme/payroll-sdk": {
      "version": "1.0.0",
      "resolved": "https://npm.internal.example/@acme/payroll-sdk/-/payroll-sdk-1.0.0.tgz"
    }
  }
}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	captureStdout(t, func() {
		if err := runOutdatedWithOptions([]string{dir}, outdatedOptions{Ecosystems: "npm", MaxDepth: 2, IncludeDev: true, resolver: resolver}); err != nil {
			t.Fatalf("run outdated: %v", err)
		}
	})

	if called.Load() {
		t.Fatal("private package-lock source triggered public latest-version lookup")
	}
}

func TestRunOutdatedWithOptionsSkipsLookupsAfterCallerCancel(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"": {"version": "1.0.0"},
			"node_modules/outdated": {"version": "1.0.0"}
		}
	}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var called atomic.Bool
	resolver := packageUpdateResolver{
		fetchLatest: func(context.Context, domain.Ecosystem, string) string {
			called.Store(true)
			return ""
		},
	}

	err := runOutdatedWithOptions([]string{dir}, outdatedOptions{
		Context:    ctx,
		Ecosystems: "npm",
		MaxDepth:   2,
		IncludeDev: true,
		OutputHTML: filepath.Join(t.TempDir(), "outdated.html"),
		Quiet:      true,
		resolver:   resolver,
		Timeout:    1,
	})
	if err != nil {
		t.Fatalf("runOutdatedWithOptions: %v", err)
	}
	if called.Load() {
		t.Fatal("outdated latest-version lookup ran after caller context was canceled")
	}
}

func TestRunOutdatedWithOptionsUsesConfiguredLookupTimeout(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"": {"version": "1.0.0"},
			"node_modules/outdated": {"version": "1.0.0"}
		}
	}`)

	var sawDeadline atomic.Bool
	resolver := packageUpdateResolver{
		fetchLatest: func(ctx context.Context, _ domain.Ecosystem, _ string) string {
			if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= 2*time.Second {
				sawDeadline.Store(true)
			}
			return "2.0.0"
		},
	}

	err := runOutdatedWithOptions([]string{dir}, outdatedOptions{
		Context:    context.Background(),
		Ecosystems: "npm",
		MaxDepth:   2,
		IncludeDev: true,
		OutputHTML: filepath.Join(t.TempDir(), "outdated.html"),
		Quiet:      true,
		resolver:   resolver,
		Timeout:    1,
	})
	if err != nil {
		t.Fatalf("runOutdatedWithOptions: %v", err)
	}
	if !sawDeadline.Load() {
		t.Fatal("outdated latest-version lookup did not receive configured lookup deadline")
	}
}

func TestRunOutdatedCachesLatestVersionLookups(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "bom.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{
		"bomFormat":"CycloneDX",
		"components":[
			{"type":"library","name":"dupe","version":"2.0.0","purl":"pkg:npm/dupe@2.0.0"},
			{"type":"library","name":"dupe","version":"1.0.0","purl":"pkg:npm/dupe@1.0.0"}
		]
	}`), 0o600); err != nil {
		t.Fatalf("write SBOM: %v", err)
	}

	var calls atomic.Int32
	resolver := packageUpdateResolver{
		fetchLatest: func(_ context.Context, eco domain.Ecosystem, name string) string {
			if eco != domain.EcosystemNPM || name != "dupe" {
				t.Fatalf("fetchLatest(%s, %q)", eco, name)
			}
			calls.Add(1)
			return "2.0.0"
		},
	}

	output := captureStdout(t, func() {
		if err := runOutdatedWithOptions([]string{dir}, outdatedOptions{Ecosystems: "npm", MaxDepth: 2, IncludeDev: true, SBOMFiles: []string{sbomPath}, resolver: resolver}); err != nil {
			t.Fatalf("runOutdated: %v", err)
		}
	})
	if !strings.Contains(output, "1 outdated, 1 up to date (2 total)") {
		t.Fatalf("runOutdated output = %q, want duplicate versions counted", output)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("latest-version lookups = %d, want 1 cached lookup", got)
	}
}

func TestRunOutdatedQuietWithoutHTMLSkipsRegistryLookups(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"": {"version": "1.0.0"},
			"node_modules/outdated": {"version": "1.0.0"}
		}
	}`)

	var called atomic.Bool
	resolver := packageUpdateResolver{
		fetchLatest: func(context.Context, domain.Ecosystem, string) string {
			called.Store(true)
			return "2.0.0"
		},
	}

	if err := runOutdatedWithOptions([]string{dir}, outdatedOptions{Ecosystems: "npm", MaxDepth: 2, IncludeDev: true, Quiet: true, resolver: resolver}); err != nil {
		t.Fatalf("runOutdatedWithOptions: %v", err)
	}
	if called.Load() {
		t.Fatal("quiet outdated run without HTML performed a registry lookup")
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
		if err := runOutdatedForTest([]string{t.TempDir()}, "", 2); err != nil {
			t.Fatalf("run outdated: %v", err)
		}
	})
	if !strings.Contains(output, "No lock files found.") {
		t.Fatalf("run outdated output = %q", output)
	}
}

func runOutdatedForTest(args []string, ecosystems string, maxDepth int, sbomFilesOpt ...[]string) error {
	var sbomFiles []string
	if len(sbomFilesOpt) > 0 {
		sbomFiles = sbomFilesOpt[0]
	}
	return runOutdatedWithOptions(args, outdatedOptions{
		Ecosystems: ecosystems,
		MaxDepth:   maxDepth,
		IncludeDev: true,
		SBOMFiles:  sbomFiles,
	})
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
		if err := runOutdatedForTest([]string{dir}, "npm", 2); err != nil {
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

func TestPrintOutdatedReportSanitizesTerminalControlText(t *testing.T) {
	report := outdatedReport{
		Total: 1,
		Outdated: []outdatedRow{{
			Name:      "pkg\x1b]8;;https://evil.example\a\n::warning::pkg",
			Installed: "1.0.0\rspoof",
			Latest:    "2.0.0\tmasked",
			Ecosystem: "npm",
			Scope:     "runtime",
			Relation:  "direct",
			Via:       "parent\x1b[31m",
			Flags:     "optional\n::error::flag",
			LockFile:  "package-lock.json\x1b[0m",
		}},
	}

	output := captureStdout(t, func() {
		printOutdatedReport(report)
	})

	for _, blocked := range []string{"\x1b", "\a", "\r", "\t", "\n::warning::", "\n::error::"} {
		if strings.Contains(output, blocked) {
			t.Fatalf("outdated output contains raw terminal control %q:\n%s", blocked, output)
		}
	}
	for _, want := range []string{`\x1B`, `\n::warning::pkg`, `\rspoof`, `\tmasked`, `\n::error::flag`} {
		if !strings.Contains(output, want) {
			t.Fatalf("outdated output missing sanitized text %q:\n%s", want, output)
		}
	}
}

func TestPrintOutdatedReportUnknownOnlyDoesNotClaimUpToDate(t *testing.T) {
	report := outdatedReport{Total: 2, Unknown: 2, PackageWord: "packages"}

	output := captureStdout(t, func() {
		printOutdatedReport(report)
	})

	if strings.Contains(output, "All 0 packages are up to date") {
		t.Fatalf("unknown-only report claimed all-clear:\n%s", output)
	}
	if !strings.Contains(output, "latest status is unknown for 2 packages") {
		t.Fatalf("unknown-only report missing unknown empty state:\n%s", output)
	}
}

func TestOutdatedHTMLUnknownOnlyDoesNotRenderAllClear(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	report := outdatedReport{Total: 2, Unknown: 2, PackageWord: "packages"}

	if err := writeOutdatedHTML(htmlPath, report); err != nil {
		t.Fatalf("write outdated HTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read outdated HTML: %v", err)
	}
	html := string(data)
	if strings.Contains(html, "All 0 packages are up to date") {
		t.Fatalf("unknown-only HTML claimed all-clear:\n%s", html)
	}
	if !strings.Contains(html, "latest status is unknown for 2 packages") {
		t.Fatalf("unknown-only HTML missing unknown empty state:\n%s", html)
	}
}

func TestOutdatedHTMLIncludesResponsivePrintAndLightThemePolicy(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	report := outdatedReport{
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      "github.com/acme/" + strings.Repeat("very-long-module-name-", 6),
			Installed: strings.Repeat("abcdef0123456789", 4),
			Latest:    strings.Repeat("fedcba9876543210", 4),
			Ecosystem: string(domain.EcosystemGo),
			Scope:     "runtime",
			Relation:  "direct",
			LockFile:  "go.sum",
		}},
	}

	if err := writeOutdatedHTML(htmlPath, report); err != nil {
		t.Fatalf("write outdated HTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read outdated HTML: %v", err)
	}
	html := string(data)
	for _, want := range []string{
		"--success:",
		"--warning:",
		"--warning-bg:",
		"background:var(--warning-bg)",
		"overflow-wrap:anywhere",
		"word-break:break-word",
		"@media (prefers-color-scheme: light)",
		"@media print",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("outdated HTML CSS missing %q:\n%s", want, html)
		}
	}
	if strings.Contains(html, "background:#2d1f0f") {
		t.Fatalf("outdated HTML CSS still hard-codes the unknown empty-state background:\n%s", html)
	}
}

func TestOutdatedHTMLMinimizesAbsoluteReportPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "student-123", "course-assignment")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	lockPath := filepath.Join(root, "package-lock.json")
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	report := outdatedReport{
		Target:      root,
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      "left-pad",
			Installed: "1.0.0",
			Latest:    "1.3.0",
			Ecosystem: string(domain.EcosystemNPM),
			Scope:     "runtime",
			Relation:  "direct",
			LockFile:  lockPath,
		}},
		LockFiles: 1,
	}

	if err := writeOutdatedHTML(htmlPath, report); err != nil {
		t.Fatalf("write outdated HTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read outdated HTML: %v", err)
	}
	html := string(data)
	for _, leaked := range []string{
		root,
		filepath.ToSlash(root),
		filepath.Dir(root),
		filepath.ToSlash(filepath.Dir(root)),
		lockPath,
		filepath.ToSlash(lockPath),
		"student-123",
	} {
		if strings.Contains(html, leaked) {
			t.Fatalf("outdated HTML leaked local path fragment %q:\n%s", leaked, html)
		}
	}
	for _, want := range []string{
		"course-assignment",
		`<td class="lockfile">package-lock.json</td>`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("outdated HTML missing minimized path %q:\n%s", want, html)
		}
	}
}

func TestOutdatedHTMLTableScrollRegionIsKeyboardFocusable(t *testing.T) {
	for _, want := range []string{
		".table-scroll:focus{",
		`<div class="table-scroll" tabindex="0" role="region" aria-label="Outdated packages table">`,
	} {
		if !strings.Contains(outdatedHTML, want) {
			t.Fatalf("outdated HTML template missing keyboard-scroll contract %q", want)
		}
	}
}

func TestScanCommandOutdatedHTMLFlagWritesReport(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
	cmd.SetContext(ctx)
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
		".version{min-width:260px;overflow-wrap:anywhere;word-break:break-word;}",
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
	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		cmd.SetContext(ctx)
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
	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		cmd.SetContext(ctx)
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
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		if err := runOutdatedWithOptions([]string{dir}, outdatedOptions{Ecosystems: "go", MaxDepth: 2, IncludeDev: true, resolver: resolver}); err != nil {
			t.Fatalf("run outdated: %v", err)
		}
	})

	if strings.Contains(output, "github.com/davecgh/go-spew") {
		t.Fatalf("newer Go pseudo-version should not be reported as outdated:\n%s", output)
	}
	if !strings.Contains(output, "All 1 package is up to date.") {
		t.Fatalf("run outdated output = %q, want up-to-date summary", output)
	}
}

func TestRunOutdatedReportsNoPackagesAfterParseErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`not json`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runOutdatedForTest([]string{dir}, "npm", 2); err != nil {
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

	err := runOutdatedForTest([]string{dir}, "", 2, []string{badPath})
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
