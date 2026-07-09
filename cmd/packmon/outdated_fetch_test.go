package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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
		"registry.npmjs.org/pkg/latest":                                          `{"version":"1.2.3"}`,
		"pypi.org/pypi/pkg/json":                                                 `{"info":{"version":"2.3.4"}}`,
		"proxy.golang.org/github.com/acme/lib/@latest":                           `{"Version":"v1.2.0"}`,
		"proxy.golang.org/github.com/!burnt!sushi/toml/@latest":                  `{"Version":"v1.6.0"}`,
		"crates.io/api/v1/crates/pkg":                                            `{"crate":{"max_stable_version":"3.4.5"}}`,
		"api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json":              `{"versions":["12.0.1","13.0.3","13.0.2"]}`,
		"rubygems.org/api/v1/gems/pkg.json":                                      `{"version":"4.5.6"}`,
		"repo.packagist.org/p2/vendor/package.json":                              `{"packages":{"vendor/package":[{"version":"dev-main"},{"version":"5.6.7"}]}}`,
		"repo.maven.apache.org/maven2/com/google/guava/guava/maven-metadata.xml": `<metadata><versioning><release>33.4.8-jre</release><latest>34.0.0-SNAPSHOT</latest></versioning></metadata>`,
		"pub.dev/api/packages/http":                                              `{"latest":{"version":"1.5.0"}}`,
		"hex.pm/api/packages/jason":                                              `{"latest_version":"1.5.0-alpha.2","latest_stable_version":"1.4.5"}`,
		"cran.r-project.org/web/packages/dplyr/DESCRIPTION":                      "Package: dplyr\nVersion: 1.1.4\n",
		"trunk.cocoapods.org/api/v1/pods/Alamofire/specs/latest":                 `{"name":"Alamofire","version":"5.11.2"}`,
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

func TestSelectNPMWantedVersionUsesCompiledParentRanges(t *testing.T) {
	versions := map[string]npmVersionManifest{
		"1.0.0": {},
		"1.4.0": {},
		"1.8.0": {},
		"2.0.0": {},
	}

	if got := selectNPMWantedVersion(versions, []string{">=1.2.0 <2.0.0", "^1.3.0"}); got != "1.8.0" {
		t.Fatalf("selectNPMWantedVersion() = %q, want 1.8.0", got)
	}
	if got := selectNPMWantedVersion(versions, []string{"not a valid range ("}); got != "" {
		t.Fatalf("selectNPMWantedVersion(invalid range) = %q, want empty fallback marker", got)
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

func TestRegistryGetLimitedRejectsOversizedValidJSONPrefix(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	validPrefix := `{"version":"1.2.3"}`
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(validPrefix + "x")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	data, err := registryGetLimitedWithHeaders(context.Background(), "https://registry.example/pkg", int64(len(validPrefix)), nil)
	if err == nil {
		t.Fatalf("registryGetLimitedWithHeaders() accepted oversized response as %q", string(data))
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("registryGetLimitedWithHeaders() error = %v, want exceeds limit", err)
	}
}

func TestLatestRegistryLookupsEscapePackageNames(t *testing.T) {
	originalClient := registryClient
	originalThrottle := cratesIOThrottle
	t.Cleanup(func() {
		registryClient = originalClient
		cratesIOThrottle = originalThrottle
	})
	cratesIOThrottle = &registryThrottle{}

	responses := map[string]string{
		"registry.npmjs.org/@scope%2Fpkg/latest":                                          `{"version":"1.2.3"}`,
		"registry.npmjs.org/pkg%3Fx%23frag/latest":                                        `{"version":"1.2.3"}`,
		"registry.npmjs.org/@scope%2Fpkg%3Fx%23frag":                                      `{"versions":{"1.2.3":{"version":"1.2.3"}}}`,
		"pypi.org/pypi/pkg%20name%3Fx%23frag/json":                                        `{"info":{"version":"2.3.4"}}`,
		"crates.io/api/v1/crates/crate%2Fname%3Fx%23frag":                                 `{"crate":{"max_stable_version":"3.4.5"}}`,
		"rubygems.org/api/v1/gems/gem%20name%3Fx%23frag.json":                             `{"version":"4.5.6"}`,
		"repo.packagist.org/p2/vendor/package%20name%3Fx%23frag.json":                     `{"packages":{"vendor/package name?x#frag":[{"version":"5.6.7"}]}}`,
		"repo.maven.apache.org/maven2/com/example%3Fx/artifact%23frag/maven-metadata.xml": `<metadata><versioning><release>6.7.8</release></versioning></metadata>`,
	}
	var requests []string
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		key := req.URL.Host + req.URL.EscapedPath()
		if req.URL.RawQuery != "" {
			key += "?" + req.URL.RawQuery
		}
		requests = append(requests, key)
		body, ok := responses[key]
		if !ok {
			return &http.Response{
				StatusCode: http.StatusNotFound,
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

	cases := []struct {
		name    string
		wantKey string
		want    string
		call    func(context.Context) string
	}{
		{
			name:    "npm scoped package",
			wantKey: "registry.npmjs.org/@scope%2Fpkg/latest",
			want:    "1.2.3",
			call: func(ctx context.Context) string {
				return fetchNPMLatest(ctx, "@scope/pkg")
			},
		},
		{
			name:    "npm query and fragment",
			wantKey: "registry.npmjs.org/pkg%3Fx%23frag/latest",
			want:    "1.2.3",
			call: func(ctx context.Context) string {
				return fetchNPMLatest(ctx, "pkg?x#frag")
			},
		},
		{
			name:    "npm metadata scoped query and fragment",
			wantKey: "registry.npmjs.org/@scope%2Fpkg%3Fx%23frag",
			want:    "ok",
			call: func(ctx context.Context) string {
				if _, ok := fetchNPMMetadata(ctx, "@scope/pkg?x#frag"); ok {
					return "ok"
				}
				return ""
			},
		},
		{
			name:    "pypi spaces query and fragment",
			wantKey: "pypi.org/pypi/pkg%20name%3Fx%23frag/json",
			want:    "2.3.4",
			call: func(ctx context.Context) string {
				return fetchPyPILatest(ctx, "pkg name?x#frag")
			},
		},
		{
			name:    "crates slash query and fragment",
			wantKey: "crates.io/api/v1/crates/crate%2Fname%3Fx%23frag",
			want:    "3.4.5",
			call: func(ctx context.Context) string {
				return fetchCratesLatest(ctx, "crate/name?x#frag")
			},
		},
		{
			name:    "rubygems spaces query and fragment",
			wantKey: "rubygems.org/api/v1/gems/gem%20name%3Fx%23frag.json",
			want:    "4.5.6",
			call: func(ctx context.Context) string {
				return fetchRubyGemsLatest(ctx, "gem name?x#frag")
			},
		},
		{
			name:    "packagist package component spaces query and fragment",
			wantKey: "repo.packagist.org/p2/vendor/package%20name%3Fx%23frag.json",
			want:    "5.6.7",
			call: func(ctx context.Context) string {
				return fetchPackagistLatest(ctx, "vendor/package name?x#frag")
			},
		},
		{
			name:    "maven path components",
			wantKey: "repo.maven.apache.org/maven2/com/example%3Fx/artifact%23frag/maven-metadata.xml",
			want:    "6.7.8",
			call: func(ctx context.Context) string {
				return fetchMavenLatest(ctx, "com.example?x:artifact#frag")
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			requests = requests[:0]
			if got := tt.call(context.Background()); got != tt.want {
				t.Fatalf("latest = %q, want %q; requests = %v", got, tt.want, requests)
			}
			if len(requests) != 1 || requests[0] != tt.wantKey {
				t.Fatalf("requests = %v, want [%s]", requests, tt.wantKey)
			}
		})
	}

	t.Run("packagist rejects extra path components", func(t *testing.T) {
		requests = requests[:0]
		if got := fetchPackagistLatest(context.Background(), "vendor/package/extra"); got != "" {
			t.Fatalf("fetchPackagistLatest(extra slash) = %q, want empty", got)
		}
		if len(requests) != 0 {
			t.Fatalf("extra path components triggered requests = %v", requests)
		}
	})

	t.Run("git remotes reject query and fragment", func(t *testing.T) {
		var remotes []string
		resolver := packageUpdateResolver{
			gitRemoteTags: func(_ context.Context, remote string) ([]string, error) {
				remotes = append(remotes, remote)
				return []string{"v1.2.3"}, nil
			},
		}
		if got := resolver.latestVersion(context.Background(), domain.EcosystemGitHubActions, "actions/checkout"); got != "v1.2.3" {
			t.Fatalf("GitHub Actions latest = %q, want v1.2.3", got)
		}
		if got := resolver.latestVersion(context.Background(), domain.EcosystemSwiftPM, "github.com/acme/lib"); got != "v1.2.3" {
			t.Fatalf("SwiftPM latest = %q, want v1.2.3", got)
		}
		if got := resolver.latestVersion(context.Background(), domain.EcosystemGitHubActions, "actions/checkout?x#frag"); got != "" {
			t.Fatalf("GitHub Actions dangerous latest = %q, want empty", got)
		}
		if got := resolver.latestVersion(context.Background(), domain.EcosystemSwiftPM, "github.com/acme/lib?x#frag"); got != "" {
			t.Fatalf("SwiftPM dangerous latest = %q, want empty", got)
		}
		wantRemotes := []string{
			"https://github.com/actions/checkout.git",
			"https://github.com/acme/lib.git",
		}
		if strings.Join(remotes, "\n") != strings.Join(wantRemotes, "\n") {
			t.Fatalf("git remotes = %v, want %v", remotes, wantRemotes)
		}
	})
}

func TestFetchPackagistLatestHandlesLargePublicMetadata(t *testing.T) {
	stubPackagistLatestResponse(t, "laravel/framework", largePackagistMetadata("laravel/framework", "v13.17.0", maxRegistryResponseSize))

	if got := fetchPackagistLatest(context.Background(), "laravel/framework"); got != "v13.17.0" {
		t.Fatalf("fetchPackagistLatest(large metadata) = %q, want v13.17.0", got)
	}
}

func TestListAllReportUsesLargePackagistMetadata(t *testing.T) {
	stubPackagistLatestResponse(t, "laravel/framework", largePackagistMetadata("laravel/framework", "v13.17.0", maxRegistryResponseSize))

	report := buildListAllPackageReportWithOptions(context.Background(), []listAllPackage{{
		Name:       "laravel/framework",
		Version:    "v10.48.0",
		Ecosystem:  domain.EcosystemComposer,
		LockFile:   "composer.lock",
		SourceRefs: []string{"https://github.com/laravel/framework.git", "https://api.github.com/repos/laravel/framework/zipball/v10.48.0"},
	}}, nil, "repo", 30, listAllPackageReportOptions{})

	if len(report.Rows) != 1 {
		t.Fatalf("Rows = %d, want 1", len(report.Rows))
	}
	if got := report.Rows[0].Latest; got != "v13.17.0" {
		t.Fatalf("list-all Latest = %q, want v13.17.0", got)
	}
	if got := report.Rows[0].Update; got != "yes" {
		t.Fatalf("list-all Update = %q, want yes", got)
	}
	if report.Unknown != 0 {
		t.Fatalf("Unknown = %d, want 0", report.Unknown)
	}
}

func TestOutdatedReportUsesLargePackagistMetadata(t *testing.T) {
	stubPackagistLatestResponse(t, "laravel/framework", largePackagistMetadata("laravel/framework", "v13.17.0", maxRegistryResponseSize))

	dir := t.TempDir()
	composerLock := `{
  "packages": [
    {
      "name": "laravel/framework",
      "version": "v10.48.0",
      "source": {"type": "git", "url": "https://github.com/laravel/framework.git"},
      "dist": {"type": "zip", "url": "https://api.github.com/repos/laravel/framework/zipball/v10.48.0"}
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(composerLock), 0o600); err != nil {
		t.Fatalf("write composer.lock: %v", err)
	}
	htmlPath := filepath.Join(dir, "outdated.html")
	if err := runOutdatedWithOptions([]string{dir}, outdatedOptions{
		Context:    context.Background(),
		MaxDepth:   10,
		OutputHTML: htmlPath,
		Quiet:      true,
	}); err != nil {
		t.Fatalf("runOutdatedWithOptions() error = %v", err)
	}

	html, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report from t.TempDir().
	if err != nil {
		t.Fatalf("read outdated HTML: %v", err)
	}
	for _, want := range []string{"laravel/framework", "v10.48.0", "v13.17.0"} {
		if !strings.Contains(string(html), want) {
			t.Fatalf("outdated HTML missing %q:\n%s", want, string(html))
		}
	}
}

func TestFetchPackagistLatestKeepsVeryLargeMetadataBounded(t *testing.T) {
	stubPackagistLatestResponse(t, "laravel/framework", largePackagistMetadata("laravel/framework", "v13.17.0", maxPackagistRegistryResponseSize))

	if got := fetchPackagistLatest(context.Background(), "laravel/framework"); got != "" {
		t.Fatalf("fetchPackagistLatest(oversized metadata) = %q, want empty", got)
	}
}

func largePackagistMetadata(name, latest string, fillerBytes int) string {
	return `{"packages":{"` + name + `":[{"version":"` + latest + `"},{"version":"` + strings.Repeat("x", fillerBytes) + `"}]}}`
}

func stubPackagistLatestResponse(t *testing.T, name, body string) {
	t.Helper()
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	wantURL := "https://repo.packagist.org/p2/" + name + ".json"
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != wantURL {
			t.Fatalf("unexpected registry request: %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}
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
	var active atomic.Int32
	var maxActive atomic.Int32

	done := make(chan []packageLatestStatus, 1)
	go func() {
		done <- resolveLatestWithWorkerPool(context.Background(), items, func(context.Context, int) packageLatestStatus {
			current := active.Add(1)
			for {
				previous := maxActive.Load()
				if current <= previous || maxActive.CompareAndSwap(previous, current) {
					break
				}
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
			return packageLatestStatus{Latest: "1.0.0", Update: "-"}
		})
	}()

	for i := 0; i < maxConcurrentRegistryRequests; i++ {
		<-started
	}
	close(release)
	results := <-done

	if len(results) != len(items) {
		t.Fatalf("results = %d, want %d", len(results), len(items))
	}
	if got := latestLookupWorkerCount(len(items)); got != maxConcurrentRegistryRequests {
		t.Fatalf("latestLookupWorkerCount(%d) = %d, want %d", len(items), got, maxConcurrentRegistryRequests)
	}
	if got := int(maxActive.Load()); got != maxConcurrentRegistryRequests {
		t.Fatalf("max concurrent resolver calls = %d, want %d", got, maxConcurrentRegistryRequests)
	}
}

func TestResolveLatestWithWorkerPoolContainsResolverPanicPerJob(t *testing.T) {
	items := make([]int, maxConcurrentRegistryRequests+3)
	for i := range items {
		items[i] = i
	}

	done := make(chan []packageLatestStatus, 1)
	go func() {
		done <- resolveLatestWithWorkerPool(context.Background(), items, func(_ context.Context, item int) packageLatestStatus {
			if item < maxConcurrentRegistryRequests {
				panic("latest resolver panic")
			}
			return packageLatestStatus{Latest: "1.0.0", Update: "-"}
		})
	}()

	var results []packageLatestStatus
	select {
	case results = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker pool did not continue after resolver panics")
	}
	if len(results) != len(items) {
		t.Fatalf("results = %d, want %d", len(results), len(items))
	}
	for i := 0; i < maxConcurrentRegistryRequests; i++ {
		if got := results[i]; !got.Unknown || got.Latest != "unknown" || got.Update != "-" {
			t.Fatalf("panicked job result[%d] = %+v, want unknown latest status", i, got)
		}
	}
	for i := maxConcurrentRegistryRequests; i < len(results); i++ {
		if got := results[i]; got.Unknown || got.Latest != "1.0.0" || got.Update != "-" {
			t.Fatalf("non-panicked job result[%d] = %+v, want resolved latest status", i, got)
		}
	}
}

func TestDefaultRegistryHTTPClientRetainsIdleConnectionsForLookupWorkers(t *testing.T) {
	client := newRegistryHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("registry client transport = %T, want *http.Transport", client.Transport)
	}
	if transport.MaxIdleConnsPerHost < maxConcurrentRegistryRequests {
		t.Fatalf("MaxIdleConnsPerHost = %d, want at least %d", transport.MaxIdleConnsPerHost, maxConcurrentRegistryRequests)
	}
	if transport.MaxIdleConns < maxConcurrentRegistryRequests {
		t.Fatalf("MaxIdleConns = %d, want at least %d", transport.MaxIdleConns, maxConcurrentRegistryRequests)
	}
}

func TestCRANPublicLatestLookupAllowlist(t *testing.T) {
	cases := []struct {
		name string
		refs []string
		want bool
	}{
		{
			name: "public cran repository",
			refs: []string{"source=repository", "repository=cran"},
			want: true,
		},
		{
			name: "private github source",
			refs: []string{"source=GitHub", "repository=cran"},
		},
		{
			name: "private repository",
			refs: []string{"source=repository", "repository=internal"},
		},
		{
			name: "missing source",
			refs: []string{"repository=cran"},
		},
		{
			name: "missing repository",
			refs: []string{"source=repository"},
		},
		{
			name: "malformed source ref",
			refs: []string{"source repository", "repository=cran"},
		},
		{
			name: "unexpected source ref key",
			refs: []string{"source=repository", "url=https://cran.internal.example"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := publicLatestLookupAllowed(domain.EcosystemCRAN, tt.refs); got != tt.want {
				t.Fatalf("publicLatestLookupAllowed(CRAN, %v) = %v, want %v", tt.refs, got, tt.want)
			}
		})
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
		{"hex", domain.EcosystemHex, "repo=internal_hex"},
		{"nuget", domain.EcosystemNuGet, "https://nuget.internal.example/v3/index.json"},
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

func TestLatestVersionResolversSkipUnknownHexAndNuGetWithoutMirror(t *testing.T) {
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
	}{
		{"hex", domain.EcosystemHex},
		{"nuget", domain.EcosystemNuGet},
	}

	for _, tt := range cases {
		t.Run("list-all "+tt.name, func(t *testing.T) {
			called.Store(false)
			status := resolveListAllLatestWithLookup(context.Background(), listAllPackage{
				Name:      "private",
				Version:   "1.0.0",
				Ecosystem: tt.ecosystem,
			}, lookup, nil)
			if !status.Unknown || status.Latest != "unknown" || status.Update != "-" {
				t.Fatalf("unknown source status = %+v, want unknown", status)
			}
			if called.Load() {
				t.Fatal("unknown Hex/NuGet source triggered a public latest-version lookup")
			}
		})
		t.Run("outdated "+tt.name, func(t *testing.T) {
			called.Store(false)
			status := resolveOutdatedLatestWithLookup(context.Background(), outdatedPackage{
				Name:      "private",
				Version:   "1.0.0",
				Ecosystem: tt.ecosystem,
			}, lookup)
			if !status.Unknown || status.Latest != "unknown" || status.Update != "-" {
				t.Fatalf("unknown source status = %+v, want unknown", status)
			}
			if called.Load() {
				t.Fatal("unknown Hex/NuGet source triggered a public latest-version lookup")
			}
		})
	}
}

func TestConfiguredLatestRegistryMirrorsUseBaseURLs(t *testing.T) {
	originalClient := registryClient
	originalThrottle := cratesIOThrottle
	t.Cleanup(func() {
		registryClient = originalClient
		cratesIOThrottle = originalThrottle
	})
	cratesIOThrottle = &registryThrottle{}

	responses := map[string]string{
		"npm-mirror.example/registry/left-pad/latest":                                  `{"version":"1.3.0"}`,
		"npm-mirror.example/registry/left-pad":                                         `{"versions":{"1.3.0":{"version":"1.3.0"}}}`,
		"pypi-mirror.example/pypi/requests/json":                                       `{"info":{"version":"2.31.0"}}`,
		"rubygems-mirror.example/api/v1/gems/rails.json":                               `{"version":"7.2.2"}`,
		"cargo-mirror.example/api/v1/crates/serde":                                     `{"crate":{"max_stable_version":"1.0.203"}}`,
		"cocoapods-mirror.example/api/v1/pods/Alamofire/specs/latest":                  `{"name":"Alamofire","version":"5.11.2"}`,
		"composer-mirror.example/p2/laravel/framework.json":                            `{"packages":{"laravel/framework":[{"version":"11.0.0"}]}}`,
		"go-proxy.example/github.com/acme/lib/@latest":                                 `{"Version":"v1.2.3"}`,
		"maven-mirror.example/repository/maven-public/com/acme/sdk/maven-metadata.xml": `<metadata><versioning><latest>3.4.5</latest></versioning></metadata>`,
		"cran-mirror.example/web/packages/dplyr/DESCRIPTION":                           "Package: dplyr\nVersion: 1.1.4\n",
		"pub-mirror.example/api/packages/http":                                         `{"latest":{"version":"1.5.0"}}`,
		"hex-mirror.example/api/packages/jason":                                        `{"latest_version":"1.5.0-alpha.2","latest_stable_version":"1.4.5"}`,
		"nuget-mirror.example/v3-flatcontainer/newtonsoft.json/index.json":             `{"versions":["12.0.1","13.0.3","13.0.2"]}`,
	}
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		key := req.URL.Host + req.URL.EscapedPath()
		body, ok := responses[key]
		if !ok {
			t.Fatalf("unexpected registry request: %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	resolver := packageUpdateResolver{latestRegistry: latestRegistryConfig{
		NPMRegistryBaseURL:                  "https://npm-mirror.example/registry/",
		NPMRegistryBaseURLConfigured:        true,
		PyPIAPIBaseURL:                      "https://pypi-mirror.example/pypi/",
		PyPIAPIBaseURLConfigured:            true,
		RubyGemsAPIBaseURL:                  "https://rubygems-mirror.example/api/v1/gems/",
		RubyGemsAPIBaseURLConfigured:        true,
		CargoRegistryAPIBaseURL:             "https://cargo-mirror.example/api/v1/crates/",
		CargoRegistryAPIBaseURLConfigured:   true,
		CocoaPodsTrunkAPIBaseURL:            "https://cocoapods-mirror.example/api/v1/pods/",
		CocoaPodsTrunkAPIBaseURLConfigured:  true,
		ComposerRepositoryBaseURL:           "https://composer-mirror.example/p2/",
		ComposerRepositoryBaseURLConfigured: true,
		GoModuleProxyURL:                    "https://go-proxy.example/",
		GoModuleProxyURLConfigured:          true,
		MavenRepositoryBaseURL:              "https://maven-mirror.example/repository/maven-public/",
		MavenRepositoryBaseURLConfigured:    true,
		CRANMirrorURL:                       "https://cran-mirror.example/",
		CRANMirrorURLConfigured:             true,
		PubHostedURL:                        "https://pub-mirror.example/",
		PubHostedURLConfigured:              true,
		HexAPIBaseURL:                       "https://hex-mirror.example/api/",
		HexAPIBaseURLConfigured:             true,
		NuGetV3BaseURL:                      "https://nuget-mirror.example/v3-flatcontainer/",
		NuGetV3BaseURLConfigured:            true,
	}}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemNPM, "left-pad"); got != "1.3.0" {
		t.Fatalf("npm mirror latest = %q, want 1.3.0", got)
	}
	if meta, ok := resolver.npmMetadata(context.Background(), "left-pad"); !ok || meta.Versions["1.3.0"].Version != "1.3.0" {
		t.Fatalf("npm mirror metadata = %+v, ok=%v; want mirrored metadata", meta, ok)
	}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemPyPI, "requests"); got != "2.31.0" {
		t.Fatalf("PyPI mirror latest = %q, want 2.31.0", got)
	}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemGem, "rails"); got != "7.2.2" {
		t.Fatalf("RubyGems mirror latest = %q, want 7.2.2", got)
	}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemCargo, "serde"); got != "1.0.203" {
		t.Fatalf("Cargo mirror latest = %q, want 1.0.203", got)
	}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemCocoaPods, "Alamofire"); got != "5.11.2" {
		t.Fatalf("CocoaPods mirror latest = %q, want 5.11.2", got)
	}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemComposer, "laravel/framework"); got != "11.0.0" {
		t.Fatalf("Composer mirror latest = %q, want 11.0.0", got)
	}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemGo, "github.com/acme/lib"); got != "v1.2.3" {
		t.Fatalf("Go mirror latest = %q, want v1.2.3", got)
	}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemMaven, "com.acme:sdk"); got != "3.4.5" {
		t.Fatalf("Maven mirror latest = %q, want 3.4.5", got)
	}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemCRAN, "dplyr"); got != "1.1.4" {
		t.Fatalf("CRAN mirror latest = %q, want 1.1.4", got)
	}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemPub, "http"); got != "1.5.0" {
		t.Fatalf("Pub mirror latest = %q, want 1.5.0", got)
	}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemHex, "jason"); got != "1.4.5" {
		t.Fatalf("Hex mirror latest = %q, want 1.4.5", got)
	}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemNuGet, "Newtonsoft.Json"); got != "13.0.3" {
		t.Fatalf("NuGet mirror latest = %q, want 13.0.3", got)
	}

	var called atomic.Bool
	lookup := directPackageUpdateLookupWithResolver(packageUpdateResolver{
		latestRegistry: resolver.latestRegistry,
		fetchLatest: func(context.Context, domain.Ecosystem, string) string {
			called.Store(true)
			return "2.0.0"
		},
	})
	for _, tt := range []struct {
		name      string
		ecosystem domain.Ecosystem
	}{
		{"npm", domain.EcosystemNPM},
		{"pypi", domain.EcosystemPyPI},
		{"rubygems", domain.EcosystemGem},
		{"cargo", domain.EcosystemCargo},
		{"cocoapods", domain.EcosystemCocoaPods},
		{"composer", domain.EcosystemComposer},
		{"go", domain.EcosystemGo},
		{"maven", domain.EcosystemMaven},
		{"cran", domain.EcosystemCRAN},
		{"pub", domain.EcosystemPub},
		{"hex", domain.EcosystemHex},
	} {
		t.Run("private source allowed with configured "+tt.name+" mirror", func(t *testing.T) {
			called.Store(false)
			status := resolveOutdatedLatestWithLookup(context.Background(), outdatedPackage{
				Name:       "private",
				Version:    "1.0.0",
				Ecosystem:  tt.ecosystem,
				SourceRefs: []string{"https://internal.example/private"},
			}, lookup)
			if status.Unknown || status.Latest != "2.0.0" {
				t.Fatalf("configured %s mirror status = %+v, want resolved mirror latest", tt.name, status)
			}
			if !called.Load() {
				t.Fatalf("configured %s mirror did not allow private-source latest lookup", tt.name)
			}
		})
	}
}

func TestGoModuleProxyOffSkipsLatestLookup(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("go proxy off still sent request: %s", req.URL.String())
		return nil, nil
	})}

	if got := fetchGoLatestFromBase(context.Background(), "off", "github.com/acme/lib"); got != "" {
		t.Fatalf("fetchGoLatestFromBase(off) = %q, want empty latest", got)
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
	if !strings.Contains(output, "No lockfiles found.") {
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
	assertStandaloneHTMLUsesRemTypography(t, html)
	for _, want := range []string{
		`<html lang="en" dir="auto">`,
		`<meta name="color-scheme" content="dark light">`,
		":root{color-scheme:dark;",
		"--success:",
		"--warning:",
		"--warning-bg:",
		"background:var(--warning-bg)",
		"overflow-wrap:anywhere",
		"word-break:break-word",
		"@media (prefers-color-scheme: light)",
		"@media (prefers-color-scheme: light){:root{color-scheme:light;",
		"@media (prefers-contrast: more)",
		"@media (forced-colors: active)",
		"@media print",
		"table{min-width:0;table-layout:fixed;}",
		".name,.version,.ecosystem,.short,.lockfile{min-width:0;white-space:normal;}",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("outdated HTML CSS missing %q:\n%s", want, html)
		}
	}
	if strings.Contains(html, "background:#2d1f0f") {
		t.Fatalf("outdated HTML CSS still hard-codes the unknown empty-state background:\n%s", html)
	}
}

func TestOutdatedHTMLIsolatesDynamicValuesAndUsesLogicalCSS(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	report := outdatedReport{
		Target:      "repo-\u05d0",
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      "pkg-\u05d1",
			Installed: "1.0.0-\u05d2",
			Latest:    "2.0.0-\u05d4",
			Ecosystem: string(domain.EcosystemNPM),
			Scope:     "runtime",
			Relation:  "direct",
			Via:       "parent-\u05d5",
			Flags:     "peer-\u05d6",
			LockFile:  "package-lock-\u05d7.json",
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
		`<bdi dir="auto">repo-` + "\u05d0" + `</bdi>`,
		`<h2><bdi dir="auto">pkg-` + "\u05d1" + `</bdi></h2>`,
		`<dd><bdi dir="auto">1.0.0-` + "\u05d2" + `</bdi></dd>`,
		`<dd><bdi dir="auto">2.0.0-` + "\u05d4" + `</bdi></dd>`,
		`<dt>Via</dt><dd><bdi dir="auto">parent-` + "\u05d5" + `</bdi></dd>`,
		`<td class="name"><bdi dir="auto">pkg-` + "\u05d1" + `</bdi></td>`,
		`<td class="lockfile"><bdi dir="auto">package-lock-` + "\u05d7" + `.json</bdi></td>`,
		"text-align:start",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("outdated HTML missing bidi/logical CSS contract %q:\n%s", want, html)
		}
	}
	for _, bad := range []string{`<html lang="en" dir="ltr">`, "text-align:left", "margin-left", "border-left"} {
		if strings.Contains(html, bad) {
			t.Fatalf("outdated HTML still uses physical left-side rule %q:\n%s", bad, html)
		}
	}
}

func assertStandaloneHTMLUsesRemTypography(t *testing.T, out string) {
	t.Helper()

	for _, want := range []string{
		"font-size:1.375rem",
		"font-size:0.9375rem",
		"font-size:0.8125rem",
		"font-size:0.75rem",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML report missing rem typography %q:\n%s", want, out)
		}
	}
	if match := regexp.MustCompile(`font-size:\s*[0-9]+px`).FindString(out); match != "" {
		t.Fatalf("HTML report uses fixed pixel font size %q:\n%s", match, out)
	}
}

func TestOutdatedHTMLIncludesStandaloneCSPMeta(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	report := outdatedReport{
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      "github.com/acme/pkg",
			Installed: "1.0.0",
			Latest:    "1.1.0",
			Ecosystem: string(domain.EcosystemGo),
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
	want := `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">`
	if !strings.Contains(html, want) {
		t.Fatalf("outdated HTML missing CSP meta %q:\n%s", want, html)
	}
	if strings.Index(html, want) > strings.Index(html, "<style>") {
		t.Fatalf("CSP meta should appear before inline styles:\n%s", html)
	}
	if strings.Contains(html, `<script src=`) {
		t.Fatalf("outdated HTML must not load external scripts:\n%s", html)
	}
}

func TestOutdatedHTMLUsesMainLandmark(t *testing.T) {
	out := renderOutdatedAccessibilityHTML(t)

	assertCLIHTMLUsesMainWrapLandmark(t, out)
}

func TestOutdatedHTMLTableHeadersUseColumnScope(t *testing.T) {
	out := renderOutdatedAccessibilityHTML(t)

	assertHTMLTableHeadersHaveColumnScope(t, out)
}

func renderOutdatedAccessibilityHTML(t *testing.T) string {
	t.Helper()

	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	report := outdatedReport{
		Target:      "repo",
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      "left-pad",
			Installed: "1.0.0",
			Latest:    "1.3.0",
			Ecosystem: string(domain.EcosystemNPM),
			Scope:     "runtime",
			Relation:  "direct",
			Via:       "root",
			Flags:     "optional",
			LockFile:  "package-lock.json",
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
	return string(data)
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
		`<td class="lockfile"><bdi dir="auto">package-lock.json</bdi></td>`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("outdated HTML missing minimized path %q:\n%s", want, html)
		}
	}
}

func TestOutdatedHTMLTableScrollRegionIsKeyboardFocusable(t *testing.T) {
	for _, want := range []string{
		".table-scroll:focus{",
		`<div class="table-scroll" tabindex="0" role="region" aria-label="{{.Messages.OutdatedTableLabel}}">`,
	} {
		if !strings.Contains(outdatedHTML, want) {
			t.Fatalf("outdated HTML template missing keyboard-scroll contract %q", want)
		}
	}
}

func TestRunOutdatedWithOptionsWritesHTMLReport(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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

	if err := runOutdatedWithOptions([]string{dir}, outdatedOptions{
		Context:    context.Background(),
		MaxDepth:   10,
		IncludeDev: true,
		OutputHTML: htmlPath,
		resolver:   resolver,
	}); err != nil {
		t.Fatalf("runOutdatedWithOptions: %v", err)
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
		"<th scope=\"col\" class=\"version\">Installed</th>",
		`<td class="version"><bdi dir="auto">1.0.0</bdi></td>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("outdated HTML missing %q:\n%s", want, out)
		}
	}
}

func TestRunOutdatedWithOptionsIncludesDevPackages(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		if err := runOutdatedWithOptions([]string{dir}, outdatedOptions{
			Context:    context.Background(),
			MaxDepth:   10,
			IncludeDev: true,
			resolver:   resolver,
		}); err != nil {
			t.Fatalf("runOutdatedWithOptions: %v", err)
		}
	})

	if !strings.Contains(output, "prod") {
		t.Fatalf("outdated output missing production package:\n%s", output)
	}
	if !strings.Contains(output, "dev-only") {
		t.Fatalf("outdated output should include dev packages by default:\n%s", output)
	}
}

func TestRunOutdatedWithOptionsRendersScopeRelationViaAndFlags(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		if err := runOutdatedWithOptions([]string{dir}, outdatedOptions{
			Context:    context.Background(),
			MaxDepth:   10,
			IncludeDev: true,
			OutputHTML: htmlPath,
			resolver:   resolver,
		}); err != nil {
			t.Fatalf("runOutdatedWithOptions: %v", err)
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
	for _, want := range []string{
		`id="outdated-provenance-legend"`,
		`aria-describedby="outdated-provenance-legend"`,
		`class="mobile-list"`,
		`aria-label="Outdated packages cards"`,
		`<summary>Provenance and source</summary>`,
		`@media (min-width:900px)`,
		`.mobile-list{display:none;}`,
		"Scope is where Packmon found the dependency",
		"Relation is its graph relationship",
		"Via lists npm parent roots when known",
		"Flags show optional/peer or source-specific markers",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("outdated HTML missing provenance legend contract %q:\n%s", want, html)
		}
	}
	legendIndex := strings.Index(html, `id="outdated-provenance-legend"`)
	tableIndex := strings.Index(html, "<table")
	if legendIndex == -1 || tableIndex == -1 || legendIndex > tableIndex {
		t.Fatalf("outdated HTML should explain provenance columns before the table:\n%s", html)
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
