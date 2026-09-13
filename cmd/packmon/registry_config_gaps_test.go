package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

var latestRegistryEnvKeys = []string{
	"PACKMON_NPM_REGISTRY_BASE_URL", "PACKMON_PYPI_API_BASE_URL",
	"PACKMON_RUBYGEMS_API_BASE_URL", "PACKMON_CARGO_REGISTRY_API_BASE_URL",
	"PACKMON_COCOAPODS_TRUNK_API_BASE_URL", "PACKMON_COMPOSER_REPOSITORY_BASE_URL",
	"PACKMON_GO_PROXY_URL", "PACKMON_MAVEN_REPOSITORY_BASE_URL",
	"PACKMON_DOCKER_REGISTRY_MIRRORS", "PACKMON_SWIFTPM_GIT_ALLOWED_HOSTS",
	"PACKMON_CRAN_MIRROR_URL", "PACKMON_PUB_HOSTED_URL", "PACKMON_HEX_API_BASE_URL",
	"PACKMON_NUGET_V3_BASE_URL", "PACKMON_CHOCOLATEY_FEED_URLS",
}

func isolateLatestRegistryEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range latestRegistryEnvKeys {
		t.Setenv(key, "")
	}
}

func TestLatestRegistryGoProxyOffEnvironmentSkipsLookup(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })
	var requests atomic.Int32
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("Go proxy off must not send a request")
	})}

	for _, raw := range []string{"off", "OFF", "  Off  "} {
		t.Run(raw, func(t *testing.T) {
			isolateLatestRegistryEnvironment(t)
			t.Setenv("PACKMON_GO_PROXY_URL", raw)
			settings := scanSettings{LatestRegistry: latestRegistryConfig{
				NPMRegistryBaseURL:           "https://configured.example/",
				NPMRegistryBaseURLConfigured: true,
			}}
			if err := applyLatestRegistryEnvSettings(&settings); err != nil {
				t.Fatalf("apply env: %v", err)
			}
			cfg := settings.LatestRegistry.withDefaults()
			if cfg.GoModuleProxyURL != "off" || !cfg.GoModuleProxyURLConfigured {
				t.Fatalf("Go proxy config = %+v, want configured off", cfg)
			}
			if cfg.NPMRegistryBaseURL != "https://configured.example" || !cfg.NPMRegistryBaseURLConfigured {
				t.Fatalf("unrelated configured registry was not preserved: %+v", cfg)
			}
			if got := fetchGoLatestFromBase(context.Background(), cfg.GoModuleProxyURL, "github.com/acme/lib"); got != "" {
				t.Fatalf("fetchGoLatestFromBase(off) = %q, want empty", got)
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("Go proxy off sent %d request(s), want none", got)
			}
		})
	}
}

func TestLatestRegistryEnvironmentRejectsInvalidValues(t *testing.T) {
	urlVariables := []string{
		"PACKMON_NPM_REGISTRY_BASE_URL", "PACKMON_PYPI_API_BASE_URL", "PACKMON_RUBYGEMS_API_BASE_URL",
		"PACKMON_CARGO_REGISTRY_API_BASE_URL", "PACKMON_COCOAPODS_TRUNK_API_BASE_URL", "PACKMON_COMPOSER_REPOSITORY_BASE_URL",
		"PACKMON_GO_PROXY_URL", "PACKMON_MAVEN_REPOSITORY_BASE_URL", "PACKMON_CRAN_MIRROR_URL",
		"PACKMON_PUB_HOSTED_URL", "PACKMON_HEX_API_BASE_URL", "PACKMON_NUGET_V3_BASE_URL", "PACKMON_CHOCOLATEY_FEED_URLS",
	}
	for _, key := range urlVariables {
		t.Run(key, func(t *testing.T) {
			isolateLatestRegistryEnvironment(t)
			t.Setenv(key, "http://registry.invalid")
			if err := applyLatestRegistryEnvSettings(&scanSettings{}); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("apply %s error = %v, want named rejection", key, err)
			}
		})
	}
	for _, tc := range []struct{ name, value string }{
		{"docker missing equals", "ghcr.io"}, {"docker empty host", "=https://mirror.example"},
		{"docker empty mirror", "ghcr.io="}, {"docker unsupported host", "private.example=https://mirror.example"},
		{"docker invalid mirror URL", "ghcr.io=http://registry.invalid"},
		{"swift malformed host", "git.example.com,broken..host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateLatestRegistryEnvironment(t)
			key := "PACKMON_DOCKER_REGISTRY_MIRRORS"
			if strings.HasPrefix(tc.name, "swift") {
				key = "PACKMON_SWIFTPM_GIT_ALLOWED_HOSTS"
			}
			t.Setenv(key, tc.value)
			if err := applyLatestRegistryEnvSettings(&scanSettings{}); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("apply %s=%q error = %v, want named rejection", key, tc.value, err)
			}
		})
	}
}

func TestLatestRegistryEnvironmentPropagatesDockerAndSwiftPM(t *testing.T) {
	isolateLatestRegistryEnvironment(t)
	t.Setenv("PACKMON_DOCKER_REGISTRY_MIRRORS", "docker.io=https://mirror.example/,ghcr.io=https://ghcr-mirror.example")
	t.Setenv("PACKMON_SWIFTPM_GIT_ALLOWED_HOSTS", " Git.Example.com.,git.example.com ")
	var settings scanSettings
	if err := applyLatestRegistryEnvSettings(&settings); err != nil {
		t.Fatalf("apply env: %v", err)
	}
	cfg := settings.LatestRegistry
	if !cfg.DockerRegistryMirrorsConfigured || cfg.DockerRegistryMirrors["registry-1.docker.io"] != "https://mirror.example" || !cfg.SwiftPMGitAllowedHostsConfigured || strings.Join(cfg.SwiftPMGitAllowedHosts, ",") != "git.example.com" {
		t.Fatalf("registry settings = %+v", cfg)
	}
}

func TestLatestRegistryNormalizersHandleListsAndEndpoints(t *testing.T) {
	hosts, err := normalizeSwiftPMGitAllowedHosts("hosts", []string{"", " Git.Example.com. ", "git.example.com"})
	if err != nil || strings.Join(hosts, ",") != "git.example.com" {
		t.Fatalf("hosts = %v, %v", hosts, err)
	}
	for _, raw := range []string{"broken..host", "git_thing.example", "git.example.com:443", "git@example.com", "localhost"} {
		if _, err := normalizeSwiftPMGitAllowedHost("hosts", raw); err == nil {
			t.Fatalf("host %q accepted", raw)
		}
	}
	if feeds, err := normalizeFeedURLList("feeds", []string{" ", "https://feeds.example/api/", "https://feeds.example/api"}); err != nil || strings.Join(feeds, ",") != "https://feeds.example/api" {
		t.Fatalf("feeds = %v, %v", feeds, err)
	}
	if feeds, err := normalizeFeedURLList("feeds", []string{" ", "\t"}); err != nil || len(feeds) != 0 {
		t.Fatalf("blank feeds = %v, %v; want no configured entries", feeds, err)
	}
	if _, err := normalizeLatestRegistryBaseURL("url", "http://registry.invalid"); err == nil {
		t.Fatal("non-loopback HTTP accepted")
	}
	if got, err := normalizeLatestRegistryBaseURL("url", "http://127.0.0.1:8080/"); err != nil || got != "http://127.0.0.1:8080" {
		t.Fatalf("loopback URL = %q, %v", got, err)
	}
	if got := registryEndpoint(" /base/ ", "/one/", "two/"); got != "/base/one/two" {
		t.Fatalf("endpoint = %q", got)
	}
	if got := registryEndpoint("", "/one/", "two/"); got != "/one/two" {
		t.Fatalf("blank-base endpoint = %q", got)
	}
}
