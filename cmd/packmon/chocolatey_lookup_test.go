package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

const chocolateyODataFeed = `<?xml version="1.0" encoding="utf-8"?>
<feed xml:base="https://feeds.example/api/v2/" xmlns="http://www.w3.org/2005/Atom" xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
  <title type="text">Packages</title>
  <entry>
    <id>https://feeds.example/api/v2/Packages(Id='7zip.vm',Version='23.1.0.20250902')</id>
    <title type="text">7zip.vm</title>
    <m:properties>
      <d:Id>7zip.vm</d:Id>
      <d:Version>23.1.0.20250902</d:Version>
      <d:IsLatestVersion m:type="Edm.Boolean">true</d:IsLatestVersion>
    </m:properties>
  </entry>
</feed>`

const chocolateyODataEmpty = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title type="text">Packages</title></feed>`

func TestFetchChocolateyLatestQueriesFeedsInOrderWithAtomAccept(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	var requests []string
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.Host+req.URL.Path+"?"+req.URL.RawQuery)
		if got := req.Header.Values("Accept"); len(got) != 1 || got[0] != "application/atom+xml" {
			t.Fatalf("Accept = %v, want exactly application/atom+xml", got)
		}
		filter := req.URL.Query().Get("$filter")
		if filter != "tolower(Id) eq '7zip.vm' and IsLatestVersion" {
			t.Fatalf("$filter = %q", filter)
		}
		if strings.Contains(req.URL.RawQuery, "+") || !strings.Contains(req.URL.RawQuery, "%20") {
			t.Fatalf("raw query %q must percent-encode spaces (OData feeds do not decode '+')", req.URL.RawQuery)
		}
		body := chocolateyODataEmpty
		if req.URL.Host == "myget.example" {
			body = chocolateyODataFeed
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     http.Header{"Content-Type": []string{"application/atom+xml;charset=utf-8"}},
			Request:    req,
		}, nil
	})}

	got := fetchChocolateyLatestFromFeeds(context.Background(), []string{"https://community.example/api/v2", "https://myget.example/F/vm-packages/api/v2"}, "7ZIP.VM")
	if got != "23.1.0.20250902" {
		t.Fatalf("fetchChocolateyLatestFromFeeds() = %q, want version from the second feed", got)
	}
	if len(requests) != 2 || !strings.HasPrefix(requests[0], "community.example/api/v2/Packages()") || !strings.HasPrefix(requests[1], "myget.example/F/vm-packages/api/v2/Packages()") {
		t.Fatalf("requests = %v, want community feed first, then myget", requests)
	}
}

func TestFetchChocolateyLatestStopsAtFirstFeedThatKnowsThePackage(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	var calls atomic.Int32
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(chocolateyODataFeed)), Header: make(http.Header), Request: req}, nil
	})}
	if got := fetchChocolateyLatestFromFeeds(context.Background(), []string{"https://a.example/api/v2", "https://b.example/api/v2"}, "7zip.vm"); got != "23.1.0.20250902" {
		t.Fatalf("latest = %q", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("feed requests = %d, want 1 (first feed answered)", calls.Load())
	}
}

func TestFetchChocolateyLatestReturnsEmptyOnErrorsAndInvalidBodies(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "down.example":
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: req}, nil
		case "garbage.example":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("<not xml")), Header: make(http.Header), Request: req}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(chocolateyODataEmpty)), Header: make(http.Header), Request: req}, nil
	})}
	if got := fetchChocolateyLatestFromFeeds(context.Background(), []string{"https://down.example/api/v2", "https://garbage.example/api/v2", "https://empty.example/api/v2"}, "7zip.vm"); got != "" {
		t.Fatalf("latest = %q, want empty", got)
	}
	if got := fetchChocolateyLatestFromFeeds(context.Background(), nil, "7zip.vm"); got != "" {
		t.Fatalf("latest without feeds = %q, want empty", got)
	}
	if got := fetchChocolateyLatestFromFeeds(context.Background(), []string{"https://empty.example/api/v2"}, "bad id with spaces"); got != "" {
		t.Fatalf("latest for invalid id = %q, want empty without any request", got)
	}
}

func TestChocolateyResolverEntryUsesConfiguredFeeds(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	var hosts []string
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		hosts = append(hosts, req.URL.Host)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(chocolateyODataFeed)), Header: make(http.Header), Request: req}, nil
	})}
	resolver := packageUpdateResolver{latestRegistry: latestRegistryConfig{ChocolateyFeedURLs: []string{"https://vm-feed.example/api/v2"}}}
	if got := resolver.latestVersion(context.Background(), domain.EcosystemChocolatey, "7zip.vm"); got != "23.1.0.20250902" {
		t.Fatalf("latestVersion(chocolatey) = %q", got)
	}
	if len(hosts) != 1 || hosts[0] != "vm-feed.example" {
		t.Fatalf("hosts = %v, want the configured feed only", hosts)
	}
	if !latestLookupAllowed(domain.EcosystemChocolatey, nil, directPackageUpdateLookupWithResolver(packageUpdateResolver{})) {
		t.Fatal("chocolatey lookups without source refs must be allowed against the default feed")
	}
}

func TestParseChocolateyODataLatestVersionPicksHighestNuGetVersion(t *testing.T) {
	t.Parallel()

	feed := `<feed xmlns="http://www.w3.org/2005/Atom" xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
<entry><m:properties><d:Version>1.10.0</d:Version></m:properties></entry>
<entry><m:properties><d:Version>1.9.0</d:Version></m:properties></entry>
<entry><m:properties><d:Version>1.10.0-beta</d:Version></m:properties></entry>
</feed>`
	if got := parseChocolateyODataLatestVersion([]byte(feed)); got != "1.10.0" {
		t.Fatalf("parseChocolateyODataLatestVersion() = %q, want 1.10.0", got)
	}
}
