package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFetchChocolateyLatestBuildsFeedURLWithoutDoubleSlashOrRefusal(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	var paths []string
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(chocolateyODataEmpty)), Header: make(http.Header), Request: req}, nil
	})}
	ctx, phase := withRegistryLookupPhase(context.Background(), 5)
	if got := fetchChocolateyLatestFromFeeds(ctx, []string{"https://feeds.example/F/vm-packages/api/v2/", "https://feeds.example/api/v2"}, "7zip.vm"); got != "" {
		t.Fatalf("latest from empty feeds = %q, want empty", got)
	}
	if len(paths) != 2 || paths[0] != "/F/vm-packages/api/v2/Packages()" || paths[1] != "/api/v2/Packages()" {
		t.Fatalf("request paths = %v, want feed path + /Packages() without double slashes", paths)
	}
	// An empty 200 feed is an answer, not a refusal: it must not feed the breaker.
	if phase.refusedCount() != 0 || phase.breakerOpen() {
		t.Fatalf("refused = %d breakerOpen = %v, want no refusal for empty feeds", phase.refusedCount(), phase.breakerOpen())
	}
}

func TestFetchChocolateyLatestStopsWhenContextIsCanceled(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		cancel()
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(chocolateyODataEmpty)), Header: make(http.Header), Request: req}, nil
	})}
	if got := fetchChocolateyLatestFromFeeds(ctx, []string{"https://a.example/api/v2", "https://b.example/api/v2", "https://c.example/api/v2"}, "7zip.vm"); got != "" {
		t.Fatalf("latest = %q, want empty after cancellation", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("feed requests after cancellation = %d, want the loop to stop at 1", calls.Load())
	}
}

func TestIsChocolateyPackageIDMatchesCollectorRules(t *testing.T) {
	t.Parallel()
	for id, want := range map[string]bool{
		"7zip.vm":                      true,
		"vcredist-all":                 true,
		"a_b":                          true,
		".leading-dot":                 false,
		"-leading-dash":                false,
		"has space":                    false,
		"upper.Case":                   false, // callers lowercase first
		"":                             false,
		"x" + strings.Repeat("y", 100): false,
	} {
		if got := isChocolateyPackageID(id); got != want {
			t.Errorf("isChocolateyPackageID(%q) = %v, want %v", id, got, want)
		}
	}
}
