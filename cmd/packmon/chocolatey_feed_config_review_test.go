package main

import (
	"strings"
	"testing"
)

func TestChocolateyFeedURLsOverlayReplacesAndProjectConfigCannotSetThem(t *testing.T) {
	t.Parallel()

	dst := cliRegistryConfig{ChocolateyFeedURLs: []string{"https://base-a.internal/api/v2", "https://base-b.internal/api/v2"}}
	src := cliRegistryConfig{ChocolateyFeedURLs: []string{"https://override.internal/api/v2"}}
	overlayCLIRegistryConfig(&dst, src)
	if got := strings.Join(dst.ChocolateyFeedURLs, ","); got != "https://override.internal/api/v2" {
		t.Fatalf("overlay chocolatey feeds = %q, want the later layer to replace the ordered list", got)
	}
	src.ChocolateyFeedURLs[0] = "https://mutated.internal"
	if dst.ChocolateyFeedURLs[0] != "https://override.internal/api/v2" {
		t.Fatal("overlay aliases the source feed list")
	}
	overlayCLIRegistryConfig(&dst, cliRegistryConfig{})
	if len(dst.ChocolateyFeedURLs) != 1 {
		t.Fatalf("empty overlay changed feeds to %v", dst.ChocolateyFeedURLs)
	}

	project := cliConfig{Registries: cliRegistryConfig{ChocolateyFeedURLs: []string{"https://evil.example/api/v2"}}}
	project.stripUntrustedAutoProjectFields()
	if len(project.Registries.ChocolateyFeedURLs) != 0 {
		t.Fatalf("auto-discovered project config kept chocolatey feeds %v", project.Registries.ChocolateyFeedURLs)
	}

	// An explicit list equal to the default keeps lookups on the default feed
	// without marking a trusted mirror as configured.
	same := latestRegistryConfig{ChocolateyFeedURLs: []string{defaultChocolateyFeedURL + "/"}}.withDefaults()
	if same.ChocolateyFeedURLsConfigured || len(same.ChocolateyFeedURLs) != 1 {
		t.Fatalf("default-equal list = %v configured=%v, want unconfigured default", same.ChocolateyFeedURLs, same.ChocolateyFeedURLsConfigured)
	}
}
