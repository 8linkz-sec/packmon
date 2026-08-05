package main

import (
	"strings"
	"testing"
)

func TestSelectLatestMavenMetadataVersionPicksHighest(t *testing.T) {
	t.Parallel()

	if got := selectLatestMavenMetadataVersion(nil); got != "" {
		t.Fatalf("selectLatestMavenMetadataVersion(nil) = %q, want empty", got)
	}
	if got := selectLatestMavenMetadataVersion([]string{" ", ""}); got != "" {
		t.Fatalf("selectLatestMavenMetadataVersion(blank entries) = %q, want empty", got)
	}
	if got := selectLatestMavenMetadataVersion([]string{"1.2.3", " 2.0.0 ", "1.9.9"}); got != "2.0.0" {
		t.Fatalf("selectLatestMavenMetadataVersion() = %q, want 2.0.0", got)
	}
}

func TestPackagistLatestEndpointValidatesVendorPackageShape(t *testing.T) {
	t.Parallel()

	endpoint, ok := packagistLatestEndpoint("monolog/monolog")
	if !ok {
		t.Fatal("packagistLatestEndpoint(monolog/monolog) ok = false, want endpoint")
	}
	if !strings.HasPrefix(endpoint, "https://repo.packagist.org/p2/") || !strings.HasSuffix(endpoint, "monolog/monolog.json") {
		t.Fatalf("packagistLatestEndpoint() = %q, want packagist p2 JSON endpoint", endpoint)
	}

	for _, invalid := range []string{"", "monolog", "monolog/", "/monolog", "a/b/c"} {
		if endpoint, ok := packagistLatestEndpoint(invalid); ok {
			t.Fatalf("packagistLatestEndpoint(%q) = %q, want rejection", invalid, endpoint)
		}
	}
}

func TestIsCanonicalSwiftPMLookupIdentity(t *testing.T) {
	t.Parallel()

	valid := []string{
		"github.com/apple/swift-nio",
		"GitHub.com/apple/swift-nio.git",
		"gitlab.com/group/subgroup/project",
		"bitbucket.org/team/repo",
	}
	for _, name := range valid {
		if !isCanonicalSwiftPMLookupIdentity(name) {
			t.Fatalf("isCanonicalSwiftPMLookupIdentity(%q) = false, want true", name)
		}
	}

	invalid := []string{
		"",
		"github.com/apple",
		"https://github.com/apple/swift-nio",
		"github.com//swift-nio",
		"github.com/apple/..",
		"evil.example/apple/swift-nio",
		"github.com/apple/swift nio",
		"-github.com/apple/swift-nio",
		"/github.com/apple/swift-nio",
		"github.com/apple/swift-nio?x=1",
	}
	for _, name := range invalid {
		if isCanonicalSwiftPMLookupIdentity(name) {
			t.Fatalf("isCanonicalSwiftPMLookupIdentity(%q) = true, want false", name)
		}
	}
}

func TestIsAllowedSwiftPMGitHost(t *testing.T) {
	t.Parallel()

	for _, host := range []string{"github.com", " GitHub.com ", "gitlab.com", "bitbucket.org"} {
		if !isAllowedSwiftPMGitHost(host) {
			t.Fatalf("isAllowedSwiftPMGitHost(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"", "evil.example", "github.com.evil.example"} {
		if isAllowedSwiftPMGitHost(host) {
			t.Fatalf("isAllowedSwiftPMGitHost(%q) = true, want false", host)
		}
	}
}

func TestAllowAllPublicSourceRefsAlwaysAllows(t *testing.T) {
	t.Parallel()

	if !allowAllPublicSourceRefs(nil) || !allowAllPublicSourceRefs([]string{"registry+https://example"}) {
		t.Fatal("allowAllPublicSourceRefs() = false, want unconditional true")
	}
}
