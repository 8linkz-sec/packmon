package server

import (
	"testing"

	v1 "github.com/8linkz-sec/packmon/internal/api/v1"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/feed/socket"
)

func TestServerLayoutLinksCopiesConfiguredLegalURLs(t *testing.T) {
	t.Parallel()

	if got := serverLayoutLinks(nil); got.PrivacyURL != "" || got.LegalURL != "" || got.TermsURL != "" {
		t.Fatalf("serverLayoutLinks(nil) = %+v, want empty links", got)
	}

	cfg := &config.Config{Web: config.WebConfig{
		PrivacyURL: "https://example.test/privacy",
		LegalURL:   "https://example.test/legal",
		TermsURL:   "https://example.test/terms",
	}}
	got := serverLayoutLinks(cfg)
	if got.PrivacyURL != cfg.Web.PrivacyURL || got.LegalURL != cfg.Web.LegalURL || got.TermsURL != cfg.Web.TermsURL {
		t.Fatalf("serverLayoutLinks() = %+v, want URLs from config", got)
	}
}

func TestAPISocketRefreshProviderHonorsConfigurationAndPolicy(t *testing.T) {
	t.Parallel()

	var nilProvider *apiSocketRefreshProvider
	if nilProvider.Active() {
		t.Fatal("nil provider reported active")
	}
	if nilProvider.ExcludedByPolicy("npm", "@internal/widget") {
		t.Fatal("nil provider excluded a package")
	}
	nilProvider.Configure(v1.PackageRefreshProviderConfig{Active: true})

	provider := &apiSocketRefreshProvider{}
	excluded := []string{"npm/@internal/"}
	provider.Configure(v1.PackageRefreshProviderConfig{
		Active:             true,
		ExcludedNamespaces: excluded,
	})
	excluded[0] = "npm/@changed/"

	if !provider.Active() {
		t.Fatal("configured provider reported inactive")
	}
	if got := provider.Source(); got != socket.FeedName {
		t.Fatalf("Source() = %q, want %q", got, socket.FeedName)
	}
	if !provider.SupportsEcosystem(" NPM ") {
		t.Fatal("provider did not support normalized npm ecosystem")
	}
	if provider.SupportsEcosystem("unknown") {
		t.Fatal("provider supported unknown ecosystem")
	}
	if !provider.ExcludedByPolicy("npm", "@internal/widget") {
		t.Fatal("provider did not apply configured exclusion")
	}
	if provider.ExcludedByPolicy("npm", "@changed/widget") {
		t.Fatal("provider configuration retained caller slice mutation")
	}
}
