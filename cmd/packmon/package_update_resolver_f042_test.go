package main

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestLatestRegistryMirrorConfiguredSwiftPMRequiresExplicitConfiguration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  latestRegistryConfig
		want bool
	}{
		{name: "default configuration", cfg: latestRegistryConfig{}, want: false},
		{name: "explicit configured flag", cfg: latestRegistryConfig{SwiftPMGitAllowedHostsConfigured: true}, want: true},
		{name: "explicit allowed host", cfg: latestRegistryConfig{SwiftPMGitAllowedHosts: []string{"git.internal"}}, want: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := latestRegistryMirrorConfigured(tt.cfg, domain.EcosystemSwiftPM); got != tt.want {
				t.Fatalf("latestRegistryMirrorConfigured(SwiftPM) = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLatestRegistryMirrorConfiguredIsolatedEcosystemConfiguration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		ecosystem domain.Ecosystem
		cfg       latestRegistryConfig
	}{
		{"npm", domain.EcosystemNPM, latestRegistryConfig{NPMRegistryBaseURLConfigured: true}},
		{"pypi", domain.EcosystemPyPI, latestRegistryConfig{PyPIAPIBaseURLConfigured: true}},
		{"go", domain.EcosystemGo, latestRegistryConfig{GoModuleProxyURLConfigured: true}},
		{"cargo", domain.EcosystemCargo, latestRegistryConfig{CargoRegistryAPIBaseURLConfigured: true}},
		{"nuget", domain.EcosystemNuGet, latestRegistryConfig{NuGetV3BaseURLConfigured: true}},
		{"rubygems", domain.EcosystemGem, latestRegistryConfig{RubyGemsAPIBaseURLConfigured: true}},
		{"composer", domain.EcosystemComposer, latestRegistryConfig{ComposerRepositoryBaseURLConfigured: true}},
		{"maven", domain.EcosystemMaven, latestRegistryConfig{MavenRepositoryBaseURLConfigured: true}},
		{"pub", domain.EcosystemPub, latestRegistryConfig{PubHostedURLConfigured: true}},
		{"hex", domain.EcosystemHex, latestRegistryConfig{HexAPIBaseURLConfigured: true}},
		{"cran", domain.EcosystemCRAN, latestRegistryConfig{CRANMirrorURLConfigured: true}},
		{"cocoapods", domain.EcosystemCocoaPods, latestRegistryConfig{CocoaPodsTrunkAPIBaseURLConfigured: true}},
		{"swiftpm", domain.EcosystemSwiftPM, latestRegistryConfig{SwiftPMGitAllowedHostsConfigured: true}},
		{"chocolatey", domain.EcosystemChocolatey, latestRegistryConfig{ChocolateyFeedURLsConfigured: true}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			for ecosystem := range latestVersionResolverRegistry {
				want := ecosystem == tt.ecosystem
				if got := latestRegistryMirrorConfigured(tt.cfg, ecosystem); got != want {
					t.Errorf("latestRegistryMirrorConfigured(%s) with only %s configured = %v, want %v", ecosystem, tt.name, got, want)
				}
			}
			if latestRegistryMirrorConfigured(tt.cfg, domain.Ecosystem("unknown")) {
				t.Errorf("latestRegistryMirrorConfigured(unknown) with only %s configured = true, want false", tt.name)
			}
		})
	}
}

func TestNuGetLatestLookupPolicyRequiresConfiguredMirrorForPrivateOrUnknownSources(t *testing.T) {
	privateRefs := []string{"https://nuget.internal/v3/index.json"}
	cases := []struct {
		name    string
		cfg     latestRegistryConfig
		refs    []string
		allowed bool
	}{
		{"default with no source refs", latestRegistryConfig{}, nil, false},
		{"default with private source", latestRegistryConfig{}, privateRefs, false},
		{"configured mirror with no source refs", latestRegistryConfig{NuGetV3BaseURLConfigured: true}, nil, true},
		{"configured mirror with private source", latestRegistryConfig{NuGetV3BaseURLConfigured: true}, privateRefs, true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var called atomic.Bool
			lookup := directPackageUpdateLookupWithResolver(packageUpdateResolver{
				latestRegistry: tt.cfg,
				fetchLatest: func(context.Context, domain.Ecosystem, string) string {
					called.Store(true)
					return "2.0.0"
				},
			})

			if got := latestLookupAllowed(domain.EcosystemNuGet, tt.refs, lookup); got != tt.allowed {
				t.Fatalf("latestLookupAllowed(NuGet, %v) = %v, want %v", tt.refs, got, tt.allowed)
			}
			status := resolveOutdatedLatestWithLookup(context.Background(), outdatedPackage{
				Name: "private.package", Version: "1.0.0", Ecosystem: domain.EcosystemNuGet, SourceRefs: tt.refs,
			}, lookup)
			if tt.allowed {
				if status.Unknown || status.Latest != "2.0.0" || !called.Load() {
					t.Fatalf("configured NuGet mirror status = %+v, called=%v; want a hermetic resolver lookup", status, called.Load())
				}
				return
			}
			if !status.Unknown || called.Load() {
				t.Fatalf("default NuGet policy status = %+v, called=%v; want lookup refusal without a request", status, called.Load())
			}
		})
	}
}
