package main

import (
	"context"

	"github.com/8linkz-sec/packmon/internal/domain"
)

type latestVersionResolverEntry struct {
	fetchLatest                    func(context.Context, packageUpdateResolver, string) string
	publicLookupAllowed            func([]string) bool
	allowLookupWithoutSourceRefs   bool
	configuredLatestRegistryMirror func(latestRegistryConfig) bool
}

var latestVersionResolverRegistry = map[domain.Ecosystem]latestVersionResolverEntry{
	domain.EcosystemNPM: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchNPMLatestFromBase(ctx, r.latestRegistry.NPMRegistryBaseURL, name)
		},
		publicLookupAllowed:          npmPublicLatestLookupAllowed,
		allowLookupWithoutSourceRefs: true,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().NPMRegistryBaseURLConfigured
		},
	},
	domain.EcosystemPyPI: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchPyPILatestFromBase(ctx, r.latestRegistry.PyPIAPIBaseURL, name)
		},
		publicLookupAllowed:          pyPIPublicLatestLookupAllowed,
		allowLookupWithoutSourceRefs: true,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().PyPIAPIBaseURLConfigured
		},
	},
	domain.EcosystemGo: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchGoLatestFromBase(ctx, r.latestRegistry.GoModuleProxyURL, name)
		},
		publicLookupAllowed:          allowAllPublicSourceRefs,
		allowLookupWithoutSourceRefs: true,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().GoModuleProxyURLConfigured
		},
	},
	domain.EcosystemCargo: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchCratesLatestFromBase(ctx, r.latestRegistry.CargoRegistryAPIBaseURL, name)
		},
		publicLookupAllowed:          cargoPublicLatestLookupAllowed,
		allowLookupWithoutSourceRefs: true,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().CargoRegistryAPIBaseURLConfigured
		},
	},
	domain.EcosystemNuGet: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchNuGetLatestFromBase(ctx, r.latestRegistry.NuGetV3BaseURL, name)
		},
		publicLookupAllowed: nuGetPublicLatestLookupAllowed,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().NuGetV3BaseURLConfigured
		},
	},
	domain.EcosystemGem: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchRubyGemsLatestFromBase(ctx, r.latestRegistry.RubyGemsAPIBaseURL, name)
		},
		publicLookupAllowed:          gemPublicLatestLookupAllowed,
		allowLookupWithoutSourceRefs: true,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().RubyGemsAPIBaseURLConfigured
		},
	},
	domain.EcosystemComposer: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchPackagistLatestFromBase(ctx, r.latestRegistry.ComposerRepositoryBaseURL, name)
		},
		publicLookupAllowed:          composerPublicLatestLookupAllowed,
		allowLookupWithoutSourceRefs: true,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().ComposerRepositoryBaseURLConfigured
		},
	},
	domain.EcosystemMaven: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchMavenLatestFromBase(ctx, r.latestRegistry.MavenRepositoryBaseURL, name)
		},
		publicLookupAllowed:          mavenPublicLatestLookupAllowed,
		allowLookupWithoutSourceRefs: true,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().MavenRepositoryBaseURLConfigured
		},
	},
	domain.EcosystemPub: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchPubLatestFromBase(ctx, r.latestRegistry.PubHostedURL, name)
		},
		publicLookupAllowed:          pubSourceRefsAllowPublicLookup,
		allowLookupWithoutSourceRefs: true,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().PubHostedURLConfigured
		},
	},
	domain.EcosystemHex: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchHexLatestFromBase(ctx, r.latestRegistry.HexAPIBaseURL, name)
		},
		publicLookupAllowed: hexPublicLatestLookupAllowed,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().HexAPIBaseURLConfigured
		},
	},
	domain.EcosystemCRAN: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchCRANLatestFromBase(ctx, r.latestRegistry.CRANMirrorURL, name)
		},
		publicLookupAllowed:          cranSourceRefsAllowPublicLookup,
		allowLookupWithoutSourceRefs: true,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().CRANMirrorURLConfigured
		},
	},
	domain.EcosystemCocoaPods: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return fetchCocoaPodsLatestFromBase(ctx, r.latestRegistry.CocoaPodsTrunkAPIBaseURL, name)
		},
		publicLookupAllowed:          cocoaPodsPublicLatestLookupAllowed,
		allowLookupWithoutSourceRefs: true,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().CocoaPodsTrunkAPIBaseURLConfigured
		},
	},
	domain.EcosystemSwiftPM: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return r.fetchSwiftPMLatest(ctx, name)
		},
		publicLookupAllowed:          allowAllPublicSourceRefs,
		allowLookupWithoutSourceRefs: true,
		configuredLatestRegistryMirror: func(c latestRegistryConfig) bool {
			return c.withDefaults().SwiftPMGitAllowedHostsConfigured
		},
	},
	domain.EcosystemGitHubActions: {
		fetchLatest: func(ctx context.Context, r packageUpdateResolver, name string) string {
			return r.fetchGitHubActionLatest(ctx, name)
		},
		publicLookupAllowed:          allowAllPublicSourceRefs,
		allowLookupWithoutSourceRefs: true,
	},
}

func latestVersionResolverFor(eco domain.Ecosystem) (latestVersionResolverEntry, bool) {
	entry, ok := latestVersionResolverRegistry[eco]
	return entry, ok
}

func latestRegistryMirrorConfigured(c latestRegistryConfig, eco domain.Ecosystem) bool {
	entry, ok := latestVersionResolverFor(eco)
	return ok && entry.configuredLatestRegistryMirror != nil && entry.configuredLatestRegistryMirror(c)
}
