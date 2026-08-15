package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// registryStringFields returns the name of every plain string field on
// cliRegistryConfig together with its yaml key. The three functions under test
// each repeat one branch per field, so the tests walk the struct instead of
// listing the fields by hand -- a field added later is then covered
// automatically rather than silently skipped.
func registryStringFields(t *testing.T) map[string]string {
	t.Helper()

	fields := map[string]string{}
	typ := reflect.TypeOf(cliRegistryConfig{})
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.Type.Kind() != reflect.String {
			continue
		}
		key, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if key == "" {
			t.Fatalf("field %s has no yaml key", field.Name)
		}
		fields[field.Name] = key
	}
	if len(fields) < 10 {
		t.Fatalf("found only %d string registry fields; the walk is probably broken", len(fields))
	}
	return fields
}

// TestNormalizeCLIRegistryConfigValidatesEveryURLField is the security-relevant
// one. Each of these values ends up as the base URL of an outbound HTTP request
// for latest-version lookups, so every field must be validated and the error
// must name the yaml key the operator has to fix.
func TestNormalizeCLIRegistryConfigValidatesEveryURLField(t *testing.T) {
	t.Parallel()

	for name, yamlKey := range registryStringFields(t) {
		cfg := &cliRegistryConfig{}
		reflect.ValueOf(cfg).Elem().FieldByName(name).SetString("http://example.test/not-loopback")

		err := normalizeCLIRegistryConfig(cfg)
		if err == nil {
			t.Errorf("%s accepted plain http to a non-loopback host", name)
			continue
		}
		if !strings.Contains(err.Error(), yamlKey) {
			t.Errorf("%s error = %v, want it to name the yaml key %q", name, err, yamlKey)
		}
	}
}

// TestNormalizeCLIRegistryConfigRejectsNonURLValues covers the other rejection
// shapes each field has to apply: a value that is not an absolute URL, and one
// carrying credentials.
func TestNormalizeCLIRegistryConfigRejectsNonURLValues(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"not-a-url", "ftp://example.test", "https://user:pw@example.test"} {
		for name := range registryStringFields(t) {
			cfg := &cliRegistryConfig{}
			reflect.ValueOf(cfg).Elem().FieldByName(name).SetString(bad)

			if err := normalizeCLIRegistryConfig(cfg); err == nil {
				t.Errorf("%s accepted %q", name, bad)
			}
		}
	}
}

// TestNormalizeCLIRegistryConfigAcceptsHTTPSAndLoopback pins the positive side,
// so the validation tests above cannot pass by rejecting everything.
func TestNormalizeCLIRegistryConfigAcceptsHTTPSAndLoopback(t *testing.T) {
	t.Parallel()

	for name := range registryStringFields(t) {
		for _, good := range []string{"https://registry.internal/api/", "http://127.0.0.1:8081"} {
			cfg := &cliRegistryConfig{}
			reflect.ValueOf(cfg).Elem().FieldByName(name).SetString(good)

			if err := normalizeCLIRegistryConfig(cfg); err != nil {
				t.Errorf("%s rejected %q: %v", name, good, err)
				continue
			}
			// Normalisation strips the trailing slash so later joins are stable.
			normalised := reflect.ValueOf(cfg).Elem().FieldByName(name).String()
			if strings.HasSuffix(normalised, "/") {
				t.Errorf("%s = %q, want the trailing slash removed", name, normalised)
			}
		}
	}

	// An empty config is valid: every field falls back to its default.
	if err := normalizeCLIRegistryConfig(&cliRegistryConfig{}); err != nil {
		t.Errorf("an empty registry config was rejected: %v", err)
	}
	if err := normalizeCLIRegistryConfig(nil); err != nil {
		t.Errorf("normalizeCLIRegistryConfig(nil) = %v, want a no-op", err)
	}
}

// TestApplyCLIRegistryConfigMarksEveryOverrideAsConfigured covers the transfer
// into the scan settings. The `Configured` flag decides whether the CLI warns
// about a non-default registry, so setting the value without the flag would hide
// an operator override from the report.
func TestApplyCLIRegistryConfigMarksEveryOverrideAsConfigured(t *testing.T) {
	t.Parallel()

	for name := range registryStringFields(t) {
		cfg := cliRegistryConfig{}
		reflect.ValueOf(&cfg).Elem().FieldByName(name).SetString("https://registry.internal")

		var settings scanSettings
		applyCLIRegistryConfig(&settings, cfg)

		applied := reflect.ValueOf(settings.LatestRegistry).FieldByName(name)
		if !applied.IsValid() {
			t.Errorf("latestRegistryConfig has no field %s", name)
			continue
		}
		if applied.String() != "https://registry.internal" {
			t.Errorf("%s = %q, want the override applied", name, applied.String())
		}
		flag := reflect.ValueOf(settings.LatestRegistry).FieldByName(name + "Configured")
		if !flag.IsValid() {
			t.Errorf("latestRegistryConfig has no %sConfigured flag", name)
			continue
		}
		if !flag.Bool() {
			t.Errorf("%sConfigured = false, want the override flagged", name)
		}
	}
}

// TestApplyCLIRegistryConfigLeavesUnsetFieldsAlone is the counterpart: an empty
// config field means "not specified" and must not overwrite a value that came
// from a flag or an environment variable.
func TestApplyCLIRegistryConfigLeavesUnsetFieldsAlone(t *testing.T) {
	t.Parallel()

	for name := range registryStringFields(t) {
		var settings scanSettings
		reflect.ValueOf(&settings.LatestRegistry).Elem().FieldByName(name).SetString("https://from-flag")

		applyCLIRegistryConfig(&settings, cliRegistryConfig{})

		got := reflect.ValueOf(settings.LatestRegistry).FieldByName(name).String()
		if got != "https://from-flag" {
			t.Errorf("%s = %q, want the pre-existing value preserved", name, got)
		}
	}
}

// TestInheritFallbackFillsEveryUnsetField covers the layering between the
// per-target and the global registry configuration. A field the target does not
// set has to inherit both the value and its `Configured` flag, otherwise the
// inherited override would be applied but never reported.
func TestInheritFallbackFillsEveryUnsetField(t *testing.T) {
	t.Parallel()

	for name := range registryStringFields(t) {
		var fallback latestRegistryConfig
		reflect.ValueOf(&fallback).Elem().FieldByName(name).SetString("https://fallback.internal")
		flag := reflect.ValueOf(&fallback).Elem().FieldByName(name + "Configured")
		if !flag.IsValid() {
			t.Errorf("latestRegistryConfig has no %sConfigured flag", name)
			continue
		}
		flag.SetBool(true)

		merged := latestRegistryConfig{}.inheritFallback(fallback)

		if got := reflect.ValueOf(merged).FieldByName(name).String(); got != "https://fallback.internal" {
			t.Errorf("%s = %q, want the fallback inherited", name, got)
		}
		if !reflect.ValueOf(merged).FieldByName(name + "Configured").Bool() {
			t.Errorf("%sConfigured = false, want the fallback's flag inherited", name)
		}
	}
}

// TestInheritFallbackKeepsExplicitValues is the precedence rule: a target that
// sets its own registry must not have it replaced by the global one.
func TestInheritFallbackKeepsExplicitValues(t *testing.T) {
	t.Parallel()

	for name := range registryStringFields(t) {
		var own, fallback latestRegistryConfig
		reflect.ValueOf(&own).Elem().FieldByName(name).SetString("https://own.internal")
		reflect.ValueOf(&fallback).Elem().FieldByName(name).SetString("https://fallback.internal")

		merged := own.inheritFallback(fallback)
		if got := reflect.ValueOf(merged).FieldByName(name).String(); got != "https://own.internal" {
			t.Errorf("%s = %q, want the explicit value kept", name, got)
		}
	}
}

// TestInheritFallbackCoversTheCollectionFields handles the two fields that are
// not plain strings, and which the reflective walk above skips.
func TestInheritFallbackCoversTheCollectionFields(t *testing.T) {
	t.Parallel()

	fallback := latestRegistryConfig{
		DockerRegistryMirrors:            map[string]string{"ghcr.io": "https://mirror.internal"},
		DockerRegistryMirrorsConfigured:  true,
		SwiftPMGitAllowedHosts:           []string{"git.internal"},
		SwiftPMGitAllowedHostsConfigured: true,
	}

	merged := latestRegistryConfig{}.inheritFallback(fallback)
	if merged.DockerRegistryMirrors["ghcr.io"] != "https://mirror.internal" {
		t.Errorf("mirrors = %v, want the fallback inherited", merged.DockerRegistryMirrors)
	}
	if !merged.DockerRegistryMirrorsConfigured {
		t.Error("DockerRegistryMirrorsConfigured = false, want the flag inherited")
	}
	if len(merged.SwiftPMGitAllowedHosts) != 1 || merged.SwiftPMGitAllowedHosts[0] != "git.internal" {
		t.Errorf("allowed hosts = %v, want the fallback inherited", merged.SwiftPMGitAllowedHosts)
	}
	if !merged.SwiftPMGitAllowedHostsConfigured {
		t.Error("SwiftPMGitAllowedHostsConfigured = false, want the flag inherited")
	}

	// The inherited collections must be copies: mutating the merged result must
	// not reach back into the shared fallback configuration.
	merged.DockerRegistryMirrors["ghcr.io"] = "https://other.internal"
	if fallback.DockerRegistryMirrors["ghcr.io"] != "https://mirror.internal" {
		t.Error("the inherited mirror map aliases the fallback")
	}
	merged.SwiftPMGitAllowedHosts[0] = "evil.internal"
	if fallback.SwiftPMGitAllowedHosts[0] != "git.internal" {
		t.Error("the inherited host list aliases the fallback")
	}

	// A target that configures its own collections keeps them.
	own := latestRegistryConfig{
		DockerRegistryMirrors:  map[string]string{"quay.io": "https://own.internal"},
		SwiftPMGitAllowedHosts: []string{"own.internal"},
	}
	kept := own.inheritFallback(fallback)
	if _, ok := kept.DockerRegistryMirrors["ghcr.io"]; ok {
		t.Error("the fallback mirrors were merged into an explicit map")
	}
	if len(kept.SwiftPMGitAllowedHosts) != 1 || kept.SwiftPMGitAllowedHosts[0] != "own.internal" {
		t.Errorf("allowed hosts = %v, want the explicit list kept", kept.SwiftPMGitAllowedHosts)
	}
}

func TestChocolateyFeedURLsConfigDefaultsInheritanceAndValidation(t *testing.T) {
	t.Parallel()

	defaults := latestRegistryConfig{}.withDefaults()
	if len(defaults.ChocolateyFeedURLs) != 1 || defaults.ChocolateyFeedURLs[0] != defaultChocolateyFeedURL || defaults.ChocolateyFeedURLsConfigured {
		t.Fatalf("default chocolatey feeds = %v (configured=%v), want [%s] unconfigured", defaults.ChocolateyFeedURLs, defaults.ChocolateyFeedURLsConfigured, defaultChocolateyFeedURL)
	}

	explicit := latestRegistryConfig{ChocolateyFeedURLs: []string{"https://www.myget.org/F/vm-packages/api/v2/", " https://community.chocolatey.org/api/v2 ", "https://www.myget.org/F/vm-packages/api/v2"}}.withDefaults()
	if got := strings.Join(explicit.ChocolateyFeedURLs, ","); got != "https://www.myget.org/F/vm-packages/api/v2,https://community.chocolatey.org/api/v2" {
		t.Fatalf("explicit chocolatey feeds = %q, want trimmed, deduplicated, ordered list", got)
	}
	if !explicit.ChocolateyFeedURLsConfigured {
		t.Fatal("ChocolateyFeedURLsConfigured = false, want true for an explicit list")
	}
	if !latestRegistryMirrorConfigured(explicit, domain.EcosystemChocolatey) {
		t.Fatal("latestRegistryMirrorConfigured(chocolatey) = false, want true for explicit feeds")
	}

	fallback := latestRegistryConfig{ChocolateyFeedURLs: []string{"https://feeds.internal/api/v2"}, ChocolateyFeedURLsConfigured: true}
	merged := latestRegistryConfig{}.inheritFallback(fallback)
	if len(merged.ChocolateyFeedURLs) != 1 || merged.ChocolateyFeedURLs[0] != "https://feeds.internal/api/v2" || !merged.ChocolateyFeedURLsConfigured {
		t.Fatalf("inherited chocolatey feeds = %v (configured=%v), want fallback list", merged.ChocolateyFeedURLs, merged.ChocolateyFeedURLsConfigured)
	}
	merged.ChocolateyFeedURLs[0] = "https://evil.internal"
	if fallback.ChocolateyFeedURLs[0] != "https://feeds.internal/api/v2" {
		t.Fatal("inherited chocolatey feed list aliases the fallback")
	}
	own := latestRegistryConfig{ChocolateyFeedURLs: []string{"https://own.internal/api/v2"}}.inheritFallback(fallback)
	if len(own.ChocolateyFeedURLs) != 1 || own.ChocolateyFeedURLs[0] != "https://own.internal/api/v2" {
		t.Fatalf("own chocolatey feeds = %v, want the explicit list kept", own.ChocolateyFeedURLs)
	}

	cfg := cliRegistryConfig{ChocolateyFeedURLs: []string{"https://www.myget.org/F/vm-packages/api/v2", "http://127.0.0.1:8081/api/v2"}}
	if err := normalizeCLIRegistryConfig(&cfg); err != nil {
		t.Fatalf("normalizeCLIRegistryConfig(valid feeds) error = %v", err)
	}
	for _, bad := range []string{"http://feeds.example/api/v2", "https://user:pw@feeds.example/api/v2", "https://feeds.example/api/v2?x=1", "ftp://feeds.example"} {
		cfg := cliRegistryConfig{ChocolateyFeedURLs: []string{bad}}
		if err := normalizeCLIRegistryConfig(&cfg); err == nil || !strings.Contains(err.Error(), "registries.chocolatey_feed_urls") {
			t.Fatalf("normalizeCLIRegistryConfig(%q) error = %v, want chocolatey_feed_urls rejection", bad, err)
		}
	}

	var settings scanSettings
	applyCLIRegistryConfig(&settings, cliRegistryConfig{ChocolateyFeedURLs: []string{"https://a.internal/api/v2"}})
	applyCLIRegistryConfig(&settings, cliRegistryConfig{ChocolateyFeedURLs: []string{"https://b.internal/api/v2"}})
	if got := strings.Join(settings.LatestRegistry.ChocolateyFeedURLs, ","); got != "https://b.internal/api/v2" || !settings.LatestRegistry.ChocolateyFeedURLsConfigured {
		t.Fatalf("applied chocolatey feeds = %q, want the later config layer to replace the ordered list", got)
	}
}

func TestChocolateyFeedURLsEnvOverridesConfig(t *testing.T) {
	t.Setenv("PACKMON_CHOCOLATEY_FEED_URLS", " https://env-a.internal/api/v2 , https://env-b.internal/api/v2/ ")
	settings := scanSettings{LatestRegistry: latestRegistryConfig{ChocolateyFeedURLs: []string{"https://cfg.internal/api/v2"}, ChocolateyFeedURLsConfigured: true}}
	if err := applyLatestRegistryEnvSettings(&settings); err != nil {
		t.Fatalf("applyLatestRegistryEnvSettings() error = %v", err)
	}
	if got := strings.Join(settings.LatestRegistry.ChocolateyFeedURLs, ","); got != "https://env-a.internal/api/v2,https://env-b.internal/api/v2" {
		t.Fatalf("env chocolatey feeds = %q, want CSV env list to replace config", got)
	}

	t.Setenv("PACKMON_CHOCOLATEY_FEED_URLS", "http://insecure.internal/api/v2")
	if err := applyLatestRegistryEnvSettings(&settings); err == nil || !strings.Contains(err.Error(), "PACKMON_CHOCOLATEY_FEED_URLS") {
		t.Fatalf("applyLatestRegistryEnvSettings(insecure) error = %v, want rejection naming the variable", err)
	}
}
