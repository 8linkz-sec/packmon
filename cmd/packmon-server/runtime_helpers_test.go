package main

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
)

// TestWarnIfMetricsEndpointExposedOnlyWarnsOffLocalhost covers the startup
// warning for the metrics listener. Metrics carry operational detail and are
// unauthenticated, so binding them publicly must be called out -- but warning on
// the safe default would train operators to ignore the message.
func TestWarnIfMetricsEndpointExposedOnlyWarnsOffLocalhost(t *testing.T) {
	t.Parallel()

	for _, host := range []string{"", "127.0.0.1", "::1", "localhost", "  LOCALHOST  "} {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
		cfg := &config.Config{}
		cfg.Metrics.Host = host

		warnIfMetricsEndpointExposed(cfg, logger)
		if buf.Len() != 0 {
			t.Errorf("host %q produced a warning: %s", host, buf.String())
		}
	}

	for _, host := range []string{"0.0.0.0", "::", "10.0.0.5", "metrics.internal"} {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
		cfg := &config.Config{}
		cfg.Metrics.Host = host
		cfg.Metrics.Port = 9090

		warnIfMetricsEndpointExposed(cfg, logger)
		if buf.Len() == 0 {
			t.Errorf("host %q produced no warning", host)
			continue
		}
		if !strings.Contains(buf.String(), host) {
			t.Errorf("warning for %q does not name the host: %s", host, buf.String())
		}
	}
}

// TestRuntimePostgresPoolConfigCarriesEveryLimit covers the pool translation.
// A dropped limit would silently fall back to the driver default, which is how a
// connection-starved server ends up with an unbounded pool.
func TestRuntimePostgresPoolConfigCarriesEveryLimit(t *testing.T) {
	t.Parallel()

	if got := runtimePostgresPoolConfig(nil); got == nil {
		t.Fatal("runtimePostgresPoolConfig(nil) = nil, want an empty config")
	} else if got.MaxConns != 0 || got.MinConns != 0 || got.ConnectTimeout != 0 {
		t.Fatalf("runtimePostgresPoolConfig(nil) = %+v, want the zero value", got)
	}

	cfg := &config.Config{}
	cfg.DB.MaxConns = 25
	cfg.DB.MinConns = 5
	cfg.DB.ConnectTimeout = 7 * time.Second

	got := runtimePostgresPoolConfig(cfg)
	if got.MaxConns != 25 || got.MinConns != 5 || got.ConnectTimeout != 7*time.Second {
		t.Fatalf("pool config = %+v, want every limit carried over", got)
	}
}

// TestWithConfiguredFatalLoggerAttachesALoggerOnce covers the wrapper that lets a
// startup failure be logged through the configured logger instead of bare
// stderr. Wrapping twice would nest the error and lose the first logger.
func TestWithConfiguredFatalLoggerAttachesALoggerOnce(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	inner := errors.New("transport security is not configured")

	if got := withConfiguredFatalLogger(nil, logger); got != nil {
		t.Errorf("withConfiguredFatalLogger(nil error) = %v, want nil", got)
	}
	if got := withConfiguredFatalLogger(inner, nil); !errors.Is(got, inner) {
		t.Errorf("withConfiguredFatalLogger(nil logger) = %v, want the error unchanged", got)
	}

	wrapped := withConfiguredFatalLogger(inner, logger)
	var fatal *configuredFatalError
	if !errors.As(wrapped, &fatal) {
		t.Fatalf("withConfiguredFatalLogger = %v, want a configuredFatalError", wrapped)
	}
	if !errors.Is(wrapped, inner) {
		t.Error("the wrapped error no longer matches its cause")
	}

	// A second wrap must return the same error rather than nest.
	again := withConfiguredFatalLogger(wrapped, slog.New(slog.DiscardHandler))
	if again != wrapped {
		t.Fatal("a second wrap created another layer")
	}
}

// TestLogFatalErrorPrefersTheConfiguredLogger covers the reporting side. Once a
// logger is configured the failure belongs in the structured log; before that,
// stderr is the only place an operator will see it.
func TestLogFatalErrorPrefersTheConfiguredLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))
	inner := errors.New("database is unreachable")

	logFatalError("packmon-server", "startup failed", withConfiguredFatalLogger(inner, logger))
	if buf.Len() == 0 {
		t.Fatal("nothing was written to the configured logger")
	}
	if !strings.Contains(buf.String(), "startup failed") {
		t.Errorf("log line = %q, want the message", buf.String())
	}
	if !strings.Contains(buf.String(), "database is unreachable") {
		t.Errorf("log line = %q, want the cause", buf.String())
	}
}

// testFeedAPIKey stands in for a configured feed credential. The guard under test
// only checks whether the value is blank, so any non-empty string does -- but a
// literal here trips the hardcoded-credentials scanner.
const testFeedAPIKey = "configured-value"

// TestAsyncWorkerDescriptorAPIKeyConfiguredTreatsBlankAsMissing covers the guard
// that decides whether an async worker starts. A worker started without its key
// would fail every request and mark the feed as broken, so a blank key has to
// read as "not configured" rather than as an empty-but-present one.
func TestAsyncWorkerDescriptorAPIKeyConfiguredTreatsBlankAsMissing(t *testing.T) {
	t.Parallel()

	// A descriptor with no key accessor needs no key at all.
	if !(asyncWorkerDescriptor{}).apiKeyConfigured(config.FeedsConfig{}) {
		t.Error("a descriptor without an API key accessor reported a missing key")
	}

	descriptor := asyncWorkerDescriptor{
		apiKey: func(feeds config.FeedsConfig) string { return feeds.SocketAPIKey },
	}
	for _, key := range []string{"", "   ", "\t\n"} {
		if descriptor.apiKeyConfigured(config.FeedsConfig{SocketAPIKey: key}) {
			t.Errorf("blank API key %q was accepted as configured", key)
		}
	}
	if !descriptor.apiKeyConfigured(config.FeedsConfig{SocketAPIKey: testFeedAPIKey}) {
		t.Error("a configured API key was reported as missing")
	}
}

// TestRuntimeFeedConfigSignatureDetectsEveryReconfigurableField covers the change
// detector for live feed reconfiguration. Two configurations that differ in any
// applied setting must produce different signatures, otherwise an admin edit is
// saved but never applied to the running syncer.
func TestRuntimeFeedConfigSignatureDetectsEveryReconfigurableField(t *testing.T) {
	t.Parallel()

	base := config.FeedSettings{
		Name:                 "socket",
		Enabled:              true,
		Mode:                 config.FeedModeSelf,
		APIKey:               "sk-1",
		SupportsSyncInterval: true,
		SyncInterval:         time.Hour,
	}
	feeds := config.FeedsConfig{SocketExcludedNamespaces: []string{"@internal"}}
	cfg := &config.Config{}

	signature := runtimeFeedConfigSignature(cfg, feeds, base)

	for _, tc := range []struct {
		name     string
		settings config.FeedSettings
		feeds    config.FeedsConfig
	}{
		{name: "enabled", settings: withFeedSettings(base, func(s *config.FeedSettings) { s.Enabled = false }), feeds: feeds},
		{name: "mode", settings: withFeedSettings(base, func(s *config.FeedSettings) { s.Mode = config.FeedModeExternal }), feeds: feeds},
		{name: "api key", settings: withFeedSettings(base, func(s *config.FeedSettings) { s.APIKey = "sk-2" }), feeds: feeds},
		{name: "sync interval", settings: withFeedSettings(base, func(s *config.FeedSettings) { s.SyncInterval = 2 * time.Hour }), feeds: feeds},
		{
			name:     "excluded namespaces",
			settings: base,
			feeds:    config.FeedsConfig{SocketExcludedNamespaces: []string{"@internal", "@other"}},
		},
	} {
		changed := runtimeFeedConfigSignature(cfg, tc.feeds, tc.settings)
		if equalRuntimeFeedConfig(signature, changed) {
			t.Errorf("changing %s produced an identical signature", tc.name)
		}
	}

	// The same input must produce the same signature, or every reconciliation
	// would restart every feed.
	if !equalRuntimeFeedConfig(signature, runtimeFeedConfigSignature(cfg, feeds, base)) {
		t.Error("the signature is not stable for identical input")
	}
}

// TestRuntimeFeedConfigSignatureIgnoresUnsupportedIntervals covers the guard on
// feeds that have no sync interval: recording one would make the signature
// change on a setting the feed never applies.
func TestRuntimeFeedConfigSignatureIgnoresUnsupportedIntervals(t *testing.T) {
	t.Parallel()

	settings := config.FeedSettings{
		Name:                 "cisa_kev",
		Enabled:              true,
		Mode:                 config.FeedModeSelf,
		SupportsSyncInterval: false,
		SyncInterval:         time.Hour,
	}
	signature := runtimeFeedConfigSignature(&config.Config{}, config.FeedsConfig{}, settings)
	if signature.syncInterval != 0 {
		t.Fatalf("syncInterval = %v, want it ignored for a feed without interval support", signature.syncInterval)
	}
}

// TestRuntimeFeedConfigSignatureFallsBackToTheGlobalInterval covers the default:
// a feed that supports an interval but has none configured inherits the global
// one, so the signature must reflect what actually runs.
func TestRuntimeFeedConfigSignatureFallsBackToTheGlobalInterval(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.FeedSync.Interval = 6 * time.Hour

	signature := runtimeFeedConfigSignature(cfg, config.FeedsConfig{}, config.FeedSettings{
		Name:                 "osv",
		Enabled:              true,
		Mode:                 config.FeedModeSelf,
		SupportsSyncInterval: true,
	})
	if signature.syncInterval != 6*time.Hour {
		t.Fatalf("syncInterval = %v, want the global fallback", signature.syncInterval)
	}
}

// TestRuntimeFeedConfigSignatureNormalisesTheFeedName keeps two spellings of the
// same feed from looking like different feeds to the reconciler.
func TestRuntimeFeedConfigSignatureNormalisesTheFeedName(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	lower := runtimeFeedConfigSignature(cfg, config.FeedsConfig{}, config.FeedSettings{Name: "socket"})
	upper := runtimeFeedConfigSignature(cfg, config.FeedsConfig{}, config.FeedSettings{Name: "  SOCKET  "})

	if lower.name != upper.name {
		t.Fatalf("names = %q and %q, want both normalised", lower.name, upper.name)
	}
}

func withFeedSettings(base config.FeedSettings, mutate func(*config.FeedSettings)) config.FeedSettings {
	out := base
	mutate(&out)
	return out
}

// equalRuntimeFeedConfig compares two signatures including their slice fields,
// which a plain == cannot do.
func equalRuntimeFeedConfig(a, b runtimeFeedConfig) bool {
	if a.name != b.name || a.enabled != b.enabled || a.mode != b.mode || a.apiKey != b.apiKey ||
		a.syncInterval != b.syncInterval || a.reversingLabsBaseURL != b.reversingLabsBaseURL ||
		a.reversingLabsLookupTTL != b.reversingLabsLookupTTL ||
		a.reversingLabsBatchSize != b.reversingLabsBatchSize ||
		a.reversingLabsCacheRetention != b.reversingLabsCacheRetention {
		return false
	}
	return equalStringSlices(a.reversingLabsExcludedNS, b.reversingLabsExcludedNS) &&
		equalStringSlices(a.socketExcludedNS, b.socketExcludedNS)
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
