package config

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// FeedSettings describes one feed's runtime configuration.
type FeedSettings struct {
	Name                 string
	DisplayName          string
	Enabled              bool
	Mode                 FeedMode
	SyncInterval         time.Duration
	APIKey               string
	RequiresAPIKey       bool
	SupportsAPIKey       bool
	SupportsSyncInterval bool
	SupportsManualSync   bool
}

// FeedModeOption is one selectable feed mode for admin/UI rendering.
type FeedModeOption struct {
	Value FeedMode
	Label string
}

type feedDescriptor struct {
	Name                 string
	DisplayName          string
	RequiresAPIKey       bool
	SupportsAPIKey       bool
	SupportsExternalMode bool
	SupportsSyncInterval bool
	SupportsManualSync   bool
	Enabled              func(FeedsConfig) bool
	Mode                 func(FeedsConfig) FeedMode
	SyncInterval         func(FeedsConfig) time.Duration
	APIKey               func(FeedsConfig) string
}

// FeedSyncMinInterval is the minimum persisted self-managed provider sync
// interval accepted for feed-specific overrides.
const FeedSyncMinInterval = 15 * time.Minute

const (
	reversingLabsDefaultBaseURL = "https://data.reversinglabs.com/api/oss/community/v2/free"
	socketDefaultBaseURL        = "https://socket.dev/api/v1"
	vulnCheckDefaultBaseURL     = "https://api.vulncheck.com"
)

var feedDescriptors = []feedDescriptor{
	{
		Name:                 "osv",
		DisplayName:          "OSV",
		SupportsExternalMode: true,
		SupportsSyncInterval: true,
		SupportsManualSync:   true,
		Enabled:              func(feeds FeedsConfig) bool { return feeds.OSVEnabled },
		Mode:                 func(feeds FeedsConfig) FeedMode { return feeds.OSVMode },
		SyncInterval:         func(feeds FeedsConfig) time.Duration { return feeds.OSVInterval },
	},
	{
		Name:                 "ghsa",
		DisplayName:          "GHSA",
		SupportsExternalMode: true,
		SupportsSyncInterval: true,
		SupportsManualSync:   true,
		Enabled:              func(feeds FeedsConfig) bool { return feeds.GHSAEnabled },
		Mode:                 func(feeds FeedsConfig) FeedMode { return feeds.GHSAMode },
		SyncInterval:         func(feeds FeedsConfig) time.Duration { return feeds.GHSAInterval },
	},
	{
		Name:                 "openssf",
		DisplayName:          "OpenSSF Malicious",
		SupportsExternalMode: true,
		SupportsSyncInterval: true,
		SupportsManualSync:   true,
		Enabled:              func(feeds FeedsConfig) bool { return feeds.OpenSSFEnabled },
		Mode:                 func(feeds FeedsConfig) FeedMode { return feeds.OpenSSFMode },
		SyncInterval:         func(feeds FeedsConfig) time.Duration { return feeds.OpenSSFInterval },
	},
	{
		Name:                 "vulncheck",
		DisplayName:          "VulnCheck",
		RequiresAPIKey:       true,
		SupportsAPIKey:       true,
		SupportsExternalMode: true,
		SupportsSyncInterval: true,
		SupportsManualSync:   true,
		Enabled:              func(feeds FeedsConfig) bool { return feeds.VulnCheckEnabled },
		Mode:                 func(feeds FeedsConfig) FeedMode { return feeds.VulnCheckMode },
		SyncInterval:         func(feeds FeedsConfig) time.Duration { return feeds.VulnCheckInterval },
		APIKey:               func(feeds FeedsConfig) string { return feeds.VulnCheckAPIKey },
	},
	{
		Name:                 "cisakev",
		DisplayName:          "CISA KEV",
		SupportsExternalMode: true,
		SupportsSyncInterval: true,
		SupportsManualSync:   true,
		Enabled:              func(feeds FeedsConfig) bool { return feeds.CISAKEVEnabled },
		Mode:                 func(feeds FeedsConfig) FeedMode { return feeds.CISAKEVMode },
		SyncInterval:         func(feeds FeedsConfig) time.Duration { return feeds.CISAKEVInterval },
	},
	{
		Name:                 "epss",
		DisplayName:          "EPSS",
		SupportsExternalMode: true,
		SupportsSyncInterval: true,
		SupportsManualSync:   true,
		Enabled:              func(feeds FeedsConfig) bool { return feeds.EPSSEnabled },
		Mode:                 func(feeds FeedsConfig) FeedMode { return feeds.EPSSMode },
		SyncInterval:         func(feeds FeedsConfig) time.Duration { return feeds.EPSSInterval },
	},
	{
		Name:                 "nvd",
		DisplayName:          "NVD",
		SupportsAPIKey:       true,
		SupportsSyncInterval: true,
		SupportsManualSync:   true,
		Enabled:              func(feeds FeedsConfig) bool { return feeds.NVDEnabled },
		Mode:                 func(feeds FeedsConfig) FeedMode { return feeds.NVDMode },
		SyncInterval:         func(feeds FeedsConfig) time.Duration { return feeds.NVDInterval },
		APIKey:               func(feeds FeedsConfig) string { return feeds.NVDAPIKey },
	},
	{
		Name:                 "endoflife",
		DisplayName:          "endoflife.date",
		SupportsSyncInterval: true,
		SupportsManualSync:   true,
		Enabled:              func(feeds FeedsConfig) bool { return feeds.EndOfLifeEnabled },
		Mode:                 func(feeds FeedsConfig) FeedMode { return feeds.EndOfLifeMode },
		SyncInterval:         func(feeds FeedsConfig) time.Duration { return feeds.EndOfLifeInterval },
	},
	{
		Name:                 "socket",
		DisplayName:          "Socket.dev",
		RequiresAPIKey:       true,
		SupportsAPIKey:       true,
		SupportsExternalMode: true,
		Enabled:              func(feeds FeedsConfig) bool { return feeds.SocketEnabled },
		Mode:                 func(feeds FeedsConfig) FeedMode { return feeds.SocketMode },
		APIKey:               func(feeds FeedsConfig) string { return feeds.SocketAPIKey },
	},
	{
		Name:           "reversinglabs",
		DisplayName:    "ReversingLabs",
		RequiresAPIKey: true,
		SupportsAPIKey: true,
		Enabled:        func(feeds FeedsConfig) bool { return feeds.ReversingLabsEnabled },
		Mode:           func(feeds FeedsConfig) FeedMode { return feeds.ReversingLabsMode },
		APIKey:         func(feeds FeedsConfig) string { return feeds.ReversingLabsAPIKey },
	},
}

var feedDescriptorsByName = func() map[string]feedDescriptor {
	out := make(map[string]feedDescriptor, len(feedDescriptors))
	for _, descriptor := range feedDescriptors {
		out[descriptor.Name] = descriptor
	}
	return out
}()

var configFeedLockInit sync.Mutex

func (c *Config) feedLock() *sync.RWMutex {
	configFeedLockInit.Lock()
	defer configFeedLockInit.Unlock()
	if c.feedsMu == nil {
		c.feedsMu = &sync.RWMutex{}
	}
	return c.feedsMu
}

// NormalizeFeedName canonicalizes a feed key used across config, DB, and UI.
func NormalizeFeedName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ParseFeedMode validates and normalizes a feed mode.
func ParseFeedMode(raw string) (FeedMode, error) {
	if mode, ok := domain.ParseFeedMode(raw); ok {
		return mode, nil
	}
	return "", fmt.Errorf("invalid feed mode %q", raw)
}

// FeedModeOptions returns selectable feed modes for a feed capability set.
func FeedModeOptions(supportsExternal bool) []FeedModeOption {
	modes := []FeedMode{FeedModeSelf}
	if supportsExternal {
		modes = domain.FeedModeValues()
	}
	options := make([]FeedModeOption, 0, len(modes))
	for _, mode := range modes {
		options = append(options, FeedModeOption{
			Value: mode,
			Label: string(mode),
		})
	}
	return options
}

func lookupFeedDescriptor(name string) (feedDescriptor, bool) {
	descriptor, ok := feedDescriptorsByName[NormalizeFeedName(name)]
	return descriptor, ok
}

func (d feedDescriptor) settings(feeds FeedsConfig) FeedSettings {
	settings := FeedSettings{
		Name:                 d.Name,
		DisplayName:          d.DisplayName,
		RequiresAPIKey:       d.RequiresAPIKey,
		SupportsAPIKey:       d.SupportsAPIKey,
		SupportsSyncInterval: d.SupportsSyncInterval,
		SupportsManualSync:   d.SupportsManualSync,
	}
	if d.Enabled != nil {
		settings.Enabled = d.Enabled(feeds)
	}
	if d.Mode != nil {
		settings.Mode = d.Mode(feeds)
	}
	if d.SyncInterval != nil {
		settings.SyncInterval = d.SyncInterval(feeds)
	}
	if d.APIKey != nil {
		settings.APIKey = d.APIKey(feeds)
	}
	return settings
}

// FeedSupportsExternalMode reports whether Packmon has an import/API path for
// externally managed data for the named feed.
func FeedSupportsExternalMode(name string) bool {
	descriptor, ok := lookupFeedDescriptor(name)
	return ok && descriptor.SupportsExternalMode
}

// FeedExternalModeNames returns the canonical feed names that can be supplied
// by an external importer.
func FeedExternalModeNames() []string {
	out := make([]string, 0, len(feedDescriptors))
	for _, descriptor := range feedDescriptors {
		if descriptor.SupportsExternalMode {
			out = append(out, descriptor.Name)
		}
	}
	return out
}

func feedSupportsSyncInterval(name string) bool {
	descriptor, ok := lookupFeedDescriptor(name)
	return ok && descriptor.SupportsSyncInterval
}

// FeedsSnapshot returns a consistent copy of the mutable feed configuration.
func (c *Config) FeedsSnapshot() FeedsConfig {
	if c == nil {
		return FeedsConfig{}
	}
	mu := c.feedLock()
	mu.RLock()
	defer mu.RUnlock()
	feeds := c.Feeds
	feeds.ReversingLabsExcludedNamespaces = append([]string(nil), c.Feeds.ReversingLabsExcludedNamespaces...)
	feeds.SocketExcludedNamespaces = append([]string(nil), c.Feeds.SocketExcludedNamespaces...)
	return feeds
}

// FeedSettings returns one feed's configuration.
func (c *Config) FeedSettings(name string) (FeedSettings, bool) {
	if c == nil {
		return FeedSettings{}, false
	}
	feeds := c.FeedsSnapshot()

	descriptor, ok := lookupFeedDescriptor(name)
	if !ok {
		return FeedSettings{}, false
	}
	return descriptor.settings(feeds), true
}

// FeedSettingsList returns all known feeds in UI/runtime order.
func (c *Config) FeedSettingsList() []FeedSettings {
	if c == nil {
		return nil
	}

	feeds := c.FeedsSnapshot()
	out := make([]FeedSettings, 0, len(feedDescriptors))
	for _, descriptor := range feedDescriptors {
		out = append(out, descriptor.settings(feeds))
	}
	return out
}

// EffectiveFeedInterval returns the interval a feed will use at runtime. A
// zero result means the feed does not use periodic sync scheduling.
func (c *Config) EffectiveFeedInterval(name string) time.Duration {
	feed, ok := c.FeedSettings(name)
	if !ok || !feed.SupportsSyncInterval {
		return 0
	}
	if feed.SyncInterval > 0 {
		return feed.SyncInterval
	}
	return c.FeedSync.Interval
}

func ValidateFeedSettings(feed FeedSettings) error {
	_, err := validateFeedSettings(feed)
	return err
}

func validateFeedSettings(feed FeedSettings) (FeedMode, error) {
	mode, err := ParseFeedMode(string(feed.Mode))
	if err != nil {
		return "", err
	}
	name := NormalizeFeedName(feed.Name)
	descriptor, ok := lookupFeedDescriptor(name)
	if !ok {
		return "", fmt.Errorf("unknown feed %q", feed.Name)
	}
	if mode == FeedModeExternal && !descriptor.SupportsExternalMode {
		return "", fmt.Errorf("%s does not support external mode", name)
	}
	if mode == FeedModeSelf && descriptor.SupportsSyncInterval && feed.SyncInterval > 0 && feed.SyncInterval < FeedSyncMinInterval {
		return "", fmt.Errorf("%s sync interval must be at least %s", name, FeedSyncMinInterval)
	}
	return mode, nil
}

// SetFeedSettings mutates the config for one feed.
func (c *Config) SetFeedSettings(feed FeedSettings) error {
	if c == nil {
		return fmt.Errorf("nil config")
	}
	mode, err := validateFeedSettings(feed)
	if err != nil {
		return err
	}

	mu := c.feedLock()
	mu.Lock()
	defer mu.Unlock()

	switch NormalizeFeedName(feed.Name) {
	case "osv":
		c.Feeds.OSVEnabled = feed.Enabled
		c.Feeds.OSVMode = mode
		c.Feeds.OSVInterval = normalizeOptionalDuration(feed.SyncInterval)
	case "ghsa":
		c.Feeds.GHSAEnabled = feed.Enabled
		c.Feeds.GHSAMode = mode
		c.Feeds.GHSAInterval = normalizeOptionalDuration(feed.SyncInterval)
	case "openssf":
		c.Feeds.OpenSSFEnabled = feed.Enabled
		c.Feeds.OpenSSFMode = mode
		c.Feeds.OpenSSFInterval = normalizeOptionalDuration(feed.SyncInterval)
	case "vulncheck":
		c.Feeds.VulnCheckEnabled = feed.Enabled
		c.Feeds.VulnCheckMode = mode
		c.Feeds.VulnCheckInterval = normalizeOptionalDuration(feed.SyncInterval)
		c.Feeds.VulnCheckAPIKey = strings.TrimSpace(feed.APIKey)
	case "cisakev":
		c.Feeds.CISAKEVEnabled = feed.Enabled
		c.Feeds.CISAKEVMode = mode
		c.Feeds.CISAKEVInterval = normalizeOptionalDuration(feed.SyncInterval)
	case "epss":
		c.Feeds.EPSSEnabled = feed.Enabled
		c.Feeds.EPSSMode = mode
		c.Feeds.EPSSInterval = normalizeOptionalDuration(feed.SyncInterval)
	case "nvd":
		c.Feeds.NVDEnabled = feed.Enabled
		c.Feeds.NVDMode = mode
		c.Feeds.NVDInterval = normalizeOptionalDuration(feed.SyncInterval)
		c.Feeds.NVDAPIKey = strings.TrimSpace(feed.APIKey)
	case "endoflife":
		c.Feeds.EndOfLifeEnabled = feed.Enabled
		c.Feeds.EndOfLifeMode = FeedModeSelf
		c.Feeds.EndOfLifeInterval = normalizeOptionalDuration(feed.SyncInterval)
	case "socket":
		c.Feeds.SocketEnabled = feed.Enabled
		c.Feeds.SocketMode = mode
		c.Feeds.SocketAPIKey = strings.TrimSpace(feed.APIKey)
	case "reversinglabs":
		apiKey := strings.TrimSpace(feed.APIKey)
		baseURL := strings.TrimSpace(c.Feeds.ReversingLabsBaseURL)
		if baseURL == "" {
			baseURL = reversingLabsDefaultBaseURL
		}
		if err := validateReversingLabsBaseURL(apiKey, baseURL); err != nil {
			return err
		}
		c.Feeds.ReversingLabsEnabled = feed.Enabled
		c.Feeds.ReversingLabsMode = FeedModeSelf
		c.Feeds.ReversingLabsAPIKey = apiKey
		c.Feeds.ReversingLabsBaseURL = baseURL
	default:
		return fmt.Errorf("unknown feed %q", feed.Name)
	}

	return nil
}

func normalizeOptionalDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return d
}
