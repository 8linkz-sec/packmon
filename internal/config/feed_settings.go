package config

import (
	"fmt"
	"strings"
	"sync"
	"time"
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

// FeedSyncMinInterval is the minimum persisted self-managed provider sync
// interval accepted for feed-specific overrides.
const FeedSyncMinInterval = 15 * time.Minute

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
	switch FeedMode(strings.ToLower(strings.TrimSpace(raw))) {
	case FeedModeSelf:
		return FeedModeSelf, nil
	case FeedModeExternal:
		return FeedModeExternal, nil
	default:
		return "", fmt.Errorf("invalid feed mode %q", raw)
	}
}

// FeedSupportsExternalMode reports whether Packmon has an import/API path for
// externally managed data for the named feed.
func FeedSupportsExternalMode(name string) bool {
	switch NormalizeFeedName(name) {
	case "osv", "ghsa", "openssf", "vulncheck", "cisakev", "epss", "socket":
		return true
	default:
		return false
	}
}

func feedSupportsSyncInterval(name string) bool {
	switch NormalizeFeedName(name) {
	case "osv", "ghsa", "openssf", "vulncheck", "cisakev", "epss", "nvd", "endoflife":
		return true
	default:
		return false
	}
}

// FeedSupportsManualSync reports whether the feed manager registers a syncer
// that can be triggered on demand from the admin UI.
func FeedSupportsManualSync(name string) bool {
	return feedSupportsSyncInterval(name)
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
	return feeds
}

// FeedSettings returns one feed's configuration.
func (c *Config) FeedSettings(name string) (FeedSettings, bool) {
	if c == nil {
		return FeedSettings{}, false
	}
	feeds := c.FeedsSnapshot()

	switch NormalizeFeedName(name) {
	case "osv":
		return FeedSettings{
			Name:                 "osv",
			DisplayName:          "OSV",
			Enabled:              feeds.OSVEnabled,
			Mode:                 feeds.OSVMode,
			SyncInterval:         feeds.OSVInterval,
			SupportsSyncInterval: true,
			SupportsManualSync:   true,
		}, true
	case "ghsa":
		return FeedSettings{
			Name:                 "ghsa",
			DisplayName:          "GHSA",
			Enabled:              feeds.GHSAEnabled,
			Mode:                 feeds.GHSAMode,
			SyncInterval:         feeds.GHSAInterval,
			SupportsSyncInterval: true,
			SupportsManualSync:   true,
		}, true
	case "openssf":
		return FeedSettings{
			Name:                 "openssf",
			DisplayName:          "OpenSSF Malicious",
			Enabled:              feeds.OpenSSFEnabled,
			Mode:                 feeds.OpenSSFMode,
			SyncInterval:         feeds.OpenSSFInterval,
			SupportsSyncInterval: true,
			SupportsManualSync:   true,
		}, true
	case "vulncheck":
		return FeedSettings{
			Name:                 "vulncheck",
			DisplayName:          "VulnCheck",
			Enabled:              feeds.VulnCheckEnabled,
			Mode:                 feeds.VulnCheckMode,
			SyncInterval:         feeds.VulnCheckInterval,
			APIKey:               feeds.VulnCheckAPIKey,
			RequiresAPIKey:       true,
			SupportsAPIKey:       true,
			SupportsSyncInterval: true,
			SupportsManualSync:   true,
		}, true
	case "cisakev":
		return FeedSettings{
			Name:                 "cisakev",
			DisplayName:          "CISA KEV",
			Enabled:              feeds.CISAKEVEnabled,
			Mode:                 feeds.CISAKEVMode,
			SyncInterval:         feeds.CISAKEVInterval,
			SupportsSyncInterval: true,
			SupportsManualSync:   true,
		}, true
	case "epss":
		return FeedSettings{
			Name:                 "epss",
			DisplayName:          "EPSS",
			Enabled:              feeds.EPSSEnabled,
			Mode:                 feeds.EPSSMode,
			SyncInterval:         feeds.EPSSInterval,
			SupportsSyncInterval: true,
			SupportsManualSync:   true,
		}, true
	case "nvd":
		return FeedSettings{
			Name:                 "nvd",
			DisplayName:          "NVD",
			Enabled:              feeds.NVDEnabled,
			Mode:                 feeds.NVDMode,
			SyncInterval:         feeds.NVDInterval,
			APIKey:               feeds.NVDAPIKey,
			RequiresAPIKey:       false,
			SupportsAPIKey:       true,
			SupportsSyncInterval: true,
			SupportsManualSync:   true,
		}, true
	case "endoflife":
		return FeedSettings{
			Name:                 "endoflife",
			DisplayName:          "endoflife.date",
			Enabled:              feeds.EndOfLifeEnabled,
			Mode:                 feeds.EndOfLifeMode,
			SyncInterval:         feeds.EndOfLifeInterval,
			SupportsSyncInterval: true,
			SupportsManualSync:   true,
		}, true
	case "socket":
		return FeedSettings{
			Name:                 "socket",
			DisplayName:          "Socket.dev",
			Enabled:              feeds.SocketEnabled,
			Mode:                 feeds.SocketMode,
			APIKey:               feeds.SocketAPIKey,
			RequiresAPIKey:       true,
			SupportsAPIKey:       true,
			SupportsSyncInterval: false,
		}, true
	case "reversinglabs":
		return FeedSettings{
			Name:                 "reversinglabs",
			DisplayName:          "ReversingLabs",
			Enabled:              feeds.ReversingLabsEnabled,
			Mode:                 feeds.ReversingLabsMode,
			APIKey:               feeds.ReversingLabsAPIKey,
			RequiresAPIKey:       true,
			SupportsAPIKey:       true,
			SupportsSyncInterval: false,
		}, true
	default:
		return FeedSettings{}, false
	}
}

// FeedSettingsList returns all known feeds in UI/runtime order.
func (c *Config) FeedSettingsList() []FeedSettings {
	if c == nil {
		return nil
	}

	names := []string{"osv", "ghsa", "openssf", "vulncheck", "cisakev", "epss", "nvd", "endoflife", "socket", "reversinglabs"}
	out := make([]FeedSettings, 0, len(names))
	for _, name := range names {
		feed, ok := c.FeedSettings(name)
		if ok {
			out = append(out, feed)
		}
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
	switch name {
	case "osv", "ghsa", "openssf", "vulncheck", "cisakev", "epss", "nvd", "endoflife", "socket", "reversinglabs":
		if mode == FeedModeExternal && !FeedSupportsExternalMode(name) {
			return "", fmt.Errorf("%s does not support external mode", name)
		}
		if mode == FeedModeSelf && feedSupportsSyncInterval(name) && feed.SyncInterval > 0 && feed.SyncInterval < FeedSyncMinInterval {
			return "", fmt.Errorf("%s sync interval must be at least %s", name, FeedSyncMinInterval)
		}
		return mode, nil
	default:
		return "", fmt.Errorf("unknown feed %q", feed.Name)
	}
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
		c.Feeds.ReversingLabsEnabled = feed.Enabled
		c.Feeds.ReversingLabsMode = FeedModeSelf
		c.Feeds.ReversingLabsAPIKey = strings.TrimSpace(feed.APIKey)
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
