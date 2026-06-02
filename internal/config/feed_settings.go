package config

import (
	"fmt"
	"strings"
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
	SupportsSyncInterval bool
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

// FeedSettings returns one feed's configuration.
func (c *Config) FeedSettings(name string) (FeedSettings, bool) {
	switch NormalizeFeedName(name) {
	case "osv":
		return FeedSettings{
			Name:                 "osv",
			DisplayName:          "OSV",
			Enabled:              c.Feeds.OSVEnabled,
			Mode:                 c.Feeds.OSVMode,
			SyncInterval:         c.Feeds.OSVInterval,
			SupportsSyncInterval: true,
		}, true
	case "ghsa":
		return FeedSettings{
			Name:                 "ghsa",
			DisplayName:          "GHSA",
			Enabled:              c.Feeds.GHSAEnabled,
			Mode:                 c.Feeds.GHSAMode,
			SyncInterval:         c.Feeds.GHSAInterval,
			SupportsSyncInterval: true,
		}, true
	case "openssf":
		return FeedSettings{
			Name:                 "openssf",
			DisplayName:          "OpenSSF Malicious",
			Enabled:              c.Feeds.OpenSSFEnabled,
			Mode:                 c.Feeds.OpenSSFMode,
			SyncInterval:         c.Feeds.OpenSSFInterval,
			SupportsSyncInterval: true,
		}, true
	case "vulncheck":
		return FeedSettings{
			Name:                 "vulncheck",
			DisplayName:          "VulnCheck",
			Enabled:              c.Feeds.VulnCheckEnabled,
			Mode:                 c.Feeds.VulnCheckMode,
			SyncInterval:         c.Feeds.VulnCheckInterval,
			APIKey:               c.Feeds.VulnCheckAPIKey,
			RequiresAPIKey:       true,
			SupportsSyncInterval: true,
		}, true
	case "cisakev":
		return FeedSettings{
			Name:                 "cisakev",
			DisplayName:          "CISA KEV",
			Enabled:              c.Feeds.CISAKEVEnabled,
			Mode:                 c.Feeds.CISAKEVMode,
			SyncInterval:         c.Feeds.CISAKEVInterval,
			SupportsSyncInterval: true,
		}, true
	case "epss":
		return FeedSettings{
			Name:                 "epss",
			DisplayName:          "EPSS",
			Enabled:              c.Feeds.EPSSEnabled,
			Mode:                 c.Feeds.EPSSMode,
			SyncInterval:         c.Feeds.EPSSInterval,
			SupportsSyncInterval: true,
		}, true
	case "nvd":
		return FeedSettings{
			Name:                 "nvd",
			DisplayName:          "NVD",
			Enabled:              c.Feeds.NVDEnabled,
			Mode:                 c.Feeds.NVDMode,
			SyncInterval:         c.Feeds.NVDInterval,
			APIKey:               c.Feeds.NVDAPIKey,
			RequiresAPIKey:       false,
			SupportsSyncInterval: true,
		}, true
	case "endoflife":
		return FeedSettings{
			Name:                 "endoflife",
			DisplayName:          "endoflife.date",
			Enabled:              c.Feeds.EndOfLifeEnabled,
			Mode:                 c.Feeds.EndOfLifeMode,
			SyncInterval:         c.Feeds.EndOfLifeInterval,
			SupportsSyncInterval: true,
		}, true
	case "socket":
		return FeedSettings{
			Name:                 "socket",
			DisplayName:          "Socket.dev",
			Enabled:              c.Feeds.SocketEnabled,
			Mode:                 c.Feeds.SocketMode,
			APIKey:               c.Feeds.SocketAPIKey,
			RequiresAPIKey:       true,
			SupportsSyncInterval: false,
		}, true
	case "reversinglabs":
		return FeedSettings{
			Name:                 "reversinglabs",
			DisplayName:          "ReversingLabs",
			Enabled:              c.Feeds.ReversingLabsEnabled,
			Mode:                 c.Feeds.ReversingLabsMode,
			APIKey:               c.Feeds.ReversingLabsAPIKey,
			RequiresAPIKey:       true,
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

// SetFeedSettings mutates the config for one feed.
func (c *Config) SetFeedSettings(feed FeedSettings) error {
	mode, err := ParseFeedMode(string(feed.Mode))
	if err != nil {
		return err
	}

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
		if mode == FeedModeExternal {
			return fmt.Errorf("endoflife does not support external mode")
		}
		c.Feeds.EndOfLifeEnabled = feed.Enabled
		c.Feeds.EndOfLifeMode = FeedModeSelf
		c.Feeds.EndOfLifeInterval = normalizeOptionalDuration(feed.SyncInterval)
	case "socket":
		c.Feeds.SocketEnabled = feed.Enabled
		c.Feeds.SocketMode = mode
		c.Feeds.SocketAPIKey = strings.TrimSpace(feed.APIKey)
	case "reversinglabs":
		if mode == FeedModeExternal {
			return fmt.Errorf("reversinglabs does not support external mode")
		}
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
