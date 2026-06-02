package config

import (
	"reflect"
	"testing"
	"time"
)

func TestNormalizeAndParseFeedMode(t *testing.T) {
	if got := NormalizeFeedName("  OSV  "); got != "osv" {
		t.Fatalf("NormalizeFeedName() = %q, want osv", got)
	}

	for _, raw := range []string{"self", " SELF ", "external", "EXTERNAL"} {
		mode, err := ParseFeedMode(raw)
		if err != nil {
			t.Fatalf("ParseFeedMode(%q) error = %v", raw, err)
		}
		if raw[0] == 'e' || raw[0] == 'E' || raw[1] == 'E' {
			if mode != FeedModeExternal {
				t.Fatalf("ParseFeedMode(%q) = %q, want external", raw, mode)
			}
			continue
		}
		if mode != FeedModeSelf {
			t.Fatalf("ParseFeedMode(%q) = %q, want self", raw, mode)
		}
	}

	if _, err := ParseFeedMode("invalid"); err == nil {
		t.Fatal("ParseFeedMode(invalid) error = nil, want error")
	}
}

func TestFeedSettingsListAndEffectiveIntervals(t *testing.T) {
	cfg := &Config{
		FeedSync: FeedSyncConfig{Interval: 8 * time.Hour},
		Feeds: FeedsConfig{
			OSVEnabled:           true,
			GHSAEnabled:          true,
			OpenSSFEnabled:       true,
			VulnCheckEnabled:     true,
			CISAKEVEnabled:       true,
			EPSSEnabled:          true,
			NVDEnabled:           true,
			EndOfLifeEnabled:     true,
			SocketEnabled:        true,
			ReversingLabsEnabled: true,
			OSVMode:              FeedModeSelf,
			GHSAMode:             FeedModeExternal,
			OpenSSFMode:          FeedModeSelf,
			VulnCheckMode:        FeedModeExternal,
			CISAKEVMode:          FeedModeSelf,
			EPSSMode:             FeedModeSelf,
			NVDMode:              FeedModeExternal,
			EndOfLifeMode:        FeedModeSelf,
			SocketMode:           FeedModeExternal,
			ReversingLabsMode:    FeedModeSelf,
			OSVInterval:          30 * time.Minute,
			GHSAInterval:         time.Hour,
			VulnCheckInterval:    2 * time.Hour,
			EndOfLifeInterval:    3 * time.Hour,
			VulnCheckAPIKey:      "vc-token",
			NVDAPIKey:            "nvd-token",
			SocketAPIKey:         "socket-token",
			ReversingLabsAPIKey:  "rl-token",
		},
	}

	gotNames := make([]string, 0, len(cfg.FeedSettingsList()))
	for _, feed := range cfg.FeedSettingsList() {
		gotNames = append(gotNames, feed.Name)
	}
	wantNames := []string{"osv", "ghsa", "openssf", "vulncheck", "cisakev", "epss", "nvd", "endoflife", "socket", "reversinglabs"}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("FeedSettingsList names = %#v, want %#v", gotNames, wantNames)
	}

	tests := []struct {
		name     string
		wantName string
		wantKey  string
		wantAPI  bool
		wantSync bool
	}{
		{" OSV ", "osv", "", false, true},
		{"ghsa", "ghsa", "", false, true},
		{"openssf", "openssf", "", false, true},
		{"vulncheck", "vulncheck", "vc-token", true, true},
		{"cisakev", "cisakev", "", false, true},
		{"epss", "epss", "", false, true},
		{"nvd", "nvd", "nvd-token", false, true},
		{"endoflife", "endoflife", "", false, true},
		{"socket", "socket", "socket-token", true, false},
		{"reversinglabs", "reversinglabs", "rl-token", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.wantName, func(t *testing.T) {
			feed, ok := cfg.FeedSettings(tt.name)
			if !ok {
				t.Fatalf("FeedSettings(%q) ok = false, want true", tt.name)
			}
			if feed.Name != tt.wantName {
				t.Fatalf("FeedSettings(%q).Name = %q, want %q", tt.name, feed.Name, tt.wantName)
			}
			if feed.APIKey != tt.wantKey {
				t.Fatalf("FeedSettings(%q).APIKey = %q, want %q", tt.name, feed.APIKey, tt.wantKey)
			}
			if feed.RequiresAPIKey != tt.wantAPI {
				t.Fatalf("FeedSettings(%q).RequiresAPIKey = %v, want %v", tt.name, feed.RequiresAPIKey, tt.wantAPI)
			}
			if feed.SupportsSyncInterval != tt.wantSync {
				t.Fatalf("FeedSettings(%q).SupportsSyncInterval = %v, want %v", tt.name, feed.SupportsSyncInterval, tt.wantSync)
			}
		})
	}

	if _, ok := cfg.FeedSettings("unknown"); ok {
		t.Fatal("FeedSettings(unknown) ok = true, want false")
	}
	if got := (*Config)(nil).FeedSettingsList(); got != nil {
		t.Fatalf("nil Config FeedSettingsList = %#v, want nil", got)
	}
	if got := cfg.EffectiveFeedInterval("osv"); got != 30*time.Minute {
		t.Fatalf("EffectiveFeedInterval(osv) = %v, want 30m", got)
	}
	if got := cfg.EffectiveFeedInterval("epss"); got != 8*time.Hour {
		t.Fatalf("EffectiveFeedInterval(epss) = %v, want global interval", got)
	}
	if got := cfg.EffectiveFeedInterval("endoflife"); got != 3*time.Hour {
		t.Fatalf("EffectiveFeedInterval(endoflife) = %v, want 3h", got)
	}
	if got := cfg.EffectiveFeedInterval("socket"); got != 0 {
		t.Fatalf("EffectiveFeedInterval(socket) = %v, want 0", got)
	}
	if got := cfg.EffectiveFeedInterval("unknown"); got != 0 {
		t.Fatalf("EffectiveFeedInterval(unknown) = %v, want 0", got)
	}
}

func TestSetFeedSettingsUpdatesEveryFeed(t *testing.T) {
	cfg := &Config{}

	tests := []struct {
		feed FeedSettings
		want func(t *testing.T)
	}{
		{FeedSettings{Name: "osv", Enabled: true, Mode: FeedModeExternal, SyncInterval: -time.Second}, func(t *testing.T) {
			if !cfg.Feeds.OSVEnabled || cfg.Feeds.OSVMode != FeedModeExternal || cfg.Feeds.OSVInterval != 0 {
				t.Fatalf("OSV settings not applied: %#v", cfg.Feeds)
			}
		}},
		{FeedSettings{Name: "ghsa", Enabled: true, Mode: FeedModeSelf, SyncInterval: time.Hour}, func(t *testing.T) {
			if !cfg.Feeds.GHSAEnabled || cfg.Feeds.GHSAMode != FeedModeSelf || cfg.Feeds.GHSAInterval != time.Hour {
				t.Fatalf("GHSA settings not applied: %#v", cfg.Feeds)
			}
		}},
		{FeedSettings{Name: "openssf", Enabled: true, Mode: FeedModeExternal, SyncInterval: 2 * time.Hour}, func(t *testing.T) {
			if !cfg.Feeds.OpenSSFEnabled || cfg.Feeds.OpenSSFMode != FeedModeExternal || cfg.Feeds.OpenSSFInterval != 2*time.Hour {
				t.Fatalf("OpenSSF settings not applied: %#v", cfg.Feeds)
			}
		}},
		{FeedSettings{Name: "vulncheck", Enabled: true, Mode: FeedModeSelf, SyncInterval: 3 * time.Hour, APIKey: " vc "}, func(t *testing.T) {
			if !cfg.Feeds.VulnCheckEnabled || cfg.Feeds.VulnCheckMode != FeedModeSelf || cfg.Feeds.VulnCheckInterval != 3*time.Hour || cfg.Feeds.VulnCheckAPIKey != "vc" {
				t.Fatalf("VulnCheck settings not applied: %#v", cfg.Feeds)
			}
		}},
		{FeedSettings{Name: "cisakev", Enabled: true, Mode: FeedModeExternal, SyncInterval: 4 * time.Hour}, func(t *testing.T) {
			if !cfg.Feeds.CISAKEVEnabled || cfg.Feeds.CISAKEVMode != FeedModeExternal || cfg.Feeds.CISAKEVInterval != 4*time.Hour {
				t.Fatalf("CISA KEV settings not applied: %#v", cfg.Feeds)
			}
		}},
		{FeedSettings{Name: "epss", Enabled: true, Mode: FeedModeSelf, SyncInterval: 5 * time.Hour}, func(t *testing.T) {
			if !cfg.Feeds.EPSSEnabled || cfg.Feeds.EPSSMode != FeedModeSelf || cfg.Feeds.EPSSInterval != 5*time.Hour {
				t.Fatalf("EPSS settings not applied: %#v", cfg.Feeds)
			}
		}},
		{FeedSettings{Name: "nvd", Enabled: true, Mode: FeedModeExternal, SyncInterval: 6 * time.Hour, APIKey: " nvd "}, func(t *testing.T) {
			if !cfg.Feeds.NVDEnabled || cfg.Feeds.NVDMode != FeedModeExternal || cfg.Feeds.NVDInterval != 6*time.Hour || cfg.Feeds.NVDAPIKey != "nvd" {
				t.Fatalf("NVD settings not applied: %#v", cfg.Feeds)
			}
		}},
		{FeedSettings{Name: "endoflife", Enabled: true, Mode: FeedModeSelf, SyncInterval: 7 * time.Hour}, func(t *testing.T) {
			if !cfg.Feeds.EndOfLifeEnabled || cfg.Feeds.EndOfLifeMode != FeedModeSelf || cfg.Feeds.EndOfLifeInterval != 7*time.Hour {
				t.Fatalf("EndOfLife settings not applied: %#v", cfg.Feeds)
			}
		}},
		{FeedSettings{Name: "socket", Enabled: true, Mode: FeedModeExternal, APIKey: " socket "}, func(t *testing.T) {
			if !cfg.Feeds.SocketEnabled || cfg.Feeds.SocketMode != FeedModeExternal || cfg.Feeds.SocketAPIKey != "socket" {
				t.Fatalf("Socket settings not applied: %#v", cfg.Feeds)
			}
		}},
		{FeedSettings{Name: "reversinglabs", Enabled: true, Mode: FeedModeSelf, APIKey: " rl "}, func(t *testing.T) {
			if !cfg.Feeds.ReversingLabsEnabled || cfg.Feeds.ReversingLabsMode != FeedModeSelf || cfg.Feeds.ReversingLabsAPIKey != "rl" {
				t.Fatalf("ReversingLabs settings not applied: %#v", cfg.Feeds)
			}
		}},
	}

	for _, tt := range tests {
		if err := cfg.SetFeedSettings(tt.feed); err != nil {
			t.Fatalf("SetFeedSettings(%q) error = %v", tt.feed.Name, err)
		}
		tt.want(t)
	}

	if err := cfg.SetFeedSettings(FeedSettings{Name: "reversinglabs", Mode: FeedModeExternal}); err == nil {
		t.Fatal("SetFeedSettings(reversinglabs external) error = nil, want error")
	}
	if err := cfg.SetFeedSettings(FeedSettings{Name: "unknown", Mode: FeedModeSelf}); err == nil {
		t.Fatal("SetFeedSettings(unknown) error = nil, want error")
	}
	if err := cfg.SetFeedSettings(FeedSettings{Name: "osv", Mode: FeedMode("bad")}); err == nil {
		t.Fatal("SetFeedSettings(invalid mode) error = nil, want error")
	}
}

func TestRuntimeSettingsUpdateIgnoresEmptyValues(t *testing.T) {
	settings := NewRuntimeSettings("CRITICAL", 60, 10)
	if got := settings.BlockThreshold(); got != "CRITICAL" {
		t.Fatalf("BlockThreshold() = %q, want CRITICAL", got)
	}
	perMinute, burst := settings.RateLimit()
	if perMinute != 60 || burst != 10 {
		t.Fatalf("RateLimit() = (%d, %d), want (60, 10)", perMinute, burst)
	}

	settings.Update("", -1, 0)
	if got := settings.BlockThreshold(); got != "CRITICAL" {
		t.Fatalf("BlockThreshold after empty update = %q, want CRITICAL", got)
	}
	perMinute, burst = settings.RateLimit()
	if perMinute != 60 || burst != 10 {
		t.Fatalf("RateLimit after empty update = (%d, %d), want (60, 10)", perMinute, burst)
	}

	settings.Update("HIGH", 120, 30)
	if got := settings.BlockThreshold(); got != "HIGH" {
		t.Fatalf("BlockThreshold after update = %q, want HIGH", got)
	}
	perMinute, burst = settings.RateLimit()
	if perMinute != 120 || burst != 30 {
		t.Fatalf("RateLimit after update = (%d, %d), want (120, 30)", perMinute, burst)
	}
}
