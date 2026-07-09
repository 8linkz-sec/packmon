package admin

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
)

func TestParseFeedSettingsFormAppliesFieldsAndAPIKeyActions(t *testing.T) {
	t.Parallel()

	base := config.FeedSettings{
		Name:                 "vulncheck",
		Enabled:              true,
		Mode:                 config.FeedModeExternal,
		SyncInterval:         30 * time.Minute,
		APIKey:               "old-key",
		SupportsAPIKey:       true,
		SupportsSyncInterval: true,
	}

	got, err := parseFeedSettingsForm(base, url.Values{
		"enabled":       {"on"},
		"mode":          {"self"},
		"sync_interval": {"45m"},
		"api_key":       {"  new-key  "},
	})
	if err != nil {
		t.Fatalf("parseFeedSettingsForm(new key) error = %v", err)
	}
	if !got.Enabled || got.Mode != config.FeedModeSelf || got.SyncInterval != 45*time.Minute || got.APIKey != "new-key" {
		t.Fatalf("parsed new-key feed = %+v, want enabled self 45m with trimmed key", got)
	}

	got, err = parseFeedSettingsForm(base, url.Values{
		"mode": {"external"},
	})
	if err != nil {
		t.Fatalf("parseFeedSettingsForm(preserve key) error = %v", err)
	}
	if got.Enabled || got.Mode != config.FeedModeExternal || got.SyncInterval != 0 || got.APIKey != "old-key" {
		t.Fatalf("parsed preserved-key feed = %+v, want disabled external with old key and default interval", got)
	}

	got, err = parseFeedSettingsForm(base, url.Values{
		"enabled":               {"on"},
		"mode":                  {"self"},
		"clear_api_key":         {"on"},
		"confirm_clear_api_key": {"on"},
	})
	if err != nil {
		t.Fatalf("parseFeedSettingsForm(clear key) error = %v", err)
	}
	if !got.Enabled || got.Mode != config.FeedModeSelf || got.APIKey != "" {
		t.Fatalf("parsed cleared-key feed = %+v, want enabled self with empty key", got)
	}
}

func TestParseFeedSettingsFormRejectsAmbiguousAPIKeyActions(t *testing.T) {
	t.Parallel()

	base := config.FeedSettings{
		Name:           "vulncheck",
		Mode:           config.FeedModeSelf,
		APIKey:         "old-key",
		SupportsAPIKey: true,
	}

	cases := []struct {
		name   string
		values url.Values
		want   string
	}{
		{
			name: "new and clear",
			values: url.Values{
				"mode":                  {"self"},
				"api_key":               {"new-key"},
				"clear_api_key":         {"on"},
				"confirm_clear_api_key": {"on"},
			},
			want: "Choose either a new API key or clear the stored key",
		},
		{
			name: "clear without confirmation",
			values: url.Values{
				"mode":          {"self"},
				"clear_api_key": {"on"},
			},
			want: "Confirm API key removal",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFeedSettingsForm(base, tt.values)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("parseFeedSettingsForm() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestFeedConfigRecordFromRuntimeSettingCarriesRevisionAndOptionalInterval(t *testing.T) {
	t.Parallel()

	updatedAt := time.Date(2026, 6, 28, 10, 15, 0, 0, time.FixedZone("CEST", 2*60*60))
	interval := 45 * time.Minute
	feed := config.FeedSettings{
		Name:                 "vulncheck",
		Enabled:              true,
		Mode:                 config.FeedModeSelf,
		SyncInterval:         interval,
		APIKey:               "stored-key",
		SupportsSyncInterval: true,
	}

	record := feedConfigRecordFromRuntimeSetting(feed, &db.FeedConfig{UpdatedAt: updatedAt})
	if record.FeedName != "vulncheck" || !record.Enabled || record.Mode != "self" || record.APIKey != "stored-key" {
		t.Fatalf("record fields = %+v, want runtime values", record)
	}
	if record.SyncInterval == nil || *record.SyncInterval != interval {
		t.Fatalf("record SyncInterval = %v, want %v", record.SyncInterval, interval)
	}
	if record.ExpectedUpdatedAt == nil || !record.ExpectedUpdatedAt.Equal(updatedAt.UTC()) {
		t.Fatalf("record ExpectedUpdatedAt = %v, want %v", record.ExpectedUpdatedAt, updatedAt.UTC())
	}

	record = feedConfigRecordFromRuntimeSetting(feed, nil)
	if record.ExpectedUpdatedAt == nil || !record.ExpectedUpdatedAt.IsZero() {
		t.Fatalf("new record ExpectedUpdatedAt = %v, want zero revision expectation", record.ExpectedUpdatedAt)
	}

	feed.SyncInterval = 0
	record = feedConfigRecordFromRuntimeSetting(feed, &db.FeedConfig{UpdatedAt: updatedAt})
	if record.SyncInterval != nil {
		t.Fatalf("record SyncInterval = %v, want nil for default interval", record.SyncInterval)
	}
}
