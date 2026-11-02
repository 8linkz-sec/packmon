package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
)

func decodeJSONLogRecords(t *testing.T, output string) map[string]map[string]any {
	t.Helper()

	records := make(map[string]map[string]any)
	decoder := json.NewDecoder(strings.NewReader(output))
	for decoder.More() {
		var record map[string]any
		if err := decoder.Decode(&record); err != nil {
			t.Fatalf("decode structured log %q: %v", output, err)
		}
		delete(record, "time")
		message, ok := record["msg"].(string)
		if !ok || message == "" {
			t.Fatalf("structured log record has no message: %#v", record)
		}
		if _, duplicate := records[message]; duplicate {
			t.Fatalf("duplicate structured log message %q in %q", message, output)
		}
		records[message] = record
	}
	return records
}

func TestApplyStoredFeedConfigOverrides(t *testing.T) {
	store := newNoopStore()
	interval := 90 * time.Minute
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName:     "ghsa",
		Enabled:      false,
		Mode:         "external",
		SyncInterval: &interval,
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(ghsa) error = %v", err)
	}
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName: "socket",
		Enabled:  true,
		Mode:     "self",
		APIKey:   "socket-live-key",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(socket) error = %v", err)
	}

	cfg := testAdminConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := applyStoredFeedConfigOverrides(context.Background(), cfg, store, logger); err != nil {
		t.Fatalf("applyStoredFeedConfigOverrides() error = %v", err)
	}

	ghsa, ok := cfg.FeedSettings("ghsa")
	if !ok {
		t.Fatal("cfg.FeedSettings(ghsa) = !ok")
	}
	if ghsa.Enabled {
		t.Fatal("ghsa.Enabled = true, want false")
	}
	if ghsa.Mode != config.FeedModeExternal {
		t.Fatalf("ghsa.Mode = %q, want external", ghsa.Mode)
	}
	if ghsa.SyncInterval != interval {
		t.Fatalf("ghsa.SyncInterval = %s, want %s", ghsa.SyncInterval, interval)
	}

	socket, ok := cfg.FeedSettings("socket")
	if !ok {
		t.Fatal("cfg.FeedSettings(socket) = !ok")
	}
	if !socket.Enabled {
		t.Fatal("socket.Enabled = false, want true")
	}
	if socket.APIKey != "socket-live-key" {
		t.Fatalf("socket.APIKey = %q, want socket-live-key", socket.APIKey)
	}

	rl, ok := cfg.FeedSettings("reversinglabs")
	if !ok {
		t.Fatal("cfg.FeedSettings(reversinglabs) = !ok")
	}
	if rl.DisplayName != "ReversingLabs" || !rl.RequiresAPIKey || rl.SupportsSyncInterval {
		t.Fatalf("reversinglabs feed settings = %+v", rl)
	}
}

type feedConfigErrorStore struct {
	db.Store
}

func (*feedConfigErrorStore) ListFeedConfigs(context.Context) ([]db.FeedConfig, error) {
	return nil, errors.New("feed configs unavailable")
}

func TestApplyStoredFeedConfigOverridesErrorAndIgnoredBranches(t *testing.T) {
	t.Parallel()

	cfg := testAdminConfig()
	if err := applyStoredFeedConfigOverrides(context.Background(), cfg, &feedConfigErrorStore{}, nil); err == nil || !strings.Contains(err.Error(), "list feed config overrides") {
		t.Fatalf("applyStoredFeedConfigOverrides(error store) = %v", err)
	}

	osvBefore, ok := cfg.FeedSettings("osv")
	if !ok {
		t.Fatal("cfg.FeedSettings(osv) = !ok")
	}
	osvBefore.Enabled = false
	osvBefore.Mode = config.FeedModeExternal
	osvBefore.SyncInterval = 45 * time.Minute
	if err := cfg.SetFeedSettings(osvBefore); err != nil {
		t.Fatalf("cfg.SetFeedSettings(osv) error = %v", err)
	}
	osvBefore, _ = cfg.FeedSettings("osv")

	store := newNoopStore()
	ignoredInterval := 2 * time.Hour
	invalidMode := strings.Repeat("x", 600)
	for _, override := range []*db.FeedConfig{
		{FeedName: "unknown", Enabled: true, Mode: "self"},
		{FeedName: "osv", Enabled: true, Mode: invalidMode, SyncInterval: &ignoredInterval, APIKey: "ignored-key"}, //nolint:gosec // fake ignored test credential.
		{FeedName: "vulncheck", Enabled: true, Mode: "external", APIKey: "  persisted-key  "},                      //nolint:gosec // fake persisted test credential.
	} {
		if err := store.UpsertFeedConfig(context.Background(), override); err != nil {
			t.Fatalf("UpsertFeedConfig(%s) error = %v", override.FeedName, err)
		}
	}
	var logs bytes.Buffer
	if err := applyStoredFeedConfigOverrides(context.Background(), cfg, store, slog.New(slog.NewJSONHandler(&logs, nil))); err != nil {
		t.Fatalf("applyStoredFeedConfigOverrides(ignored branches) error = %v", err)
	}

	osv, _ := cfg.FeedSettings("osv")
	if osv != osvBefore {
		t.Fatalf("OSV settings changed for ignored record: got %+v, want %+v", osv, osvBefore)
	}
	vulncheck, _ := cfg.FeedSettings("vulncheck")
	if !vulncheck.Enabled || vulncheck.Mode != config.FeedModeExternal || vulncheck.SyncInterval != 0 || vulncheck.APIKey != "persisted-key" {
		t.Fatalf("vulncheck override = %+v, want enabled external mode with default cadence and trimmed key", vulncheck)
	}

	wantLogs := map[string]map[string]any{
		"ignoring unknown persisted feed override": {
			"level": "WARN",
			"msg":   "ignoring unknown persisted feed override",
			"feed":  "unknown",
		},
		"ignoring invalid persisted feed mode": {
			"level": "WARN",
			"msg":   "ignoring invalid persisted feed mode",
			"feed":  "osv",
			"mode":  strings.Repeat("x", 50) + "...[truncated]",
			"error": `invalid feed mode "` + strings.Repeat("x", 479) + "...[truncated]",
		},
		"applied persisted feed configuration overrides": {
			"level": "INFO",
			"msg":   "applied persisted feed configuration overrides",
			"count": float64(1),
		},
	}
	if got := decodeJSONLogRecords(t, logs.String()); !reflect.DeepEqual(got, wantLogs) {
		t.Fatalf("structured feed logs = %#v, want %#v", got, wantLogs)
	}
}

func TestApplyStoredFeedConfigOverridesClearsStaleValues(t *testing.T) {
	t.Parallel()

	cfg := testAdminConfig()
	current, ok := cfg.FeedSettings("vulncheck")
	if !ok {
		t.Fatal("cfg.FeedSettings(vulncheck) = !ok")
	}
	current.Enabled = false
	current.Mode = config.FeedModeSelf
	current.SyncInterval = 90 * time.Minute
	current.APIKey = "stale-key"
	if err := cfg.SetFeedSettings(current); err != nil {
		t.Fatalf("cfg.SetFeedSettings(vulncheck) error = %v", err)
	}

	store := newNoopStore()
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName: "vulncheck",
		Enabled:  true,
		Mode:     "external",
		APIKey:   "   ",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(vulncheck) error = %v", err)
	}
	if err := applyStoredFeedConfigOverrides(context.Background(), cfg, store, nil); err != nil {
		t.Fatalf("applyStoredFeedConfigOverrides() error = %v", err)
	}

	got, _ := cfg.FeedSettings("vulncheck")
	if !got.Enabled || got.Mode != config.FeedModeExternal {
		t.Fatalf("vulncheck successful fields = enabled:%v mode:%q, want true/external", got.Enabled, got.Mode)
	}
	if got.SyncInterval != 0 {
		t.Fatalf("vulncheck sync interval = %s, want cleared to zero", got.SyncInterval)
	}
	if got.APIKey != "" {
		t.Fatalf("vulncheck API key = %q, want cleared", got.APIKey)
	}
}

func TestApplyStoredFeedConfigOverridesRejectsUnsafeSyncInterval(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	interval := time.Second
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName:     "vulncheck",
		Enabled:      true,
		Mode:         "self",
		SyncInterval: &interval,
		APIKey:       "persisted-key",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(vulncheck) error = %v", err)
	}

	cfg := testAdminConfig()
	err := applyStoredFeedConfigOverrides(context.Background(), cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "at least 15m0s") {
		t.Fatalf("applyStoredFeedConfigOverrides() error = %v, want minimum interval error", err)
	}

	vulncheck, _ := cfg.FeedSettings("vulncheck")
	if vulncheck.SyncInterval == interval {
		t.Fatalf("unsafe vulncheck interval was applied: %+v", vulncheck)
	}
}

func TestApplyStoredFeedConfigOverridesRejectsProductionPlaintextAPIKey(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName: "socket",
		Enabled:  true,
		Mode:     "self",
		APIKey:   "legacy-plaintext-key",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(socket) error = %v", err)
	}

	cfg := testAdminConfig()
	cfg.Server.Mode = config.ModeProduction
	cfg.Admin.EncryptionKey = "active-test-key"
	err := applyStoredFeedConfigOverrides(context.Background(), cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "plaintext feed API key") || strings.Contains(err.Error(), "legacy-plaintext-key") {
		t.Fatalf("applyStoredFeedConfigOverrides() error = %v, want non-secret plaintext rejection", err)
	}

	socket, _ := cfg.FeedSettings("socket")
	if socket.APIKey != "" {
		t.Fatalf("socket API key = %q, want not applied after plaintext rejection", socket.APIKey)
	}
}

func TestApplyStoredFeedConfigOverridesAllowsProductionEncryptedAPIKey(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName:        "socket",
		Enabled:         true,
		Mode:            "self",
		APIKey:          "decrypted-key",
		APIKeyEncrypted: true,
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(socket) error = %v", err)
	}

	cfg := testAdminConfig()
	cfg.Server.Mode = config.ModeProduction
	cfg.Admin.EncryptionKey = "active-test-key"
	if err := applyStoredFeedConfigOverrides(context.Background(), cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("applyStoredFeedConfigOverrides() error = %v", err)
	}

	socket, _ := cfg.FeedSettings("socket")
	if socket.APIKey != "decrypted-key" {
		t.Fatalf("socket API key = %q, want decrypted-key", socket.APIKey)
	}
}

func TestApplyStoredFeedConfigOverridesAllowsDevelopmentPlaintextAPIKey(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName: "socket",
		Enabled:  true,
		Mode:     "self",
		APIKey:   "development-plaintext-key",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(socket) error = %v", err)
	}

	cfg := testAdminConfig()
	cfg.Server.Mode = config.ModeDevelopment
	cfg.Admin.EncryptionKey = "active-test-key"
	if err := applyStoredFeedConfigOverrides(context.Background(), cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("applyStoredFeedConfigOverrides() error = %v", err)
	}

	socket, _ := cfg.FeedSettings("socket")
	if socket.APIKey != "development-plaintext-key" {
		t.Fatalf("socket API key = %q, want development-plaintext-key", socket.APIKey)
	}
}

func TestApplyStoredFeedConfigOverridesRejectsReversingLabsHTTPWithPersistedAPIKey(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	//nolint:gosec // G101: fixture credential, deliberately fake.
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName: "reversinglabs",
		Enabled:  true,
		Mode:     "self",
		APIKey:   "persisted-rl-key",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(reversinglabs) error = %v", err)
	}

	cfg := testAdminConfig()
	cfg.Feeds.ReversingLabsBaseURL = "http://downloads.example.test/community"
	err := applyStoredFeedConfigOverrides(context.Background(), cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "PACKMON_REVERSINGLABS_API_BASE_URL") || !strings.Contains(err.Error(), "https") {
		t.Fatalf("applyStoredFeedConfigOverrides() error = %v, want ReversingLabs HTTPS validation error", err)
	}

	rl, _ := cfg.FeedSettings("reversinglabs")
	if rl.APIKey != "" {
		t.Fatalf("reversinglabs API key = %q, want not applied after rejected HTTP base URL", rl.APIKey)
	}
}
