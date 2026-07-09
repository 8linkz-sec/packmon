package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
)

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

	store := newNoopStore()
	for _, override := range []*db.FeedConfig{
		{FeedName: "unknown", Enabled: true, Mode: "self"},
		{FeedName: "osv", Enabled: true, Mode: "sideways"},
		{FeedName: "vulncheck", Enabled: true, Mode: "external", APIKey: "  persisted-key  "}, //nolint:gosec // fake persisted test credential.
	} {
		if err := store.UpsertFeedConfig(context.Background(), override); err != nil {
			t.Fatalf("UpsertFeedConfig(%s) error = %v", override.FeedName, err)
		}
	}
	if err := applyStoredFeedConfigOverrides(context.Background(), cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("applyStoredFeedConfigOverrides(ignored branches) error = %v", err)
	}

	osv, _ := cfg.FeedSettings("osv")
	if osv.Mode == config.FeedMode("sideways") {
		t.Fatalf("invalid OSV mode was applied: %+v", osv)
	}
	vulncheck, _ := cfg.FeedSettings("vulncheck")
	if vulncheck.Mode != config.FeedModeExternal || vulncheck.APIKey != "persisted-key" {
		t.Fatalf("vulncheck override = %+v, want external mode with trimmed key", vulncheck)
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
