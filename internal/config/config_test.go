package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// clearPackmonEnv unsets all PACKMON_* environment variables so tests start
// from a clean state. t.Setenv cannot unset vars, but we can set them to ""
// which envOrDefault treats identically to unset.
func clearPackmonEnv(t *testing.T) {
	t.Helper()
	// Collect all existing PACKMON_ vars and blank them.
	for _, kv := range os.Environ() {
		if len(kv) > 8 && kv[:8] == "PACKMON_" {
			key := kv[:indexOf(kv, '=')]
			t.Setenv(key, "")
		}
	}
}

func indexOf(s string, c byte) int {
	for i := range len(s) {
		if s[i] == c {
			return i
		}
	}
	return len(s)
}

func TestLoadWithNoEnvVarsReturnsDefaults(t *testing.T) {
	t.Parallel()

	// Use a sub-test with Setenv to isolate env changes.
	clearPackmonEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	// Server defaults.
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.Server.Mode != ModeProduction {
		t.Errorf("Server.Mode = %q, want %q", cfg.Server.Mode, ModeProduction)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("Server.ReadTimeout = %v, want 30s", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 30*time.Second {
		t.Errorf("Server.WriteTimeout = %v, want 30s", cfg.Server.WriteTimeout)
	}
	if cfg.Server.ShutdownTimeout != 5*time.Second {
		t.Errorf("Server.ShutdownTimeout = %v, want 5s", cfg.Server.ShutdownTimeout)
	}
	if cfg.Server.BlockThreshold != "CRITICAL" {
		t.Errorf("Server.BlockThreshold = %q, want CRITICAL", cfg.Server.BlockThreshold)
	}
	if cfg.Server.RateLimitPerMinute != 60 {
		t.Errorf("Server.RateLimitPerMinute = %d, want 60", cfg.Server.RateLimitPerMinute)
	}
	if cfg.Server.RateLimitBurst != 60 {
		t.Errorf("Server.RateLimitBurst = %d, want 60", cfg.Server.RateLimitBurst)
	}

	// DB defaults.
	if cfg.DB.Host != "localhost" {
		t.Errorf("DB.Host = %q, want localhost", cfg.DB.Host)
	}
	if cfg.DB.Port != 5432 {
		t.Errorf("DB.Port = %d, want 5432", cfg.DB.Port)
	}
	if cfg.DB.Name != "packmon" {
		t.Errorf("DB.Name = %q, want packmon", cfg.DB.Name)
	}
	if cfg.DB.User != "packmon" {
		t.Errorf("DB.User = %q, want packmon", cfg.DB.User)
	}
	if cfg.DB.Password != "" {
		t.Errorf("DB.Password = %q, want empty", cfg.DB.Password)
	}
	// Production default SSL mode is "require".
	if cfg.DB.SSLMode != "require" {
		t.Errorf("DB.SSLMode = %q, want require", cfg.DB.SSLMode)
	}

	// Log defaults (production mode).
	if cfg.Log.Level != "info" {
		t.Errorf("Log.Level = %q, want info", cfg.Log.Level)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format = %q, want json", cfg.Log.Format)
	}

	// Metrics defaults.
	if cfg.Metrics.Port != 9090 {
		t.Errorf("Metrics.Port = %d, want 9090", cfg.Metrics.Port)
	}

	// Admin defaults.
	if cfg.Admin.InitialPassword != "" {
		t.Errorf("Admin.InitialPassword = %q, want empty", cfg.Admin.InitialPassword)
	}
	if cfg.Admin.SessionTimeout != 8*time.Hour {
		t.Errorf("Admin.SessionTimeout = %v, want 8h", cfg.Admin.SessionTimeout)
	}

	// Feed sync defaults.
	if cfg.FeedSync.Interval != 8*time.Hour {
		t.Errorf("FeedSync.Interval = %v, want 8h", cfg.FeedSync.Interval)
	}
	if !cfg.FeedSync.OnStartup {
		t.Error("FeedSync.OnStartup = false, want true")
	}

	// Feed enabled defaults.
	if !cfg.Feeds.OSVEnabled {
		t.Error("Feeds.OSVEnabled = false, want true")
	}
	if !cfg.Feeds.GHSAEnabled {
		t.Error("Feeds.GHSAEnabled = false, want true")
	}
	if !cfg.Feeds.OpenSSFEnabled {
		t.Error("Feeds.OpenSSFEnabled = false, want true")
	}
	if !cfg.Feeds.VulnCheckEnabled {
		t.Error("Feeds.VulnCheckEnabled = false, want true")
	}
	if cfg.Feeds.SocketEnabled {
		t.Error("Feeds.SocketEnabled = true, want false (default)")
	}
	if !cfg.Feeds.CISAKEVEnabled {
		t.Error("Feeds.CISAKEVEnabled = false, want true")
	}
	if !cfg.Feeds.EPSSEnabled {
		t.Error("Feeds.EPSSEnabled = false, want true")
	}

	// Feed modes default to "self".
	if cfg.Feeds.OSVMode != FeedModeSelf {
		t.Errorf("Feeds.OSVMode = %q, want self", cfg.Feeds.OSVMode)
	}

	// DataDir default.
	wantDataDir := filepath.Join(os.TempDir(), "packmon-feeds")
	if cfg.Feeds.DataDir != wantDataDir {
		t.Errorf("Feeds.DataDir = %q, want %q", cfg.Feeds.DataDir, wantDataDir)
	}
}

func TestLoadWithDevelopmentModeSetsDevDefaults(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_SERVER_MODE", "development")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.Mode != ModeDevelopment {
		t.Errorf("Server.Mode = %q, want development", cfg.Server.Mode)
	}

	// Development mode changes SSL default.
	if cfg.DB.SSLMode != "disable" {
		t.Errorf("DB.SSLMode = %q, want disable (dev mode)", cfg.DB.SSLMode)
	}

	// Development mode changes log level default.
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug (dev mode)", cfg.Log.Level)
	}

	if !cfg.IsDevelopment() {
		t.Error("IsDevelopment() = false, want true")
	}
}

func TestLoadWithInvalidServerModeReturnsError(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_SERVER_MODE", "staging")

	_, err := Load()
	if err == nil {
		t.Fatal("Load with invalid PACKMON_SERVER_MODE should return error")
	}
}

func TestLoadWithCustomServerPort(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_SERVER_PORT", "9999")
	t.Setenv("PACKMON_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.10.10")
	t.Setenv("PACKMON_BLOCK_THRESHOLD", "HIGH")
	t.Setenv("PACKMON_RATE_LIMIT_PER_MINUTE", "120")
	t.Setenv("PACKMON_RATE_LIMIT_BURST", "25")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.Port != 9999 {
		t.Errorf("Server.Port = %d, want 9999", cfg.Server.Port)
	}
	if got := cfg.Server.TrustedProxies; len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "192.168.10.10" {
		t.Errorf("Server.TrustedProxies = %#v, want configured proxy list", got)
	}
	if cfg.Server.BlockThreshold != "HIGH" {
		t.Errorf("Server.BlockThreshold = %q, want HIGH", cfg.Server.BlockThreshold)
	}
	if cfg.Server.RateLimitPerMinute != 120 {
		t.Errorf("Server.RateLimitPerMinute = %d, want 120", cfg.Server.RateLimitPerMinute)
	}
	if cfg.Server.RateLimitBurst != 25 {
		t.Errorf("Server.RateLimitBurst = %d, want 25", cfg.Server.RateLimitBurst)
	}
}

func TestLoadWithInvalidPortReturnsError(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_SERVER_PORT", "not-a-number")

	_, err := Load()
	if err == nil {
		t.Fatal("Load with invalid PACKMON_SERVER_PORT should return error")
	}
}

func TestLoadWithInvalidDBPortReturnsError(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_DB_PORT", "abc")

	_, err := Load()
	if err == nil {
		t.Fatal("Load with invalid PACKMON_DB_PORT should return error")
	}
}

func TestLoadWithDBPoolSizeOverflowReturnsError(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_DB_MAX_CONNS", "2147483648")

	_, err := Load()
	if err == nil {
		t.Fatal("Load with overflowing PACKMON_DB_MAX_CONNS should return error")
	}
}

func TestLoadWithInvalidDurationReturnsError(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_SERVER_READ_TIMEOUT", "not-a-duration")

	_, err := Load()
	if err == nil {
		t.Fatal("Load with invalid duration should return error")
	}
}

func TestLoadReadsDBVars(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_DB_HOST", "db.internal")
	t.Setenv("PACKMON_DB_PORT", "15432")
	t.Setenv("PACKMON_DB_NAME", "mydb")
	t.Setenv("PACKMON_DB_USER", "myuser")
	t.Setenv("PACKMON_DB_PASSWORD", "s3cret")
	t.Setenv("PACKMON_DB_SSLMODE", "verify-full")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.DB.Host != "db.internal" {
		t.Errorf("DB.Host = %q, want db.internal", cfg.DB.Host)
	}
	if cfg.DB.Port != 15432 {
		t.Errorf("DB.Port = %d, want 15432", cfg.DB.Port)
	}
	if cfg.DB.Name != "mydb" {
		t.Errorf("DB.Name = %q, want mydb", cfg.DB.Name)
	}
	if cfg.DB.User != "myuser" {
		t.Errorf("DB.User = %q, want myuser", cfg.DB.User)
	}
	if cfg.DB.Password != "s3cret" {
		t.Errorf("DB.Password = %q, want s3cret", cfg.DB.Password)
	}
	if cfg.DB.SSLMode != "verify-full" {
		t.Errorf("DB.SSLMode = %q, want verify-full", cfg.DB.SSLMode)
	}

	// Verify DSN composition.
	wantDSN := "postgres://myuser:s3cret@db.internal:15432/mydb?sslmode=verify-full" // #nosec G101 -- test fixture, not a real credential
	if cfg.DB.DSN() != wantDSN {
		t.Errorf("DB.DSN() = %q, want %q", cfg.DB.DSN(), wantDSN)
	}
}

func TestLoadReadsFeedEnabledFlags(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_FEED_OSV_ENABLED", "false")
	t.Setenv("PACKMON_FEED_GHSA_ENABLED", "false")
	t.Setenv("PACKMON_FEED_OPENSSF_ENABLED", "false")
	t.Setenv("PACKMON_FEED_VULNCHECK_ENABLED", "false")
	t.Setenv("PACKMON_FEED_SOCKET_ENABLED", "true")
	t.Setenv("PACKMON_FEED_CISAKEV_ENABLED", "false")
	t.Setenv("PACKMON_FEED_EPSS_ENABLED", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Feeds.OSVEnabled {
		t.Error("Feeds.OSVEnabled = true, want false")
	}
	if cfg.Feeds.GHSAEnabled {
		t.Error("Feeds.GHSAEnabled = true, want false")
	}
	if cfg.Feeds.OpenSSFEnabled {
		t.Error("Feeds.OpenSSFEnabled = true, want false")
	}
	if cfg.Feeds.VulnCheckEnabled {
		t.Error("Feeds.VulnCheckEnabled = true, want false")
	}
	if !cfg.Feeds.SocketEnabled {
		t.Error("Feeds.SocketEnabled = false, want true")
	}
	if cfg.Feeds.CISAKEVEnabled {
		t.Error("Feeds.CISAKEVEnabled = true, want false")
	}
	if cfg.Feeds.EPSSEnabled {
		t.Error("Feeds.EPSSEnabled = true, want false")
	}
}

func TestLoadReadsAPIKeys(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_VULNCHECK_API_KEY", "vc-key-123")
	t.Setenv("PACKMON_SOCKET_API_KEY", "sock-key-456")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Feeds.VulnCheckAPIKey != "vc-key-123" {
		t.Errorf("Feeds.VulnCheckAPIKey = %q, want vc-key-123", cfg.Feeds.VulnCheckAPIKey)
	}
	if cfg.Feeds.SocketAPIKey != "sock-key-456" {
		t.Errorf("Feeds.SocketAPIKey = %q, want sock-key-456", cfg.Feeds.SocketAPIKey)
	}
}

func TestLoadReadsAdminInitialPassword(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_ADMIN_INITIAL_PASSWORD", "my-init-pw")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Admin.InitialPassword != "my-init-pw" {
		t.Errorf("Admin.InitialPassword = %q, want my-init-pw", cfg.Admin.InitialPassword)
	}
}

func TestLoadReadsFeedModes(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_FEED_OSV_MODE", "external")
	t.Setenv("PACKMON_FEED_GHSA_MODE", "self")
	t.Setenv("PACKMON_FEED_SOCKET_MODE", "external")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Feeds.OSVMode != FeedModeExternal {
		t.Errorf("Feeds.OSVMode = %q, want external", cfg.Feeds.OSVMode)
	}
	if cfg.Feeds.GHSAMode != FeedModeSelf {
		t.Errorf("Feeds.GHSAMode = %q, want self", cfg.Feeds.GHSAMode)
	}
	if cfg.Feeds.SocketMode != FeedModeExternal {
		t.Errorf("Feeds.SocketMode = %q, want external", cfg.Feeds.SocketMode)
	}
}

func TestLoadReadsFeedSyncSettings(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_FEED_SYNC_INTERVAL", "2h")
	t.Setenv("PACKMON_FEED_SYNC_ON_STARTUP", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.FeedSync.Interval != 2*time.Hour {
		t.Errorf("FeedSync.Interval = %v, want 2h", cfg.FeedSync.Interval)
	}
	if cfg.FeedSync.OnStartup {
		t.Error("FeedSync.OnStartup = true, want false")
	}
}

func TestLoadReadsCustomTimeouts(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_SERVER_READ_TIMEOUT", "60s")
	t.Setenv("PACKMON_SERVER_WRITE_TIMEOUT", "45s")
	t.Setenv("PACKMON_SERVER_SHUTDOWN_TIMEOUT", "30s")
	t.Setenv("PACKMON_ADMIN_SESSION_TIMEOUT", "4h")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.ReadTimeout != 60*time.Second {
		t.Errorf("Server.ReadTimeout = %v, want 60s", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 45*time.Second {
		t.Errorf("Server.WriteTimeout = %v, want 45s", cfg.Server.WriteTimeout)
	}
	if cfg.Server.ShutdownTimeout != 30*time.Second {
		t.Errorf("Server.ShutdownTimeout = %v, want 30s", cfg.Server.ShutdownTimeout)
	}
	if cfg.Admin.SessionTimeout != 4*time.Hour {
		t.Errorf("Admin.SessionTimeout = %v, want 4h", cfg.Admin.SessionTimeout)
	}
}

func TestLoadReadsMetricsConfig(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_METRICS_PORT", "3333")
	t.Setenv("PACKMON_METRICS_HOST", "0.0.0.0")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Metrics.Port != 3333 {
		t.Errorf("Metrics.Port = %d, want 3333", cfg.Metrics.Port)
	}
	if cfg.Metrics.Host != "0.0.0.0" {
		t.Errorf("Metrics.Host = %q, want 0.0.0.0", cfg.Metrics.Host)
	}
	if cfg.Metrics.Addr() != "0.0.0.0:3333" {
		t.Errorf("Metrics.Addr() = %q, want 0.0.0.0:3333", cfg.Metrics.Addr())
	}
}

func TestLoadReadsLogConfig(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_LOG_LEVEL", "warn")
	t.Setenv("PACKMON_LOG_FORMAT", "console")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Log.Level != "warn" {
		t.Errorf("Log.Level = %q, want warn", cfg.Log.Level)
	}
	if cfg.Log.Format != "console" {
		t.Errorf("Log.Format = %q, want console", cfg.Log.Format)
	}
}

func TestLoadReadsFeedDataDir(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_FEED_DATA_DIR", "/custom/feed/dir")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Feeds.DataDir != "/custom/feed/dir" {
		t.Errorf("Feeds.DataDir = %q, want /custom/feed/dir", cfg.Feeds.DataDir)
	}
}

func TestLoadWithInvalidMetricsPortReturnsError(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_METRICS_PORT", "xyz")

	_, err := Load()
	if err == nil {
		t.Fatal("Load with invalid PACKMON_METRICS_PORT should return error")
	}
}

func TestLoadWithInvalidSyncIntervalReturnsError(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_FEED_SYNC_INTERVAL", "not-a-duration")

	_, err := Load()
	if err == nil {
		t.Fatal("Load with invalid PACKMON_FEED_SYNC_INTERVAL should return error")
	}
}

func TestLoadWithInvalidSessionTimeoutReturnsError(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_ADMIN_SESSION_TIMEOUT", "nope")

	_, err := Load()
	if err == nil {
		t.Fatal("Load with invalid PACKMON_ADMIN_SESSION_TIMEOUT should return error")
	}
}

func TestIsDevelopmentReturnsFalseForProduction(t *testing.T) {
	clearPackmonEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.IsDevelopment() {
		t.Error("IsDevelopment() = true, want false for production mode")
	}
}

func TestEnvBoolOrDefaultHandlesInvalidValues(t *testing.T) {
	clearPackmonEnv(t)
	// An invalid boolean value should fall back to the default.
	t.Setenv("PACKMON_FEED_SYNC_ON_STARTUP", "maybe")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	// Default for PACKMON_FEED_SYNC_ON_STARTUP is true.
	if !cfg.FeedSync.OnStartup {
		t.Error("FeedSync.OnStartup = false, want true (default fallback for invalid bool)")
	}
}
