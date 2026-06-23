package config

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	// Production default SSL mode verifies both encryption and server identity.
	if cfg.DB.SSLMode != "verify-full" {
		t.Errorf("DB.SSLMode = %q, want verify-full", cfg.DB.SSLMode)
	}
	if cfg.DB.ConnectTimeout != 10*time.Second {
		t.Errorf("DB.ConnectTimeout = %v, want 10s", cfg.DB.ConnectTimeout)
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

	if cfg.Web.PrivacyURL != "/privacy" {
		t.Errorf("Web.PrivacyURL = %q, want /privacy", cfg.Web.PrivacyURL)
	}
	if cfg.Web.LegalURL != "" {
		t.Errorf("Web.LegalURL = %q, want empty", cfg.Web.LegalURL)
	}

	// Admin defaults.
	if cfg.Admin.InitialPassword != "" {
		t.Errorf("Admin.InitialPassword = %q, want empty", cfg.Admin.InitialPassword)
	}
	if cfg.Admin.SessionTimeout != 8*time.Hour {
		t.Errorf("Admin.SessionTimeout = %v, want 8h", cfg.Admin.SessionTimeout)
	}
	if cfg.Admin.IdleTimeout != 15*time.Minute {
		t.Errorf("Admin.IdleTimeout = %v, want 15m", cfg.Admin.IdleTimeout)
	}

	// Audit retention defaults.
	if cfg.Retention.ScanLog != 90*24*time.Hour {
		t.Errorf("Retention.ScanLog = %v, want 2160h", cfg.Retention.ScanLog)
	}
	if cfg.Retention.AdminAuditLog != 365*24*time.Hour {
		t.Errorf("Retention.AdminAuditLog = %v, want 8760h", cfg.Retention.AdminAuditLog)
	}
	if cfg.Retention.RefreshQueue != 30*24*time.Hour {
		t.Errorf("Retention.RefreshQueue = %v, want 720h", cfg.Retention.RefreshQueue)
	}
	if cfg.Retention.Interval != 24*time.Hour {
		t.Errorf("Retention.Interval = %v, want 24h", cfg.Retention.Interval)
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
	if cfg.Feeds.VulnCheckEnabled {
		t.Error("Feeds.VulnCheckEnabled = true, want false")
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
	if !cfg.Feeds.EndOfLifeEnabled {
		t.Error("Feeds.EndOfLifeEnabled = false, want true")
	}
	if cfg.Feeds.EndOfLifeBaseURL != "https://endoflife.date/api/v1" {
		t.Errorf("Feeds.EndOfLifeBaseURL = %q, want default endoflife API URL", cfg.Feeds.EndOfLifeBaseURL)
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

func TestLoadAuditRetentionConfigFromEnv(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_SCAN_LOG_RETENTION", "48h")
	t.Setenv("PACKMON_ADMIN_AUDIT_LOG_RETENTION", "72h")
	t.Setenv("PACKMON_REFRESH_QUEUE_RETENTION", "96h")
	t.Setenv("PACKMON_AUDIT_RETENTION_INTERVAL", "6h")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Retention.ScanLog != 48*time.Hour {
		t.Errorf("Retention.ScanLog = %v, want 48h", cfg.Retention.ScanLog)
	}
	if cfg.Retention.AdminAuditLog != 72*time.Hour {
		t.Errorf("Retention.AdminAuditLog = %v, want 72h", cfg.Retention.AdminAuditLog)
	}
	if cfg.Retention.RefreshQueue != 96*time.Hour {
		t.Errorf("Retention.RefreshQueue = %v, want 96h", cfg.Retention.RefreshQueue)
	}
	if cfg.Retention.Interval != 6*time.Hour {
		t.Errorf("Retention.Interval = %v, want 6h", cfg.Retention.Interval)
	}
}

func TestLoadDBConnectTimeoutFromEnv(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_DB_CONNECT_TIMEOUT", "7s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.DB.ConnectTimeout != 7*time.Second {
		t.Fatalf("DB.ConnectTimeout = %v, want 7s", cfg.DB.ConnectTimeout)
	}
}

func TestLoadRejectsNegativeAuditRetention(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_SCAN_LOG_RETENTION", "-1h")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PACKMON_SCAN_LOG_RETENTION must be zero or greater") {
		t.Fatalf("Load() error = %v, want negative retention rejection", err)
	}

	clearPackmonEnv(t)
	t.Setenv("PACKMON_REFRESH_QUEUE_RETENTION", "-1h")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PACKMON_REFRESH_QUEUE_RETENTION must be zero or greater") {
		t.Fatalf("Load() error = %v, want refresh queue retention rejection", err)
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

func TestLoadProductionDBSSLModeDefaultsToVerifyFull(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_SERVER_MODE", "production")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.DB.SSLMode != "verify-full" {
		t.Fatalf("DB.SSLMode = %q, want verify-full", cfg.DB.SSLMode)
	}
	if got := cfg.DB.DSN(); !strings.Contains(got, "sslmode=verify-full") {
		t.Fatalf("DB.DSN() = %q, want sslmode=verify-full", got)
	}
}

func TestLoadExplicitDBSSLModeOverridesProductionDefault(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_SERVER_MODE", "production")
	t.Setenv("PACKMON_DB_SSLMODE", "require")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.DB.SSLMode != "require" {
		t.Fatalf("DB.SSLMode = %q, want explicit require override", cfg.DB.SSLMode)
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

func TestLoadWebNoticeURLsFromEnv(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_WEB_PRIVACY_URL", "https://privacy.example.test/packmon")
	t.Setenv("PACKMON_WEB_LEGAL_URL", "/legal-notice")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Web.PrivacyURL != "https://privacy.example.test/packmon" {
		t.Fatalf("Web.PrivacyURL = %q", cfg.Web.PrivacyURL)
	}
	if cfg.Web.LegalURL != "/legal-notice" {
		t.Fatalf("Web.LegalURL = %q", cfg.Web.LegalURL)
	}
}

func TestLoadRejectsUnsafeWebNoticeURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		val  string
	}{
		{name: "privacy javascript", key: "PACKMON_WEB_PRIVACY_URL", val: "javascript:alert(1)"},
		{name: "privacy protocol-relative", key: "PACKMON_WEB_PRIVACY_URL", val: "//example.test/privacy"},
		{name: "legal ftp", key: "PACKMON_WEB_LEGAL_URL", val: "ftp://example.test/legal"},
		{name: "legal relative", key: "PACKMON_WEB_LEGAL_URL", val: "legal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearPackmonEnv(t)
			t.Setenv(tc.key, tc.val)

			if _, err := Load(); err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("Load() error = %v, want %s validation error", err, tc.key)
			}
		})
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

func TestDBConfigDSNEscapesCredentials(t *testing.T) {
	const (
		wantUser     = "user:name@example"
		wantPassword = `pa:ss/word@secret?x=1&y=2` // #nosec G101 -- fake password fixture verifies DSN escaping.
	)

	dsn := DBConfig{
		Host:     "db.internal",
		Port:     15432,
		Name:     "mydb",
		User:     wantUser,
		Password: wantPassword,
		SSLMode:  "verify-full",
	}.DSN()

	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", dsn, err)
	}
	if got := parsed.User.Username(); got != wantUser {
		t.Fatalf("DSN username = %q, want %q; dsn=%q", got, wantUser, dsn)
	}
	gotPassword, ok := parsed.User.Password()
	if !ok {
		t.Fatalf("DSN did not contain a password; dsn=%q", dsn)
	}
	if gotPassword != wantPassword {
		t.Fatalf("DSN password = %q, want %q; dsn=%q", gotPassword, wantPassword, dsn)
	}
	if parsed.Host != "db.internal:15432" {
		t.Fatalf("DSN host = %q, want db.internal:15432; dsn=%q", parsed.Host, dsn)
	}
	if parsed.Query().Get("sslmode") != "verify-full" {
		t.Fatalf("DSN sslmode = %q, want verify-full; dsn=%q", parsed.Query().Get("sslmode"), dsn)
	}
}

func TestLoadConfigErrorsDoNotIncludeRawEnvValues(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		value     string
		setup     func(*testing.T)
		wantLabel string
	}{
		{
			name:      "server mode",
			key:       "PACKMON_SERVER_MODE",
			value:     "production-secret",
			wantLabel: "PACKMON_SERVER_MODE",
		},
		{
			name:      "integer",
			key:       "PACKMON_DB_PORT",
			value:     "5432-secret",
			wantLabel: "PACKMON_DB_PORT",
		},
		{
			name:      "duration",
			key:       "PACKMON_SERVER_READ_TIMEOUT",
			value:     "duration-secret",
			wantLabel: "PACKMON_SERVER_READ_TIMEOUT",
		},
		{
			name:      "boolean",
			key:       "PACKMON_FEED_SYNC_ON_STARTUP",
			value:     "boolean-secret",
			wantLabel: "PACKMON_FEED_SYNC_ON_STARTUP",
		},
		{
			name:      "feed mode",
			key:       "PACKMON_FEED_GHSA_MODE",
			value:     "feed-mode-secret",
			wantLabel: "PACKMON_FEED_GHSA_MODE",
		},
		{
			name:      "tls min version",
			key:       "PACKMON_TLS_MIN_VERSION",
			value:     "tls-secret",
			wantLabel: "PACKMON_TLS_MIN_VERSION",
		},
		{
			name:      "local http bind mode",
			key:       "PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE",
			value:     "bind-secret",
			wantLabel: "PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE",
		},
		{
			name:      "block threshold",
			key:       "PACKMON_BLOCK_THRESHOLD",
			value:     "threshold-secret",
			wantLabel: "PACKMON_BLOCK_THRESHOLD",
		},
		{
			name:  "reversinglabs base url",
			key:   "PACKMON_REVERSINGLABS_API_BASE_URL",
			value: "base-url-secret",
			setup: func(t *testing.T) {
				t.Setenv("PACKMON_REVERSINGLABS_API_KEY", "configured")
			},
			wantLabel: "PACKMON_REVERSINGLABS_API_BASE_URL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearPackmonEnv(t)
			if tc.setup != nil {
				tc.setup(t)
			}
			t.Setenv(tc.key, tc.value)

			_, err := Load()
			if err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.wantLabel) {
				t.Fatalf("Load() error = %q, want key label %q", msg, tc.wantLabel)
			}
			if strings.Contains(msg, tc.value) {
				t.Fatalf("Load() error leaked raw environment value %q: %q", tc.value, msg)
			}
		})
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
	t.Setenv("PACKMON_FEED_ENDOFLIFE_ENABLED", "false")

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
	if cfg.Feeds.EndOfLifeEnabled {
		t.Error("Feeds.EndOfLifeEnabled = true, want false")
	}
}

func TestEndOfLifeEnv(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_FEED_ENDOFLIFE_ENABLED", "true")
	t.Setenv("PACKMON_FEED_ENDOFLIFE_MODE", "self")
	t.Setenv("PACKMON_ENDOFLIFE_API_BASE_URL", "https://eol.example/api/v1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Feeds.EndOfLifeEnabled {
		t.Fatal("EndOfLifeEnabled = false, want true")
	}
	if cfg.Feeds.EndOfLifeMode != FeedModeSelf {
		t.Fatalf("EndOfLifeMode = %q, want self", cfg.Feeds.EndOfLifeMode)
	}
	if cfg.Feeds.EndOfLifeBaseURL != "https://eol.example/api/v1" {
		t.Fatalf("EndOfLifeBaseURL = %q", cfg.Feeds.EndOfLifeBaseURL)
	}
}

func TestEndOfLifeRejectsNonHTTPSBaseURL(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_ENDOFLIFE_API_BASE_URL", "http://downloads.example.test/api/v1")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want error for non-HTTPS endoflife base URL")
	} else if !strings.Contains(err.Error(), "PACKMON_ENDOFLIFE_API_BASE_URL") || !strings.Contains(err.Error(), "https") {
		t.Fatalf("Load() error = %v, want explicit HTTPS base URL error", err)
	}
}

func TestEndOfLifeAllowsLoopbackHTTPBaseURL(t *testing.T) {
	for _, baseURL := range []string{
		"http://127.0.0.1:8080/api/v1",
		"http://localhost:8080/api/v1",
		"http://[::1]:8080/api/v1",
	} {
		t.Run(baseURL, func(t *testing.T) {
			clearPackmonEnv(t)
			t.Setenv("PACKMON_ENDOFLIFE_API_BASE_URL", baseURL)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v, want loopback HTTP allowed", err)
			}
			if cfg.Feeds.EndOfLifeBaseURL != baseURL {
				t.Fatalf("EndOfLifeBaseURL = %q, want %q", cfg.Feeds.EndOfLifeBaseURL, baseURL)
			}
		})
	}
}

func TestReversingLabsDefaults(t *testing.T) {
	clearPackmonEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Feeds.ReversingLabsEnabled {
		t.Fatal("ReversingLabs should be disabled by default")
	}
	if cfg.Feeds.ReversingLabsMode != FeedModeSelf {
		t.Fatalf("ReversingLabsMode = %q, want self", cfg.Feeds.ReversingLabsMode)
	}
	if cfg.Feeds.ReversingLabsLookupTTL != 24*time.Hour {
		t.Fatalf("ReversingLabsLookupTTL = %v, want 24h", cfg.Feeds.ReversingLabsLookupTTL)
	}
	if cfg.Feeds.ReversingLabsBatchSize != 5 {
		t.Fatalf("ReversingLabsBatchSize = %d, want 5", cfg.Feeds.ReversingLabsBatchSize)
	}
}

func TestReversingLabsEnv(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_FEED_REVERSINGLABS_ENABLED", "true")
	t.Setenv("PACKMON_FEED_REVERSINGLABS_MODE", "self")
	t.Setenv("PACKMON_REVERSINGLABS_API_KEY", "rl-token")
	t.Setenv("PACKMON_REVERSINGLABS_API_BASE_URL", "https://example.test/community")
	t.Setenv("PACKMON_REVERSINGLABS_LOOKUP_TTL", "12h")
	t.Setenv("PACKMON_REVERSINGLABS_BATCH_SIZE", "3")
	t.Setenv("PACKMON_REVERSINGLABS_MAX_SCHEDULE_PER_CHECK", "17")
	t.Setenv("PACKMON_REVERSINGLABS_CACHE_RETENTION", "48h")
	t.Setenv("PACKMON_REVERSINGLABS_EXCLUDED_NAMESPACES", "npm/@school/,maven/edu.school:")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Feeds.ReversingLabsEnabled {
		t.Fatal("ReversingLabsEnabled = false, want true")
	}
	if cfg.Feeds.ReversingLabsMode != FeedModeSelf {
		t.Fatalf("ReversingLabsMode = %q, want self", cfg.Feeds.ReversingLabsMode)
	}
	if cfg.Feeds.ReversingLabsAPIKey != "rl-token" {
		t.Fatalf("ReversingLabsAPIKey = %q, want rl-token", cfg.Feeds.ReversingLabsAPIKey)
	}
	if cfg.Feeds.ReversingLabsBaseURL != "https://example.test/community" {
		t.Fatalf("ReversingLabsBaseURL = %q", cfg.Feeds.ReversingLabsBaseURL)
	}
	if cfg.Feeds.ReversingLabsLookupTTL != 12*time.Hour {
		t.Fatalf("ReversingLabsLookupTTL = %v, want 12h", cfg.Feeds.ReversingLabsLookupTTL)
	}
	if cfg.Feeds.ReversingLabsBatchSize != 3 {
		t.Fatalf("ReversingLabsBatchSize = %d, want 3", cfg.Feeds.ReversingLabsBatchSize)
	}
	if cfg.Feeds.ReversingLabsMaxSchedulePerCheck != 17 {
		t.Fatalf("ReversingLabsMaxSchedulePerCheck = %d, want 17", cfg.Feeds.ReversingLabsMaxSchedulePerCheck)
	}
	if cfg.Feeds.ReversingLabsCacheRetention != 48*time.Hour {
		t.Fatalf("ReversingLabsCacheRetention = %v, want 48h", cfg.Feeds.ReversingLabsCacheRetention)
	}
	if got := strings.Join(cfg.Feeds.ReversingLabsExcludedNamespaces, ","); got != "npm/@school/,maven/edu.school:" {
		t.Fatalf("ReversingLabsExcludedNamespaces = %q", got)
	}
}

func TestReversingLabsRejectsExternalMode(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_FEED_REVERSINGLABS_ENABLED", "true")
	t.Setenv("PACKMON_FEED_REVERSINGLABS_MODE", "external")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want error for ReversingLabs external mode")
	}
}

func TestNVDRejectsExternalMode(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_FEED_NVD_ENABLED", "true")
	t.Setenv("PACKMON_FEED_NVD_MODE", "external")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want error for NVD external mode")
	} else if !strings.Contains(err.Error(), "PACKMON_FEED_NVD_MODE") || !strings.Contains(err.Error(), "external") {
		t.Fatalf("Load() error = %v, want explicit NVD external-mode error", err)
	}
}

func TestReversingLabsRejectsNonHTTPSBaseURLWithToken(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_REVERSINGLABS_API_KEY", "rl-token")
	t.Setenv("PACKMON_REVERSINGLABS_API_BASE_URL", "http://downloads.example.test/community")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want error for non-HTTPS ReversingLabs base URL with token")
	} else if !strings.Contains(err.Error(), "PACKMON_REVERSINGLABS_API_BASE_URL") || !strings.Contains(err.Error(), "https") {
		t.Fatalf("Load() error = %v, want explicit HTTPS base URL error", err)
	}
}

func TestReversingLabsAllowsLoopbackHTTPBaseURLWithToken(t *testing.T) {
	for _, baseURL := range []string{
		"http://127.0.0.1:8080/community",
		"http://localhost:8080/community",
		"http://[::1]:8080/community",
	} {
		t.Run(baseURL, func(t *testing.T) {
			clearPackmonEnv(t)
			t.Setenv("PACKMON_REVERSINGLABS_API_KEY", "rl-token")
			t.Setenv("PACKMON_REVERSINGLABS_API_BASE_URL", baseURL)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v, want loopback HTTP allowed", err)
			}
			if cfg.Feeds.ReversingLabsBaseURL != baseURL {
				t.Fatalf("ReversingLabsBaseURL = %q, want %q", cfg.Feeds.ReversingLabsBaseURL, baseURL)
			}
		})
	}
}

func TestReversingLabsBatchSizeCappedAtFive(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_REVERSINGLABS_BATCH_SIZE", "25")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Feeds.ReversingLabsBatchSize != 5 {
		t.Fatalf("ReversingLabsBatchSize = %d, want 5 (capped)", cfg.Feeds.ReversingLabsBatchSize)
	}
}

func TestLoadReadsAPIKeys(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_VULNCHECK_API_KEY", "vc-key-123")
	t.Setenv("PACKMON_SOCKET_API_KEY", "sock-key-456")
	t.Setenv("PACKMON_FEED_IMPORT_SECRET", "import-secret")

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
	if cfg.Feeds.FeedImportSecret != "import-secret" {
		t.Errorf("Feeds.FeedImportSecret = %q, want import-secret", cfg.Feeds.FeedImportSecret)
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
	t.Setenv("PACKMON_ADMIN_IDLE_TIMEOUT", "10m")

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
	if cfg.Admin.IdleTimeout != 10*time.Minute {
		t.Errorf("Admin.IdleTimeout = %v, want 10m", cfg.Admin.IdleTimeout)
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

func TestLoadWithInvalidAdminIdleTimeoutReturnsError(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_ADMIN_IDLE_TIMEOUT", "nope")

	_, err := Load()
	if err == nil {
		t.Fatal("Load with invalid PACKMON_ADMIN_IDLE_TIMEOUT should return error")
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

func TestLoadRejectsInvalidBooleanEnvValues(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_FEED_SYNC_ON_STARTUP", "maybe")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "PACKMON_FEED_SYNC_ON_STARTUP") {
		t.Fatalf("Load() error = %v, want invalid PACKMON_FEED_SYNC_ON_STARTUP rejection", err)
	}
}

func TestLoadRejectsInvalidFeedModeEnvValues(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_FEED_GHSA_MODE", "externl")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "PACKMON_FEED_GHSA_MODE") {
		t.Fatalf("Load() error = %v, want invalid PACKMON_FEED_GHSA_MODE rejection", err)
	}
}

func TestConfigRemainingHelperBranches(t *testing.T) {
	clearPackmonEnv(t)

	if got := (MetricsConfig{Port: 9090}).Addr(); got != "127.0.0.1:9090" {
		t.Fatalf("MetricsConfig.Addr(empty host) = %q, want loopback default", got)
	}

	t.Setenv("PACKMON_TEST_INT32", "-2147483649")
	if _, err := envInt32OrDefault("PACKMON_TEST_INT32", 1); err == nil || !strings.Contains(err.Error(), "must fit in int32") {
		t.Fatalf("envInt32OrDefault(lower overflow) error = %v", err)
	}

	t.Setenv("PACKMON_TEST_POSITIVE", "0")
	if _, err := envPositiveIntOrDefault("PACKMON_TEST_POSITIVE", 1); err == nil || !strings.Contains(err.Error(), "greater than zero") {
		t.Fatalf("envPositiveIntOrDefault(zero) error = %v", err)
	}

	for _, raw := range []string{"localhost", "http://localhost:8080/admin", "[::1]:9090", "http://127.0.0.1:8080"} {
		if !isLoopbackPublicHost(raw) {
			t.Fatalf("isLoopbackPublicHost(%q) = false, want true", raw)
		}
	}
	for _, raw := range []string{"", "https://example.com", "http://%zz"} {
		if isLoopbackPublicHost(raw) {
			t.Fatalf("isLoopbackPublicHost(%q) = true, want false", raw)
		}
	}

	if threshold, err := parseBlockThreshold(" none "); err != nil || threshold != "NONE" {
		t.Fatalf("parseBlockThreshold(none) = %q, %v; want NONE nil", threshold, err)
	}
	if _, err := parseBlockThreshold("SEVERE"); err == nil {
		t.Fatal("parseBlockThreshold(invalid) error = nil")
	}
}

func TestLoadValidationErrorBranches(t *testing.T) {
	for _, tt := range []struct {
		name string
		key  string
		val  string
		want string
	}{
		{name: "db min conns overflow", key: "PACKMON_DB_MIN_CONNS", val: "2147483648", want: "must fit in int32"},
		{name: "rate limit minute zero", key: "PACKMON_RATE_LIMIT_PER_MINUTE", val: "0", want: "greater than zero"},
		{name: "rate limit burst zero", key: "PACKMON_RATE_LIMIT_BURST", val: "0", want: "greater than zero"},
		{name: "block threshold invalid", key: "PACKMON_BLOCK_THRESHOLD", val: "SEVERE", want: "invalid PACKMON_BLOCK_THRESHOLD"},
		{name: "write timeout invalid", key: "PACKMON_SERVER_WRITE_TIMEOUT", val: "later", want: "PACKMON_SERVER_WRITE_TIMEOUT"},
		{name: "shutdown timeout invalid", key: "PACKMON_SERVER_SHUTDOWN_TIMEOUT", val: "later", want: "PACKMON_SERVER_SHUTDOWN_TIMEOUT"},
		{name: "reversinglabs ttl invalid", key: "PACKMON_REVERSINGLABS_LOOKUP_TTL", val: "later", want: "PACKMON_REVERSINGLABS_LOOKUP_TTL"},
		{name: "reversinglabs batch invalid", key: "PACKMON_REVERSINGLABS_BATCH_SIZE", val: "0", want: "greater than zero"},
		{name: "tls min invalid", key: "PACKMON_TLS_MIN_VERSION", val: "1.1", want: "invalid PACKMON_TLS_MIN_VERSION"},
		{name: "local http bind mode invalid", key: "PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE", val: "public", want: "invalid PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clearPackmonEnv(t)
			t.Setenv(tt.key, tt.val)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}
