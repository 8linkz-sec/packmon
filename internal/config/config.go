// Package config loads server configuration from environment variables
// with sensible defaults. No Viper dependency -- just os.Getenv with
// fallback values, following 12-factor principles.
package config

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/netutil"
)

// ServerMode controls runtime behaviour (TLS enforcement, auth bypass, log defaults).
type ServerMode string

const (
	ModeProduction  ServerMode = "production"
	ModeDevelopment ServerMode = "development"
)

// Config holds all server configuration values.
type Config struct {
	Server    ServerConfig
	DB        DBConfig
	Log       LogConfig
	Metrics   MetricsConfig
	Web       WebConfig
	Admin     AdminConfig
	Retention RetentionConfig
	FeedSync  FeedSyncConfig
	Feeds     FeedsConfig

	feedsMu *sync.RWMutex
}

// FeedMode controls whether the server runs a feed syncer itself or
// expects an external system (e.g. N8N) to push data. See DE-18.
type FeedMode string

const (
	FeedModeSelf     FeedMode = "self"
	FeedModeExternal FeedMode = "external"
)

// FeedsConfig holds per-feed settings including API keys, enabled state,
// and per-feed sync mode (self vs. external).
type FeedsConfig struct {
	// DataDir is the directory where feed syncers store cloned repos and
	// other working data. Defaults to os.TempDir()/packmon-feeds.
	DataDir string

	// Per-feed enabled flags.
	OSVEnabled           bool
	GHSAEnabled          bool
	OpenSSFEnabled       bool
	VulnCheckEnabled     bool
	SocketEnabled        bool
	ReversingLabsEnabled bool
	CISAKEVEnabled       bool
	EPSSEnabled          bool
	EndOfLifeEnabled     bool

	// Per-feed mode: "self" (server syncs) or "external" (N8N pushes).
	OSVMode           FeedMode
	GHSAMode          FeedMode
	OpenSSFMode       FeedMode
	VulnCheckMode     FeedMode
	CISAKEVMode       FeedMode
	EPSSMode          FeedMode
	EndOfLifeMode     FeedMode
	SocketMode        FeedMode
	ReversingLabsMode FeedMode

	// Optional per-feed sync interval overrides. Zero means "use
	// PACKMON_FEED_SYNC_INTERVAL".
	OSVInterval       time.Duration
	GHSAInterval      time.Duration
	OpenSSFInterval   time.Duration
	VulnCheckInterval time.Duration
	CISAKEVInterval   time.Duration
	EPSSInterval      time.Duration
	EndOfLifeInterval time.Duration

	// NVD enrichment feed settings.
	NVDEnabled  bool
	NVDMode     FeedMode
	NVDInterval time.Duration

	// API keys for feeds that require authentication.
	FeedImportSecret       string
	VulnCheckAPIKey        string
	SocketAPIKey           string
	ReversingLabsAPIKey    string
	ReversingLabsBaseURL   string
	ReversingLabsLookupTTL time.Duration
	ReversingLabsBatchSize int
	// ReversingLabsMaxSchedulePerCheck caps demand-driven lookup rows created
	// by one /api/v1/check request.
	ReversingLabsMaxSchedulePerCheck int
	// ReversingLabsCacheRetention is the maximum age for non-finding
	// ReversingLabs cache rows such as clean/not_found/unsupported/error.
	ReversingLabsCacheRetention time.Duration
	// ReversingLabsExcludedNamespaces suppresses demand-driven external
	// lookups for private package namespace prefixes.
	ReversingLabsExcludedNamespaces []string
	EndOfLifeBaseURL                string
	NVDAPIKey                       string
}

// ServerConfig groups HTTP server settings.
type ServerConfig struct {
	Port                   int
	Mode                   ServerMode
	PublicHost             string
	TrustedProxies         []string
	AllowInsecureLocalHTTP bool
	InsecureLocalHTTPBind  string
	BlockThreshold         string
	RateLimitPerMinute     int
	RateLimitBurst         int
	ReadTimeout            time.Duration
	WriteTimeout           time.Duration
	ShutdownTimeout        time.Duration
	TLS                    TLSConfig
}

func (s ServerConfig) Addr() string {
	if s.InsecureLocalHTTPOverrideActive() && s.InsecureLocalHTTPBind != "container" {
		return fmt.Sprintf("127.0.0.1:%d", s.Port)
	}
	return fmt.Sprintf(":%d", s.Port)
}

func (s ServerConfig) InsecureLocalHTTPOverrideActive() bool {
	trustedProxies, err := netutil.ParseTrustedProxies(s.TrustedProxies)
	return s.Mode == ModeProduction &&
		s.AllowInsecureLocalHTTP &&
		!s.TLS.Enabled() &&
		err == nil &&
		trustedProxies.Len() == 0
}

// TLSConfig groups in-app TLS termination settings. When both CertFile and
// KeyFile are set, the server terminates TLS itself (no reverse proxy needed).
type TLSConfig struct {
	CertFile string
	KeyFile  string
	// MinVersion is the configured minimum TLS version string ("1.2" or "1.3").
	MinVersion string
}

// Enabled reports whether in-app TLS termination is configured (both cert and
// key files set).
func (t TLSConfig) Enabled() bool {
	return strings.TrimSpace(t.CertFile) != "" && strings.TrimSpace(t.KeyFile) != ""
}

// MinVersionTLS maps the configured MinVersion string to the corresponding
// crypto/tls constant. It assumes the value was validated at load time and
// falls back to TLS 1.2 for an empty/unknown value.
func (t TLSConfig) MinVersionTLS() uint16 {
	switch strings.TrimSpace(t.MinVersion) {
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// DBConfig groups PostgreSQL connection settings.
type DBConfig struct {
	Host           string
	Port           int
	Name           string
	User           string
	Password       string
	SSLMode        string
	MaxConns       int32
	MinConns       int32
	ConnectTimeout time.Duration
}

// DSN returns a PostgreSQL connection string.
func (d DBConfig) DSN() string {
	query := url.Values{}
	query.Set("sslmode", d.SSLMode)
	dsn := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(d.User, d.Password),
		Host:     net.JoinHostPort(d.Host, strconv.Itoa(d.Port)),
		Path:     "/" + d.Name,
		RawQuery: query.Encode(),
	}
	return dsn.String()
}

// LogConfig groups logging settings.
type LogConfig struct {
	Level  string
	Format string
}

// MetricsConfig groups the Prometheus metrics server settings.
type MetricsConfig struct {
	Host string
	Port int
}

// WebConfig controls optional public web UI notice links.
type WebConfig struct {
	// PrivacyURL is linked from the shared footer. It defaults to Packmon's
	// built-in privacy notice at /privacy.
	PrivacyURL string
	// LegalURL is an optional operator-provided legal notice or Impressum URL.
	LegalURL string
}

// AdminConfig holds initial admin bootstrap values.
type AdminConfig struct {
	InitialPassword string
	SessionTimeout  time.Duration
	IdleTimeout     time.Duration
	// EncryptionKey is used to encrypt sensitive fields (e.g. feed API
	// keys) at rest with AES-256-GCM. Production startup requires this
	// value; development mode may run without it.
	EncryptionKey string
}

// RetentionConfig controls pruning for server-side operational metadata.
type RetentionConfig struct {
	// ScanLog is the maximum age for scan_log rows. Zero disables pruning.
	ScanLog time.Duration
	// AdminAuditLog is the maximum age for admin_audit_log rows. Zero disables pruning.
	AdminAuditLog time.Duration
	// RefreshQueue is the maximum age for terminal refresh_queue rows. Zero disables pruning.
	RefreshQueue time.Duration
	// Interval controls how often the background retention job runs.
	Interval time.Duration
}

// FeedSyncConfig holds feed sync scheduling settings.
type FeedSyncConfig struct {
	Interval  time.Duration
	OnStartup bool
}

// Load reads configuration from environment variables with defaults.
// It does not validate semantic correctness (e.g. whether the DB is
// reachable) -- that is the caller's responsibility.
func Load() (*Config, error) {
	mode := ServerMode(envOrDefault("PACKMON_SERVER_MODE", "production"))
	if mode != ModeProduction && mode != ModeDevelopment {
		return nil, fmt.Errorf("config: invalid PACKMON_SERVER_MODE (want production or development)")
	}

	serverPort, err := envIntOrDefault("PACKMON_SERVER_PORT", 8080)
	if err != nil {
		return nil, err
	}

	metricsPort, err := envIntOrDefault("PACKMON_METRICS_PORT", 9090)
	if err != nil {
		return nil, err
	}

	dbPort, err := envIntOrDefault("PACKMON_DB_PORT", 5432)
	if err != nil {
		return nil, err
	}

	dbMaxConns, err := envInt32OrDefault("PACKMON_DB_MAX_CONNS", 20)
	if err != nil {
		return nil, err
	}

	dbMinConns, err := envInt32OrDefault("PACKMON_DB_MIN_CONNS", 2)
	if err != nil {
		return nil, err
	}
	dbConnectTimeout, err := envPositiveDurationOrDefault("PACKMON_DB_CONNECT_TIMEOUT", 10*time.Second)
	if err != nil {
		return nil, err
	}

	rateLimitPerMinute, err := envPositiveIntOrDefault("PACKMON_RATE_LIMIT_PER_MINUTE", 60)
	if err != nil {
		return nil, err
	}

	rateLimitBurst, err := envPositiveIntOrDefault("PACKMON_RATE_LIMIT_BURST", 60)
	if err != nil {
		return nil, err
	}

	blockThreshold, err := parseBlockThreshold(envOrDefault("PACKMON_BLOCK_THRESHOLD", "CRITICAL"))
	if err != nil {
		return nil, err
	}

	readTimeout, err := envDurationOrDefault("PACKMON_SERVER_READ_TIMEOUT", 30*time.Second)
	if err != nil {
		return nil, err
	}

	writeTimeout, err := envDurationOrDefault("PACKMON_SERVER_WRITE_TIMEOUT", 30*time.Second)
	if err != nil {
		return nil, err
	}

	shutdownTimeout, err := envDurationOrDefault("PACKMON_SERVER_SHUTDOWN_TIMEOUT", 5*time.Second)
	if err != nil {
		return nil, err
	}

	syncInterval, err := envDurationOrDefault("PACKMON_FEED_SYNC_INTERVAL", 8*time.Hour)
	if err != nil {
		return nil, err
	}

	reversingLabsTTL, err := envDurationOrDefault("PACKMON_REVERSINGLABS_LOOKUP_TTL", 24*time.Hour)
	if err != nil {
		return nil, err
	}
	reversingLabsCacheRetention, err := envDurationOrDefault("PACKMON_REVERSINGLABS_CACHE_RETENTION", 7*24*time.Hour)
	if err != nil {
		return nil, err
	}

	reversingLabsBatchSize, err := envPositiveIntOrDefault("PACKMON_REVERSINGLABS_BATCH_SIZE", 5)
	if err != nil {
		return nil, err
	}
	if reversingLabsBatchSize > 5 {
		reversingLabsBatchSize = 5
	}
	reversingLabsMaxSchedule, err := envPositiveIntOrDefault("PACKMON_REVERSINGLABS_MAX_SCHEDULE_PER_CHECK", 100)
	if err != nil {
		return nil, err
	}

	reversingLabsMode, err := envFeedModeOrDefault("PACKMON_FEED_REVERSINGLABS_MODE", FeedModeSelf)
	if err != nil {
		return nil, err
	}
	if reversingLabsMode == FeedModeExternal {
		return nil, fmt.Errorf("PACKMON_FEED_REVERSINGLABS_MODE does not support external mode: ReversingLabs is demand-driven and has no import endpoint")
	}
	endOfLifeMode, err := envFeedModeOrDefault("PACKMON_FEED_ENDOFLIFE_MODE", FeedModeSelf)
	if err != nil {
		return nil, err
	}
	if endOfLifeMode == FeedModeExternal {
		return nil, fmt.Errorf("PACKMON_FEED_ENDOFLIFE_MODE does not support external mode: endoflife has no import endpoint")
	}

	sessionTimeout, err := envDurationOrDefault("PACKMON_ADMIN_SESSION_TIMEOUT", 8*time.Hour)
	if err != nil {
		return nil, err
	}
	adminIdleTimeout, err := envPositiveDurationOrDefault("PACKMON_ADMIN_IDLE_TIMEOUT", auth.DefaultAdminIdleTimeout)
	if err != nil {
		return nil, err
	}
	scanLogRetention, err := envNonNegativeDurationOrDefault("PACKMON_SCAN_LOG_RETENTION", 90*24*time.Hour)
	if err != nil {
		return nil, err
	}
	adminAuditRetention, err := envNonNegativeDurationOrDefault("PACKMON_ADMIN_AUDIT_LOG_RETENTION", 365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	refreshQueueRetention, err := envNonNegativeDurationOrDefault("PACKMON_REFRESH_QUEUE_RETENTION", 30*24*time.Hour)
	if err != nil {
		return nil, err
	}
	auditRetentionInterval, err := envPositiveDurationOrDefault("PACKMON_AUDIT_RETENTION_INTERVAL", 24*time.Hour)
	if err != nil {
		return nil, err
	}

	tlsMinVersion, err := parseTLSMinVersion(envOrDefault("PACKMON_TLS_MIN_VERSION", "1.2"))
	if err != nil {
		return nil, err
	}
	insecureLocalHTTPBind, err := parseInsecureLocalHTTPBind(envOrDefault("PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE", "loopback"))
	if err != nil {
		return nil, err
	}

	allowInsecureLocalHTTP, err := envBoolOrDefault("PACKMON_ALLOW_INSECURE_LOCAL_HTTP", false)
	if err != nil {
		return nil, err
	}
	feedSyncOnStartup, err := envBoolOrDefault("PACKMON_FEED_SYNC_ON_STARTUP", true)
	if err != nil {
		return nil, err
	}
	privacyURL, err := envWebNoticeURLOrDefault("PACKMON_WEB_PRIVACY_URL", "/privacy")
	if err != nil {
		return nil, err
	}
	legalURL, err := envWebNoticeURLOrDefault("PACKMON_WEB_LEGAL_URL", "")
	if err != nil {
		return nil, err
	}
	osvEnabled, err := envBoolOrDefault("PACKMON_FEED_OSV_ENABLED", true)
	if err != nil {
		return nil, err
	}
	ghsaEnabled, err := envBoolOrDefault("PACKMON_FEED_GHSA_ENABLED", true)
	if err != nil {
		return nil, err
	}
	openSSFEnabled, err := envBoolOrDefault("PACKMON_FEED_OPENSSF_ENABLED", true)
	if err != nil {
		return nil, err
	}
	vulnCheckEnabled, err := envBoolOrDefault("PACKMON_FEED_VULNCHECK_ENABLED", false)
	if err != nil {
		return nil, err
	}
	socketEnabled, err := envBoolOrDefault("PACKMON_FEED_SOCKET_ENABLED", false)
	if err != nil {
		return nil, err
	}
	reversingLabsEnabled, err := envBoolOrDefault("PACKMON_FEED_REVERSINGLABS_ENABLED", false)
	if err != nil {
		return nil, err
	}
	cisaKEVEnabled, err := envBoolOrDefault("PACKMON_FEED_CISAKEV_ENABLED", true)
	if err != nil {
		return nil, err
	}
	epssEnabled, err := envBoolOrDefault("PACKMON_FEED_EPSS_ENABLED", true)
	if err != nil {
		return nil, err
	}
	nvdEnabled, err := envBoolOrDefault("PACKMON_FEED_NVD_ENABLED", true)
	if err != nil {
		return nil, err
	}
	endOfLifeEnabled, err := envBoolOrDefault("PACKMON_FEED_ENDOFLIFE_ENABLED", true)
	if err != nil {
		return nil, err
	}
	osvMode, err := envFeedModeOrDefault("PACKMON_FEED_OSV_MODE", FeedModeSelf)
	if err != nil {
		return nil, err
	}
	ghsaMode, err := envFeedModeOrDefault("PACKMON_FEED_GHSA_MODE", FeedModeSelf)
	if err != nil {
		return nil, err
	}
	openSSFMode, err := envFeedModeOrDefault("PACKMON_FEED_OPENSSF_MODE", FeedModeSelf)
	if err != nil {
		return nil, err
	}
	vulnCheckMode, err := envFeedModeOrDefault("PACKMON_FEED_VULNCHECK_MODE", FeedModeSelf)
	if err != nil {
		return nil, err
	}
	cisaKEVMode, err := envFeedModeOrDefault("PACKMON_FEED_CISAKEV_MODE", FeedModeSelf)
	if err != nil {
		return nil, err
	}
	epssMode, err := envFeedModeOrDefault("PACKMON_FEED_EPSS_MODE", FeedModeSelf)
	if err != nil {
		return nil, err
	}
	nvdMode, err := envFeedModeOrDefault("PACKMON_FEED_NVD_MODE", FeedModeSelf)
	if err != nil {
		return nil, err
	}
	if nvdMode == FeedModeExternal {
		return nil, fmt.Errorf("PACKMON_FEED_NVD_MODE does not support external mode: NVD has no import endpoint")
	}
	socketMode, err := envFeedModeOrDefault("PACKMON_FEED_SOCKET_MODE", FeedModeSelf)
	if err != nil {
		return nil, err
	}
	reversingLabsAPIKey := os.Getenv("PACKMON_REVERSINGLABS_API_KEY")
	reversingLabsBaseURL := envOrDefault("PACKMON_REVERSINGLABS_API_BASE_URL", "https://data.reversinglabs.com/api/oss/community/v2/free")
	if err := validateReversingLabsBaseURL(reversingLabsAPIKey, reversingLabsBaseURL); err != nil {
		return nil, err
	}
	endOfLifeBaseURL := envOrDefault("PACKMON_ENDOFLIFE_API_BASE_URL", "https://endoflife.date/api/v1")
	if err := validateEndOfLifeBaseURL(endOfLifeBaseURL); err != nil {
		return nil, err
	}

	// Default SSL mode depends on server mode.
	defaultSSL := "verify-full"
	if mode == ModeDevelopment {
		defaultSSL = "disable"
	}

	// Default log level depends on server mode.
	defaultLogLevel := "info"
	if mode == ModeDevelopment {
		defaultLogLevel = "debug"
	}

	cfg := &Config{
		Server: ServerConfig{
			Port:                   serverPort,
			Mode:                   mode,
			PublicHost:             envOrDefault("PACKMON_SERVER_PUBLIC_HOST", ""),
			TrustedProxies:         splitCSVEnv(os.Getenv("PACKMON_TRUSTED_PROXIES")),
			AllowInsecureLocalHTTP: allowInsecureLocalHTTP,
			InsecureLocalHTTPBind:  insecureLocalHTTPBind,
			BlockThreshold:         blockThreshold,
			RateLimitPerMinute:     rateLimitPerMinute,
			RateLimitBurst:         rateLimitBurst,
			ReadTimeout:            readTimeout,
			WriteTimeout:           writeTimeout,
			ShutdownTimeout:        shutdownTimeout,
			TLS: TLSConfig{
				CertFile:   envOrDefault("PACKMON_TLS_CERT_FILE", ""),
				KeyFile:    envOrDefault("PACKMON_TLS_KEY_FILE", ""),
				MinVersion: tlsMinVersion,
			},
		},
		DB: DBConfig{
			Host:           envOrDefault("PACKMON_DB_HOST", "localhost"),
			Port:           dbPort,
			Name:           envOrDefault("PACKMON_DB_NAME", "packmon"),
			User:           envOrDefault("PACKMON_DB_USER", "packmon"),
			Password:       os.Getenv("PACKMON_DB_PASSWORD"),
			SSLMode:        envOrDefault("PACKMON_DB_SSLMODE", defaultSSL),
			MaxConns:       dbMaxConns,
			MinConns:       dbMinConns,
			ConnectTimeout: dbConnectTimeout,
		},
		Log: LogConfig{
			Level:  envOrDefault("PACKMON_LOG_LEVEL", defaultLogLevel),
			Format: envOrDefault("PACKMON_LOG_FORMAT", "json"),
		},
		Metrics: MetricsConfig{
			Host: envOrDefault("PACKMON_METRICS_HOST", "127.0.0.1"),
			Port: metricsPort,
		},
		Web: WebConfig{
			PrivacyURL: privacyURL,
			LegalURL:   legalURL,
		},
		Admin: AdminConfig{
			InitialPassword: os.Getenv("PACKMON_ADMIN_INITIAL_PASSWORD"),
			SessionTimeout:  sessionTimeout,
			IdleTimeout:     adminIdleTimeout,
			EncryptionKey:   os.Getenv("PACKMON_ENCRYPTION_KEY"),
		},
		Retention: RetentionConfig{
			ScanLog:       scanLogRetention,
			AdminAuditLog: adminAuditRetention,
			RefreshQueue:  refreshQueueRetention,
			Interval:      auditRetentionInterval,
		},
		FeedSync: FeedSyncConfig{
			Interval:  syncInterval,
			OnStartup: feedSyncOnStartup,
		},
		Feeds: FeedsConfig{
			DataDir: envOrDefault("PACKMON_FEED_DATA_DIR",
				filepath.Join(os.TempDir(), "packmon-feeds")),

			OSVEnabled:           osvEnabled,
			GHSAEnabled:          ghsaEnabled,
			OpenSSFEnabled:       openSSFEnabled,
			VulnCheckEnabled:     vulnCheckEnabled,
			SocketEnabled:        socketEnabled,
			ReversingLabsEnabled: reversingLabsEnabled,
			CISAKEVEnabled:       cisaKEVEnabled,
			EPSSEnabled:          epssEnabled,
			NVDEnabled:           nvdEnabled,
			EndOfLifeEnabled:     endOfLifeEnabled,

			OSVMode:           osvMode,
			GHSAMode:          ghsaMode,
			OpenSSFMode:       openSSFMode,
			VulnCheckMode:     vulnCheckMode,
			CISAKEVMode:       cisaKEVMode,
			EPSSMode:          epssMode,
			NVDMode:           nvdMode,
			EndOfLifeMode:     endOfLifeMode,
			SocketMode:        socketMode,
			ReversingLabsMode: reversingLabsMode,

			FeedImportSecret:                 os.Getenv("PACKMON_FEED_IMPORT_SECRET"),
			VulnCheckAPIKey:                  os.Getenv("PACKMON_VULNCHECK_API_KEY"),
			SocketAPIKey:                     os.Getenv("PACKMON_SOCKET_API_KEY"),
			ReversingLabsAPIKey:              reversingLabsAPIKey,
			ReversingLabsBaseURL:             reversingLabsBaseURL,
			ReversingLabsLookupTTL:           reversingLabsTTL,
			ReversingLabsBatchSize:           reversingLabsBatchSize,
			ReversingLabsMaxSchedulePerCheck: reversingLabsMaxSchedule,
			ReversingLabsCacheRetention:      reversingLabsCacheRetention,
			ReversingLabsExcludedNamespaces:  splitCSVEnv(os.Getenv("PACKMON_REVERSINGLABS_EXCLUDED_NAMESPACES")),
			EndOfLifeBaseURL:                 endOfLifeBaseURL,
			NVDAPIKey:                        os.Getenv("PACKMON_NVD_API_KEY"),
		},
	}

	return cfg, nil
}

// Addr returns the metrics listen address.
func (m MetricsConfig) Addr() string {
	host := strings.TrimSpace(m.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(m.Port))
}

// IsDevelopment is a convenience check on the server mode.
func (c *Config) IsDevelopment() bool {
	return c.Server.Mode == ModeDevelopment
}

// ValidateTransportSecurity enforces a fail-closed transport policy in
// production: the server must either terminate TLS itself (cert+key) or sit
// behind a trusted reverse proxy (PACKMON_TRUSTED_PROXIES). Otherwise it would
// serve cleartext HTTP directly on the network, exposing bearer tokens.
//
// In development mode this always returns nil. It is intended to be called
// from main.go at startup, not from server.New, so that httptest-based tests
// can construct production servers without configuring TLS.
func (c *Config) ValidateTransportSecurity() error {
	if c.IsDevelopment() {
		return nil
	}
	if c.Server.TLS.Enabled() {
		return nil
	}
	trustedProxies, err := netutil.ParseTrustedProxies(c.Server.TrustedProxies)
	if err != nil {
		return fmt.Errorf("config: invalid PACKMON_TRUSTED_PROXIES: %w", err)
	}
	if trustedProxies.Len() > 0 {
		return nil
	}
	if c.Server.AllowInsecureLocalHTTP {
		if isLoopbackPublicHost(c.Server.PublicHost) {
			return nil
		}
		return fmt.Errorf("config: PACKMON_ALLOW_INSECURE_LOCAL_HTTP requires PACKMON_SERVER_PUBLIC_HOST to be localhost, 127.0.0.1, or ::1; configure TLS or PACKMON_TRUSTED_PROXIES for non-local production use")
	}
	return fmt.Errorf("config: refusing to start in production without transport security: set PACKMON_TLS_CERT_FILE and PACKMON_TLS_KEY_FILE for in-app TLS, or PACKMON_TRUSTED_PROXIES when running behind a TLS-terminating reverse proxy")
}

// --- helpers ----------------------------------------------------------------

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOrDefault(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s (want integer)", key)
	}
	return n, nil
}

func envInt32OrDefault(key string, fallback int32) (int32, error) {
	const (
		minInt32 = -1 << 31
		maxInt32 = 1<<31 - 1
	)

	n, err := envIntOrDefault(key, int(fallback))
	if err != nil {
		return 0, err
	}
	if n < minInt32 || n > maxInt32 {
		return 0, fmt.Errorf("config: %s must fit in int32", key)
	}
	return int32(n), nil
}

func envPositiveIntOrDefault(key string, fallback int) (int, error) {
	n, err := envIntOrDefault(key, fallback)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, fmt.Errorf("config: %s must be greater than zero", key)
	}
	return n, nil
}

func envDurationOrDefault(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s (want duration, for example 30s, 5m, or 1h)", key)
	}
	return d, nil
}

func envNonNegativeDurationOrDefault(key string, fallback time.Duration) (time.Duration, error) {
	d, err := envDurationOrDefault(key, fallback)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("config: %s must be zero or greater", key)
	}
	return d, nil
}

func envPositiveDurationOrDefault(key string, fallback time.Duration) (time.Duration, error) {
	d, err := envDurationOrDefault(key, fallback)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("config: %s must be greater than zero", key)
	}
	return d, nil
}

func envBoolOrDefault(key string, fallback bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("config: invalid %s (want true or false)", key)
	}
	return b, nil
}

func envFeedModeOrDefault(key string, fallback FeedMode) (FeedMode, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	mode, err := ParseFeedMode(raw)
	if err != nil {
		return "", fmt.Errorf("config: invalid %s (want self or external)", key)
	}
	return mode, nil
}

func envWebNoticeURLOrDefault(key, fallback string) (string, error) {
	raw := strings.TrimSpace(envOrDefault(key, fallback))
	if raw == "" {
		return "", nil
	}
	if strings.HasPrefix(raw, "/") {
		if strings.HasPrefix(raw, "//") {
			return "", fmt.Errorf("config: %s must be a root-relative path or absolute http(s) URL", key)
		}
		return raw, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("config: %s must be a root-relative path or absolute http(s) URL", key)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return raw, nil
	default:
		return "", fmt.Errorf("config: %s must use http or https URLs", key)
	}
}

// parseTLSMinVersion validates and normalizes the configured minimum TLS
// version. Only "1.2" and "1.3" are accepted.
func parseTLSMinVersion(raw string) (string, error) {
	normalized := strings.TrimSpace(raw)
	switch normalized {
	case "1.2", "1.3":
		return normalized, nil
	default:
		return "", fmt.Errorf("config: invalid PACKMON_TLS_MIN_VERSION (want 1.2 or 1.3)")
	}
}

func parseInsecureLocalHTTPBind(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case "", "loopback":
		return "loopback", nil
	case "container":
		return "container", nil
	default:
		return "", fmt.Errorf("config: invalid PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE (want loopback or container)")
	}
}

func isLoopbackPublicHost(raw string) bool {
	hostport := strings.TrimSpace(raw)
	if hostport == "" {
		return false
	}
	if strings.Contains(hostport, "://") {
		u, err := url.Parse(hostport)
		if err != nil {
			return false
		}
		hostport = u.Host
	}

	host := hostport
	if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsedHost
	}
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateReversingLabsBaseURL(apiKey, raw string) error {
	if strings.TrimSpace(apiKey) == "" {
		return nil
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("config: invalid PACKMON_REVERSINGLABS_API_BASE_URL (want absolute http(s) URL)")
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(parsed.Scheme, "http") && isLoopbackPublicHost(parsed.Host) {
		return nil
	}
	return fmt.Errorf("config: PACKMON_REVERSINGLABS_API_BASE_URL must use https when PACKMON_REVERSINGLABS_API_KEY is configured; http is allowed only for loopback test endpoints")
}

func validateEndOfLifeBaseURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("config: invalid PACKMON_ENDOFLIFE_API_BASE_URL (want absolute http(s) URL)")
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(parsed.Scheme, "http") && isLoopbackPublicHost(parsed.Host) {
		return nil
	}
	return fmt.Errorf("config: PACKMON_ENDOFLIFE_API_BASE_URL must use https; http is allowed only for loopback test endpoints")
}

func parseBlockThreshold(raw string) (string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(raw))
	switch normalized {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE":
		return normalized, nil
	default:
		return "", fmt.Errorf("config: invalid PACKMON_BLOCK_THRESHOLD (want CRITICAL, HIGH, MEDIUM, LOW, or NONE)")
	}
}

func splitCSVEnv(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
