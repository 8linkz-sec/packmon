// Package config loads server configuration from environment variables
// with sensible defaults. No Viper dependency -- just os.Getenv with
// fallback values, following 12-factor principles.
package config

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/netutil"
)

// ServerMode controls runtime behaviour (TLS enforcement, auth bypass, log defaults).
type ServerMode string

const (
	ModeProduction  ServerMode = "production"
	ModeDevelopment ServerMode = "development"

	// DefaultAdminIdleTimeout is the server-side inactivity timeout used when
	// PACKMON_ADMIN_IDLE_TIMEOUT is not set.
	DefaultAdminIdleTimeout = 15 * time.Minute
)

// ScanLogIdentityMode controls which identity-adjacent fields are retained in
// server-side scan_log rows.
type ScanLogIdentityMode string

const (
	// ScanLogIdentityModeFull preserves the historical scan_log metadata shape.
	ScanLogIdentityModeFull ScanLogIdentityMode = "full"
	// ScanLogIdentityModeMinimal drops client IP and API-key identity fields.
	ScanLogIdentityModeMinimal ScanLogIdentityMode = "minimal"
	// ScanLogIdentityModeNone drops client/API-key identity, repo name, and
	// normalized client version fields.
	ScanLogIdentityModeNone ScanLogIdentityMode = "none"
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

// FeedMode controls whether the server runs a feed syncer itself or expects an
// external system to push data through authenticated import endpoints.
type FeedMode = domain.FeedMode

const (
	FeedModeSelf     = domain.FeedModeSelf
	FeedModeExternal = domain.FeedModeExternal
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
	VulnCheckBaseURL       string
	SocketAPIKey           string
	SocketBaseURL          string
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
	SocketExcludedNamespaces        []string
	OSVBaseURL                      string
	GHSARepoURL                     string
	OpenSSFRepoURL                  string
	CISAKEVCatalogURL               string
	EPSSScoresURL                   string
	EndOfLifeBaseURL                string
	NVDAPIURL                       string
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
	ScanLogIdentityMode    ScanLogIdentityMode
	BlockThreshold         string
	RateLimitPerMinute     int
	RateLimitBurst         int
	ReadTimeout            time.Duration
	WriteTimeout           time.Duration
	ShutdownTimeout        time.Duration
	TLS                    TLSConfig
}

// Addr returns the main listener address for the configured server mode.
// Development always binds to loopback. Production normally uses the wildcard
// bind, but the explicit local HTTP override binds to loopback unless
// PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE=container requests container-wide
// exposure for the bundled local stack.
func (s ServerConfig) Addr() string {
	if s.Mode == ModeDevelopment {
		return fmt.Sprintf("127.0.0.1:%d", s.Port)
	}
	if s.InsecureLocalHTTPOverrideActive() && s.InsecureLocalHTTPBind != "container" {
		return fmt.Sprintf("127.0.0.1:%d", s.Port)
	}
	return fmt.Sprintf(":%d", s.Port)
}

// InsecureLocalHTTPOverrideActive reports whether the local-only production
// HTTP exception is actually in force. The override is active only in
// production, with TLS disabled, no trusted proxies configured, and a valid
// trusted-proxy configuration.
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
	// TermsURL is linked from the shared footer. It defaults to Packmon's
	// built-in operator-facing terms hook at /terms.
	TermsURL string
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
	// AdminAuditHMACKey is a base64-encoded 32-byte key used to HMAC new
	// admin audit digest-chain rows. Production startup requires it.
	AdminAuditHMACKey string
}

// RetentionConfig controls pruning for server-side operational metadata.
type RetentionConfig struct {
	// ScanLog is the maximum age for scan_log rows. Zero disables pruning.
	ScanLog time.Duration
	// AdminAuditLog is the maximum age for admin_audit_log rows. Zero disables pruning.
	AdminAuditLog time.Duration
	// RefreshQueue is the maximum age for terminal refresh_queue rows. Zero disables pruning.
	RefreshQueue time.Duration
	// PackageCheckStatus is the maximum age for Socket.dev package_check_status rows. Zero disables pruning.
	PackageCheckStatus time.Duration
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
	mode, err := loadServerMode()
	if err != nil {
		return nil, err
	}

	server, err := loadServerConfig(mode)
	if err != nil {
		return nil, err
	}
	db, err := loadDBConfig(mode)
	if err != nil {
		return nil, err
	}
	metrics, err := loadMetricsConfig()
	if err != nil {
		return nil, err
	}
	logConfig, err := loadLogConfig(mode)
	if err != nil {
		return nil, err
	}
	web, err := loadWebConfig()
	if err != nil {
		return nil, err
	}
	admin, err := loadAdminConfig()
	if err != nil {
		return nil, err
	}
	retention, err := loadRetentionConfig()
	if err != nil {
		return nil, err
	}
	feedSync, err := loadFeedSyncConfig()
	if err != nil {
		return nil, err
	}
	feeds, err := loadFeedsConfig()
	if err != nil {
		return nil, err
	}

	return &Config{
		Server:    server,
		DB:        db,
		Log:       logConfig,
		Metrics:   metrics,
		Web:       web,
		Admin:     admin,
		Retention: retention,
		FeedSync:  feedSync,
		Feeds:     feeds,
	}, nil
}

func loadServerMode() (ServerMode, error) {
	mode := ServerMode(envOrDefault("PACKMON_SERVER_MODE", "production"))
	if mode != ModeProduction && mode != ModeDevelopment {
		return "", fmt.Errorf("config: invalid PACKMON_SERVER_MODE (want production or development)")
	}
	return mode, nil
}

func loadServerConfig(mode ServerMode) (ServerConfig, error) {
	serverPort, err := envListenPortOrDefault("PACKMON_SERVER_PORT", 8080)
	if err != nil {
		return ServerConfig{}, err
	}
	publicHost, err := envPublicHostOrDefault("PACKMON_SERVER_PUBLIC_HOST", "")
	if err != nil {
		return ServerConfig{}, err
	}
	rateLimitPerMinute, err := envPositiveIntOrDefault("PACKMON_RATE_LIMIT_PER_MINUTE", 60)
	if err != nil {
		return ServerConfig{}, err
	}
	rateLimitBurst, err := envPositiveIntOrDefault("PACKMON_RATE_LIMIT_BURST", 60)
	if err != nil {
		return ServerConfig{}, err
	}
	blockThreshold, err := parseBlockThreshold(envOrDefault("PACKMON_BLOCK_THRESHOLD", "CRITICAL"))
	if err != nil {
		return ServerConfig{}, err
	}
	scanLogIdentityMode, err := ScanLogIdentityModeFromEnv()
	if err != nil {
		return ServerConfig{}, err
	}
	readTimeout, err := envPositiveDurationOrDefault("PACKMON_SERVER_READ_TIMEOUT", 30*time.Second)
	if err != nil {
		return ServerConfig{}, err
	}
	writeTimeout, err := envPositiveDurationOrDefault("PACKMON_SERVER_WRITE_TIMEOUT", 30*time.Second)
	if err != nil {
		return ServerConfig{}, err
	}
	shutdownTimeout, err := envPositiveDurationOrDefault("PACKMON_SERVER_SHUTDOWN_TIMEOUT", 5*time.Second)
	if err != nil {
		return ServerConfig{}, err
	}
	tlsConfig, err := loadTLSConfig()
	if err != nil {
		return ServerConfig{}, err
	}
	insecureLocalHTTPBind, err := parseInsecureLocalHTTPBind(envOrDefault("PACKMON_INSECURE_LOCAL_HTTP_BIND_MODE", "loopback"))
	if err != nil {
		return ServerConfig{}, err
	}
	allowInsecureLocalHTTP, err := envBoolOrDefault("PACKMON_ALLOW_INSECURE_LOCAL_HTTP", false)
	if err != nil {
		return ServerConfig{}, err
	}

	return ServerConfig{
		Port:                   serverPort,
		Mode:                   mode,
		PublicHost:             publicHost,
		TrustedProxies:         splitCSVEnv(os.Getenv("PACKMON_TRUSTED_PROXIES")),
		AllowInsecureLocalHTTP: allowInsecureLocalHTTP,
		InsecureLocalHTTPBind:  insecureLocalHTTPBind,
		ScanLogIdentityMode:    scanLogIdentityMode,
		BlockThreshold:         blockThreshold,
		RateLimitPerMinute:     rateLimitPerMinute,
		RateLimitBurst:         rateLimitBurst,
		ReadTimeout:            readTimeout,
		WriteTimeout:           writeTimeout,
		ShutdownTimeout:        shutdownTimeout,
		TLS:                    tlsConfig,
	}, nil
}

func loadTLSConfig() (TLSConfig, error) {
	tlsMinVersion, err := parseTLSMinVersion(envOrDefault("PACKMON_TLS_MIN_VERSION", "1.2"))
	if err != nil {
		return TLSConfig{}, err
	}
	return TLSConfig{
		CertFile:   envOrDefault("PACKMON_TLS_CERT_FILE", ""),
		KeyFile:    envOrDefault("PACKMON_TLS_KEY_FILE", ""),
		MinVersion: tlsMinVersion,
	}, nil
}

func loadDBConfig(mode ServerMode) (DBConfig, error) {
	dbPort, err := envPortOrDefault("PACKMON_DB_PORT", 5432)
	if err != nil {
		return DBConfig{}, err
	}
	dbMaxConns, err := envInt32OrDefault("PACKMON_DB_MAX_CONNS", 20)
	if err != nil {
		return DBConfig{}, err
	}
	dbMinConns, err := envInt32OrDefault("PACKMON_DB_MIN_CONNS", 2)
	if err != nil {
		return DBConfig{}, err
	}
	if err := validateDBPoolConns(dbMaxConns, dbMinConns); err != nil {
		return DBConfig{}, err
	}
	dbConnectTimeout, err := envPositiveDurationOrDefault("PACKMON_DB_CONNECT_TIMEOUT", 10*time.Second)
	if err != nil {
		return DBConfig{}, err
	}

	defaultSSL := "verify-full"
	if mode == ModeDevelopment {
		defaultSSL = "disable"
	}
	dbHost := envOrDefault("PACKMON_DB_HOST", "localhost")
	dbSSLMode := envOrDefault("PACKMON_DB_SSLMODE", defaultSSL)
	if err := validateDBSSLMode(mode, dbHost, dbSSLMode); err != nil {
		return DBConfig{}, err
	}

	return DBConfig{
		Host:           dbHost,
		Port:           dbPort,
		Name:           envOrDefault("PACKMON_DB_NAME", "packmon"),
		User:           envOrDefault("PACKMON_DB_USER", "packmon"),
		Password:       os.Getenv("PACKMON_DB_PASSWORD"),
		SSLMode:        dbSSLMode,
		MaxConns:       dbMaxConns,
		MinConns:       dbMinConns,
		ConnectTimeout: dbConnectTimeout,
	}, nil
}

func loadLogConfig(mode ServerMode) (LogConfig, error) {
	defaultLogLevel := "info"
	if mode == ModeDevelopment {
		defaultLogLevel = "debug"
	}
	level, err := parseLogLevel("PACKMON_LOG_LEVEL", envOrDefault("PACKMON_LOG_LEVEL", defaultLogLevel))
	if err != nil {
		return LogConfig{}, err
	}
	format, err := parseLogFormat("PACKMON_LOG_FORMAT", envOrDefault("PACKMON_LOG_FORMAT", "json"))
	if err != nil {
		return LogConfig{}, err
	}
	return LogConfig{
		Level:  level,
		Format: format,
	}, nil
}

func loadMetricsConfig() (MetricsConfig, error) {
	metricsPort, err := envListenPortOrDefault("PACKMON_METRICS_PORT", 9090)
	if err != nil {
		return MetricsConfig{}, err
	}
	return MetricsConfig{
		Host: envOrDefault("PACKMON_METRICS_HOST", "127.0.0.1"),
		Port: metricsPort,
	}, nil
}

func loadWebConfig() (WebConfig, error) {
	privacyURL, err := envWebNoticeURLOrDefault("PACKMON_WEB_PRIVACY_URL", "/privacy")
	if err != nil {
		return WebConfig{}, err
	}
	legalURL, err := envWebNoticeURLOrDefault("PACKMON_WEB_LEGAL_URL", "")
	if err != nil {
		return WebConfig{}, err
	}
	termsURL, err := envWebNoticeURLOrDefault("PACKMON_WEB_TERMS_URL", "/terms")
	if err != nil {
		return WebConfig{}, err
	}
	return WebConfig{
		PrivacyURL: privacyURL,
		LegalURL:   legalURL,
		TermsURL:   termsURL,
	}, nil
}

func loadAdminConfig() (AdminConfig, error) {
	sessionTimeout, err := envPositiveDurationOrDefault("PACKMON_ADMIN_SESSION_TIMEOUT", 8*time.Hour)
	if err != nil {
		return AdminConfig{}, err
	}
	adminIdleTimeout, err := envPositiveDurationOrDefault("PACKMON_ADMIN_IDLE_TIMEOUT", DefaultAdminIdleTimeout)
	if err != nil {
		return AdminConfig{}, err
	}
	adminAuditHMACKey := os.Getenv("PACKMON_ADMIN_AUDIT_HMAC_KEY")
	if err := validateAdminAuditHMACKey(adminAuditHMACKey); err != nil {
		return AdminConfig{}, err
	}
	return AdminConfig{
		InitialPassword:   os.Getenv("PACKMON_ADMIN_INITIAL_PASSWORD"),
		SessionTimeout:    sessionTimeout,
		IdleTimeout:       adminIdleTimeout,
		EncryptionKey:     os.Getenv("PACKMON_ENCRYPTION_KEY"),
		AdminAuditHMACKey: adminAuditHMACKey,
	}, nil
}

func validateAdminAuditHMACKey(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("config: PACKMON_ADMIN_AUDIT_HMAC_KEY must be base64-encoded 32 random bytes")
	}
	return nil
}

func loadRetentionConfig() (RetentionConfig, error) {
	scanLogRetention, err := envNonNegativeDurationOrDefault("PACKMON_SCAN_LOG_RETENTION", 30*24*time.Hour)
	if err != nil {
		return RetentionConfig{}, err
	}
	adminAuditRetention, err := envNonNegativeDurationOrDefault("PACKMON_ADMIN_AUDIT_LOG_RETENTION", 30*24*time.Hour)
	if err != nil {
		return RetentionConfig{}, err
	}
	refreshQueueRetention, err := envNonNegativeDurationOrDefault("PACKMON_REFRESH_QUEUE_RETENTION", 30*24*time.Hour)
	if err != nil {
		return RetentionConfig{}, err
	}
	packageCheckStatusRetention, err := envNonNegativeDurationOrDefault("PACKMON_PACKAGE_CHECK_STATUS_RETENTION", 90*24*time.Hour)
	if err != nil {
		return RetentionConfig{}, err
	}
	auditRetentionInterval, err := envPositiveDurationOrDefault("PACKMON_AUDIT_RETENTION_INTERVAL", 24*time.Hour)
	if err != nil {
		return RetentionConfig{}, err
	}
	return RetentionConfig{
		ScanLog:            scanLogRetention,
		AdminAuditLog:      adminAuditRetention,
		RefreshQueue:       refreshQueueRetention,
		PackageCheckStatus: packageCheckStatusRetention,
		Interval:           auditRetentionInterval,
	}, nil
}

func loadFeedSyncConfig() (FeedSyncConfig, error) {
	syncInterval, err := envPositiveDurationOrDefault("PACKMON_FEED_SYNC_INTERVAL", 8*time.Hour)
	if err != nil {
		return FeedSyncConfig{}, err
	}
	if syncInterval < FeedSyncMinInterval {
		return FeedSyncConfig{}, fmt.Errorf("config: PACKMON_FEED_SYNC_INTERVAL must be at least %s", FeedSyncMinInterval)
	}
	feedSyncOnStartup, err := envBoolOrDefault("PACKMON_FEED_SYNC_ON_STARTUP", false)
	if err != nil {
		return FeedSyncConfig{}, err
	}
	return FeedSyncConfig{
		Interval:  syncInterval,
		OnStartup: feedSyncOnStartup,
	}, nil
}

func loadFeedsConfig() (FeedsConfig, error) {
	enabled, err := loadFeedEnabledConfig()
	if err != nil {
		return FeedsConfig{}, err
	}
	modes, err := loadFeedModeConfig()
	if err != nil {
		return FeedsConfig{}, err
	}
	provider, err := loadFeedProviderConfig()
	if err != nil {
		return FeedsConfig{}, err
	}

	cfg := provider
	cfg.OSVEnabled = enabled.OSVEnabled
	cfg.GHSAEnabled = enabled.GHSAEnabled
	cfg.OpenSSFEnabled = enabled.OpenSSFEnabled
	cfg.VulnCheckEnabled = enabled.VulnCheckEnabled
	cfg.SocketEnabled = enabled.SocketEnabled
	cfg.ReversingLabsEnabled = enabled.ReversingLabsEnabled
	cfg.CISAKEVEnabled = enabled.CISAKEVEnabled
	cfg.EPSSEnabled = enabled.EPSSEnabled
	cfg.NVDEnabled = enabled.NVDEnabled
	cfg.EndOfLifeEnabled = enabled.EndOfLifeEnabled

	cfg.OSVMode = modes.OSVMode
	cfg.GHSAMode = modes.GHSAMode
	cfg.OpenSSFMode = modes.OpenSSFMode
	cfg.VulnCheckMode = modes.VulnCheckMode
	cfg.CISAKEVMode = modes.CISAKEVMode
	cfg.EPSSMode = modes.EPSSMode
	cfg.NVDMode = modes.NVDMode
	cfg.EndOfLifeMode = modes.EndOfLifeMode
	cfg.SocketMode = modes.SocketMode
	cfg.ReversingLabsMode = modes.ReversingLabsMode

	return cfg, nil
}

func loadFeedEnabledConfig() (FeedsConfig, error) {
	osvEnabled, err := envBoolOrDefault("PACKMON_FEED_OSV_ENABLED", true)
	if err != nil {
		return FeedsConfig{}, err
	}
	ghsaEnabled, err := envBoolOrDefault("PACKMON_FEED_GHSA_ENABLED", true)
	if err != nil {
		return FeedsConfig{}, err
	}
	openSSFEnabled, err := envBoolOrDefault("PACKMON_FEED_OPENSSF_ENABLED", true)
	if err != nil {
		return FeedsConfig{}, err
	}
	vulnCheckEnabled, err := envBoolOrDefault("PACKMON_FEED_VULNCHECK_ENABLED", false)
	if err != nil {
		return FeedsConfig{}, err
	}
	socketEnabled, err := envBoolOrDefault("PACKMON_FEED_SOCKET_ENABLED", false)
	if err != nil {
		return FeedsConfig{}, err
	}
	reversingLabsEnabled, err := envBoolOrDefault("PACKMON_FEED_REVERSINGLABS_ENABLED", false)
	if err != nil {
		return FeedsConfig{}, err
	}
	cisaKEVEnabled, err := envBoolOrDefault("PACKMON_FEED_CISAKEV_ENABLED", true)
	if err != nil {
		return FeedsConfig{}, err
	}
	epssEnabled, err := envBoolOrDefault("PACKMON_FEED_EPSS_ENABLED", true)
	if err != nil {
		return FeedsConfig{}, err
	}
	nvdEnabled, err := envBoolOrDefault("PACKMON_FEED_NVD_ENABLED", true)
	if err != nil {
		return FeedsConfig{}, err
	}
	endOfLifeEnabled, err := envBoolOrDefault("PACKMON_FEED_ENDOFLIFE_ENABLED", true)
	if err != nil {
		return FeedsConfig{}, err
	}

	return FeedsConfig{
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
	}, nil
}

func loadFeedModeConfig() (FeedsConfig, error) {
	reversingLabsMode, err := envFeedModeOrDefault("PACKMON_FEED_REVERSINGLABS_MODE", FeedModeSelf)
	if err != nil {
		return FeedsConfig{}, err
	}
	if reversingLabsMode == FeedModeExternal {
		return FeedsConfig{}, fmt.Errorf("PACKMON_FEED_REVERSINGLABS_MODE does not support external mode: ReversingLabs is demand-driven and has no import endpoint")
	}
	endOfLifeMode, err := envFeedModeOrDefault("PACKMON_FEED_ENDOFLIFE_MODE", FeedModeSelf)
	if err != nil {
		return FeedsConfig{}, err
	}
	if endOfLifeMode == FeedModeExternal {
		return FeedsConfig{}, fmt.Errorf("PACKMON_FEED_ENDOFLIFE_MODE does not support external mode: endoflife has no import endpoint")
	}

	osvMode, err := envFeedModeOrDefault("PACKMON_FEED_OSV_MODE", FeedModeSelf)
	if err != nil {
		return FeedsConfig{}, err
	}
	ghsaMode, err := envFeedModeOrDefault("PACKMON_FEED_GHSA_MODE", FeedModeSelf)
	if err != nil {
		return FeedsConfig{}, err
	}
	openSSFMode, err := envFeedModeOrDefault("PACKMON_FEED_OPENSSF_MODE", FeedModeSelf)
	if err != nil {
		return FeedsConfig{}, err
	}
	vulnCheckMode, err := envFeedModeOrDefault("PACKMON_FEED_VULNCHECK_MODE", FeedModeSelf)
	if err != nil {
		return FeedsConfig{}, err
	}
	cisaKEVMode, err := envFeedModeOrDefault("PACKMON_FEED_CISAKEV_MODE", FeedModeSelf)
	if err != nil {
		return FeedsConfig{}, err
	}
	epssMode, err := envFeedModeOrDefault("PACKMON_FEED_EPSS_MODE", FeedModeSelf)
	if err != nil {
		return FeedsConfig{}, err
	}
	nvdMode, err := envFeedModeOrDefault("PACKMON_FEED_NVD_MODE", FeedModeSelf)
	if err != nil {
		return FeedsConfig{}, err
	}
	if nvdMode == FeedModeExternal {
		return FeedsConfig{}, fmt.Errorf("PACKMON_FEED_NVD_MODE does not support external mode: NVD has no import endpoint")
	}
	socketMode, err := envFeedModeOrDefault("PACKMON_FEED_SOCKET_MODE", FeedModeSelf)
	if err != nil {
		return FeedsConfig{}, err
	}

	return FeedsConfig{
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
	}, nil
}

func loadFeedProviderConfig() (FeedsConfig, error) {
	reversingLabsTTL, err := envDurationOrDefault("PACKMON_REVERSINGLABS_LOOKUP_TTL", 24*time.Hour)
	if err != nil {
		return FeedsConfig{}, err
	}
	reversingLabsCacheRetention, err := envNonNegativeDurationOrDefault("PACKMON_REVERSINGLABS_CACHE_RETENTION", 7*24*time.Hour)
	if err != nil {
		return FeedsConfig{}, err
	}
	reversingLabsBatchSize, err := envPositiveIntOrDefault("PACKMON_REVERSINGLABS_BATCH_SIZE", 5)
	if err != nil {
		return FeedsConfig{}, err
	}
	if reversingLabsBatchSize > 5 {
		reversingLabsBatchSize = 5
	}
	reversingLabsMaxSchedule, err := envPositiveIntOrDefault("PACKMON_REVERSINGLABS_MAX_SCHEDULE_PER_CHECK", 100)
	if err != nil {
		return FeedsConfig{}, err
	}

	reversingLabsAPIKey := os.Getenv("PACKMON_REVERSINGLABS_API_KEY")
	reversingLabsBaseURL := envOrDefault("PACKMON_REVERSINGLABS_API_BASE_URL", reversingLabsDefaultBaseURL)
	if err := validateReversingLabsBaseURL(reversingLabsAPIKey, reversingLabsBaseURL); err != nil {
		return FeedsConfig{}, err
	}
	vulnCheckBaseURL := envOrDefault("PACKMON_VULNCHECK_API_BASE_URL", vulnCheckDefaultBaseURL)
	if err := validateMirrorURL("PACKMON_VULNCHECK_API_BASE_URL", vulnCheckBaseURL); err != nil {
		return FeedsConfig{}, err
	}
	socketBaseURL := envOrDefault("PACKMON_SOCKET_API_BASE_URL", socketDefaultBaseURL)
	if err := validateMirrorURL("PACKMON_SOCKET_API_BASE_URL", socketBaseURL); err != nil {
		return FeedsConfig{}, err
	}
	osvBaseURL := envOrDefault("PACKMON_FEED_OSV_BASE_URL", "https://osv-vulnerabilities.storage.googleapis.com")
	if err := validateMirrorURL("PACKMON_FEED_OSV_BASE_URL", osvBaseURL); err != nil {
		return FeedsConfig{}, err
	}
	ghsaRepoURL := envOrDefault("PACKMON_FEED_GHSA_REPO_URL", "https://github.com/github/advisory-database.git")
	if err := validateMirrorURL("PACKMON_FEED_GHSA_REPO_URL", ghsaRepoURL); err != nil {
		return FeedsConfig{}, err
	}
	openSSFRepoURL := envOrDefault("PACKMON_FEED_OPENSSF_REPO_URL", "https://github.com/ossf/malicious-packages.git")
	if err := validateMirrorURL("PACKMON_FEED_OPENSSF_REPO_URL", openSSFRepoURL); err != nil {
		return FeedsConfig{}, err
	}
	cisaKEVCatalogURL := envOrDefault("PACKMON_FEED_CISAKEV_CATALOG_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if err := validateMirrorURL("PACKMON_FEED_CISAKEV_CATALOG_URL", cisaKEVCatalogURL); err != nil {
		return FeedsConfig{}, err
	}
	epssScoresURL := envOrDefault("PACKMON_FEED_EPSS_SCORES_URL", "https://epss.cyentia.com/epss_scores-current.csv.gz")
	if err := validateMirrorURL("PACKMON_FEED_EPSS_SCORES_URL", epssScoresURL); err != nil {
		return FeedsConfig{}, err
	}
	nvdAPIURL := envOrDefault("PACKMON_FEED_NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
	if err := validateMirrorURL("PACKMON_FEED_NVD_API_URL", nvdAPIURL); err != nil {
		return FeedsConfig{}, err
	}
	endOfLifeBaseURL := envOrDefault("PACKMON_ENDOFLIFE_API_BASE_URL", "https://endoflife.date/api/v1")
	if err := validateEndOfLifeBaseURL(endOfLifeBaseURL); err != nil {
		return FeedsConfig{}, err
	}

	return FeedsConfig{
		DataDir: envOrDefault("PACKMON_FEED_DATA_DIR",
			filepath.Join(os.TempDir(), "packmon-feeds")),

		FeedImportSecret:                 os.Getenv("PACKMON_FEED_IMPORT_SECRET"),
		VulnCheckAPIKey:                  os.Getenv("PACKMON_VULNCHECK_API_KEY"),
		VulnCheckBaseURL:                 vulnCheckBaseURL,
		SocketAPIKey:                     os.Getenv("PACKMON_SOCKET_API_KEY"),
		SocketBaseURL:                    socketBaseURL,
		ReversingLabsAPIKey:              reversingLabsAPIKey,
		ReversingLabsBaseURL:             reversingLabsBaseURL,
		ReversingLabsLookupTTL:           reversingLabsTTL,
		ReversingLabsBatchSize:           reversingLabsBatchSize,
		ReversingLabsMaxSchedulePerCheck: reversingLabsMaxSchedule,
		ReversingLabsCacheRetention:      reversingLabsCacheRetention,
		ReversingLabsExcludedNamespaces:  splitCSVEnv(os.Getenv("PACKMON_REVERSINGLABS_EXCLUDED_NAMESPACES")),
		SocketExcludedNamespaces:         splitCSVEnv(os.Getenv("PACKMON_SOCKET_EXCLUDED_NAMESPACES")),
		OSVBaseURL:                       osvBaseURL,
		GHSARepoURL:                      ghsaRepoURL,
		OpenSSFRepoURL:                   openSSFRepoURL,
		CISAKEVCatalogURL:                cisaKEVCatalogURL,
		EPSSScoresURL:                    epssScoresURL,
		EndOfLifeBaseURL:                 endOfLifeBaseURL,
		NVDAPIURL:                        nvdAPIURL,
		NVDAPIKey:                        os.Getenv("PACKMON_NVD_API_KEY"),
	}, nil
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
	trustedProxies, err := netutil.ParseTrustedProxies(c.Server.TrustedProxies)
	if err != nil {
		return fmt.Errorf("config: invalid PACKMON_TRUSTED_PROXIES: %w", err)
	}
	if c.Server.TLS.Enabled() {
		return nil
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

// ValidateMetricsExposure enforces that the unauthenticated plaintext metrics
// listener stays on loopback in production.
func (c *Config) ValidateMetricsExposure() error {
	if c == nil || c.IsDevelopment() {
		return nil
	}
	host := strings.TrimSpace(c.Metrics.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	if netutil.IsLoopbackHost(host) {
		return nil
	}
	return fmt.Errorf("config: PACKMON_METRICS_HOST must bind to a loopback address in production because /metrics is unauthenticated plaintext HTTP")
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

func envPortOrDefault(key string, fallback int) (int, error) {
	n, err := envIntOrDefault(key, fallback)
	if err != nil {
		return 0, err
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("config: %s must be between 1 and 65535", key)
	}
	return n, nil
}

func envListenPortOrDefault(key string, fallback int) (int, error) {
	n, err := envIntOrDefault(key, fallback)
	if err != nil {
		return 0, err
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("config: %s must be between 0 and 65535", key)
	}
	return n, nil
}

func envPublicHostOrDefault(key, fallback string) (string, error) {
	value := envOrDefault(key, fallback)
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	if err := validatePublicHost(key, value); err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func validatePublicHost(key, raw string) error {
	hostport := strings.TrimSpace(raw)
	if hostport == "" || strings.ContainsAny(hostport, "/\\@") || strings.Contains(hostport, "://") {
		return fmt.Errorf("config: invalid %s (want host[:port] without scheme, path, or userinfo)", key)
	}
	host := hostport
	port := ""
	if strings.HasPrefix(hostport, "[") {
		end := strings.Index(hostport, "]")
		if end < 0 {
			return fmt.Errorf("config: invalid %s (want host[:port] without scheme, path, or userinfo)", key)
		}
		host = hostport[1:end]
		rest := hostport[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || strings.Count(rest, ":") != 1 {
				return fmt.Errorf("config: invalid %s (want host[:port] without scheme, path, or userinfo)", key)
			}
			port = strings.TrimPrefix(rest, ":")
		}
	} else if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, p
	} else if strings.Count(hostport, ":") == 1 {
		idx := strings.LastIndex(hostport, ":")
		host, port = hostport[:idx], hostport[idx+1:]
	} else if strings.Contains(hostport, ":") {
		host = hostport
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("config: invalid %s (want host[:port] without scheme, path, or userinfo)", key)
	}
	if port != "" {
		parsed, err := strconv.Atoi(port)
		if err != nil || parsed < 1 || parsed > 65535 {
			return fmt.Errorf("config: invalid %s (want host[:port] with port between 1 and 65535)", key)
		}
	}
	return nil
}

func parseLogLevel(key, raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case "debug", "info", "warn", "error":
		return normalized, nil
	default:
		return "", fmt.Errorf("config: invalid %s (want debug, info, warn, or error)", key)
	}
}

func parseLogFormat(key, raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case "json", "console":
		return normalized, nil
	default:
		return "", fmt.Errorf("config: invalid %s (want json or console)", key)
	}
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

// ScanLogIdentityModeFromEnv validates PACKMON_SCAN_LOG_IDENTITY_MODE and
// returns the compatibility-preserving default when it is unset.
func ScanLogIdentityModeFromEnv() (ScanLogIdentityMode, error) {
	raw := strings.TrimSpace(os.Getenv("PACKMON_SCAN_LOG_IDENTITY_MODE"))
	if raw == "" {
		return ScanLogIdentityModeFull, nil
	}
	return ParseScanLogIdentityMode(raw)
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

func validateDBPoolConns(maxConns, minConns int32) error {
	if maxConns < 0 {
		return fmt.Errorf("config: PACKMON_DB_MAX_CONNS must be zero or greater")
	}
	if minConns < 0 {
		return fmt.Errorf("config: PACKMON_DB_MIN_CONNS must be zero or greater")
	}
	if maxConns > 0 && minConns > maxConns {
		return fmt.Errorf("config: PACKMON_DB_MIN_CONNS cannot exceed PACKMON_DB_MAX_CONNS when both are greater than zero")
	}
	return nil
}

func validateDBSSLMode(mode ServerMode, host, sslMode string) error {
	normalized := strings.ToLower(strings.TrimSpace(sslMode))
	switch normalized {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("config: invalid PACKMON_DB_SSLMODE (want disable, allow, prefer, require, verify-ca, or verify-full)")
	}
	if mode != ModeProduction || normalized != "disable" {
		return nil
	}
	if isLocalDBHost(host) {
		return nil
	}
	return fmt.Errorf("config: PACKMON_DB_SSLMODE=disable is only allowed for the bundled local database; use verify-full or another TLS sslmode for shared production databases")
}

func isLocalDBHost(raw string) bool {
	host := strings.Trim(strings.ToLower(strings.TrimSpace(raw)), "[]")
	switch host {
	case "localhost", "postgres", "db", "packmon-db":
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
	return fmt.Errorf("config: PACKMON_REVERSINGLABS_API_BASE_URL must use https when a ReversingLabs API key is configured; http is allowed only for loopback test endpoints")
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

func validateMirrorURL(envName, raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("config: invalid %s (want absolute http(s) URL)", envName)
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(parsed.Scheme, "http") && isLoopbackPublicHost(parsed.Host) {
		return nil
	}
	return fmt.Errorf("config: %s must use https; http is allowed only for loopback test endpoints", envName)
}

func parseBlockThreshold(raw string) (string, error) {
	if threshold, ok := domain.ParseBlockThreshold(raw); ok {
		return string(threshold), nil
	}
	return "", fmt.Errorf("config: invalid PACKMON_BLOCK_THRESHOLD (want CRITICAL, HIGH, MEDIUM, LOW, or NONE)")
}

// ParseScanLogIdentityMode validates a scan_log identity retention mode.
func ParseScanLogIdentityMode(raw string) (ScanLogIdentityMode, error) {
	switch ScanLogIdentityMode(strings.ToLower(strings.TrimSpace(raw))) {
	case ScanLogIdentityModeFull:
		return ScanLogIdentityModeFull, nil
	case ScanLogIdentityModeMinimal:
		return ScanLogIdentityModeMinimal, nil
	case ScanLogIdentityModeNone:
		return ScanLogIdentityModeNone, nil
	default:
		return "", fmt.Errorf("config: invalid PACKMON_SCAN_LOG_IDENTITY_MODE (want full, minimal, or none)")
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
