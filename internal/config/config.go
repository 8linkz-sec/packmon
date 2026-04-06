// Package config loads server configuration from environment variables
// with sensible defaults. No Viper dependency -- just os.Getenv with
// fallback values, following 12-factor principles.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ServerMode controls runtime behaviour (TLS enforcement, auth bypass, log defaults).
type ServerMode string

const (
	ModeProduction  ServerMode = "production"
	ModeDevelopment ServerMode = "development"
)

// Config holds all server configuration values.
type Config struct {
	Server   ServerConfig
	DB       DBConfig
	Log      LogConfig
	Metrics  MetricsConfig
	Admin    AdminConfig
	FeedSync FeedSyncConfig
	Feeds    FeedsConfig
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
	OSVEnabled       bool
	GHSAEnabled      bool
	OpenSSFEnabled   bool
	VulnCheckEnabled bool
	SocketEnabled    bool
	CISAKEVEnabled   bool
	EPSSEnabled      bool

	// Per-feed mode: "self" (server syncs) or "external" (N8N pushes).
	OSVMode       FeedMode
	GHSAMode      FeedMode
	OpenSSFMode   FeedMode
	VulnCheckMode FeedMode
	CISAKEVMode   FeedMode
	EPSSMode      FeedMode
	SocketMode    FeedMode

	// Optional per-feed sync interval overrides. Zero means "use
	// PACKMON_FEED_SYNC_INTERVAL".
	OSVInterval       time.Duration
	GHSAInterval      time.Duration
	OpenSSFInterval   time.Duration
	VulnCheckInterval time.Duration
	CISAKEVInterval   time.Duration
	EPSSInterval      time.Duration

	// API keys for feeds that require authentication.
	VulnCheckAPIKey string
	SocketAPIKey    string
}

// ServerConfig groups HTTP server settings.
type ServerConfig struct {
	Port            int
	Mode            ServerMode
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

// DBConfig groups PostgreSQL connection settings.
type DBConfig struct {
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	SSLMode  string
	MaxConns int32
	MinConns int32
}

// DSN returns a PostgreSQL connection string.
func (d DBConfig) DSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password, d.Host, d.Port, d.Name, d.SSLMode,
	)
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

// AdminConfig holds initial admin bootstrap values.
type AdminConfig struct {
	InitialPassword string
	SessionTimeout  time.Duration
	// EncryptionKey is used to encrypt sensitive fields (e.g. feed API
	// keys) at rest with AES-256-GCM. When empty, fields are stored in
	// plaintext and a startup warning is emitted.
	EncryptionKey string
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
		return nil, fmt.Errorf("config: invalid PACKMON_SERVER_MODE %q (want production or development)", mode)
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

	dbMaxConns, err := envIntOrDefault("PACKMON_DB_MAX_CONNS", 20)
	if err != nil {
		return nil, err
	}

	dbMinConns, err := envIntOrDefault("PACKMON_DB_MIN_CONNS", 2)
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

	sessionTimeout, err := envDurationOrDefault("PACKMON_ADMIN_SESSION_TIMEOUT", 8*time.Hour)
	if err != nil {
		return nil, err
	}

	// Default SSL mode depends on server mode.
	defaultSSL := "require"
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
			Port:            serverPort,
			Mode:            mode,
			ReadTimeout:     readTimeout,
			WriteTimeout:    writeTimeout,
			ShutdownTimeout: shutdownTimeout,
		},
		DB: DBConfig{
			Host:     envOrDefault("PACKMON_DB_HOST", "localhost"),
			Port:     dbPort,
			Name:     envOrDefault("PACKMON_DB_NAME", "packmon"),
			User:     envOrDefault("PACKMON_DB_USER", "packmon"),
			Password: os.Getenv("PACKMON_DB_PASSWORD"),
			SSLMode:  envOrDefault("PACKMON_DB_SSLMODE", defaultSSL),
			MaxConns: int32(dbMaxConns),
			MinConns: int32(dbMinConns),
		},
		Log: LogConfig{
			Level:  envOrDefault("PACKMON_LOG_LEVEL", defaultLogLevel),
			Format: envOrDefault("PACKMON_LOG_FORMAT", "json"),
		},
		Metrics: MetricsConfig{
			Host: envOrDefault("PACKMON_METRICS_HOST", "127.0.0.1"),
			Port: metricsPort,
		},
		Admin: AdminConfig{
			InitialPassword: os.Getenv("PACKMON_ADMIN_INITIAL_PASSWORD"),
			SessionTimeout:  sessionTimeout,
			EncryptionKey:   os.Getenv("PACKMON_ENCRYPTION_KEY"),
		},
		FeedSync: FeedSyncConfig{
			Interval:  syncInterval,
			OnStartup: envBoolOrDefault("PACKMON_FEED_SYNC_ON_STARTUP", true),
		},
		Feeds: FeedsConfig{
			DataDir: envOrDefault("PACKMON_FEED_DATA_DIR",
				filepath.Join(os.TempDir(), "packmon-feeds")),

			OSVEnabled:       envBoolOrDefault("PACKMON_FEED_OSV_ENABLED", true),
			GHSAEnabled:      envBoolOrDefault("PACKMON_FEED_GHSA_ENABLED", true),
			OpenSSFEnabled:   envBoolOrDefault("PACKMON_FEED_OPENSSF_ENABLED", true),
			VulnCheckEnabled: envBoolOrDefault("PACKMON_FEED_VULNCHECK_ENABLED", true),
			SocketEnabled:    envBoolOrDefault("PACKMON_FEED_SOCKET_ENABLED", false),
			CISAKEVEnabled:   envBoolOrDefault("PACKMON_FEED_CISAKEV_ENABLED", true),
			EPSSEnabled:      envBoolOrDefault("PACKMON_FEED_EPSS_ENABLED", true),

			OSVMode:       parseFeedMode("PACKMON_FEED_OSV_MODE"),
			GHSAMode:      parseFeedMode("PACKMON_FEED_GHSA_MODE"),
			OpenSSFMode:   parseFeedMode("PACKMON_FEED_OPENSSF_MODE"),
			VulnCheckMode: parseFeedMode("PACKMON_FEED_VULNCHECK_MODE"),
			CISAKEVMode:   parseFeedMode("PACKMON_FEED_CISAKEV_MODE"),
			EPSSMode:      parseFeedMode("PACKMON_FEED_EPSS_MODE"),
			SocketMode:    parseFeedMode("PACKMON_FEED_SOCKET_MODE"),

			VulnCheckAPIKey: os.Getenv("PACKMON_VULNCHECK_API_KEY"),
			SocketAPIKey:    os.Getenv("PACKMON_SOCKET_API_KEY"),
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
		return 0, fmt.Errorf("config: %s: %w", key, err)
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
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return d, nil
}

func envBoolOrDefault(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// parseFeedMode reads a feed mode from an environment variable.
// Valid values are "self" and "external". Default is "self".
func parseFeedMode(key string) FeedMode {
	v := strings.ToLower(os.Getenv(key))
	if v == "external" {
		return FeedModeExternal
	}
	return FeedModeSelf
}
