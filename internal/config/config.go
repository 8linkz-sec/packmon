// Package config loads server configuration from environment variables
// with sensible defaults. No Viper dependency -- just os.Getenv with
// fallback values, following 12-factor principles.
package config

import (
	"fmt"
	"os"
	"strconv"
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
	Port int
}

// AdminConfig holds initial admin bootstrap values.
type AdminConfig struct {
	InitialPassword string
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

	readTimeout, err := envDurationOrDefault("PACKMON_SERVER_READ_TIMEOUT", 30*time.Second)
	if err != nil {
		return nil, err
	}

	writeTimeout, err := envDurationOrDefault("PACKMON_SERVER_WRITE_TIMEOUT", 30*time.Second)
	if err != nil {
		return nil, err
	}

	shutdownTimeout, err := envDurationOrDefault("PACKMON_SERVER_SHUTDOWN_TIMEOUT", 15*time.Second)
	if err != nil {
		return nil, err
	}

	syncInterval, err := envDurationOrDefault("PACKMON_FEED_SYNC_INTERVAL", 6*time.Hour)
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
		},
		Log: LogConfig{
			Level:  envOrDefault("PACKMON_LOG_LEVEL", defaultLogLevel),
			Format: envOrDefault("PACKMON_LOG_FORMAT", "json"),
		},
		Metrics: MetricsConfig{
			Port: metricsPort,
		},
		Admin: AdminConfig{
			InitialPassword: os.Getenv("PACKMON_ADMIN_INITIAL_PASSWORD"),
		},
		FeedSync: FeedSyncConfig{
			Interval:  syncInterval,
			OnStartup: envBoolOrDefault("PACKMON_FEED_SYNC_ON_STARTUP", true),
		},
	}

	return cfg, nil
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
