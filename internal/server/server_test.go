package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
)

func TestRateLimitConfigUsesServerSettings(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			RateLimitPerMinute: 120,
			RateLimitBurst:     25,
		},
	}

	got := rateLimitConfig(cfg)

	if got.Rate != 2 {
		t.Fatalf("Rate = %v, want 2", got.Rate)
	}
	if got.Burst != 25 {
		t.Fatalf("Burst = %d, want 25", got.Burst)
	}
}

func TestRateLimitConfigFallsBackToDefaults(t *testing.T) {
	got := rateLimitConfig(&config.Config{})

	if got.Rate != 1 {
		t.Fatalf("Rate = %v, want 1", got.Rate)
	}
	if got.Burst != 60 {
		t.Fatalf("Burst = %d, want 60", got.Burst)
	}
}

func TestNewWiresServersAndRoutes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "HIGH",
			RateLimitPerMinute: 120,
			RateLimitBurst:     10,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{Version: "v-new"}, nil, nil, nil)

	if srv.main == nil || srv.metrics == nil || srv.health == nil {
		t.Fatal("New did not initialize server components")
	}
	if srv.main.Addr != "127.0.0.1:0" {
		t.Fatalf("main addr = %q, want 127.0.0.1:0", srv.main.Addr)
	}
	if srv.metrics.Addr != "127.0.0.1:0" {
		t.Fatalf("metrics addr = %q, want 127.0.0.1:0", srv.metrics.Addr)
	}
	if srv.metrics.ReadTimeout != cfg.Server.ReadTimeout {
		t.Fatalf("metrics ReadTimeout = %s, want %s", srv.metrics.ReadTimeout, cfg.Server.ReadTimeout)
	}
	if srv.metrics.WriteTimeout != cfg.Server.WriteTimeout {
		t.Fatalf("metrics WriteTimeout = %s, want %s", srv.metrics.WriteTimeout, cfg.Server.WriteTimeout)
	}
	if srv.metrics.IdleTimeout != cfg.Server.ReadTimeout {
		t.Fatalf("metrics IdleTimeout = %s, want %s", srv.metrics.IdleTimeout, cfg.Server.ReadTimeout)
	}

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	req.Header.Set("User-Agent", "packmon-test")
	rec := httptest.NewRecorder()
	srv.main.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/version through New handler status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestNewWiresHTTPServerErrorLogsToConfiguredLogger(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:            0,
			Mode:            config.ModeDevelopment,
			ReadTimeout:     time.Second,
			WriteTimeout:    time.Second,
			ShutdownTimeout: time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	for name, httpServer := range map[string]*http.Server{
		"main":    srv.main,
		"metrics": srv.metrics,
	} {
		if httpServer.ErrorLog == nil {
			t.Fatalf("%s ErrorLog is nil", name)
		}
	}

	srv.main.ErrorLog.Print("main transport failure")
	srv.metrics.ErrorLog.Print("metrics transport failure")

	output := logs.String()
	for _, want := range []string{
		`"time":`,
		`"level":"ERROR"`,
		`"msg":"main transport failure"`,
		`"msg":"metrics transport failure"`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("configured logger output missing %s: %s", want, output)
		}
	}
}

func TestNewWiresMetricsSecurityHeaders(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:            0,
			Mode:            config.ModeDevelopment,
			ReadTimeout:     time.Second,
			WriteTimeout:    time.Second,
			ShutdownTimeout: time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ctx, cfg, metricsHeaderStore{}, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	rec := httptest.NewRecorder()
	srv.metrics.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	headers := rec.Result().Header
	for name, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
	} {
		if got := headers.Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if got := headers.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Fatalf("Content-Security-Policy = %q, want self baseline", got)
	}
}

func TestNewBindsLocalHTTPOverrideToLoopback(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:                   8080,
			Mode:                   config.ModeProduction,
			PublicHost:             "localhost:8080",
			AllowInsecureLocalHTTP: true,
			BlockThreshold:         "HIGH",
			RateLimitPerMinute:     120,
			RateLimitBurst:         10,
			ReadTimeout:            time.Second,
			WriteTimeout:           time.Second,
			ShutdownTimeout:        time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{Version: "v-new"}, nil, nil, nil)
	if srv.main.Addr != "127.0.0.1:8080" {
		t.Fatalf("main addr = %q, want loopback bind", srv.main.Addr)
	}
}

func TestSessionCookieSecureUsesActiveLocalHTTPOverride(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		cfg            *config.Config
		overrideActive bool
		wantSecure     bool
	}{
		{
			name: "production TLS with stale local flag keeps secure",
			cfg: &config.Config{
				Server: config.ServerConfig{
					Mode:                   config.ModeProduction,
					AllowInsecureLocalHTTP: true,
					TLS: config.TLSConfig{
						CertFile: "server.crt",
						KeyFile:  "server.key",
					},
				},
			},
			overrideActive: false,
			wantSecure:     true,
		},
		{
			name: "production trusted proxy with stale local flag keeps secure",
			cfg: &config.Config{
				Server: config.ServerConfig{
					Mode:                   config.ModeProduction,
					AllowInsecureLocalHTTP: true,
					TrustedProxies:         []string{"10.0.0.0/8"},
				},
			},
			overrideActive: false,
			wantSecure:     true,
		},
		{
			name: "production invalid proxy config does not activate local override",
			cfg: &config.Config{
				Server: config.ServerConfig{
					Mode:                   config.ModeProduction,
					AllowInsecureLocalHTTP: true,
					TrustedProxies:         []string{"not-a-proxy"},
				},
			},
			overrideActive: false,
			wantSecure:     true,
		},
		{
			name: "active loopback local HTTP override disables secure",
			cfg: &config.Config{
				Server: config.ServerConfig{
					Mode:                   config.ModeProduction,
					PublicHost:             "localhost:8080",
					AllowInsecureLocalHTTP: true,
				},
			},
			overrideActive: true,
			wantSecure:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.cfg.Server.InsecureLocalHTTPOverrideActive(); got != tc.overrideActive {
				t.Fatalf("InsecureLocalHTTPOverrideActive() = %t, want %t", got, tc.overrideActive)
			}
			if got := sessionCookieSecure(tc.cfg); got != tc.wantSecure {
				t.Fatalf("sessionCookieSecure() = %t, want %t", got, tc.wantSecure)
			}
		})
	}
}

func TestRateLimitRunsBeforeAuthForInvalidAPIKeys(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &rateLimitAuthStore{}
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeProduction,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 1,
			RateLimitBurst:     1,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ctx, cfg, store, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	req1.Header.Set("User-Agent", "packmon-cli/test")
	req1.Header.Set("Authorization", "Bearer invalid-one")
	req1.RemoteAddr = "203.0.113.10:12345"
	rec1 := httptest.NewRecorder()
	srv.main.Handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("first invalid-key request status = %d, want 401; body=%s", rec1.Code, rec1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	req2.Header.Set("User-Agent", "packmon-cli/test")
	req2.Header.Set("Authorization", "Bearer invalid-two")
	req2.RemoteAddr = "203.0.113.10:12345"
	rec2 := httptest.NewRecorder()
	srv.main.Handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second invalid-key request status = %d, want 429; body=%s", rec2.Code, rec2.Body.String())
	}
	if got := store.lookups.Load(); got != 1 {
		t.Fatalf("FindAPIKeyByHash calls = %d, want 1", got)
	}
}

func TestAuthenticatedRateLimitUsesAPIKeyAcrossClientIPs(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const apiKey = "valid-ci-key"
	store := &rateLimitAuthStore{
		validHash: hashTestAPIKey(apiKey),
		keyID:     42,
		keyName:   "ci-runner",
	}
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeProduction,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 1,
			RateLimitBurst:     1,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ctx, cfg, store, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	send := func(remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(`{"packages":[]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "packmon-cli/test")
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		srv.main.Handler.ServeHTTP(rec, req)
		return rec
	}

	rec1 := send("203.0.113.10:12345")
	if rec1.Code == http.StatusTooManyRequests {
		t.Fatalf("first authenticated request was rate limited; body=%s", rec1.Body.String())
	}

	rec2 := send("203.0.113.20:12345")
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second authenticated request with same API key and different IP status = %d, want 429; body=%s", rec2.Code, rec2.Body.String())
	}
}

func TestRunShutsDownOnContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    2 * time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	if err := srv.Run(ctx); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRunMetricsBindFailureKeepsMainServerAvailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	metricsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve metrics listener: %v", err)
	}
	defer metricsListener.Close()

	mainPort := reserveTCPPort(t)
	metricsPort := listenerPort(t, metricsListener)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               mainPort,
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    time.Second,
		},
		Metrics:  config.MetricsConfig{Host: "127.0.0.1", Port: metricsPort},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	runErr := make(chan error, 1)
	go func() {
		runErr <- srv.Run(ctx)
	}()

	readyURL := fmt.Sprintf("http://127.0.0.1:%d/readyz", mainPort)
	waitForHTTPStatus(t, readyURL, http.StatusOK, runErr, &logs)

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error after context cancel: %v\nlogs:\n%s", err, logs.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not return after context cancel\nlogs:\n%s", logs.String())
	}
}

func TestRunFatalServerErrorMarksShuttingDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{}, nil, nil, nil)
	srv.main.Addr = "127.0.0.1:bad-port"

	if err := srv.Run(ctx); err == nil {
		t.Fatal("Run returned nil, want fatal main server error")
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Header.Set("User-Agent", "packmon-test")
	rec := httptest.NewRecorder()
	srv.main.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz after fatal server error status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRunTLSFatalLogRedactsCertificatePaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tlsDir := filepath.Join(t.TempDir(), "private", "tls")
	certFile := filepath.Join(tlsDir, "server-cert.pem")
	keyFile := filepath.Join(tlsDir, "server-key.pem")
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeProduction,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    time.Second,
			TLS: config.TLSConfig{
				CertFile:   certFile,
				KeyFile:    keyFile,
				MinVersion: "1.2",
			},
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	err := srv.Run(ctx)
	if err == nil {
		t.Fatal("Run returned nil, want TLS startup error")
	}

	logText := logs.String()
	for _, leaked := range []string{certFile, keyFile, tlsDir, "server-cert.pem", "server-key.pem"} {
		if strings.Contains(logText, leaked) {
			t.Fatalf("TLS fatal log leaked path marker %q:\n%s", leaked, logText)
		}
	}
	if !strings.Contains(logText, "(redacted-path)") {
		t.Fatalf("TLS fatal log missing path redaction marker:\n%s", logText)
	}
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	port := listenerPort(t, listener)
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved tcp port listener: %v", err)
	}
	return port
}

func listenerPort(t *testing.T, listener net.Listener) int {
	t.Helper()

	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr %q: %v", listener.Addr().String(), err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatalf("parse listener port %q: %v", rawPort, err)
	}
	return port
}

func waitForHTTPStatus(t *testing.T, url string, want int, runErr <-chan error, logs *bytes.Buffer) {
	t.Helper()

	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case err := <-runErr:
			t.Fatalf("Run returned before %s reached status %d: %v\nlogs:\n%s", url, want, err, logs.String())
		case <-deadline:
			t.Fatalf("%s did not reach status %d\nlogs:\n%s", url, want, logs.String())
		case <-tick.C:
			resp, err := client.Get(url)
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == want {
				return
			}
		}
	}
}

func TestLogHTTPServerStoppedIncludesConcreteError(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	logHTTPServerStopped(logger, "main HTTP server", time.Now(), errors.New("context deadline exceeded"))

	output := logs.String()
	if !strings.Contains(output, `"error":"context deadline exceeded"`) {
		t.Fatalf("shutdown log missing concrete error: %s", output)
	}
	if strings.Contains(output, `"error":true`) {
		t.Fatalf("shutdown log still uses boolean-only error field: %s", output)
	}
}

type rateLimitAuthStore struct {
	metricsHeaderStore
	lookups   atomic.Int64
	validHash string
	keyID     int
	keyName   string
}

func (s *rateLimitAuthStore) FindAPIKeyByHash(_ context.Context, keyHash string) (*db.APIKey, error) {
	s.lookups.Add(1)
	if s.validHash != "" && keyHash == s.validHash {
		return &db.APIKey{ID: s.keyID, Name: s.keyName, KeyHash: keyHash}, nil
	}
	return nil, nil
}

func (s *rateLimitAuthStore) TouchAPIKeyLastUsed(context.Context, int) error {
	return nil
}

func hashTestAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

type metricsHeaderStore struct {
	db.Store
}

func (metricsHeaderStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	return nil, nil
}

func (metricsHeaderStore) ListQueueJobs(context.Context, string, int) ([]db.RefreshJob, error) {
	return nil, nil
}

func (metricsHeaderStore) QueueStats(context.Context) (*db.QueueStatsResult, error) {
	return nil, nil
}

func (metricsHeaderStore) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
	return nil, nil
}

func (metricsHeaderStore) ScanTotals(context.Context) (*db.ScanTotals, error) {
	return nil, nil
}

func (metricsHeaderStore) DBPoolStats() db.DBPoolStats {
	return db.DBPoolStats{}
}

func TestSetShuttingDownMakesReadyEndpointUnavailable(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	srv.SetShuttingDown()

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Header.Set("User-Agent", "packmon-test")
	rec := httptest.NewRecorder()
	srv.main.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}
