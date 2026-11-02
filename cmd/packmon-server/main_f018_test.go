package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	migrations "github.com/8linkz-sec/packmon/internal/db/postgres/migrations"
)

const f018ValidSecret = "0123456789abcdef0123456789abcdef"

func TestF018MainDispatchesSuccessfulSubcommands(t *testing.T) {
	originalArgs := os.Args
	originalRunMigrations := runDatabaseMigrationsContext
	originalVersion := readDatabaseMigrationVersionContext
	originalSignalContext := serverSignalContext
	originalPrivacyOutput := privacyExportOutput
	originalPrivacyOpen := openPrivacyExportStore
	t.Cleanup(func() {
		os.Args = originalArgs
		runDatabaseMigrationsContext = originalRunMigrations
		readDatabaseMigrationVersionContext = originalVersion
		serverSignalContext = originalSignalContext
		privacyExportOutput = originalPrivacyOutput
		openPrivacyExportStore = originalPrivacyOpen
		db.ClearAdminAuditDigestHMACKey()
	})

	f018SetDatabaseEnvironment(t, f018ClosedLoopbackPort(t), 50*time.Millisecond)
	t.Setenv("PACKMON_ADMIN_AUDIT_HMAC_KEY", f018EncodedSecret())

	t.Run("migrate", func(t *testing.T) {
		var migrationCalls, versionCalls int
		runDatabaseMigrationsContext = func(context.Context, string, migrations.RunOptions) error {
			migrationCalls++
			return nil
		}
		readDatabaseMigrationVersionContext = func(context.Context, string) (uint, bool, error) {
			versionCalls++
			return uint(migrations.ExpectedVersion), false, nil
		}
		serverSignalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
			return context.WithCancel(parent)
		}
		os.Args = []string{"packmon-server", "migrate"}
		_ = captureServerStdout(t, main)
		if migrationCalls != 1 || versionCalls != 1 {
			t.Fatalf("migrate dispatch calls = migrations:%d version:%d, want 1 each", migrationCalls, versionCalls)
		}
	})

	t.Run("init-secrets", func(t *testing.T) {
		target := t.TempDir() + string(os.PathSeparator) + "generated.env"
		example := t.TempDir() + string(os.PathSeparator) + "missing-example.env"
		os.Args = []string{"packmon-server", "init-secrets", "--env", target, "--example", example}
		out := captureServerStdout(t, main)
		if !strings.Contains(out, "init-secrets:") || !strings.Contains(out, target) {
			t.Fatalf("init-secrets output = %q, want successful target report", out)
		}
		contents, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read generated env: %v", err)
		}
		for _, spec := range config.RequiredSecrets() {
			if !bytes.Contains(contents, []byte(spec.Key+"=")) {
				t.Fatalf("generated env missing %s: %s", spec.Key, contents)
			}
		}
	})

	t.Run("privacy", func(t *testing.T) {
		store := &privacyExportStoreStub{export: &db.PrivacyExport{
			Selector: db.PrivacyExportSelector{Type: db.PrivacySelectorRepoName, Value: "org/repo"},
		}}
		var output bytes.Buffer
		privacyExportOutput = &output
		readDatabaseMigrationVersionContext = func(context.Context, string) (uint, bool, error) {
			return uint(migrations.ExpectedVersion), false, nil
		}
		openPrivacyExportStore = func(context.Context, string, time.Duration) (privacyExportStore, error) {
			return store, nil
		}
		os.Args = []string{"packmon-server", "privacy", "export", "--selector", "repo-name=org/repo", "--format", "json"}
		main()
		if store.selector != (db.PrivacyExportSelector{Type: db.PrivacySelectorRepoName, Value: "org/repo"}) {
			t.Fatalf("privacy dispatch selector = %+v, want exact forwarded selector", store.selector)
		}
		if !store.closed || output.Len() == 0 {
			t.Fatalf("privacy dispatch closed=%v output=%q, want closed store and JSON", store.closed, output.String())
		}
	})
}

func TestF018MainSubcommandsUsePreconfigurationStderrFallback(t *testing.T) {
	marker := "must-not-leak-f018"
	tests := []struct {
		name       string
		helper     string
		wantPrefix string
	}{
		{name: "init-secrets invalid flag", helper: "init-invalid", wantPrefix: "packmon-server init-secrets:"},
		{name: "privacy missing command", helper: "privacy-missing", wantPrefix: "packmon-server privacy:"},
		{name: "privacy unknown command", helper: "privacy-unknown", wantPrefix: "packmon-server privacy:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestF018MainHelperProcess$") //nolint:gosec // test re-executes its own binary
			cmd.Env = append(f018EnvironmentWithoutPackmon(), "PACKMON_TEST_F018_HELPER="+tt.helper, "PACKMON_TEST_SECRET_MARKER="+marker)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("helper error = %v, stdout=%q stderr=%q; want exit 1", err, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantPrefix) {
				t.Fatalf("stderr = %q, want prefix %q", stderr.String(), tt.wantPrefix)
			}
			if strings.Contains(stdout.String(), marker) || strings.Contains(stderr.String(), marker) {
				t.Fatalf("helper output leaked marker: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestF018MainHelperProcess(t *testing.T) {
	switch os.Getenv("PACKMON_TEST_F018_HELPER") {
	case "init-invalid":
		os.Args = []string{"packmon-server", "init-secrets", "--not-a-real-flag"}
		main()
	case "privacy-missing":
		os.Args = []string{"packmon-server", "privacy"}
		main()
	case "privacy-unknown":
		os.Args = []string{"packmon-server", "privacy", "erase"}
		main()
	}
}

func TestF018BootstrapRuntimeDatabaseFailureOrderAndCleanup(t *testing.T) {
	verifyErr := errors.New("schema unavailable")
	openErr := errors.New("store unavailable")
	applyErr := errors.New("state unavailable")
	tests := []struct {
		name      string
		verifyErr error
		openErr   error
		applyErr  error
		wantOrder []string
		wantErr   error
		wantClose int32
	}{
		{name: "schema failure", verifyErr: verifyErr, wantOrder: []string{"verify"}, wantErr: verifyErr},
		{name: "open failure", openErr: openErr, wantOrder: []string{"verify", "open"}, wantErr: openErr},
		{name: "apply failure", applyErr: applyErr, wantOrder: []string{"verify", "open", "apply"}, wantErr: applyErr, wantClose: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &f018CloseStore{noopStore: newNoopStore()}
			runtime := &runtimeConfig{cfg: &config.Config{}, logger: slog.New(slog.DiscardHandler)}
			var order []string
			hooks := runtimeDatabaseBootstrapHooks{
				verifySchema: func(context.Context, *config.Config, *slog.Logger) (uint, error) {
					order = append(order, "verify")
					return 23, tt.verifyErr
				},
				openStore: func(context.Context, *config.Config, *slog.Logger) (*runtimeStore, error) {
					order = append(order, "open")
					if tt.openErr != nil {
						return nil, tt.openErr
					}
					return &runtimeStore{store: store, pinger: &noopPinger{}}, nil
				},
				applyState: func(context.Context, *config.Config, db.Store, *slog.Logger) (config.FeedsConfig, error) {
					order = append(order, "apply")
					return config.FeedsConfig{}, tt.applyErr
				},
			}
			opened, _, err := bootstrapRuntimeDatabase(context.Background(), runtime, hooks)
			if opened != nil || !errors.Is(err, tt.wantErr) {
				t.Fatalf("bootstrapRuntimeDatabase() = %#v, %v; want nil, %v", opened, err, tt.wantErr)
			}
			if strings.Join(order, ",") != strings.Join(tt.wantOrder, ",") {
				t.Fatalf("call order = %v, want %v", order, tt.wantOrder)
			}
			wantVersion := uint(0)
			if tt.verifyErr == nil {
				wantVersion = 23
			}
			if runtime.schemaVersion != wantVersion {
				t.Fatalf("schema version = %d, want %d", runtime.schemaVersion, wantVersion)
			}
			if got := store.closes.Load(); got != tt.wantClose {
				t.Fatalf("store closes = %d, want %d", got, tt.wantClose)
			}
		})
	}
}

func TestF018RunRejectsProductionSecretsBeforeDatabaseAccess(t *testing.T) {
	originalDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(originalDefault) })
	f018SetProductionEnvironment(t, f018ClosedLoopbackPort(t), 25*time.Millisecond)
	t.Setenv("PACKMON_ENCRYPTION_KEY", "")
	t.Setenv("PACKMON_ADMIN_AUDIT_HMAC_KEY", "")
	originalVersion := readDatabaseMigrationVersionContext
	t.Cleanup(func() { readDatabaseMigrationVersionContext = originalVersion })
	called := false
	readDatabaseMigrationVersionContext = func(context.Context, string) (uint, bool, error) {
		called = true
		return uint(migrations.ExpectedVersion), false, nil
	}
	err := run()
	if err == nil || !strings.Contains(err.Error(), "secret(s) missing or invalid") {
		t.Fatalf("run() error = %v, want production-secret rejection", err)
	}
	if called {
		t.Fatal("schema hook called after production-secret rejection")
	}
}

func TestF018RunPropagatesProductionStoreOpenFailureBeforeServing(t *testing.T) {
	originalDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(originalDefault) })
	port := f018ClosedLoopbackPort(t)
	f018SetProductionEnvironment(t, port, 25*time.Millisecond)
	originalVersion := readDatabaseMigrationVersionContext
	originalSignalContext := serverSignalContext
	t.Cleanup(func() {
		readDatabaseMigrationVersionContext = originalVersion
		serverSignalContext = originalSignalContext
		db.ClearAdminAuditDigestHMACKey()
	})
	readDatabaseMigrationVersionContext = func(context.Context, string) (uint, bool, error) {
		return uint(migrations.ExpectedVersion), false, nil
	}
	var signalCalls atomic.Int32
	serverSignalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
		signalCalls.Add(1)
		return context.WithCancel(parent)
	}
	err := run()
	if err == nil || !strings.Contains(err.Error(), "open postgres store") {
		t.Fatalf("run() error = %v, want store-open failure", err)
	}
	if signalCalls.Load() != 0 {
		t.Fatalf("serverSignalContext calls = %d, want zero before server construction", signalCalls.Load())
	}
}

func TestF018OpenRuntimeStoreProductionFailureBranches(t *testing.T) {
	valid := f018EncodedSecret()
	logger := slog.New(slog.DiscardHandler)
	t.Cleanup(db.ClearAdminAuditDigestHMACKey)

	t.Run("inactive encryption", func(t *testing.T) {
		db.ClearAdminAuditDigestHMACKey()
		cfg := &config.Config{Server: config.ServerConfig{Mode: config.ModeProduction}}
		if _, err := openRuntimeStore(context.Background(), cfg, logger); err == nil || !strings.Contains(err.Error(), "PACKMON_ENCRYPTION_KEY") {
			t.Fatalf("openRuntimeStore() error = %v, want encryption requirement", err)
		}
	})

	t.Run("invalid audit HMAC", func(t *testing.T) {
		db.ClearAdminAuditDigestHMACKey()
		cfg := &config.Config{
			Server: config.ServerConfig{Mode: config.ModeProduction},
			Admin:  config.AdminConfig{EncryptionKey: valid, AdminAuditHMACKey: "%%%"},
		}
		if _, err := openRuntimeStore(context.Background(), cfg, logger); err == nil || !strings.Contains(err.Error(), "configure admin audit HMAC key") {
			t.Fatalf("openRuntimeStore() error = %v, want audit-HMAC decode failure", err)
		}
	})

	t.Run("postgres connection", func(t *testing.T) {
		db.ClearAdminAuditDigestHMACKey()
		cfg := &config.Config{
			Server: config.ServerConfig{Mode: config.ModeProduction},
			Admin:  config.AdminConfig{EncryptionKey: valid, AdminAuditHMACKey: valid},
			DB: config.DBConfig{
				Host: "127.0.0.1", Port: f018ClosedLoopbackPort(t), User: "packmon", Password: "packmon", Name: "packmon", SSLMode: "disable", ConnectTimeout: 25 * time.Millisecond,
			},
		}
		if _, err := openRuntimeStore(context.Background(), cfg, logger); err == nil || !strings.Contains(err.Error(), "open postgres store") {
			t.Fatalf("openRuntimeStore() error = %v, want connection failure", err)
		}
	})
}

func TestF018RunPreservesListenerFailureThroughShutdown(t *testing.T) {
	originalDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(originalDefault) })
	mainListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve main listener: %v", err)
	}
	defer mainListener.Close()
	metricsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve metrics listener: %v", err)
	}
	defer metricsListener.Close()

	t.Setenv("PACKMON_SERVER_MODE", "development")
	t.Setenv("PACKMON_SERVER_PORT", strconv.Itoa(mainListener.Addr().(*net.TCPAddr).Port))
	t.Setenv("PACKMON_METRICS_HOST", "127.0.0.1")
	t.Setenv("PACKMON_METRICS_PORT", strconv.Itoa(metricsListener.Addr().(*net.TCPAddr).Port))
	t.Setenv("PACKMON_SERVER_SHUTDOWN_TIMEOUT", "25ms")
	t.Setenv("PACKMON_LOG_LEVEL", "error")
	t.Setenv("PACKMON_LOG_FORMAT", "json")

	originalSignalContext := serverSignalContext
	originalHardExit := hardExit
	originalDelay := hardExitDelay
	hardExitCalled := make(chan int, 1)
	serverSignalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
		return context.WithCancel(parent)
	}
	hardExit = func(code int) { hardExitCalled <- code }
	hardExitDelay = time.Millisecond
	t.Cleanup(func() {
		serverSignalContext = originalSignalContext
		hardExit = originalHardExit
		hardExitDelay = originalDelay
	})

	runErr := run()
	if runErr == nil || !strings.Contains(runErr.Error(), "main server listen") {
		t.Fatalf("run() error = %v, want occupied-listener failure", runErr)
	}
	select {
	case code := <-hardExitCalled:
		if code != 1 {
			t.Fatalf("hard exit code = %d, want 1", code)
		}
	case <-time.After(time.Second):
		t.Fatal("hard-exit hook was not called after listener failure shutdown")
	}
}

func TestF018ShutdownRuntimeAbandonmentCancelsClosesAndPreservesRunError(t *testing.T) {
	var logs f018LockedBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	rootCtx, cancel := context.WithCancel(context.Background())
	managerDone := make(chan struct{})
	store := &f018CloseStore{noopStore: newNoopStore()}
	background := &backgroundServices{
		logger:           logger,
		rootCtx:          rootCtx,
		shutdownWait:     10 * time.Millisecond,
		managerStartDone: managerDone,
	}
	runtime := &runtimeServer{
		rootCtx: rootCtx, stop: cancel, logger: logger, store: store, background: background,
	}
	runErr := errors.New("listener failed")
	got := shutdownRuntime(runtime, runErr)
	if !errors.Is(got, runErr) {
		t.Fatalf("shutdownRuntime() error = %v, want original run error", got)
	}
	if rootCtx.Err() != context.Canceled {
		t.Fatalf("root context error = %v, want canceled", rootCtx.Err())
	}
	if store.closes.Load() != 1 {
		t.Fatalf("store closes = %d, want 1", store.closes.Load())
	}
	if !strings.Contains(logs.String(), "shutdown: background services abandoned") {
		t.Fatalf("shutdown logs = %s, want abandonment warning", logs.String())
	}

	close(managerDone)
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(logs.String(), "shutdown: background startup tasks stopped") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(logs.String(), "shutdown: background startup tasks stopped") {
		t.Fatalf("abandoned Wait goroutine did not finish after release: %s", logs.String())
	}
}

func TestF018RuntimeConfigWarningsMatchModeAndTransport(t *testing.T) {
	tests := []struct {
		name     string
		runtime  *runtimeConfig
		messages []string
	}{
		{
			name:     "development",
			runtime:  &runtimeConfig{cfg: &config.Config{}, devMode: true},
			messages: []string{"running in DEVELOPMENT mode"},
		},
		{
			name:     "relaxed local production",
			runtime:  &runtimeConfig{cfg: &config.Config{Server: config.ServerConfig{AllowInsecureLocalHTTP: true}}},
			messages: []string{"production transport security relaxed", "PACKMON_SERVER_PUBLIC_HOST is not set"},
		},
		{
			name:    "secure production",
			runtime: &runtimeConfig{cfg: &config.Config{Server: config.ServerConfig{PublicHost: "packmon.internal"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			tt.runtime.logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
			logRuntimeConfigWarnings(tt.runtime)
			if got := strings.Count(logs.String(), `"level":"WARN"`); got != len(tt.messages) {
				t.Fatalf("warning count = %d, want %d; logs=%s", got, len(tt.messages), logs.String())
			}
			for _, message := range tt.messages {
				if !strings.Contains(logs.String(), message) {
					t.Fatalf("logs = %s, want %q", logs.String(), message)
				}
			}
		})
	}
}

func TestF018ConfigureAdminAuditDigestHMACKeyRejectsMalformedKeysWithoutInstallingThem(t *testing.T) {
	t.Cleanup(db.ClearAdminAuditDigestHMACKey)
	entry := db.AdminAuditLogEntry{ID: 1, Action: "test", CreatedAt: time.Unix(1, 0).UTC()}
	for _, raw := range []string{"%%%", base64.StdEncoding.EncodeToString([]byte("short"))} {
		db.ClearAdminAuditDigestHMACKey()
		cfg := &config.Config{Admin: config.AdminConfig{AdminAuditHMACKey: raw}}
		if err := configureAdminAuditDigestHMACKey(cfg); err == nil {
			t.Fatalf("configureAdminAuditDigestHMACKey(%q) error = nil", raw)
		}
		if digest := db.ComputeAdminAuditDigest(entry); !strings.HasPrefix(digest, "sha256:") {
			t.Fatalf("digest after invalid key = %q, want legacy sha256", digest)
		}
	}

	valid := f018EncodedSecret()
	if err := configureAdminAuditDigestHMACKey(&config.Config{Admin: config.AdminConfig{AdminAuditHMACKey: valid}}); err != nil {
		t.Fatalf("configure valid HMAC key: %v", err)
	}
	if digest := db.ComputeAdminAuditDigest(entry); !strings.HasPrefix(digest, "hmac-sha256:") {
		t.Fatalf("digest with valid key = %q, want HMAC", digest)
	}
	if err := configureAdminAuditDigestHMACKey(&config.Config{}); err != nil {
		t.Fatalf("clear HMAC key: %v", err)
	}
	if digest := db.ComputeAdminAuditDigest(entry); !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("digest after empty key = %q, want legacy sha256", digest)
	}
}

func TestF018RequiredSecretSpecFallsBackForUnknownKey(t *testing.T) {
	spec := requiredSecretSpec("PACKMON_UNKNOWN_SECRET")
	if spec.Key != "PACKMON_UNKNOWN_SECRET" || spec.Kind != config.SecretBase64Bytes || spec.Bytes != 32 {
		t.Fatalf("fallback spec = %+v, want exact key/base64/32 bytes", spec)
	}
}

func TestF018DatabaseStartupContextNormalizesNilInputs(t *testing.T) {
	ctx, cancel := databaseStartupContext(nil, nil)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("databaseStartupContext(nil, nil) has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > defaultDatabaseStartupTimeout {
		t.Fatalf("deadline remaining = %s, want within %s", remaining, defaultDatabaseStartupTimeout)
	}
}

func TestF018DSNWithConnectTimeoutBranchMatrix(t *testing.T) {
	base := "postgres://packmon:secret@127.0.0.1:5432/packmon?sslmode=disable"
	for _, timeout := range []time.Duration{0, -time.Second} {
		got, err := dsnWithConnectTimeout(base, timeout)
		if err != nil || got != base {
			t.Fatalf("dsnWithConnectTimeout(%s) = %q, %v; want unchanged", timeout, got, err)
		}
	}
	if _, err := dsnWithConnectTimeout("postgres://%zz", time.Second); err == nil {
		t.Fatal("dsnWithConnectTimeout(invalid URL) error = nil")
	}
	existing := base + "&connect_timeout=9"
	if got, err := dsnWithConnectTimeout(existing, time.Second); err != nil || got != existing {
		t.Fatalf("existing connect_timeout = %q, %v; want byte-identical %q", got, err, existing)
	}
	for _, tt := range []struct {
		timeout time.Duration
		want    string
	}{{time.Nanosecond, "1"}, {time.Second, "1"}, {time.Second + time.Nanosecond, "2"}} {
		got, err := dsnWithConnectTimeout(base, tt.timeout)
		if err != nil {
			t.Fatalf("dsnWithConnectTimeout(%s): %v", tt.timeout, err)
		}
		parsed, err := url.Parse(got)
		if err != nil || parsed.Query().Get("connect_timeout") != tt.want {
			t.Fatalf("dsnWithConnectTimeout(%s) = %q, want connect_timeout=%s", tt.timeout, got, tt.want)
		}
	}
}

func TestF018EffectiveHardExitDelayBranchMatrix(t *testing.T) {
	original := hardExitDelay
	t.Cleanup(func() { hardExitDelay = original })
	hardExitDelay = defaultHardExitDelay
	for name, cfg := range map[string]*config.Config{
		"nil":   nil,
		"zero":  {Server: config.ServerConfig{}},
		"short": {Server: config.ServerConfig{ShutdownTimeout: time.Second}},
	} {
		if got := effectiveHardExitDelay(cfg); got != defaultHardExitDelay {
			t.Errorf("%s delay = %s, want %s", name, got, defaultHardExitDelay)
		}
	}
	long := &config.Config{Server: config.ServerConfig{ShutdownTimeout: 10 * time.Second}}
	if got := effectiveHardExitDelay(long); got != 15*time.Second {
		t.Fatalf("long shutdown delay = %s, want 15s", got)
	}
	hardExitDelay = 17 * time.Millisecond
	if got := effectiveHardExitDelay(long); got != 17*time.Millisecond {
		t.Fatalf("test override delay = %s, want 17ms", got)
	}
}

func TestF018BoundedErrorLogValueHandlesNil(t *testing.T) {
	if got := boundedErrorLogValue(nil); got != "" {
		t.Fatalf("boundedErrorLogValue(nil) = %q, want empty", got)
	}
}

type f018CloseStore struct {
	*noopStore
	closes atomic.Int32
}

func (s *f018CloseStore) Close() error {
	s.closes.Add(1)
	return nil
}

var _ db.Store = (*f018CloseStore)(nil)

type f018LockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *f018LockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *f018LockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func f018EncodedSecret() string {
	return base64.StdEncoding.EncodeToString([]byte(f018ValidSecret))
}

func f018SetProductionEnvironment(t *testing.T, databasePort int, timeout time.Duration) {
	t.Helper()
	t.Setenv("PACKMON_SERVER_MODE", "production")
	t.Setenv("PACKMON_SERVER_PORT", "0")
	t.Setenv("PACKMON_TRUSTED_PROXIES", "")
	t.Setenv("PACKMON_TLS_CERT_FILE", "")
	t.Setenv("PACKMON_TLS_KEY_FILE", "")
	t.Setenv("PACKMON_ALLOW_INSECURE_LOCAL_HTTP", "true")
	t.Setenv("PACKMON_SERVER_PUBLIC_HOST", "localhost")
	t.Setenv("PACKMON_METRICS_HOST", "127.0.0.1")
	t.Setenv("PACKMON_METRICS_PORT", "0")
	t.Setenv("PACKMON_LOG_LEVEL", "error")
	t.Setenv("PACKMON_LOG_FORMAT", "json")
	t.Setenv("PACKMON_ENCRYPTION_KEY", f018EncodedSecret())
	t.Setenv("PACKMON_ADMIN_AUDIT_HMAC_KEY", f018EncodedSecret())
	f018SetDatabaseEnvironment(t, databasePort, timeout)
}

func f018SetDatabaseEnvironment(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	t.Setenv("PACKMON_DB_HOST", "127.0.0.1")
	t.Setenv("PACKMON_DB_PORT", strconv.Itoa(port))
	t.Setenv("PACKMON_DB_USER", "packmon")
	t.Setenv("PACKMON_DB_PASSWORD", "packmon")
	t.Setenv("PACKMON_DB_NAME", "packmon")
	t.Setenv("PACKMON_DB_SSLMODE", "disable")
	t.Setenv("PACKMON_DB_CONNECT_TIMEOUT", timeout.String())
}

func f018ClosedLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve closed loopback port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved loopback port: %v", err)
	}
	return port
}

func f018EnvironmentWithoutPackmon() []string {
	env := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "PACKMON_") {
			continue
		}
		env = append(env, entry)
	}
	return env
}
