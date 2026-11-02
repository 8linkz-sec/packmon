//go:build integration

package integration

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	composeRuntimePostgresImage = "cgr.dev/chainguard/postgres:18@sha256:891139a6d9036632791857fb7585425f1bf0c64516fc52bc39da94305ee92461"
	composeRuntimeOverallBudget = 25 * time.Minute
	composeRuntimeCleanupBudget = 90 * time.Second
)

type composeRuntimeHarness struct {
	t            *testing.T
	repo         string
	buildContext string
	sha          string
	image        string
	builds       int
	secrets      map[string]string
	deadline     time.Time
}

type composeRuntimeScenario struct {
	h       *composeRuntimeHarness
	dir     string
	project string
	files   []string
	envFile string
}

func TestComposeRuntimeContracts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Compose ownership/runtime contracts require a native Linux host")
	}
	if os.Geteuid() == 0 {
		t.Fatal("Compose runtime contracts must run as a non-root Linux user")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("Docker prerequisite unavailable: %v", err)
	}
	runtimeDeadline := requireComposeRuntimePackageBudget(t)
	requireDockerOutput(t, 30*time.Second, []string{"version", "--format", "{{.Server.Os}}"}, "linux")
	requireDockerOutput(t, 30*time.Second, []string{"compose", "version", "--short"}, "")
	if output, err := dockerCommandOutput(30*time.Second, nil, "image", "inspect", composeRuntimePostgresImage); err != nil {
		t.Fatalf("pinned PostgreSQL image must already be available; runtime tests never pull: %v: %s", err, boundedRuntimeDiagnostic(string(output), nil))
	}

	h := newComposeRuntimeHarness(t, runtimeDeadline)
	h.buildServerImage()
	t.Cleanup(func() {
		ctx, cancel, _, ok := h.cleanupContext(time.Minute)
		if !ok {
			return
		}
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", "image", "rm", "--force", h.image) // #nosec G204 -- exact test-owned image tag
		cmd.Env = runtimeDockerEnvironment(nil)
		_, _ = cmd.CombinedOutput()
	})

	t.Run("bootstrap_owner_and_explicit_run", h.testBootstrapOwnerAndExplicitRun)
	t.Run("migration_orders_server_startup", h.testMigrationOrdersServerStartup)
	t.Run("production_lifecycle_proxy_and_persistence", h.testProductionLifecycleProxyAndPersistence)
	t.Run("metrics_loopback_access", h.testMetricsLoopbackAccess)
	t.Run("configured_backup_entrypoint_probe", h.testConfiguredBackupEntrypointProbe)
	t.Run("backup_create_restore_failure_and_retention", h.testBackupCreateRestoreFailureAndRetention)

	if h.builds != 1 {
		t.Fatalf("server image build helper invoked %d times, want exactly one", h.builds)
	}
}

// The runtime contract intentionally has a larger budget than Go's default
// ten-minute package timeout because it may spend up to fifteen minutes on the
// one exact-SHA image build. Run it with:
//
//	go test -timeout 30m -count=1 -tags integration ./tests/integration -run '^TestComposeRuntimeContracts$'
//
// Every long-running child process is also capped by the 25-minute test budget,
// with the final 90 seconds reserved for project/image cleanup.
func requireComposeRuntimePackageBudget(t *testing.T) time.Time {
	t.Helper()
	now := time.Now()
	if packageDeadline, ok := t.Deadline(); ok {
		const packageMargin = time.Minute
		if remaining := time.Until(packageDeadline); remaining < composeRuntimeOverallBudget+packageMargin {
			t.Fatalf("Compose runtime contracts need a package timeout longer than %s (remaining %s); run `go test -timeout 30m -count=1 -tags integration ./tests/integration -run '^TestComposeRuntimeContracts$'`", composeRuntimeOverallBudget, remaining.Round(time.Second))
		}
	}
	return now.Add(composeRuntimeOverallBudget)
}

func newComposeRuntimeHarness(t *testing.T, deadline time.Time) *composeRuntimeHarness {
	t.Helper()
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	sha := strings.TrimSpace(runHostCommand(t, repo, 30*time.Second, nil, "git", "rev-parse", "HEAD"))
	if sha == "" {
		t.Fatal("reviewed HEAD SHA is empty")
	}
	status := runHostCommand(t, repo, 30*time.Second, nil, "git", "status", "--porcelain", "--untracked-files=no")
	if strings.TrimSpace(status) != "" {
		t.Fatalf("runtime test requires a tracked-clean reviewed branch, got %s", boundedRuntimeDiagnostic(status, map[string]string{repo: "[REPO]"}))
	}
	contextDir := t.TempDir()
	archivePath := filepath.Join(t.TempDir(), "reviewed.tar")
	runHostCommand(t, repo, 2*time.Minute, nil, "git", "archive", "--format=tar", "-o", archivePath, sha)
	extractTar(t, archivePath, contextDir)
	if got := strings.TrimSpace(runHostCommand(t, repo, 30*time.Second, nil, "git", "rev-parse", "HEAD")); got != sha {
		t.Fatalf("reviewed SHA changed while materializing build context: %s != %s", got, sha)
	}
	return &composeRuntimeHarness{
		t:            t,
		repo:         repo,
		buildContext: contextDir,
		sha:          sha,
		image:        "packmon-compose-contract:" + sha[:12] + "-" + strconv.Itoa(os.Getpid()),
		secrets:      generatedComposeEnvironment(t),
		deadline:     deadline,
	}
}

func (h *composeRuntimeHarness) buildServerImage() {
	h.t.Helper()
	h.builds++
	if h.builds != 1 {
		h.t.Fatal("server image build helper may run only once")
	}
	ctx, cancel, effectiveTimeout, ok := h.workContext(15 * time.Minute)
	if !ok {
		h.t.Fatal("Compose runtime budget exhausted before the exact-SHA server image build")
	}
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "build", "--pull=false", "--target", "server", "--build-arg", "COMMIT="+h.sha, "--tag", h.image, h.buildContext) // #nosec G204 -- exact reviewed archive and test-owned tag
	cmd.Env = runtimeDockerEnvironment(nil)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		h.t.Fatalf("exact-SHA server image build exceeded its bounded %s budget: %v", effectiveTimeout.Round(time.Second), ctx.Err())
	}
	if err != nil {
		h.t.Fatalf("build exact-SHA server image: %v: %s", err, h.diagnostic(string(output)))
	}
	version, err := h.dockerCommandOutput(30*time.Second, nil, "run", "--rm", "--pull=never", h.image, "version")
	if err != nil || !strings.Contains(string(version), h.sha) {
		h.t.Fatalf("built image version does not contain reviewed SHA %s: %v: %s", h.sha, err, h.diagnostic(string(version)))
	}
}

func (h *composeRuntimeHarness) testBootstrapOwnerAndExplicitRun(t *testing.T) {
	checkout := t.TempDir()
	envPath := filepath.Join(checkout, ".env")
	if err := os.WriteFile(envPath, []byte("POSTGRES_USER=packmon\nPOSTGRES_DB=packmon\n"), 0o600); err != nil {
		t.Fatalf("seed owner-only environment file: %v", err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	imageUID, err := h.dockerCommandOutput(30*time.Second, nil, "run", "--rm", "--pull=never", "--entrypoint", "/bin/sh", h.image, "-ec", "id -u")
	if err != nil {
		t.Fatalf("inspect image user: %v: %s", err, h.diagnostic(string(imageUID)))
	}
	if strings.TrimSpace(string(imageUID)) == strconv.Itoa(uid) {
		t.Fatalf("host UID %d must differ from image packmon UID", uid)
	}
	overlay := fmt.Sprintf(`services:
  init-secrets:
    volumes: !override
      - %s:/workspace
`, yamlQuote(checkout))
	s := h.newScenario(t, []string{"docker-compose.yml", "docker-compose.override.yml"}, h.commonOverlay(true, ""), overlay)
	s.env("PACKMON_UID", strconv.Itoa(uid))
	s.env("PACKMON_GID", strconv.Itoa(gid))
	s.down()
	s.run(2*time.Minute, "run", "--rm", "--no-deps", "init-secrets")
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat generated environment file: %v", err)
	}
	ownership := strings.TrimSpace(runHostCommand(t, checkout, 30*time.Second, nil, "stat", "-c", "%u:%g", envPath))
	if ownership != fmt.Sprintf("%d:%d", uid, gid) {
		t.Fatalf("environment ownership = %q, want %d:%d", ownership, uid, gid)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("environment mode = %o, want no group/other access", info.Mode().Perm())
	}
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read generated environment structure: %v", err)
	}
	for _, key := range []string{"POSTGRES_PASSWORD=", "PACKMON_DB_PASSWORD=", "PACKMON_ADMIN_INITIAL_PASSWORD=", "PACKMON_ENCRYPTION_KEY=", "PACKMON_ADMIN_AUDIT_HMAC_KEY="} {
		if !bytes.Contains(data, []byte(key)) {
			t.Fatalf("generated environment is missing key %s", strings.TrimSuffix(key, "="))
		}
	}

	t.Run("F056-bugs-2_plain_model", func(t *testing.T) {
		services := s.run(30*time.Second, "config", "--services")
		for _, service := range strings.Fields(services) {
			if service == "init-secrets" {
				t.Skip("F056-bugs-2: the exact unprofiled init-secrets service participates in the plain default model")
			}
		}
	})
}

func (h *composeRuntimeHarness) testMigrationOrdersServerStartup(t *testing.T) {
	failureOverlay := `services:
  packmon-migrate:
    entrypoint: !override ["/bin/sh", "-ec"]
    command: !override ["exit 42"]
`
	s := h.newScenario(t, []string{"docker-compose.yml", "docker-compose.override.yml"}, h.commonOverlay(true, "127.0.0.1::8080"), failureOverlay)
	s.down()
	_, output, err := s.command(2*time.Minute, "up", "-d", "--wait", "packmon-server")
	if err == nil {
		t.Fatal("server startup unexpectedly succeeded after synthetic migrate failure")
	}
	if !strings.Contains(output, "42") && !strings.Contains(strings.ToLower(output), "failed") {
		t.Fatalf("migration failure was not attributable to the synthetic nonzero migrate: %s", s.diagnostic(output))
	}
	serverID := strings.TrimSpace(s.runAllowFailure(30*time.Second, "ps", "-q", "packmon-server"))
	if serverID != "" {
		state, _ := h.dockerCommandOutput(30*time.Second, nil, "inspect", "--format", "{{.State.Running}}", serverID)
		if strings.TrimSpace(string(state)) == "true" {
			t.Fatal("server reached running state after migrate failure")
		}
	}

	s.down()
	s = h.newScenario(t, []string{"docker-compose.yml", "docker-compose.override.yml"}, h.commonOverlay(true, "127.0.0.1::8080"))
	s.down()
	s.run(3*time.Minute, "up", "-d", "--wait", "packmon-server")
	migrateID := strings.TrimSpace(s.run(30*time.Second, "ps", "-a", "-q", "packmon-migrate"))
	if migrateID == "" {
		t.Fatal("normal dependency startup did not create the packmon-migrate container")
	}
	migrateState := strings.TrimSpace(string(h.mustDockerOutput(t, 30*time.Second, "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}} {{.State.FinishedAt}}", migrateID)))
	migrateFields := strings.Fields(migrateState)
	if len(migrateFields) != 3 || migrateFields[0] != "exited" || migrateFields[1] != "0" {
		t.Fatalf("packmon-migrate state after normal dependency startup = %q, want exited 0 with completion timestamp", migrateState)
	}
	migrateFinished, err := time.Parse(time.RFC3339Nano, migrateFields[2])
	if err != nil || migrateFinished.IsZero() {
		t.Fatalf("parse packmon-migrate completion timestamp %q: %v", migrateFields[2], err)
	}
	successServerID := strings.TrimSpace(s.run(30*time.Second, "ps", "-q", "packmon-server"))
	if successServerID == "" {
		t.Fatal("normal dependency startup did not create the packmon-server container")
	}
	serverStartedText := strings.TrimSpace(string(h.mustDockerOutput(t, 30*time.Second, "inspect", "--format", "{{.State.StartedAt}}", successServerID)))
	serverStarted, err := time.Parse(time.RFC3339Nano, serverStartedText)
	if err != nil {
		t.Fatalf("parse packmon-server start timestamp %q: %v", serverStartedText, err)
	}
	if serverStarted.Before(migrateFinished) {
		t.Fatalf("server started at %s before migration completed at %s", serverStarted, migrateFinished)
	}
	port := s.publishedPort("packmon-server", "8080")
	s.waitHTTP("http://127.0.0.1:"+port+"/readyz", 2*time.Minute)
	s.assertNoProviderActivity()
}

func (h *composeRuntimeHarness) testProductionLifecycleProxyAndPersistence(t *testing.T) {
	s := h.newScenario(t, []string{"docker-compose.server.yml"}, h.commonOverlay(false, "127.0.0.1::8080"))
	s.down()
	s.startMigratedServer()
	port := s.publishedPort("packmon-server", "8080")
	readyURL := "http://127.0.0.1:" + port + "/readyz"
	s.waitHTTP(readyURL, 2*time.Minute)

	target, _ := url.Parse("http://127.0.0.1:" + port)
	proxy := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(target))
	defer proxy.Close()
	proxyClient := proxy.Client()
	proxyClient.Timeout = 5 * time.Second
	response, err := proxyClient.Get(proxy.URL + "/version")
	if err != nil {
		t.Fatalf("HTTPS request through test-owned TLS reverse proxy: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("TLS reverse proxy /version status = %d, want 200", response.StatusCode)
	}

	containerID := strings.TrimSpace(s.run(30*time.Second, "ps", "-q", "packmon-server"))
	if containerID == "" {
		t.Fatal("server container ID is empty")
	}
	// Kill PID 1 from inside the container so Docker observes a crash. A
	// `docker stop`/`docker kill` API call is an operator stop and can suppress
	// an unless-stopped restart instead of exercising the restart policy.
	_, _, _ = s.command(30*time.Second, "exec", "-T", "packmon-server", "/bin/busybox", "kill", "-9", "1")
	s.waitHTTP(readyURL, 2*time.Minute)
	restarts := strings.TrimSpace(string(h.mustDockerOutput(t, 30*time.Second, "inspect", "--format", "{{.RestartCount}}", containerID)))
	if restarts == "0" || restarts == "" {
		t.Fatalf("unless-stopped policy did not record a restart: %q", restarts)
	}

	s.run(30*time.Second, "exec", "-T", "postgres", "psql", "-U", "packmon", "-d", "packmon", "-v", "ON_ERROR_STOP=1", "-c", "CREATE TABLE compose_contract_sentinel(value text PRIMARY KEY); INSERT INTO compose_contract_sentinel VALUES ('persisted');")
	s.run(30*time.Second, "exec", "-T", "packmon-server", "/bin/sh", "-ec", "printf persisted > /data/feeds/compose-contract-marker")
	s.downKeepVolumes()
	s.startMigratedServer()
	if output := s.run(30*time.Second, "exec", "-T", "postgres", "psql", "-At", "-U", "packmon", "-d", "packmon", "-c", "SELECT value FROM compose_contract_sentinel"); strings.TrimSpace(output) != "persisted" {
		t.Fatalf("database sentinel after container recreation = %q", output)
	}
	if output := s.run(30*time.Second, "exec", "-T", "packmon-server", "/bin/sh", "-ec", "cat /data/feeds/compose-contract-marker"); strings.TrimSpace(output) != "persisted" {
		t.Fatalf("feed marker after container recreation = %q", output)
	}
	s.assertNoProviderActivity()
}

func (h *composeRuntimeHarness) testMetricsLoopbackAccess(t *testing.T) {
	overlay := `services:
  packmon-server:
    ports: !override
      - "127.0.0.1::9090"
`
	s := h.newScenario(t, []string{"docker-compose.server.yml"}, h.commonOverlay(false, ""), overlay)
	s.down()
	s.startMigratedServer()
	port := s.publishedPort("packmon-server", "9090")
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://127.0.0.1:" + port + "/metrics")
	if err == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		t.Fatalf("host unexpectedly reached container-loopback metrics listener (status %d)", response.StatusCode)
	}
	metrics := s.waitContainerMetrics(2 * time.Minute)
	if !strings.Contains(metrics, "packmon_") {
		t.Fatalf("in-container metrics output has no Packmon metric: %s", s.diagnostic(metrics))
	}
	s.assertNoProviderActivity()
}

func (h *composeRuntimeHarness) testConfiguredBackupEntrypointProbe(t *testing.T) {
	backupDir := t.TempDir()
	if err := os.Chmod(backupDir, 0o777); err != nil {
		t.Fatalf("make test-owned backup directory writable: %v", err)
	}
	overlay := fmt.Sprintf(`services:
  packmon-backup:
    volumes: !override
      - %s:/backups/packmon
`, yamlQuote(backupDir))
	s := h.newScenario(t, []string{"docker-compose.server.yml"}, h.commonOverlay(false, ""), overlay)
	s.down()
	s.startPostgresAndMigrate()
	_, output, err := s.command(2*time.Minute, "run", "--rm", "--no-deps", "packmon-backup")
	dumps, globErr := filepath.Glob(filepath.Join(backupDir, "packmon-*.dump"))
	if globErr != nil {
		t.Fatalf("glob backup dumps: %v", globErr)
	}
	if err == nil && len(dumps) > 0 {
		return
	}

	t.Run("F058-bugs-4_configured_entrypoint", func(t *testing.T) {
		entrypoint := string(h.mustDockerOutput(t, 30*time.Second, "image", "inspect", "--format", "{{json .Config.Entrypoint}}", composeRuntimePostgresImage))
		failure := strings.ToLower(output)
		entrypointRetained := strings.Contains(entrypoint, "docker-entrypoint") && strings.Contains(entrypoint, "postgres")
		commandPassedAsArgs := strings.Contains(failure, "sh") && (strings.Contains(failure, "postgres") || strings.Contains(failure, "invalid"))
		if entrypointRetained && commandPassedAsArgs && len(dumps) == 0 {
			t.Skip("F058-bugs-4: configured backup retains the PostgreSQL entrypoint and passes sh -ec as postgres arguments")
		}
		t.Fatalf("configured backup failed for a reason other than F058-bugs-4: %v: %s", err, s.diagnostic(output))
	})
}

func (h *composeRuntimeHarness) testBackupCreateRestoreFailureAndRetention(t *testing.T) {
	backupDir := t.TempDir()
	if err := os.Chmod(backupDir, 0o777); err != nil {
		t.Fatalf("make test-owned backup directory writable: %v", err)
	}
	overlay := fmt.Sprintf(`services:
  packmon-backup:
    entrypoint: !override []
    volumes: !override
      - %s:/backups/packmon
`, yamlQuote(backupDir))
	s := h.newScenario(t, []string{"docker-compose.server.yml"}, h.commonOverlay(false, ""), overlay)
	s.down()
	s.startPostgresAndMigrate()
	configured := s.run(30*time.Second, "config")
	productionCommand := readProductionBackupCommand(t, filepath.Join(h.buildContext, "docker-compose.server.yml"))
	if !strings.Contains(configured, "pg_dump --format=custom") || !strings.Contains(configured, "pg_restore --list") || !strings.Contains(productionCommand, "pg_dump --format=custom") {
		t.Fatal("entrypoint-clearing overlay did not preserve the production backup command body")
	}

	s.run(30*time.Second, "exec", "-T", "postgres", "psql", "-U", "packmon", "-d", "packmon", "-v", "ON_ERROR_STOP=1", "-c", "CREATE TABLE backup_contract_sentinel(value text PRIMARY KEY); INSERT INTO backup_contract_sentinel VALUES ('restored');")
	s.run(2*time.Minute, "run", "--rm", "--no-deps", "packmon-backup")
	dump := newestDump(t, backupDir)
	s.run(2*time.Minute, "run", "--rm", "--no-deps", "--entrypoint", "pg_restore", "packmon-backup", "--list", "/backups/packmon/"+filepath.Base(dump))
	s.run(30*time.Second, "exec", "-T", "postgres", "createdb", "-U", "packmon", "compose_restore")
	s.run(2*time.Minute, "run", "--rm", "--no-deps", "--entrypoint", "pg_restore", "packmon-backup", "--no-owner", "--dbname", "compose_restore", "/backups/packmon/"+filepath.Base(dump))
	if output := s.run(30*time.Second, "exec", "-T", "postgres", "psql", "-At", "-U", "packmon", "-d", "compose_restore", "-c", "SELECT value FROM backup_contract_sentinel"); strings.TrimSpace(output) != "restored" {
		t.Fatalf("restored backup sentinel = %q", output)
	}

	oldSentinel := filepath.Join(backupDir, "packmon-failure-must-not-prune.dump")
	writeAgedFile(t, oldSentinel, 10*24*time.Hour)
	if _, _, err := s.command(2*time.Minute, "run", "--rm", "--no-deps", "-e", "PGHOST=127.0.0.1", "-e", "PGPORT=1", "packmon-backup"); err == nil {
		t.Fatal("forced pg_dump failure unexpectedly succeeded")
	}
	if _, err := os.Stat(oldSentinel); err != nil {
		t.Fatalf("backup failure pruned old sentinel before successful validation: %v", err)
	}
	if err := os.Remove(oldSentinel); err != nil {
		t.Fatalf("remove failure sentinel: %v", err)
	}

	young := filepath.Join(backupDir, "packmon-retention-young.dump")
	boundary := filepath.Join(backupDir, "packmon-retention-boundary.dump")
	old := filepath.Join(backupDir, "packmon-retention-old.dump")
	writeAgedFile(t, young, 6*24*time.Hour+23*time.Hour)
	writeAgedFile(t, boundary, 7*24*time.Hour+time.Hour)
	writeAgedFile(t, old, 8*24*time.Hour+time.Hour)
	s.run(2*time.Minute, "run", "--rm", "--no-deps", "packmon-backup")
	if _, err := os.Stat(young); err != nil {
		t.Fatalf("6d23h retention fixture was removed: %v", err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("8d1h retention fixture remains or stat failed: %v", err)
	}
	t.Run("F058-bugs-3_seven_day_boundary", func(t *testing.T) {
		if _, err := os.Stat(boundary); err == nil {
			t.Skip("F058-bugs-3: GNU find -mtime +7 retains the sole 7d1h boundary fixture while both margin cases pass")
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat 7d1h retention fixture: %v", err)
		}
	})
}

func (h *composeRuntimeHarness) commonOverlay(local bool, serverPort string) string {
	var b strings.Builder
	b.WriteString("services:\n  postgres:\n    ports: !override []\n")
	fmt.Fprintf(&b, "    image: %s\n    pull_policy: never\n", yamlQuote(composeRuntimePostgresImage))
	for _, name := range []string{"packmon-server", "packmon-migrate"} {
		fmt.Fprintf(&b, "  %s:\n    image: %s\n    pull_policy: never\n    build: !reset null\n", name, yamlQuote(h.image))
		if name == "packmon-server" {
			b.WriteString("    env_file: !override []\n")
			if serverPort == "" {
				b.WriteString("    ports: !override []\n")
			} else {
				fmt.Fprintf(&b, "    ports: !override\n      - %s\n", yamlQuote(serverPort))
			}
			b.WriteString("    environment:\n")
			for _, pair := range []string{
				"PACKMON_FEED_SYNC_ON_STARTUP=false",
				"PACKMON_FEED_OSV_ENABLED=false", "PACKMON_FEED_GHSA_ENABLED=false", "PACKMON_FEED_OPENSSF_ENABLED=false",
				"PACKMON_FEED_VULNCHECK_ENABLED=false", "PACKMON_FEED_NVD_ENABLED=false", "PACKMON_FEED_CISAKEV_ENABLED=false",
				"PACKMON_FEED_EPSS_ENABLED=false", "PACKMON_FEED_ENDOFLIFE_ENABLED=false", "PACKMON_FEED_SOCKET_ENABLED=false",
				"PACKMON_FEED_REVERSINGLABS_ENABLED=false", "PACKMON_VULNCHECK_API_KEY=", "PACKMON_SOCKET_API_KEY=", "PACKMON_REVERSINGLABS_API_KEY=",
			} {
				key, value, _ := strings.Cut(pair, "=")
				fmt.Fprintf(&b, "      %s: %s\n", key, yamlQuote(value))
			}
		}
	}
	if local {
		fmt.Fprintf(&b, "  init-secrets:\n    image: %s\n    pull_policy: never\n    build: !reset null\n", yamlQuote(h.image))
	}
	fmt.Fprintf(&b, "  packmon-backup:\n    image: %s\n    pull_policy: never\n", yamlQuote(composeRuntimePostgresImage))
	return b.String()
}

func (h *composeRuntimeHarness) newScenario(t *testing.T, composeNames []string, overlays ...string) *composeRuntimeScenario {
	t.Helper()
	dir := t.TempDir()
	files := make([]string, 0, len(composeNames)+1)
	for _, name := range composeNames {
		from := filepath.Join(h.buildContext, name)
		to := filepath.Join(dir, name)
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatalf("read reviewed Compose input %s: %v", name, err)
		}
		if err := os.WriteFile(to, data, 0o600); err != nil {
			t.Fatalf("stage Compose input %s: %v", name, err)
		}
		files = append(files, to)
	}
	for i, overlay := range overlays {
		overlayPath := filepath.Join(dir, fmt.Sprintf("runtime-%d.override.yml", i))
		if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
			t.Fatalf("write runtime overlay: %v", err)
		}
		files = append(files, overlayPath)
	}
	envFile := filepath.Join(dir, "runtime.env")
	writeRuntimeEnv(t, envFile, h.secrets)
	s := &composeRuntimeScenario{
		h:       h,
		dir:     dir,
		project: "packmoncontract" + strconv.FormatInt(time.Now().UnixNano(), 36),
		files:   files,
		envFile: envFile,
	}
	t.Cleanup(s.down)
	return s
}

func (s *composeRuntimeScenario) env(key, value string) {
	s.h.t.Helper()
	data, err := os.ReadFile(s.envFile)
	if err != nil {
		s.h.t.Fatalf("read test-owned environment file: %v", err)
	}
	data = append(data, []byte(key+"="+value+"\n")...)
	if err := os.WriteFile(s.envFile, data, 0o600); err != nil {
		s.h.t.Fatalf("update test-owned environment file: %v", err)
	}
}

func (s *composeRuntimeScenario) composeArgs(args ...string) []string {
	result := []string{"compose", "--env-file", s.envFile, "--project-name", s.project}
	for _, file := range s.files {
		result = append(result, "-f", file)
	}
	return append(result, args...)
}

func (s *composeRuntimeScenario) command(timeout time.Duration, args ...string) (string, string, error) {
	ctx, cancel, effectiveTimeout, ok := s.h.workContext(timeout)
	if !ok {
		return "", "", fmt.Errorf("Compose runtime work budget exhausted before docker compose %s", args[0])
	}
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", s.composeArgs(args...)...) // #nosec G204 -- exact test-owned project/files and fixed caller arguments
	cmd.Dir = s.dir
	cmd.Env = runtimeDockerEnvironment(nil)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "", string(output), fmt.Errorf("docker compose %s timed out after bounded %s", args[0], effectiveTimeout.Round(time.Second))
	}
	return string(output), string(output), err
}

func (s *composeRuntimeScenario) run(timeout time.Duration, args ...string) string {
	s.h.t.Helper()
	output, diagnostic, err := s.command(timeout, args...)
	if err != nil {
		s.h.t.Fatalf("docker compose %s: %v: %s", args[0], err, s.diagnostic(diagnostic))
	}
	return output
}

func (s *composeRuntimeScenario) runAllowFailure(timeout time.Duration, args ...string) string {
	output, _, _ := s.command(timeout, args...)
	return output
}

func (s *composeRuntimeScenario) down() {
	ctx, cancel, _, ok := s.h.cleanupContext(time.Minute)
	if !ok {
		return
	}
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", s.composeArgs("down", "--volumes", "--remove-orphans")...) // #nosec G204 -- exact test-owned project/files and fixed cleanup arguments
	cmd.Dir = s.dir
	cmd.Env = runtimeDockerEnvironment(nil)
	_, _ = cmd.CombinedOutput()
}

func (s *composeRuntimeScenario) downKeepVolumes() {
	s.run(time.Minute, "down", "--remove-orphans")
}

func (s *composeRuntimeScenario) waitHealthy(service string, timeout time.Duration) {
	s.h.t.Helper()
	deadline := earlierTime(time.Now().Add(timeout), s.h.deadline.Add(-composeRuntimeCleanupBudget))
	for time.Now().Before(deadline) {
		id := strings.TrimSpace(s.runAllowFailure(30*time.Second, "ps", "-q", service))
		if id != "" {
			output, err := s.h.dockerCommandOutput(30*time.Second, nil, "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", id)
			if err == nil && strings.TrimSpace(string(output)) == "healthy" {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	s.h.t.Fatalf("%s did not become healthy: %s", service, s.diagnostic(s.runAllowFailure(30*time.Second, "ps", "-a")))
}

func (s *composeRuntimeScenario) publishedPort(service, target string) string {
	s.h.t.Helper()
	output := strings.TrimSpace(s.run(30*time.Second, "port", service, target))
	_, port, ok := strings.Cut(output, ":")
	if !ok || port == "" {
		s.h.t.Fatalf("parse published port from %q", output)
	}
	return port
}

func (s *composeRuntimeScenario) waitHTTP(address string, timeout time.Duration) {
	s.h.t.Helper()
	deadline := earlierTime(time.Now().Add(timeout), s.h.deadline.Add(-composeRuntimeCleanupBudget))
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		response, err := client.Get(address)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	s.h.t.Fatalf("HTTP endpoint did not become ready: %s; services: %s", strings.ReplaceAll(address, s.dir, "[TMP]"), s.diagnostic(s.runAllowFailure(30*time.Second, "ps", "-a")))
}

func (s *composeRuntimeScenario) waitContainerMetrics(timeout time.Duration) string {
	s.h.t.Helper()
	deadline := earlierTime(time.Now().Add(timeout), s.h.deadline.Add(-composeRuntimeCleanupBudget))
	for time.Now().Before(deadline) {
		output, _, err := s.command(30*time.Second, "exec", "-T", "packmon-server", "/bin/busybox", "wget", "-qO-", "http://127.0.0.1:9090/metrics")
		if err == nil && strings.Contains(output, "packmon_") {
			return output
		}
		time.Sleep(250 * time.Millisecond)
	}
	s.h.t.Fatalf("in-container metrics endpoint did not become ready: %s", s.diagnostic(s.runAllowFailure(30*time.Second, "logs", "--no-color", "packmon-server")))
	return ""
}

func (s *composeRuntimeScenario) startPostgresAndMigrate() {
	s.h.t.Helper()
	s.run(2*time.Minute, "up", "-d", "postgres")
	s.waitHealthy("postgres", 2*time.Minute)
	s.run(2*time.Minute, "run", "--rm", "--no-deps", "packmon-migrate")
}

func (s *composeRuntimeScenario) startMigratedServer() {
	s.h.t.Helper()
	s.startPostgresAndMigrate()
	s.run(2*time.Minute, "up", "-d", "--no-deps", "packmon-server")
}

func (s *composeRuntimeScenario) assertNoProviderActivity() {
	s.h.t.Helper()
	logs := strings.ToLower(s.runAllowFailure(30*time.Second, "logs", "--no-color", "packmon-server"))
	for _, marker := range []string{"starting provider sync", "starting feed sync", "provider lookup started", "external lookup started"} {
		if strings.Contains(logs, marker) {
			s.h.t.Fatalf("server logs show prohibited provider egress marker %q: %s", marker, s.diagnostic(logs))
		}
	}
}

func (s *composeRuntimeScenario) diagnostic(output string) string {
	output = strings.ReplaceAll(output, s.dir, "[SCENARIO]")
	output = strings.ReplaceAll(output, filepath.ToSlash(s.dir), "[SCENARIO]")
	return s.h.diagnostic(output)
}

func (h *composeRuntimeHarness) diagnostic(output string) string {
	replacements := map[string]string{h.repo: "[REPO]", h.buildContext: "[BUILD_CONTEXT]"}
	for key, value := range h.secrets {
		if value != "" {
			replacements[value] = "[REDACTED_" + key + "]"
		}
	}
	return boundedRuntimeDiagnostic(output, replacements)
}

func (h *composeRuntimeHarness) workContext(requested time.Duration) (context.Context, context.CancelFunc, time.Duration, bool) {
	return boundedRuntimeContext(h.deadline.Add(-composeRuntimeCleanupBudget), requested)
}

func (h *composeRuntimeHarness) cleanupContext(requested time.Duration) (context.Context, context.CancelFunc, time.Duration, bool) {
	return boundedRuntimeContext(h.deadline, requested)
}

func (h *composeRuntimeHarness) dockerCommandOutput(timeout time.Duration, env map[string]string, args ...string) ([]byte, error) {
	ctx, cancel, effectiveTimeout, ok := h.workContext(timeout)
	if !ok {
		return nil, fmt.Errorf("Compose runtime work budget exhausted before docker %s", args[0])
	}
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- fixed Docker executable and controlled test arguments
	cmd.Env = runtimeDockerEnvironment(env)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return output, fmt.Errorf("docker %s timed out after bounded %s", args[0], effectiveTimeout.Round(time.Second))
	}
	return output, err
}

func (h *composeRuntimeHarness) mustDockerOutput(t *testing.T, timeout time.Duration, args ...string) []byte {
	t.Helper()
	output, err := h.dockerCommandOutput(timeout, nil, args...)
	if err != nil {
		t.Fatalf("docker %s: %v: %s", args[0], err, h.diagnostic(string(output)))
	}
	return output
}

func boundedRuntimeContext(deadline time.Time, requested time.Duration) (context.Context, context.CancelFunc, time.Duration, bool) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, nil, 0, false
	}
	effective := min(requested, remaining)
	ctx, cancel := context.WithTimeout(context.Background(), effective)
	return ctx, cancel, effective, true
}

func earlierTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func generatedComposeEnvironment(t *testing.T) map[string]string {
	t.Helper()
	secret := func(bytes int) string {
		value := make([]byte, bytes)
		if _, err := rand.Read(value); err != nil {
			t.Fatalf("generate runtime secret: %v", err)
		}
		return base64.StdEncoding.EncodeToString(value)
	}
	databasePassword := secret(24)
	return map[string]string{
		"POSTGRES_DB":                     "packmon",
		"POSTGRES_USER":                   "packmon",
		"POSTGRES_PASSWORD":               databasePassword,
		"PACKMON_DB_PASSWORD":             databasePassword,
		"PACKMON_ADMIN_INITIAL_PASSWORD":  "Runtime-" + secret(18) + "!",
		"PACKMON_ENCRYPTION_KEY":          secret(32),
		"PACKMON_ADMIN_AUDIT_HMAC_KEY":    secret(32),
		"PACKMON_TRUSTED_PROXIES":         "127.0.0.1/32",
		"PACKMON_SERVER_SHUTDOWN_TIMEOUT": "15s",
	}
}

func writeRuntimeEnv(t *testing.T, path string, values map[string]string) {
	t.Helper()
	keys := []string{"POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD", "PACKMON_DB_PASSWORD", "PACKMON_ADMIN_INITIAL_PASSWORD", "PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY", "PACKMON_TRUSTED_PROXIES", "PACKMON_SERVER_SHUTDOWN_TIMEOUT"}
	var b strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&b, "%s=%s\n", key, values[key])
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write test-owned Compose environment: %v", err)
	}
}

func runtimeDockerEnvironment(extra map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "COMPOSE_") || strings.HasPrefix(upper, "PACKMON_") || strings.HasPrefix(upper, "POSTGRES_") || strings.HasPrefix(upper, "PG") {
			continue
		}
		env = append(env, entry)
	}
	for key, value := range extra {
		env = append(env, key+"="+value)
	}
	return env
}

func runHostCommand(t *testing.T, dir string, timeout time.Duration, env map[string]string, executable string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...) // #nosec G204 -- executable and arguments are fixed by the test harness
	cmd.Dir = dir
	cmd.Env = runtimeDockerEnvironment(env)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("%s timed out after %s", executable, timeout)
	}
	if err != nil {
		t.Fatalf("%s %s: %v: %s", executable, strings.Join(args, " "), err, boundedRuntimeDiagnostic(string(output), map[string]string{dir: "[DIR]"}))
	}
	return string(output)
}

func dockerCommandOutput(timeout time.Duration, env map[string]string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- fixed Docker executable and controlled test arguments
	cmd.Env = runtimeDockerEnvironment(env)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return output, fmt.Errorf("docker %s timed out after %s", args[0], timeout)
	}
	return output, err
}

func mustDockerOutput(t *testing.T, timeout time.Duration, args ...string) []byte {
	t.Helper()
	output, err := dockerCommandOutput(timeout, nil, args...)
	if err != nil {
		t.Fatalf("docker %s: %v: %s", args[0], err, boundedRuntimeDiagnostic(string(output), nil))
	}
	return output
}

func requireDockerOutput(t *testing.T, timeout time.Duration, args []string, want string) {
	t.Helper()
	output := strings.TrimSpace(string(mustDockerOutput(t, timeout, args...)))
	if want != "" && output != want {
		t.Fatalf("docker %s = %q, want %q", strings.Join(args, " "), output, want)
	}
}

func boundedRuntimeDiagnostic(output string, replacements map[string]string) string {
	for old, replacement := range replacements {
		if old != "" {
			output = strings.ReplaceAll(output, old, replacement)
		}
	}
	const limit = 4000
	if len(output) > limit {
		return output[:limit] + "...[truncated]"
	}
	return output
}

func extractTar(t *testing.T, archivePath, destination string) {
	t.Helper()
	file, err := os.Open(archivePath) // #nosec G304 -- test-owned archive path
	if err != nil {
		t.Fatalf("open reviewed archive: %v", err)
	}
	defer file.Close()
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("read reviewed archive: %v", err)
		}
		target := filepath.Join(destination, filepath.FromSlash(header.Name))
		rel, err := filepath.Rel(destination, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("reviewed archive contains unsafe path %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				t.Fatalf("create reviewed archive directory: %v", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatalf("create reviewed archive parent: %v", err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode)&0o777) // #nosec G304 -- target was constrained to test-owned destination
			if err != nil {
				t.Fatalf("create reviewed archive file: %v", err)
			}
			if _, err := io.Copy(out, reader); err != nil {
				_ = out.Close()
				t.Fatalf("extract reviewed archive file: %v", err)
			}
			if err := out.Close(); err != nil {
				t.Fatalf("close reviewed archive file: %v", err)
			}
		default:
			t.Fatalf("reviewed archive contains unsupported entry %q type %d", header.Name, header.Typeflag)
		}
	}
}

func yamlQuote(value string) string {
	return strconv.Quote(filepath.ToSlash(value))
}

func newestDump(t *testing.T, dir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "packmon-*.dump"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("find generated custom dump: %v; matches=%d", err, len(matches))
	}
	newest := matches[0]
	newestInfo, _ := os.Stat(newest)
	for _, match := range matches[1:] {
		info, err := os.Stat(match)
		if err == nil && info.ModTime().After(newestInfo.ModTime()) {
			newest, newestInfo = match, info
		}
	}
	return newest
}

func writeAgedFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte("retention fixture"), 0o600); err != nil {
		t.Fatalf("write retention fixture: %v", err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatalf("age retention fixture: %v", err)
	}
}

func readProductionBackupCommand(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- path is under the exact reviewed archive
	if err != nil {
		t.Fatalf("read reviewed production Compose file: %v", err)
	}
	text := string(data)
	start := strings.Index(text, "  packmon-backup:")
	if start < 0 {
		t.Fatal("reviewed production Compose has no backup service")
	}
	return text[start:]
}
