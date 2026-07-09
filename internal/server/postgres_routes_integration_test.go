//go:build integration

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/db/postgres"
	"github.com/8linkz-sec/packmon/internal/db/postgres/migrations"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

const postgresRoutesIntegrationImage = "cgr.dev/chainguard/postgres:18@sha256:891139a6d9036632791857fb7585425f1bf0c64516fc52bc39da94305ee92461"

func TestPostgresBackedPackageAPIAndWebRoutes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := startPostgresRoutesStore(t, ctx)
	t.Cleanup(func() {
		cancel()
		if err := store.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	const apiToken = "packmon-postgres-routes-token"
	seedPostgresRoutesFixtures(t, ctx, store, apiToken)

	srv := New(
		ctx,
		postgresRoutesServerConfig(),
		store,
		store,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		BuildInfo{Version: "test", Commit: "test", Date: "test", SchemaVersion: migrations.ExpectedVersion},
		nil,
		nil,
		nil,
	)
	handler := srv.main.Handler

	apiDetail := servePostgresRoutesRequest(t, handler, http.MethodGet, "/api/v1/packages/npm/left-pad-vuln-a?version=2.0.0", apiToken, nil)
	requirePostgresRoutesStatus(t, apiDetail, http.StatusOK)
	var detail struct {
		Ecosystem string           `json:"ecosystem"`
		Name      string           `json:"name"`
		Findings  []domain.Finding `json:"findings"`
	}
	if err := json.Unmarshal(apiDetail.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode package detail JSON: %v\n%s", err, apiDetail.Body.String())
	}
	if detail.Ecosystem != "npm" || detail.Name != "left-pad-vuln-a" {
		t.Fatalf("package detail identity = %s/%s, want npm/left-pad-vuln-a", detail.Ecosystem, detail.Name)
	}
	assertPostgresRoutesFinding(t, detail.Findings, "GHSA-POSTGRES-0001", "left-pad-vuln-a", "2.0.0")

	refresh := servePostgresRoutesRequest(t, handler, http.MethodPost, "/api/v1/packages/npm/left-pad-refresh/refresh", apiToken, nil)
	requirePostgresRoutesStatus(t, refresh, http.StatusAccepted)
	var refreshBody struct {
		Queued bool `json:"queued"`
		New    bool `json:"new"`
	}
	if err := json.Unmarshal(refresh.Body.Bytes(), &refreshBody); err != nil {
		t.Fatalf("decode refresh JSON: %v\n%s", err, refresh.Body.String())
	}
	if !refreshBody.Queued || !refreshBody.New {
		t.Fatalf("refresh response = %+v, want newly queued job", refreshBody)
	}
	assertPostgresRoutesRefreshJob(t, ctx, store)

	search := servePostgresRoutesRequest(t, handler, http.MethodGet, "/search?q=left-pad-vuln-a", "", nil)
	requirePostgresRoutesStatus(t, search, http.StatusOK)
	assertPostgresRoutesHTMLContains(t, search.Body.String(), "search page",
		"left-pad-vuln-a",
		"GHSA-POSTGRES-0001",
		"/package/npm/left-pad-vuln-a",
	)

	packagePage := servePostgresRoutesRequest(t, handler, http.MethodGet, "/package/npm/left-pad-vuln-a?version=2.0.0", "", nil)
	requirePostgresRoutesStatus(t, packagePage, http.StatusOK)
	assertPostgresRoutesHTMLContains(t, packagePage.Body.String(), "package page",
		"left-pad-vuln-a",
		"2.0.0",
		"Vulnerabilities (1)",
		"GHSA-POSTGRES-0001",
		"Postgres-backed test vulnerability",
		"https://osv.dev/vulnerability/GHSA-POSTGRES-0001",
	)
}

func startPostgresRoutesStore(t *testing.T, ctx context.Context) *postgres.Store {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; tagged integration test requires Docker-backed PostgreSQL: %v", err)
	}

	containerName := fmt.Sprintf("packmon-server-routes-pg-%d", time.Now().UnixNano())
	out := dockerRoutesOutput(t, 30*time.Second,
		"run", "-d", "--rm",
		"--name", containerName,
		"-e", "POSTGRES_DB=packmon",
		"-e", "POSTGRES_USER=packmon",
		"-e", "POSTGRES_PASSWORD=packmon",
		"-p", "127.0.0.1::5432",
		postgresRoutesIntegrationImage,
	)
	containerID := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		removePostgresRoutesContainer(containerName)
		removePostgresRoutesContainer(containerID)
	})

	waitForPostgresRoutesContainer(t, containerName)
	port := dockerRoutesPublishedPort(t, containerName, "5432/tcp")
	dsn := fmt.Sprintf("postgres://packmon:packmon@127.0.0.1:%d/packmon?sslmode=disable", port)
	waitForPostgresRoutesDSN(t, dsn)

	if err := migrations.Run(dsn); err != nil {
		t.Fatalf("migrations.Run() error = %v", err)
	}
	version, dirty, err := migrations.Version(dsn)
	if err != nil {
		t.Fatalf("migrations.Version() error = %v", err)
	}
	if dirty || version != migrations.ExpectedVersion {
		t.Fatalf("schema version = %d dirty=%v, want %d clean", version, dirty, migrations.ExpectedVersion)
	}

	store, err := postgres.New(ctx, dsn, nil, &postgres.PoolConfig{MaxConns: 4, MinConns: 1, ConnectTimeout: time.Second})
	if err != nil {
		t.Fatalf("postgres.New() error = %v", err)
	}
	return store
}

func seedPostgresRoutesFixtures(t *testing.T, ctx context.Context, store *postgres.Store, token string) {
	t.Helper()

	expiresAt := time.Now().UTC().Add(time.Hour)
	if _, err := store.CreateAPIKey(ctx, "postgres-routes-integration", sha256Hex(token), &expiresAt); err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:        "GHSA-POSTGRES-0001",
		Summary:   "Postgres-backed test vulnerability",
		Details:   "A tagged integration fixture for package API and web routes.",
		Severity:  "HIGH",
		Published: now.Add(-24 * time.Hour),
		Modified:  now,
		Sources: []db.VulnerabilitySource{{
			Source:   "osv",
			SourceID: "GHSA-POSTGRES-0001",
			URL:      "https://osv.dev/vulnerability/GHSA-POSTGRES-0001",
			RawJSON:  json.RawMessage(`{"id":"GHSA-POSTGRES-0001"}`),
		}},
		References: []db.VulnerabilityReference{{
			Type:   "ADVISORY",
			URL:    "https://osv.dev/vulnerability/GHSA-POSTGRES-0001",
			Source: "osv",
		}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem: "npm",
			Name:      "left-pad-vuln-a",
			VersionRanges: json.RawMessage(`[
				{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}
			]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
}

func postgresRoutesServerConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Mode:                   config.ModeProduction,
			PublicHost:             "localhost",
			AllowInsecureLocalHTTP: true,
			BlockThreshold:         string(domain.SeverityCritical),
			RateLimitPerMinute:     600,
			RateLimitBurst:         600,
			ReadTimeout:            30 * time.Second,
			WriteTimeout:           30 * time.Second,
			ShutdownTimeout:        5 * time.Second,
		},
		Metrics: config.MetricsConfig{
			Host: "127.0.0.1",
		},
		Web: config.WebConfig{
			PrivacyURL: "/privacy",
			TermsURL:   "/terms",
		},
		Admin: config.AdminConfig{
			SessionTimeout: 8 * time.Hour,
			IdleTimeout:    config.DefaultAdminIdleTimeout,
		},
		FeedSync: config.FeedSyncConfig{
			Interval: 8 * time.Hour,
		},
		Feeds: config.FeedsConfig{
			SocketEnabled: true,
			SocketMode:    config.FeedModeSelf,
			SocketAPIKey:  "socket-test-key",
		},
	}
}

func servePostgresRoutesRequest(t *testing.T, handler http.Handler, method, target, token string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, body)
	req.RemoteAddr = "127.0.0.1:12345"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "packmon-cli/postgres-routes-integration")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func requirePostgresRoutesStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, want, rec.Body.String())
	}
}

func assertPostgresRoutesFinding(t *testing.T, findings []domain.Finding, advisoryID, name, version string) {
	t.Helper()

	for _, finding := range findings {
		if finding.AdvisoryID != advisoryID {
			continue
		}
		if finding.Type != domain.FindingTypeVulnerability {
			t.Fatalf("%s type = %q, want vulnerability", advisoryID, finding.Type)
		}
		if finding.Severity != domain.SeverityHigh {
			t.Fatalf("%s severity = %q, want HIGH", advisoryID, finding.Severity)
		}
		if finding.Source != "osv" {
			t.Fatalf("%s source = %q, want osv", advisoryID, finding.Source)
		}
		if finding.Ecosystem != domain.EcosystemNPM || finding.Name != name || finding.Version != version {
			t.Fatalf("%s package = %s/%s@%s, want npm/%s@%s", advisoryID, finding.Ecosystem, finding.Name, finding.Version, name, version)
		}
		if finding.Title != "Postgres-backed test vulnerability" {
			t.Fatalf("%s title = %q, want seeded summary", advisoryID, finding.Title)
		}
		return
	}
	t.Fatalf("missing finding %s in %+v", advisoryID, findings)
}

func assertPostgresRoutesRefreshJob(t *testing.T, ctx context.Context, store *postgres.Store) {
	t.Helper()

	jobs, err := store.ListQueueJobs(ctx, db.RefreshStatusPending, 10)
	if err != nil {
		t.Fatalf("ListQueueJobs() error = %v", err)
	}
	for _, job := range jobs {
		if job.Ecosystem == "npm" && job.Name == "left-pad-refresh" && job.Source == "socket" {
			if job.Priority != db.RefreshPriorityManual || job.Status != db.RefreshStatusPending {
				t.Fatalf("refresh job = %+v, want socket priority 0 pending", job)
			}
			return
		}
	}
	t.Fatalf("missing socket refresh queue job for npm/left-pad-refresh: %+v", jobs)
}

func assertPostgresRoutesHTMLContains(t *testing.T, body, label string, want ...string) {
	t.Helper()
	for _, text := range want {
		if !strings.Contains(body, text) {
			t.Fatalf("%s missing %q in body:\n%s", label, text, body)
		}
	}
}

func dockerRoutesOutput(t *testing.T, timeout time.Duration, args ...string) []byte {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- integration test executes Docker with fixed command shapes and generated container names.
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("docker %s timed out after %s:\n%s", strings.Join(args, " "), timeout, string(out))
	}
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, string(out))
	}
	return out
}

func waitForPostgresRoutesContainer(t *testing.T, containerName string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "pg_isready", "-h", "127.0.0.1", "-p", "5432", "-U", "packmon", "-d", "packmon") // #nosec G204 -- probes the generated test container.
		err := cmd.Run()
		cancel()
		if err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres container %s did not become ready", containerName)
}

func dockerRoutesPublishedPort(t *testing.T, containerName, containerPort string) int {
	t.Helper()

	out := dockerRoutesOutput(t, 10*time.Second, "port", containerName, containerPort)
	lines := strings.Fields(strings.TrimSpace(string(out)))
	if len(lines) == 0 {
		t.Fatalf("docker port %s %s returned no mapping", containerName, containerPort)
	}
	_, port, err := net.SplitHostPort(lines[len(lines)-1])
	if err != nil {
		t.Fatalf("parse docker port mapping %q: %v", lines[len(lines)-1], err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse docker host port %q: %v", port, err)
	}
	return n
}

func waitForPostgresRoutesDSN(t *testing.T, dsn string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			err = pool.Ping(ctx)
			pool.Close()
		}
		cancel()
		if err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("postgres DSN did not become reachable")
}

func removePostgresRoutesContainer(id string) {
	if strings.TrimSpace(id) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", id).Run() // #nosec G204 -- cleanup uses generated test container identifiers.
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
