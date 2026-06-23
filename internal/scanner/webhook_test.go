package scanner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// ---------------------------------------------------------------------------
// computeHMACSHA256 tests
// ---------------------------------------------------------------------------

func TestComputeHMACSHA256(t *testing.T) {
	t.Parallel()

	secret := []byte("my-webhook-secret")
	message := []byte(`{"event":"scan_completed"}`)

	got := computeHMACSHA256(secret, message)

	// Compute the expected value independently.
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	want := hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("computeHMACSHA256() = %q, want %q", got, want)
	}
}

func TestComputeHMACSHA256_EmptySecret(t *testing.T) {
	t.Parallel()

	message := []byte("hello")
	got := computeHMACSHA256([]byte(""), message)

	// With an empty secret, HMAC should still produce a valid hex string.
	if got == "" {
		t.Fatal("computeHMACSHA256 with empty secret should return a non-empty hex string")
	}
	if len(got) != 64 { // SHA256 produces 32 bytes = 64 hex chars
		t.Fatalf("computeHMACSHA256 returned %d hex chars, want 64", len(got))
	}
}

func TestComputeHMACSHA256_DifferentSecretsDifferentResults(t *testing.T) {
	t.Parallel()

	message := []byte("same message")
	sig1 := computeHMACSHA256([]byte("secret-a"), message)
	sig2 := computeHMACSHA256([]byte("secret-b"), message)

	if sig1 == sig2 {
		t.Fatal("different secrets should produce different signatures")
	}
}

// ---------------------------------------------------------------------------
// SendWebhook tests
// ---------------------------------------------------------------------------

func testScanResult() *domain.ScanResult {
	return &domain.ScanResult{
		ScanID:          "test-scan-1",
		Mode:            "remote",
		ScannedAt:       time.Now().UTC(),
		DurationMs:      42,
		PackagesScanned: 5,
		FindingsCount:   1,
		Summary: domain.ScanSummary{
			BySeverity: map[string]int{"HIGH": 1},
			ByType:     map[string]int{"vulnerability": 1},
			BySource:   map[string]int{"osv": 1},
		},
		Findings: []domain.Finding{
			{
				Name:       "lodash",
				Version:    "4.17.15",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "CVE-2021-23337",
				Title:      "Prototype pollution",
				Source:     "osv",
			},
		},
		FeedVersions: map[string]string{"osv": "2026-04-03T03:00:00Z"},
	}
}

func TestSendWebhook_Success(t *testing.T) {
	t.Parallel()

	var (
		mu           sync.Mutex
		gotBody      []byte
		gotHeaders   http.Header
		gotMethod    string
		serverCalled bool
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		serverCalled = true
		gotMethod = r.Method
		gotHeaders = r.Header.Clone()
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read webhook body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	secret := "test-webhook-secret" //nolint:gosec // test fixture secret
	cfg := WebhookConfig{
		URL:     server.URL,
		Secret:  secret,
		Version: "1.0.0",
	}

	result := testScanResult()
	repo := &domain.RepoInfo{Name: "org/repo", Branch: "main", Commit: "abc123"}

	SendWebhook(context.Background(), cfg, result, repo)

	mu.Lock()
	defer mu.Unlock()

	if !serverCalled {
		t.Fatal("webhook server was not called")
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("webhook method = %q, want POST", gotMethod)
	}

	// Verify Content-Type.
	ct := gotHeaders.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	// Verify User-Agent contains the version.
	ua := gotHeaders.Get("User-Agent")
	if !strings.Contains(ua, "1.0.0") {
		t.Fatalf("User-Agent = %q, expected to contain version 1.0.0", ua)
	}

	// Verify HMAC authentication header.
	sigHeader := gotHeaders.Get("X-Packmon-Signature")
	if sigHeader == "" {
		t.Fatal("X-Packmon-Signature header must be set when secret is configured")
	}
	if !strings.HasPrefix(sigHeader, "sha256=") {
		t.Fatalf("X-Packmon-Signature = %q, want sha256= prefix", sigHeader)
	}

	expectedSig := computeHMACSHA256([]byte(secret), gotBody)
	if sigHeader != "sha256="+expectedSig {
		t.Fatalf("HMAC authentication header mismatch: got %q, want sha256=%s", sigHeader, expectedSig)
	}

	// Verify the body deserializes to a WebhookEnvelope.
	var envelope domain.WebhookEnvelope
	if err := json.Unmarshal(gotBody, &envelope); err != nil {
		t.Fatalf("failed to unmarshal webhook body: %v", err)
	}

	if envelope.Event != "scan_completed" {
		t.Fatalf("envelope.Event = %q, want %q", envelope.Event, "scan_completed")
	}
	if envelope.Version != "1" {
		t.Fatalf("envelope.Version = %q, want %q", envelope.Version, "1")
	}
	if envelope.Source != "cli" {
		t.Fatalf("envelope.Source = %q, want %q", envelope.Source, "cli")
	}
	if envelope.Repository == nil {
		t.Fatal("envelope.Repository must not be nil")
	}
	if envelope.Repository.Name != "org/repo" {
		t.Fatalf("envelope.Repository.Name = %q, want %q", envelope.Repository.Name, "org/repo")
	}
	if envelope.Repository.Branch != "" || envelope.Repository.Commit != "" {
		t.Fatalf("envelope.Repository includes branch/commit metadata: %+v", envelope.Repository)
	}
	if envelope.Result.ScanID != "test-scan-1" {
		t.Fatalf("envelope.Result.ScanID = %q, want %q", envelope.Result.ScanID, "test-scan-1")
	}
}

func TestSendWebhook_NoSecret_NoAuthenticationHeader(t *testing.T) {
	t.Parallel()

	var gotHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := WebhookConfig{
		URL:    server.URL,
		Secret: "", // no secret
	}

	SendWebhook(context.Background(), cfg, testScanResult(), nil)

	if sig := gotHeaders.Get("X-Packmon-Signature"); sig != "" {
		t.Fatalf("X-Packmon-Signature should be empty when no secret, got %q", sig)
	}
}

func TestSendWebhookRejectsPlainHTTPToNonLoopback(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	SendWebhook(context.Background(), WebhookConfig{URL: "http://user:hook-secret@example.test/private?token=query-secret", Version: "1.0.0"}, testScanResult(), nil) //nolint:gosec // fake secret-bearing URL verifies redaction.

	output := logs.String()
	if !strings.Contains(output, "refusing insecure webhook URL") {
		t.Fatalf("webhook insecure URL log = %q, want refusal", output)
	}
	for _, leaked := range []string{"hook-secret", "query-secret", "/private"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("webhook insecure URL log leaked %q:\n%s", leaked, output)
		}
	}
}

func TestSendWebhookAllowsPlainHTTPToLoopback(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	SendWebhook(context.Background(), WebhookConfig{URL: server.URL, Version: "1.0.0"}, testScanResult(), nil)

	if !called {
		t.Fatal("loopback HTTP webhook server was not called")
	}
}

func TestSendWebhook_EmptyURL_NoOp(t *testing.T) {
	t.Parallel()

	// Should not panic or make any HTTP call.
	SendWebhook(context.Background(), WebhookConfig{URL: ""}, testScanResult(), nil)
}

func TestSendWebhook_Timeout(t *testing.T) {
	t.Parallel()

	// Use a TCP listener that accepts but never reads or writes.
	// This causes the client to time out without needing an httptest server
	// that blocks on Close().
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Accept connections in the background but never respond.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			// Hold the connection open without sending anything.
			go func(c net.Conn) {
				<-time.After(30 * time.Second)
				_ = c.Close()
			}(conn)
		}
	}()

	cfg := WebhookConfig{
		URL:     "http://" + ln.Addr().String(),
		Version: "1.0.0",
	}

	// Create a context with a very short deadline so we do not wait long.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// SendWebhook should return without error (best-effort). It logs the
	// timeout but does not propagate it. We just verify it does not panic
	// or hang.
	done := make(chan struct{})
	go func() {
		SendWebhook(ctx, cfg, testScanResult(), nil)
		close(done)
	}()

	select {
	case <-done:
		// Good: returned within a reasonable time.
	case <-time.After(5 * time.Second):
		t.Fatal("SendWebhook did not return within 5 seconds; likely stuck")
	}
}

func TestSendWebhook_ServerError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := WebhookConfig{
		URL:     server.URL,
		Version: "1.0.0",
	}

	// Should not panic; webhook errors are logged but swallowed.
	SendWebhook(context.Background(), cfg, testScanResult(), nil)
}

func TestSendWebhookLogsRedactedURL(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previousLogger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	webhookURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	webhookURL.User = url.UserPassword("user-secret", "pass-secret")
	webhookURL.Path = "/services/path-token"
	webhookURL.RawQuery = "sig=query-secret"
	webhookURL.Fragment = "frag-secret"

	SendWebhook(context.Background(), WebhookConfig{URL: webhookURL.String(), Version: "1.0.0"}, testScanResult(), nil)

	output := logs.String()
	for _, leaked := range []string{"user-secret", "pass-secret", "path-token", "query-secret", "frag-secret"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("webhook log leaked %q:\n%s", leaked, output)
		}
	}
	if !strings.Contains(output, "url="+webhookURL.Scheme+"://"+webhookURL.Host+"/...") {
		t.Fatalf("webhook log missing redacted URL:\n%s", output)
	}
}

func TestSendWebhookPostFailureLogsRedactedURLAndError(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previousLogger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	rawURL := "http://user-secret:pass-secret@" + addr + "/services/path-token?sig=query-secret#frag-secret"
	SendWebhook(context.Background(), WebhookConfig{URL: rawURL, Version: "1.0.0"}, testScanResult(), nil)

	output := logs.String()
	for _, leaked := range []string{"user-secret", "pass-secret", "path-token", "query-secret", "frag-secret"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("webhook POST failure log leaked %q:\n%s", leaked, output)
		}
	}
	if !strings.Contains(output, "url=http://"+addr+"/...") {
		t.Fatalf("webhook POST failure log missing redacted URL:\n%s", output)
	}
}

func TestSendWebhookCreateRequestLogsRedactedURL(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previousLogger)

	rawURL := "://user-secret/path-token?sig=query-secret#frag-secret"
	SendWebhook(context.Background(), WebhookConfig{URL: rawURL, Version: "1.0.0"}, testScanResult(), nil)

	output := logs.String()
	for _, leaked := range []string{"user-secret", "path-token", "query-secret", "frag-secret"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("webhook create-request log leaked %q:\n%s", leaked, output)
		}
	}
	if !strings.Contains(output, "url=(redacted-url)") {
		t.Fatalf("webhook create-request log missing redacted URL:\n%s", output)
	}
}

func TestSendWebhook_DefaultUserAgent(t *testing.T) {
	t.Parallel()

	var gotUA string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := WebhookConfig{
		URL:     server.URL,
		Version: "", // empty version -> should use "dev"
	}

	SendWebhook(context.Background(), cfg, testScanResult(), nil)

	if !strings.Contains(gotUA, "dev") {
		t.Fatalf("User-Agent = %q, expected to contain 'dev' when version is empty", gotUA)
	}
}
