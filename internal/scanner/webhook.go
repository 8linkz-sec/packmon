package scanner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/logsafe"
)

const (
	webhookTimeout      = 10 * time.Second
	webhookHMACHeader   = "X-Packmon-Signature"
	webhookContentType  = "application/json; charset=utf-8"
	webhookEventScan    = "scan_completed"
	webhookPayloadVer   = "1"
	webhookUserAgentFmt = "packmon-cli/%s"
	webhookMaxRespBody  = 4096
)

// WebhookConfig holds parameters for webhook delivery.
type WebhookConfig struct {
	URL     string
	Secret  string
	Version string // packmon version for User-Agent
}

// SendWebhook delivers the scan result to the configured webhook URL.
// It wraps the result in a domain.WebhookEnvelope. If a secret is configured,
// the request body is authenticated with HMAC-SHA256 and the MAC is sent in the
// X-Packmon-Signature header as described in SECURITY.md.
//
// Webhook delivery is best-effort: failures are logged but never cause
// the scan command to return a non-zero exit code.
func SendWebhook(ctx context.Context, cfg WebhookConfig, result *domain.ScanResult, repo *domain.RepoInfo) {
	if cfg.URL == "" {
		return
	}
	logURL := logsafe.RedactURL(cfg.URL)
	if err := validateWebhookURL(cfg.URL); err != nil {
		slog.Warn("webhook: refusing insecure webhook URL", slog.String("url", logURL), slog.String("error", err.Error()))
		return
	}

	envelope := domain.WebhookEnvelope{
		Event:      webhookEventScan,
		Version:    webhookPayloadVer,
		Timestamp:  time.Now().UTC(),
		Source:     "cli",
		Repository: webhookRepoInfo(repo),
		Result:     *result,
	}

	body, err := json.Marshal(envelope)
	if err != nil {
		slog.Warn("webhook: marshal error", slog.String("error", err.Error()))
		return
	}

	// Build the HTTP request.
	reqCtx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		slog.Warn("webhook: create request error", slog.String("url", logURL), slog.String("error", "invalid webhook URL"))
		return
	}

	req.Header.Set("Content-Type", webhookContentType)

	userAgent := fmt.Sprintf(webhookUserAgentFmt, cfg.Version)
	if cfg.Version == "" {
		userAgent = fmt.Sprintf(webhookUserAgentFmt, "dev")
	}
	req.Header.Set("User-Agent", userAgent)

	// Add HMAC authentication if a secret is configured (DE-21).
	if cfg.Secret != "" {
		sig := computeHMACSHA256([]byte(cfg.Secret), body)
		req.Header.Set(webhookHMACHeader, "sha256="+sig)
	}

	// Send with a dedicated client (separate from the scanner's HTTP client)
	// so the webhook timeout is isolated.
	client := &http.Client{Timeout: webhookTimeout}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("webhook: POST failed", slog.String("url", logURL), slog.String("error", logsafe.RedactURLError(err)))
		return
	}
	defer closeSilently(resp.Body)

	// Drain and discard response body to allow connection reuse.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, webhookMaxRespBody))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		slog.Info("webhook: POST succeeded", slog.String("url", logURL), slog.Int("status", resp.StatusCode))
	} else {
		slog.Warn("webhook: POST returned non-2xx", slog.String("url", logURL), slog.Int("status", resp.StatusCode))
	}
}

func validateWebhookURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid webhook URL")
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("webhook URL must include scheme and host")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackWebhookHost(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("scheme must be https unless webhook host is loopback")
	default:
		return fmt.Errorf("scheme must be https")
	}
}

func isLoopbackWebhookHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func webhookRepoInfo(repo *domain.RepoInfo) *domain.RepoInfo {
	if repo == nil {
		return nil
	}
	name := strings.TrimSpace(repo.Name)
	if name == "" {
		return nil
	}
	return &domain.RepoInfo{Name: name}
}

// computeHMACSHA256 returns the hex-encoded HMAC-SHA256 of message
// using the given secret key.
func computeHMACSHA256(secret, message []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}
