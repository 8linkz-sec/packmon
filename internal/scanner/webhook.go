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
	"net/http"
	"time"

	"github.com/8linkz/packmon/internal/domain"
)

const (
	webhookTimeout      = 10 * time.Second
	webhookSignatureHdr = "X-Packmon-Signature"
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
// the request body is signed with HMAC-SHA256 and the signature is sent in the
// X-Packmon-Signature header as described in SECURITY.md.
//
// Webhook delivery is best-effort: failures are logged but never cause
// the scan command to return a non-zero exit code.
func SendWebhook(ctx context.Context, cfg WebhookConfig, result *domain.ScanResult, repo *domain.RepoInfo) {
	if cfg.URL == "" {
		return
	}

	envelope := domain.WebhookEnvelope{
		Event:      webhookEventScan,
		Version:    webhookPayloadVer,
		Timestamp:  time.Now().UTC(),
		Source:     "cli",
		Repository: repo,
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
		slog.Warn("webhook: create request error", slog.String("error", err.Error()))
		return
	}

	req.Header.Set("Content-Type", webhookContentType)

	userAgent := fmt.Sprintf(webhookUserAgentFmt, cfg.Version)
	if cfg.Version == "" {
		userAgent = fmt.Sprintf(webhookUserAgentFmt, "dev")
	}
	req.Header.Set("User-Agent", userAgent)

	// Sign the payload if a secret is configured (DE-21).
	if cfg.Secret != "" {
		sig := computeHMACSHA256([]byte(cfg.Secret), body)
		req.Header.Set(webhookSignatureHdr, "sha256="+sig)
	}

	// Send with a dedicated client (separate from the scanner's HTTP client)
	// so the webhook timeout is isolated.
	client := &http.Client{Timeout: webhookTimeout}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("webhook: POST failed", slog.String("url", cfg.URL), slog.String("error", err.Error()))
		return
	}
	defer closeSilently(resp.Body)

	// Drain and discard response body to allow connection reuse.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, webhookMaxRespBody))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		slog.Info("webhook: POST succeeded", slog.String("url", cfg.URL), slog.Int("status", resp.StatusCode))
	} else {
		slog.Warn("webhook: POST returned non-2xx", slog.String("url", cfg.URL), slog.Int("status", resp.StatusCode))
	}
}

// computeHMACSHA256 returns the hex-encoded HMAC-SHA256 of message
// using the given secret key.
func computeHMACSHA256(secret, message []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}
