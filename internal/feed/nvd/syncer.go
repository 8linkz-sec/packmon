// Package nvd implements a feed syncer that enriches vulnerabilities with
// CVSS scores from the NIST National Vulnerability Database (NVD) API v2.0.
//
// Many vulnerability entries (GO-*, RUSTSEC-*, PYSEC-*) lack CVSS data in
// their upstream source and are initially stored at Packmon's LOW fallback
// severity. However, these entries often carry CVE aliases (e.g. GO-2026-4337
// has alias CVE-2025-68121). The NVD API provides CVSS v3.1 base scores for
// these CVEs at no cost.
//
// The syncer queries the database for UNKNOWN-severity vulnerabilities that
// have CVE aliases, fetches scores from the NVD API (respecting rate limits),
// and updates the severity and cvss_score columns accordingly.
package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
)

const (
	// feedName is the canonical name used in feed_sync_status.
	feedName = "nvd"

	// DefaultAPIURL is the NVD CVE API v2.0 endpoint.
	DefaultAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// maxBodySize limits the response body to 5 MB per CVE lookup.
	maxBodySize = 5 << 20

	// batchSizeNoKey is the number of requests per window without an API key.
	// NVD allows 5 requests per 30 seconds for unauthenticated callers.
	batchSizeNoKey = 5

	// batchSizeWithKey is the number of requests per window with an API key.
	// NVD allows 50 requests per 30 seconds for authenticated callers.
	batchSizeWithKey = 50

	// rateLimitWindow is the NVD rate limit window.
	rateLimitWindow = 30 * time.Second

	// maxRateLimitRetries limits how often one CVE lookup is retried after
	// a typed rate-limit response from NVD.
	maxRateLimitRetries = 2
)

// nvdResponse is the top-level NVD API v2.0 response for a single CVE lookup.
type nvdResponse struct {
	Vulnerabilities []nvdVulnWrapper `json:"vulnerabilities"`
}

type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID      string     `json:"id"`
	Metrics nvdMetrics `json:"metrics"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCvssMetric `json:"cvssMetricV31"`
	CvssMetricV30 []nvdCvssMetric `json:"cvssMetricV30"`
}

type nvdCvssMetric struct {
	CvssData nvdCvssData `json:"cvssData"`
}

type nvdCvssData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type rateLimitError struct {
	status     int
	retryAfter time.Duration
}

func (e *rateLimitError) Error() string {
	return fmt.Sprintf("rate limited (HTTP %d), retry after %s", e.status, e.retryAfter)
}

// Syncer fetches CVSS scores from the NVD API and updates UNKNOWN-severity
// vulnerabilities. It implements feed.FeedSyncer.
type Syncer struct {
	logger     *slog.Logger
	httpClient *http.Client
	apiURL     string
	apiKey     string
}

// Option configures a Syncer.
type Option func(*Syncer)

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Syncer) { s.httpClient = c }
}

// WithAPIURL overrides the default NVD API URL (useful for testing).
func WithAPIURL(url string) Option {
	return func(s *Syncer) { s.apiURL = url }
}

// WithAPIKey sets the NVD API key for higher rate limits.
func WithAPIKey(key string) Option {
	return func(s *Syncer) { s.apiKey = key }
}

// NewSyncer creates an NVD enrichment syncer.
func NewSyncer(logger *slog.Logger, opts ...Option) *Syncer {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Syncer{
		logger: logger.With(slog.String("feed", feedName)),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiURL: DefaultAPIURL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name implements feed.FeedSyncer.
func (s *Syncer) Name() string { return feedName }

// Sync implements feed.FeedSyncer. It finds unresolved vulnerabilities with
// CVE aliases, fetches their CVSS scores from the NVD API, and updates the
// database.
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	s.logger.Info("starting NVD enrichment sync")

	aliases, err := store.FindUnknownSeverityCVEAliases(ctx)
	if err != nil {
		return nil, fmt.Errorf("nvd: find unknown severity CVE aliases: %w", err)
	}

	if len(aliases) == 0 {
		s.logger.Info("NVD enrichment: no UNKNOWN-severity CVE aliases found, nothing to do")
		return &feed.SyncResult{EntriesSynced: 0, EntriesTotal: 0}, nil
	}

	// Deduplicate CVE IDs -- multiple vulnerabilities can share the same
	// CVE alias, and we only need to fetch each CVE once.
	seen := make(map[string]struct{}, len(aliases))
	var uniqueCVEs []string
	for _, a := range aliases {
		if _, ok := seen[a.CVEID]; ok {
			continue
		}
		seen[a.CVEID] = struct{}{}
		uniqueCVEs = append(uniqueCVEs, a.CVEID)
	}

	s.logger.Info("NVD enrichment: processing CVEs",
		slog.Int("total_aliases", len(aliases)),
		slog.Int("unique_cves", len(uniqueCVEs)),
	)

	batchSize := batchSizeNoKey
	if s.apiKey != "" {
		batchSize = batchSizeWithKey
	}

	updated := 0
	processed := 0
	skipped := 0

	for i := 0; i < len(uniqueCVEs); i += batchSize {
		// Check context cancellation between batches.
		if err := ctx.Err(); err != nil {
			s.logger.Info("NVD enrichment: context cancelled, stopping",
				slog.Int("processed", processed),
				slog.Int("updated", updated),
			)
			return nil, fmt.Errorf("nvd: context cancelled: %w", err)
		}

		end := i + batchSize
		if end > len(uniqueCVEs) {
			end = len(uniqueCVEs)
		}
		batch := uniqueCVEs[i:end]

		// Respect rate limits: sleep before each batch (except the first).
		if i > 0 {
			s.logger.Debug("NVD enrichment: rate limit pause",
				slog.Duration("duration", rateLimitWindow),
				slog.Int("processed", processed),
				slog.Int("total", len(uniqueCVEs)),
			)
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("nvd: context cancelled during rate limit wait: %w", ctx.Err())
			case <-time.After(rateLimitWindow):
			}
		}

		for _, cveID := range batch {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("nvd: context cancelled: %w", err)
			}

			score, severity, fetchErr := s.fetchCVSS(ctx, cveID)
			for retries := 0; retries < maxRateLimitRetries; retries++ {
				var rlErr *rateLimitError
				if !errors.As(fetchErr, &rlErr) {
					break
				}

				s.logger.Debug("NVD enrichment: rate limited, retrying CVE lookup",
					slog.String("cve_id", cveID),
					slog.Int("attempt", retries+1),
					slog.Duration("retry_after", rlErr.retryAfter),
				)
				if err := waitForRetry(ctx, rlErr.retryAfter); err != nil {
					return nil, fmt.Errorf("nvd: context cancelled during rate limit retry: %w", err)
				}

				score, severity, fetchErr = s.fetchCVSS(ctx, cveID)
			}
			processed++

			if fetchErr != nil {
				s.logger.Debug("NVD enrichment: failed to fetch CVE",
					slog.String("cve_id", cveID),
					slog.String("error", fetchErr.Error()),
				)
				skipped++
				continue
			}

			if score <= 0 || severity == "UNKNOWN" {
				skipped++
				continue
			}

			if err := store.UpdateSeverityByCVE(ctx, cveID, severity, score); err != nil {
				s.logger.Warn("NVD enrichment: failed to update CVE",
					slog.String("cve_id", cveID),
					slog.String("error", err.Error()),
				)
				continue
			}
			updated++

			if processed%100 == 0 || processed == len(uniqueCVEs) {
				s.logger.Info("NVD enrichment: progress",
					slog.Int("processed", processed),
					slog.Int("total", len(uniqueCVEs)),
					slog.Int("updated", updated),
					slog.Int("skipped", skipped),
				)
			}
		}
	}

	s.logger.Info("NVD enrichment sync completed",
		slog.Int("total_cves", len(uniqueCVEs)),
		slog.Int("processed", processed),
		slog.Int("updated", updated),
		slog.Int("skipped", skipped),
	)

	return &feed.SyncResult{
		EntriesSynced: updated,
		EntriesTotal:  len(uniqueCVEs),
	}, nil
}

// fetchCVSS queries the NVD API for a single CVE and returns its CVSS v3.1
// base score and severity. Returns (0, "UNKNOWN", nil) when the CVE has no
// CVSS data. Returns an error for HTTP/network failures.
func (s *Syncer) fetchCVSS(ctx context.Context, cveID string) (float64, string, error) {
	reqURL, err := buildRequestURL(s.apiURL, cveID)
	if err != nil {
		return 0, "UNKNOWN", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, "UNKNOWN", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")
	if s.apiKey != "" {
		req.Header.Set("apiKey", s.apiKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, "UNKNOWN", fmt.Errorf("http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// continue below
	case http.StatusNotFound:
		// CVE not found in NVD -- skip gracefully.
		return 0, "UNKNOWN", nil
	case http.StatusForbidden, http.StatusTooManyRequests:
		// Rate limited. Read body for diagnostics, then return a typed
		// rate-limit error so the caller can back off and retry.
		_, _ = io.Copy(io.Discard, resp.Body)
		return 0, "UNKNOWN", &rateLimitError{
			status:     resp.StatusCode,
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	default:
		_, _ = io.Copy(io.Discard, resp.Body)
		return 0, "UNKNOWN", fmt.Errorf("unexpected status %d for %s", resp.StatusCode, cveID)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return 0, "UNKNOWN", fmt.Errorf("read body: %w", err)
	}

	var nvdResp nvdResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return 0, "UNKNOWN", fmt.Errorf("parse json: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return 0, "UNKNOWN", nil
	}

	metrics := nvdResp.Vulnerabilities[0].CVE.Metrics

	// Prefer CVSS v3.1, fall back to v3.0.
	cvssMetrics := metrics.CvssMetricV31
	if len(cvssMetrics) == 0 {
		cvssMetrics = metrics.CvssMetricV30
	}
	if len(cvssMetrics) == 0 {
		return 0, "UNKNOWN", nil
	}

	score := cvssMetrics[0].CvssData.BaseScore
	severity := feed.CVSSToSeverity(score)

	return score, severity, nil
}

func buildRequestURL(apiURL, cveID string) (string, error) {
	endpoint, err := url.Parse(apiURL)
	if err != nil {
		return "", fmt.Errorf("parse API URL: %w", err)
	}

	query := endpoint.Query()
	query.Set("cveId", cveID)
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return rateLimitWindow
	}

	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}

	if when, err := http.ParseTime(value); err == nil {
		wait := time.Until(when)
		if wait > 0 {
			return wait
		}
		return 0
	}

	return rateLimitWindow
}

func waitForRetry(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
