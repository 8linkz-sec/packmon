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

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/httpclient"
)

const (
	// feedName is the canonical name used in feed_sync_status.
	feedName = "nvd"

	// DefaultAPIURL is the NVD CVE API v2.0 endpoint.
	DefaultAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// maxBodySize limits the response body to 5 MB per CVE lookup.
	maxBodySize = 5 << 20

	// maxErrorBodyDrain limits non-success response drains used only to make
	// short keep-alive reuse possible before returning an error.
	maxErrorBodyDrain = 64 << 10

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

	// maxRetryAfterDelay bounds upstream Retry-After values so one malformed
	// or hostile response cannot stall the whole feed sync for hours.
	maxRetryAfterDelay = 5 * time.Minute

	// unknownCVEIDPageSize bounds database discovery memory independently of
	// the NVD request rate-limit batch size.
	unknownCVEIDPageSize = 500

	// maxOperationErrorSamples caps retained per-CVE errors while preserving
	// the total failure count returned to operators.
	maxOperationErrorSamples = 5
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
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
}

type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
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

type nvdNegativeLookupRecorder interface {
	RecordNVDCVSSNegativeLookup(context.Context, string) error
}

// Syncer fetches CVSS scores from the NVD API and updates UNKNOWN-severity
// vulnerabilities. It implements feed.FeedSyncer.
type Syncer struct {
	logger            *slog.Logger
	httpClient        *http.Client
	apiURL            string
	apiKey            string
	discoveryPageSize int
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

// WithDiscoveryPageSize overrides the bounded database discovery page size.
// It is primarily useful for tests that need to exercise multiple pages.
func WithDiscoveryPageSize(size int) Option {
	return func(s *Syncer) { s.discoveryPageSize = size }
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
		apiURL:            DefaultAPIURL,
		discoveryPageSize: unknownCVEIDPageSize,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.httpClient = httpclient.CloneWithSafeRedirectPolicy(s.httpClient)
	return s
}

// Name implements feed.FeedSyncer.
func (s *Syncer) Name() string { return feedName }

// Sync implements feed.FeedSyncer. It finds unresolved vulnerabilities with
// CVE aliases, fetches their CVSS scores from the NVD API, and updates the
// database.
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	s.logger.Info("starting NVD enrichment sync")

	batchSize := batchSizeNoKey
	if s.apiKey != "" {
		batchSize = batchSizeWithKey
	}
	pageSize := s.discoveryPageSize
	if pageSize <= 0 {
		pageSize = unknownCVEIDPageSize
	}

	progress := nvdSyncProgress{}
	operationErrors := nvdOperationErrorCollector{}
	rateLimiter := nvdRequestRateLimiter{batchSize: batchSize}
	afterCVE := ""

	for {
		cveIDs, err := store.FindUnknownSeverityCVEIDs(ctx, afterCVE, pageSize)
		if err != nil {
			return nil, fmt.Errorf("nvd: find unknown severity CVE IDs after %q: %w", afterCVE, err)
		}
		if len(cveIDs) == 0 {
			if progress.total == 0 {
				s.logger.Info("NVD enrichment: no UNKNOWN-severity CVEs found, nothing to do")
			}
			break
		}

		progress.total += len(cveIDs)
		s.logger.Info("NVD enrichment: processing CVE page",
			slog.String("after_cve", afterCVE),
			slog.Int("page_cves", len(cveIDs)),
			slog.Int("total_discovered", progress.total),
		)

		for _, cveID := range cveIDs {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("nvd: context cancelled: %w", err)
			}
			if err := rateLimiter.waitBeforeRequest(ctx, s.logger, progress); err != nil {
				return nil, err
			}

			score, severity, fetchErr := s.fetchCVSSWithRateLimitRetry(ctx, cveID)
			var retryWaitErr *rateLimitRetryWaitError
			if errors.As(fetchErr, &retryWaitErr) {
				return nil, fetchErr
			}
			progress.processed++

			if fetchErr != nil {
				s.logger.Debug("NVD enrichment: failed to fetch CVE",
					slog.String("cve_id", cveID),
					slog.String("error", feed.SafeDiagnosticError(fetchErr)),
				)
				operationErrors.add(fmt.Errorf("fetch %s: %w", cveID, fetchErr))
				progress.skipped++
				continue
			}

			updated, err := applyNVDSeverityUpdate(ctx, store, cveID, score, severity)
			if err != nil {
				s.logger.Warn("NVD enrichment: failed to update CVE",
					slog.String("cve_id", cveID),
					slog.String("error", feed.SafeDiagnosticError(err)),
				)
				operationErrors.add(fmt.Errorf("update %s: %w", cveID, err))
				continue
			}
			if !updated {
				if err := recordNVDNegativeLookup(ctx, store, cveID); err != nil {
					s.logger.Warn("NVD enrichment: failed to record negative CVSS lookup",
						slog.String("cve_id", cveID),
						slog.String("error", feed.SafeDiagnosticError(err)),
					)
					operationErrors.add(fmt.Errorf("record negative lookup %s: %w", cveID, err))
				}
				progress.skipped++
				continue
			}
			progress.updated++

			s.logNVDProgress(progress)
		}

		afterCVE = cveIDs[len(cveIDs)-1]
		if len(cveIDs) < pageSize {
			break
		}
	}

	s.logger.Info("NVD enrichment sync completed",
		slog.Int("total_cves", progress.total),
		slog.Int("processed", progress.processed),
		slog.Int("updated", progress.updated),
		slog.Int("skipped", progress.skipped),
	)

	if err := operationErrors.err(); err != nil {
		return nil, err
	}

	return &feed.SyncResult{
		EntriesSynced: progress.updated,
		EntriesTotal:  progress.total,
	}, nil
}

type nvdSyncProgress struct {
	total     int
	updated   int
	processed int
	skipped   int
}

type nvdRequestRateLimiter struct {
	batchSize int
	sent      int
}

func (l *nvdRequestRateLimiter) waitBeforeRequest(ctx context.Context, logger *slog.Logger, progress nvdSyncProgress) error {
	if l.batchSize <= 0 {
		return nil
	}
	if l.sent < l.batchSize {
		l.sent++
		return nil
	}

	logger.Debug("NVD enrichment: rate limit pause",
		slog.Duration("duration", rateLimitWindow),
		slog.Int("processed", progress.processed),
		slog.Int("total_discovered", progress.total),
	)
	if err := waitForRetry(ctx, rateLimitWindow); err != nil {
		return fmt.Errorf("nvd: context cancelled during rate limit wait: %w", err)
	}
	l.sent = 1
	return nil
}

type nvdOperationErrorCollector struct {
	total   int
	samples []error
}

func (c *nvdOperationErrorCollector) add(err error) {
	c.total++
	if len(c.samples) < maxOperationErrorSamples {
		c.samples = append(c.samples, err)
	}
}

func (c nvdOperationErrorCollector) err() error {
	if c.total == 0 {
		return nil
	}
	joined := errors.Join(c.samples...)
	if c.total > len(c.samples) {
		return fmt.Errorf("nvd: %d CVE enrichment error(s); showing first %d: %w", c.total, len(c.samples), joined)
	}
	return fmt.Errorf("nvd: %d CVE enrichment error(s): %w", c.total, joined)
}

type rateLimitRetryWaitError struct {
	err error
}

func (e *rateLimitRetryWaitError) Error() string {
	return fmt.Sprintf("nvd: context cancelled during rate limit retry: %v", e.err)
}

func (e *rateLimitRetryWaitError) Unwrap() error {
	return e.err
}

func forEachNVDBatch(cves []string, batchSize int, fn func(start int, batch []string) error) error {
	if batchSize <= 0 {
		batchSize = len(cves)
	}
	if batchSize == 0 {
		return nil
	}

	for start := 0; start < len(cves); start += batchSize {
		end := start + batchSize
		if end > len(cves) {
			end = len(cves)
		}
		if err := fn(start, cves[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Syncer) fetchCVSSWithRateLimitRetry(ctx context.Context, cveID string) (float64, string, error) {
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
			return 0, "UNKNOWN", &rateLimitRetryWaitError{err: err}
		}

		score, severity, fetchErr = s.fetchCVSS(ctx, cveID)
	}
	return score, severity, fetchErr
}

func applyNVDSeverityUpdate(ctx context.Context, store db.Store, cveID string, score float64, severity string) (bool, error) {
	if score <= 0 || severity == "UNKNOWN" {
		return false, nil
	}
	if err := store.UpdateSeverityByCVE(ctx, cveID, severity, score); err != nil {
		return false, err
	}
	return true, nil
}

func recordNVDNegativeLookup(ctx context.Context, store db.Store, cveID string) error {
	recorder, ok := store.(nvdNegativeLookupRecorder)
	if !ok {
		return nil
	}
	return recorder.RecordNVDCVSSNegativeLookup(ctx, cveID)
}

func (s *Syncer) logNVDProgress(progress nvdSyncProgress) {
	if progress.processed%100 != 0 && progress.processed != progress.total {
		return
	}
	s.logger.Info("NVD enrichment: progress",
		slog.Int("processed", progress.processed),
		slog.Int("total", progress.total),
		slog.Int("updated", progress.updated),
		slog.Int("skipped", progress.skipped),
	)
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
	req.Header.Set("User-Agent", feed.FeedSyncUserAgent)
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
		drainErrorBody(resp.Body)
		return 0, "UNKNOWN", nil
	case http.StatusForbidden:
		// NVD returns 403 for access/API-key configuration failures. Retrying
		// them as rate limits only delays surfacing the operator action needed.
		drainErrorBody(resp.Body)
		return 0, "UNKNOWN", feed.PermanentError(fmt.Errorf("nvd API access denied (HTTP %d) for %s; check API key or mirror permissions", resp.StatusCode, cveID))
	case http.StatusTooManyRequests:
		// Rate limited. Read body for diagnostics, then return a typed
		// rate-limit error so the caller can back off and retry.
		drainErrorBody(resp.Body)
		return 0, "UNKNOWN", &rateLimitError{
			status:     resp.StatusCode,
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	default:
		drainErrorBody(resp.Body)
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
	cvssMetrics := metrics.CVSSMetricV31
	if len(cvssMetrics) == 0 {
		cvssMetrics = metrics.CVSSMetricV30
	}
	if len(cvssMetrics) == 0 {
		return 0, "UNKNOWN", nil
	}

	score := cvssMetrics[0].CVSSData.BaseScore
	severity := feed.CVSSToSeverity(score)

	return score, severity, nil
}

func drainErrorBody(r io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r, maxErrorBodyDrain))
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
	return parseRetryAfterAt(value, time.Now())
}

func parseRetryAfterAt(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return rateLimitWindow
	}

	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return boundRetryAfter(time.Duration(seconds) * time.Second)
	}

	if when, err := http.ParseTime(value); err == nil {
		wait := when.Sub(now)
		if wait > 0 {
			return boundRetryAfter(wait)
		}
		return 0
	}

	return rateLimitWindow
}

func boundRetryAfter(d time.Duration) time.Duration {
	if d > maxRetryAfterDelay {
		return maxRetryAfterDelay
	}
	return d
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
