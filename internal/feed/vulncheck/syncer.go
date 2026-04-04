// Package vulncheck implements a feed syncer for the VulnCheck Community
// API. VulnCheck provides NVD++ data with better CPE coverage (77% vs 41%),
// an extended KEV list, and exploit PoC references (XDB).
//
// This syncer uses the /v3/backup/ bulk-download endpoint which requires a
// free VulnCheck API key. If no key is configured the syncer reports a
// non-retryable configuration issue.
// The data enriches existing vulnerabilities rather than creating new ones:
// it improves CVSS scores, adds exploit-exists flags, and stores source
// provenance records.
package vulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
)

const (
	// feedName is the canonical name used in feed_sync_status.
	feedName = "vulncheck"

	// DefaultBaseURL is the VulnCheck Community API base URL.
	DefaultBaseURL = "https://api.vulncheck.com"

	// nvd2Endpoint is the NVD2-compatible CVE bulk endpoint.
	nvd2Endpoint = "/v3/backup/nist-nvd2"

	// maxBodySize limits a single response to 200 MB (bulk data).
	maxBodySize = 200 << 20

	// batchSize controls how many entries are sent per EnrichVulnCheck call.
	batchSize = 1000
)

// backupResponse is the top-level shape returned by VulnCheck bulk endpoints.
type backupResponse struct {
	Data []backupCVE `json:"data"`
}

// backupCVE is one CVE record from the VulnCheck backup.
type backupCVE struct {
	ID       string       `json:"id"`
	CVEID    string       `json:"cve_id"`
	CVSS     *cvssData    `json:"cvss"`
	Exploits []exploitRef `json:"exploits"`
	URL      string       `json:"url"`
}

// cvssData holds CVSS scoring information from VulnCheck.
type cvssData struct {
	BaseScore float64 `json:"base_score"`
	Vector    string  `json:"vector_string"`
	Version   string  `json:"version"`
}

// exploitRef is a reference to an exploit PoC from VulnCheck XDB.
type exploitRef struct {
	URL    string `json:"url"`
	Name   string `json:"name"`
	Source string `json:"source"`
}

// Syncer downloads VulnCheck data and enriches existing vulnerabilities.
// It implements feed.FeedSyncer.
type Syncer struct {
	logger     *slog.Logger
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// Option configures a Syncer.
type Option func(*Syncer)

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Syncer) { s.httpClient = c }
}

// WithBaseURL overrides the default VulnCheck API base URL.
func WithBaseURL(url string) Option {
	return func(s *Syncer) { s.baseURL = url }
}

// NewSyncer creates a VulnCheck syncer. If apiKey is empty the syncer will
// report a non-retryable configuration issue on Sync.
func NewSyncer(apiKey string, logger *slog.Logger, opts ...Option) *Syncer {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Syncer{
		logger: logger.With(slog.String("feed", feedName)),
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
		baseURL: DefaultBaseURL,
		apiKey:  apiKey,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name implements feed.FeedSyncer.
func (s *Syncer) Name() string { return feedName }

// Sync implements feed.FeedSyncer. It downloads VulnCheck bulk data and
// enriches existing vulnerabilities. If no API key is configured the sync
// is skipped as a non-retryable configuration issue.
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	if s.apiKey == "" {
		s.logger.Warn("VulnCheck API key not configured, skipping sync")
		return nil, feed.PermanentError(fmt.Errorf("VulnCheck API key not configured"))
	}

	s.logger.Info("starting VulnCheck sync")

	entries, err := s.downloadBulk(ctx)
	if err != nil {
		return nil, fmt.Errorf("vulncheck: download: %w", err)
	}

	s.logger.Info("downloaded VulnCheck data", slog.Int("entry_count", len(entries)))

	totalUpdated := 0
	for i := 0; i < len(entries); i += batchSize {
		end := i + batchSize
		if end > len(entries) {
			end = len(entries)
		}

		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("vulncheck: context cancelled: %w", err)
		}

		updated, err := store.EnrichVulnCheck(ctx, entries[i:end])
		if err != nil {
			return nil, fmt.Errorf("vulncheck: enrich (batch %d-%d): %w", i, end, err)
		}
		totalUpdated += updated
	}

	s.logger.Info("VulnCheck sync completed",
		slog.Int("total_entries", len(entries)),
		slog.Int("updated", totalUpdated),
	)

	return &feed.SyncResult{
		EntriesSynced: totalUpdated,
		EntriesTotal:  len(entries),
	}, nil
}

// downloadBulk fetches the VulnCheck NVD2 backup and converts each entry
// into a VulnCheckEntry for database enrichment.
func (s *Syncer) downloadBulk(ctx context.Context) ([]db.VulnCheckEntry, error) {
	url := strings.TrimRight(s.baseURL, "/") + nvd2Endpoint

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("authentication failed (status %d): check PACKMON_VULNCHECK_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var bulk backupResponse
	if err := json.Unmarshal(body, &bulk); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}

	entries := make([]db.VulnCheckEntry, 0, len(bulk.Data))
	for _, cve := range bulk.Data {
		cveID := cve.CVEID
		if cveID == "" {
			cveID = cve.ID
		}
		if cveID == "" || !strings.HasPrefix(cveID, "CVE-") {
			continue
		}

		entry := db.VulnCheckEntry{
			CVEID:         cveID,
			ExploitExists: len(cve.Exploits) > 0,
			SourceURL:     cve.URL,
		}

		if cve.CVSS != nil && cve.CVSS.BaseScore > 0 {
			score := cve.CVSS.BaseScore
			entry.CVSSScore = &score
		}

		// Store the raw CVE record for provenance.
		rawBytes, err := json.Marshal(cve)
		if err == nil {
			entry.RawJSON = rawBytes
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
