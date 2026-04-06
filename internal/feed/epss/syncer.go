// Package epss implements a feed syncer for the Exploit Prediction Scoring
// System (EPSS). EPSS provides a daily-updated CSV mapping CVE IDs to
// exploit probability scores (0-1) and percentile rankings.
//
// The syncer downloads the gzipped CSV from the FIRST (formerly Cyentia)
// EPSS endpoint, parses the two-column data, and batch-updates the
// epss_score and epss_percentile columns on matching vulnerability rows.
package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
)

const (
	// feedName is the canonical name used in feed_sync_status.
	feedName = "epss"

	// DefaultScoresURL is the official EPSS gzipped CSV endpoint.
	DefaultScoresURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

	// maxBodySize limits the decompressed response to 50 MB.
	maxBodySize = 50 << 20

	// batchSize controls how many entries are sent per SetEPSSScores call.
	batchSize = 5000
)

// Syncer downloads and applies EPSS scores to known vulnerabilities.
// It implements feed.FeedSyncer.
type Syncer struct {
	logger     *slog.Logger
	httpClient *http.Client
	scoresURL  string
}

// Option configures a Syncer.
type Option func(*Syncer)

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Syncer) { s.httpClient = c }
}

// WithScoresURL overrides the default EPSS CSV URL (useful for testing).
func WithScoresURL(url string) Option {
	return func(s *Syncer) { s.scoresURL = url }
}

// NewSyncer creates an EPSS syncer.
func NewSyncer(logger *slog.Logger, opts ...Option) *Syncer {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Syncer{
		logger: logger.With(slog.String("feed", feedName)),
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
		scoresURL: DefaultScoresURL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name implements feed.FeedSyncer.
func (s *Syncer) Name() string { return feedName }

// Sync implements feed.FeedSyncer. It downloads the current EPSS CSV and
// updates all matching vulnerabilities in the database. This is always a
// full replacement of EPSS data because the CSV contains the complete
// current dataset.
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	s.logger.Info("starting EPSS sync")

	entries, err := s.downloadScores(ctx)
	if err != nil {
		return nil, fmt.Errorf("epss: download scores: %w", err)
	}

	s.logger.Info("downloaded EPSS scores", slog.Int("entry_count", len(entries)))

	totalUpdated := 0
	for i := 0; i < len(entries); i += batchSize {
		end := i + batchSize
		if end > len(entries) {
			end = len(entries)
		}

		// Check context cancellation between batches.
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("epss: context cancelled: %w", err)
		}

		updated, err := store.SetEPSSScores(ctx, entries[i:end])
		if err != nil {
			return nil, fmt.Errorf("epss: set scores (batch %d-%d): %w", i, end, err)
		}
		totalUpdated += updated
	}

	s.logger.Info("EPSS sync completed",
		slog.Int("total_entries", len(entries)),
		slog.Int("updated", totalUpdated),
	)

	return &feed.SyncResult{
		EntriesSynced: totalUpdated,
		EntriesTotal:  len(entries),
	}, nil
}

// downloadScores fetches and parses the gzipped EPSS CSV.
// The CSV format (after a comment header line) is:
//
//	cve,epss,percentile
//	CVE-2021-23337,0.01234,0.87654
func (s *Syncer) downloadScores(ctx context.Context) ([]db.EPSSEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.scoresURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	// Determine whether the response body is gzip-compressed. The
	// Content-Encoding header is the primary signal. As a fallback we
	// peek at the first two bytes for the gzip magic number (0x1f 0x8b).
	var bodyReader io.Reader = resp.Body

	contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if contentEncoding == "gzip" {
		gz, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			return nil, fmt.Errorf("gzip reader: %w", gzErr)
		}
		defer func() { _ = gz.Close() }()
		bodyReader = gz
	} else {
		// No Content-Encoding header (or non-gzip). Peek at the stream
		// to detect gzip magic bytes in case the server omitted the header.
		peek := make([]byte, 2)
		n, peekErr := io.ReadFull(resp.Body, peek)
		if peekErr != nil && peekErr != io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("peek response: %w", peekErr)
		}
		// Reassemble the stream: prepend the peeked bytes.
		bodyReader = io.MultiReader(
			bytes.NewReader(peek[:n]),
			resp.Body,
		)
		if n == 2 && peek[0] == 0x1f && peek[1] == 0x8b {
			gz, gzErr := gzip.NewReader(bodyReader)
			if gzErr != nil {
				return nil, fmt.Errorf("gzip reader (detected from magic bytes): %w", gzErr)
			}
			defer func() { _ = gz.Close() }()
			bodyReader = gz
		}
	}

	limitedReader := io.LimitReader(bodyReader, maxBodySize)
	return parseCSV(limitedReader)
}

// parseCSV reads the EPSS CSV format. The first line may be a comment
// starting with '#' (model version metadata). The second line is the
// header row. Subsequent lines are data rows.
func parseCSV(r io.Reader) ([]db.EPSSEntry, error) {
	csvReader := csv.NewReader(r)
	csvReader.FieldsPerRecord = -1 // allow variable fields; we validate ourselves
	csvReader.LazyQuotes = true
	csvReader.TrimLeadingSpace = true

	// Pre-allocate for the typical EPSS dataset (~230k entries).
	entries := make([]db.EPSSEntry, 0, 250000)

	headerFound := false
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("csv read: %w", err)
		}

		// Skip comment lines (model version metadata).
		if len(record) > 0 && strings.HasPrefix(record[0], "#") {
			continue
		}

		// Skip the header row.
		if !headerFound {
			if len(record) >= 3 && strings.ToLower(strings.TrimSpace(record[0])) == "cve" {
				headerFound = true
				continue
			}
			// If the first non-comment line does not look like a header,
			// treat it as data (defensive).
			headerFound = true
		}

		if len(record) < 3 {
			continue
		}

		cveID := strings.TrimSpace(record[0])
		if !strings.HasPrefix(cveID, "CVE-") {
			continue
		}

		score, err := strconv.ParseFloat(strings.TrimSpace(record[1]), 64)
		if err != nil {
			continue
		}

		percentile, err := strconv.ParseFloat(strings.TrimSpace(record[2]), 64)
		if err != nil {
			continue
		}

		entries = append(entries, db.EPSSEntry{
			CVEID:      cveID,
			Score:      score,
			Percentile: percentile,
		})
	}

	return entries, nil
}
