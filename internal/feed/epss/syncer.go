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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

const (
	// feedName is the canonical name used in feed_sync_status.
	feedName = "epss"

	// DefaultScoresURL is the official EPSS gzipped CSV endpoint.
	DefaultScoresURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

	// maxBodySize limits the decompressed response to 50 MB.
	maxBodySize = 50 << 20

	epssBatchSize = 5000
)

type epssScoreStreamReplacer interface {
	ReplaceEPSSScoresStream(ctx context.Context, stream func(func([]db.EPSSEntry) error) error) (updated, cleared, total int, err error)
}

type epssMetadata struct {
	ModelVersion string `json:"model_version,omitempty"`
	ScoreDate    string `json:"score_date,omitempty"`
}

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

	if replacer, ok := store.(epssScoreStreamReplacer); ok {
		totalUpdated, cleared, totalEntries, metadata, err := s.replaceScoresStream(ctx, replacer)
		if err != nil {
			return nil, fmt.Errorf("epss: stream replace scores: %w", err)
		}
		s.logger.Info("EPSS sync completed",
			slog.Int("total_entries", totalEntries),
			slog.Int("updated", totalUpdated),
			slog.Int("cleared", cleared),
		)
		return syncResult(totalUpdated, totalEntries, metadata), nil
	}

	entries, metadata, err := s.downloadScores(ctx)
	if err != nil {
		return nil, fmt.Errorf("epss: download scores: %w", err)
	}

	s.logger.Info("downloaded EPSS scores", slog.Int("entry_count", len(entries)))

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("epss: context cancelled: %w", err)
	}
	totalUpdated, cleared, err := store.ReplaceEPSSScores(ctx, entries)
	if err != nil {
		return nil, fmt.Errorf("epss: replace scores: %w", err)
	}

	s.logger.Info("EPSS sync completed",
		slog.Int("total_entries", len(entries)),
		slog.Int("updated", totalUpdated),
		slog.Int("cleared", cleared),
	)

	return &feed.SyncResult{
		EntriesSynced: totalUpdated,
		EntriesTotal:  len(entries),
		Metadata:      metadataJSON(metadata),
	}, nil
}

// downloadScores fetches and parses the gzipped EPSS CSV.
// The CSV format (after a comment header line) is:
//
//	cve,epss,percentile
//	CVE-2021-23337,0.01234,0.87654
func (s *Syncer) replaceScoresStream(ctx context.Context, replacer epssScoreStreamReplacer) (int, int, int, epssMetadata, error) {
	bodyReader, closeBody, err := s.openScores(ctx)
	if err != nil {
		return 0, 0, 0, epssMetadata{}, err
	}
	defer closeBody()

	var metadata epssMetadata
	parsedTotal := 0
	updated, cleared, total, err := replacer.ReplaceEPSSScoresStream(ctx, func(yield func([]db.EPSSEntry) error) error {
		var parsedMetadata epssMetadata
		var parseErr error
		parsedTotal, parsedMetadata, parseErr = streamLimitedCSV(bodyReader, maxBodySize, epssBatchSize, yield)
		if parseErr != nil {
			return parseErr
		}
		metadata = parsedMetadata
		return nil
	})
	if err != nil {
		return updated, cleared, total, metadata, err
	}
	if total == 0 {
		total = parsedTotal
	}
	return updated, cleared, total, metadata, nil
}

func syncResult(entriesSynced, entriesTotal int, metadata epssMetadata) *feed.SyncResult {
	return &feed.SyncResult{
		EntriesSynced: entriesSynced,
		EntriesTotal:  entriesTotal,
		Metadata:      metadataJSON(metadata),
	}
}

func metadataJSON(metadata epssMetadata) json.RawMessage {
	if metadata.ModelVersion == "" && metadata.ScoreDate == "" {
		return nil
	}
	raw, _ := json.Marshal(metadata)
	return raw
}

func (s *Syncer) downloadScores(ctx context.Context) ([]db.EPSSEntry, epssMetadata, error) {
	bodyReader, closeBody, err := s.openScores(ctx)
	if err != nil {
		return nil, epssMetadata{}, err
	}
	defer closeBody()

	return parseLimitedCSV(bodyReader, maxBodySize)
}

func (s *Syncer) openScores(ctx context.Context) (io.Reader, func(), error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.scoresURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http get: %w", err)
	}
	closeBody := func() { _ = resp.Body.Close() }

	if resp.StatusCode != http.StatusOK {
		closeBody()
		return nil, nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	// Determine whether the response body is gzip-compressed. The
	// Content-Encoding header is the primary signal. As a fallback we
	// peek at the first two bytes for the gzip magic number (0x1f 0x8b).
	var bodyReader io.Reader

	contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if contentEncoding == "gzip" {
		gz, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			closeBody()
			return nil, nil, fmt.Errorf("gzip reader: %w", gzErr)
		}
		closeBody = func() {
			_ = gz.Close()
			_ = resp.Body.Close()
		}
		bodyReader = gz
	} else {
		// No Content-Encoding header (or non-gzip). Peek at the stream
		// to detect gzip magic bytes in case the server omitted the header.
		peek := make([]byte, 2)
		n, peekErr := io.ReadFull(resp.Body, peek)
		if peekErr != nil && peekErr != io.ErrUnexpectedEOF {
			closeBody()
			return nil, nil, fmt.Errorf("peek response: %w", peekErr)
		}
		// Reassemble the stream: prepend the peeked bytes.
		bodyReader = io.MultiReader(
			bytes.NewReader(peek[:n]),
			resp.Body,
		)
		if n == 2 && peek[0] == 0x1f && peek[1] == 0x8b {
			gz, gzErr := gzip.NewReader(bodyReader)
			if gzErr != nil {
				closeBody()
				return nil, nil, fmt.Errorf("gzip reader (detected from magic bytes): %w", gzErr)
			}
			closeBody = func() {
				_ = gz.Close()
				_ = resp.Body.Close()
			}
			bodyReader = gz
		}
	}

	return bodyReader, closeBody, nil
}

func parseLimitedCSV(r io.Reader, maxBytes int64) ([]db.EPSSEntry, epssMetadata, error) {
	limitedReader := &io.LimitedReader{R: r, N: maxBytes + 1}
	entries, metadata, err := parseCSVWithMetadata(limitedReader)
	if err != nil {
		return nil, metadata, err
	}
	if limitedReader.N == 0 {
		return nil, metadata, fmt.Errorf("decompressed EPSS CSV exceeds %d bytes", maxBytes)
	}
	return entries, metadata, nil
}

func streamLimitedCSV(r io.Reader, maxBytes int64, batchSize int, yield func([]db.EPSSEntry) error) (int, epssMetadata, error) {
	limitedReader := &io.LimitedReader{R: r, N: maxBytes + 1}
	total, metadata, err := streamCSV(limitedReader, batchSize, yield)
	if err != nil {
		return total, metadata, err
	}
	if limitedReader.N == 0 {
		return total, metadata, fmt.Errorf("decompressed EPSS CSV exceeds %d bytes", maxBytes)
	}
	return total, metadata, nil
}

// parseCSV reads the EPSS CSV format. The first line may be a comment
// starting with '#' (model version metadata). The second line is the
// header row. Subsequent lines are data rows.
func parseCSV(r io.Reader) ([]db.EPSSEntry, error) {
	entries, _, err := parseCSVWithMetadata(r)
	return entries, err
}

func parseCSVWithMetadata(r io.Reader) ([]db.EPSSEntry, epssMetadata, error) {
	entries := make([]db.EPSSEntry, 0, epssBatchSize)
	total, metadata, err := streamCSV(r, epssBatchSize, func(batch []db.EPSSEntry) error {
		entries = append(entries, batch...)
		return nil
	})
	if err != nil {
		return nil, metadata, err
	}
	if total == 0 {
		return nil, metadata, fmt.Errorf("no EPSS score rows found")
	}
	return entries, metadata, nil
}

func streamCSV(r io.Reader, batchSize int, yield func([]db.EPSSEntry) error) (int, epssMetadata, error) {
	if batchSize <= 0 {
		batchSize = epssBatchSize
	}
	csvReader := csv.NewReader(r)
	csvReader.FieldsPerRecord = -1 // allow variable fields; we validate ourselves
	csvReader.LazyQuotes = true
	csvReader.TrimLeadingSpace = true

	metadata := epssMetadata{}
	headerFound := false
	row := 0
	total := 0
	batch := make([]db.EPSSEntry, 0, batchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := yield(batch); err != nil {
			return err
		}
		total += len(batch)
		batch = batch[:0]
		return nil
	}
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		row++
		if err != nil {
			return total, metadata, fmt.Errorf("row %d: csv read: %w", row, err)
		}

		if isBlankCSVRecord(record) {
			continue
		}

		// Skip comment lines (model version metadata).
		if len(record) > 0 && strings.HasPrefix(strings.TrimSpace(record[0]), "#") {
			metadata.merge(parseCommentMetadata(record))
			continue
		}

		if !headerFound {
			if !isEPSSHeader(record) {
				return total, metadata, fmt.Errorf("row %d: expected header cve,epss,percentile", row)
			}
			headerFound = true
			continue
		}

		if len(record) != 3 {
			return total, metadata, fmt.Errorf("row %d: expected 3 fields, got %d", row, len(record))
		}

		cveID := strings.TrimSpace(record[0])
		if !strings.HasPrefix(cveID, "CVE-") {
			return total, metadata, fmt.Errorf("row %d: invalid CVE ID %q", row, cveID)
		}

		score, err := strconv.ParseFloat(strings.TrimSpace(record[1]), 64)
		if err != nil {
			return total, metadata, fmt.Errorf("row %d: invalid EPSS score: %w", row, err)
		}
		if score < 0 || score > 1 {
			return total, metadata, fmt.Errorf("row %d: EPSS score %v outside range 0..1", row, score)
		}

		percentile, err := strconv.ParseFloat(strings.TrimSpace(record[2]), 64)
		if err != nil {
			return total, metadata, fmt.Errorf("row %d: invalid EPSS percentile: %w", row, err)
		}
		if percentile < 0 || percentile > 1 {
			return total, metadata, fmt.Errorf("row %d: EPSS percentile %v outside range 0..1", row, percentile)
		}

		batch = append(batch, db.EPSSEntry{
			CVEID:      cveID,
			Score:      score,
			Percentile: percentile,
		})
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				return total, metadata, err
			}
		}
	}

	if !headerFound {
		return total, metadata, fmt.Errorf("expected header cve,epss,percentile")
	}
	if err := flush(); err != nil {
		return total, metadata, err
	}
	if total == 0 {
		return total, metadata, fmt.Errorf("no EPSS score rows found")
	}
	return total, metadata, nil
}

func (m *epssMetadata) merge(other epssMetadata) {
	if m.ModelVersion == "" {
		m.ModelVersion = other.ModelVersion
	}
	if m.ScoreDate == "" {
		m.ScoreDate = other.ScoreDate
	}
}

func parseCommentMetadata(record []string) epssMetadata {
	raw := strings.TrimSpace(strings.Join(record, ","))
	raw = strings.TrimPrefix(raw, "#")
	var metadata epssMetadata
	for _, part := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok {
			key, value, ok = strings.Cut(strings.TrimSpace(part), "=")
		}
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "model_version":
			metadata.ModelVersion = strings.TrimSpace(value)
		case "score_date":
			metadata.ScoreDate = strings.TrimSpace(value)
		}
	}
	return metadata
}

func isBlankCSVRecord(record []string) bool {
	for _, field := range record {
		if strings.TrimSpace(field) != "" {
			return false
		}
	}
	return true
}

func isEPSSHeader(record []string) bool {
	if len(record) != 3 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(record[0]), "cve") &&
		strings.EqualFold(strings.TrimSpace(record[1]), "epss") &&
		strings.EqualFold(strings.TrimSpace(record[2]), "percentile")
}
