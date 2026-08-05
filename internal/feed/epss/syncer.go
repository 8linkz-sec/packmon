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
	"math"
	"net/http"
	"regexp"
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

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

type epssScoreStreamReplacer interface {
	ReplaceEPSSScoresStream(ctx context.Context, stream func(func([]db.EPSSEntry) error) error) (updated, cleared, total int, err error)
}

type epssMetadata struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	ModelVersion string `json:"model_version,omitempty"`
	ScoreDate    string `json:"score_date,omitempty"`
}

type epssCSVRecordKind uint8

const (
	epssCSVRecordBlank epssCSVRecordKind = iota
	epssCSVRecordComment
	epssCSVRecordHeader
	epssCSVRecordData
)

type epssCSVRecord struct {
	kind     epssCSVRecordKind
	metadata epssMetadata
}

type epssScoreSnapshot struct {
	batches [][]db.EPSSEntry
	total   int
}

func (s *epssScoreSnapshot) addBatch(batch []db.EPSSEntry) error {
	if len(batch) == 0 {
		return nil
	}
	copied := append([]db.EPSSEntry(nil), batch...)
	s.batches = append(s.batches, copied)
	s.total += len(copied)
	return nil
}

func (s epssScoreSnapshot) stream(yield func([]db.EPSSEntry) error) error {
	for _, batch := range s.batches {
		if err := yield(batch); err != nil {
			return err
		}
	}
	return nil
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

	status := s.loadFeedStatus(store)
	storedMetadata := epssMetadataFromStatus(status)
	if replacer, ok := store.(epssScoreStreamReplacer); ok {
		totalUpdated, cleared, totalEntries, metadata, notModified, err := s.replaceScoresStream(ctx, replacer, storedMetadata)
		if err != nil {
			return nil, fmt.Errorf("epss: stream replace scores: %w", err)
		}
		if notModified {
			synced, total := statusCounts(status)
			s.logger.Info("EPSS scores unchanged",
				slog.Int("entries_synced", synced),
				slog.Int("entries_total", total),
			)
			return syncResult(synced, total, metadata), nil
		}
		s.logger.Info("EPSS sync completed",
			slog.Int("total_entries", totalEntries),
			slog.Int("updated", totalUpdated),
			slog.Int("cleared", cleared),
		)
		return syncResult(totalUpdated, totalEntries, metadata), nil
	}

	entries, metadata, notModified, err := s.downloadScores(ctx, storedMetadata)
	if err != nil {
		return nil, fmt.Errorf("epss: download scores: %w", err)
	}
	if notModified {
		synced, total := statusCounts(status)
		s.logger.Info("EPSS scores unchanged",
			slog.Int("entries_synced", synced),
			slog.Int("entries_total", total),
		)
		return syncResult(synced, total, metadata), nil
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

// replaceScoresStream fetches and parses the gzipped EPSS CSV.
// The CSV format (after a comment header line) is:
//
//	cve,epss,percentile
//	CVE-2021-23337,0.01234,0.87654
func (s *Syncer) replaceScoresStream(ctx context.Context, replacer epssScoreStreamReplacer, validators epssMetadata) (int, int, int, epssMetadata, bool, error) {
	bodyReader, closeBody, metadata, notModified, err := s.openScores(ctx, validators)
	if err != nil {
		return 0, 0, 0, epssMetadata{}, false, err
	}
	if notModified {
		return 0, 0, 0, metadata, true, nil
	}

	var snapshot epssScoreSnapshot
	parsedTotal, parsedMetadata, parseErr := streamLimitedCSV(bodyReader, maxBodySize, epssBatchSize, snapshot.addBatch)
	closeBody()
	if parseErr != nil {
		return 0, 0, parsedTotal, metadata, false, parseErr
	}
	metadata.merge(parsedMetadata)

	if err := ctx.Err(); err != nil {
		return 0, 0, parsedTotal, metadata, false, fmt.Errorf("context cancelled: %w", err)
	}
	updated, cleared, total, err := replacer.ReplaceEPSSScoresStream(ctx, snapshot.stream)
	if err != nil {
		return updated, cleared, total, metadata, false, err
	}
	if total == 0 {
		total = snapshot.total
	}
	return updated, cleared, total, metadata, false, nil
}

func syncResult(entriesSynced, entriesTotal int, metadata epssMetadata) *feed.SyncResult {
	return &feed.SyncResult{
		EntriesSynced: entriesSynced,
		EntriesTotal:  entriesTotal,
		Metadata:      metadataJSON(metadata),
	}
}

func metadataJSON(metadata epssMetadata) json.RawMessage {
	if metadata.ETag == "" && metadata.LastModified == "" && metadata.ModelVersion == "" && metadata.ScoreDate == "" {
		return nil
	}
	raw, _ := json.Marshal(metadata)
	return raw
}

func (s *Syncer) downloadScores(ctx context.Context, validators epssMetadata) ([]db.EPSSEntry, epssMetadata, bool, error) {
	bodyReader, closeBody, metadata, notModified, err := s.openScores(ctx, validators)
	if err != nil {
		return nil, epssMetadata{}, false, err
	}
	if notModified {
		return nil, metadata, true, nil
	}
	defer closeBody()

	entries, parsedMetadata, err := parseLimitedCSV(bodyReader, maxBodySize)
	if err != nil {
		return nil, metadata, false, err
	}
	metadata.merge(parsedMetadata)
	return entries, metadata, false, nil
}

func (s *Syncer) openScores(ctx context.Context, validators epssMetadata) (io.Reader, func(), epssMetadata, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.scoresURL, nil)
	if err != nil {
		return nil, nil, epssMetadata{}, false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", feed.FeedSyncUserAgent)
	if validators.ETag != "" {
		req.Header.Set("If-None-Match", validators.ETag)
	}
	if validators.LastModified != "" {
		req.Header.Set("If-Modified-Since", validators.LastModified)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil, epssMetadata{}, false, fmt.Errorf("http get: %w", err)
	}
	closeBody := func() { _ = resp.Body.Close() }
	metadata := validators.mergeResponseValidators(resp)

	if resp.StatusCode == http.StatusNotModified {
		closeBody()
		return nil, func() {}, metadata, true, nil
	}

	if resp.StatusCode != http.StatusOK {
		closeBody()
		return nil, nil, epssMetadata{}, false, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	metadata = epssMetadata{}.mergeResponseValidators(resp)

	// Determine whether the response body is gzip-compressed. The
	// Content-Encoding header is the primary signal. As a fallback we
	// peek at the first two bytes for the gzip magic number (0x1f 0x8b).
	var bodyReader io.Reader

	contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if contentEncoding == "gzip" {
		gz, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			closeBody()
			return nil, nil, epssMetadata{}, false, fmt.Errorf("gzip reader: %w", gzErr)
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
			return nil, nil, epssMetadata{}, false, fmt.Errorf("peek response: %w", peekErr)
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
				return nil, nil, epssMetadata{}, false, fmt.Errorf("gzip reader (detected from magic bytes): %w", gzErr)
			}
			closeBody = func() {
				_ = gz.Close()
				_ = resp.Body.Close()
			}
			bodyReader = gz
		}
	}

	return bodyReader, closeBody, metadata, false, nil
}

func parseLimitedCSV(r io.Reader, maxBytes int64) ([]db.EPSSEntry, epssMetadata, error) {
	limitedReader := &io.LimitedReader{R: r, N: maxBytes + 1}
	entries, metadata, err := parseCSVWithMetadata(limitedReader)
	if err != nil {
		return nil, metadata, err
	}
	if limitedReader.N == 0 {
		return nil, metadata, feed.NonRetryableError(fmt.Errorf("decompressed EPSS CSV exceeds %d bytes", maxBytes))
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
		return total, metadata, feed.NonRetryableError(fmt.Errorf("decompressed EPSS CSV exceeds %d bytes", maxBytes))
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
		return nil, metadata, feed.NonRetryableError(fmt.Errorf("no EPSS score rows found"))
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
			return total, metadata, feed.NonRetryableError(fmt.Errorf("row %d: csv read: %w", row, err))
		}

		parsedRecord := parseEPSSCSVRecord(row, record)
		switch parsedRecord.kind {
		case epssCSVRecordBlank:
			continue
		case epssCSVRecordComment:
			metadata.merge(parsedRecord.metadata)
			continue
		case epssCSVRecordHeader:
			if !headerFound {
				headerFound = true
				continue
			}
			fallthrough
		case epssCSVRecordData:
			if !headerFound {
				return total, metadata, feed.NonRetryableError(fmt.Errorf("row %d: expected header cve,epss,percentile", row))
			}
			entry, err := parseEPSSEntry(row, record)
			if err != nil {
				return total, metadata, err
			}
			batch = append(batch, entry)
		}
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				return total, metadata, err
			}
		}
	}

	if !headerFound {
		return total, metadata, feed.NonRetryableError(fmt.Errorf("expected header cve,epss,percentile"))
	}
	if err := flush(); err != nil {
		return total, metadata, err
	}
	if total == 0 {
		return total, metadata, feed.NonRetryableError(fmt.Errorf("no EPSS score rows found"))
	}
	return total, metadata, nil
}

func parseEPSSCSVRecord(_ int, record []string) epssCSVRecord {
	if isBlankCSVRecord(record) {
		return epssCSVRecord{kind: epssCSVRecordBlank}
	}
	if len(record) > 0 && strings.HasPrefix(strings.TrimSpace(record[0]), "#") {
		return epssCSVRecord{
			kind:     epssCSVRecordComment,
			metadata: parseCommentMetadata(record),
		}
	}
	if isEPSSHeader(record) {
		return epssCSVRecord{kind: epssCSVRecordHeader}
	}
	return epssCSVRecord{kind: epssCSVRecordData}
}

func parseEPSSEntry(row int, record []string) (db.EPSSEntry, error) {
	if len(record) != 3 {
		return db.EPSSEntry{}, feed.NonRetryableError(fmt.Errorf("row %d: expected 3 fields, got %d", row, len(record)))
	}

	cveID := strings.TrimSpace(record[0])
	if !cveIDPattern.MatchString(cveID) {
		return db.EPSSEntry{}, feed.NonRetryableError(fmt.Errorf("row %d: invalid CVE ID %q", row, cveID))
	}

	score, err := strconv.ParseFloat(strings.TrimSpace(record[1]), 64)
	if err != nil {
		return db.EPSSEntry{}, feed.NonRetryableError(fmt.Errorf("row %d: invalid EPSS score: %w", row, err))
	}
	if !validUnitInterval(score) {
		return db.EPSSEntry{}, feed.NonRetryableError(fmt.Errorf("row %d: EPSS score %v outside range 0..1", row, score))
	}

	percentile, err := strconv.ParseFloat(strings.TrimSpace(record[2]), 64)
	if err != nil {
		return db.EPSSEntry{}, feed.NonRetryableError(fmt.Errorf("row %d: invalid EPSS percentile: %w", row, err))
	}
	if !validUnitInterval(percentile) {
		return db.EPSSEntry{}, feed.NonRetryableError(fmt.Errorf("row %d: EPSS percentile %v outside range 0..1", row, percentile))
	}

	return db.EPSSEntry{
		CVEID:      cveID,
		Score:      score,
		Percentile: percentile,
	}, nil
}

func validUnitInterval(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
}

func (s *Syncer) loadFeedStatus(store db.Store) *db.FeedSyncStatus {
	status, err := feed.GetFeedSyncStatusBounded(store, feedName)
	if err != nil {
		s.logger.Warn("failed to get EPSS feed sync status, proceeding with full sync",
			slog.String("error", feed.SafeDiagnosticError(err)),
		)
		return nil
	}
	return status
}

func epssMetadataFromStatus(status *db.FeedSyncStatus) epssMetadata {
	if status == nil {
		return epssMetadata{}
	}
	var metadata epssMetadata
	if len(status.Metadata) > 0 {
		_ = json.Unmarshal(status.Metadata, &metadata)
	}
	if etag := strings.TrimSpace(status.LastETag); etag != "" {
		metadata.ETag = etag
	}
	metadata.ETag = strings.TrimSpace(metadata.ETag)
	metadata.LastModified = strings.TrimSpace(metadata.LastModified)
	metadata.ModelVersion = strings.TrimSpace(metadata.ModelVersion)
	metadata.ScoreDate = strings.TrimSpace(metadata.ScoreDate)
	return metadata
}

func (m epssMetadata) mergeResponseValidators(resp *http.Response) epssMetadata {
	if resp == nil {
		return m
	}
	if etag := strings.TrimSpace(resp.Header.Get("ETag")); etag != "" {
		m.ETag = etag
	}
	if lastModified := strings.TrimSpace(resp.Header.Get("Last-Modified")); lastModified != "" {
		m.LastModified = lastModified
	}
	return m
}

func statusCounts(status *db.FeedSyncStatus) (synced, total int) {
	if status == nil {
		return 0, 0
	}
	return status.EntriesSynced, status.EntriesTotal
}

func (m *epssMetadata) merge(other epssMetadata) {
	if m.ETag == "" {
		m.ETag = other.ETag
	}
	if m.LastModified == "" {
		m.LastModified = other.LastModified
	}
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
