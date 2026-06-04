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
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
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

	// nvd2Endpoint requests a download link for the VulnCheck NVD2 backup.
	nvd2Endpoint = "/v3/backup/vulncheck-nvd2"

	// maxBodySize limits a single response to 200 MB (bulk data).
	maxBodySize = 200 << 20

	// batchSize controls how many entries are sent per EnrichVulnCheck call.
	batchSize = 1000
)

// backupLinkResponse is the top-level shape returned by /v3/backup/{index}.
type backupLinkResponse struct {
	Data []backupLink `json:"data"`
}

type backupLink struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	URL      string `json:"url"`
}

// backupResponse is the top-level shape stored inside VulnCheck backup files.
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

	totalUpdated, totalEntries, err := s.processBulk(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("vulncheck: download: %w", err)
	}

	s.logger.Info("VulnCheck sync completed",
		slog.Int("total_entries", totalEntries),
		slog.Int("updated", totalUpdated),
	)

	return &feed.SyncResult{
		EntriesSynced: totalUpdated,
		EntriesTotal:  totalEntries,
	}, nil
}

func (s *Syncer) processBulk(ctx context.Context, store db.Store) (updated, total int, err error) {
	downloadURL, err := s.fetchBackupURL(ctx)
	if err != nil {
		return 0, 0, err
	}
	entriesTotal, err := s.streamBackupFile(ctx, downloadURL, func(entries []db.VulnCheckEntry) error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled: %w", err)
		}
		total += len(entries)
		batchUpdated, err := store.EnrichVulnCheck(ctx, entries)
		if err != nil {
			return fmt.Errorf("enrich batch ending at %d: %w", total, err)
		}
		updated += batchUpdated
		return nil
	})
	return updated, entriesTotal, err
}

// downloadBulk fetches the VulnCheck NVD2 backup and converts each entry
// into a VulnCheckEntry for database enrichment.
func (s *Syncer) downloadBulk(ctx context.Context) ([]db.VulnCheckEntry, error) {
	downloadURL, err := s.fetchBackupURL(ctx)
	if err != nil {
		return nil, err
	}
	body, contentType, err := s.downloadBackupFile(ctx, downloadURL)
	if err != nil {
		return nil, err
	}

	cves, err := decodeBackupPayload(body, contentType, downloadURL)
	if err != nil {
		return nil, err
	}

	entries := make([]db.VulnCheckEntry, 0, len(cves))
	for _, cve := range cves {
		entry, ok := vulnCheckEntryFromBackupCVE(cve)
		if !ok {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func vulnCheckEntryFromBackupCVE(cve backupCVE) (db.VulnCheckEntry, bool) {
	cveID := cve.CVEID
	if cveID == "" {
		cveID = cve.ID
	}
	if cveID == "" || !strings.HasPrefix(cveID, "CVE-") {
		return db.VulnCheckEntry{}, false
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

	rawBytes, err := json.Marshal(cve)
	if err == nil {
		entry.RawJSON = rawBytes
	}
	return entry, true
}

func (s *Syncer) fetchBackupURL(ctx context.Context) (string, error) {
	endpoint := strings.TrimRight(s.baseURL, "/") + nvd2Endpoint

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("authentication failed (status %d): check PACKMON_VULNCHECK_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := readLimited(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	var links backupLinkResponse
	if err := json.Unmarshal(body, &links); err != nil {
		return "", fmt.Errorf("parse json: %w", err)
	}
	for _, item := range links.Data {
		if strings.TrimSpace(item.URL) != "" {
			return resolveBackupURL(s.baseURL, item.URL)
		}
	}
	return "", fmt.Errorf("backup response did not include a download URL")
}

func (s *Syncer) downloadBackupFile(ctx context.Context, downloadURL string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create backup request: %w", err)
	}
	req.Header.Set("Accept", "application/zip, application/json")
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("backup http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("backup unexpected status %d", resp.StatusCode)
	}
	body, err := readLimited(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read backup body: %w", err)
	}
	return body, resp.Header.Get("Content-Type"), nil
}

func (s *Syncer) streamBackupFile(ctx context.Context, downloadURL string, emit func([]db.VulnCheckEntry) error) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return 0, fmt.Errorf("create backup request: %w", err)
	}
	req.Header.Set("Accept", "application/zip, application/json")
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("backup http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("backup unexpected status %d", resp.StatusCode)
	}

	limited := newMaxBytesReader(resp.Body, maxBodySize)
	buffered := bufio.NewReader(limited)
	peek, _ := buffered.Peek(4)
	if isZipPayloadHeader(peek, resp.Header.Get("Content-Type"), downloadURL) {
		return streamBackupZip(buffered, emit)
	}
	return streamBackupJSON(buffered, emit)
}

func resolveBackupURL(baseURL, raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse backup URL: %w", err)
	}
	if parsed.IsAbs() {
		return parsed.String(), nil
	}
	base, err := url.Parse(strings.TrimRight(baseURL, "/") + "/")
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}
	return base.ResolveReference(parsed).String(), nil
}

func readLimited(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodySize {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBodySize)
	}
	return body, nil
}

func decodeBackupPayload(body []byte, contentType, sourceURL string) ([]backupCVE, error) {
	if isZipPayload(body, contentType, sourceURL) {
		return decodeBackupZip(body)
	}
	return decodeBackupJSON(body)
}

func isZipPayload(body []byte, contentType, sourceURL string) bool {
	if bytes.HasPrefix(body, []byte("PK\x03\x04")) {
		return true
	}
	if strings.Contains(strings.ToLower(contentType), "zip") {
		return true
	}
	parsed, err := url.Parse(sourceURL)
	return err == nil && strings.HasSuffix(strings.ToLower(parsed.Path), ".zip")
}

func isZipPayloadHeader(header []byte, contentType, sourceURL string) bool {
	if bytes.HasPrefix(header, []byte("PK\x03\x04")) {
		return true
	}
	if strings.Contains(strings.ToLower(contentType), "zip") {
		return true
	}
	parsed, err := url.Parse(sourceURL)
	return err == nil && strings.HasSuffix(strings.ToLower(parsed.Path), ".zip")
}

func streamBackupZip(r io.Reader, emit func([]db.VulnCheckEntry) error) (int, error) {
	tmp, err := os.CreateTemp("", "packmon-vulncheck-*.zip")
	if err != nil {
		return 0, fmt.Errorf("create temp zip: %w", err)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	written, err := io.Copy(tmp, r)
	if err != nil {
		return 0, fmt.Errorf("write temp zip: %w", err)
	}
	reader, err := zip.NewReader(tmp, written)
	if err != nil {
		return 0, fmt.Errorf("parse zip: %w", err)
	}

	var lastErr error
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(file.Name), ".json") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			lastErr = err
			continue
		}
		total, parseErr := streamBackupJSON(newMaxBytesReader(rc, maxBodySize), emit)
		closeErr := rc.Close()
		if parseErr == nil && closeErr == nil {
			return total, nil
		}
		if parseErr != nil {
			lastErr = parseErr
		} else {
			lastErr = closeErr
		}
	}
	if lastErr != nil {
		return 0, fmt.Errorf("parse zip JSON: %w", lastErr)
	}
	return 0, fmt.Errorf("parse zip: no JSON backup file found")
}

func streamBackupJSON(r io.Reader, emit func([]db.VulnCheckEntry) error) (int, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return 0, fmt.Errorf("parse json: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return 0, fmt.Errorf("parse json: expected object or array")
	}
	switch delim {
	case '[':
		return streamBackupCVEArray(dec, emit)
	case '{':
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return 0, fmt.Errorf("parse json key: %w", err)
			}
			key, ok := keyTok.(string)
			if !ok {
				return 0, fmt.Errorf("parse json: expected object key")
			}
			if key != "data" {
				var discard json.RawMessage
				if err := dec.Decode(&discard); err != nil {
					return 0, fmt.Errorf("parse json field %q: %w", key, err)
				}
				continue
			}
			dataTok, err := dec.Token()
			if err != nil {
				return 0, fmt.Errorf("parse json data: %w", err)
			}
			dataDelim, ok := dataTok.(json.Delim)
			if !ok || dataDelim != '[' {
				return 0, fmt.Errorf("parse json: data is not an array")
			}
			return streamBackupCVEArray(dec, emit)
		}
		return 0, fmt.Errorf("parse json: data array missing")
	default:
		return 0, fmt.Errorf("parse json: expected object or array")
	}
}

func streamBackupCVEArray(dec *json.Decoder, emit func([]db.VulnCheckEntry) error) (int, error) {
	batch := make([]db.VulnCheckEntry, 0, batchSize)
	total := 0
	for dec.More() {
		var cve backupCVE
		if err := dec.Decode(&cve); err != nil {
			return total, fmt.Errorf("parse cve: %w", err)
		}
		entry, ok := vulnCheckEntryFromBackupCVE(cve)
		if !ok {
			continue
		}
		batch = append(batch, entry)
		total++
		if len(batch) == batchSize {
			if err := emit(batch); err != nil {
				return total, err
			}
			batch = make([]db.VulnCheckEntry, 0, batchSize)
		}
	}
	if _, err := dec.Token(); err != nil {
		return total, fmt.Errorf("parse json array close: %w", err)
	}
	if len(batch) > 0 {
		if err := emit(batch); err != nil {
			return total, err
		}
	}
	return total, nil
}

type maxBytesReader struct {
	r         io.Reader
	remaining int64
	limit     int64
}

func newMaxBytesReader(r io.Reader, limit int64) *maxBytesReader {
	return &maxBytesReader{r: r, remaining: limit, limit: limit}
}

func (r *maxBytesReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		var probe [1]byte
		n, err := r.r.Read(probe[:])
		if n > 0 {
			return 0, fmt.Errorf("response exceeds %d bytes", r.limit)
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.r.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func decodeBackupZip(body []byte) ([]backupCVE, error) {
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("parse zip: %w", err)
	}

	var lastErr error
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(file.Name), ".json") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			lastErr = err
			continue
		}
		data, readErr := readLimited(rc)
		closeErr := rc.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if closeErr != nil {
			lastErr = closeErr
			continue
		}
		cves, err := decodeBackupJSON(data)
		if err == nil {
			return cves, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("parse zip JSON: %w", lastErr)
	}
	return nil, fmt.Errorf("parse zip: no JSON backup file found")
}

func decodeBackupJSON(body []byte) ([]backupCVE, error) {
	var bulk backupResponse
	if err := json.Unmarshal(body, &bulk); err == nil && bulk.Data != nil {
		return bulk.Data, nil
	}

	var cves []backupCVE
	if err := json.Unmarshal(body, &cves); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}
	return cves, nil
}
