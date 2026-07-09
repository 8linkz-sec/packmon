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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/logsafe"
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

	// maxVulnCheckRawJSONBytes limits raw per-CVE provenance persisted in DB.
	maxVulnCheckRawJSONBytes = 1 << 20

	// maxVulnCheckSourceURLBytes bounds user-facing VulnCheck attribution URLs.
	maxVulnCheckSourceURLBytes = 4096

	// maxVulnCheckExploitRefs bounds exploit-reference arrays in one CVE record.
	maxVulnCheckExploitRefs = 256

	// maxVulnCheckExploitURLBytes bounds exploit reference URL fields.
	maxVulnCheckExploitURLBytes = 4096

	// maxVulnCheckExploitTextBytes bounds exploit reference text fields.
	maxVulnCheckExploitTextBytes = 1024

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

type backupSelection struct {
	URL    string
	SHA256 string
}

type backupStreamStats struct {
	entriesTotal    int
	rejectedRecords int
	rejectionReason string
}

func (s *backupStreamStats) add(other backupStreamStats) {
	s.entriesTotal += other.entriesTotal
	s.rejectedRecords += other.rejectedRecords
	if s.rejectionReason == "" {
		s.rejectionReason = other.rejectionReason
	}
}

func (s *backupStreamStats) reject(reason string) {
	s.rejectedRecords++
	if s.rejectionReason == "" {
		s.rejectionReason = reason
	}
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

	start := time.Now()
	s.logger.Info("starting VulnCheck sync")

	totalUpdated, totalEntries, metadata, backupDigest, err := s.processBulk(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("vulncheck: download: %w", err)
	}
	s.recordSyncSuccessWithDigest(ctx, store, time.Since(start), totalEntries, totalUpdated, backupDigest, metadata)

	s.logger.Info("VulnCheck sync completed",
		slog.Int("total_entries", totalEntries),
		slog.Int("updated", totalUpdated),
	)

	return &feed.SyncResult{
		EntriesSynced: totalUpdated,
		EntriesTotal:  totalEntries,
		Metadata:      metadata,
	}, nil
}

func (s *Syncer) processBulk(ctx context.Context, store db.Store) (updated, total int, metadata json.RawMessage, backupDigest string, err error) {
	backup, err := s.fetchBackupSelection(ctx)
	if err != nil {
		return 0, 0, nil, "", err
	}
	status := s.loadFeedStatus(ctx, store)
	if statusHasProcessedBackupDigest(status, backup.SHA256) {
		s.logger.Info("VulnCheck backup digest unchanged, skipping download",
			slog.String("sha256", backup.SHA256),
		)
		if len(status.Metadata) > 0 {
			metadata = append(json.RawMessage(nil), status.Metadata...)
		}
		return 0, status.EntriesTotal, metadata, backup.SHA256, nil
	}
	stats, err := s.streamVerifiedBackupFileWithStats(ctx, backup, func(entries []db.VulnCheckEntry) error {
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
	if stats.rejectedRecords > 0 {
		s.logger.Warn("VulnCheck backup records rejected",
			slog.Int("rejected_records", stats.rejectedRecords),
			slog.String("reason", stats.rejectionReason),
		)
		metadata, _ = json.Marshal(feed.StatusMetadata{
			RejectedCount:   stats.rejectedRecords,
			RejectionReason: stats.rejectionReason,
		})
	}
	return updated, stats.entriesTotal, metadata, backup.SHA256, err
}

func (s *Syncer) loadFeedStatus(ctx context.Context, store db.Store) *db.FeedSyncStatus {
	status, err := store.GetFeedSyncStatus(ctx, feedName)
	if err != nil {
		s.logger.Warn("failed to load VulnCheck feed status, proceeding with download",
			slog.String("error", feed.SafeDiagnosticError(err)),
		)
		return nil
	}
	return status
}

func statusHasProcessedBackupDigest(status *db.FeedSyncStatus, digest string) bool {
	if status == nil || status.LastSyncAt == nil {
		return false
	}
	storedDigest, err := normalizeBackupSHA256(status.LastETag)
	if err != nil {
		return false
	}
	return storedDigest == digest
}

func (s *Syncer) recordSyncSuccessWithDigest(ctx context.Context, store db.Store, duration time.Duration, total, updated int, digest string, metadata json.RawMessage) {
	now := time.Now().UTC()
	status := &db.FeedSyncStatus{
		FeedName:         feedName,
		LastSyncAt:       &now,
		LastSyncDuration: &duration,
		LastSyncStatus:   db.FeedSyncStatusSuccess,
		EntriesSynced:    updated,
		EntriesTotal:     total,
		LastETag:         digest,
	}
	if len(metadata) > 0 {
		status.Metadata = append(json.RawMessage(nil), metadata...)
	}
	if err := feed.UpsertFeedSyncStatusBounded(store, status); err != nil {
		s.logger.Warn("failed to record VulnCheck sync status",
			slog.String("error", feed.SafeDiagnosticError(err)),
		)
	}
	_ = ctx
}

func vulnCheckEntryFromBackupCVE(cve backupCVE) (db.VulnCheckEntry, bool) {
	entry, ok, _ := vulnCheckEntryFromBackupCVEWithRaw(cve, nil)
	return entry, ok
}

func vulnCheckEntryFromBackupRaw(raw json.RawMessage) (db.VulnCheckEntry, bool, string) {
	if len(raw) > maxVulnCheckRawJSONBytes {
		return db.VulnCheckEntry{}, false, "raw_json_too_large"
	}
	var cve backupCVE
	if err := json.Unmarshal(raw, &cve); err != nil {
		return db.VulnCheckEntry{}, false, "malformed_json"
	}
	return vulnCheckEntryFromBackupCVEWithRaw(cve, raw)
}

func vulnCheckEntryFromBackupCVEWithRaw(cve backupCVE, raw json.RawMessage) (db.VulnCheckEntry, bool, string) {
	cveID := cve.CVEID
	if cveID == "" {
		cveID = cve.ID
	}
	if cveID == "" || !strings.HasPrefix(cveID, "CVE-") {
		return db.VulnCheckEntry{}, false, "invalid_cve_id"
	}
	if len(cve.URL) > maxVulnCheckSourceURLBytes {
		return db.VulnCheckEntry{}, false, "source_url_too_large"
	}
	if len(cve.Exploits) > maxVulnCheckExploitRefs {
		return db.VulnCheckEntry{}, false, "too_many_exploit_references"
	}
	for _, ref := range cve.Exploits {
		if len(ref.URL) > maxVulnCheckExploitURLBytes ||
			len(ref.Name) > maxVulnCheckExploitTextBytes ||
			len(ref.Source) > maxVulnCheckExploitTextBytes {
			return db.VulnCheckEntry{}, false, "exploit_reference_too_large"
		}
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

	if len(raw) > 0 {
		entry.RawJSON = append(json.RawMessage(nil), raw...)
	} else if rawBytes, err := json.Marshal(cve); err == nil && len(rawBytes) <= maxVulnCheckRawJSONBytes {
		entry.RawJSON = rawBytes
	}
	return entry, true, ""
}

func (s *Syncer) fetchBackupSelection(ctx context.Context) (backupSelection, error) {
	endpoint := strings.TrimRight(s.baseURL, "/") + nvd2Endpoint

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return backupSelection{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", feed.FeedSyncUserAgent)

	resp, err := s.doBackupRequest(req)
	if err != nil {
		return backupSelection{}, fmt.Errorf("http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return backupSelection{}, feed.PermanentError(fmt.Errorf("authentication failed (status %d): check PACKMON_VULNCHECK_API_KEY", resp.StatusCode))
	}
	if resp.StatusCode != http.StatusOK {
		return backupSelection{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := readLimited(resp.Body)
	if err != nil {
		return backupSelection{}, fmt.Errorf("read body: %w", err)
	}

	var links backupLinkResponse
	if err := json.Unmarshal(body, &links); err != nil {
		return backupSelection{}, fmt.Errorf("parse json: %w", err)
	}
	for _, item := range links.Data {
		if strings.TrimSpace(item.URL) != "" {
			resolved, err := resolveBackupURL(s.baseURL, item.URL)
			if err != nil {
				return backupSelection{}, err
			}
			digest, err := normalizeBackupSHA256(item.SHA256)
			if err != nil {
				return backupSelection{}, err
			}
			return backupSelection{URL: resolved, SHA256: digest}, nil
		}
	}
	return backupSelection{}, fmt.Errorf("backup response did not include a download URL")
}

func (s *Syncer) streamVerifiedBackupFile(ctx context.Context, backup backupSelection, emit func([]db.VulnCheckEntry) error) (int, error) {
	stats, err := s.streamVerifiedBackupFileWithStats(ctx, backup, emit)
	return stats.entriesTotal, err
}

func (s *Syncer) streamVerifiedBackupFileWithStats(ctx context.Context, backup backupSelection, emit func([]db.VulnCheckEntry) error) (backupStreamStats, error) {
	path, contentType, digest, err := s.downloadBackupToTemp(ctx, backup.URL)
	if err != nil {
		return backupStreamStats{}, err
	}
	defer func() { _ = os.Remove(path) }()
	if err := verifyBackupSHA256Digest(backup.SHA256, digest); err != nil {
		return backupStreamStats{}, err
	}
	file, err := os.Open(path) // #nosec G304 -- path was created by downloadBackupToTemp via os.CreateTemp and verified by digest before opening.
	if err != nil {
		return backupStreamStats{}, fmt.Errorf("open verified backup: %w", err)
	}
	defer func() { _ = file.Close() }()
	return streamBackupPayloadWithStats(file, contentType, backup.URL, emit)
}

func (s *Syncer) downloadBackupToTemp(ctx context.Context, downloadURL string) (path, contentType, digest string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("create backup request: %s", logsafe.RedactDiagnosticMessage(err.Error()))
	}
	req.Header.Set("Accept", "application/zip, application/json")
	req.Header.Set("User-Agent", feed.FeedSyncUserAgent)

	resp, err := s.doBackupRequest(req)
	if err != nil {
		return "", "", "", fmt.Errorf("backup http get: %s", logsafe.RedactDiagnosticMessage(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("backup unexpected status %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "packmon-vulncheck-backup-*.bin")
	if err != nil {
		return "", "", "", fmt.Errorf("create temp backup: %w", err)
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	hasher := sha256.New()
	if _, err := copyAndHash(tmp, newMaxBytesReader(resp.Body, maxBodySize), hasher); err != nil {
		return "", "", "", fmt.Errorf("write temp backup: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", "", "", fmt.Errorf("close temp backup: %w", err)
	}
	removeTemp = false
	return tmp.Name(), resp.Header.Get("Content-Type"), hex.EncodeToString(hasher.Sum(nil)), nil
}

func streamBackupPayload(r io.Reader, contentType, sourceURL string, emit func([]db.VulnCheckEntry) error) (int, error) {
	stats, err := streamBackupPayloadWithStats(r, contentType, sourceURL, emit)
	return stats.entriesTotal, err
}

func streamBackupPayloadWithStats(r io.Reader, contentType, sourceURL string, emit func([]db.VulnCheckEntry) error) (backupStreamStats, error) {
	buffered := bufio.NewReader(r)
	peek, _ := buffered.Peek(4)
	if isZipPayloadHeader(peek, contentType, sourceURL) {
		return streamBackupZipWithStats(buffered, emit)
	}
	return streamBackupJSONWithStats(buffered, emit)
}

func normalizeBackupSHA256(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", fmt.Errorf("backup response missing sha256")
	}
	if len(value) != sha256.Size*2 {
		return "", fmt.Errorf("backup response sha256 has invalid length")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("backup response sha256 is invalid: %w", err)
	}
	return value, nil
}

func verifyBackupSHA256Digest(expected, actual string) error {
	expected = strings.ToLower(strings.TrimSpace(expected))
	actual = strings.ToLower(strings.TrimSpace(actual))
	if expected == "" {
		return fmt.Errorf("backup response missing sha256")
	}
	if expected != actual {
		return fmt.Errorf("backup sha256 mismatch")
	}
	return nil
}

func copyAndHash(dst io.Writer, src io.Reader, h hash.Hash) (int64, error) {
	return io.Copy(io.MultiWriter(dst, h), src)
}

func resolveBackupURL(baseURL, raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse backup URL: %w", err)
	}
	base, err := url.Parse(strings.TrimRight(baseURL, "/") + "/")
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}
	resolved := parsed
	if !parsed.IsAbs() {
		resolved = base.ResolveReference(parsed)
	}
	if err := validateBackupURL(base, resolved); err != nil {
		return "", err
	}
	return resolved.String(), nil
}

func validateBackupURL(base, candidate *url.URL) error {
	scheme := strings.ToLower(strings.TrimSpace(candidate.Scheme))
	baseScheme := strings.ToLower(strings.TrimSpace(base.Scheme))
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("backup URL scheme %q is not supported", candidate.Scheme)
	}
	if baseScheme != "http" && baseScheme != "https" {
		return fmt.Errorf("base URL scheme %q is not supported", base.Scheme)
	}
	if scheme != baseScheme {
		return fmt.Errorf("backup URL scheme %q does not match base scheme %q", candidate.Scheme, base.Scheme)
	}
	if candidate.User != nil {
		return fmt.Errorf("backup URL must not include credentials")
	}
	if strings.TrimSpace(candidate.Hostname()) == "" {
		return fmt.Errorf("backup URL host is required")
	}
	if sameBackupOrigin(base, candidate) {
		return nil
	}
	if err := validateCrossOriginBackupHost(candidate.Hostname()); err != nil {
		return err
	}
	if port := candidate.Port(); port != "" && port != defaultPortForScheme(scheme) {
		return fmt.Errorf("cross-origin backup URL must not use non-default port %q", port)
	}
	return nil
}

func (s *Syncer) doBackupRequest(req *http.Request) (*http.Response, error) {
	client := *s.httpClient
	originalURL := req.URL
	existingRedirectPolicy := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if existingRedirectPolicy != nil {
			if err := existingRedirectPolicy(next, via); err != nil {
				return err
			}
		} else if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		if next == nil || next.URL == nil {
			return fmt.Errorf("backup redirect target is missing")
		}
		if err := validateBackupURL(originalURL, next.URL); err != nil {
			return fmt.Errorf("refusing backup redirect: %w", err)
		}
		return nil
	}
	return client.Do(req)
}

func sameBackupOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(strings.TrimSuffix(a.Hostname(), "."), strings.TrimSuffix(b.Hostname(), ".")) &&
		normalizedURLPort(a) == normalizedURLPort(b)
}

func normalizedURLPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	return defaultPortForScheme(strings.ToLower(u.Scheme))
}

func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func validateCrossOriginBackupHost(rawHost string) error {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	if host == "" {
		return fmt.Errorf("backup URL host is required")
	}
	if strings.Contains(host, "%") {
		return fmt.Errorf("cross-origin backup URL host must not include zone identifiers")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if addr.IsUnspecified() ||
			addr.IsLoopback() ||
			addr.IsPrivate() ||
			addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() ||
			addr.IsInterfaceLocalMulticast() ||
			addr.IsMulticast() {
			return fmt.Errorf("cross-origin backup URL host %q is not public", rawHost)
		}
		return fmt.Errorf("cross-origin backup URL host %q is not an allowed VulnCheck backup host", rawHost)
	}
	if host == "localhost" ||
		strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") ||
		!strings.Contains(host, ".") {
		return fmt.Errorf("cross-origin backup URL host %q is not public", rawHost)
	}
	if !isAllowedCrossOriginBackupHost(host) {
		return fmt.Errorf("cross-origin backup URL host %q is not an allowed VulnCheck backup host", rawHost)
	}
	return nil
}

func isAllowedCrossOriginBackupHost(host string) bool {
	return host == "amazonaws.com" ||
		strings.HasSuffix(host, ".amazonaws.com") ||
		host == "amazonaws.com.cn" ||
		strings.HasSuffix(host, ".amazonaws.com.cn")
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
	stats, err := streamBackupZipWithStats(r, emit)
	return stats.entriesTotal, err
}

type tempZipWriteFile interface {
	io.Writer
	io.Closer
	Name() string
}

type tempZipReadFile interface {
	io.ReaderAt
	io.Closer
}

type tempZipFileHooks struct {
	create   func() (tempZipWriteFile, error)
	openRead func(string) (tempZipReadFile, error)
	remove   func(string) error
}

func defaultTempZipFileHooks() tempZipFileHooks {
	return tempZipFileHooks{
		create: func() (tempZipWriteFile, error) {
			return os.CreateTemp("", "packmon-vulncheck-*.zip")
		},
		openRead: func(path string) (tempZipReadFile, error) {
			return os.Open(path) // #nosec G304 -- path was created by os.CreateTemp in this package and is removed after parsing.
		},
		remove: os.Remove,
	}
}

func streamBackupZipWithStats(r io.Reader, emit func([]db.VulnCheckEntry) error) (backupStreamStats, error) {
	return streamBackupZipWithStatsWithTempFiles(r, emit, defaultTempZipFileHooks())
}

func streamBackupZipWithStatsWithTempFiles(r io.Reader, emit func([]db.VulnCheckEntry) error, hooks tempZipFileHooks) (backupStreamStats, error) {
	tmp, err := hooks.create()
	if err != nil {
		return backupStreamStats{}, fmt.Errorf("create temp zip: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = hooks.remove(tmpName) }()

	written, err := io.Copy(tmp, r)
	closeErr := tmp.Close()
	if err != nil {
		if closeErr != nil {
			return backupStreamStats{}, errors.Join(
				fmt.Errorf("write temp zip: %w", err),
				fmt.Errorf("close temp zip: %w", closeErr),
			)
		}
		return backupStreamStats{}, fmt.Errorf("write temp zip: %w", err)
	}
	if closeErr != nil {
		return backupStreamStats{}, fmt.Errorf("close temp zip: %w", closeErr)
	}

	tmpReader, err := hooks.openRead(tmpName)
	if err != nil {
		return backupStreamStats{}, fmt.Errorf("open temp zip: %w", err)
	}
	defer func() { _ = tmpReader.Close() }()

	reader, err := zip.NewReader(tmpReader, written)
	if err != nil {
		return backupStreamStats{}, fmt.Errorf("parse zip: %w", err)
	}

	var lastErr error
	var lastStats backupStreamStats
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(file.Name), ".json") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			lastErr = err
			continue
		}
		stats, parseErr := streamBackupJSONWithStats(newMaxBytesReader(rc, maxBodySize), emit)
		closeErr := rc.Close()
		if parseErr == nil && closeErr == nil {
			return stats, nil
		}
		lastStats = stats
		if parseErr != nil {
			lastErr = parseErr
		} else {
			lastErr = closeErr
		}
	}
	if lastErr != nil {
		return lastStats, fmt.Errorf("parse zip JSON: %w", lastErr)
	}
	return backupStreamStats{}, fmt.Errorf("parse zip: no JSON backup file found")
}

func streamBackupJSON(r io.Reader, emit func([]db.VulnCheckEntry) error) (int, error) {
	stats, err := streamBackupJSONWithStats(r, emit)
	return stats.entriesTotal, err
}

func streamBackupJSONWithStats(r io.Reader, emit func([]db.VulnCheckEntry) error) (backupStreamStats, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return backupStreamStats{}, fmt.Errorf("parse json: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return backupStreamStats{}, fmt.Errorf("parse json: expected object or array")
	}
	switch delim {
	case '[':
		return streamBackupJSONArrayWithStats(dec, emit)
	case '{':
		return streamBackupJSONObjectWithStats(dec, emit)
	default:
		return backupStreamStats{}, fmt.Errorf("parse json: expected object or array")
	}
}

func streamBackupJSONArray(dec *json.Decoder, emit func([]db.VulnCheckEntry) error) (int, error) {
	stats, err := streamBackupJSONArrayWithStats(dec, emit)
	return stats.entriesTotal, err
}

func streamBackupJSONArrayWithStats(dec *json.Decoder, emit func([]db.VulnCheckEntry) error) (backupStreamStats, error) {
	stats, err := streamBackupCVEArrayWithStats(dec, emit)
	if err != nil {
		return stats, err
	}
	if err := requireJSONEOF(dec); err != nil {
		return stats, err
	}
	return stats, nil
}

func streamBackupJSONObject(dec *json.Decoder, emit func([]db.VulnCheckEntry) error) (int, error) {
	stats, err := streamBackupJSONObjectWithStats(dec, emit)
	return stats.entriesTotal, err
}

func streamBackupJSONObjectWithStats(dec *json.Decoder, emit func([]db.VulnCheckEntry) error) (backupStreamStats, error) {
	var stats backupStreamStats
	foundData := false
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return stats, fmt.Errorf("parse json key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return stats, fmt.Errorf("parse json: expected object key")
		}
		if key != "data" {
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return stats, fmt.Errorf("parse json field %q: %w", key, err)
			}
			continue
		}
		dataTok, err := dec.Token()
		if err != nil {
			return stats, fmt.Errorf("parse json data: %w", err)
		}
		dataDelim, ok := dataTok.(json.Delim)
		if !ok || dataDelim != '[' {
			return stats, fmt.Errorf("parse json: data is not an array")
		}
		foundData = true
		parsed, err := streamBackupCVEArrayWithStats(dec, emit)
		stats.add(parsed)
		if err != nil {
			return stats, err
		}
	}
	if !foundData {
		return stats, fmt.Errorf("parse json: data array missing")
	}
	if _, err := dec.Token(); err != nil {
		return stats, fmt.Errorf("parse json object close: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return stats, err
	}
	return stats, nil
}

func requireJSONEOF(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse json trailing data: %w", err)
	}
	return fmt.Errorf("parse json trailing token %v", tok)
}

func streamBackupCVEArray(dec *json.Decoder, emit func([]db.VulnCheckEntry) error) (int, error) {
	stats, err := streamBackupCVEArrayWithStats(dec, emit)
	return stats.entriesTotal, err
}

func streamBackupCVEArrayWithStats(dec *json.Decoder, emit func([]db.VulnCheckEntry) error) (backupStreamStats, error) {
	batch := make([]db.VulnCheckEntry, 0, batchSize)
	var stats backupStreamStats
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return stats, fmt.Errorf("parse cve: %w", err)
		}
		entry, ok, reason := vulnCheckEntryFromBackupRaw(raw)
		if !ok {
			if reason != "invalid_cve_id" {
				stats.reject(reason)
			}
			continue
		}
		batch = append(batch, entry)
		stats.entriesTotal++
		if len(batch) == batchSize {
			if err := emit(batch); err != nil {
				return stats, err
			}
			batch = make([]db.VulnCheckEntry, 0, batchSize)
		}
	}
	if _, err := dec.Token(); err != nil {
		return stats, fmt.Errorf("parse json array close: %w", err)
	}
	if len(batch) > 0 {
		if err := emit(batch); err != nil {
			return stats, err
		}
	}
	return stats, nil
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
