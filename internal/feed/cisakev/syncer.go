// Package cisakev implements a feed syncer for the CISA Known Exploited
// Vulnerabilities (KEV) catalog. The catalog is a small JSON file (~300 KB)
// downloaded conditionally when upstream HTTP validators are available. For
// each CVE in the catalog the syncer sets the cisa_kev flag on the matching
// vulnerability row in the database.
package cisakev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

const (
	// feedName is the canonical name used in feed_sync_status.
	feedName = "cisakev"

	// DefaultCatalogURL is the official CISA KEV JSON endpoint.
	DefaultCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// maxBodySize limits the response body to 10 MB (catalog is ~300 KB).
	maxBodySize = 10 << 20
)

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// catalog is the top-level structure of the CISA KEV JSON file.
type catalog struct {
	Title           string             `json:"title"`
	CatalogVersion  string             `json:"catalogVersion"`
	DateReleased    string             `json:"dateReleased"`
	Count           int                `json:"count"`
	Vulnerabilities []catalogVulnEntry `json:"vulnerabilities"`
}

// catalogVulnEntry is one entry in the CISA KEV vulnerabilities array.
type catalogVulnEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

type catalogSyncMetadata struct {
	ETag           string `json:"etag,omitempty"`
	LastModified   string `json:"last_modified,omitempty"`
	CatalogVersion string `json:"catalog_version,omitempty"`
}

type catalogDownload struct {
	cveIDs      []string
	version     string
	metadata    catalogSyncMetadata
	notModified bool
}

// Syncer downloads the CISA KEV catalog and marks matching CVEs in the
// database. It implements feed.FeedSyncer.
type Syncer struct {
	logger     *slog.Logger
	httpClient *http.Client
	catalogURL string
}

// Option configures a Syncer.
type Option func(*Syncer)

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Syncer) { s.httpClient = c }
}

// WithCatalogURL overrides the default catalog URL (useful for testing).
func WithCatalogURL(url string) Option {
	return func(s *Syncer) { s.catalogURL = url }
}

// NewSyncer creates a CISA KEV syncer.
func NewSyncer(logger *slog.Logger, opts ...Option) *Syncer {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Syncer{
		logger: logger.With(slog.String("feed", feedName)),
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		catalogURL: DefaultCatalogURL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name implements feed.FeedSyncer.
func (s *Syncer) Name() string { return feedName }

// Sync implements feed.FeedSyncer. It downloads the CISA KEV catalog and
// updates the database. When upstream returns HTTP 304 Not Modified, the sync
// is treated as a successful unchanged sync and existing KEV flags are left
// untouched. Modified catalogs are applied as complete snapshots.
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	s.logger.Info("starting CISA KEV sync")

	status := s.loadFeedStatus(store)
	storedMetadata := catalogMetadataFromStatus(status)
	download, err := s.downloadCatalogWithValidators(ctx, storedMetadata)
	if err != nil {
		return nil, fmt.Errorf("cisakev: download catalog: %w", err)
	}
	if download.notModified {
		synced, total := statusCounts(status)
		s.logger.Info("CISA KEV catalog unchanged",
			slog.Int("entries_synced", synced),
			slog.Int("entries_total", total),
		)
		return &feed.SyncResult{
			EntriesSynced: synced,
			EntriesTotal:  total,
			Metadata:      metadataJSON(download.metadata),
		}, nil
	}

	cveIDs := download.cveIDs

	s.logger.Info("downloaded CISA KEV catalog",
		slog.Int("cve_count", len(cveIDs)),
		slog.String("catalog_version", download.version),
	)

	var updated, cleared int
	updated, cleared, err = store.ReplaceCISAKEV(ctx, cveIDs)
	if err != nil {
		return nil, fmt.Errorf("cisakev: replace flags: %w", err)
	}

	s.logger.Info("CISA KEV sync completed",
		slog.Int("updated", updated),
		slog.Int("cleared", cleared),
		slog.Int("total_cves", len(cveIDs)),
	)

	return &feed.SyncResult{
		EntriesSynced: updated,
		EntriesTotal:  len(cveIDs),
		Metadata:      metadataJSON(download.metadata),
	}, nil
}

// downloadCatalog fetches the CISA KEV JSON and extracts all CVE IDs.
func (s *Syncer) downloadCatalog(ctx context.Context) (cveIDs []string, version string, err error) {
	download, err := s.downloadCatalogWithValidators(ctx, catalogSyncMetadata{})
	if err != nil {
		return nil, "", err
	}
	return download.cveIDs, download.version, nil
}

func (s *Syncer) downloadCatalogWithValidators(ctx context.Context, validators catalogSyncMetadata) (catalogDownload, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.catalogURL, nil)
	if err != nil {
		return catalogDownload{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", feed.FeedSyncUserAgent)
	if validators.ETag != "" {
		req.Header.Set("If-None-Match", validators.ETag)
	}
	if validators.LastModified != "" {
		req.Header.Set("If-Modified-Since", validators.LastModified)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return catalogDownload{}, fmt.Errorf("http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	metadata := validators.mergeResponseValidators(resp)
	if resp.StatusCode == http.StatusNotModified {
		return catalogDownload{
			metadata:    metadata,
			notModified: true,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return catalogDownload{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	metadata = catalogSyncMetadata{}.mergeResponseValidators(resp)

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return catalogDownload{}, fmt.Errorf("read body: %w", err)
	}
	if len(body) > maxBodySize {
		return catalogDownload{}, fmt.Errorf("response body exceeds %d byte limit", maxBodySize)
	}

	var cat catalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return catalogDownload{}, feed.NonRetryableError(fmt.Errorf("parse json: %w", err))
	}

	ids, err := validateCatalog(cat)
	if err != nil {
		return catalogDownload{}, feed.NonRetryableError(err)
	}

	metadata.CatalogVersion = strings.TrimSpace(cat.CatalogVersion)
	return catalogDownload{
		cveIDs:   ids,
		version:  cat.CatalogVersion,
		metadata: metadata,
	}, nil
}

func (s *Syncer) loadFeedStatus(store db.Store) *db.FeedSyncStatus {
	status, err := feed.GetFeedSyncStatusBounded(store, feedName)
	if err != nil {
		s.logger.Warn("failed to get CISA KEV feed sync status, proceeding with full sync",
			slog.String("error", feed.SafeDiagnosticError(err)),
		)
		return nil
	}
	return status
}

func catalogMetadataFromStatus(status *db.FeedSyncStatus) catalogSyncMetadata {
	if status == nil {
		return catalogSyncMetadata{}
	}
	var metadata catalogSyncMetadata
	if len(status.Metadata) > 0 {
		_ = json.Unmarshal(status.Metadata, &metadata)
	}
	if etag := strings.TrimSpace(status.LastETag); etag != "" {
		metadata.ETag = etag
	}
	metadata.ETag = strings.TrimSpace(metadata.ETag)
	metadata.LastModified = strings.TrimSpace(metadata.LastModified)
	metadata.CatalogVersion = strings.TrimSpace(metadata.CatalogVersion)
	return metadata
}

func (m catalogSyncMetadata) mergeResponseValidators(resp *http.Response) catalogSyncMetadata {
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

func metadataJSON(metadata catalogSyncMetadata) json.RawMessage {
	if metadata.ETag == "" && metadata.LastModified == "" && metadata.CatalogVersion == "" {
		return nil
	}
	raw, _ := json.Marshal(metadata)
	return raw
}

func validateCatalog(cat catalog) ([]string, error) {
	if strings.TrimSpace(cat.CatalogVersion) == "" {
		return nil, fmt.Errorf("invalid catalog: missing catalogVersion")
	}
	if cat.Count <= 0 {
		return nil, fmt.Errorf("invalid catalog: count must be greater than zero")
	}
	if len(cat.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("invalid catalog: vulnerabilities must not be empty")
	}
	if cat.Count != len(cat.Vulnerabilities) {
		return nil, fmt.Errorf("invalid catalog: count %d does not match vulnerabilities length %d", cat.Count, len(cat.Vulnerabilities))
	}

	ids := make([]string, 0, len(cat.Vulnerabilities))
	for i, v := range cat.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if !cveIDPattern.MatchString(id) {
			return nil, fmt.Errorf("invalid catalog: vulnerabilities[%d].cveID is invalid", i)
		}
		ids = append(ids, id)
	}
	return ids, nil
}
