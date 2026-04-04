// Package cisakev implements a feed syncer for the CISA Known Exploited
// Vulnerabilities (KEV) catalog. The catalog is a small JSON file (~300 KB)
// downloaded in full on every sync. For each CVE in the catalog the syncer
// sets the cisa_kev flag on the matching vulnerability row in the database.
package cisakev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
)

const (
	// feedName is the canonical name used in feed_sync_status.
	feedName = "cisakev"

	// DefaultCatalogURL is the official CISA KEV JSON endpoint.
	DefaultCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// maxBodySize limits the response body to 10 MB (catalog is ~300 KB).
	maxBodySize = 10 << 20
)

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
// updates the database. Because the catalog is small, this always performs
// a full sync: it sets cisa_kev for all CVEs in the catalog and clears it
// for any CVE no longer listed.
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	s.logger.Info("starting CISA KEV sync")

	cveIDs, catalogVersion, err := s.downloadCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("cisakev: download catalog: %w", err)
	}

	s.logger.Info("downloaded CISA KEV catalog",
		slog.Int("cve_count", len(cveIDs)),
		slog.String("catalog_version", catalogVersion),
	)

	// Set cisa_kev = true for all CVEs in the catalog.
	updated, err := store.SetCISAKEV(ctx, cveIDs)
	if err != nil {
		return nil, fmt.Errorf("cisakev: set flags: %w", err)
	}

	// Clear cisa_kev for CVEs no longer in the catalog.
	cleared, err := store.ClearCISAKEV(ctx, cveIDs)
	if err != nil {
		return nil, fmt.Errorf("cisakev: clear stale flags: %w", err)
	}

	s.logger.Info("CISA KEV sync completed",
		slog.Int("updated", updated),
		slog.Int("cleared", cleared),
		slog.Int("total_cves", len(cveIDs)),
	)

	return &feed.SyncResult{
		EntriesSynced: updated,
		EntriesTotal:  len(cveIDs),
	}, nil
}

// downloadCatalog fetches the CISA KEV JSON and extracts all CVE IDs.
func (s *Syncer) downloadCatalog(ctx context.Context) (cveIDs []string, version string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.catalogURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, "", fmt.Errorf("read body: %w", err)
	}

	var cat catalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, "", fmt.Errorf("parse json: %w", err)
	}

	ids := make([]string, 0, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		if v.CVEID != "" {
			ids = append(ids, v.CVEID)
		}
	}

	return ids, cat.CatalogVersion, nil
}
