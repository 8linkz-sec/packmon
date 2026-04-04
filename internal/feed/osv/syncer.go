// Package osv implements the FeedSyncer for the OSV.dev vulnerability
// database. It downloads per-ecosystem ZIP archives from the public GCS
// bucket at https://osv-vulnerabilities.storage.googleapis.com/ and
// upserts each vulnerability into the Packmon database.
package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	// FeedName is the canonical name used in feed_sync_status.
	FeedName = "osv"

	// bucketBaseURL is the base URL for the OSV GCS bucket. Each
	// ecosystem has a directory with an all.zip file.
	bucketBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

	// httpTimeout is the per-request timeout for downloading a single
	// ecosystem ZIP file. These can be large (10-50 MB), so we allow
	// generous time.
	httpTimeout = 10 * time.Minute

	// maxZIPSize is a safety limit for the decompressed ZIP payload.
	// This prevents runaway memory usage if a ZIP is unexpectedly huge.
	maxZIPSize = 500 * 1024 * 1024 // 500 MB
)

// Compile-time interface assertion.
var _ feed.FeedSyncer = (*Syncer)(nil)

type errArchiveUnavailable struct {
	url        string
	statusCode int
}

func (e *errArchiveUnavailable) Error() string {
	return fmt.Sprintf("archive unavailable: HTTP %d from %s", e.statusCode, e.url)
}

// Syncer downloads OSV vulnerability data from the public GCS bucket
// and upserts it into the Packmon database. It implements the
// FeedSyncer interface defined in feed.go.
type Syncer struct {
	store  db.Store
	logger *slog.Logger
	client *http.Client
}

// Option configures a Syncer.
type Option func(*Syncer)

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Syncer) { s.client = c }
}

// NewSyncer creates an OSV Syncer. If logger is nil, slog.Default() is
// used.
func NewSyncer(store db.Store, logger *slog.Logger, opts ...Option) *Syncer {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Syncer{
		store:  store,
		logger: logger.With(slog.String("feed", FeedName)),
		client: &http.Client{Timeout: httpTimeout},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name implements feed.FeedSyncer.
func (s *Syncer) Name() string { return FeedName }

// Sync implements feed.FeedSyncer. It iterates over all supported
// ecosystems, downloads the all.zip archive for each, parses every
// JSON vulnerability entry, maps it to the Packmon data model, and
// upserts it into the store.
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	start := time.Now()
	s.logger.Info("starting OSV sync")

	ecosystems := feed.OSVBucketEcosystems()
	var totalSynced, totalEntries int

	for _, eco := range ecosystems {
		if ctx.Err() != nil {
			s.recordSyncFailure(ctx, start, ctx.Err())
			return nil, ctx.Err()
		}

		synced, entries, err := s.syncEcosystem(ctx, store, eco)
		if err != nil {
			var unavailable *errArchiveUnavailable
			if errors.As(err, &unavailable) {
				s.logger.Info("ecosystem archive unavailable, skipping",
					slog.String("ecosystem", eco),
					slog.Int("status", unavailable.statusCode),
				)
				continue
			}
			s.logger.Error("ecosystem sync failed, continuing with next",
				slog.String("ecosystem", eco),
				slog.String("error", err.Error()),
			)
			// Continue with other ecosystems rather than aborting.
			continue
		}
		totalSynced += synced
		totalEntries += entries

		s.logger.Info("ecosystem sync completed",
			slog.String("ecosystem", eco),
			slog.Int("synced", synced),
			slog.Int("entries", entries),
		)
	}

	duration := time.Since(start)
	s.logger.Info("OSV sync completed",
		slog.Int("total_synced", totalSynced),
		slog.Int("total_entries", totalEntries),
		slog.String("duration", duration.String()),
	)

	s.recordSyncSuccess(ctx, start, duration, totalEntries, totalSynced)
	return &feed.SyncResult{
		EntriesSynced: totalSynced,
		EntriesTotal:  totalEntries,
	}, nil
}

// syncEcosystem downloads and processes a single ecosystem's all.zip.
func (s *Syncer) syncEcosystem(ctx context.Context, store db.Store, ecosystem string) (synced, total int, err error) {
	url := fmt.Sprintf("%s/%s/all.zip", bucketBaseURL, ecosystem)
	s.logger.Debug("downloading ecosystem archive", slog.String("url", url))

	body, err := s.download(ctx, url)
	if err != nil {
		return 0, 0, fmt.Errorf("download %s: %w", url, err)
	}

	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return 0, 0, fmt.Errorf("open zip for %s: %w", ecosystem, err)
	}

	for _, f := range reader.File {
		if ctx.Err() != nil {
			return synced, total, ctx.Err()
		}

		// Only process .json files.
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		total++

		rc, err := f.Open()
		if err != nil {
			s.logger.Warn("failed to open zip entry",
				slog.String("file", f.Name),
				slog.String("error", err.Error()),
			)
			continue
		}

		data, err := io.ReadAll(io.LimitReader(rc, maxZIPSize))
		_ = rc.Close()
		if err != nil {
			s.logger.Warn("failed to read zip entry",
				slog.String("file", f.Name),
				slog.String("error", err.Error()),
			)
			continue
		}

		var entry osvEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			s.logger.Warn("failed to parse OSV entry",
				slog.String("file", f.Name),
				slog.String("error", err.Error()),
			)
			continue
		}

		vuln := mapToVulnerability(&entry, data)
		if err := store.UpsertVulnerability(ctx, vuln); err != nil {
			s.logger.Warn("failed to upsert vulnerability",
				slog.String("id", entry.ID),
				slog.String("error", err.Error()),
			)
			continue
		}
		synced++
	}

	return synced, total, nil
}

// download fetches a URL and returns the response body. It checks the
// status code and respects context cancellation.
func (s *Syncer) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &errArchiveUnavailable{
			url:        url,
			statusCode: resp.StatusCode,
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxZIPSize))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return body, nil
}

// recordSyncSuccess persists a successful sync status.
func (s *Syncer) recordSyncSuccess(ctx context.Context, start time.Time, dur time.Duration, total, synced int) {
	now := time.Now()
	err := s.store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:         FeedName,
		LastSyncAt:       &now,
		LastSyncDuration: &dur,
		LastSyncStatus:   "success",
		EntriesSynced:    synced,
		EntriesTotal:     total,
	})
	if err != nil {
		s.logger.Warn("failed to record sync status", "error", err)
	}
}

// recordSyncFailure persists a failed sync status.
func (s *Syncer) recordSyncFailure(ctx context.Context, start time.Time, syncErr error) {
	dur := time.Since(start)
	now := time.Now()
	err := s.store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:         FeedName,
		LastSyncAt:       &now,
		LastSyncDuration: &dur,
		LastSyncStatus:   "error",
		LastError:        syncErr.Error(),
	})
	if err != nil {
		s.logger.Warn("failed to record sync failure", "error", err)
	}
}

// ---------------------------------------------------------------------------
// OSV JSON schema types (subset relevant for Packmon)
// ---------------------------------------------------------------------------

// osvEntry is the top-level OSV vulnerability JSON structure.
// See https://ossf.github.io/osv-schema/
type osvEntry struct {
	ID        string    `json:"id"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Aliases   []string  `json:"aliases"`
	Modified  time.Time `json:"modified"`
	Published time.Time `json:"published"`
	Withdrawn *string   `json:"withdrawn"`

	Severity         []osvSeverity   `json:"severity"`
	Affected         []osvAffected   `json:"affected"`
	References       []osvReference  `json:"references"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

// osvSeverity is one entry in the severity array.
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"` // CVSS vector string
}

// osvAffected is one entry in the affected array.
type osvAffected struct {
	Package           osvPackage      `json:"package"`
	Ranges            []osvRange      `json:"ranges"`
	Versions          []string        `json:"versions"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific"`
	DatabaseSpecific  json.RawMessage `json:"database_specific"`
}

// osvPackage identifies the affected package.
type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl"`
}

// osvRange defines a version range in the OSV schema.
type osvRange struct {
	Type   string     `json:"type"` // "SEMVER", "ECOSYSTEM", "GIT"
	Events []osvEvent `json:"events"`
}

// osvEvent is a single event in a range (introduced, fixed, last_affected, limit).
type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

// osvReference is a link associated with the vulnerability.
type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ---------------------------------------------------------------------------
// Mapping: OSV entry -> Packmon db.Vulnerability
// ---------------------------------------------------------------------------

// mapToVulnerability converts an OSV JSON entry into the Packmon
// Vulnerability data model.
func mapToVulnerability(entry *osvEntry, rawJSON []byte) *db.Vulnerability {
	vuln := &db.Vulnerability{
		ID:        entry.ID,
		Summary:   entry.Summary,
		Details:   entry.Details,
		Severity:  mapSeverity(entry),
		Published: entry.Published,
		Modified:  entry.Modified,
	}

	// Handle withdrawn timestamp.
	if entry.Withdrawn != nil && *entry.Withdrawn != "" {
		t, err := time.Parse(time.RFC3339, *entry.Withdrawn)
		if err == nil {
			vuln.Withdrawn = &t
		}
	}

	// CVSS score extraction from severity vector.
	if score := extractCVSSScore(entry.Severity); score > 0 {
		vuln.CVSSScore = &score
	}

	// Aliases. The entry ID itself is also an alias for deduplication.
	aliasSet := make(map[string]struct{})
	aliasSet[entry.ID] = struct{}{}
	for _, alias := range entry.Aliases {
		aliasSet[alias] = struct{}{}
	}
	for alias := range aliasSet {
		vuln.Aliases = append(vuln.Aliases, db.VulnerabilityAlias{
			AliasID: alias,
		})
	}

	// Source provenance.
	vuln.Sources = []db.VulnerabilitySource{
		{
			Source:   FeedName,
			SourceID: entry.ID,
			RawJSON:  rawJSON,
		},
	}

	// References.
	for _, ref := range entry.References {
		if ref.URL == "" {
			continue
		}
		vuln.References = append(vuln.References, db.VulnerabilityReference{
			Type:   ref.Type,
			URL:    ref.URL,
			Source: FeedName,
		})
	}

	// Affected packages.
	for _, aff := range entry.Affected {
		ecosystemRaw := aff.Package.Ecosystem
		// Strip scope suffix if present (e.g. "Maven:org.apache" -> "Maven").
		if idx := strings.IndexByte(ecosystemRaw, ':'); idx != -1 {
			ecosystemRaw = ecosystemRaw[:idx]
		}

		canonicalEco, ok := feed.MapOSVEcosystem(ecosystemRaw)
		if !ok {
			// Unsupported ecosystem, skip.
			continue
		}

		// Encode version ranges as JSON.
		rangesJSON, _ := json.Marshal(aff.Ranges)
		versionsJSON, _ := json.Marshal(aff.Versions)

		vuln.AffectedPackages = append(vuln.AffectedPackages, db.AffectedPackage{
			Ecosystem:        string(canonicalEco),
			Name:             aff.Package.Name,
			VersionRanges:    rangesJSON,
			VersionsAffected: versionsJSON,
		})
	}

	return vuln
}

// mapSeverity derives a Packmon severity string from OSV severity entries.
// It looks for a CVSS_V3 or CVSS_V2 vector and maps the base score to a
// severity level. If no CVSS data is available it falls back to "UNKNOWN".
func mapSeverity(entry *osvEntry) string {
	score := extractCVSSScore(entry.Severity)
	return cvssToSeverity(score)
}

// extractCVSSScore attempts to extract a numeric CVSS base score from the
// vector string. The OSV schema stores the full CVSS vector, not a numeric
// score, so we parse it heuristically.
func extractCVSSScore(severities []osvSeverity) float64 {
	for _, s := range severities {
		if s.Type != "CVSS_V3" && s.Type != "CVSS_V2" {
			continue
		}
		// CVSS v3 vectors look like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		// We do not ship a full CVSS calculator; instead we estimate from
		// the base metrics. For now, return 0 and rely on VulnCheck/NVD
		// enrichment for precise scores. The severity mapping will fall
		// back to database_specific or UNKNOWN.
		//
		// A full CVSS parser can be added later when VulnCheck enrichment
		// provides numeric scores.
	}
	return 0
}

// cvssToSeverity maps a CVSS base score (0-10) to the Packmon Severity
// enum string. Uses the standard NVD ranges.
func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
