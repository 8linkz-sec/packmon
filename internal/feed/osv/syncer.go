// Package osv implements the FeedSyncer for the OSV.dev vulnerability
// database. It downloads per-ecosystem ZIP archives from the public GCS
// bucket at https://osv-vulnerabilities.storage.googleapis.com/ and
// upserts each vulnerability into the Packmon database.
package osv

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
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

	// maxEntrySize is a safety limit for individual JSON entries within
	// the ZIP archive. A single OSV entry should never exceed 10 MB.
	maxEntrySize = 10 * 1024 * 1024 // 10 MB
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
// upserts it into the store. It uses ETag-based delta updates to
// skip re-downloading unchanged ecosystem archives.
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	start := time.Now()
	s.logger.Info("starting OSV sync")

	// Load stored per-ecosystem ETags from feed_sync_status.metadata.
	etags := s.loadEcosystemETags(ctx)

	ecosystems := feed.OSVBucketEcosystems()
	var totalSynced, totalEntries int
	var skippedByETag int
	var unavailableArchives int
	var failedEcosystems int
	var syncErrors []error

	for _, eco := range ecosystems {
		if ctx.Err() != nil {
			s.recordSyncFailure(ctx, start, ctx.Err())
			return nil, ctx.Err()
		}

		storedETag := etags[eco]
		synced, entries, newETag, err := s.syncEcosystem(ctx, store, eco, storedETag)
		if err != nil {
			if errors.Is(err, errNotModified) {
				s.logger.Debug("ecosystem unchanged (304), skipping",
					slog.String("ecosystem", eco),
				)
				skippedByETag++
				continue
			}
			var unavailable *errArchiveUnavailable
			if errors.As(err, &unavailable) {
				if unavailable.statusCode == http.StatusNotFound {
					s.logger.Info("ecosystem archive unavailable, skipping",
						slog.String("ecosystem", eco),
						slog.Int("status", unavailable.statusCode),
					)
					unavailableArchives++
					continue
				}
				failedEcosystems++
				syncErrors = append(syncErrors, err)
				s.logger.Warn("ecosystem archive request failed",
					slog.String("ecosystem", eco),
					slog.Int("status", unavailable.statusCode),
				)
				continue
			}
			failedEcosystems++
			syncErrors = append(syncErrors, err)
			totalSynced += synced
			totalEntries += entries
			s.logger.Error("ecosystem sync failed, continuing with next",
				slog.String("ecosystem", eco),
				slog.String("error", err.Error()),
			)
			// Continue with other ecosystems rather than aborting.
			continue
		}
		totalSynced += synced
		totalEntries += entries

		// Store the new ETag for this ecosystem.
		if newETag != "" {
			etags[eco] = newETag
		}

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
		slog.Int("skipped_by_etag", skippedByETag),
		slog.Int("unavailable_archives", unavailableArchives),
		slog.Int("failed_ecosystems", failedEcosystems),
		slog.String("duration", duration.String()),
	)

	if failedEcosystems > 0 {
		syncErr := fmt.Errorf("OSV sync failed for %d ecosystem(s): %w", failedEcosystems, errors.Join(syncErrors...))
		s.recordSyncFailure(ctx, start, syncErr)
		return nil, syncErr
	}

	s.recordSyncSuccess(ctx, start, duration, totalEntries, totalSynced)
	s.saveEcosystemETags(ctx, etags)
	return &feed.SyncResult{
		EntriesSynced: totalSynced,
		EntriesTotal:  totalEntries,
	}, nil
}

// errNotModified is returned by download when the server responds with
// HTTP 304 Not Modified, meaning the ETag matched and no new data is
// available.
var errNotModified = errors.New("not modified (HTTP 304)")

// loadEcosystemETags reads the per-ecosystem ETag map from the
// feed_sync_status metadata JSONB column.
func (s *Syncer) loadEcosystemETags(ctx context.Context) map[string]string {
	status, err := s.store.GetFeedSyncStatus(ctx, FeedName)
	if err != nil || status == nil || len(status.Metadata) == 0 {
		return make(map[string]string)
	}

	var meta struct {
		ETags map[string]string `json:"ecosystem_etags"`
	}
	if err := json.Unmarshal(status.Metadata, &meta); err != nil || meta.ETags == nil {
		return make(map[string]string)
	}
	return meta.ETags
}

// saveEcosystemETags persists the per-ecosystem ETag map into the
// feed_sync_status metadata JSONB column.
func (s *Syncer) saveEcosystemETags(ctx context.Context, etags map[string]string) {
	meta := struct {
		ETags map[string]string `json:"ecosystem_etags"`
	}{ETags: etags}

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		s.logger.Warn("failed to marshal ecosystem ETags", "error", err)
		return
	}

	status, err := s.store.GetFeedSyncStatus(ctx, FeedName)
	if err != nil || status == nil {
		// The status row should already exist from recordSyncSuccess.
		// If not, we just skip saving ETags this time.
		s.logger.Warn("failed to load feed status for ETag save", "error", err)
		return
	}

	status.Metadata = metaJSON
	if err := s.store.UpsertFeedSyncStatus(ctx, status); err != nil {
		s.logger.Warn("failed to save ecosystem ETags", "error", err)
	}
}

// syncEcosystem downloads and processes a single ecosystem's all.zip.
// It returns the new ETag from the server response (empty if none).
// If the stored ETag matches, it returns errNotModified.
func (s *Syncer) syncEcosystem(ctx context.Context, store db.Store, ecosystem, storedETag string) (synced, total int, newETag string, err error) {
	url := fmt.Sprintf("%s/%s/all.zip", bucketBaseURL, ecosystem)
	s.logger.Debug("downloading ecosystem archive", slog.String("url", url))

	tmpPath, respETag, err := s.download(ctx, url, storedETag)
	if err != nil {
		return 0, 0, "", fmt.Errorf("download %s: %w", url, err)
	}
	newETag = respETag

	// Clean up the temporary ZIP file when done.
	defer func() { _ = os.Remove(tmpPath) }()

	reader, err := zip.OpenReader(tmpPath)
	if err != nil {
		return 0, 0, "", fmt.Errorf("open zip for %s: %w", ecosystem, err)
	}
	defer func() { _ = reader.Close() }()

	var entryErrors int

	for _, f := range reader.File {
		if ctx.Err() != nil {
			return synced, total, newETag, ctx.Err()
		}

		// Only process .json files.
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		total++

		rc, err := f.Open()
		if err != nil {
			entryErrors++
			s.logger.Warn("failed to open zip entry",
				slog.String("file", f.Name),
				slog.String("error", err.Error()),
			)
			continue
		}

		data, err := io.ReadAll(io.LimitReader(rc, maxEntrySize))
		_ = rc.Close()
		if err != nil {
			entryErrors++
			s.logger.Warn("failed to read zip entry",
				slog.String("file", f.Name),
				slog.String("error", err.Error()),
			)
			continue
		}

		var entry osvEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			entryErrors++
			s.logger.Warn("failed to parse OSV entry",
				slog.String("file", f.Name),
				slog.String("error", err.Error()),
			)
			continue
		}

		// Skip MAL-* entries -- these are malicious package advisories
		// from OpenSSF that OSV aggregates. They belong in the
		// malicious_findings table, handled by the OpenSSF syncer.
		if strings.HasPrefix(entry.ID, "MAL-") {
			continue
		}

		if findings := mapToMaliciousFindings(&entry); len(findings) > 0 {
			if err := store.DeleteVulnerability(ctx, entry.ID); err != nil {
				entryErrors++
				s.logger.Warn("failed to delete vulnerability superseded by malicious OSV category",
					slog.String("id", entry.ID),
					slog.String("error", err.Error()),
				)
			}
			for _, finding := range findings {
				if err := store.UpsertMaliciousFinding(ctx, finding); err != nil {
					entryErrors++
					s.logger.Warn("failed to upsert malicious finding",
						slog.String("id", finding.ID),
						slog.String("error", err.Error()),
					)
					continue
				}
				synced++
			}
			continue
		}

		vuln := mapToVulnerability(&entry, data)
		if err := store.UpsertVulnerability(ctx, vuln); err != nil {
			entryErrors++
			s.logger.Warn("failed to upsert vulnerability",
				slog.String("id", entry.ID),
				slog.String("error", err.Error()),
			)
			continue
		}
		synced++
	}

	if entryErrors > 0 {
		return synced, total, newETag, fmt.Errorf("ecosystem %s: %d entry import error(s)", ecosystem, entryErrors)
	}

	return synced, total, newETag, nil
}

// download fetches a URL and streams the response body to a temporary
// file. It returns the path to the temp file along with the ETag from
// the response. The caller is responsible for removing the temp file.
// If storedETag is non-empty, it sends an If-None-Match header. When
// the server responds with 304 Not Modified, download returns
// errNotModified (wrapped so errors.Is works).
func (s *Syncer) download(ctx context.Context, url, storedETag string) (tmpPath, etag string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")
	if storedETag != "" {
		req.Header.Set("If-None-Match", storedETag)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return "", storedETag, errNotModified
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", &errArchiveUnavailable{
			url:        url,
			statusCode: resp.StatusCode,
		}
	}

	// Stream the response body to a temporary file instead of loading
	// the entire ZIP into memory.
	tmpFile, err := os.CreateTemp("", "packmon-osv-*.zip")
	if err != nil {
		return "", "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath = tmpFile.Name()

	// If anything goes wrong after creating the file, clean it up.
	defer func() {
		_ = tmpFile.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	written, err := io.Copy(tmpFile, io.LimitReader(resp.Body, maxZIPSize))
	if err != nil {
		return "", "", fmt.Errorf("writing response to temp file: %w", err)
	}

	s.logger.Debug("downloaded archive to temp file",
		slog.String("path", tmpPath),
		slog.Int64("bytes", written),
	)

	respETag := resp.Header.Get("ETag")
	return tmpPath, respETag, nil
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

func mapToMaliciousFindings(entry *osvEntry) []*db.MaliciousFinding {
	if entry == nil || len(entry.Affected) == 0 {
		return nil
	}

	refURLsJSON := marshalReferenceURLs(entry.References)
	entryRiskType := classifyMaliciousRiskType(entry)
	published := &entry.Published
	if published.IsZero() {
		published = nil
	}

	var findings []*db.MaliciousFinding
	for i, aff := range entry.Affected {
		if !affectedHasMaliciousCategory(aff) {
			continue
		}

		ecosystemRaw := aff.Package.Ecosystem
		if idx := strings.IndexByte(ecosystemRaw, ':'); idx != -1 {
			ecosystemRaw = ecosystemRaw[:idx]
		}
		canonicalEco, ok := feed.MapOSVEcosystem(ecosystemRaw)
		if !ok {
			continue
		}
		riskType := entryRiskType
		if affRiskType := maliciousRiskTypeFromJSON(aff.DatabaseSpecific); affRiskType != "" {
			riskType = affRiskType
		}

		id := entry.ID
		if i > 0 {
			id = fmt.Sprintf("%s-%d", entry.ID, i)
		}

		findings = append(findings, &db.MaliciousFinding{
			ID:            id,
			Ecosystem:     string(canonicalEco),
			Name:          aff.Package.Name,
			Versions:      maliciousVersions(aff),
			Source:        FeedName,
			RiskType:      riskType,
			Severity:      "CRITICAL",
			Summary:       entry.Summary,
			Description:   entry.Details,
			ReferenceURLs: refURLsJSON,
			OriginRef:     affectedSource(aff),
			Published:     published,
			CreatedBy:     "feed-sync",
		})
	}
	return findings
}

func affectedHasMaliciousCategory(aff osvAffected) bool {
	if len(aff.DatabaseSpecific) == 0 {
		return false
	}
	var dbSpec struct {
		Categories []string `json:"categories"`
	}
	if err := json.Unmarshal(aff.DatabaseSpecific, &dbSpec); err != nil {
		return false
	}
	for _, category := range dbSpec.Categories {
		if strings.EqualFold(strings.TrimSpace(category), "malicious") {
			return true
		}
	}
	return false
}

func affectedSource(aff osvAffected) string {
	if len(aff.DatabaseSpecific) == 0 {
		return ""
	}
	var dbSpec struct {
		Source string `json:"source"`
	}
	if err := json.Unmarshal(aff.DatabaseSpecific, &dbSpec); err != nil {
		return ""
	}
	return strings.TrimSpace(dbSpec.Source)
}

func maliciousVersions(aff osvAffected) json.RawMessage {
	versions := make([]string, 0, len(aff.Versions))
	versions = append(versions, aff.Versions...)
	for _, r := range aff.Ranges {
		for _, event := range r.Events {
			if event.Introduced != "" && event.Introduced != "0" && event.Introduced != "0.0.0-0" {
				versions = append(versions, event.Introduced)
			}
		}
	}
	if len(versions) == 0 {
		return nil
	}
	out, _ := json.Marshal(versions)
	return out
}

func marshalReferenceURLs(refs []osvReference) json.RawMessage {
	urls := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.URL != "" {
			urls = append(urls, ref.URL)
		}
	}
	out, _ := json.Marshal(urls)
	return out
}

func classifyMaliciousRiskType(entry *osvEntry) string {
	if riskType := maliciousRiskTypeFromJSON(entry.DatabaseSpecific); riskType != "" {
		return riskType
	}
	lower := strings.ToLower(entry.Summary + " " + entry.Details)
	switch {
	case strings.Contains(lower, "typosquat"):
		return "typosquatting"
	case strings.Contains(lower, "supply chain") || strings.Contains(lower, "supply-chain"):
		return "supply_chain"
	case strings.Contains(lower, "dependency confusion"):
		return "supply_chain"
	default:
		return "malware"
	}
}

func maliciousRiskTypeFromJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var spec struct {
		RiskType       string   `json:"risk_type"`
		Type           string   `json:"type"`
		Classification string   `json:"classification"`
		Categories     []string `json:"categories"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		return ""
	}
	for _, candidate := range append([]string{spec.RiskType, spec.Type, spec.Classification}, spec.Categories...) {
		if normalized := normalizeMaliciousRiskType(candidate); normalized != "" {
			return normalized
		}
	}
	return ""
}

func normalizeMaliciousRiskType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "malware", "trojan", "backdoor", "cryptominer", "cryptomining", "exfiltration", "protestware":
		return "malware"
	case "typosquat", "typosquatting", "typo-squatting":
		return "typosquatting"
	case "supply_chain", "supply-chain", "supply chain", "dependency_confusion", "dependency confusion":
		return "supply_chain"
	default:
		return ""
	}
}

// mapSeverity derives a Packmon severity string from OSV severity entries.
// It checks (in order):
//  1. CVSS_V3 or CVSS_V2 vectors in the severity array
//  2. database_specific.severity (used by GHSA, PYSEC, and others)
//
// If neither is available it falls back to "UNKNOWN".
func mapSeverity(entry *osvEntry) string {
	// Try CVSS vectors first (most precise).
	if score := extractCVSSScore(entry.Severity); score > 0 {
		return cvssToSeverity(score)
	}

	// Fallback: database_specific.severity (human-readable string).
	if len(entry.DatabaseSpecific) > 0 {
		var dbSpec struct {
			Severity string `json:"severity"`
		}
		if json.Unmarshal(entry.DatabaseSpecific, &dbSpec) == nil && dbSpec.Severity != "" {
			switch strings.ToUpper(dbSpec.Severity) {
			case "CRITICAL":
				return "CRITICAL"
			case "HIGH":
				return "HIGH"
			case "MODERATE", "MEDIUM":
				return "MEDIUM"
			case "LOW":
				return "LOW"
			}
		}
	}

	return "UNKNOWN"
}

// extractCVSSScore attempts to extract a numeric CVSS base score from the
// vector string. The OSV schema stores the full CVSS vector, not a numeric
// score, so we parse it heuristically.
func extractCVSSScore(severities []osvSeverity) float64 {
	for _, s := range severities {
		if s.Type != "CVSS_V3" && s.Type != "CVSS_V2" {
			continue
		}
		if score := feed.ParseCVSSVector(s.Score); score > 0 {
			return score
		}
	}
	return 0
}

func cvssToSeverity(score float64) string {
	return feed.CVSSToSeverity(score)
}
