// Package malicious implements the FeedSyncer for the OpenSSF
// Malicious Packages database. It clones/pulls the malicious-packages
// git repository and parses entries from the malicious/ directory tree
// into the malicious_findings table.
package malicious

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
)

const (
	// FeedName is the canonical name used in feed_sync_status.
	FeedName = "openssf"

	// importerVersion is bumped when the importer semantics change and an
	// unchanged git feed commit must be reprocessed.
	importerVersion = 2

	// repoURL is the OpenSSF malicious-packages repository.
	repoURL = "https://github.com/ossf/malicious-packages.git"

	// maliciousDir is the subdirectory containing malicious package
	// reports. The structure is:
	//   malicious/{ecosystem}/{package_name}/{MAL-id}.json
	// Some entries use an "osv" subdirectory:
	//   osv/{ecosystem}/{package_name}/{MAL-id}.json
	maliciousDir = "malicious"
	osvDir       = "osv"
)

// Compile-time interface assertion.
var _ feed.FeedSyncer = (*Syncer)(nil)

type sourceMaliciousPruner interface {
	DeleteMaliciousFindingsNotInSource(ctx context.Context, source string, ids []string) (int, error)
}

// Syncer clones or pulls the OpenSSF malicious-packages repository and
// parses all entries into the Packmon malicious_findings table. It
// implements the FeedSyncer interface defined in feed.go.
type Syncer struct {
	store   db.Store
	logger  *slog.Logger
	dataDir string
}

// NewSyncer creates a Syncer for the OpenSSF Malicious Packages feed.
// dataDir is the parent directory where the repo will be cloned. If
// empty, os.TempDir() is used.
func NewSyncer(store db.Store, logger *slog.Logger, dataDir string) *Syncer {
	if logger == nil {
		logger = slog.Default()
	}
	if dataDir == "" {
		dataDir = os.TempDir()
	}
	return &Syncer{
		store:   store,
		logger:  logger.With(slog.String("feed", FeedName)),
		dataDir: dataDir,
	}
}

// Name implements feed.FeedSyncer.
func (s *Syncer) Name() string { return FeedName }

// Sync implements feed.FeedSyncer. It clones or pulls the
// malicious-packages repository, then walks the entry directories,
// parsing each JSON file and upserting malicious findings into the
// store.
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	start := time.Now()
	s.logger.Info("starting OpenSSF malicious packages sync")

	repoDir := filepath.Join(s.dataDir, "malicious-packages")

	repo := &feed.GitRepo{
		URL:    repoURL,
		Dir:    repoDir,
		Logger: s.logger,
	}

	commitHash, err := repo.EnsureCloned(ctx)
	if err != nil {
		s.recordSyncFailure(ctx, start, err)
		return nil, fmt.Errorf("malicious: ensure cloned: %w", err)
	}
	s.logger.Info("malicious-packages ready", slog.String("commit", commitHash))

	// Check whether we already synced this commit.
	status, err := store.GetFeedSyncStatus(ctx, FeedName)
	if err != nil {
		s.logger.Warn("failed to get feed sync status, proceeding with full sync",
			slog.String("error", err.Error()),
		)
	}
	if status != nil && status.LastCommitHash == commitHash && status.LastSyncStatus == "success" {
		if hasCurrentImporterMetadata(status) {
			s.logger.Info("malicious-packages unchanged, skipping sync",
				slog.String("commit", commitHash),
			)
			dur := time.Since(start)
			s.recordSyncSuccessWithCommit(ctx, start, dur, status.EntriesTotal, 0, commitHash)
			return &feed.SyncResult{
				EntriesSynced: 0,
				EntriesTotal:  status.EntriesTotal,
			}, nil
		}
		s.logger.Info("malicious-packages importer changed, reprocessing unchanged commit",
			slog.String("commit", commitHash),
		)
	}

	// The repository has two potential directory layouts:
	//   malicious/{ecosystem}/{name}/...json
	//   osv/{ecosystem}/{name}/...json
	// We try both.
	var totalSynced, totalEntries int
	seenIDs := make(map[string]struct{})

	for _, dir := range []string{maliciousDir, osvDir} {
		root := filepath.Join(repoDir, dir)
		if _, statErr := os.Stat(root); os.IsNotExist(statErr) {
			continue
		}
		synced, entries, walkErr := s.walkEntries(ctx, store, root, seenIDs)
		if walkErr != nil {
			s.recordSyncFailure(ctx, start, walkErr)
			return nil, fmt.Errorf("malicious: walk %s: %w", dir, walkErr)
		}
		totalSynced += synced
		totalEntries += entries
	}
	pruned, pruneErr := s.pruneStaleFindings(ctx, store, seenIDs)
	if pruneErr != nil {
		s.recordSyncFailure(ctx, start, pruneErr)
		return nil, fmt.Errorf("malicious: prune stale findings: %w", pruneErr)
	}

	duration := time.Since(start)
	s.logger.Info("OpenSSF malicious packages sync completed",
		slog.Int("synced", totalSynced),
		slog.Int("total", totalEntries),
		slog.Int("pruned", pruned),
		slog.String("commit", commitHash),
		slog.String("duration", duration.String()),
	)

	s.recordSyncSuccessWithCommit(ctx, start, duration, totalEntries, totalSynced, commitHash)
	return &feed.SyncResult{
		EntriesSynced: totalSynced,
		EntriesTotal:  totalEntries,
	}, nil
}

// walkEntries traverses an entry root directory and processes each
// JSON file.
func (s *Syncer) walkEntries(ctx context.Context, store db.Store, root string, seenIDs map[string]struct{}) (synced, total int, err error) {
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return 0, 0, fmt.Errorf("open malicious feed root: %w", err)
	}
	defer func() {
		_ = rootDir.Close()
	}()

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			s.logger.Warn("walk error",
				slog.String("file", filepath.Base(path)),
				slog.String("error", walkErr.Error()),
			)
			return walkErr
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if d.IsDir() {
			return nil
		}

		if !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		total++

		relativePath, relErr := filepath.Rel(root, path)
		if relErr != nil {
			s.logger.Warn("failed to resolve entry path",
				slog.String("file", d.Name()),
				slog.String("error", relErr.Error()),
			)
			return relErr
		}

		data, readErr := rootDir.ReadFile(relativePath)
		if readErr != nil {
			s.logger.Warn("failed to read entry file",
				slog.String("file", d.Name()),
				slog.String("error", readErr.Error()),
			)
			return fmt.Errorf("read entry %s: %w", d.Name(), readErr)
		}

		var entry malEntry
		if parseErr := json.Unmarshal(data, &entry); parseErr != nil {
			s.logger.Warn("failed to parse entry JSON",
				slog.String("file", d.Name()),
				slog.String("error", parseErr.Error()),
			)
			return fmt.Errorf("parse entry %s: %w", d.Name(), parseErr)
		}

		findings := mapToMaliciousFindings(&entry, relativePath)
		if isWithdrawnEntry(&entry, relativePath) {
			ids := findingIDsForTombstone(&entry, relativePath, findings)
			for _, id := range ids {
				if deleteErr := store.DeleteMaliciousFinding(ctx, id); deleteErr != nil {
					s.logger.Warn("failed to tombstone withdrawn malicious finding",
						slog.String("id", id),
						slog.String("error", deleteErr.Error()),
					)
					return fmt.Errorf("tombstone withdrawn malicious finding %s: %w", id, deleteErr)
				}
				if seenIDs != nil {
					delete(seenIDs, id)
				}
				synced++
			}
			return nil
		}
		if len(findings) == 0 {
			return nil
		}

		for _, mf := range findings {
			if upsertErr := store.UpsertMaliciousFinding(ctx, mf); upsertErr != nil {
				s.logger.Warn("failed to upsert malicious finding",
					slog.String("id", mf.ID),
					slog.String("error", upsertErr.Error()),
				)
				return fmt.Errorf("upsert malicious finding %s: %w", mf.ID, upsertErr)
			}
			if seenIDs != nil {
				seenIDs[mf.ID] = struct{}{}
			}
			synced++
		}

		return nil
	})

	return synced, total, err
}

func (s *Syncer) pruneStaleFindings(ctx context.Context, store db.Store, seenIDs map[string]struct{}) (int, error) {
	pruner, ok := store.(sourceMaliciousPruner)
	if !ok {
		s.logger.Warn("store cannot prune stale OpenSSF findings")
		return 0, nil
	}
	ids := make([]string, 0, len(seenIDs))
	for id := range seenIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return pruner.DeleteMaliciousFindingsNotInSource(ctx, "openssf", ids)
}

// recordSyncSuccessWithCommit persists a successful sync status including
// the git commit hash for delta detection.
func (s *Syncer) recordSyncSuccessWithCommit(ctx context.Context, start time.Time, dur time.Duration, total, synced int, commitHash string) {
	now := time.Now()
	err := s.store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:         FeedName,
		LastSyncAt:       &now,
		LastSyncDuration: &dur,
		LastSyncStatus:   "success",
		EntriesSynced:    synced,
		EntriesTotal:     total,
		LastCommitHash:   commitHash,
		Metadata:         importerMetadata(),
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

type syncMetadata struct {
	ImporterVersion int `json:"importer_version"`
}

func hasCurrentImporterMetadata(status *db.FeedSyncStatus) bool {
	if status == nil || len(status.Metadata) == 0 {
		return false
	}
	var meta syncMetadata
	if err := json.Unmarshal(status.Metadata, &meta); err != nil {
		return false
	}
	return meta.ImporterVersion >= importerVersion
}

func importerMetadata() json.RawMessage {
	data, _ := json.Marshal(syncMetadata{ImporterVersion: importerVersion})
	return data
}

// ---------------------------------------------------------------------------
// OpenSSF Malicious Packages JSON schema
//
// The format follows a variant of the OSV schema. The key fields are:
//   id, summary, details, aliases, affected[].package, modified, published
// ---------------------------------------------------------------------------

type malEntry struct {
	ID        string     `json:"id"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Aliases   []string   `json:"aliases"`
	Modified  time.Time  `json:"modified"`
	Published time.Time  `json:"published"`
	Withdrawn *time.Time `json:"withdrawn"`

	Affected         []malAffected   `json:"affected"`
	References       []malReference  `json:"references"`
	Credits          []malCredit     `json:"credits"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

type malAffected struct {
	Package          malPackage      `json:"package"`
	Ranges           []malRange      `json:"ranges"`
	Versions         []string        `json:"versions"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

type malPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type malRange struct {
	Type   string     `json:"type"`
	Events []malEvent `json:"events"`
}

type malEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type malReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type malCredit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact"`
}

// ---------------------------------------------------------------------------
// Mapping: OpenSSF entry -> Packmon db.MaliciousFinding
// ---------------------------------------------------------------------------

// mapToMaliciousFindings converts an OpenSSF malicious-packages entry
// into one or more Packmon MaliciousFinding models -- one per affected
// ecosystem/package pair. Returns nil if the entry has no recognised
// ecosystems.
func mapToMaliciousFindings(entry *malEntry, filePath string) []*db.MaliciousFinding {
	if len(entry.Affected) == 0 {
		return nil
	}

	// Determine risk type from explicit feed metadata first, then fall back to
	// older summary/details heuristics.
	entryRiskType := classifyRiskType(entry)

	// Collect reference URLs (shared across all findings from this entry).
	var refURLs []string
	for _, ref := range entry.References {
		if ref.URL != "" {
			refURLs = append(refURLs, ref.URL)
		}
	}
	refURLsJSON, _ := json.Marshal(refURLs)

	// Use the entry ID as the base finding ID. If empty, derive from file path.
	baseID := entry.ID
	if baseID == "" {
		baseID = deriveIDFromPath(filePath)
	}

	published := &entry.Published
	if published.IsZero() {
		published = nil
	}

	var findings []*db.MaliciousFinding

	// Iterate over ALL affected entries, not just the first one.
	for i, aff := range entry.Affected {
		canonicalEco, ok := feed.MapOpenSSFEcosystem(aff.Package.Ecosystem)
		if !ok {
			continue
		}
		riskType := entryRiskType
		if affRiskType := riskTypeFromJSON(aff.DatabaseSpecific); affRiskType != "" {
			riskType = affRiskType
		}

		// Collect versions for this specific affected entry.
		var versions []string
		versions = append(versions, aff.Versions...)
		for _, r := range aff.Ranges {
			for _, e := range r.Events {
				if e.Introduced != "" && e.Introduced != "0" {
					versions = append(versions, e.Introduced)
				}
			}
		}

		var versionsJSON json.RawMessage
		if len(versions) > 0 {
			versionsJSON, _ = json.Marshal(versions)
		}

		// For entries with multiple affected ecosystems, append a suffix
		// to keep IDs unique. The first entry keeps the original ID for
		// backwards compatibility.
		id := baseID
		if i > 0 {
			id = fmt.Sprintf("%s-%d", baseID, i)
		}

		findings = append(findings, &db.MaliciousFinding{
			ID:            id,
			Ecosystem:     string(canonicalEco),
			Name:          aff.Package.Name,
			Versions:      versionsJSON,
			Source:        "openssf",
			RiskType:      riskType,
			Severity:      "CRITICAL", // malicious packages are always critical
			Summary:       entry.Summary,
			Description:   entry.Details,
			ReferenceURLs: refURLsJSON,
			OriginRef:     filePath,
			Published:     published,
			CreatedBy:     "feed-sync",
		})
	}

	return findings
}

func isWithdrawnEntry(entry *malEntry, filePath string) bool {
	if entry.Withdrawn != nil {
		return true
	}
	path := filepath.ToSlash(filePath)
	return path == "withdrawn" || strings.HasPrefix(path, "withdrawn/")
}

func findingIDsForTombstone(entry *malEntry, filePath string, findings []*db.MaliciousFinding) []string {
	if len(findings) > 0 {
		ids := make([]string, 0, len(findings))
		for _, finding := range findings {
			if finding.ID != "" {
				ids = append(ids, finding.ID)
			}
		}
		return ids
	}

	id := entry.ID
	if id == "" {
		id = deriveIDFromPath(filePath)
	}
	if id == "" {
		return nil
	}
	return []string{id}
}

// classifyRiskType attempts to determine whether a malicious package is
// malware, typosquatting, or a supply-chain attack based on heuristics
// in the entry ID and summary.
func classifyRiskType(entry *malEntry) string {
	if riskType := riskTypeFromJSON(entry.DatabaseSpecific); riskType != "" {
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
	case strings.Contains(lower, "trojan") || strings.Contains(lower, "backdoor"):
		return "malware"
	case strings.Contains(lower, "cryptomin"):
		return "malware"
	case strings.Contains(lower, "exfiltrat"):
		return "malware"
	default:
		return "malware"
	}
}

func riskTypeFromJSON(raw json.RawMessage) string {
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
		if normalized := normalizeRiskType(candidate); normalized != "" {
			return normalized
		}
	}
	return ""
}

func normalizeRiskType(raw string) string {
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

// deriveIDFromPath creates a stable ID from a file path when the JSON
// entry has no id field. It uses the last two path components.
func deriveIDFromPath(path string) string {
	// Normalise separators.
	path = filepath.ToSlash(path)
	parts := strings.Split(path, "/")
	if len(parts) >= 2 {
		return "openssf-" + parts[len(parts)-2] + "-" + strings.TrimSuffix(parts[len(parts)-1], ".json")
	}
	return "openssf-" + strings.TrimSuffix(filepath.Base(path), ".json")
}
