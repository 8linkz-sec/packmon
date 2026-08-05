// Package malicious implements the FeedSyncer for the OpenSSF
// Malicious Packages database. It clones/pulls the malicious-packages
// git repository and parses entries from the malicious/ directory tree
// into the malicious_findings table.
package malicious

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

const (
	// FeedName is the canonical name used in feed_sync_status.
	FeedName = "openssf"

	// importerVersion is bumped when the importer semantics change and an
	// unchanged git feed commit must be reprocessed.
	importerVersion = 4

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

// Syncer clones or pulls the OpenSSF malicious-packages repository and
// parses all entries into the Packmon malicious_findings table. It
// implements the FeedSyncer interface defined in feed.go.
type Syncer struct {
	logger  *slog.Logger
	dataDir string
	repoURL string
}

// NewSyncer creates a Syncer for the OpenSSF Malicious Packages feed.
// dataDir is the parent directory where the repo will be cloned. If
// empty, os.TempDir() is used.
func NewSyncer(logger *slog.Logger, dataDir string) *Syncer {
	if logger == nil {
		logger = slog.Default()
	}
	if dataDir == "" {
		dataDir = os.TempDir()
	}
	return &Syncer{
		logger:  logger.With(slog.String("feed", FeedName)),
		dataDir: dataDir,
		repoURL: repoURL,
	}
}

// Option configures a Syncer.
type Option func(*Syncer)

// WithRepoURL overrides the Git repository URL for operator-controlled mirrors.
func WithRepoURL(url string) Option {
	return func(s *Syncer) {
		if strings.TrimSpace(url) != "" {
			s.repoURL = strings.TrimSpace(url)
		}
	}
}

// NewSyncerWithOptions creates an OpenSSF Syncer with optional overrides.
func NewSyncerWithOptions(logger *slog.Logger, dataDir string, opts ...Option) *Syncer {
	s := NewSyncer(logger, dataDir)
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name implements feed.FeedSyncer.
func (s *Syncer) Name() string { return FeedName }

// Sync implements feed.FeedSyncer. It clones or pulls the
// malicious-packages repository, then walks the entry directories,
// parsing each JSON file and upserting malicious findings into the
// store.
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	start := time.Now().UTC()
	s.logger.Info("starting OpenSSF malicious packages sync")

	repoDir := filepath.Join(s.dataDir, "malicious-packages")

	repo := &feed.GitRepo{
		URL:    s.repoURL,
		Dir:    repoDir,
		Logger: s.logger,
	}

	commitHash, err := repo.EnsureCloned(ctx)
	if err != nil {
		s.recordSyncFailure(ctx, store, start, err)
		return nil, fmt.Errorf("malicious: ensure cloned: %w", err)
	}
	s.logger.Info("malicious-packages ready", slog.String("commit", commitHash))

	// Check whether we already synced this commit.
	status, err := store.GetFeedSyncStatus(ctx, FeedName)
	if err != nil {
		s.logger.Warn("failed to get feed sync status, proceeding with full sync",
			slog.String("error", feed.SafeDiagnosticError(err)),
		)
	}
	if status != nil && status.LastCommitHash == commitHash && status.LastSyncStatus == db.FeedSyncStatusSuccess {
		if hasCurrentImporterMetadata(status) {
			s.logger.Info("malicious-packages unchanged, skipping sync",
				slog.String("commit", commitHash),
			)
			dur := time.Since(start)
			s.recordSyncSuccessWithCommit(ctx, store, dur, status.EntriesTotal, 0, commitHash)
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
	var totalSynced, totalEntries, rootsFound int
	var totalActiveFindings int

	for _, dir := range []string{maliciousDir, osvDir} {
		root := filepath.Join(repoDir, dir)
		info, statErr := os.Stat(root)
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			s.recordSyncFailure(ctx, store, start, statErr)
			return nil, fmt.Errorf("malicious: inspect feed root %s: %w", dir, statErr)
		}
		if !info.IsDir() {
			validationErr := fmt.Errorf("feed root %s is not a directory", dir)
			s.recordSyncFailure(ctx, store, start, validationErr)
			return nil, fmt.Errorf("malicious: validate feed root: %w", validationErr)
		}
		rootsFound++

		synced, entries, activeFindings, walkErr := s.walkEntries(ctx, store, root, nil)
		if walkErr != nil {
			s.recordSyncFailure(ctx, store, start, walkErr)
			return nil, fmt.Errorf("malicious: walk %s: %w", dir, walkErr)
		}
		totalSynced += synced
		totalEntries += entries
		totalActiveFindings += activeFindings
	}
	if rootsFound == 0 {
		validationErr := fmt.Errorf("expected feed roots %q or %q not found", maliciousDir, osvDir)
		s.recordSyncFailure(ctx, store, start, validationErr)
		return nil, fmt.Errorf("malicious: validate feed: %w", validationErr)
	}
	if totalEntries == 0 && totalActiveFindings == 0 {
		validationErr := fmt.Errorf("no entries found under expected feed roots")
		s.recordSyncFailure(ctx, store, start, validationErr)
		return nil, fmt.Errorf("malicious: validate feed: %w", validationErr)
	}
	if totalActiveFindings == 0 {
		validationErr := fmt.Errorf("no active supported entries found under expected feed roots")
		s.recordSyncFailure(ctx, store, start, validationErr)
		return nil, fmt.Errorf("malicious: validate feed: %w", validationErr)
	}

	pruned, pruneErr := s.pruneStaleFindings(ctx, store, start)
	if pruneErr != nil {
		s.recordSyncFailure(ctx, store, start, pruneErr)
		return nil, fmt.Errorf("malicious: prune stale findings: %w", pruneErr)
	}

	duration := time.Since(start)
	s.logger.Info("OpenSSF malicious packages sync completed",
		slog.Int("synced", totalSynced),
		slog.Int("total", totalEntries),
		slog.Int("pruned", pruned),
		slog.String("commit", commitHash),
		slog.Duration("duration", duration),
	)

	s.recordSyncSuccessWithCommit(ctx, store, duration, totalEntries, totalSynced, commitHash)
	return &feed.SyncResult{
		EntriesSynced: totalSynced,
		EntriesTotal:  totalEntries,
	}, nil
}

// walkEntries traverses an entry root directory and processes each
// JSON file.
func (s *Syncer) walkEntries(ctx context.Context, store db.Store, root string, seenIDs map[string]struct{}) (synced, total, activeFindings int, err error) {
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("open malicious feed root: %w", err)
	}
	defer func() {
		_ = rootDir.Close()
	}()

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			s.logger.Warn("walk error",
				slog.String("file", filepath.Base(path)),
				slog.String("error", feed.SafeDiagnosticError(walkErr)),
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
				slog.String("error", feed.SafeDiagnosticError(relErr)),
			)
			return relErr
		}

		entrySynced, entryActive, processErr := s.processMaliciousEntry(ctx, store, rootDir, relativePath, seenIDs)
		if processErr != nil {
			return processErr
		}
		synced += entrySynced
		activeFindings += entryActive

		return nil
	})

	return synced, total, activeFindings, err
}

func (s *Syncer) processMaliciousEntry(ctx context.Context, store db.Store, rootDir *os.Root, relativePath string, seenIDs map[string]struct{}) (int, int, error) {
	fileName := filepath.Base(relativePath)
	data, readErr := feed.ReadRootFileLimited(rootDir, relativePath, feed.MaxGitAdvisoryJSONSize)
	if readErr != nil {
		s.logger.Warn("failed to read entry file",
			slog.String("file", fileName),
			slog.String("error", feed.SafeDiagnosticError(readErr)),
		)
		return 0, 0, fmt.Errorf("read entry %s: %w", fileName, readErr)
	}

	var entry malEntry
	if parseErr := json.Unmarshal(data, &entry); parseErr != nil {
		s.logger.Warn("failed to parse entry JSON",
			slog.String("file", fileName),
			slog.String("error", feed.SafeDiagnosticError(parseErr)),
		)
		return 0, 0, fmt.Errorf("parse entry %s: %w", fileName, parseErr)
	}

	findings := mapToMaliciousFindings(&entry, relativePath)
	if isWithdrawnEntry(&entry, relativePath) {
		synced := 0
		ids := findingIDsForTombstone(&entry, relativePath, findings)
		for _, id := range ids {
			if deleteErr := feed.DeleteMaliciousFindingForSource(ctx, store, id, FeedName); deleteErr != nil {
				s.logger.Warn("failed to tombstone withdrawn malicious finding",
					slog.String("id", id),
					slog.String("error", feed.SafeDiagnosticError(deleteErr)),
				)
				return synced, 0, fmt.Errorf("tombstone withdrawn malicious finding %s: %w", id, deleteErr)
			}
			if seenIDs != nil {
				delete(seenIDs, id)
			}
			synced++
		}
		return synced, 0, nil
	}
	if len(findings) == 0 {
		return 0, 0, nil
	}

	synced := 0
	active := 0
	for _, mf := range findings {
		if upsertErr := store.UpsertMaliciousFinding(ctx, mf); upsertErr != nil {
			s.logger.Warn("failed to upsert malicious finding",
				slog.String("id", mf.ID),
				slog.String("error", feed.SafeDiagnosticError(upsertErr)),
			)
			return synced, active, fmt.Errorf("upsert malicious finding %s: %w", mf.ID, upsertErr)
		}
		if seenIDs != nil {
			seenIDs[mf.ID] = struct{}{}
		}
		synced++
		active++
	}

	return synced, active, nil
}

func (s *Syncer) pruneStaleFindings(ctx context.Context, store db.Store, updatedBefore time.Time) (int, error) {
	pruner, ok := store.(db.SourceMaliciousFindingStalePruner)
	if !ok {
		s.logger.Warn("store cannot prune stale OpenSSF findings")
		return 0, nil
	}
	return pruner.PruneMaliciousFindingsForSourceUpdatedBefore(ctx, FeedName, updatedBefore)
}

// recordSyncSuccessWithCommit persists a successful sync status including
// the git commit hash for delta detection.
func (s *Syncer) recordSyncSuccessWithCommit(ctx context.Context, store db.Store, dur time.Duration, total, synced int, commitHash string) {
	now := time.Now()
	err := feed.UpsertFeedSyncStatusBounded(store, &db.FeedSyncStatus{
		FeedName:         FeedName,
		LastSyncAt:       &now,
		LastSyncDuration: &dur,
		LastSyncStatus:   db.FeedSyncStatusSuccess,
		EntriesSynced:    synced,
		EntriesTotal:     total,
		LastCommitHash:   commitHash,
		Metadata:         importerMetadata(),
	})
	if err != nil {
		s.logger.Warn("failed to record sync status", "error", err)
	}
	_ = ctx
}

// recordSyncFailure persists a failed sync status.
func (s *Syncer) recordSyncFailure(ctx context.Context, store db.Store, start time.Time, syncErr error) {
	dur := time.Since(start)
	now := time.Now().UTC()
	diagnostic := feed.SafeDiagnosticError(syncErr)
	status := &db.FeedSyncStatus{
		FeedName:         FeedName,
		LastSyncDuration: &dur,
		LastSyncStatus:   db.FeedSyncStatusError,
		LastError:        diagnostic,
		UpdatedAt:        now,
	}
	logMessage := "OpenSSF malicious packages sync failed"
	logStatus := db.FeedSyncStatusError
	if errors.Is(syncErr, context.Canceled) || errors.Is(syncErr, context.DeadlineExceeded) {
		logMessage = "OpenSSF malicious packages sync cancelled"
		logStatus = "cancelled"
	}
	s.logger.Warn(logMessage,
		slog.String("status", logStatus),
		slog.String("error", diagnostic),
		slog.Duration("duration", dur),
	)
	if current, err := feed.GetFeedSyncStatusBounded(store, FeedName); err == nil {
		feed.PreserveFeedStatusData(status, current)
	}
	err := feed.UpsertFeedSyncStatusBounded(store, status)
	if err != nil {
		s.logger.Warn("failed to record sync failure", "error", err)
	}
	_ = ctx
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

		var versionsJSON json.RawMessage
		if len(aff.Versions) > 0 {
			versionsJSON, _ = json.Marshal(aff.Versions)
		}
		var versionRangesJSON json.RawMessage
		if len(aff.Ranges) > 0 {
			versionRangesJSON, _ = json.Marshal(aff.Ranges)
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
			VersionRanges: versionRangesJSON,
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

// classifyRiskType keeps OpenSSF mapping code on the shared feed classifier.
func classifyRiskType(entry *malEntry) string {
	return feed.ClassifyMaliciousRiskType(entry.DatabaseSpecific, entry.Summary, entry.Details)
}

func riskTypeFromJSON(raw json.RawMessage) string {
	return feed.MaliciousRiskTypeFromJSON(raw)
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
