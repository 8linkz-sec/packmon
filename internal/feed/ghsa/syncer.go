// Package ghsa implements the FeedSyncer for the GitHub Advisory
// Database. It clones/pulls the advisory-database git repository and
// parses reviewed advisories from the advisories/github-reviewed/
// directory tree.
package ghsa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

const (
	// FeedName is the canonical name used in feed_sync_status.
	FeedName = "ghsa"

	// repoURL is the GitHub Advisory Database repository.
	repoURL = "https://github.com/github/advisory-database.git"

	// reviewedDir is the subdirectory containing reviewed (curated)
	// advisories. Unreviewed advisories are lower quality and may
	// contain duplicates.
	reviewedDir = "advisories/github-reviewed"
)

// Compile-time interface assertion.
var _ feed.FeedSyncer = (*Syncer)(nil)

// Syncer clones or pulls the GitHub Advisory Database and parses all
// reviewed advisories into the Packmon database. It implements the
// FeedSyncer interface defined in feed.go.
type Syncer struct {
	store   db.Store
	logger  *slog.Logger
	dataDir string // parent directory for the cloned repo
}

type affectedPackageRepairer interface {
	RepairGHSAAffectedPackages(ctx context.Context) (int, error)
}

// NewSyncer creates a GHSA Syncer. dataDir is the parent directory
// where the advisory-database repo will be cloned. If dataDir is
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

// Sync implements feed.FeedSyncer. It clones or pulls the advisory
// database, then walks the reviewed advisories directory, parses each
// JSON file, and upserts the vulnerability into the store.
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error) {
	start := time.Now()
	s.logger.Info("starting GHSA sync")

	repoDir := filepath.Join(s.dataDir, "advisory-database")

	repo := &feed.GitRepo{
		URL:    repoURL,
		Dir:    repoDir,
		Logger: s.logger,
	}

	// PullWithChangedFiles handles clone-or-pull and computes the diff
	// between old HEAD and fetched origin/HEAD before resetting. This is
	// necessary because after a shallow fetch+reset the old commit is
	// unreachable and git diff would fail.
	commitHash, changedFiles, err := repo.PullWithChangedFiles(ctx)
	if err != nil {
		s.recordSyncFailure(ctx, start, err)
		return nil, fmt.Errorf("ghsa: pull with changed files: %w", err)
	}
	s.logger.Info("advisory-database ready", slog.String("commit", commitHash))

	// Check whether we already synced this commit.
	status, err := store.GetFeedSyncStatus(ctx, FeedName)
	if err != nil {
		s.logger.Warn("failed to get feed sync status, proceeding with full sync",
			slog.String("error", feed.SafeDiagnosticError(err)),
		)
	}
	if status != nil && status.LastCommitHash == commitHash && status.LastSyncStatus == "success" {
		s.logger.Info("advisory-database unchanged, skipping sync",
			slog.String("commit", commitHash),
		)
		s.repairAffectedPackages(ctx, store)
		// Still record a successful status to update the timestamp.
		dur := time.Since(start)
		s.recordSyncSuccessWithCommit(ctx, dur, status.EntriesTotal, 0, commitHash)
		return &feed.SyncResult{
			EntriesSynced: 0,
			EntriesTotal:  status.EntriesTotal,
		}, nil
	}

	advisoryRoot := filepath.Join(repoDir, reviewedDir)
	var synced, total int

	if changedFiles != nil {
		// Delta sync: only process changed advisory files.
		s.logger.Info("delta sync: processing changed files only",
			slog.String("commit", commitHash),
			slog.Int("changed_files", len(changedFiles)),
		)
		synced, total, err = s.processChangedFiles(ctx, store, repoDir, changedFiles)
		if err != nil {
			s.recordSyncFailure(ctx, start, err)
			return nil, fmt.Errorf("ghsa: process changed files: %w", err)
		}
	} else {
		// Full walk: first clone or diff unavailable.
		synced, total, err = s.walkAdvisories(ctx, store, advisoryRoot)
		if err != nil {
			s.recordSyncFailure(ctx, start, err)
			return nil, fmt.Errorf("ghsa: walk advisories: %w", err)
		}
	}

	repaired := s.repairAffectedPackages(ctx, store)

	duration := time.Since(start)
	s.logger.Info("GHSA sync completed",
		slog.Int("synced", synced),
		slog.Int("total", total),
		slog.Int("repaired_packages", repaired),
		slog.String("commit", commitHash),
		slog.String("duration", duration.String()),
	)

	s.recordSyncSuccessWithCommit(ctx, duration, total, synced, commitHash)
	return &feed.SyncResult{
		EntriesSynced: synced,
		EntriesTotal:  total,
	}, nil
}

// processChangedFiles processes only the advisory files that were
// modified between two git commits. It filters for JSON files under
// the reviewed directory and upserts each one.
func (s *Syncer) processChangedFiles(ctx context.Context, store db.Store, repoDir string, changedFiles []string) (synced, total int, err error) {
	repoRoot, err := os.OpenRoot(repoDir)
	if err != nil {
		return 0, 0, fmt.Errorf("open repo root: %w", err)
	}
	defer func() {
		_ = repoRoot.Close()
	}()

	entryErrors := 0
	for _, relPath := range changedFiles {
		if ctx.Err() != nil {
			return synced, total, ctx.Err()
		}
		cleanRelPath := path.Clean(relPath)

		// Only process JSON files under the reviewed advisories directory.
		if !strings.HasPrefix(cleanRelPath, reviewedDir+"/") {
			continue
		}
		if !strings.HasSuffix(cleanRelPath, ".json") {
			continue
		}
		total++

		data, readErr := feed.ReadRootFileLimited(repoRoot, cleanRelPath, feed.MaxGitAdvisoryJSONSize)
		if readErr != nil {
			if !errors.Is(readErr, fs.ErrNotExist) {
				s.logger.Warn("failed to read changed advisory file",
					slog.String("file", cleanRelPath),
					slog.String("error", feed.SafeDiagnosticError(readErr)),
				)
				entryErrors++
				continue
			}
			advisoryID := strings.TrimSuffix(path.Base(cleanRelPath), ".json")
			if advisoryID == "" {
				return synced, total, fmt.Errorf("derive deleted advisory ID from %s", cleanRelPath)
			}
			if deleteErr := db.DeleteVulnerabilityForSource(ctx, store, advisoryID, "ghsa"); deleteErr != nil {
				s.logger.Warn("failed to delete removed advisory",
					slog.String("id", advisoryID),
					slog.String("file", cleanRelPath),
					slog.String("error", feed.SafeDiagnosticError(deleteErr)),
				)
				return synced, total, fmt.Errorf("delete removed advisory %s: %w", advisoryID, deleteErr)
			}
			s.logger.Info("deleted removed advisory",
				slog.String("id", advisoryID),
				slog.String("file", cleanRelPath),
			)
			synced++
			continue
		}

		var advisory ghsaAdvisory
		if parseErr := json.Unmarshal(data, &advisory); parseErr != nil {
			s.logger.Warn("failed to parse advisory JSON",
				slog.String("file", cleanRelPath),
				slog.String("error", feed.SafeDiagnosticError(parseErr)),
			)
			entryErrors++
			continue
		}

		if advisory.ID == "" {
			s.logger.Warn("advisory has no ID, skipping", slog.String("file", cleanRelPath))
			entryErrors++
			continue
		}

		vuln := mapToVulnerability(&advisory, data)
		if upsertErr := store.UpsertVulnerability(ctx, vuln); upsertErr != nil {
			s.logger.Warn("failed to upsert advisory",
				slog.String("id", advisory.ID),
				slog.String("error", feed.SafeDiagnosticError(upsertErr)),
			)
			entryErrors++
			continue
		}
		synced++
	}

	if entryErrors > 0 {
		return synced, total, fmt.Errorf("%d GHSA advisory import errors", entryErrors)
	}
	return synced, total, nil
}

// walkAdvisories traverses the advisories directory tree and processes
// each JSON file.
func (s *Syncer) walkAdvisories(ctx context.Context, store db.Store, root string) (synced, total int, err error) {
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return 0, 0, fmt.Errorf("open advisory root: %w", err)
	}
	defer func() {
		_ = rootDir.Close()
	}()

	entryErrors := 0
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			s.logger.Warn("walk error", slog.String("file", filepath.Base(path)), slog.String("error", feed.SafeDiagnosticError(walkErr)))
			entryErrors++
			return nil
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if d.IsDir() {
			return nil
		}

		// Only process .json files.
		if !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		total++

		relativePath, relErr := filepath.Rel(root, path)
		if relErr != nil {
			s.logger.Warn("failed to resolve advisory path",
				slog.String("file", d.Name()),
				slog.String("error", feed.SafeDiagnosticError(relErr)),
			)
			entryErrors++
			return nil
		}

		data, readErr := feed.ReadRootFileLimited(rootDir, relativePath, feed.MaxGitAdvisoryJSONSize)
		if readErr != nil {
			s.logger.Warn("failed to read advisory file",
				slog.String("file", d.Name()),
				slog.String("error", feed.SafeDiagnosticError(readErr)),
			)
			entryErrors++
			return nil
		}

		var advisory ghsaAdvisory
		if parseErr := json.Unmarshal(data, &advisory); parseErr != nil {
			s.logger.Warn("failed to parse advisory JSON",
				slog.String("file", d.Name()),
				slog.String("error", feed.SafeDiagnosticError(parseErr)),
			)
			entryErrors++
			return nil
		}

		if advisory.ID == "" {
			s.logger.Warn("advisory has no ID, skipping", slog.String("file", d.Name()))
			entryErrors++
			return nil
		}

		vuln := mapToVulnerability(&advisory, data)
		if upsertErr := store.UpsertVulnerability(ctx, vuln); upsertErr != nil {
			s.logger.Warn("failed to upsert advisory",
				slog.String("id", advisory.ID),
				slog.String("error", feed.SafeDiagnosticError(upsertErr)),
			)
			entryErrors++
			return nil
		}
		synced++

		return nil
	})
	if err != nil {
		return synced, total, err
	}
	if entryErrors > 0 {
		return synced, total, fmt.Errorf("%d GHSA advisory import errors", entryErrors)
	}
	return synced, total, nil
}

// recordSyncSuccessWithCommit persists a successful sync status including
// the git commit hash for delta detection.
func (s *Syncer) recordSyncSuccessWithCommit(ctx context.Context, dur time.Duration, total, synced int, commitHash string) {
	now := time.Now()
	err := feed.UpsertFeedSyncStatusBounded(s.store, &db.FeedSyncStatus{
		FeedName:         FeedName,
		LastSyncAt:       &now,
		LastSyncDuration: &dur,
		LastSyncStatus:   "success",
		EntriesSynced:    synced,
		EntriesTotal:     total,
		LastCommitHash:   commitHash,
	})
	if err != nil {
		s.logger.Warn("failed to record sync status", "error", err)
	}
	_ = ctx
}

// recordSyncFailure persists a failed sync status.
func (s *Syncer) recordSyncFailure(ctx context.Context, start time.Time, syncErr error) {
	dur := time.Since(start)
	now := time.Now()
	err := feed.UpsertFeedSyncStatusBounded(s.store, &db.FeedSyncStatus{
		FeedName:         FeedName,
		LastSyncAt:       &now,
		LastSyncDuration: &dur,
		LastSyncStatus:   "error",
		LastError:        feed.SafeDiagnosticError(syncErr),
	})
	if err != nil {
		s.logger.Warn("failed to record sync failure", "error", err)
	}
	_ = ctx
}

func (s *Syncer) repairAffectedPackages(ctx context.Context, store db.Store) int {
	repairer, ok := store.(affectedPackageRepairer)
	if !ok {
		return 0
	}

	repaired, err := repairer.RepairGHSAAffectedPackages(ctx)
	if err != nil {
		s.logger.Warn("failed to repair GHSA affected packages from stored raw JSON",
			slog.String("error", feed.SafeDiagnosticError(err)),
		)
		return 0
	}
	if repaired > 0 {
		s.logger.Info("repaired GHSA affected packages from stored raw JSON",
			slog.Int("repaired", repaired),
		)
	}
	return repaired
}

// ---------------------------------------------------------------------------
// GHSA JSON schema types
// ---------------------------------------------------------------------------

// ghsaAdvisory is the top-level GHSA advisory JSON structure. The
// advisory-database uses OSV schema format for reviewed advisories.
type ghsaAdvisory struct {
	ID        string    `json:"id"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Aliases   []string  `json:"aliases"`
	Modified  time.Time `json:"modified"`
	Published time.Time `json:"published"`
	Withdrawn *string   `json:"withdrawn"`

	Severity         []ghsaSeverity        `json:"severity"`
	Affected         []ghsaAffected        `json:"affected"`
	References       []ghsaReference       `json:"references"`
	DatabaseSpecific *ghsaDatabaseSpecific `json:"database_specific"`
}

type ghsaSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type ghsaAffected struct {
	Package          ghsaPackage                   `json:"package"`
	Ranges           []ghsaRange                   `json:"ranges"`
	Versions         []string                      `json:"versions"`
	DatabaseSpecific *ghsaAffectedDatabaseSpecific `json:"database_specific"`
}

type ghsaAffectedDatabaseSpecific struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range"`
}

type ghsaPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type ghsaRange struct {
	Type   string      `json:"type"`
	Events []ghsaEvent `json:"events"`
}

type ghsaEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type ghsaReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type ghsaDatabaseSpecific struct {
	Severity       string   `json:"severity"`
	CVEs           []string `json:"cve_ids"`
	GithubReviewed bool     `json:"github_reviewed"`
}

// ---------------------------------------------------------------------------
// Mapping: GHSA advisory -> Packmon db.Vulnerability
// ---------------------------------------------------------------------------

func mapToVulnerability(advisory *ghsaAdvisory, rawJSON []byte) *db.Vulnerability {
	vuln := &db.Vulnerability{
		ID:        advisory.ID,
		Summary:   advisory.Summary,
		Details:   advisory.Details,
		Severity:  mapSeverity(advisory),
		Published: advisory.Published,
		Modified:  advisory.Modified,
	}

	// Handle withdrawn.
	if advisory.Withdrawn != nil && *advisory.Withdrawn != "" {
		t, err := time.Parse(time.RFC3339, *advisory.Withdrawn)
		if err == nil {
			vuln.Withdrawn = &t
		}
	}

	// Build alias list: include advisory ID, all explicit aliases, and
	// CVE IDs from database_specific.
	aliasSet := make(map[string]struct{})
	aliasSet[advisory.ID] = struct{}{}
	for _, a := range advisory.Aliases {
		aliasSet[a] = struct{}{}
	}
	if advisory.DatabaseSpecific != nil {
		for _, cve := range advisory.DatabaseSpecific.CVEs {
			aliasSet[cve] = struct{}{}
		}
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
			SourceID: advisory.ID,
			RawJSON:  rawJSON,
		},
	}

	// References.
	for _, ref := range advisory.References {
		if ref.URL == "" {
			continue
		}
		vuln.References = append(vuln.References, db.VulnerabilityReference{
			Type:   ref.Type,
			URL:    ref.URL,
			Source: FeedName,
		})
	}

	// Affected packages. GHSA can contain multiple affected entries for the
	// same package; keep all ranges on one canonical package row so later
	// entries do not overwrite earlier fixed boundaries during upsert.
	type affectedKey struct {
		ecosystem string
		name      string
	}
	type mergedAffected struct {
		ecosystem string
		name      string
		ranges    []ghsaRange
		versions  []string
		seen      map[string]struct{}
	}
	affectedOrder := make([]affectedKey, 0, len(advisory.Affected))
	affectedByKey := make(map[affectedKey]*mergedAffected)
	for _, aff := range advisory.Affected {
		canonicalEco, ok := feed.MapGHSAEcosystem(aff.Package.Ecosystem)
		if !ok || canonicalEco == "" {
			continue
		}

		key := affectedKey{ecosystem: string(canonicalEco), name: aff.Package.Name}
		merged := affectedByKey[key]
		if merged == nil {
			merged = &mergedAffected{
				ecosystem: key.ecosystem,
				name:      key.name,
				seen:      map[string]struct{}{},
			}
			affectedByKey[key] = merged
			affectedOrder = append(affectedOrder, key)
		}

		merged.ranges = append(merged.ranges, normalizeAffectedRanges(aff.Ranges, aff.DatabaseSpecific)...)
		for _, version := range aff.Versions {
			if _, ok := merged.seen[version]; ok {
				continue
			}
			merged.seen[version] = struct{}{}
			merged.versions = append(merged.versions, version)
		}
	}

	for _, key := range affectedOrder {
		merged := affectedByKey[key]
		rangesJSON, _ := json.Marshal(merged.ranges)
		versionsJSON, _ := json.Marshal(merged.versions)
		vuln.AffectedPackages = append(vuln.AffectedPackages, db.AffectedPackage{
			Ecosystem:        merged.ecosystem,
			Name:             merged.name,
			VersionRanges:    rangesJSON,
			VersionsAffected: versionsJSON,
		})
	}

	return vuln
}

func normalizeAffectedRanges(ranges []ghsaRange, specific *ghsaAffectedDatabaseSpecific) []ghsaRange {
	if len(ranges) == 0 {
		return nil
	}

	closure, hasClosure := closureEventFromLastKnownAffectedRange(specific)
	out := make([]ghsaRange, 0, len(ranges))
	for _, r := range ranges {
		normalized := ghsaRange{
			Type:   r.Type,
			Events: append([]ghsaEvent(nil), r.Events...),
		}
		if hasClosure && len(normalized.Events) > 0 && !hasRangeClosure(normalized.Events) {
			normalized.Events = append(normalized.Events, closure)
		}
		out = append(out, normalized)
	}
	return out
}

func hasRangeClosure(events []ghsaEvent) bool {
	for _, event := range events {
		if strings.TrimSpace(event.Fixed) != "" || strings.TrimSpace(event.LastAffected) != "" {
			return true
		}
	}
	return false
}

func closureEventFromLastKnownAffectedRange(specific *ghsaAffectedDatabaseSpecific) (ghsaEvent, bool) {
	if specific == nil {
		return ghsaEvent{}, false
	}
	for _, part := range strings.Split(specific.LastKnownAffectedVersionRange, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "<="):
			version := cleanConstraintVersion(strings.TrimPrefix(part, "<="))
			if version != "" {
				return ghsaEvent{LastAffected: version}, true
			}
		case strings.HasPrefix(part, "<"):
			version := cleanConstraintVersion(strings.TrimPrefix(part, "<"))
			if version != "" {
				return ghsaEvent{Fixed: version}, true
			}
		}
	}
	return ghsaEvent{}, false
}

func cleanConstraintVersion(version string) string {
	return strings.Trim(strings.TrimSpace(version), "`\"'")
}

// mapSeverity derives a Packmon severity string from the GHSA advisory.
// It checks database_specific.severity first (GHSA's own classification),
// then falls back to CVSS vectors, and finally to UNKNOWN.
func mapSeverity(advisory *ghsaAdvisory) string {
	// GHSA database_specific.severity is a human-readable string.
	if advisory.DatabaseSpecific != nil && advisory.DatabaseSpecific.Severity != "" {
		switch strings.ToUpper(advisory.DatabaseSpecific.Severity) {
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

	// Fallback: try CVSS severity entries (shared CVSS parser).
	for _, s := range advisory.Severity {
		if score := feed.ParseCVSSVector(s.Score); score > 0 {
			return feed.CVSSToSeverity(score)
		}
	}

	return "UNKNOWN"
}
