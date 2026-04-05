// Package ghsa implements the FeedSyncer for the GitHub Advisory
// Database. It clones/pulls the advisory-database git repository and
// parses reviewed advisories from the advisories/github-reviewed/
// directory tree.
package ghsa

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
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

	commitHash, err := repo.EnsureCloned(ctx)
	if err != nil {
		s.recordSyncFailure(ctx, start, err)
		return nil, fmt.Errorf("ghsa: ensure cloned: %w", err)
	}
	s.logger.Info("advisory-database ready", slog.String("commit", commitHash))

	// Check whether we already synced this commit.
	status, err := store.GetFeedSyncStatus(ctx, FeedName)
	if err != nil {
		s.logger.Warn("failed to get feed sync status, proceeding with full sync",
			slog.String("error", err.Error()),
		)
	}
	if status != nil && status.LastCommitHash == commitHash && status.LastSyncStatus == "success" {
		s.logger.Info("advisory-database unchanged, skipping sync",
			slog.String("commit", commitHash),
		)
		// Still record a successful status to update the timestamp.
		dur := time.Since(start)
		s.recordSyncSuccessWithCommit(ctx, start, dur, status.EntriesTotal, 0, commitHash)
		return &feed.SyncResult{
			EntriesSynced: 0,
			EntriesTotal:  status.EntriesTotal,
		}, nil
	}

	// Walk the reviewed directory and process each advisory.
	advisoryRoot := filepath.Join(repoDir, reviewedDir)
	synced, total, err := s.walkAdvisories(ctx, store, advisoryRoot)
	if err != nil {
		s.recordSyncFailure(ctx, start, err)
		return nil, fmt.Errorf("ghsa: walk advisories: %w", err)
	}

	duration := time.Since(start)
	s.logger.Info("GHSA sync completed",
		slog.Int("synced", synced),
		slog.Int("total", total),
		slog.String("commit", commitHash),
		slog.String("duration", duration.String()),
	)

	s.recordSyncSuccessWithCommit(ctx, start, duration, total, synced, commitHash)
	return &feed.SyncResult{
		EntriesSynced: synced,
		EntriesTotal:  total,
	}, nil
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

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			s.logger.Warn("walk error", slog.String("file", filepath.Base(path)), slog.String("error", walkErr.Error()))
			return nil // continue walking
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
				slog.String("error", relErr.Error()),
			)
			return nil
		}

		data, readErr := rootDir.ReadFile(relativePath)
		if readErr != nil {
			s.logger.Warn("failed to read advisory file",
				slog.String("file", d.Name()),
				slog.String("error", readErr.Error()),
			)
			return nil
		}

		var advisory ghsaAdvisory
		if parseErr := json.Unmarshal(data, &advisory); parseErr != nil {
			s.logger.Warn("failed to parse advisory JSON",
				slog.String("file", d.Name()),
				slog.String("error", parseErr.Error()),
			)
			return nil
		}

		if advisory.ID == "" {
			s.logger.Warn("advisory has no ID, skipping", slog.String("file", d.Name()))
			return nil
		}

		vuln := mapToVulnerability(&advisory, data)
		if upsertErr := store.UpsertVulnerability(ctx, vuln); upsertErr != nil {
			s.logger.Warn("failed to upsert advisory",
				slog.String("id", advisory.ID),
				slog.String("error", upsertErr.Error()),
			)
			return nil
		}
		synced++

		return nil
	})

	return synced, total, err
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
	Package  ghsaPackage `json:"package"`
	Ranges   []ghsaRange `json:"ranges"`
	Versions []string    `json:"versions"`
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

	// Affected packages.
	for _, aff := range advisory.Affected {
		canonicalEco, ok := feed.MapGHSAEcosystem(aff.Package.Ecosystem)
		if !ok || canonicalEco == "" {
			continue
		}

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
