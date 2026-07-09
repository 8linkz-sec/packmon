package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/domain"
)

const (
	defaultMaxScansPerRepo = 100
	defaultHistoryMaxAge   = 90 * 24 * time.Hour
)

func historyEnabled() (bool, error) {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("PACKMON_HISTORY_ENABLED")))
	switch value {
	case "", "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid PACKMON_HISTORY_ENABLED: expected boolean (true/false, 1/0, yes/no, on/off)")
	}
}

func historyMaxScansPerRepo() (int, error) {
	value := strings.TrimSpace(os.Getenv("PACKMON_HISTORY_MAX_SCANS_PER_REPO"))
	if value == "" {
		return defaultMaxScansPerRepo, nil
	}

	maxPerRepo, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid PACKMON_HISTORY_MAX_SCANS_PER_REPO: expected a non-negative integer")
	}
	if maxPerRepo < 0 {
		return 0, fmt.Errorf("invalid PACKMON_HISTORY_MAX_SCANS_PER_REPO: must be zero or greater")
	}

	return maxPerRepo, nil
}

func historyMaxAge() (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv("PACKMON_HISTORY_MAX_AGE"))
	if value == "" {
		return defaultHistoryMaxAge, nil
	}
	if value == "0" {
		return 0, nil
	}

	maxAge, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid PACKMON_HISTORY_MAX_AGE: expected a non-negative duration such as 720h or 0")
	}
	if maxAge < 0 {
		return 0, fmt.Errorf("invalid PACKMON_HISTORY_MAX_AGE: must be zero or greater")
	}

	return maxAge, nil
}

func recordScanHistoryWithRepo(ctx context.Context, store *sqlite.Store, repo *domain.RepoInfo, result *domain.ScanResult) error {
	repoName := "local"
	branch := ""
	commit := ""
	if repo != nil {
		if strings.TrimSpace(repo.Name) != "" {
			repoName = repo.Name
		}
		branch = repo.Branch
		commit = repo.Commit
	}

	entry := sqlite.ScanEntry{
		RepoName:          repoName,
		Branch:            branch,
		Commit:            commit,
		ScannedAt:         result.ScannedAt,
		PackagesCount:     result.PackagesScanned,
		FindingsCount:     result.FindingsCount,
		FindingIDs:        make([]string, 0, len(result.Findings)),
		FindingSeverities: make([]string, 0, len(result.Findings)),
	}

	for _, finding := range result.Findings {
		entry.FindingIDs = append(entry.FindingIDs, findingHistoryID(finding))

		severity := strings.TrimSpace(string(finding.Severity))
		if severity == "" {
			severity = "UNKNOWN"
		}
		entry.FindingSeverities = append(entry.FindingSeverities, severity)
	}

	return store.InsertScan(ctx, entry)
}

func findingHistoryID(finding domain.Finding) string {
	if finding.AdvisoryID != "" {
		return finding.AdvisoryID
	}

	return fmt.Sprintf("%s:%s:%s:%s",
		finding.Type,
		finding.Ecosystem,
		finding.Name,
		finding.Title,
	)
}

func scanRepoInfo(scanPath string) *domain.RepoInfo {
	repoName, branch, commit := scanRepoMetadata(scanPath)
	return &domain.RepoInfo{Name: repoName, Branch: branch, Commit: commit}
}

func scanRepoMetadata(scanPath string) (repoName, branch, commit string) {
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		absPath = scanPath
	}

	info, err := os.Stat(absPath)
	if err == nil && !info.IsDir() {
		absPath = filepath.Dir(absPath)
	}

	repoName = filepath.Base(absPath)
	if repoName == "." || repoName == string(filepath.Separator) || repoName == "" {
		repoName = "local"
	}

	if gitRoot, err := gitOutput(absPath, "rev-parse", "--show-toplevel"); err == nil && gitRoot != "" {
		repoName = filepath.Base(gitRoot)
		if currentBranch, err := gitOutput(gitRoot, "branch", "--show-current"); err == nil {
			branch = currentBranch
		}
		if currentCommit, err := gitOutput(gitRoot, "rev-parse", "HEAD"); err == nil {
			commit = currentCommit
		}
	}

	return repoName, branch, commit
}

func gitOutput(dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitMetadataTimeout)
	defer cancel()
	cmdArgs := append([]string{"-C", dir}, args...)
	out, err := gitCommandOutput(ctx, cmdArgs...)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}
