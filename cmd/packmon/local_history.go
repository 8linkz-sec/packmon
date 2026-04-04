package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/8linkz/packmon/internal/db/sqlite"
	"github.com/8linkz/packmon/internal/domain"
)

const defaultMaxScansPerRepo = 100

func historyEnabled() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("PACKMON_HISTORY_ENABLED")))
	switch value {
	case "", "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func historyMaxScansPerRepo() int {
	value := strings.TrimSpace(os.Getenv("PACKMON_HISTORY_MAX_SCANS_PER_REPO"))
	if value == "" {
		return defaultMaxScansPerRepo
	}

	maxPerRepo, err := strconv.Atoi(value)
	if err != nil || maxPerRepo < 0 {
		return defaultMaxScansPerRepo
	}

	return maxPerRepo
}

func recordScanHistory(ctx context.Context, store *sqlite.Store, scanPath string, result *domain.ScanResult) error {
	repoName, branch := scanRepoMetadata(scanPath)

	entry := sqlite.ScanEntry{
		RepoName:          repoName,
		Branch:            branch,
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

func scanRepoMetadata(scanPath string) (repoName, branch string) {
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
	}

	return repoName, branch
}

func gitOutput(dir string, args ...string) (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", err
	}

	cmdArgs := append([]string{"-C", dir}, args...)
	out, err := exec.Command("git", cmdArgs...).Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}
