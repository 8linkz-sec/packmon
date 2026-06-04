package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/domain"
)

func TestHistoryEnabledEnvParsing(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want bool
	}{
		{name: "default", want: true},
		{name: "true", env: "true", want: true},
		{name: "one", env: "1", want: true},
		{name: "false", env: "false", want: false},
		{name: "off", env: "off", want: false},
		{name: "unknown defaults true", env: "maybe", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("PACKMON_HISTORY_ENABLED", tt.env)
			}
			if got := historyEnabled(); got != tt.want {
				t.Fatalf("historyEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHistoryMaxScansPerRepoEnvParsing(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want int
	}{
		{name: "default", want: defaultMaxScansPerRepo},
		{name: "valid", env: "25", want: 25},
		{name: "zero disables retention", env: "0", want: 0},
		{name: "negative falls back", env: "-1", want: defaultMaxScansPerRepo},
		{name: "invalid falls back", env: "many", want: defaultMaxScansPerRepo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("PACKMON_HISTORY_MAX_SCANS_PER_REPO", tt.env)
			}
			if got := historyMaxScansPerRepo(); got != tt.want {
				t.Fatalf("historyMaxScansPerRepo() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFindingHistoryIDUsesAdvisoryOrDeterministicFallback(t *testing.T) {
	t.Parallel()

	withAdvisory := domain.Finding{AdvisoryID: "GHSA-1234"}
	if got := findingHistoryID(withAdvisory); got != "GHSA-1234" {
		t.Fatalf("findingHistoryID(advisory) = %q", got)
	}

	fallback := domain.Finding{
		Type:      domain.FindingTypeMalicious,
		Ecosystem: domain.EcosystemNPM,
		Name:      "left-pad",
		Title:     "malware",
	}
	if got := findingHistoryID(fallback); got != "malicious:npm:left-pad:malware" {
		t.Fatalf("findingHistoryID(fallback) = %q", got)
	}
}

func TestScanRepoMetadataUsesDirectoryOrFileNameWithoutGit(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	lockFile := filepath.Join(repoDir, "package-lock.json")
	if err := os.WriteFile(lockFile, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write lock file: %v", err)
	}
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(repoDir))

	repoName, branch, commit := scanRepoMetadata(lockFile)
	if repoName != "repo" || branch != "" || commit != "" {
		t.Fatalf("scanRepoMetadata(file) = %q, %q, %q", repoName, branch, commit)
	}

	info := scanRepoInfo(repoDir)
	if info.Name != "repo" || info.Branch != "" || info.Commit != "" {
		t.Fatalf("scanRepoInfo(dir) = %+v", info)
	}
}

func TestScanRepoMetadataReadsGitBranchAndCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repoDir := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	runLocalHistoryGit(t, repoDir, "init")
	runLocalHistoryGit(t, repoDir, "config", "user.email", "packmon@example.test")
	runLocalHistoryGit(t, repoDir, "config", "user.name", "Packmon Test")
	runLocalHistoryGit(t, repoDir, "checkout", "-b", "packmon-test")
	runLocalHistoryGit(t, repoDir, "commit", "--allow-empty", "-m", "initial")

	repoName, branch, commit := scanRepoMetadata(repoDir)
	if repoName != "repo" || branch != "packmon-test" || len(commit) != 40 {
		t.Fatalf("scanRepoMetadata(git repo) = %q, %q, %q; want repo, packmon-test, 40-char commit", repoName, branch, commit)
	}
}

func TestScanRepoMetadataHandlesGitRepoWithoutCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repoDir := filepath.Join(t.TempDir(), "repo-no-commit")
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	runLocalHistoryGit(t, repoDir, "init")

	repoName, _, commit := scanRepoMetadata(repoDir)
	if repoName != "repo-no-commit" || commit != "" {
		t.Fatalf("scanRepoMetadata(no commit) = %q, %q; want repo name and empty commit", repoName, commit)
	}
}

func runLocalHistoryGit(t *testing.T, dir string, args ...string) {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Packmon Test",
		"GIT_AUTHOR_EMAIL=packmon@example.test",
		"GIT_COMMITTER_NAME=Packmon Test",
		"GIT_COMMITTER_EMAIL=packmon@example.test",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}

func TestRecordScanHistoryStoresFindingIDsAndSeverities(t *testing.T) {
	store, _ := newTestSQLiteStore(t, t.TempDir())
	scanDir := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(scanDir, 0o750); err != nil {
		t.Fatalf("mkdir scan dir: %v", err)
	}
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(scanDir))
	scannedAt := time.Date(2026, 5, 30, 10, 0, 0, 0, time.UTC)
	result := &domain.ScanResult{
		ScannedAt:       scannedAt,
		PackagesScanned: 2,
		FindingsCount:   2,
		Findings: []domain.Finding{
			{AdvisoryID: "GHSA-one", Severity: domain.SeverityHigh},
			{Type: domain.FindingTypeMalicious, Ecosystem: domain.EcosystemNPM, Name: "bad", Title: "malware"},
		},
	}

	if err := recordScanHistory(context.Background(), store, scanDir, result); err != nil {
		t.Fatalf("record scan history: %v", err)
	}

	var repoName, idsJSON, severitiesJSON string
	var packagesCount, findingsCount int
	if err := store.DB().QueryRowContext(context.Background(), `
		SELECT repo_name, packages_count, findings_count, finding_ids, finding_severities
		FROM scan_history`).Scan(&repoName, &packagesCount, &findingsCount, &idsJSON, &severitiesJSON); err != nil {
		t.Fatalf("read scan history: %v", err)
	}
	if repoName != "app" || packagesCount != 2 || findingsCount != 2 {
		t.Fatalf("history row = repo %q packages %d findings %d", repoName, packagesCount, findingsCount)
	}

	var ids []string
	if err := json.Unmarshal([]byte(idsJSON), &ids); err != nil {
		t.Fatalf("decode finding ids: %v", err)
	}
	if len(ids) != 2 || ids[0] != "GHSA-one" || ids[1] != "malicious:npm:bad:malware" {
		t.Fatalf("finding ids = %v", ids)
	}

	var severities []string
	if err := json.Unmarshal([]byte(severitiesJSON), &severities); err != nil {
		t.Fatalf("decode severities: %v", err)
	}
	if len(severities) != 2 || severities[0] != "HIGH" || severities[1] != "UNKNOWN" {
		t.Fatalf("finding severities = %v", severities)
	}
}
