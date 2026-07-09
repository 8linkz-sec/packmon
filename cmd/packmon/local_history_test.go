package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestHistoryEnabledEnvParsing(t *testing.T) {
	tests := []struct {
		name   string
		env    string
		setEnv bool
		want   bool
	}{
		{name: "default", want: true},
		{name: "blank defaults true", env: "  ", setEnv: true, want: true},
		{name: "true", env: "true", setEnv: true, want: true},
		{name: "one", env: "1", setEnv: true, want: true},
		{name: "false", env: "false", setEnv: true, want: false},
		{name: "off", env: "off", setEnv: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv("PACKMON_HISTORY_ENABLED", tt.env)
			}
			got, err := historyEnabled()
			if err != nil {
				t.Fatalf("historyEnabled() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("historyEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHistoryEnabledEnvRejectsUnknownBoolean(t *testing.T) {
	t.Setenv("PACKMON_HISTORY_ENABLED", "maybe")

	_, err := historyEnabled()
	if err == nil {
		t.Fatal("historyEnabled() error = nil, want invalid PACKMON_HISTORY_ENABLED")
	}
	if !strings.Contains(err.Error(), "PACKMON_HISTORY_ENABLED") {
		t.Fatalf("historyEnabled() error = %v, want env var name", err)
	}
}

func TestHistoryMaxScansPerRepoEnvParsing(t *testing.T) {
	tests := []struct {
		name   string
		env    string
		setEnv bool
		want   int
	}{
		{name: "default", want: defaultMaxScansPerRepo},
		{name: "blank defaults", env: "  ", setEnv: true, want: defaultMaxScansPerRepo},
		{name: "valid", env: "25", setEnv: true, want: 25},
		{name: "zero disables retention", env: "0", setEnv: true, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv("PACKMON_HISTORY_MAX_SCANS_PER_REPO", tt.env)
			}
			got, err := historyMaxScansPerRepo()
			if err != nil {
				t.Fatalf("historyMaxScansPerRepo() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("historyMaxScansPerRepo() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestHistoryMaxScansPerRepoRejectsMalformedOrNegativeEnv(t *testing.T) {
	tests := []struct {
		name string
		env  string
	}{
		{name: "malformed integer", env: "many"},
		{name: "negative retention", env: "-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PACKMON_HISTORY_MAX_SCANS_PER_REPO", tt.env)

			_, err := historyMaxScansPerRepo()
			if err == nil {
				t.Fatal("historyMaxScansPerRepo() error = nil, want invalid PACKMON_HISTORY_MAX_SCANS_PER_REPO")
			}
			if !strings.Contains(err.Error(), "PACKMON_HISTORY_MAX_SCANS_PER_REPO") {
				t.Fatalf("historyMaxScansPerRepo() error = %v, want env var name", err)
			}
		})
	}
}

func TestHistoryMaxAgeEnvParsing(t *testing.T) {
	tests := []struct {
		name   string
		env    string
		setEnv bool
		want   time.Duration
	}{
		{name: "default", want: defaultHistoryMaxAge},
		{name: "blank defaults", env: "  ", setEnv: true, want: defaultHistoryMaxAge},
		{name: "valid duration", env: "48h", setEnv: true, want: 48 * time.Hour},
		{name: "zero disables age retention", env: "0", setEnv: true, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv("PACKMON_HISTORY_MAX_AGE", tt.env)
			}
			got, err := historyMaxAge()
			if err != nil {
				t.Fatalf("historyMaxAge() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("historyMaxAge() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestHistoryMaxAgeRejectsMalformedOrNegativeEnv(t *testing.T) {
	tests := []struct {
		name string
		env  string
	}{
		{name: "malformed duration", env: "many"},
		{name: "negative duration", env: "-1h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PACKMON_HISTORY_MAX_AGE", tt.env)

			_, err := historyMaxAge()
			if err == nil {
				t.Fatal("historyMaxAge() error = nil, want invalid PACKMON_HISTORY_MAX_AGE")
			}
			if !strings.Contains(err.Error(), "PACKMON_HISTORY_MAX_AGE") {
				t.Fatalf("historyMaxAge() error = %v, want env var name", err)
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

func TestScanRepoMetadataTimesOutGitProbe(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}

	originalGitCommandOutput := gitCommandOutput
	originalGitMetadataTimeout := gitMetadataTimeout
	t.Cleanup(func() {
		gitCommandOutput = originalGitCommandOutput
		gitMetadataTimeout = originalGitMetadataTimeout
	})

	gitMetadataTimeout = time.Hour
	calls := 0
	sawDeadline := false
	gitCommandOutput = func(ctx context.Context, args ...string) ([]byte, error) {
		calls++
		_, sawDeadline = ctx.Deadline()
		return nil, context.DeadlineExceeded
	}

	repoName, branch, commit := scanRepoMetadata(repoDir)
	if repoName != "repo" || branch != "" || commit != "" {
		t.Fatalf("scanRepoMetadata(timeout) = %q, %q, %q; want fallback repo name only", repoName, branch, commit)
	}
	if !sawDeadline {
		t.Fatal("git command context had no deadline")
	}
	if calls != 1 {
		t.Fatalf("git command calls = %d, want only root probe after timeout", calls)
	}
}

func runLocalHistoryGit(t *testing.T, dir string, args ...string) {
	t.Helper()

	cmd := exec.Command("git", args...) // #nosec G204 -- test helper invokes fixed git binary with test-controlled arguments.
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
	commit := "0123456789abcdef0123456789abcdef01234567"
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

	if err := recordScanHistoryWithRepo(context.Background(), store, &domain.RepoInfo{Name: "app", Branch: "main", Commit: commit}, result); err != nil {
		t.Fatalf("record scan history: %v", err)
	}

	var repoName, branch, storedCommit, idsJSON, severitiesJSON string
	var packagesCount, findingsCount int
	if err := store.DB().QueryRowContext(context.Background(), `
		SELECT repo_name, branch, "commit", packages_count, findings_count, finding_ids, finding_severities
		FROM scan_history`).Scan(&repoName, &branch, &storedCommit, &packagesCount, &findingsCount, &idsJSON, &severitiesJSON); err != nil {
		t.Fatalf("read scan history: %v", err)
	}
	if repoName != "app" || packagesCount != 2 || findingsCount != 2 {
		t.Fatalf("history row = repo %q packages %d findings %d", repoName, packagesCount, findingsCount)
	}
	if branch != "main" || storedCommit != commit {
		t.Fatalf("history row branch/commit = %q/%q, want main/%s", branch, storedCommit, commit)
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
