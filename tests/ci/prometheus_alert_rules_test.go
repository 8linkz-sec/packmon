package ci

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const promtoolUnavailable = "promtool is not installed; skipping Prometheus starter rule evaluation"

func TestPrometheusStarterRulesWithPromtool(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	fixtureRel := filepath.Join("tests", "ci", "testdata", "prometheus", "packmon-alerts.test.yml")
	fixturePath := filepath.Join(root, fixtureRel)
	fixtureData, err := os.ReadFile(fixturePath) //nolint:gosec // fixed repository test fixture path.
	if err != nil {
		t.Fatalf("read %s: %v", filepath.ToSlash(fixtureRel), err)
	}
	if len(fixtureData) == 0 {
		t.Fatalf("%s is empty", filepath.ToSlash(fixtureRel))
	}
	var fixture any
	if err := yaml.Unmarshal(fixtureData, &fixture); err != nil {
		t.Fatalf("parse %s: %v", filepath.ToSlash(fixtureRel), err)
	}

	if output, err := gitTrackedFixture(root, fixtureRel); err != nil {
		t.Fatalf("%s must be tracked by git: %v\n%s", filepath.ToSlash(fixtureRel), err, output)
	}

	promtool, err := exec.LookPath("promtool")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip(promtoolUnavailable)
		}
		t.Fatalf("find promtool: %v", err)
	}

	check := exec.Command(promtool, "check", "rules", filepath.ToSlash(filepath.Join("docs", "monitoring", "packmon-alerts.yml")))
	check.Dir = root
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("promtool check rules failed: %v\n%s", err, output)
	}

	testRules := exec.Command(promtool, "test", "rules", filepath.Base(fixturePath))
	testRules.Dir = filepath.Dir(fixturePath)
	if output, err := testRules.CombinedOutput(); err != nil {
		t.Fatalf("promtool test rules failed: %v\n%s", err, output)
	}
}

func gitTrackedFixture(root, fixtureRel string) ([]byte, error) {
	args := []string{"ls-files", "--error-unmatch", "--", filepath.ToSlash(fixtureRel)}
	tracked := exec.Command("git", args...)
	tracked.Dir = root
	output, err := tracked.CombinedOutput()
	if err == nil || runtime.GOOS != "linux" {
		return output, err
	}

	gitFile, readErr := os.ReadFile(filepath.Join(root, ".git")) //nolint:gosec // fixed repository metadata path.
	if readErr != nil {
		return output, err
	}
	gitDir := strings.TrimSpace(strings.TrimPrefix(string(gitFile), "gitdir:"))
	if len(gitDir) < 4 || gitDir[1] != ':' || gitDir[2] != '/' {
		return output, err
	}
	gitDir = filepath.Join("/mnt", strings.ToLower(gitDir[:1]), filepath.FromSlash(gitDir[3:]))
	tracked = exec.Command("git", append([]string{"--git-dir", gitDir, "--work-tree", root}, args...)...)
	tracked.Dir = root
	return tracked.CombinedOutput()
}
