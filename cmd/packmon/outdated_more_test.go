package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestOutdatedHelperBranches(t *testing.T) {
	t.Parallel()

	if err := finishOutdatedReport(outdatedOptions{}, outdatedReport{}); err != nil {
		t.Fatalf("finishOutdatedReport(no output) = %v", err)
	}

	parentFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	err := finishOutdatedReport(outdatedOptions{OutputHTML: filepath.Join(parentFile, "outdated.html"), Quiet: true}, outdatedReport{})
	if err == nil || !strings.Contains(err.Error(), "prepare HTML output") {
		t.Fatalf("finishOutdatedReport(parent file) = %v, want prepare HTML error", err)
	}

	if got := swiftPMGitRemote(""); got != "" {
		t.Fatalf("swiftPMGitRemote(empty) = %q, want empty", got)
	}
	if got := swiftPMGitRemote("apple/swift-nio.git"); got != "https://apple/swift-nio.git" {
		t.Fatalf("swiftPMGitRemote(.git) = %q", got)
	}
	if got := swiftPMGitRemote("https://example.test/repo"); got != "https://example.test/repo" {
		t.Fatalf("swiftPMGitRemote(URL) = %q", got)
	}
	if got := fetchGitHubActionLatest(context.Background(), "bad"); got != "" {
		t.Fatalf("fetchGitHubActionLatest(bad) = %q, want empty", got)
	}
	if got := fetchMavenLatest(context.Background(), "bad"); got != "" {
		t.Fatalf("fetchMavenLatest(bad) = %q, want empty", got)
	}
	if got := fetchGitLatest(context.Background(), "not-a-url", domain.EcosystemSwiftPM); got != "" {
		t.Fatalf("fetchGitLatest(invalid remote) = %q, want empty", got)
	}
	if got := selectLatestVersion([]string{"not-a-version", "v1.2.0", "1.10.0"}, domain.EcosystemNPM); got != "1.10.0" {
		t.Fatalf("selectLatestVersion() = %q, want 1.10.0", got)
	}
	for _, raw := range []string{"", "v", "release"} {
		if isVersionLike(raw) {
			t.Fatalf("isVersionLike(%q) = true, want false", raw)
		}
	}
	if !isVersionLike("V2.0.0") {
		t.Fatal("isVersionLike(V2.0.0) = false, want true")
	}
}

func TestOutdatedRegistryAndGitErrorBranches(t *testing.T) {
	originalClient := registryClient
	originalGitRemoteTags := gitRemoteTagsFn
	t.Cleanup(func() {
		registryClient = originalClient
		gitRemoteTagsFn = originalGitRemoteTags
	})

	gitRemoteTagsFn = func(context.Context, string) ([]string, error) {
		return nil, errors.New("git down")
	}
	if got := fetchGitLatest(context.Background(), "https://example.test/repo.git", domain.EcosystemSwiftPM); got != "" {
		t.Fatalf("fetchGitLatest(error) = %q, want empty", got)
	}
	gitRemoteTagsFn = func(context.Context, string) ([]string, error) {
		return []string{"1.0.0", "2.0.0"}, nil
	}
	if got := fetchGitLatest(context.Background(), "https://example.test/repo.git", domain.EcosystemSwiftPM); got != "2.0.0" {
		t.Fatalf("fetchGitLatest(success) = %q, want 2.0.0", got)
	}

	if _, err := registryGet(context.Background(), "://bad-url"); err == nil {
		t.Fatal("registryGet(bad URL) error = nil")
	}
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		key := req.URL.Host + req.URL.EscapedPath()
		responses := map[string]string{
			"hex.pm/api/packages/jason":                       `{"latest_version":"1.5.0"}`,
			"repo.packagist.org/p2/vendor/pkg.json":           `{"packages":{"vendor/pkg":[{"version":"dev-main"},{"version":"1.2.3-dev"}]}}`,
			"cran.r-project.org/web/packages/pkg/DESCRIPTION": "Package: pkg\nTitle: no version\n",
		}
		body, ok := responses[key]
		if !ok {
			t.Fatalf("unexpected registry request %s", req.URL.String())
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
	})}
	if got := fetchHexLatest(context.Background(), "jason"); got != "1.5.0" {
		t.Fatalf("fetchHexLatest(fallback) = %q, want 1.5.0", got)
	}
	if got := fetchPackagistLatest(context.Background(), "vendor/pkg"); got != "" {
		t.Fatalf("fetchPackagistLatest(dev-only) = %q, want empty", got)
	}
	if got := fetchCRANLatest(context.Background(), "pkg"); got != "" {
		t.Fatalf("fetchCRANLatest(no version) = %q, want empty", got)
	}
}

func TestGitRemoteTagsParsesVersionRefsFromGitOutput(t *testing.T) {
	dir := t.TempDir()
	gitName := "git"
	script := "#!/bin/sh\ncat <<'EOF'\nabc refs/tags/v1.0.0\nbadline\ndef refs/tags/not-version\nghi refs/tags/2.0.0^{}\njkl refs/heads/main\nmno refs/tags/1.5.0\nEOF\n"
	if runtime.GOOS == "windows" {
		gitName = "git.bat"
		script = "@echo off\r\necho abc refs/tags/v1.0.0\r\necho badline\r\necho def refs/tags/not-version\r\necho ghi refs/tags/2.0.0^^{}\r\necho jkl refs/heads/main\r\necho mno refs/tags/1.5.0\r\n"
	}
	gitPath := filepath.Join(dir, gitName)
	if err := os.WriteFile(gitPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake git: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatalf("set PATH: %v", err)
	}

	tags, err := gitRemoteTags(context.Background(), "https://example.test/repo.git")
	if err != nil {
		t.Fatalf("gitRemoteTags() error = %v", err)
	}
	want := []string{"v1.0.0", "1.5.0"}
	if len(tags) != len(want) {
		t.Fatalf("tags = %+v, want %+v", tags, want)
	}
	for i := range want {
		if tags[i] != want[i] {
			t.Fatalf("tags = %+v, want %+v", tags, want)
		}
	}
}
