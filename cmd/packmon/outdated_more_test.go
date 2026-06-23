package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestOutdatedDoesNotDependOnListAllPrivatePackageHelpers(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(token.NewFileSet(), "outdated.go", nil, 0)
	if err != nil {
		t.Fatalf("parse outdated.go: %v", err)
	}

	forbidden := map[string]struct{}{
		"listAllLatest":            {},
		"listAllPackage":           {},
		"listAllPackageScope":      {},
		"listAllPackageRelation":   {},
		"listAllPackageFlags":      {},
		"outdatedAsListAllPackage": {},
	}
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if ok {
			if _, forbidden := forbidden[ident.Name]; forbidden {
				found = append(found, ident.Name)
			}
		}
		return true
	})
	if len(found) > 0 {
		t.Fatalf("outdated.go still depends on list-all private helpers/types: %v", found)
	}
}

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
	if got := swiftPMGitRemote("github.com/apple/swift-nio.git"); got != "https://github.com/apple/swift-nio.git" {
		t.Fatalf("swiftPMGitRemote(.git) = %q", got)
	}
	for _, raw := range []string{
		"--upload-pack=/tmp/payload://example.test/repo",
		"-host/owner/repo",
		"apple/swift-nio.git",
		"https://",
		"https://example.test/repo",
		"file:///tmp/repo.git",
	} {
		if got := swiftPMGitRemote(raw); got != "" {
			t.Fatalf("swiftPMGitRemote(%q) = %q, want empty unsafe remote", raw, got)
		}
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

func TestSwiftPMLatestRejectsNonCanonicalPackageIdentities(t *testing.T) {
	resolver := packageUpdateResolver{
		gitRemoteTags: func(_ context.Context, remote string) ([]string, error) {
			if remote != "https://github.com/Alamofire/Alamofire.git" {
				t.Fatalf("unexpected git remote for SwiftPM lookup: %s", remote)
			}
			return []string{"1.0.0", "2.0.0"}, nil
		},
	}

	if got := resolver.fetchSwiftPMLatest(context.Background(), "github.com/Alamofire/Alamofire"); got != "2.0.0" {
		t.Fatalf("fetchSwiftPMLatest(canonical) = %q, want 2.0.0", got)
	}

	for _, raw := range []string{
		"https://github.com/Alamofire/Alamofire.git",
		"ssh://github.com/Alamofire/Alamofire.git",
		"file:///tmp/Alamofire.git",
		"git@github.com:Alamofire/Alamofire.git",
		"127.0.0.1/Alamofire/Alamofire",
		"localhost/Alamofire/Alamofire",
		"internal.example.test/Alamofire/Alamofire",
		"github.com/Alamofire",
	} {
		if got := resolver.fetchSwiftPMLatest(context.Background(), raw); got != "" {
			t.Fatalf("fetchSwiftPMLatest(%q) = %q, want empty", raw, got)
		}
	}
}

func TestOutdatedRegistryAndGitErrorBranches(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() {
		registryClient = originalClient
	})

	errorResolver := packageUpdateResolver{
		gitRemoteTags: func(context.Context, string) ([]string, error) {
			return nil, errors.New("git down")
		},
	}
	if got := errorResolver.fetchGitLatest(context.Background(), "https://example.test/repo.git", domain.EcosystemSwiftPM); got != "" {
		t.Fatalf("fetchGitLatest(error) = %q, want empty", got)
	}
	successResolver := packageUpdateResolver{
		gitRemoteTags: func(context.Context, string) ([]string, error) {
			return []string{"1.0.0", "2.0.0"}, nil
		},
	}
	if got := successResolver.fetchGitLatest(context.Background(), "https://example.test/repo.git", domain.EcosystemSwiftPM); got != "2.0.0" {
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
	if err := os.WriteFile(gitPath, []byte(script), 0o700); err != nil { // #nosec G306 -- fake git must be executable for PATH-based test.
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

func TestGitRemoteTagCommitDereferencesAnnotatedTags(t *testing.T) {
	dir := t.TempDir()
	gitName := "git"
	script := "#!/bin/sh\ncat <<'EOF'\n1111111111111111111111111111111111111111 refs/tags/v1.2.3\n2222222222222222222222222222222222222222 refs/tags/v1.2.3^{}\n3333333333333333333333333333333333333333 refs/tags/v2.0.0\nEOF\n"
	if runtime.GOOS == "windows" {
		gitName = "git.bat"
		script = "@echo off\r\necho 1111111111111111111111111111111111111111 refs/tags/v1.2.3\r\necho 2222222222222222222222222222222222222222 refs/tags/v1.2.3^^{}\r\necho 3333333333333333333333333333333333333333 refs/tags/v2.0.0\r\n"
	}
	gitPath := filepath.Join(dir, gitName)
	if err := os.WriteFile(gitPath, []byte(script), 0o700); err != nil { // #nosec G306 -- fake git must be executable for PATH-based test.
		t.Fatalf("write fake git: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatalf("set PATH: %v", err)
	}

	commit, ok := gitRemoteTagCommit(context.Background(), "https://example.test/repo.git", "v1.2.3")
	if !ok || commit != "2222222222222222222222222222222222222222" {
		t.Fatalf("gitRemoteTagCommit(annotated) = %q, %v; want peeled commit", commit, ok)
	}

	commit, ok = gitRemoteTagCommit(context.Background(), "https://example.test/repo.git", "v2.0.0")
	if !ok || commit != "3333333333333333333333333333333333333333" {
		t.Fatalf("gitRemoteTagCommit(lightweight) = %q, %v; want tag object fallback", commit, ok)
	}

	for _, tt := range []struct {
		remote string
		tag    string
	}{
		{"https://example.test/repo.git", "missing"},
		{"https://example.test/repo.git", "v1.2.3 extra"},
		{"file:///tmp/repo.git", "v1.2.3"},
	} {
		if commit, ok := gitRemoteTagCommit(context.Background(), tt.remote, tt.tag); ok || commit != "" {
			t.Fatalf("gitRemoteTagCommit(%q, %q) = %q, %v; want no commit", tt.remote, tt.tag, commit, ok)
		}
	}
}

func TestGitRemoteTagsUsesEndOfOptionsDelimiter(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "git-args.txt")

	gitName := "git"
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PACKMON_FAKE_GIT_ARGS\"\ncat <<'EOF'\nabc refs/tags/v1.0.0\nEOF\n"
	if runtime.GOOS == "windows" {
		gitName = "git.bat"
		script = "@echo off\r\n> \"%PACKMON_FAKE_GIT_ARGS%\" (\r\n  echo %1\r\n  echo %2\r\n  echo %3\r\n  echo %4\r\n)\r\necho abc refs/tags/v1.0.0\r\n"
	}

	gitPath := filepath.Join(dir, gitName)
	if err := os.WriteFile(gitPath, []byte(script), 0o700); err != nil { // #nosec G306 -- fake git must be executable for PATH-based test.
		t.Fatalf("write fake git: %v", err)
	}

	oldPath := os.Getenv("PATH")
	oldArgs := os.Getenv("PACKMON_FAKE_GIT_ARGS")
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
		_ = os.Setenv("PACKMON_FAKE_GIT_ARGS", oldArgs)
	})
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	if err := os.Setenv("PACKMON_FAKE_GIT_ARGS", argsPath); err != nil {
		t.Fatalf("set PACKMON_FAKE_GIT_ARGS: %v", err)
	}

	if _, err := gitRemoteTags(context.Background(), "https://example.test/repo.git"); err != nil {
		t.Fatalf("gitRemoteTags() error = %v", err)
	}

	data, err := os.ReadFile(argsPath) // #nosec G304 -- test reads path created in t.TempDir.
	if err != nil {
		t.Fatalf("read fake git args: %v", err)
	}
	got := strings.Fields(string(data))
	want := []string{"ls-remote", "--tags", "--", "https://example.test/repo.git"}
	if len(got) != len(want) {
		t.Fatalf("git args = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("git args = %#v, want %#v", got, want)
		}
	}
}

func TestGitOutputBufferReportsOversizedOutput(t *testing.T) {
	var output gitOutputBuffer
	if _, err := output.Write([]byte(strings.Repeat("x", maxGitCommandOutputBytes+1))); err != nil {
		t.Fatalf("Write returned unexpected error: %v", err)
	}
	if _, err := output.Bytes(); !errors.Is(err, errGitCommandOutputTooLarge) {
		t.Fatalf("Bytes err = %v, want oversized output error", err)
	}
}

func TestGitRemoteTagsPropagatesOversizedOutput(t *testing.T) {
	originalGitCommandOutput := gitCommandOutput
	t.Cleanup(func() { gitCommandOutput = originalGitCommandOutput })

	gitCommandOutput = func(context.Context, ...string) ([]byte, error) {
		return nil, errGitCommandOutputTooLarge
	}
	if _, err := gitRemoteTags(context.Background(), "https://example.test/repo.git"); !errors.Is(err, errGitCommandOutputTooLarge) {
		t.Fatalf("gitRemoteTags err = %v, want oversized output error", err)
	}
}
