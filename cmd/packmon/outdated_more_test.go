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
	"sync/atomic"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/scanner"
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

func TestOutdatedKeepsSharedUpdateLookupOutOfCommandFlow(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(token.NewFileSet(), "outdated.go", nil, 0)
	if err != nil {
		t.Fatalf("parse outdated.go: %v", err)
	}

	forbiddenFunctions := map[string]struct{}{
		"fetchLatestVersionFromRegistry": {},
		"publicLatestLookupAllowed":      {},
	}
	var foundFunctions []string
	var ecosystemCaseDispatches int
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Name != nil {
				if _, forbidden := forbiddenFunctions[node.Name.Name]; forbidden {
					foundFunctions = append(foundFunctions, node.Name.Name)
				}
			}
		case *ast.CaseClause:
			for _, expr := range node.List {
				if selector, ok := expr.(*ast.SelectorExpr); ok {
					if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == "domain" && strings.HasPrefix(selector.Sel.Name, "Ecosystem") {
						ecosystemCaseDispatches++
					}
				}
			}
		}
		return true
	})
	if len(foundFunctions) > 0 {
		t.Fatalf("outdated.go still owns shared update lookup functions: %v", foundFunctions)
	}
	if ecosystemCaseDispatches > 0 {
		t.Fatalf("outdated.go still dispatches ecosystem-specific update lookup policy; found %d domain.Ecosystem case clauses", ecosystemCaseDispatches)
	}
}

func TestCollectOutdatedPackagesDeduplicatesAndCopiesMetadata(t *testing.T) {
	t.Parallel()

	collection := &scanner.PackageCollection{
		Entries: []scanner.CollectedPackage{
			{
				Package: domain.Package{
					Name:       "zeta",
					Version:    "1.0.0",
					Ecosystem:  domain.EcosystemNPM,
					Direct:     true,
					Via:        []string{"root"},
					Parents:    []domain.PackageParent{{Name: "root", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}},
					SourceRefs: []string{"https://registry.npmjs.org/zeta/-/zeta-1.0.0.tgz"},
				},
				SourceFile: "package-lock.json",
				SourceType: "lockfile",
			},
			{
				Package: domain.Package{
					Name:      "zeta",
					Version:   "1.0.0",
					Ecosystem: domain.EcosystemNPM,
				},
				SourceFile: "bom.cdx.json",
				SourceType: "sbom",
			},
			{
				Package: domain.Package{
					Name:      "alpha",
					Version:   "0.9.0",
					Ecosystem: domain.EcosystemGo,
					Indirect:  true,
				},
				SourceFile: "go.sum",
				SourceType: "lockfile",
			},
		},
		LockFiles: 1,
		SBOMFiles: 1,
	}

	packages, err := collectOutdatedPackages(collection)
	if err != nil {
		t.Fatalf("collectOutdatedPackages() error = %v", err)
	}
	if len(packages) != 2 {
		t.Fatalf("packages = %d, want 2: %+v", len(packages), packages)
	}
	if packages[0].Name != "zeta" || packages[0].LockFile != "package-lock.json" || packages[0].SourceType != "lockfile" {
		t.Fatalf("first package = %+v, want zeta from lockfile", packages[0])
	}
	if packages[1].Name != "alpha" || packages[1].LockFile != "go.sum" {
		t.Fatalf("second package = %+v, want alpha from go.sum", packages[1])
	}

	collection.Entries[0].Package.Via[0] = "mutated"
	collection.Entries[0].Package.Parents[0].Name = "mutated"
	collection.Entries[0].Package.SourceRefs[0] = "https://private.example/zeta.tgz"
	if packages[0].Via[0] != "root" || packages[0].Parents[0].Name != "root" || !strings.Contains(packages[0].SourceRefs[0], "registry.npmjs.org") {
		t.Fatalf("collectOutdatedPackages did not copy package metadata: %+v", packages[0])
	}
}

func TestBuildInitialOutdatedReportCarriesInventoryCounts(t *testing.T) {
	t.Parallel()

	report := buildInitialOutdatedReport("repo", &scanner.PackageCollection{
		LockFiles: 2,
		SBOMFiles: 1,
	})

	if report.Target != "repo" {
		t.Fatalf("Target = %q, want repo", report.Target)
	}
	if report.LockFiles != 2 || report.SBOMFiles != 1 {
		t.Fatalf("source counts = %d lockfiles, %d SBOMs; want 2, 1", report.LockFiles, report.SBOMFiles)
	}
	if report.PackageWord != "packages" {
		t.Fatalf("PackageWord = %q, want packages", report.PackageWord)
	}
	if report.ScannedAt == "" {
		t.Fatal("ScannedAt is empty")
	}
}

func TestResolveOutdatedStatusesUsesConfiguredLatestRegistryFallback(t *testing.T) {
	t.Parallel()

	var called atomic.Bool
	statuses := resolveOutdatedStatuses([]outdatedPackage{{
		Name:      "private",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemHex,
	}}, outdatedOptions{
		Context: context.Background(),
		Timeout: 1,
		LatestRegistry: latestRegistryConfig{
			HexAPIBaseURL:           "https://hex-mirror.example/api",
			HexAPIBaseURLConfigured: true,
		},
		resolver: packageUpdateResolver{
			fetchLatest: func(context.Context, domain.Ecosystem, string) string {
				called.Store(true)
				return "1.2.0"
			},
		},
	})

	if !called.Load() {
		t.Fatal("resolveOutdatedStatuses did not use configured latest registry fallback")
	}
	if len(statuses) != 1 || statuses[0].Latest != "1.2.0" || statuses[0].Update != "yes" {
		t.Fatalf("statuses = %+v, want one outdated status", statuses)
	}
}

func TestApplyOutdatedStatusesToReportCountsAndSorts(t *testing.T) {
	t.Parallel()

	packages := []outdatedPackage{
		{Name: "zeta", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Direct: true, LockFile: "package-lock.json"},
		{Name: "unknown", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, LockFile: "package-lock.json"},
		{Name: "alpha", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Dev: true, Indirect: true, Peer: true, Via: []string{"zeta"}, LockFile: "package-lock.json"},
		{Name: "current", Version: "2.0.0", Ecosystem: domain.EcosystemGo, LockFile: "go.sum"},
	}
	statuses := []packageLatestStatus{
		{Latest: "2.0.0", Update: "yes"},
		{Latest: "unknown", Update: "-", Unknown: true},
		{Latest: "1.1.0", Update: "yes"},
		{Latest: "2.0.0", Update: "-"},
	}

	report := applyOutdatedStatusesToReport(outdatedReport{Target: "repo", PackageWord: "packages"}, packages, statuses)

	if report.Total != 4 || report.Unknown != 1 || report.UpToDate != 1 {
		t.Fatalf("summary = total %d, unknown %d, up-to-date %d; want 4, 1, 1", report.Total, report.Unknown, report.UpToDate)
	}
	if len(report.Outdated) != 2 {
		t.Fatalf("Outdated rows = %d, want 2: %+v", len(report.Outdated), report.Outdated)
	}
	if report.Outdated[0].Name != "alpha" || report.Outdated[1].Name != "zeta" {
		t.Fatalf("Outdated rows sorted = %+v, want alpha then zeta", report.Outdated)
	}
	if row := report.Outdated[0]; row.Scope != "dev" || row.Relation != "transitive" || row.Via != "zeta" || row.Flags != "peer" {
		t.Fatalf("alpha row metadata = %+v", row)
	}
}

func TestFinishOutdatedReportAllowsNoOutput(t *testing.T) {
	t.Parallel()

	if err := finishOutdatedReport(outdatedOptions{}, outdatedReport{}); err != nil {
		t.Fatalf("finishOutdatedReport(no output) = %v", err)
	}
}

func TestFinishOutdatedReportReturnsHTMLOutputPreparationErrors(t *testing.T) {
	t.Parallel()

	parentFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	err := finishOutdatedReport(outdatedOptions{OutputHTML: filepath.Join(parentFile, "outdated.html"), Quiet: true}, outdatedReport{})
	if err == nil || !strings.Contains(err.Error(), "prepare HTML output") {
		t.Fatalf("finishOutdatedReport(parent file) = %v, want prepare HTML error", err)
	}
}

func TestSwiftPMGitRemoteNormalizesGitHubShorthandAndRejectsUnsafeRemotes(t *testing.T) {
	t.Parallel()

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
}

func TestOutdatedFetchLatestRejectsMalformedPackageInputs(t *testing.T) {
	t.Parallel()

	if got := fetchGitHubActionLatest(context.Background(), "bad"); got != "" {
		t.Fatalf("fetchGitHubActionLatest(bad) = %q, want empty", got)
	}
	if got := fetchMavenLatest(context.Background(), "bad"); got != "" {
		t.Fatalf("fetchMavenLatest(bad) = %q, want empty", got)
	}
	if got := fetchGitLatest(context.Background(), "not-a-url", domain.EcosystemSwiftPM); got != "" {
		t.Fatalf("fetchGitLatest(invalid remote) = %q, want empty", got)
	}
}

func TestSelectLatestVersionIgnoresNonVersionStrings(t *testing.T) {
	t.Parallel()

	if got := selectLatestVersion([]string{"not-a-version", "v1.2.0", "1.10.0"}, domain.EcosystemNPM); got != "1.10.0" {
		t.Fatalf("selectLatestVersion() = %q, want 1.10.0", got)
	}
}

func TestIsVersionLikeAcceptsVersionPrefixesOnly(t *testing.T) {
	t.Parallel()

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

func TestSwiftPMLatestUsesConfiguredAllowedGitHosts(t *testing.T) {
	var remotes []string
	resolver := packageUpdateResolver{
		latestRegistry: latestRegistryConfig{
			SwiftPMGitAllowedHosts: []string{"git.example.com"},
		},
		gitRemoteTags: func(_ context.Context, remote string) ([]string, error) {
			remotes = append(remotes, remote)
			return []string{"1.0.0", "2.0.0"}, nil
		},
	}

	if got := resolver.fetchSwiftPMLatest(context.Background(), "git.example.com/acme/private-kit"); got != "2.0.0" {
		t.Fatalf("fetchSwiftPMLatest(configured host) = %q, want 2.0.0", got)
	}
	if strings.Join(remotes, "\n") != "https://git.example.com/acme/private-kit.git" {
		t.Fatalf("SwiftPM git remotes = %v, want configured HTTPS remote", remotes)
	}

	blocked := packageUpdateResolver{
		gitRemoteTags: func(_ context.Context, remote string) ([]string, error) {
			t.Fatalf("unexpected git remote without configured host: %s", remote)
			return nil, nil
		},
	}
	if got := blocked.fetchSwiftPMLatest(context.Background(), "git.example.com/acme/private-kit"); got != "" {
		t.Fatalf("fetchSwiftPMLatest(unconfigured host) = %q, want empty", got)
	}
}

func TestNormalizeSwiftPMGitAllowedHostsRejectsUnsafeHosts(t *testing.T) {
	for _, raw := range []string{
		"http://git.example.com",
		"git@example.com",
		"git.example.com/org",
		"git.example.com:8443",
		"127.0.0.1",
		"localhost",
		"-git.example.com",
	} {
		if _, err := normalizeSwiftPMGitAllowedHosts("registries.swiftpm_git_allowed_hosts", []string{raw}); err == nil {
			t.Fatalf("normalizeSwiftPMGitAllowedHosts(%q) error = nil, want rejection", raw)
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
