package main

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	versioncmp "github.com/8linkz-sec/packmon/internal/version"
	semver "github.com/Masterminds/semver/v3"
	"golang.org/x/mod/module"
)

const (
	maxConcurrentRegistryRequests = 10
	// defaultRegistryRequestInterval caps outbound registry traffic at roughly
	// 20 requests per second. Public registries throttle anonymous clients well
	// below the rate an unthrottled worker pool produces, and a throttled scan
	// loses freshness data silently, so trading scan time for complete results
	// is the better default.
	defaultRegistryRequestInterval = 50 * time.Millisecond
	// cratesIORequestInterval mirrors the crates.io crawler policy of one
	// request per second; it drives both the crates.io throttle and the
	// lookup-phase time estimate for cargo packages.
	cratesIORequestInterval = time.Second
	// chocolateyRequestInterval spaces Chocolatey feed requests: the community
	// feed rate-limits anonymous OData clients aggressively, and each package
	// may need one request per configured feed.
	chocolateyRequestInterval        = 500 * time.Millisecond
	maxRegistryResponseSize          = 512 * 1024
	maxRegistryErrorBodyDrain        = 64 * 1024
	maxPackagistRegistryResponseSize = 4 * 1024 * 1024
	maxPyPIRegistryResponseSize      = 16 * 1024 * 1024
)

// lookupSlowCounts counts the packages that serialize behind a dedicated
// per-registry throttle slower than the generic request interval.
type lookupSlowCounts struct {
	Cargo      int
	Chocolatey int
}

func countSlowLookups(ecosystems []domain.Ecosystem) lookupSlowCounts {
	var counts lookupSlowCounts
	for _, eco := range ecosystems {
		switch eco {
		case domain.EcosystemCargo:
			counts.Cargo++
		case domain.EcosystemChocolatey:
			counts.Chocolatey++
		}
	}
	return counts
}

// announceLookupPhase tells the user up front that a large lookup phase is
// rate-limited work, not a hang. Not trust-changing, so --quiet suppresses it.
func announceLookupPhase(w io.Writer, packageCount, cargoCount int, quiet bool) {
	announceLookupPhaseWithCounts(w, packageCount, lookupSlowCounts{Cargo: cargoCount}, quiet)
}

func announceLookupPhaseWithCounts(w io.Writer, packageCount int, slow lookupSlowCounts, quiet bool) {
	if quiet || packageCount == 0 {
		return
	}
	unit := "packages"
	if packageCount == 1 {
		unit = "package"
	}
	// Cargo and Chocolatey lookups serialize behind their own throttles while
	// everything else runs at the generic interval; the slowest stream
	// dominates the wall-clock estimate.
	estimate := time.Duration(packageCount) * defaultRegistryRequestInterval
	if cargoEstimate := time.Duration(slow.Cargo) * cratesIORequestInterval; cargoEstimate > estimate {
		estimate = cargoEstimate
	}
	if chocoEstimate := time.Duration(slow.Chocolatey) * chocolateyRequestInterval; chocoEstimate > estimate {
		estimate = chocoEstimate
	}
	_, _ = fmt.Fprintf(w, "Looking up latest versions for %d %s (rate-limited, %s)...\n",
		packageCount, unit, humanLookupEstimate(estimate))
}

func humanLookupEstimate(d time.Duration) string {
	if d < time.Minute {
		return "under a minute"
	}
	minutes := int((d + 30*time.Second) / time.Minute)
	if minutes <= 1 {
		return "about 1 minute"
	}
	return fmt.Sprintf("about %d minutes", minutes)
}

type npmRegistryMetadata struct {
	DistTags map[string]string             `json:"dist-tags"`
	Versions map[string]npmVersionManifest `json:"versions"`
}

type npmVersionManifest struct {
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type packageUpdateResolver struct {
	fetchLatest        func(context.Context, domain.Ecosystem, string) string
	fetchNPMMetadata   func(context.Context, string) (npmRegistryMetadata, bool)
	gitRemoteTags      func(context.Context, string) ([]string, error)
	gitRemoteTagCommit func(context.Context, string, string) (string, bool)
	latestRegistry     latestRegistryConfig
}

func (r packageUpdateResolver) withDefaults() packageUpdateResolver {
	r.latestRegistry = r.latestRegistry.withDefaults()
	if r.fetchNPMMetadata == nil {
		npmRegistryBaseURL := r.latestRegistry.NPMRegistryBaseURL
		r.fetchNPMMetadata = func(ctx context.Context, name string) (npmRegistryMetadata, bool) {
			return fetchNPMMetadataFromBase(ctx, npmRegistryBaseURL, name)
		}
	}
	if r.gitRemoteTags == nil {
		r.gitRemoteTags = gitRemoteTags
	}
	if r.gitRemoteTagCommit == nil {
		r.gitRemoteTagCommit = gitRemoteTagCommit
	}
	return r
}

func (r packageUpdateResolver) latestVersion(ctx context.Context, eco domain.Ecosystem, name string) string {
	r = r.withDefaults()
	if r.fetchLatest != nil {
		return r.fetchLatest(ctx, eco, name)
	}
	return r.fetchLatestVersionFromRegistry(ctx, eco, name)
}

func (r packageUpdateResolver) fetchLatestVersionFromRegistry(ctx context.Context, eco domain.Ecosystem, name string) string {
	entry, ok := latestVersionResolverFor(eco)
	if !ok || entry.fetchLatest == nil {
		return ""
	}
	return entry.fetchLatest(ctx, r, name)
}

func (r packageUpdateResolver) npmMetadata(ctx context.Context, name string) (npmRegistryMetadata, bool) {
	r = r.withDefaults()
	return r.fetchNPMMetadata(ctx, name)
}

type packageUpdateLookup struct {
	fetchLatest        func(context.Context, domain.Ecosystem, string) string
	fetchNPMMetadata   func(context.Context, string) (npmRegistryMetadata, bool)
	gitRemoteTagCommit func(context.Context, string, string) (string, bool)
	latestRegistry     latestRegistryConfig
}

func directPackageUpdateLookup() packageUpdateLookup {
	return directPackageUpdateLookupWithResolver(packageUpdateResolver{})
}

func directPackageUpdateLookupWithResolver(resolver packageUpdateResolver) packageUpdateLookup {
	resolver = resolver.withDefaults()
	return packageUpdateLookup{
		fetchLatest:        resolver.latestVersion,
		fetchNPMMetadata:   resolver.npmMetadata,
		gitRemoteTagCommit: resolver.gitRemoteTagCommit,
		latestRegistry:     resolver.latestRegistry,
	}
}

func newCachedPackageUpdateLookupWithResolver(resolver packageUpdateResolver) packageUpdateLookup {
	resolver = resolver.withDefaults()
	cache := &packageUpdateCache{
		latest:              make(map[latestVersionCacheKey]string),
		latestInflight:      make(map[latestVersionCacheKey]*latestVersionCacheCall),
		npmMetadata:         make(map[string]npmMetadataCacheEntry),
		npmMetadataInflight: make(map[string]*npmMetadataCacheCall),
		tagCommits:          make(map[gitTagCommitCacheKey]gitTagCommitCacheEntry),
		tagCommitsInflight:  make(map[gitTagCommitCacheKey]*gitTagCommitCacheCall),
		resolver:            resolver,
	}
	return packageUpdateLookup{
		fetchLatest:        cache.fetchLatestVersion,
		fetchNPMMetadata:   cache.fetchNPMMetadata,
		gitRemoteTagCommit: cache.gitRemoteTagCommit,
		latestRegistry:     resolver.latestRegistry,
	}
}

type latestVersionCacheKey struct {
	ecosystem domain.Ecosystem
	name      string
}

type latestVersionCacheCall struct {
	done  chan struct{}
	value string
}

type npmMetadataCacheEntry struct {
	value npmRegistryMetadata
	ok    bool
}

type npmMetadataCacheCall struct {
	done  chan struct{}
	value npmRegistryMetadata
	ok    bool
}

type packageUpdateCache struct {
	mu                  sync.Mutex
	latest              map[latestVersionCacheKey]string
	latestInflight      map[latestVersionCacheKey]*latestVersionCacheCall
	npmMetadata         map[string]npmMetadataCacheEntry
	npmMetadataInflight map[string]*npmMetadataCacheCall
	tagCommits          map[gitTagCommitCacheKey]gitTagCommitCacheEntry
	tagCommitsInflight  map[gitTagCommitCacheKey]*gitTagCommitCacheCall
	resolver            packageUpdateResolver
}

type gitTagCommitCacheKey struct {
	remote string
	tag    string
}

type gitTagCommitCacheEntry struct {
	commit string
	ok     bool
}

type gitTagCommitCacheCall struct {
	done   chan struct{}
	commit string
	ok     bool
}

// gitRemoteTagCommit memoizes tag-to-commit dereferences per (remote, tag) so
// the same SHA-pinned action referenced from several workflows costs one
// `git ls-remote`, and concurrent callers share one in-flight invocation.
func (c *packageUpdateCache) gitRemoteTagCommit(ctx context.Context, remote, tag string) (string, bool) {
	key := gitTagCommitCacheKey{remote: remote, tag: tag}

	c.mu.Lock()
	if entry, ok := c.tagCommits[key]; ok {
		c.mu.Unlock()
		return entry.commit, entry.ok
	}
	if call, ok := c.tagCommitsInflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.commit, call.ok
		case <-ctx.Done():
			return "", false
		}
	}
	call := &gitTagCommitCacheCall{done: make(chan struct{})}
	c.tagCommitsInflight[key] = call
	c.mu.Unlock()

	commit, ok := c.resolver.gitRemoteTagCommit(ctx, remote, tag)

	c.mu.Lock()
	call.commit = commit
	call.ok = ok
	c.tagCommits[key] = gitTagCommitCacheEntry{commit: commit, ok: ok}
	delete(c.tagCommitsInflight, key)
	close(call.done)
	c.mu.Unlock()
	return commit, ok
}

func (c *packageUpdateCache) fetchLatestVersion(ctx context.Context, eco domain.Ecosystem, name string) string {
	key := latestVersionCacheKey{ecosystem: eco, name: name}

	c.mu.Lock()
	if value, ok := c.latest[key]; ok {
		c.mu.Unlock()
		return value
	}
	if call, ok := c.latestInflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.value
		case <-ctx.Done():
			return ""
		}
	}
	call := &latestVersionCacheCall{done: make(chan struct{})}
	c.latestInflight[key] = call
	c.mu.Unlock()

	value := c.resolver.latestVersion(ctx, eco, name)

	c.mu.Lock()
	call.value = value
	c.latest[key] = value
	delete(c.latestInflight, key)
	close(call.done)
	c.mu.Unlock()
	return value
}

func (c *packageUpdateCache) fetchNPMMetadata(ctx context.Context, name string) (npmRegistryMetadata, bool) {
	key := strings.TrimSpace(name)

	c.mu.Lock()
	if entry, ok := c.npmMetadata[key]; ok {
		c.mu.Unlock()
		return entry.value, entry.ok
	}
	if call, ok := c.npmMetadataInflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.value, call.ok
		case <-ctx.Done():
			return npmRegistryMetadata{}, false
		}
	}
	call := &npmMetadataCacheCall{done: make(chan struct{})}
	c.npmMetadataInflight[key] = call
	c.mu.Unlock()

	value, ok := c.resolver.npmMetadata(ctx, name)

	c.mu.Lock()
	call.value = value
	call.ok = ok
	c.npmMetadata[key] = npmMetadataCacheEntry{value: value, ok: ok}
	delete(c.npmMetadataInflight, key)
	close(call.done)
	c.mu.Unlock()
	return value, ok
}

func resolveOutdatedLatestWithLookup(ctx context.Context, p outdatedPackage, lookup packageUpdateLookup) packageLatestStatus {
	if !latestLookupAllowed(p.Ecosystem, p.SourceRefs, lookup) {
		return unknownLatestStatus()
	}
	return resolvePackageUpdateStatusWithLookup(ctx, packageUpdateQuery{
		name:      p.Name,
		installed: p.Version,
		declared:  p.DeclaredVersion,
		ecosystem: p.Ecosystem,
		direct:    p.Direct,
		parents:   p.Parents,
	}, lookup)
}

// packageUpdateQuery describes one installed package whose latest version and
// update status should be resolved.
type packageUpdateQuery struct {
	name      string
	installed string
	// declared is the optional human-readable version hint that accompanies an
	// opaque pin (for example the "# v4.2.2" comment on a SHA-pinned GitHub
	// Action). Empty when the source did not provide one.
	declared  string
	ecosystem domain.Ecosystem
	direct    bool
	parents   []domain.PackageParent
}

func resolvePackageUpdateStatusWithLookup(ctx context.Context, q packageUpdateQuery, lookup packageUpdateLookup) packageLatestStatus {
	latest := lookup.fetchLatest(ctx, q.ecosystem, q.name)
	if latest == "" {
		return failedLatestStatus()
	}
	target := latest
	if q.ecosystem == domain.EcosystemNPM && !q.direct && len(q.parents) > 0 {
		if wanted := resolveNPMWantedVersionWithLookup(ctx, q.name, q.installed, latest, q.parents, lookup); wanted != "" {
			target = wanted
		}
	}
	if q.ecosystem == domain.EcosystemGitHubActions && versioncmp.IsGitCommitSHA(q.installed) {
		return resolveGitHubActionSHAPinStatus(ctx, q, target, lookup.gitRemoteTagCommit)
	}
	if updateAvailable(q.installed, target, q.ecosystem) {
		return packageLatestStatus{Latest: target, Update: "yes"}
	}
	return packageLatestStatus{Latest: target, Update: "-"}
}

// resolveGitHubActionSHAPinStatus decides the update status of a GitHub
// Action pinned by commit SHA. A SHA is never fed to the version comparator
// (its leading hex digits would be misread as a version number). When the
// workflow carries a declared version hint at least as precise as the latest
// tag, that hint decides without any git traffic. Otherwise the pin is
// compared against the dereferenced latest tag commit: equal means current,
// different means an update is available, and an unresolvable tag leaves the
// status unknown rather than guessing.
func resolveGitHubActionSHAPinStatus(ctx context.Context, q packageUpdateQuery, target string, resolveTagCommit func(context.Context, string, string) (string, bool)) packageLatestStatus {
	if declared := strings.TrimSpace(q.declared); declared != "" && versionPrecision(declared) >= versionPrecision(target) {
		if updateAvailable(declared, target, q.ecosystem) {
			return packageLatestStatus{Latest: target, Update: "yes"}
		}
		return packageLatestStatus{Latest: target, Update: "-"}
	}
	commit, ok := githubActionTagCommit(ctx, q.name, target, resolveTagCommit)
	if !ok {
		return packageLatestStatus{Latest: target, Update: "unknown", Unknown: true}
	}
	if gitSHAMatches(q.installed, commit) {
		return packageLatestStatus{Latest: target, Update: "-"}
	}
	return packageLatestStatus{Latest: target, Update: "yes"}
}

// versionPrecision counts the numeric components of a version string
// ("v4" -> 1, "v4.2.2" -> 3) so a coarse declared hint is not mistaken for a
// definitive comparison against a finer-grained latest tag.
func versionPrecision(version string) int {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if idx := strings.IndexAny(version, "-+"); idx >= 0 {
		version = version[:idx]
	}
	if version == "" {
		return 0
	}
	return len(strings.Split(version, "."))
}

func unknownLatestStatus() packageLatestStatus {
	return packageLatestStatus{Latest: "unknown", Update: "-", Unknown: true}
}

// failedLatestStatus marks a row whose latest version stayed unknown because
// the lookup did not produce one. Whether that was a refusal or a definitive
// "no such package" is tracked per request by registryLookupPhase, not per
// row -- a 404 and a 429 are indistinguishable at this level.
func failedLatestStatus() packageLatestStatus {
	return unknownLatestStatus()
}

func latestLookupAllowed(eco domain.Ecosystem, refs []string, lookup packageUpdateLookup) bool {
	if latestRegistryMirrorConfigured(lookup.latestRegistry.withDefaults(), eco) {
		return true
	}
	return publicLatestLookupAllowed(eco, refs)
}

func publicLatestLookupAllowed(eco domain.Ecosystem, refs []string) bool {
	entry, ok := latestVersionResolverFor(eco)
	if !ok {
		return true
	}
	return entry.publicLookupAllowedForSourceRefs(refs)
}

func (e latestVersionResolverEntry) publicLookupAllowedForSourceRefs(refs []string) bool {
	refs = normalizedSourceRefs(refs)
	if len(refs) == 0 {
		return e.allowLookupWithoutSourceRefs
	}
	if e.publicLookupAllowed == nil {
		return true
	}
	return e.publicLookupAllowed(refs)
}

func normalizedSourceRefs(refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref != "" {
			out = append(out, ref)
		}
	}
	return out
}

func allSourceRefsMatch(refs []string, allow func(string) bool) bool {
	for _, ref := range refs {
		if !allow(ref) {
			return false
		}
	}
	return true
}

func allowAllPublicSourceRefs([]string) bool {
	return true
}

func sourceRefHost(ref string) string {
	ref = strings.TrimSpace(ref)
	for _, prefix := range []string{"url=", "registry+", "sparse+", "git+"} {
		ref = strings.TrimPrefix(ref, prefix)
	}
	parsed, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func npmPublicLatestLookupAllowed(refs []string) bool {
	return allSourceRefsMatch(refs, func(ref string) bool {
		return sourceRefHost(ref) == "registry.npmjs.org"
	})
}

func pyPIPublicLatestLookupAllowed(refs []string) bool {
	return allSourceRefsMatch(refs, func(ref string) bool {
		host := sourceRefHost(ref)
		return host == "pypi.org" || host == "files.pythonhosted.org"
	})
}

func cargoPublicLatestLookupAllowed(refs []string) bool {
	return allSourceRefsMatch(refs, func(ref string) bool {
		ref = strings.TrimPrefix(strings.TrimPrefix(ref, "registry+"), "sparse+")
		return ref == "https://github.com/rust-lang/crates.io-index" || ref == "https://index.crates.io/"
	})
}

func gemPublicLatestLookupAllowed(refs []string) bool {
	return allSourceRefsMatch(refs, func(ref string) bool {
		return sourceRefHost(ref) == "rubygems.org"
	})
}

func cocoaPodsPublicLatestLookupAllowed(refs []string) bool {
	return allSourceRefsMatch(refs, func(ref string) bool {
		ref = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ref)), "/")
		return ref == "trunk" ||
			ref == "https://github.com/cocoapods/specs.git" ||
			ref == "https://github.com/cocoapods/specs"
	})
}

func composerPublicLatestLookupAllowed(refs []string) bool {
	return allSourceRefsMatch(refs, func(ref string) bool {
		switch sourceRefHost(ref) {
		case "repo.packagist.org", "packagist.org", "api.github.com", "github.com", "gitlab.com", "bitbucket.org":
			return true
		default:
			return false
		}
	})
}

func mavenPublicLatestLookupAllowed(refs []string) bool {
	return allSourceRefsMatch(refs, func(ref string) bool {
		switch sourceRefHost(ref) {
		case "repo.maven.apache.org", "repo1.maven.org", "search.maven.org":
			return true
		default:
			return false
		}
	})
}

func hexPublicLatestLookupAllowed(refs []string) bool {
	return allSourceRefsMatch(refs, func(ref string) bool {
		return strings.EqualFold(strings.TrimSpace(ref), "repo=hexpm")
	})
}

func nuGetPublicLatestLookupAllowed(refs []string) bool {
	return allSourceRefsMatch(refs, func(ref string) bool {
		switch sourceRefHost(ref) {
		case "api.nuget.org", "www.nuget.org":
			return true
		default:
			return false
		}
	})
}

func cranSourceRefsAllowPublicLookup(refs []string) bool {
	sourceOK := false
	repositoryOK := false
	for _, ref := range refs {
		normalized := strings.ToLower(strings.TrimSpace(ref))
		switch {
		case strings.HasPrefix(normalized, "source="):
			if normalized != "source=repository" {
				return false
			}
			sourceOK = true
		case strings.HasPrefix(normalized, "repository="):
			if normalized != "repository=cran" {
				return false
			}
			repositoryOK = true
		default:
			return false
		}
	}
	return sourceOK && repositoryOK
}

func pubSourceRefsAllowPublicLookup(refs []string) bool {
	for _, ref := range refs {
		normalized := strings.ToLower(strings.TrimSpace(ref))
		switch {
		case strings.HasPrefix(normalized, "source="):
			if normalized != "source=hosted" {
				return false
			}
		case strings.HasPrefix(normalized, "url="):
			host := sourceRefHost(ref)
			if host != "pub.dev" && host != "pub.dartlang.org" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// githubActionTagCommit dereferences tag on the action's GitHub repository
// to a commit SHA. ok is false when the remote is unsafe or the tag could not
// be resolved, which callers must treat as "unknown", not as a mismatch.
func githubActionTagCommit(ctx context.Context, name, tag string, resolveTagCommit func(context.Context, string, string) (string, bool)) (string, bool) {
	if resolveTagCommit == nil {
		resolveTagCommit = gitRemoteTagCommit
	}
	remote := githubActionRemote(name)
	if remote == "" {
		return "", false
	}
	commit, ok := resolveTagCommit(ctx, remote, tag)
	if !ok || !isLikelyGitSHA(commit) {
		return "", false
	}
	return commit, true
}

func githubActionRemote(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) != 2 || !safeGitPathComponent(parts[0]) || !safeGitPathComponent(parts[1]) {
		return ""
	}
	endpoint := url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   "/" + parts[0] + "/" + parts[1] + ".git",
	}
	return endpoint.String()
}

func safeGitPathComponent(part string) bool {
	return part != "" &&
		strings.TrimSpace(part) == part &&
		part != "." &&
		part != ".." &&
		!strings.ContainsAny(part, " \t\r\n\x00\\?#@:")
}

func isLikelyGitSHA(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 7 || len(value) > 64 {
		return false
	}
	for _, ch := range value {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			continue
		}
		return false
	}
	return true
}

func gitSHAMatches(installed, commit string) bool {
	installed = strings.ToLower(strings.TrimSpace(installed))
	commit = strings.ToLower(strings.TrimSpace(commit))
	return isLikelyGitSHA(installed) && isLikelyGitSHA(commit) && strings.HasPrefix(commit, installed)
}

func resolveNPMWantedVersionWithLookup(ctx context.Context, name, installed, latest string, parents []domain.PackageParent, lookup packageUpdateLookup) string {
	ranges := npmParentDependencyRangesWithLookup(ctx, name, parents, lookup)
	if len(ranges) == 0 {
		return latest
	}

	meta, ok := lookup.fetchNPMMetadata(ctx, name)
	if !ok || len(meta.Versions) == 0 {
		return latest
	}

	wanted := selectNPMWantedVersion(meta.Versions, ranges)
	if wanted == "" {
		return latest
	}
	if versioncmp.Compare(wanted, installed, "ECOSYSTEM", string(domain.EcosystemNPM)) < 0 {
		return installed
	}
	return wanted
}

func npmParentDependencyRangesWithLookup(ctx context.Context, childName string, parents []domain.PackageParent, lookup packageUpdateLookup) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(parents))
	for _, parent := range parents {
		if parent.Ecosystem != "" && parent.Ecosystem != domain.EcosystemNPM {
			continue
		}
		parentName := strings.TrimSpace(parent.Name)
		parentVersion := strings.TrimSpace(parent.Version)
		if parentName == "" || parentVersion == "" {
			continue
		}
		meta, ok := lookup.fetchNPMMetadata(ctx, parentName)
		if !ok {
			continue
		}
		manifest, ok := meta.Versions[parentVersion]
		if !ok {
			continue
		}
		if constraint := npmDependencyConstraint(manifest, childName); constraint != "" {
			if _, duplicate := seen[constraint]; duplicate {
				continue
			}
			seen[constraint] = struct{}{}
			out = append(out, constraint)
		}
	}
	sort.Strings(out)
	return out
}

func npmDependencyConstraint(manifest npmVersionManifest, childName string) string {
	for _, deps := range []map[string]string{
		manifest.Dependencies,
		manifest.OptionalDependencies,
		manifest.PeerDependencies,
	} {
		if constraint := strings.TrimSpace(deps[childName]); constraint != "" {
			return constraint
		}
	}
	return ""
}

func selectNPMWantedVersion(versions map[string]npmVersionManifest, ranges []string) string {
	constraints, ok := compileNPMVersionConstraints(ranges)
	if !ok {
		return ""
	}

	best := ""
	for version := range versions {
		if !isVersionLike(version) || !npmVersionSatisfiesAll(version, constraints) {
			continue
		}
		if best == "" || versioncmp.Compare(version, best, "ECOSYSTEM", string(domain.EcosystemNPM)) > 0 {
			best = version
		}
	}
	return best
}

func compileNPMVersionConstraints(ranges []string) ([]*semver.Constraints, bool) {
	constraints := make([]*semver.Constraints, 0, len(ranges))
	for _, raw := range ranges {
		constraint, err := semver.NewConstraint(raw)
		if err != nil {
			return nil, false
		}
		constraints = append(constraints, constraint)
	}
	return constraints, true
}

func npmVersionSatisfiesAll(version string, constraints []*semver.Constraints) bool {
	parsed, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	for _, constraint := range constraints {
		if !constraint.Check(parsed) {
			return false
		}
	}
	return true
}

func resolveLatestWithWorkerPool[T any](ctx context.Context, items []T, resolve func(context.Context, T) packageLatestStatus) []packageLatestStatus {
	results := make([]packageLatestStatus, len(items))
	for i := range results {
		// Items the pool never reaches -- a cancelled or timed-out scan --
		// are unresolved lookups, not deliberate skips.
		results[i] = failedLatestStatus()
	}
	workerCount := latestLookupWorkerCount(len(items))
	if workerCount == 0 {
		return results
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					continue
				}
				func() {
					defer func() {
						if recover() != nil {
							results[idx] = failedLatestStatus()
						}
					}()
					results[idx] = resolve(ctx, items[idx])
				}()
			}
		}()
	}

sendJobs:
	for idx := range items {
		select {
		case jobs <- idx:
		case <-ctx.Done():
			break sendJobs
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func latestLookupWorkerCount(itemCount int) int {
	if itemCount <= 0 {
		return 0
	}
	if itemCount < maxConcurrentRegistryRequests {
		return itemCount
	}
	return maxConcurrentRegistryRequests
}

func updateAvailable(installed, latest string, ecosystem domain.Ecosystem) bool {
	return versioncmp.Compare(latest, installed, "ECOSYSTEM", string(ecosystem)) > 0
}

// fetchLatestVersion queries the package registry for the latest version.
// Returns "" if the lookup fails or the ecosystem is unsupported.
func fetchLatestVersion(ctx context.Context, eco domain.Ecosystem, name string) string {
	return packageUpdateResolver{}.latestVersion(ctx, eco, name)
}

var (
	defaultRegistryTransport = http.DefaultTransport.(*http.Transport).Clone()
	registryClient           = newRegistryHTTPClient()
)

func newRegistryHTTPClient() *http.Client {
	transport := defaultRegistryTransport.Clone()
	transport.MaxIdleConnsPerHost = maxConcurrentRegistryRequests
	if transport.MaxIdleConns < maxConcurrentRegistryRequests {
		transport.MaxIdleConns = maxConcurrentRegistryRequests
	}
	return &http.Client{Transport: transport}
}

func registryGet(ctx context.Context, url string) ([]byte, error) {
	return registryGetLimited(ctx, url, maxRegistryResponseSize)
}

func registryGetLimited(ctx context.Context, url string, limit int64) ([]byte, error) {
	return registryGetLimitedWithHeaders(ctx, url, limit, nil)
}

func registryGetLimitedWithHeaders(ctx context.Context, url string, limit int64, headers http.Header) ([]byte, error) {
	phase := registryLookupPhaseFrom(ctx)
	if phase.breakerOpen() {
		phase.recordSkipped()
		return nil, fmt.Errorf("lookup skipped: registry failure breaker open after %d consecutive failures", registryBreakerThreshold)
	}
	phaseCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, phase.perRequestTimeout())
		defer cancel()
	}
	// Space every registry request, whatever ecosystem it belongs to. This is
	// the single choke point all latest-version and metadata lookups pass
	// through, so throttling here covers npm, PyPI, Go, Maven, NuGet, Hex and
	// the rest instead of crates.io alone.
	if !registryRequestThrottle.wait(ctx) {
		return nil, fmt.Errorf("registry request cancelled while rate limiting: %w", ctx.Err())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	// Caller-supplied headers replace the defaults of the same name (an XML
	// feed must not receive both an Accept: json and an Accept: xml).
	for name := range headers {
		req.Header.Del(name)
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	// Identify the client unless the caller already supplied its own agent.
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", packmonRegistryUserAgent())
	}

	resp, err := registryClient.Do(req)
	if err != nil {
		// A canceled phase (Ctrl-C) is the user's decision, not a registry
		// failure; only count refusals the registry or network is responsible
		// for, which includes the per-request timeout on a hanging server.
		if phaseCtx.Err() == nil {
			phase.recordRefusal()
		}
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		drainRegistryErrorBody(resp.Body)
		// A 404 is an answer, not a failure: the registry does not carry this
		// package, which is normal for workspace-local and private packages.
		// Everything else -- 429 above all -- means we did not get to ask.
		if resp.StatusCode == http.StatusNotFound {
			phase.recordSuccess()
		} else {
			phase.recordRefusal()
		}
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	phase.recordSuccess()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("registry response exceeds %d byte limit", limit)
	}
	return data, nil
}

func drainRegistryErrorBody(r io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r, maxRegistryErrorBodyDrain))
}

type registryThrottle struct {
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
	now      func() time.Time
	sleep    func(context.Context, time.Duration) bool
}

// registryRequestThrottle spaces every outbound public-registry request. A
// --list-all run over a repository with a four-digit dependency count issues
// one /latest request per package plus one packument request per package and
// per parent; unthrottled that burst trips the registries' abuse protection,
// and because a rejected lookup is indistinguishable from "no data" the
// affected rows silently degrade to an unknown latest version.
//
// cratesIOThrottle stays on top of this for crates.io, whose published crawler
// policy asks for a stricter one-request-per-second rate.
var (
	registryRequestThrottle = newRegistryThrottle(defaultRegistryRequestInterval)
	cratesIOThrottle        = newRegistryThrottle(cratesIORequestInterval)
	chocolateyFeedThrottle  = newRegistryThrottle(chocolateyRequestInterval)
)

func newRegistryThrottle(interval time.Duration) *registryThrottle {
	return &registryThrottle{
		interval: interval,
		now:      time.Now,
		sleep:    sleepWithContext,
	}
}

func (t *registryThrottle) wait(ctx context.Context) bool {
	if t == nil || t.interval <= 0 {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.currentTime()
	if !t.last.IsZero() {
		if wait := t.last.Add(t.interval).Sub(now); wait > 0 {
			if !t.sleepWithContext(ctx, wait) {
				return false
			}
			now = t.currentTime()
		}
	}
	t.last = now
	return true
}

func (t *registryThrottle) currentTime() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

func (t *registryThrottle) sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	if t.sleep != nil {
		return t.sleep(ctx, d)
	}
	return sleepWithContext(ctx, d)
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// npm: GET https://registry.npmjs.org/{name}/latest
func fetchNPMLatest(ctx context.Context, name string) string {
	return fetchNPMLatestFromBase(ctx, defaultNPMRegistryBaseURL, name)
}

func fetchNPMLatestFromBase(ctx context.Context, baseURL, name string) string {
	data, err := registryGet(ctx, registryEndpoint(baseURL, url.PathEscape(name), "latest"))
	if err != nil {
		return ""
	}
	var res struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &res) != nil {
		return ""
	}
	return res.Version
}

func fetchNPMMetadata(ctx context.Context, name string) (npmRegistryMetadata, bool) {
	return fetchNPMMetadataFromBase(ctx, defaultNPMRegistryBaseURL, name)
}

func fetchNPMMetadataFromBase(ctx context.Context, baseURL, name string) (npmRegistryMetadata, bool) {
	data, err := registryGet(ctx, registryEndpoint(baseURL, url.PathEscape(name)))
	if err != nil {
		return npmRegistryMetadata{}, false
	}
	var res npmRegistryMetadata
	if json.Unmarshal(data, &res) != nil {
		return npmRegistryMetadata{}, false
	}
	if len(res.Versions) == 0 {
		return npmRegistryMetadata{}, false
	}
	return res, true
}

// pypi: GET https://pypi.org/pypi/{name}/json
func fetchPyPILatest(ctx context.Context, name string) string {
	return fetchPyPILatestFromBase(ctx, defaultPyPIAPIBaseURL, name)
}

func fetchPyPILatestFromBase(ctx context.Context, baseURL, name string) string {
	data, err := registryGetLimited(ctx, registryEndpoint(baseURL, url.PathEscape(name), "json"), maxPyPIRegistryResponseSize)
	if err != nil {
		return ""
	}
	var res struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if json.Unmarshal(data, &res) != nil {
		return ""
	}
	return res.Info.Version
}

func fetchGoLatestFromBase(ctx context.Context, baseURL, name string) string {
	if strings.EqualFold(strings.TrimSpace(baseURL), "off") {
		return ""
	}
	escaped, err := module.EscapePath(name)
	if err != nil {
		return ""
	}
	data, err := registryGet(ctx, registryEndpoint(baseURL, escaped, "@latest"))
	if err != nil {
		return ""
	}
	var res struct {
		Version string `json:"Version"`
	}
	if json.Unmarshal(data, &res) != nil {
		return ""
	}
	return res.Version
}

// crates: GET https://crates.io/api/v1/crates/{name}
func fetchCratesLatest(ctx context.Context, name string) string {
	return fetchCratesLatestFromBase(ctx, defaultCargoRegistryAPIBaseURL, name)
}

func fetchCratesLatestFromBase(ctx context.Context, baseURL, name string) string {
	if !cratesIOThrottle.wait(ctx) {
		return ""
	}
	headers := http.Header{}
	headers.Set("User-Agent", packmonRegistryUserAgent())
	data, err := registryGetLimitedWithHeaders(ctx, registryEndpoint(baseURL, url.PathEscape(name)), maxRegistryResponseSize, headers)
	if err != nil {
		return ""
	}
	var res struct {
		Crate struct {
			MaxStableVersion string `json:"max_stable_version"`
		} `json:"crate"`
	}
	if json.Unmarshal(data, &res) != nil {
		return ""
	}
	return res.Crate.MaxStableVersion
}

// packmonRegistryUserAgent identifies the client to public registries. Several
// of them throttle anonymous clients harder than identified ones, and crates.io
// requires an identifying agent outright. The server-side feed syncers send the
// equivalent header via feed.FeedSyncUserAgent.
func packmonRegistryUserAgent() string {
	v := strings.TrimSpace(version)
	if v == "" {
		v = "dev"
	}
	return "packmon/" + v + " (+https://github.com/8linkz-sec/packmon)"
}

// nuget: GET https://api.nuget.org/v3-flatcontainer/{name}/index.json
func fetchNuGetLatestFromBase(ctx context.Context, baseURL, name string) string {
	lower := strings.ToLower(name)
	data, err := registryGet(ctx, registryEndpoint(baseURL, url.PathEscape(lower), "index.json"))
	if err != nil {
		return ""
	}
	var res struct {
		Versions []string `json:"versions"`
	}
	if json.Unmarshal(data, &res) != nil || len(res.Versions) == 0 {
		return ""
	}
	return selectLatestNuGetVersion(res.Versions)
}

// chocolatey: GET {feed}/Packages()?$filter=tolower(Id) eq '{id}' and IsLatestVersion
// against each configured NuGet v2 feed in order; the first feed that returns
// an entry wins. Chocolatey feeds compare Id case-sensitively, hence tolower.
func fetchChocolateyLatestFromFeeds(ctx context.Context, feeds []string, name string) string {
	id := strings.ToLower(strings.TrimSpace(name))
	if id == "" || !isChocolateyPackageID(id) {
		return ""
	}
	filter := "tolower(Id) eq '" + id + "' and IsLatestVersion"
	for _, feed := range feeds {
		feed = strings.TrimRight(strings.TrimSpace(feed), "/")
		if feed == "" {
			continue
		}
		if !chocolateyFeedThrottle.wait(ctx) {
			return ""
		}
		// OData servers (notably community.chocolatey.org) do not treat "+" as a
		// space inside $filter, so percent-encode spaces explicitly.
		endpoint := registryEndpoint(feed, "Packages()") + "?$filter=" + strings.ReplaceAll(url.QueryEscape(filter), "+", "%20")
		headers := http.Header{}
		headers.Set("Accept", "application/atom+xml")
		data, err := registryGetLimitedWithHeaders(ctx, endpoint, maxRegistryResponseSize, headers)
		if err != nil {
			continue
		}
		if version := parseChocolateyODataLatestVersion(data); version != "" {
			return version
		}
	}
	return ""
}

func isChocolateyPackageID(id string) bool {
	if id == "" || len(id) > 100 {
		return false
	}
	for i, ch := range id {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
		case i > 0 && (ch == '.' || ch == '-' || ch == '_'):
		default:
			return false
		}
	}
	return true
}

// parseChocolateyODataLatestVersion extracts the highest d:Version from an
// OData Atom feed body; an empty feed yields "".
func parseChocolateyODataLatestVersion(data []byte) string {
	var feed struct {
		Entries []struct {
			Properties struct {
				Version string `xml:"Version"`
			} `xml:"properties"`
		} `xml:"entry"`
	}
	if xml.Unmarshal(data, &feed) != nil {
		return ""
	}
	versions := make([]string, 0, len(feed.Entries))
	for _, entry := range feed.Entries {
		if version := strings.TrimSpace(entry.Properties.Version); version != "" {
			versions = append(versions, version)
		}
	}
	return selectLatestNuGetVersion(versions)
}

func selectLatestNuGetVersion(versions []string) string {
	if len(versions) == 0 {
		return ""
	}

	best := versions[0]
	for _, candidate := range versions[1:] {
		if versioncmp.Compare(candidate, best, "ECOSYSTEM", "NuGet") > 0 {
			best = candidate
		}
	}
	return best
}

// rubygems: GET https://rubygems.org/api/v1/gems/{name}.json
func fetchRubyGemsLatest(ctx context.Context, name string) string {
	return fetchRubyGemsLatestFromBase(ctx, defaultRubyGemsAPIBaseURL, name)
}

func fetchRubyGemsLatestFromBase(ctx context.Context, baseURL, name string) string {
	data, err := registryGet(ctx, registryEndpoint(baseURL, url.PathEscape(name)+".json"))
	if err != nil {
		return ""
	}
	var res struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &res) != nil {
		return ""
	}
	return res.Version
}

// packagist: GET https://repo.packagist.org/p2/{name}.json
func fetchPackagistLatest(ctx context.Context, name string) string {
	return fetchPackagistLatestFromBase(ctx, defaultComposerRepositoryBaseURL, name)
}

func fetchPackagistLatestFromBase(ctx context.Context, baseURL, name string) string {
	endpoint, ok := packagistLatestEndpointFromBase(baseURL, name)
	if !ok {
		return ""
	}
	data, err := registryGetLimited(ctx, endpoint, maxPackagistRegistryResponseSize)
	if err != nil {
		return ""
	}
	var res struct {
		Packages map[string][]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &res) != nil {
		return ""
	}
	for _, versions := range res.Packages {
		for _, v := range versions {
			ver := v.Version
			if strings.HasPrefix(ver, "dev-") || strings.Contains(ver, "-dev") {
				continue
			}
			return ver
		}
	}
	return ""
}

func packagistLatestEndpoint(name string) (string, bool) {
	return packagistLatestEndpointFromBase(defaultComposerRepositoryBaseURL, name)
}

func packagistLatestEndpointFromBase(baseURL, name string) (string, bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	return registryEndpoint(baseURL, url.PathEscape(parts[0]), url.PathEscape(parts[1])+".json"), true
}

// maven: GET https://repo.maven.apache.org/maven2/{group path}/{artifact}/maven-metadata.xml
func fetchMavenLatest(ctx context.Context, name string) string {
	return fetchMavenLatestFromBase(ctx, defaultMavenRepositoryBaseURL, name)
}

func fetchMavenLatestFromBase(ctx context.Context, baseURL, name string) string {
	parts := strings.SplitN(name, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return ""
	}

	group := strings.TrimSpace(parts[0])
	artifact := strings.TrimSpace(parts[1])
	pathParts := make([]string, 0, strings.Count(group, ".")+3)
	for _, part := range strings.Split(group, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			return ""
		}
		pathParts = append(pathParts, url.PathEscape(part))
	}
	pathParts = append(pathParts, url.PathEscape(artifact), "maven-metadata.xml")

	data, err := registryGet(ctx, registryEndpoint(baseURL, pathParts...))
	if err != nil {
		return ""
	}
	var res struct {
		Versioning struct {
			Latest   string   `xml:"latest"`
			Release  string   `xml:"release"`
			Versions []string `xml:"versions>version"`
		} `xml:"versioning"`
	}
	if xml.Unmarshal(data, &res) != nil {
		return ""
	}
	if release := strings.TrimSpace(res.Versioning.Release); release != "" {
		return release
	}
	if latest := strings.TrimSpace(res.Versioning.Latest); latest != "" {
		return latest
	}
	return selectLatestMavenMetadataVersion(res.Versioning.Versions)
}

func selectLatestMavenMetadataVersion(versions []string) string {
	best := ""
	for _, candidate := range versions {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if best == "" || versioncmp.Compare(candidate, best, "ECOSYSTEM", string(domain.EcosystemMaven)) > 0 {
			best = candidate
		}
	}
	return best
}

// pub: GET https://pub.dev/api/packages/{name}
func fetchPubLatestFromBase(ctx context.Context, baseURL, name string) string {
	data, err := registryGet(ctx, registryEndpoint(baseURL, "api", "packages", url.PathEscape(name)))
	if err != nil {
		return ""
	}
	var res struct {
		Latest struct {
			Version string `json:"version"`
		} `json:"latest"`
	}
	if json.Unmarshal(data, &res) != nil {
		return ""
	}
	return res.Latest.Version
}

// hex: GET https://hex.pm/api/packages/{name}
func fetchHexLatest(ctx context.Context, name string) string {
	return fetchHexLatestFromBase(ctx, defaultHexAPIBaseURL, name)
}

func fetchHexLatestFromBase(ctx context.Context, baseURL, name string) string {
	data, err := registryGet(ctx, registryEndpoint(baseURL, "packages", url.PathEscape(name)))
	if err != nil {
		return ""
	}
	var res struct {
		LatestStableVersion string `json:"latest_stable_version"`
		LatestVersion       string `json:"latest_version"`
	}
	if json.Unmarshal(data, &res) != nil {
		return ""
	}
	if res.LatestStableVersion != "" {
		return res.LatestStableVersion
	}
	return res.LatestVersion
}

// cran: GET https://cran.r-project.org/web/packages/{name}/DESCRIPTION
func fetchCRANLatest(ctx context.Context, name string) string {
	return fetchCRANLatestFromBase(ctx, defaultCRANMirrorURL, name)
}

func fetchCRANLatestFromBase(ctx context.Context, baseURL, name string) string {
	data, err := registryGet(ctx, registryEndpoint(baseURL, "web", "packages", url.PathEscape(name), "DESCRIPTION"))
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if after, ok := strings.CutPrefix(line, "Version:"); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}

// cocoapods: GET https://trunk.cocoapods.org/api/v1/pods/{name}/specs/latest
func fetchCocoaPodsLatestFromBase(ctx context.Context, baseURL, name string) string {
	data, err := registryGet(ctx, registryEndpoint(baseURL, url.PathEscape(name), "specs", "latest"))
	if err != nil {
		return ""
	}
	var res struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &res) != nil {
		return ""
	}
	return res.Version
}

func fetchGitHubActionLatest(ctx context.Context, name string) string {
	return packageUpdateResolver{}.fetchGitHubActionLatest(ctx, name)
}

func (r packageUpdateResolver) fetchGitHubActionLatest(ctx context.Context, name string) string {
	return r.fetchGitLatest(ctx, githubActionRemote(name), domain.EcosystemGitHubActions)
}

func (r packageUpdateResolver) fetchSwiftPMLatest(ctx context.Context, name string) string {
	r = r.withDefaults()
	remote := swiftPMGitRemoteWithAllowedHosts(name, r.latestRegistry.SwiftPMGitAllowedHosts)
	if remote == "" {
		return ""
	}
	return r.fetchGitLatest(ctx, remote, domain.EcosystemSwiftPM)
}

func swiftPMGitRemote(name string) string {
	return swiftPMGitRemoteWithAllowedHosts(name, nil)
}

func swiftPMGitRemoteWithAllowedHosts(name string, allowedHosts []string) string {
	name = strings.TrimSpace(name)
	if !isCanonicalSwiftPMLookupIdentityWithAllowedHosts(name, allowedHosts) {
		return ""
	}
	parts := strings.Split(name, "/")
	if len(parts) < 3 {
		return ""
	}
	if !strings.HasSuffix(strings.ToLower(parts[len(parts)-1]), ".git") {
		parts[len(parts)-1] += ".git"
	}
	endpoint := url.URL{
		Scheme: "https",
		Host:   parts[0],
		Path:   "/" + strings.Join(parts[1:], "/"),
	}
	return endpoint.String()
}

func isCanonicalSwiftPMLookupIdentity(name string) bool {
	return isCanonicalSwiftPMLookupIdentityWithAllowedHosts(name, nil)
}

func isCanonicalSwiftPMLookupIdentityWithAllowedHosts(name string, allowedHosts []string) bool {
	name = strings.TrimSpace(name)
	if name == "" ||
		strings.Contains(name, "://") ||
		strings.ContainsAny(name, " \t\r\n\x00\\@:?#") ||
		strings.HasPrefix(name, "-") ||
		strings.HasPrefix(name, "/") ||
		strings.Contains(name, "//") {
		return false
	}
	if strings.HasSuffix(strings.ToLower(name), ".git") {
		name = name[:len(name)-len(".git")]
	}

	parts := strings.Split(name, "/")
	if len(parts) < 3 {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(parts[0]))
	if !isAllowedSwiftPMGitHostWithConfig(host, allowedHosts) {
		return false
	}
	for _, part := range parts[1:] {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func isAllowedSwiftPMGitHost(host string) bool {
	return isAllowedSwiftPMGitHostWithConfig(host, nil)
}

func isAllowedSwiftPMGitHostWithConfig(host string, allowedHosts []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "github.com", "gitlab.com", "bitbucket.org":
		return true
	}
	for _, allowed := range allowedHosts {
		if host == strings.ToLower(strings.TrimSpace(allowed)) {
			return true
		}
	}
	return false
}

func fetchGitLatest(ctx context.Context, remote string, eco domain.Ecosystem) string {
	return packageUpdateResolver{}.fetchGitLatest(ctx, remote, eco)
}

func (r packageUpdateResolver) fetchGitLatest(ctx context.Context, remote string, eco domain.Ecosystem) string {
	r = r.withDefaults()
	remote = strings.TrimSpace(remote)
	if !isSafeGitRemote(remote) {
		return ""
	}
	tags, err := r.gitRemoteTags(ctx, remote)
	if err != nil {
		return ""
	}
	return selectLatestVersion(tags, eco)
}

func isSafeGitRemote(remote string) bool {
	remote = strings.TrimSpace(remote)
	if remote == "" || strings.HasPrefix(remote, "-") || strings.ContainsAny(remote, " \t\r\n\x00") {
		return false
	}
	parsed, err := url.Parse(remote)
	if err != nil {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return false
	}
	if parsed.Host == "" || strings.HasPrefix(parsed.Host, "-") {
		return false
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return true
}

// perRequestLookupContext bounds one outbound lookup (HTTP or git) with the
// phase per-request timeout unless the caller already carries a deadline.
func perRequestLookupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, registryLookupPhaseFrom(ctx).perRequestTimeout())
}

func gitRemoteTags(ctx context.Context, remote string) ([]string, error) {
	if !isSafeGitRemote(remote) {
		return nil, fmt.Errorf("unsafe git remote")
	}
	outerCtx := ctx
	ctx, cancel := perRequestLookupContext(ctx)
	defer cancel()
	out, err := gitCommandOutput(ctx, "ls-remote", "--tags", "--", remote)
	if err != nil {
		// A per-request timeout expiry still counts here: the outer context
		// (before the per-request wrap) is not canceled, so the hang is the
		// git invocation's, not the caller's.
		if outerCtx.Err() == nil {
			registryLookupPhaseFrom(ctx).recordRefusal()
		}
		return nil, err
	}

	var tags []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		ref := fields[1]
		if strings.HasSuffix(ref, "^{}") {
			continue
		}
		if tag, ok := strings.CutPrefix(ref, "refs/tags/"); ok && isVersionLike(tag) {
			tags = append(tags, tag)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return tags, nil
}

func gitRemoteTagCommit(ctx context.Context, remote, tag string) (string, bool) {
	remote = strings.TrimSpace(remote)
	tag = strings.TrimSpace(tag)
	if tag == "" || !isSafeGitRemote(remote) || strings.ContainsAny(tag, " \t\r\n") {
		return "", false
	}

	outerCtx := ctx
	ctx, cancel := perRequestLookupContext(ctx)
	defer cancel()

	tagRef := "refs/tags/" + tag
	out, err := gitCommandOutput(ctx, "ls-remote", "--tags", "--", remote, tagRef, tagRef+"^{}")
	if err != nil {
		// A per-request timeout expiry still counts here: the outer context
		// (before the per-request wrap) is not canceled, so the hang is the
		// git invocation's, not the caller's.
		if outerCtx.Err() == nil {
			registryLookupPhaseFrom(ctx).recordRefusal()
		}
		return "", false
	}

	object := ""
	peeled := ""
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[1] {
		case tagRef:
			object = fields[0]
		case tagRef + "^{}":
			peeled = fields[0]
		}
	}
	if scanner.Err() != nil {
		return "", false
	}
	if peeled != "" {
		return peeled, true
	}
	if object != "" {
		return object, true
	}
	return "", false
}

func selectLatestVersion(versions []string, eco domain.Ecosystem) string {
	best := ""
	for _, candidate := range versions {
		if !isVersionLike(candidate) {
			continue
		}
		if best == "" || versioncmp.Compare(candidate, best, "ECOSYSTEM", string(eco)) > 0 {
			best = candidate
		}
	}
	return best
}

func isVersionLike(version string) bool {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(strings.TrimPrefix(version, "v"), "V")
	if version == "" {
		return false
	}
	ch := version[0]
	return ch >= '0' && ch <= '9'
}
