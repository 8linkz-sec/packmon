package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/parser"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/8linkz-sec/packmon/internal/scanner"
	"github.com/8linkz-sec/packmon/internal/termtext"
	versioncmp "github.com/8linkz-sec/packmon/internal/version"
	semver "github.com/Masterminds/semver/v3"
	"golang.org/x/mod/module"
)

const (
	maxConcurrentRegistryRequests    = 10
	maxRegistryResponseSize          = 512 * 1024
	maxRegistryErrorBodyDrain        = 64 * 1024
	maxPackagistRegistryResponseSize = 4 * 1024 * 1024
	maxPyPIRegistryResponseSize      = 16 * 1024 * 1024
)

type outdatedOptions struct {
	Context    context.Context
	Ecosystems string
	MaxDepth   int
	IncludeDev bool
	OutputHTML string
	Quiet      bool
	resolver   packageUpdateResolver
	SBOMFiles  []string
	Timeout    int
}

type outdatedPackage struct {
	Name       string
	Version    string
	Ecosystem  domain.Ecosystem
	LockFile   string
	SourceType string
	Dev        bool
	Direct     bool
	Indirect   bool
	Optional   bool
	Peer       bool
	Via        []string
	Parents    []domain.PackageParent
	SourceRefs []string
}

type outdatedRow struct {
	Name      string
	Installed string
	Latest    string
	Ecosystem string
	Scope     string
	Relation  string
	Via       string
	Flags     string
	LockFile  string
}

type outdatedReport struct {
	Target      string
	ScannedAt   string
	Total       int
	Outdated    []outdatedRow
	UpToDate    int
	Unknown     int
	LockFiles   int
	SBOMFiles   int
	PackageWord string
}

func runOutdatedWithOptions(args []string, opts outdatedOptions) error {
	if opts.Quiet && strings.TrimSpace(opts.OutputHTML) == "" {
		return nil
	}

	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return withExitCode(ExitOperational, fmt.Errorf("resolve path: %w", err))
	}

	reg := parser.NewRegistry()
	collection, err := scanner.CollectPackages(scanner.CollectConfig{
		Registry:   reg,
		Root:       absPath,
		MaxDepth:   opts.MaxDepth,
		Ecosystems: splitCSV(opts.Ecosystems),
		SBOMFiles:  opts.SBOMFiles,
		IncludeDev: opts.IncludeDev,
	})
	if err != nil {
		return withDefaultExitCode(ExitOperational, err)
	}
	if err := fatalCollectionParseError(collection); err != nil {
		return err
	}
	report := outdatedReport{
		Target:      scanPath,
		ScannedAt:   formatReportTimestamp(time.Now().UTC()),
		LockFiles:   collection.LockFiles,
		SBOMFiles:   collection.SBOMFiles,
		PackageWord: "packages",
	}
	if collection.LockFiles == 0 && collection.SBOMFiles == 0 {
		if !opts.Quiet {
			fmt.Println("No lock files found.")
		}
		return withDefaultExitCode(ExitOperational, finishOutdatedReport(opts, report))
	}

	// Parse and deduplicate packages.
	type pkgKey struct {
		eco, name, version string
	}

	seen := make(map[pkgKey]struct{})
	var packages []outdatedPackage

	for _, parseErr := range collection.ParseErrors {
		fmt.Fprintf(os.Stderr, "warning: parse error in %s\n", termtext.Sanitize(parseErr))
	}
	for _, entry := range collection.Entries {
		p := entry.Package
		key := pkgKey{string(p.Ecosystem), p.Name, p.Version}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		packages = append(packages, outdatedPackage{
			Name:       p.Name,
			Version:    p.Version,
			Ecosystem:  p.Ecosystem,
			LockFile:   entry.SourceFile,
			SourceType: entry.SourceType,
			Dev:        p.Dev,
			Direct:     p.Direct,
			Indirect:   p.Indirect,
			Optional:   p.Optional,
			Peer:       p.Peer,
			Via:        append([]string(nil), p.Via...),
			Parents:    append([]domain.PackageParent(nil), p.Parents...),
			SourceRefs: append([]string(nil), p.SourceRefs...),
		})
	}

	if len(packages) == 0 {
		if !opts.Quiet {
			fmt.Println("No packages found.")
		}
		return withDefaultExitCode(ExitOperational, finishOutdatedReport(opts, report))
	}
	report.Total = len(packages)
	if report.Total == 1 {
		report.PackageWord = "package"
	}

	fmt.Fprintf(os.Stderr, "Checking %s for updates...\n", plural.Count(len(packages), "package", "packages"))

	// Look up latest versions in parallel with a bounded request fan-out.
	ctx, cancel := registryLookupContext(opts.Context, opts.Timeout)
	defer cancel()

	lookup := newCachedPackageUpdateLookupWithResolver(packageUpdateResolverFromContext(ctx, opts.resolver))
	results := resolveLatestWithWorkerPool(ctx, packages, func(ctx context.Context, p outdatedPackage) packageLatestStatus {
		return resolveOutdatedLatestWithLookup(ctx, p, lookup)
	})

	for i, pkg := range packages {
		status := results[i]
		if status.Unknown || status.Latest == "" {
			report.Unknown++
			continue
		}
		if status.Update != "yes" {
			report.UpToDate++
			continue
		}
		report.Outdated = append(report.Outdated, outdatedRow{
			Name:      pkg.Name,
			Installed: pkg.Version,
			Latest:    status.Latest,
			Ecosystem: string(pkg.Ecosystem),
			Scope:     outdatedPackageScope(pkg),
			Relation:  outdatedPackageRelation(pkg),
			Via:       strings.Join(pkg.Via, ", "),
			Flags:     outdatedPackageFlags(pkg),
			LockFile:  pkg.LockFile,
		})
	}

	// Sort: ecosystem, then name.
	sort.Slice(report.Outdated, func(i, j int) bool {
		if report.Outdated[i].Ecosystem != report.Outdated[j].Ecosystem {
			return report.Outdated[i].Ecosystem < report.Outdated[j].Ecosystem
		}
		return report.Outdated[i].Name < report.Outdated[j].Name
	})

	if !opts.Quiet {
		printOutdatedReport(report)
	}
	return withDefaultExitCode(ExitOperational, finishOutdatedReport(opts, report))
}

func registryLookupContext(parent context.Context, timeoutSeconds int) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	timeout := 60 * time.Second
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds) * time.Second
	}
	return context.WithTimeout(parent, timeout)
}

func resolveLatestWithWorkerPool[T any](ctx context.Context, items []T, resolve func(context.Context, T) packageLatestStatus) []packageLatestStatus {
	results := make([]packageLatestStatus, len(items))
	for i := range results {
		results[i] = unknownLatestStatus()
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
				results[idx] = resolve(ctx, items[idx])
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

func printOutdatedReport(report outdatedReport) {
	if len(report.Outdated) == 0 {
		fmt.Printf("\n%s\n", report.EmptyStateMessage())
		return
	}
	rows := make([]outdatedRow, 0, len(report.Outdated))
	for _, r := range report.Outdated {
		rows = append(rows, sanitizeOutdatedTerminalRow(r))
	}

	// Compute column widths.
	maxName, maxInst, maxLat, maxEco, maxScope, maxRel, maxVia, maxFlags := 7, 9, 6, 9, 5, 8, 3, 5
	for _, r := range rows {
		if len(r.Name) > maxName {
			maxName = len(r.Name)
		}
		if len(r.Installed) > maxInst {
			maxInst = len(r.Installed)
		}
		if len(r.Latest) > maxLat {
			maxLat = len(r.Latest)
		}
		if len(r.Ecosystem) > maxEco {
			maxEco = len(r.Ecosystem)
		}
		if len(r.Scope) > maxScope {
			maxScope = len(r.Scope)
		}
		if len(r.Relation) > maxRel {
			maxRel = len(r.Relation)
		}
		if len(r.Via) > maxVia {
			maxVia = len(r.Via)
		}
		if len(r.Flags) > maxFlags {
			maxFlags = len(r.Flags)
		}
	}

	gap := "  "
	fmtStr := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		maxName, gap, maxInst, gap, maxLat, gap, maxEco, gap, maxScope, gap, maxRel, gap, maxVia, gap, maxFlags, gap)

	fmt.Println()
	fmt.Printf(fmtStr, "PACKAGE", "INSTALLED", "LATEST", "ECOSYSTEM", "SCOPE", "RELATION", "VIA", "FLAGS", "LOCK FILE")
	for _, r := range rows {
		fmt.Printf(fmtStr, r.Name, r.Installed, r.Latest, r.Ecosystem, r.Scope, r.Relation, r.Via, r.Flags, r.LockFile)
	}

	fmt.Printf("\n%d outdated, %d up to date", len(rows), report.UpToDate)
	if report.Unknown > 0 {
		fmt.Printf(", %d unknown", report.Unknown)
	}
	fmt.Printf(" (%d total)\n", report.Total)
}

func sanitizeOutdatedTerminalRow(r outdatedRow) outdatedRow {
	return outdatedRow{
		Name:      termtext.Sanitize(r.Name),
		Installed: termtext.Sanitize(r.Installed),
		Latest:    termtext.Sanitize(r.Latest),
		Ecosystem: termtext.Sanitize(r.Ecosystem),
		Scope:     termtext.Sanitize(r.Scope),
		Relation:  termtext.Sanitize(r.Relation),
		Via:       termtext.Sanitize(r.Via),
		Flags:     termtext.Sanitize(r.Flags),
		LockFile:  termtext.Sanitize(r.LockFile),
	}
}

func (r outdatedReport) EmptyStateMessage() string {
	if r.Unknown > 0 {
		if r.UpToDate > 0 {
			return fmt.Sprintf("No outdated packages found; %d up to date, latest status is unknown for %s (%d total).", r.UpToDate, plural.Count(r.Unknown, "package", "packages"), r.Total)
		}
		return fmt.Sprintf("No outdated packages found; latest status is unknown for %s (%d total).", plural.Count(r.Unknown, "package", "packages"), r.Total)
	}
	verb := "are"
	if r.UpToDate == 1 {
		verb = "is"
	}
	return fmt.Sprintf("All %s %s up to date.", plural.Count(r.UpToDate, "package", "packages"), verb)
}

func (r outdatedReport) EmptyStateClass() string {
	if r.Unknown > 0 {
		return "empty empty-unknown"
	}
	return "empty"
}

func finishOutdatedReport(opts outdatedOptions, report outdatedReport) error {
	if strings.TrimSpace(opts.OutputHTML) == "" {
		return nil
	}
	if err := ensureOutputDir(opts.OutputHTML); err != nil {
		return fmt.Errorf("prepare HTML output: %w", err)
	}
	if err := writeOutdatedHTML(opts.OutputHTML, report); err != nil {
		return err
	}
	if !opts.Quiet {
		fmt.Printf("HTML report written to: %s\n", opts.OutputHTML)
	}
	return nil
}

func outdatedPackageScope(p outdatedPackage) string {
	return packageStatusScope(packageStatusFromOutdatedPackage(p))
}

func outdatedPackageRelation(p outdatedPackage) string {
	return packageStatusRelation(packageStatusFromOutdatedPackage(p))
}

func outdatedPackageFlags(p outdatedPackage) string {
	return packageStatusFlags(packageStatusFromOutdatedPackage(p))
}

var outdatedHTMLTemplate = sync.OnceValue(func() *template.Template {
	return template.Must(template.New("outdated").Parse(outdatedHTML))
})

func writeOutdatedHTML(path string, report outdatedReport) error {
	report = htmlOutdatedReport(report)
	f, err := ioutils.OpenPrivateFile(path)
	if err != nil {
		return fmt.Errorf("html: create file %s: %w", path, err)
	}
	if err := outdatedHTMLTemplate().Execute(f, report); err != nil {
		closeSilently(f)
		return fmt.Errorf("html: render outdated report: %w", err)
	}
	return f.Close()
}

func htmlOutdatedReport(report outdatedReport) outdatedReport {
	root := report.Target
	report.Target = htmlReportDisplayTarget(root)
	rows := make([]outdatedRow, 0, len(report.Outdated))
	for _, row := range report.Outdated {
		row.LockFile = htmlReportDisplaySourcePath(root, row.LockFile)
		rows = append(rows, row)
	}
	report.Outdated = rows
	return report
}

func updateAvailable(installed, latest string, ecosystem domain.Ecosystem) bool {
	return versioncmp.Compare(latest, installed, "ECOSYSTEM", string(ecosystem)) > 0
}

const outdatedHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Outdated Packages - Packmon Report</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--heading:#e6edf3;--dim:#8b949e;--warning:#ffa657;--warning-bg:#2d1f0f;--success:#7ee787;--success-bg:#0f2d2a;--success-border:#238636;--unknown:#8b949e;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;line-height:1.5;}
.wrap{max-width:1600px;margin:0 auto;padding:28px 20px 48px;}
h1{font-size:22px;margin:0;color:var(--heading);overflow-wrap:anywhere;word-break:break-word;}
.meta{color:var(--dim);font-size:13px;margin:4px 0 18px;}
.summary{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 22px;}
.badge{border:1px solid var(--border);border-radius:6px;padding:3px 11px;font-size:13px;color:var(--dim);}
.warn{color:var(--warning);border-color:var(--warning);}
.ok{color:var(--success);border-color:var(--success);}
.unknown{color:var(--unknown);border-color:var(--unknown);}
.table-scroll{overflow-x:auto;border:1px solid var(--border);border-radius:6px;background:var(--panel);}
.table-scroll:focus{outline:3px solid var(--warning);outline-offset:3px;}
table{width:100%;min-width:1600px;border-collapse:collapse;background:var(--panel);}
th,td{padding:8px 10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;}
th{color:var(--heading);font-size:12px;text-transform:uppercase;}
td{overflow-wrap:anywhere;word-break:break-word;}
.name{min-width:260px;overflow-wrap:anywhere;word-break:break-word;}
.version{min-width:260px;overflow-wrap:anywhere;word-break:break-word;}
.ecosystem{white-space:nowrap;min-width:96px;}
.short{white-space:nowrap;min-width:90px;}
.lockfile{min-width:260px;overflow-wrap:anywhere;word-break:break-word;}
.empty{margin:24px 0;padding:14px 16px;background:var(--success-bg);border:1px solid var(--success-border);border-radius:6px;color:var(--success);font-size:15px;}
.empty-unknown{background:var(--warning-bg);border-color:var(--warning);color:var(--warning);}
.meta,.footer{overflow-wrap:anywhere;word-break:break-word;}
.footer{border-top:1px solid var(--border);margin-top:28px;padding-top:10px;color:var(--dim);font-size:12px;}
@media (prefers-color-scheme: light){:root{--bg:#ffffff;--panel:#f6f8fa;--border:#d0d7de;--fg:#24292f;--heading:#111827;--dim:#57606a;--warning:#9a6700;--warning-bg:#fff8c5;--success:#116329;--success-bg:#dafbe1;--success-border:#2da44e;--unknown:#57606a;}}
@media print{:root{--bg:#ffffff;--panel:#ffffff;--border:#8c959f;--fg:#111827;--heading:#000000;--dim:#424a53;--warning:#8a4600;--warning-bg:#ffffff;--success:#116329;--success-bg:#ffffff;--success-border:#116329;--unknown:#424a53;}body{background:#fff;color:#111827;}.wrap{max-width:none;padding:0;}.table-scroll{overflow:visible;border-color:var(--border);}table{min-width:0;}.empty{break-inside:avoid;page-break-inside:avoid;background:#fff;}}
</style>
</head>
<body>
<div class="wrap">
<h1>Outdated Packages</h1>
<div class="meta">Packmon Outdated Report &middot; {{.Total}} {{.PackageWord}}{{if .Target}} &middot; {{.Target}}{{end}}{{if .ScannedAt}} &middot; {{.ScannedAt}}{{end}}</div>
<div class="summary">
<span class="badge warn">{{len .Outdated}} outdated</span>
<span class="badge ok">{{.UpToDate}} up to date</span>
<span class="badge unknown">{{.Unknown}} unknown</span>
</div>
{{if .Outdated}}
<div class="table-scroll" tabindex="0" role="region" aria-label="Outdated packages table">
<table>
<thead><tr><th class="name">Package</th><th class="version">Installed</th><th class="version">Latest</th><th class="ecosystem">Ecosystem</th><th class="short">Scope</th><th class="short">Relation</th><th>Via</th><th class="short">Flags</th><th class="lockfile">Lock File</th></tr></thead>
<tbody>
{{range .Outdated}}<tr><td class="name">{{.Name}}</td><td class="version">{{.Installed}}</td><td class="version">{{.Latest}}</td><td class="ecosystem">{{.Ecosystem}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td><td>{{.Via}}</td><td class="short">{{.Flags}}</td><td class="lockfile">{{.LockFile}}</td></tr>{{end}}
</tbody>
</table>
</div>
{{else}}
<div class="{{.EmptyStateClass}}">{{.EmptyStateMessage}}</div>
{{end}}
<div class="footer">{{.LockFiles}} lock files &middot; {{.SBOMFiles}} SBOM files</div>
</div>
</body>
</html>`

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
}

type packageUpdateResolverContextKey struct{}

func contextWithPackageUpdateResolver(ctx context.Context, resolver packageUpdateResolver) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, packageUpdateResolverContextKey{}, resolver)
}

func packageUpdateResolverFromContext(ctx context.Context, fallback packageUpdateResolver) packageUpdateResolver {
	if ctx != nil {
		if resolver, ok := ctx.Value(packageUpdateResolverContextKey{}).(packageUpdateResolver); ok {
			return resolver.withDefaults()
		}
	}
	return fallback.withDefaults()
}

func (r packageUpdateResolver) withDefaults() packageUpdateResolver {
	if r.fetchNPMMetadata == nil {
		r.fetchNPMMetadata = fetchNPMMetadata
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

func (r packageUpdateResolver) npmMetadata(ctx context.Context, name string) (npmRegistryMetadata, bool) {
	r = r.withDefaults()
	return r.fetchNPMMetadata(ctx, name)
}

type packageUpdateLookup struct {
	fetchLatest        func(context.Context, domain.Ecosystem, string) string
	fetchNPMMetadata   func(context.Context, string) (npmRegistryMetadata, bool)
	gitRemoteTagCommit func(context.Context, string, string) (string, bool)
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
	}
}

func newCachedPackageUpdateLookupWithResolver(resolver packageUpdateResolver) packageUpdateLookup {
	resolver = resolver.withDefaults()
	cache := &packageUpdateCache{
		latest:              make(map[latestVersionCacheKey]string),
		latestInflight:      make(map[latestVersionCacheKey]*latestVersionCacheCall),
		npmMetadata:         make(map[string]npmMetadataCacheEntry),
		npmMetadataInflight: make(map[string]*npmMetadataCacheCall),
		resolver:            resolver,
	}
	return packageUpdateLookup{
		fetchLatest:        cache.fetchLatestVersion,
		fetchNPMMetadata:   cache.fetchNPMMetadata,
		gitRemoteTagCommit: resolver.gitRemoteTagCommit,
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
	resolver            packageUpdateResolver
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
	if !publicLatestLookupAllowed(p.Ecosystem, p.SourceRefs) {
		return unknownLatestStatus()
	}
	return resolvePackageUpdateStatusWithLookup(ctx, p.Name, p.Version, p.Ecosystem, p.Direct, p.Parents, lookup)
}

func resolvePackageUpdateStatusWithLookup(ctx context.Context, name, installed string, eco domain.Ecosystem, direct bool, parents []domain.PackageParent, lookup packageUpdateLookup) packageLatestStatus {
	latest := lookup.fetchLatest(ctx, eco, name)
	if latest == "" {
		return unknownLatestStatus()
	}
	target := latest
	if eco == domain.EcosystemNPM && !direct && len(parents) > 0 {
		if wanted := resolveNPMWantedVersionWithLookup(ctx, name, installed, latest, parents, lookup); wanted != "" {
			target = wanted
		}
	}
	if updateAvailable(installed, target, eco) {
		if eco == domain.EcosystemGitHubActions && githubActionSHAAtTag(ctx, name, installed, target, lookup.gitRemoteTagCommit) {
			return packageLatestStatus{Latest: target, Update: "-"}
		}
		return packageLatestStatus{Latest: target, Update: "yes"}
	}
	return packageLatestStatus{Latest: target, Update: "-"}
}

func unknownLatestStatus() packageLatestStatus {
	return packageLatestStatus{Latest: "unknown", Update: "-", Unknown: true}
}

func publicLatestLookupAllowed(eco domain.Ecosystem, refs []string) bool {
	refs = normalizedSourceRefs(refs)
	if len(refs) == 0 {
		return true
	}
	switch eco {
	case domain.EcosystemNPM:
		return allSourceRefsMatch(refs, func(ref string) bool {
			return sourceRefHost(ref) == "registry.npmjs.org"
		})
	case domain.EcosystemPyPI:
		return allSourceRefsMatch(refs, func(ref string) bool {
			host := sourceRefHost(ref)
			return host == "pypi.org" || host == "files.pythonhosted.org"
		})
	case domain.EcosystemCargo:
		return allSourceRefsMatch(refs, func(ref string) bool {
			ref = strings.TrimPrefix(strings.TrimPrefix(ref, "registry+"), "sparse+")
			return ref == "https://github.com/rust-lang/crates.io-index" || ref == "https://index.crates.io/"
		})
	case domain.EcosystemGem:
		return allSourceRefsMatch(refs, func(ref string) bool {
			return sourceRefHost(ref) == "rubygems.org"
		})
	case domain.EcosystemCocoaPods:
		return allSourceRefsMatch(refs, func(ref string) bool {
			ref = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ref)), "/")
			return ref == "trunk" ||
				ref == "https://github.com/cocoapods/specs.git" ||
				ref == "https://github.com/cocoapods/specs"
		})
	case domain.EcosystemComposer:
		return allSourceRefsMatch(refs, func(ref string) bool {
			switch sourceRefHost(ref) {
			case "repo.packagist.org", "packagist.org", "api.github.com", "github.com", "gitlab.com", "bitbucket.org":
				return true
			default:
				return false
			}
		})
	case domain.EcosystemCRAN:
		return cranSourceRefsAllowPublicLookup(refs)
	case domain.EcosystemPub:
		return pubSourceRefsAllowPublicLookup(refs)
	case domain.EcosystemMaven:
		return allSourceRefsMatch(refs, func(ref string) bool {
			switch sourceRefHost(ref) {
			case "repo.maven.apache.org", "repo1.maven.org", "search.maven.org":
				return true
			default:
				return false
			}
		})
	default:
		return true
	}
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

func githubActionSHAAtTag(ctx context.Context, name, installed, tag string, resolveTagCommit func(context.Context, string, string) (string, bool)) bool {
	if !isLikelyGitSHA(installed) {
		return false
	}
	if resolveTagCommit == nil {
		resolveTagCommit = gitRemoteTagCommit
	}
	remote := githubActionRemote(name)
	if remote == "" {
		return false
	}
	commit, ok := resolveTagCommit(ctx, remote, tag)
	return ok && gitSHAMatches(installed, commit)
}

func githubActionRemote(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return ""
	}
	return "https://github.com/" + name + ".git"
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
	best := ""
	for version := range versions {
		if !isVersionLike(version) || !npmVersionSatisfiesAll(version, ranges) {
			continue
		}
		if best == "" || versioncmp.Compare(version, best, "ECOSYSTEM", string(domain.EcosystemNPM)) > 0 {
			best = version
		}
	}
	return best
}

func npmVersionSatisfiesAll(version string, ranges []string) bool {
	parsed, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	for _, raw := range ranges {
		constraint, err := semver.NewConstraint(raw)
		if err != nil {
			return false
		}
		if !constraint.Check(parsed) {
			return false
		}
	}
	return true
}

// fetchLatestVersion queries the package registry for the latest version.
// Returns "" if the lookup fails or the ecosystem is unsupported.
func fetchLatestVersion(ctx context.Context, eco domain.Ecosystem, name string) string {
	return packageUpdateResolver{}.latestVersion(ctx, eco, name)
}

func (r packageUpdateResolver) fetchLatestVersionFromRegistry(ctx context.Context, eco domain.Ecosystem, name string) string {
	switch eco {
	case domain.EcosystemNPM:
		return fetchNPMLatest(ctx, name)
	case domain.EcosystemPyPI:
		return fetchPyPILatest(ctx, name)
	case domain.EcosystemGo:
		return fetchGoLatest(ctx, name)
	case domain.EcosystemCargo:
		return fetchCratesLatest(ctx, name)
	case domain.EcosystemNuGet:
		return fetchNuGetLatest(ctx, name)
	case domain.EcosystemGem:
		return fetchRubyGemsLatest(ctx, name)
	case domain.EcosystemComposer:
		return fetchPackagistLatest(ctx, name)
	case domain.EcosystemMaven:
		return fetchMavenLatest(ctx, name)
	case domain.EcosystemPub:
		return fetchPubLatest(ctx, name)
	case domain.EcosystemHex:
		return fetchHexLatest(ctx, name)
	case domain.EcosystemCRAN:
		return fetchCRANLatest(ctx, name)
	case domain.EcosystemCocoaPods:
		return fetchCocoaPodsLatest(ctx, name)
	case domain.EcosystemSwiftPM:
		return r.fetchSwiftPMLatest(ctx, name)
	case domain.EcosystemGitHubActions:
		return r.fetchGitHubActionLatest(ctx, name)
	default:
		return ""
	}
}

var registryClient = &http.Client{}

func registryGet(ctx context.Context, url string) ([]byte, error) {
	return registryGetLimited(ctx, url, maxRegistryResponseSize)
}

func registryGetLimited(ctx context.Context, url string, limit int64) ([]byte, error) {
	return registryGetLimitedWithHeaders(ctx, url, limit, nil)
}

func registryGetLimitedWithHeaders(ctx context.Context, url string, limit int64, headers http.Header) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	resp, err := registryClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		drainRegistryErrorBody(resp.Body)
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
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

var cratesIOThrottle = newRegistryThrottle(time.Second)

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
	data, err := registryGet(ctx, "https://registry.npmjs.org/"+name+"/latest")
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
	data, err := registryGet(ctx, "https://registry.npmjs.org/"+name)
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
	data, err := registryGetLimited(ctx, "https://pypi.org/pypi/"+name+"/json", maxPyPIRegistryResponseSize)
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

// go: GET https://proxy.golang.org/{module}/@latest
func fetchGoLatest(ctx context.Context, name string) string {
	escaped, err := module.EscapePath(name)
	if err != nil {
		return ""
	}
	data, err := registryGet(ctx, "https://proxy.golang.org/"+escaped+"/@latest")
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
	if !cratesIOThrottle.wait(ctx) {
		return ""
	}
	headers := http.Header{}
	headers.Set("User-Agent", cratesIOUserAgent())
	data, err := registryGetLimitedWithHeaders(ctx, "https://crates.io/api/v1/crates/"+name, maxRegistryResponseSize, headers)
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

func cratesIOUserAgent() string {
	v := strings.TrimSpace(version)
	if v == "" {
		v = "dev"
	}
	return "packmon/" + v + " (+https://github.com/8linkz-sec/packmon)"
}

// nuget: GET https://api.nuget.org/v3-flatcontainer/{name}/index.json
func fetchNuGetLatest(ctx context.Context, name string) string {
	lower := strings.ToLower(name)
	data, err := registryGet(ctx, "https://api.nuget.org/v3-flatcontainer/"+lower+"/index.json")
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
	data, err := registryGet(ctx, "https://rubygems.org/api/v1/gems/"+name+".json")
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
	data, err := registryGetLimited(ctx, "https://repo.packagist.org/p2/"+name+".json", maxPackagistRegistryResponseSize)
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
			// Skip dev versions.
			if strings.HasPrefix(ver, "dev-") || strings.Contains(ver, "-dev") {
				continue
			}
			return ver
		}
	}
	return ""
}

// maven: GET https://search.maven.org/solrsearch/select?q=g:"group"+AND+a:"artifact"&rows=1&wt=json
func fetchMavenLatest(ctx context.Context, name string) string {
	parts := strings.SplitN(name, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return ""
	}

	endpoint := url.URL{
		Scheme: "https",
		Host:   "search.maven.org",
		Path:   "/solrsearch/select",
	}
	query := endpoint.Query()
	query.Set("q", fmt.Sprintf(`g:"%s" AND a:"%s"`, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])))
	query.Set("rows", "1")
	query.Set("wt", "json")
	endpoint.RawQuery = query.Encode()

	data, err := registryGet(ctx, endpoint.String())
	if err != nil {
		return ""
	}
	var res struct {
		Response struct {
			Docs []struct {
				LatestVersion string `json:"latestVersion"`
			} `json:"docs"`
		} `json:"response"`
	}
	if json.Unmarshal(data, &res) != nil || len(res.Response.Docs) == 0 {
		return ""
	}
	return res.Response.Docs[0].LatestVersion
}

// pub: GET https://pub.dev/api/packages/{name}
func fetchPubLatest(ctx context.Context, name string) string {
	data, err := registryGet(ctx, "https://pub.dev/api/packages/"+url.PathEscape(name))
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
	data, err := registryGet(ctx, "https://hex.pm/api/packages/"+url.PathEscape(name))
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
	data, err := registryGet(ctx, "https://cran.r-project.org/web/packages/"+url.PathEscape(name)+"/DESCRIPTION")
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
func fetchCocoaPodsLatest(ctx context.Context, name string) string {
	data, err := registryGet(ctx, "https://trunk.cocoapods.org/api/v1/pods/"+url.PathEscape(name)+"/specs/latest")
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
	remote := swiftPMGitRemote(name)
	if remote == "" {
		return ""
	}
	return r.fetchGitLatest(ctx, remote, domain.EcosystemSwiftPM)
}

func swiftPMGitRemote(name string) string {
	name = strings.TrimSpace(name)
	if !isCanonicalSwiftPMLookupIdentity(name) {
		return ""
	}
	if strings.HasSuffix(strings.ToLower(name), ".git") {
		return "https://" + name
	}
	return "https://" + name + ".git"
}

func isCanonicalSwiftPMLookupIdentity(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" ||
		strings.Contains(name, "://") ||
		strings.ContainsAny(name, " \t\r\n\x00\\@:") ||
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
	if !isAllowedSwiftPMGitHost(host) {
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
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "github.com", "gitlab.com", "bitbucket.org":
		return true
	default:
		return false
	}
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
	return true
}

func gitRemoteTags(ctx context.Context, remote string) ([]string, error) {
	if !isSafeGitRemote(remote) {
		return nil, fmt.Errorf("unsafe git remote")
	}
	out, err := gitCommandOutput(ctx, "ls-remote", "--tags", "--", remote)
	if err != nil {
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

	tagRef := "refs/tags/" + tag
	out, err := gitCommandOutput(ctx, "ls-remote", "--tags", "--", remote, tagRef, tagRef+"^{}")
	if err != nil {
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
