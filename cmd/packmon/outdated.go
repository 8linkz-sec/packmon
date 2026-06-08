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
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/parser"
	"github.com/8linkz/packmon/internal/scanner"
	versioncmp "github.com/8linkz/packmon/internal/version"
	semver "github.com/Masterminds/semver/v3"
	"golang.org/x/mod/module"
)

const (
	maxConcurrentRegistryRequests = 10
	maxRegistryResponseSize       = 512 * 1024
)

type outdatedOptions struct {
	Ecosystems string
	MaxDepth   int
	IncludeDev bool
	OutputHTML string
	Quiet      bool
	SBOMFiles  []string
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

// runOutdated walks the target, parses lock files, queries package
// registries for the latest version, and prints a comparison table.
func runOutdated(args []string, ecosystems string, maxDepth int, sbomFilesOpt ...[]string) error {
	var sbomFiles []string
	if len(sbomFilesOpt) > 0 {
		sbomFiles = sbomFilesOpt[0]
	}
	return runOutdatedWithOptions(args, outdatedOptions{
		Ecosystems: ecosystems,
		MaxDepth:   maxDepth,
		IncludeDev: true,
		SBOMFiles:  sbomFiles,
	})
}

func runOutdatedWithOptions(args []string, opts outdatedOptions) error {
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
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
		return err
	}
	if err := fatalCollectionParseError(collection); err != nil {
		return err
	}
	report := outdatedReport{
		Target:      scanPath,
		ScannedAt:   time.Now().UTC().Format("2006-01-02 15:04"),
		LockFiles:   collection.LockFiles,
		SBOMFiles:   collection.SBOMFiles,
		PackageWord: "packages",
	}
	if collection.LockFiles == 0 && collection.SBOMFiles == 0 {
		if !opts.Quiet {
			fmt.Println("No lock files found.")
		}
		return finishOutdatedReport(opts, report)
	}

	// Parse and deduplicate packages.
	type pkgKey struct {
		eco, name string
	}

	seen := make(map[pkgKey]struct{})
	var packages []outdatedPackage

	for _, parseErr := range collection.ParseErrors {
		fmt.Fprintf(os.Stderr, "warning: parse error in %s\n", parseErr)
	}
	for _, entry := range collection.Entries {
		p := entry.Package
		key := pkgKey{string(p.Ecosystem), p.Name}
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
		})
	}

	if len(packages) == 0 {
		if !opts.Quiet {
			fmt.Println("No packages found.")
		}
		return finishOutdatedReport(opts, report)
	}
	report.Total = len(packages)
	if report.Total == 1 {
		report.PackageWord = "package"
	}

	fmt.Fprintf(os.Stderr, "Checking %d packages for updates...\n", len(packages))

	// Look up latest versions in parallel with a bounded request fan-out.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results := make([]listAllLatest, len(packages))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentRegistryRequests)

	for i, pkg := range packages {
		wg.Add(1)
		go func(idx int, p outdatedPackage) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = resolvePackageUpdateStatus(ctx, p.Name, p.Version, p.Ecosystem, p.Direct, p.Parents)
		}(i, pkg)
	}
	wg.Wait()

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
	return finishOutdatedReport(opts, report)
}

func printOutdatedReport(report outdatedReport) {
	if len(report.Outdated) == 0 {
		fmt.Printf("\nAll %d packages are up to date.\n", report.UpToDate)
		return
	}
	// Compute column widths.
	maxName, maxInst, maxLat, maxEco, maxScope, maxRel, maxVia, maxFlags := 7, 9, 6, 9, 5, 8, 3, 5
	for _, r := range report.Outdated {
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
	for _, r := range report.Outdated {
		fmt.Printf(fmtStr, r.Name, r.Installed, r.Latest, r.Ecosystem, r.Scope, r.Relation, r.Via, r.Flags, r.LockFile)
	}

	fmt.Printf("\n%d outdated, %d up to date", len(report.Outdated), report.UpToDate)
	if report.Unknown > 0 {
		fmt.Printf(", %d unknown", report.Unknown)
	}
	fmt.Printf(" (%d total)\n", report.Total)
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
	return listAllPackageScope(outdatedAsListAllPackage(p))
}

func outdatedPackageRelation(p outdatedPackage) string {
	return listAllPackageRelation(outdatedAsListAllPackage(p))
}

func outdatedPackageFlags(p outdatedPackage) string {
	return listAllPackageFlags(outdatedAsListAllPackage(p))
}

func outdatedAsListAllPackage(p outdatedPackage) listAllPackage {
	return listAllPackage{
		Name:       p.Name,
		Version:    p.Version,
		Ecosystem:  p.Ecosystem,
		LockFile:   p.LockFile,
		SourceType: p.SourceType,
		Dev:        p.Dev,
		Direct:     p.Direct,
		Indirect:   p.Indirect,
		Optional:   p.Optional,
		Peer:       p.Peer,
		Via:        append([]string(nil), p.Via...),
		Parents:    append([]domain.PackageParent(nil), p.Parents...),
	}
}

var outdatedHTMLTemplate = template.Must(template.New("outdated").Parse(outdatedHTML))

func writeOutdatedHTML(path string, report outdatedReport) error {
	// #nosec G304 -- CLI output path is provided intentionally by the local user.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("html: create file %s: %w", path, err)
	}
	if err := outdatedHTMLTemplate.Execute(f, report); err != nil {
		closeSilently(f)
		return fmt.Errorf("html: render outdated report: %w", err)
	}
	return f.Close()
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
body{margin:0;background:#0d1117;color:#c9d1d9;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;line-height:1.5;}
.wrap{max-width:1600px;margin:0 auto;padding:28px 20px 48px;}
h1{font-size:22px;margin:0;color:#e6edf3;}
.meta{color:#8b949e;font-size:13px;margin:4px 0 18px;}
.summary{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 22px;}
.badge{border:1px solid #30363d;border-radius:6px;padding:3px 11px;font-size:13px;color:#8b949e;}
.warn{color:#ffa657;border-color:#ffa657;}
.ok{color:#56d4c4;border-color:#56d4c4;}
.unknown{color:#8b949e;border-color:#8b949e;}
.table-scroll{overflow-x:auto;border:1px solid #30363d;border-radius:6px;background:#161b22;}
table{width:100%;min-width:1600px;border-collapse:collapse;background:#161b22;}
th,td{padding:8px 10px;border-bottom:1px solid #30363d;text-align:left;vertical-align:top;}
th{color:#e6edf3;font-size:12px;text-transform:uppercase;}
td{word-break:normal;}
.name{min-width:260px;word-break:break-word;}
.version{white-space:nowrap;min-width:260px;}
.ecosystem{white-space:nowrap;min-width:96px;}
.short{white-space:nowrap;min-width:90px;}
.lockfile{min-width:260px;word-break:break-word;}
.empty{margin:24px 0;padding:14px 16px;background:#0f2d2a;border:1px solid #56d4c4;border-radius:6px;color:#56d4c4;font-size:15px;}
.footer{border-top:1px solid #30363d;margin-top:28px;padding-top:10px;color:#8b949e;font-size:12px;}
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
<div class="table-scroll">
<table>
<thead><tr><th class="name">Package</th><th class="version">Installed</th><th class="version">Latest</th><th class="ecosystem">Ecosystem</th><th class="short">Scope</th><th class="short">Relation</th><th>Via</th><th class="short">Flags</th><th class="lockfile">Lock File</th></tr></thead>
<tbody>
{{range .Outdated}}<tr><td class="name">{{.Name}}</td><td class="version">{{.Installed}}</td><td class="version">{{.Latest}}</td><td class="ecosystem">{{.Ecosystem}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td><td>{{.Via}}</td><td class="short">{{.Flags}}</td><td class="lockfile">{{.LockFile}}</td></tr>{{end}}
</tbody>
</table>
</div>
{{else}}
<div class="empty">All {{.UpToDate}} packages are up to date.</div>
{{end}}
<div class="footer">{{.LockFiles}} lock files &middot; {{.SBOMFiles}} SBOM files</div>
</div>
</body>
</html>`

// fetchLatestVersionFn is the indirection point for latest-version lookups so
// tests can stub registry access without hitting the network. Production code
// points it at fetchLatestVersion.
var fetchLatestVersionFn = fetchLatestVersion
var fetchNPMMetadataFn = fetchNPMMetadata

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

func resolvePackageUpdateStatus(ctx context.Context, name, installed string, eco domain.Ecosystem, direct bool, parents []domain.PackageParent) listAllLatest {
	latest := fetchLatestVersionFn(ctx, eco, name)
	if latest == "" {
		return listAllLatest{Latest: "unknown", Update: "-", Unknown: true}
	}
	target := latest
	if eco == domain.EcosystemNPM && !direct && len(parents) > 0 {
		if wanted := resolveNPMWantedVersion(ctx, name, installed, latest, parents); wanted != "" {
			target = wanted
		}
	}
	if updateAvailable(installed, target, eco) {
		return listAllLatest{Latest: target, Update: "yes"}
	}
	return listAllLatest{Latest: target, Update: "-"}
}

func resolveNPMWantedVersion(ctx context.Context, name, installed, latest string, parents []domain.PackageParent) string {
	ranges := npmParentDependencyRanges(ctx, name, parents)
	if len(ranges) == 0 {
		return latest
	}

	meta, ok := fetchNPMMetadataFn(ctx, name)
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

func npmParentDependencyRanges(ctx context.Context, childName string, parents []domain.PackageParent) []string {
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
		meta, ok := fetchNPMMetadataFn(ctx, parentName)
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
		return fetchSwiftPMLatest(ctx, name)
	case domain.EcosystemGitHubActions:
		return fetchGitHubActionLatest(ctx, name)
	default:
		return ""
	}
}

var registryClient = &http.Client{Timeout: 10 * time.Second}

func registryGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := registryClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer closeSilently(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxRegistryResponseSize))
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
	data, err := registryGet(ctx, "https://pypi.org/pypi/"+name+"/json")
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
	data, err := registryGet(ctx, "https://crates.io/api/v1/crates/"+name)
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
	data, err := registryGet(ctx, "https://repo.packagist.org/p2/"+name+".json")
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
	parts := strings.Split(name, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return ""
	}
	return fetchGitLatest(ctx, "https://github.com/"+name+".git", domain.EcosystemGitHubActions)
}

func fetchSwiftPMLatest(ctx context.Context, name string) string {
	remote := swiftPMGitRemote(name)
	if remote == "" {
		return ""
	}
	return fetchGitLatest(ctx, remote, domain.EcosystemSwiftPM)
}

func swiftPMGitRemote(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if strings.Contains(name, "://") {
		return name
	}
	if !strings.Contains(name, "/") {
		return ""
	}
	if strings.HasSuffix(strings.ToLower(name), ".git") {
		return "https://" + name
	}
	return "https://" + name + ".git"
}

func fetchGitLatest(ctx context.Context, remote string, eco domain.Ecosystem) string {
	remote = strings.TrimSpace(remote)
	if remote == "" || !strings.Contains(remote, "://") {
		return ""
	}
	tags, err := gitRemoteTagsFn(ctx, remote)
	if err != nil {
		return ""
	}
	return selectLatestVersion(tags, eco)
}

var gitRemoteTagsFn = gitRemoteTags

func gitRemoteTags(ctx context.Context, remote string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--tags", remote) // #nosec G204 -- fixed argv; remote is passed as one git URL argument without a shell.
	out, err := cmd.Output()
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
