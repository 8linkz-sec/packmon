package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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
)

const (
	maxConcurrentRegistryRequests = 10
	maxRegistryResponseSize       = 512 * 1024
)

// runOutdated walks the target, parses lock files, queries package
// registries for the latest version, and prints a comparison table.
func runOutdated(args []string, ecosystems string, maxDepth int, sbomFilesOpt ...[]string) error {
	var sbomFiles []string
	if len(sbomFilesOpt) > 0 {
		sbomFiles = sbomFilesOpt[0]
	}
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
		MaxDepth:   maxDepth,
		Ecosystems: splitCSV(ecosystems),
		SBOMFiles:  sbomFiles,
		IncludeDev: true,
	})
	if err != nil {
		return err
	}
	if collection.LockFiles == 0 && collection.SBOMFiles == 0 {
		fmt.Println("No lock files found.")
		return nil
	}

	// Parse and deduplicate packages.
	type pkgKey struct {
		eco, name string
	}
	type pkgInfo struct {
		Name      string
		Version   string
		Ecosystem domain.Ecosystem
		LockFile  string
	}

	seen := make(map[pkgKey]struct{})
	var packages []pkgInfo

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
		packages = append(packages, pkgInfo{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: p.Ecosystem,
			LockFile:  entry.SourceFile,
		})
	}

	if len(packages) == 0 {
		fmt.Println("No packages found.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Checking %d packages for updates...\n", len(packages))

	// Look up latest versions in parallel with a bounded request fan-out.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results := make([]string, len(packages))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentRegistryRequests)

	for i, pkg := range packages {
		wg.Add(1)
		go func(idx int, p pkgInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			latest := fetchLatestVersionFn(ctx, p.Ecosystem, p.Name)
			results[idx] = latest
		}(i, pkg)
	}
	wg.Wait()

	// Build output rows (only outdated packages).
	type outputRow struct {
		name      string
		installed string
		latest    string
		ecosystem string
		lockFile  string
	}

	var outdated []outputRow
	var upToDate int
	var unknown int

	for i, pkg := range packages {
		latest := results[i]
		if latest == "" {
			unknown++
			continue
		}
		if latest == pkg.Version {
			upToDate++
			continue
		}
		outdated = append(outdated, outputRow{
			name:      pkg.Name,
			installed: pkg.Version,
			latest:    latest,
			ecosystem: string(pkg.Ecosystem),
			lockFile:  pkg.LockFile,
		})
	}

	// Sort: ecosystem, then name.
	sort.Slice(outdated, func(i, j int) bool {
		if outdated[i].ecosystem != outdated[j].ecosystem {
			return outdated[i].ecosystem < outdated[j].ecosystem
		}
		return outdated[i].name < outdated[j].name
	})

	if len(outdated) == 0 {
		fmt.Printf("\nAll %d packages are up to date.\n", upToDate)
		return nil
	}

	// Compute column widths.
	maxName, maxInst, maxLat, maxEco := 7, 9, 6, 9
	for _, r := range outdated {
		if len(r.name) > maxName {
			maxName = len(r.name)
		}
		if len(r.installed) > maxInst {
			maxInst = len(r.installed)
		}
		if len(r.latest) > maxLat {
			maxLat = len(r.latest)
		}
		if len(r.ecosystem) > maxEco {
			maxEco = len(r.ecosystem)
		}
	}

	gap := "  "
	fmtStr := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		maxName, gap, maxInst, gap, maxLat, gap, maxEco, gap)

	fmt.Println()
	fmt.Printf(fmtStr, "PACKAGE", "INSTALLED", "LATEST", "ECOSYSTEM", "LOCK FILE")
	for _, r := range outdated {
		fmt.Printf(fmtStr, r.name, r.installed, r.latest, r.ecosystem, r.lockFile)
	}

	fmt.Printf("\n%d outdated, %d up to date", len(outdated), upToDate)
	if unknown > 0 {
		fmt.Printf(", %d unknown", unknown)
	}
	fmt.Printf(" (%d total)\n", len(packages))
	return nil
}

// fetchLatestVersionFn is the indirection point for latest-version lookups so
// tests can stub registry access without hitting the network. Production code
// points it at fetchLatestVersion.
var fetchLatestVersionFn = fetchLatestVersion

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
	data, err := registryGet(ctx, "https://proxy.golang.org/"+name+"/@latest")
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
