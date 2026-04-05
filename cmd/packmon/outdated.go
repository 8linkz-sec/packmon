package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/parser"
	"github.com/8linkz/packmon/internal/scanner"
)

// runOutdated walks the target, parses lock files, queries package
// registries for the latest version, and prints a comparison table.
func runOutdated(args []string, ecosystems string, maxDepth int, noColor bool) error {
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	reg := parser.NewRegistry()

	var ecoFilter []string
	if ecosystems != "" {
		for _, e := range strings.Split(ecosystems, ",") {
			if t := strings.TrimSpace(e); t != "" {
				ecoFilter = append(ecoFilter, t)
			}
		}
	}

	walker := scanner.NewWalker(reg, maxDepth, ecoFilter)
	lockFiles, err := walker.Walk(absPath)
	if err != nil {
		return fmt.Errorf("walk: %w", err)
	}
	if len(lockFiles) == 0 {
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

	for _, lf := range lockFiles {
		f, err := os.Open(lf.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot open %s: %v\n", lf.RelPath, err)
			continue
		}
		pkgs, parseErr := lf.Parser.Parse(f)
		closeSilently(f)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "warning: parse error in %s: %v\n", lf.RelPath, parseErr)
		}
		for _, p := range pkgs {
			key := pkgKey{string(p.Ecosystem), p.Name}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			packages = append(packages, pkgInfo{
				Name:      p.Name,
				Version:   p.Version,
				Ecosystem: p.Ecosystem,
				LockFile:  lf.RelPath,
			})
		}
	}

	if len(packages) == 0 {
		fmt.Println("No packages found.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Checking %d packages for updates...\n", len(packages))

	// Look up latest versions in parallel (max 10 concurrent).
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results := make([]string, len(packages))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // concurrency limit

	for i, pkg := range packages {
		wg.Add(1)
		go func(idx int, p pkgInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			latest := fetchLatestVersion(ctx, p.Ecosystem, p.Name)
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
	return io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512 KB limit
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
	return res.Versions[len(res.Versions)-1]
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
