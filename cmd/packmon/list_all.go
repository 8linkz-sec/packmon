package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/parser"
	"github.com/8linkz/packmon/internal/scanner"
)

// listAllPackage is one detected dependency row for the section-2 full list.
type listAllPackage struct {
	Name      string
	Version   string
	Ecosystem domain.Ecosystem
	LockFile  string
}

// runListAll runs the normal scanner pipeline (section 1: findings), then walks
// and parses every lock file to produce a full package list with
// available-update info (section 2). The findings table is byte-identical to a
// normal scan; the full list is printed after a few blank lines. The scanner's
// exit code is returned unchanged: --list-all is a reporting view and must not
// suppress a blocking exit code.
func runListAll(ctx context.Context, settings scanSettings) (int, error) {
	result, failOn, exitCode, err := runScanPipeline(ctx, settings)
	if err != nil {
		return exitCode, err
	}

	// Section 1: findings table (identical to a normal scan).
	if !settings.Quiet {
		tw := scanner.NewTableWriter(settings.NoColor, failOn)
		if err := tw.Write(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing table output: %v\n", err)
		}
	}

	// Collect the full package list independently of the findings, so packages
	// that are also vulnerable appear in BOTH sections.
	packages, err := collectAllPackages(settings)
	if err != nil {
		return exitCode, err
	}

	if settings.Quiet {
		return exitCode, nil
	}

	// A few blank lines separate the two sections.
	fmt.Print("\n\n\n")

	if len(packages) == 0 {
		fmt.Println("No packages found.")
		return exitCode, nil
	}

	printFullPackageList(packages, result, settings.Path)
	return exitCode, nil
}

// collectAllPackages walks and parses every lock file under the scan path and
// returns deduplicated packages keyed by ecosystem+name+version (a package at
// two versions is two rows).
func collectAllPackages(settings scanSettings) ([]listAllPackage, error) {
	absPath, err := filepath.Abs(settings.Path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	reg := parser.NewRegistry()
	collection, err := scanner.CollectPackages(scanner.CollectConfig{
		Registry:   reg,
		Root:       absPath,
		MaxDepth:   settings.MaxDepth,
		Ecosystems: settings.Ecosystems,
		SBOMFiles:  settings.SBOMFiles,
		IncludeDev: settings.IncludeDev,
	})
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var packages []listAllPackage

	for _, parseErr := range collection.ParseErrors {
		fmt.Fprintf(os.Stderr, "warning: parse error in %s\n", parseErr)
	}
	for _, entry := range collection.Entries {
		p := entry.Package
		key := string(p.Ecosystem) + "/" + p.Name + "@" + p.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		packages = append(packages, listAllPackage{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: p.Ecosystem,
			LockFile:  entry.SourceFile,
		})
	}

	return packages, nil
}

// printFullPackageList renders section 2: every detected package with its
// latest-version lookup, whether an update is available, and whether the exact
// package@version had a finding in section 1.
func printFullPackageList(packages []listAllPackage, result *domain.ScanResult, scanPath string) {
	// Look up latest versions in parallel with a bounded request fan-out and a
	// 60s timeout, exactly like runOutdated.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	latest := make([]string, len(packages))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentRegistryRequests)
	for i, pkg := range packages {
		wg.Add(1)
		go func(idx int, p listAllPackage) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			latest[idx] = fetchLatestVersionFn(ctx, p.Ecosystem, p.Name)
		}(i, pkg)
	}
	wg.Wait()

	// Index findings by ecosystem+name+version for the VULN column.
	vulnSet := make(map[string]struct{})
	if result != nil {
		for _, f := range result.Findings {
			vulnSet[string(f.Ecosystem)+"/"+f.Name+"@"+f.Version] = struct{}{}
		}
	}

	type row struct {
		name, installed, latest, update, ecosystem, vuln, lockFile string
	}

	rows := make([]row, 0, len(packages))
	var withUpdates, vulnerable, unknown int
	for i, p := range packages {
		lat := latest[i]
		latestCol := lat
		var update string
		switch {
		case lat == "":
			latestCol = "unknown"
			update = "-"
			unknown++
		case lat != p.Version:
			update = "yes"
			withUpdates++
		default:
			update = "-"
		}

		vuln := "-"
		if _, ok := vulnSet[string(p.Ecosystem)+"/"+p.Name+"@"+p.Version]; ok {
			vuln = "yes"
			vulnerable++
		}

		rows = append(rows, row{
			name:      p.Name,
			installed: p.Version,
			latest:    latestCol,
			update:    update,
			ecosystem: string(p.Ecosystem),
			vuln:      vuln,
			lockFile:  p.LockFile,
		})
	}

	// Sort: ecosystem, then name, then version.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ecosystem != rows[j].ecosystem {
			return rows[i].ecosystem < rows[j].ecosystem
		}
		if rows[i].name != rows[j].name {
			return rows[i].name < rows[j].name
		}
		return rows[i].installed < rows[j].installed
	})

	// Column widths (header widths as the minimum).
	maxName, maxInst, maxLat, maxUpd, maxEco, maxVuln := 7, 9, 6, 6, 9, 4
	for _, r := range rows {
		maxName = maxInt(maxName, len(r.name))
		maxInst = maxInt(maxInst, len(r.installed))
		maxLat = maxInt(maxLat, len(r.latest))
		maxUpd = maxInt(maxUpd, len(r.update))
		maxEco = maxInt(maxEco, len(r.ecosystem))
		maxVuln = maxInt(maxVuln, len(r.vuln))
	}

	gap := "  "
	fmtStr := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		maxName, gap, maxInst, gap, maxLat, gap, maxUpd, gap, maxEco, gap, maxVuln, gap)

	fmt.Printf(fmtStr, "PACKAGE", "INSTALLED", "LATEST", "UPDATE", "ECOSYSTEM", "VULN", "LOCK FILE")
	for _, r := range rows {
		fmt.Printf(fmtStr, r.name, r.installed, r.latest, r.update, r.ecosystem, r.vuln, r.lockFile)
	}

	fmt.Printf("\n%d packages (%d with updates, %d vulnerable, %d unknown)\n",
		len(rows), withUpdates, vulnerable, unknown)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
