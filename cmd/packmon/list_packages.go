package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/8linkz-sec/packmon/internal/parser"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/8linkz-sec/packmon/internal/scanner"
	"github.com/8linkz-sec/packmon/internal/termtext"
)

func runListPackagesWithSettings(settings scanSettings) error {
	absPath, err := filepath.Abs(settings.Path)
	if err != nil {
		return withExitCode(ExitOperational, fmt.Errorf("resolve path: %w", err))
	}

	reg := parser.NewRegistry()
	collection, err := scanner.CollectPackages(scanner.CollectConfig{
		Registry:   reg,
		Root:       absPath,
		MaxDepth:   settings.MaxDepth,
		Ecosystems: settings.Ecosystems,
		SBOMFiles:  settings.SBOMFiles,
		IncludeDev: true,
	})
	if err != nil {
		return withDefaultExitCode(ExitOperational, err)
	}
	if err := fatalCollectionParseError(collection); err != nil {
		return err
	}

	if collection.LockFiles == 0 && collection.SBOMFiles == 0 {
		fmt.Println("No lockfiles found.")
		return nil
	}

	type pkgEntry struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
		LockFile  string `json:"lock_file"`
	}

	seen := make(map[string]struct{})
	var packages []pkgEntry

	for _, parseErr := range collection.ParseErrors {
		fmt.Fprintf(os.Stderr, "warning: parse error in %s\n", termtext.Sanitize(parseErr))
	}
	for _, entry := range collection.Entries {
		p := entry.Package
		key := string(p.Ecosystem) + "/" + p.Name + "@" + p.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		packages = append(packages, pkgEntry{
			Name:      termtext.Sanitize(p.Name),
			Version:   termtext.Sanitize(p.Version),
			Ecosystem: termtext.Sanitize(string(p.Ecosystem)),
			LockFile:  termtext.Sanitize(entry.SourceFile),
		})
	}

	if len(packages) == 0 {
		fmt.Println("No packages found.")
		return nil
	}

	maxName, maxVer, maxEco := 4, 7, 9
	for _, p := range packages {
		if len(p.Name) > maxName {
			maxName = len(p.Name)
		}
		if len(p.Version) > maxVer {
			maxVer = len(p.Version)
		}
		if len(p.Ecosystem) > maxEco {
			maxEco = len(p.Ecosystem)
		}
	}

	gap := "  "
	fmtStr := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%s\n", maxName, gap, maxVer, gap, maxEco, gap)

	fmt.Printf(fmtStr, "NAME", "VERSION", "ECOSYSTEM", "LOCKFILE")
	for _, p := range packages {
		fmt.Printf(fmtStr, p.Name, p.Version, p.Ecosystem, p.LockFile)
	}

	fmt.Printf("\n%s found in %s\n",
		plural.Count(len(packages), "package", "packages"),
		plural.Count(collection.LockFiles+collection.SBOMFiles, "input file", "input files"))
	return nil
}
