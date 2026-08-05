package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/parser"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/8linkz-sec/packmon/internal/scanner"
	"github.com/8linkz-sec/packmon/internal/termtext"
)

type outdatedOptions struct {
	Context        context.Context
	Ecosystems     string
	MaxDepth       int
	IncludeDev     bool
	OutputHTML     string
	Quiet          bool
	resolver       packageUpdateResolver
	SBOMFiles      []string
	Timeout        int
	LatestRegistry latestRegistryConfig
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
	Lang              string
	Messages          outdatedHTMLMessages
	Target            string
	ScannedAt         string
	ScannedAtDateTime string
	Total             int
	Outdated          []outdatedRow
	UpToDate          int
	Unknown           int
	LockFiles         int
	SBOMFiles         int
	PackageWord       string
}

type outdatedHTMLMessages struct {
	DocumentTitle         string
	Heading               string
	ReportType            string
	OutdatedLabel         string
	UpToDateLabel         string
	UnknownLabel          string
	ProvenanceHeading     string
	ProvenanceDescription string
	OutdatedCardsLabel    string
	OutdatedTableLabel    string
	PackageColumn         string
	InstalledColumn       string
	LatestColumn          string
	EcosystemColumn       string
	ProvenanceColumn      string
	LockfileColumn        string
	ScopeLabel            string
	RelationLabel         string
	ViaLabel              string
	FlagsLabel            string
	ProvenanceSummary     string
	LockfilesLabel        string
	SBOMFilesLabel        string
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

	collection, err := collectOutdatedPackageCollection(absPath, opts)
	if err != nil {
		return withDefaultExitCode(ExitOperational, err)
	}
	report := buildInitialOutdatedReport(scanPath, collection)
	if collection.LockFiles == 0 && collection.SBOMFiles == 0 {
		if !opts.Quiet {
			fmt.Println("No lockfiles found.")
		}
		return withDefaultExitCode(ExitOperational, finishOutdatedReport(opts, report))
	}

	packages, err := collectOutdatedPackages(collection)
	if err != nil {
		return err
	}
	if len(packages) == 0 {
		if !opts.Quiet {
			fmt.Println("No packages found.")
		}
		return withDefaultExitCode(ExitOperational, finishOutdatedReport(opts, report))
	}

	fmt.Fprintf(os.Stderr, "Checking %s for updates...\n", plural.Count(len(packages), "package", "packages"))

	results := resolveOutdatedStatuses(packages, opts)
	report = applyOutdatedStatusesToReport(report, packages, results)

	if !opts.Quiet {
		printOutdatedReport(report)
	}
	return withDefaultExitCode(ExitOperational, finishOutdatedReport(opts, report))
}

func defaultOutdatedHTMLMessages() outdatedHTMLMessages {
	return outdatedHTMLMessages{
		DocumentTitle:         "Outdated Packages - Packmon Report",
		Heading:               "Outdated Packages",
		ReportType:            "Packmon Outdated Report",
		OutdatedLabel:         "outdated",
		UpToDateLabel:         "up to date",
		UnknownLabel:          "unknown",
		ProvenanceHeading:     "Package provenance.",
		ProvenanceDescription: "Scope is where Packmon found the dependency (runtime, dev, ci, sbom). Relation is its graph relationship (direct, transitive, workflow). Via lists npm parent roots when known. Flags show optional/peer or source-specific markers.",
		OutdatedCardsLabel:    "Outdated packages cards",
		OutdatedTableLabel:    "Outdated packages table",
		PackageColumn:         "Package",
		InstalledColumn:       "Installed",
		LatestColumn:          "Latest",
		EcosystemColumn:       "Ecosystem",
		ProvenanceColumn:      "Provenance",
		LockfileColumn:        "Lockfile",
		ScopeLabel:            "Scope",
		RelationLabel:         "Relation",
		ViaLabel:              "Via",
		FlagsLabel:            "Flags",
		ProvenanceSummary:     "Provenance and source",
		LockfilesLabel:        "lockfiles",
		SBOMFilesLabel:        "SBOM files",
	}
}

func collectOutdatedPackageCollection(absPath string, opts outdatedOptions) (*scanner.PackageCollection, error) {
	reg := parser.NewRegistry()
	return scanner.CollectPackages(scanner.CollectConfig{
		Registry:   reg,
		Root:       absPath,
		MaxDepth:   opts.MaxDepth,
		Ecosystems: splitCSV(opts.Ecosystems),
		SBOMFiles:  opts.SBOMFiles,
		IncludeDev: opts.IncludeDev,
	})
}

func collectOutdatedPackages(collection *scanner.PackageCollection) ([]outdatedPackage, error) {
	if err := fatalCollectionParseError(collection); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, nil
	}

	type pkgKey struct {
		eco, name, version string
	}

	seen := make(map[pkgKey]struct{})
	packages := make([]outdatedPackage, 0, len(collection.Entries))
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
	return packages, nil
}

func buildInitialOutdatedReport(scanPath string, collection *scanner.PackageCollection) outdatedReport {
	scannedAt := time.Now().UTC()
	report := outdatedReport{
		Lang:              defaultGeneratedHTMLReportLang,
		Messages:          defaultOutdatedHTMLMessages(),
		Target:            scanPath,
		ScannedAt:         formatReportTimestamp(scannedAt),
		ScannedAtDateTime: formatReportTimestampDateTime(scannedAt),
		PackageWord:       "packages",
	}
	if collection != nil {
		report.LockFiles = collection.LockFiles
		report.SBOMFiles = collection.SBOMFiles
	}
	return report
}

func resolveOutdatedStatuses(packages []outdatedPackage, opts outdatedOptions) []packageLatestStatus {
	ctx, phase := withRegistryLookupPhase(opts.Context, opts.Timeout)

	fallbackResolver := opts.resolver
	fallbackResolver.latestRegistry = fallbackResolver.latestRegistry.inheritFallback(opts.LatestRegistry)
	lookup := newCachedPackageUpdateLookupWithResolver(fallbackResolver)
	announceLookupPhase(os.Stderr, len(packages), opts.Quiet)
	statuses := resolveLatestWithWorkerPool(ctx, packages, func(ctx context.Context, p outdatedPackage) packageLatestStatus {
		return resolveOutdatedLatestWithLookup(ctx, p, lookup)
	})

	if ctx.Err() == nil && !opts.Quiet {
		if refused := phase.refusedCount(); refused > 0 {
			fmt.Fprintf(os.Stderr, "warning: %d registry requests were refused or failed; some latest-version data is missing. Rerun the scan, raise --timeout, or route the lookups through a mirror.\n", refused)
		}
		if phase.breakerOpen() {
			fmt.Fprintf(os.Stderr, "warning: %d lookups were skipped after %d consecutive registry request failures; check network connectivity and proxy settings.\n", phase.skippedCount(), registryBreakerThreshold)
		}
	}

	return statuses
}

func applyOutdatedStatusesToReport(report outdatedReport, packages []outdatedPackage, statuses []packageLatestStatus) outdatedReport {
	report.Total = len(packages)
	report.PackageWord = "packages"
	if report.Total == 1 {
		report.PackageWord = "package"
	}

	for i, pkg := range packages {
		status := unknownLatestStatus()
		if i < len(statuses) {
			status = statuses[i]
		}
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

	sort.Slice(report.Outdated, func(i, j int) bool {
		if report.Outdated[i].Ecosystem != report.Outdated[j].Ecosystem {
			return report.Outdated[i].Ecosystem < report.Outdated[j].Ecosystem
		}
		return report.Outdated[i].Name < report.Outdated[j].Name
	})
	return report
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
	fmt.Printf(fmtStr, "PACKAGE", "INSTALLED", "LATEST", "ECOSYSTEM", "SCOPE", "RELATION", "VIA", "FLAGS", "LOCKFILE")
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

func writeOutdatedHTML(path string, report outdatedReport) error {
	report = htmlOutdatedReport(report)
	f, err := ioutils.OpenPrivateFile(path)
	if err != nil {
		return fmt.Errorf("html: create file %s: %w", path, err)
	}
	if err := outdatedHTMLTemplate().Execute(f, report); err != nil {
		ioutils.CloseSilently(f)
		return fmt.Errorf("html: render outdated report: %w", err)
	}
	return f.Close()
}

func htmlOutdatedReport(report outdatedReport) outdatedReport {
	if strings.TrimSpace(report.Lang) == "" {
		report.Lang = defaultGeneratedHTMLReportLang
	}
	report.Messages = defaultOutdatedHTMLMessages()
	report.ScannedAtDateTime = reportTimestampDateTime(report.ScannedAt, report.ScannedAtDateTime)
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
