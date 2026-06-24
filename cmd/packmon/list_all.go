package main

import (
	"context"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/dockerimage"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/findinglinks"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/parser"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/8linkz-sec/packmon/internal/scanner"
	"github.com/8linkz-sec/packmon/internal/termtext"
)

// listAllPackage is one detected dependency row for the section-2 full list.
type listAllPackage struct {
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
	Scope      string
	Relation   string
	Flags      string
	DockerRef  string
}

type listAllPackageReport struct {
	Target      string
	ScannedAt   string
	Rows        []listAllRow
	Sources     []listAllSourceRow
	ScopeCounts map[string]int
	WithUpdates int
	Vulnerable  int
	Unknown     int
	Warnings    []string
}

type listAllRow struct {
	Name       string
	Installed  string
	Latest     string
	LatestCopy string
	Update     string
	Ecosystem  string
	Source     string
	Scope      string
	Relation   string
	Technology string
	Via        string
	Flags      string
	Vuln       string
	LockFile   string
}

type listAllHTMLPackageRow struct {
	Name                 string
	Installed            string
	InstalledCopy        string
	InstalledCopyLabel   string
	InstalledCopyMessage string
	Latest               string
	LatestCopy           string
	LatestCopyLabel      string
	LatestCopyMessage    string
	Status               string
	StatusClass          string
	Ecosystem            string
	Source               string
	Scope                string
	Relation             string
	Technology           string
	Via                  string
	Flags                string
	Vuln                 string
	VulnClass            string
}

type listAllHTMLFindingState struct {
	Status          string
	Rank            int
	HasFixedVersion bool
}

type listAllFindingRow struct {
	Severity      string
	SeverityClass string
	Type          string
	RiskType      string
	Package       string
	Ecosystem     string
	Advisory      string
	AdvisoryURL   string
	Title         string
	FixedVersion  string
	Source        string
	Scope         string
	Relation      string
	Via           string
	Flags         string
}

type listAllFindingSection struct {
	Title    string
	Class    string
	Findings []listAllFindingRow
}

type listAllSourceRow struct {
	Kind string
	Path string
}

type listAllScopeSummary struct {
	Scope string
	Count int
}

var (
	resolveDockerImageStatusFn  = resolveDockerImageStatusWithLocalDigests
	inspectLocalDockerDigestsFn = inspectListAllLocalDockerDigests
	newDockerRegistryClientFunc = dockerimage.NewRegistryClient
)

// runListAll runs the scanner pipeline once for findings and package
// collection, then reuses that collection to produce the full package list with
// available-update info (section 2). The findings table is byte-identical to a
// normal scan; the full list is printed after a few blank lines. The scanner's
// exit code is returned unchanged: --list-all is a reporting view and must not
// suppress a blocking exit code.
func runListAll(ctx context.Context, settings scanSettings) (int, error) {
	scanSettings := settings
	scanSettings.InventoryAll = true
	result, failOn, exitCode, _, collection, err := runScanPipeline(ctx, scanSettings)
	if err != nil {
		return exitCode, withDefaultExitCode(exitCode, err)
	}

	// Section 1: findings table (identical to a normal scan).
	if !settings.Quiet {
		tw := scanner.NewTableWriter(settings.NoColor, failOn)
		if err := tw.Write(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing table output: %v\n", err)
		}
	}
	if writeScanOutputArtifacts(settings, result, failOn, false) {
		exitCode = ExitOperational
	}
	if settings.Quiet && strings.TrimSpace(settings.OutputHTML) == "" {
		return exitCode, nil
	}

	packages, inventoryWarnings, err := listAllPackagesFromCollection(collection)
	if err != nil {
		return exitCode, withDefaultExitCode(ExitOperational, err)
	}
	absPath, err := filepath.Abs(settings.Path)
	if err != nil {
		return exitCode, withExitCode(ExitOperational, fmt.Errorf("resolve path: %w", err))
	}
	dockerRows, dockerWarnings, dockerErr := collectDockerPackagesWithWarnings(absPath, settings)
	if dockerErr != nil {
		warning := "docker inventory error: " + dockerErr.Error()
		inventoryWarnings = append(inventoryWarnings, warning)
		fmt.Fprintf(os.Stderr, "warning: %s\n", termtext.Sanitize(warning))
	} else {
		inventoryWarnings = append(inventoryWarnings, dockerWarnings...)
		packages = append(packages, dockerRows...)
	}

	packageReport := buildListAllPackageReportWithOptions(ctx, packages, result, settings.Path, settings.Timeout, listAllPackageReportOptions{
		Offline: settings.ListAllOffline,
	})
	packageReport.Warnings = append(packageReport.Warnings, inventoryWarnings...)
	packageReport.Sources = mergeListAllSourceRows(packageReport.Sources, listAllExplicitSBOMSources(settings))
	htmlWritten := false
	if settings.OutputHTML != "" {
		if err := writeListAllHTML(settings.OutputHTML, settings.TargetName, failOn, result, packageReport); err != nil {
			return exitCode, withDefaultExitCode(ExitOperational, err)
		}
		htmlWritten = true
	}

	if settings.Quiet {
		return exitCode, nil
	}

	// A few blank lines separate the two sections.
	fmt.Print("\n\n\n")

	if len(packages) == 0 {
		fmt.Println("No packages found.")
		if htmlWritten {
			fmt.Printf("HTML report written to: %s\n", settings.OutputHTML)
		}
		return exitCode, nil
	}

	printListAllPackageReport(packageReport)
	if htmlWritten {
		fmt.Printf("HTML report written to: %s\n", settings.OutputHTML)
	}
	return exitCode, nil
}

// collectAllPackages walks and parses every lock file under the scan path and
// returns deduplicated packages keyed by ecosystem+name+version (a package at
// two versions is two rows).
func collectAllPackages(settings scanSettings) ([]listAllPackage, error) {
	packages, _, err := collectAllPackagesWithWarnings(settings)
	return packages, err
}

func collectAllPackagesWithWarnings(settings scanSettings) ([]listAllPackage, []string, error) {
	absPath, err := filepath.Abs(settings.Path)
	if err != nil {
		return nil, nil, withExitCode(ExitOperational, fmt.Errorf("resolve path: %w", err))
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
		return nil, nil, withDefaultExitCode(ExitOperational, err)
	}
	packages, warnings, err := listAllPackagesFromCollection(collection)
	if err != nil {
		return nil, nil, err
	}

	dockerRows, dockerWarnings, dockerErr := collectDockerPackagesWithWarnings(absPath, settings)
	if dockerErr != nil {
		warning := "docker inventory error: " + dockerErr.Error()
		warnings = append(warnings, warning)
		fmt.Fprintf(os.Stderr, "warning: %s\n", termtext.Sanitize(warning))
	} else {
		warnings = append(warnings, dockerWarnings...)
		packages = append(packages, dockerRows...)
	}

	return packages, warnings, nil
}

func listAllPackagesFromCollection(collection *scanner.PackageCollection) ([]listAllPackage, []string, error) {
	if collection == nil {
		return nil, nil, nil
	}
	if err := fatalCollectionParseError(collection); err != nil {
		return nil, nil, err
	}
	seen := make(map[string]struct{})
	var packages []listAllPackage
	var warnings []string
	for _, parseErr := range collection.ParseErrors {
		warning := "parse error in " + parseErr
		warnings = append(warnings, warning)
		fmt.Fprintf(os.Stderr, "warning: %s\n", termtext.Sanitize(warning))
	}
	for _, entry := range collection.Entries {
		p := entry.Package
		key := string(p.Ecosystem) + "/" + p.Name + "@" + p.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		packages = append(packages, listAllPackage{
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

	return packages, warnings, nil
}

func collectDockerPackagesWithWarnings(absPath string, settings scanSettings) ([]listAllPackage, []string, error) {
	if !listAllAllowsDocker(settings.Ecosystems) {
		return nil, nil, nil
	}
	collection, err := dockerimage.Collect(absPath, settings.MaxDepth)
	if err != nil {
		return nil, nil, err
	}
	var warnings []string
	for _, discoveryWarning := range collection.DiscoveryWarnings {
		warning := "docker discovery warning in " + discoveryWarning
		warnings = append(warnings, warning)
		fmt.Fprintf(os.Stderr, "warning: %s\n", termtext.Sanitize(warning))
	}
	for _, parseErr := range collection.ParseErrors {
		warning := "docker parse error in " + parseErr
		warnings = append(warnings, warning)
		fmt.Fprintf(os.Stderr, "warning: %s\n", termtext.Sanitize(warning))
	}
	rows := make([]listAllPackage, 0, len(collection.Images))
	for _, image := range collection.Images {
		pkg := image.Package()
		rows = append(rows, listAllPackage{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Ecosystem:  pkg.Ecosystem,
			LockFile:   image.SourceFile,
			SourceType: string(image.SourceType),
			Direct:     pkg.Direct,
			Indirect:   pkg.Indirect,
			Scope:      image.Scope,
			Relation:   image.Relation,
			Flags:      strings.Join(image.Flags, ", "),
			DockerRef:  image.Ref.Original,
		})
	}
	return rows, warnings, nil
}

func listAllAllowsDocker(ecosystems []string) bool {
	if len(ecosystems) == 0 {
		return true
	}
	for _, raw := range ecosystems {
		if strings.EqualFold(strings.TrimSpace(raw), string(domain.EcosystemDocker)) {
			return true
		}
	}
	return false
}

type listAllPackageReportOptions struct {
	Offline  bool
	resolver packageUpdateResolver
}

func buildListAllPackageReport(parent context.Context, packages []listAllPackage, result *domain.ScanResult, scanPath string, timeoutSeconds int) listAllPackageReport {
	return buildListAllPackageReportWithOptions(parent, packages, result, scanPath, timeoutSeconds, listAllPackageReportOptions{})
}

func buildListAllPackageReportWithOptions(parent context.Context, packages []listAllPackage, result *domain.ScanResult, scanPath string, timeoutSeconds int, options listAllPackageReportOptions) listAllPackageReport {
	// Look up latest versions in parallel with a bounded request fan-out using
	// the scan command's context and timeout.
	ctx, cancel := registryLookupContext(parent, timeoutSeconds)
	defer cancel()

	latest := make([]packageLatestStatus, len(packages))
	if options.Offline {
		for i := range latest {
			latest[i] = packageLatestStatus{Latest: "unknown", Update: "-", Unknown: true}
		}
	} else {
		lookup := newCachedPackageUpdateLookupWithResolver(packageUpdateResolverFromContext(ctx, options.resolver))
		localDockerDigests := inspectLocalDockerDigestsFn(ctx, packages)
		latest = resolveLatestWithWorkerPool(ctx, packages, func(ctx context.Context, p listAllPackage) packageLatestStatus {
			return resolveListAllLatestWithLookup(ctx, p, lookup, localDockerDigests)
		})
	}

	// Index vulnerability findings by ecosystem+name+version for the VULN column.
	vulnSet := make(map[string]struct{})
	if result != nil {
		for _, f := range result.Findings {
			if f.Type == domain.FindingTypeVulnerability {
				vulnSet[string(f.Ecosystem)+"/"+f.Name+"@"+f.Version] = struct{}{}
			}
		}
	}

	report := listAllPackageReport{
		Target:      scanPath,
		ScannedAt:   formatReportTimestamp(time.Now().UTC()),
		Rows:        make([]listAllRow, 0, len(packages)),
		ScopeCounts: make(map[string]int),
	}
	for i, p := range packages {
		lat := latest[i]
		latestCol := lat.Latest
		update := lat.Update
		if latestCol == "" {
			latestCol = "unknown"
		}
		if update == "" {
			update = "-"
		}
		if lat.Unknown {
			report.Unknown++
		}
		if update == "yes" {
			report.WithUpdates++
		}

		vuln := "-"
		if _, ok := vulnSet[string(p.Ecosystem)+"/"+p.Name+"@"+p.Version]; ok {
			vuln = "yes"
			report.Vulnerable++
		}

		status := packageStatusFromListAllPackage(p)
		scope := packageStatusScope(status)
		report.ScopeCounts[scope]++
		report.Rows = append(report.Rows, listAllRow{
			Name:       p.Name,
			Installed:  p.Version,
			Latest:     latestCol,
			LatestCopy: lat.LatestCopy,
			Update:     update,
			Ecosystem:  string(p.Ecosystem),
			Source:     listAllPackageSource(p),
			Scope:      scope,
			Relation:   packageStatusRelation(status),
			Technology: listAllPackageTechnologies(p),
			Via:        strings.Join(p.Via, ", "),
			Flags:      packageStatusFlags(status),
			Vuln:       vuln,
			LockFile:   p.LockFile,
		})
	}

	// Sort: ecosystem, then name, then version.
	sort.Slice(report.Rows, func(i, j int) bool {
		if report.Rows[i].Ecosystem != report.Rows[j].Ecosystem {
			return report.Rows[i].Ecosystem < report.Rows[j].Ecosystem
		}
		if report.Rows[i].Name != report.Rows[j].Name {
			return report.Rows[i].Name < report.Rows[j].Name
		}
		return report.Rows[i].Installed < report.Rows[j].Installed
	})
	report.Sources = listAllCheckedInventorySources(report.Rows)

	return report
}

func resolveListAllLatest(ctx context.Context, p listAllPackage) packageLatestStatus {
	return resolveListAllLatestWithLookup(ctx, p, directPackageUpdateLookup(), nil)
}

func resolveListAllLatestWithLookup(ctx context.Context, p listAllPackage, lookup packageUpdateLookup, localDockerDigests map[string]string) packageLatestStatus {
	if p.Ecosystem == domain.EcosystemDocker {
		return resolveDockerImageStatusFn(ctx, p, localDockerDigests)
	}
	if !publicLatestLookupAllowed(p.Ecosystem, p.SourceRefs) {
		return unknownLatestStatus()
	}
	return resolvePackageUpdateStatusWithLookup(ctx, p.Name, p.Version, p.Ecosystem, p.Direct, p.Parents, lookup)
}

func inspectListAllLocalDockerDigests(ctx context.Context, packages []listAllPackage) map[string]string {
	refs := make([]dockerimage.Ref, 0)
	seen := make(map[string]struct{})
	for _, p := range packages {
		if p.Ecosystem != domain.EcosystemDocker {
			continue
		}
		ref, ok := dockerRefFromListAllPackage(p)
		if !ok || ref.Digest || strings.HasPrefix(p.Name, "local/") {
			continue
		}
		key := ref.Name + ":" + ref.Reference
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		return nil
	}
	return dockerimage.LocalInspector{}.Digests(ctx, refs)
}

func listAllPackageSource(p listAllPackage) string {
	source := strings.TrimSpace(p.SourceType)
	if source != "" {
		return source
	}
	if p.Ecosystem == domain.EcosystemDocker {
		return "docker"
	}
	if strings.TrimSpace(p.LockFile) != "" {
		return "lockfile"
	}
	return "-"
}

func resolveDockerImageStatus(ctx context.Context, p listAllPackage) packageLatestStatus {
	return resolveDockerImageStatusWithLocalDigests(ctx, p, nil)
}

func resolveDockerImageStatusWithLocalDigests(ctx context.Context, p listAllPackage, localDigests map[string]string) packageLatestStatus {
	ref, ok := dockerRefFromListAllPackage(p)
	if !ok {
		return packageLatestStatus{Latest: "unknown", Update: "unknown", Unknown: true}
	}
	if strings.HasPrefix(p.Name, "local/") {
		return packageLatestStatus{Latest: "-", Update: "local"}
	}
	registryClient := newDockerRegistryClientFunc(nil)
	if ref.Digest {
		tagRef, ok := dockerTagRefFromPinnedRef(ref)
		if !ok {
			return packageLatestStatus{Latest: "-", Update: "pinned"}
		}
		currentDigest, err := registryClient.ResolveDigest(ctx, tagRef)
		if err != nil || currentDigest == "" {
			return packageLatestStatus{Latest: "-", Update: "pinned"}
		}
		if !strings.EqualFold(currentDigest, ref.Reference) {
			return packageLatestStatus{Latest: shortDigest(currentDigest), LatestCopy: currentDigest, Update: "yes"}
		}
		return packageLatestStatus{Latest: shortDigest(currentDigest), LatestCopy: currentDigest, Update: "pinned"}
	}
	remoteDigest, err := registryClient.ResolveDigest(ctx, ref)
	if err != nil || remoteDigest == "" {
		return packageLatestStatus{Latest: "unknown", Update: "unknown", Unknown: true}
	}
	if localDigests == nil {
		localDigests = dockerimage.LocalInspector{}.Digests(ctx, []dockerimage.Ref{ref})
	}
	localDigest := localDigests[ref.Name]
	if localDigest == "" {
		return packageLatestStatus{Latest: shortDigest(remoteDigest), LatestCopy: remoteDigest, Update: "unknown", Unknown: true}
	}
	if localDigest != remoteDigest {
		return packageLatestStatus{Latest: shortDigest(remoteDigest), LatestCopy: remoteDigest, Update: "yes"}
	}
	return packageLatestStatus{Latest: shortDigest(remoteDigest), LatestCopy: remoteDigest, Update: "-"}
}

func dockerRefFromListAllPackage(p listAllPackage) (dockerimage.Ref, bool) {
	raw := p.Name + ":" + p.Version
	if dockerRef := strings.TrimSpace(p.DockerRef); dockerRef != "" {
		raw = dockerRef
	}
	if strings.Contains(p.Version, ":") {
		raw = p.Name + "@" + p.Version
		if dockerRef := strings.TrimSpace(p.DockerRef); dockerRef != "" {
			raw = dockerRef
		}
	}
	return dockerimage.ParseRef(raw)
}

func dockerTagRefFromPinnedRef(ref dockerimage.Ref) (dockerimage.Ref, bool) {
	raw := strings.TrimSpace(ref.Original)
	namePart, _, ok := strings.Cut(raw, "@")
	if !ok {
		return dockerimage.Ref{}, false
	}
	colon := strings.LastIndex(namePart, ":")
	if colon <= strings.LastIndex(namePart, "/") {
		return dockerimage.Ref{}, false
	}
	return dockerimage.ParseRef(namePart)
}

func shortDigest(digest string) string {
	algo, value, ok := strings.Cut(digest, ":")
	if !ok || len(value) <= 12 {
		return digest
	}
	return algo + ":" + value[:12] + ".."
}

func printListAllPackageReport(report listAllPackageReport) {
	rows := make([]listAllRow, 0, len(report.Rows))
	for _, r := range report.Rows {
		rows = append(rows, sanitizeListAllTerminalRow(r))
	}

	// Column widths (header widths as the minimum).
	maxName, maxInst, maxLat, maxUpd, maxEco, maxSource, maxScope, maxRel, maxTech, maxVia, maxFlags, maxVuln := 7, 9, 6, 6, 9, 6, 5, 8, 10, 3, 5, 4
	for _, r := range rows {
		maxName = maxInt(maxName, len(r.Name))
		maxInst = maxInt(maxInst, len(r.Installed))
		maxLat = maxInt(maxLat, len(r.Latest))
		maxUpd = maxInt(maxUpd, len(r.Update))
		maxEco = maxInt(maxEco, len(r.Ecosystem))
		maxSource = maxInt(maxSource, len(r.Source))
		maxScope = maxInt(maxScope, len(r.Scope))
		maxRel = maxInt(maxRel, len(r.Relation))
		maxTech = maxInt(maxTech, len(r.Technology))
		maxVia = maxInt(maxVia, len(r.Via))
		maxFlags = maxInt(maxFlags, len(r.Flags))
		maxVuln = maxInt(maxVuln, len(r.Vuln))
	}

	gap := "  "
	fmtStr := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		maxName, gap, maxInst, gap, maxLat, gap, maxUpd, gap, maxEco, gap, maxSource, gap, maxScope, gap, maxRel, gap, maxTech, gap, maxVia, gap, maxFlags, gap, maxVuln, gap)

	fmt.Printf(fmtStr, "PACKAGE", "INSTALLED", "LATEST", "UPDATE", "ECOSYSTEM", "SOURCE", "SCOPE", "RELATION", "TECHNOLOGY", "VIA", "FLAGS", "VULNERABILITY", "SOURCE FILE")
	for _, r := range rows {
		fmt.Printf(fmtStr, r.Name, r.Installed, r.Latest, r.Update, r.Ecosystem, r.Source, r.Scope, r.Relation, r.Technology, r.Via, r.Flags, r.Vuln, r.LockFile)
	}

	fmt.Printf("\n%s (%s, %s, %s)\n",
		plural.Count(len(rows), "package", "packages"),
		plural.Count(report.WithUpdates, "with update", "with updates"),
		plural.Count(report.Vulnerable, "vulnerability", "vulnerabilities"),
		plural.Count(report.Unknown, "unknown", "unknown"))
}

func sanitizeListAllTerminalRow(r listAllRow) listAllRow {
	return listAllRow{
		Name:       termtext.Sanitize(r.Name),
		Installed:  termtext.Sanitize(r.Installed),
		Latest:     termtext.Sanitize(r.Latest),
		LatestCopy: r.LatestCopy,
		Update:     termtext.Sanitize(r.Update),
		Ecosystem:  termtext.Sanitize(r.Ecosystem),
		Source:     termtext.Sanitize(r.Source),
		Scope:      termtext.Sanitize(r.Scope),
		Relation:   termtext.Sanitize(r.Relation),
		Technology: termtext.Sanitize(r.Technology),
		Via:        termtext.Sanitize(r.Via),
		Flags:      termtext.Sanitize(r.Flags),
		Vuln:       termtext.Sanitize(r.Vuln),
		LockFile:   termtext.Sanitize(r.LockFile),
	}
}

func listAllPackageTechnologies(p listAllPackage) string {
	tags := make([]string, 0, 1)
	name := strings.ToLower(strings.TrimSpace(p.Name))

	if p.Ecosystem == domain.EcosystemMaven {
		tags = append(tags, "java")
	}
	if p.Ecosystem == domain.EcosystemNPM &&
		(name == "angular" || strings.HasPrefix(name, "angular-") || strings.HasPrefix(name, "@angular/")) {
		tags = append(tags, "angular")
	}
	if len(tags) == 0 {
		return "-"
	}
	sort.Strings(tags)
	return strings.Join(tags, ", ")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var listAllHTMLTemplate = sync.OnceValue(func() *template.Template {
	return template.Must(template.New("list-all").Funcs(template.FuncMap{
		"count": plural.Count,
	}).Parse(listAllHTML))
})

func writeListAllHTML(path, title string, failOn domain.Severity, result *domain.ScanResult, packages listAllPackageReport) error {
	if err := ensureOutputDir(path); err != nil {
		return fmt.Errorf("prepare HTML output: %w", err)
	}
	if strings.TrimSpace(title) == "" {
		title = "Packmon List-All Report"
	}
	sourceRoot := packages.Target
	reportType := "Packmon List-All Report"
	documentTitle := title
	if title != reportType {
		documentTitle = title + " - " + reportType
	}
	rep := struct {
		DocumentTitle string
		Title         string
		ReportType    string
		Mode          string
		PackageRows   []listAllHTMLPackageRow
		Attention     []listAllHTMLPackageRow
		PackageInfo   listAllPackageReport
		ScopeSummary  []listAllScopeSummary
		Findings      []listAllFindingSection
		Sources       []listAllSourceRow
		Status        string
		Warnings      []string
		FailOn        string
	}{
		DocumentTitle: documentTitle,
		Title:         title,
		ReportType:    reportType,
		Mode:          result.Mode,
		PackageInfo:   packages,
		ScopeSummary:  listAllScopeSummaries(packages),
		Sources:       packages.Sources,
		Status:        listAllOperationalStatusForResult(result),
		Warnings:      listAllHTMLWarnings(result, packages.Warnings),
		FailOn:        string(failOn),
	}
	rep.PackageRows = listAllHTMLPackageRows(packages.Rows, result.Findings)
	rep.Attention = listAllHTMLAttentionRows(rep.PackageRows)
	rep.PackageInfo = listAllHTMLPackageInfo(rep.PackageInfo, rep.PackageRows)
	if len(rep.Sources) == 0 {
		rep.Sources = listAllCheckedInventorySources(packages.Rows)
	}
	rep.PackageInfo.Target = htmlReportDisplayTarget(sourceRoot)
	rep.Sources = listAllHTMLDisplaySources(sourceRoot, rep.Sources)
	packageMetadata := listAllRowsByPackage(packages.Rows)
	findingRows := make([]listAllFindingRow, 0, len(result.Findings))
	for _, f := range result.Findings {
		meta := packageMetadata[listAllFindingKey(f)]
		severity := domain.NormalizeFindingSeverity(f)
		findingRows = append(findingRows, listAllFindingRow{
			Severity:      string(severity),
			SeverityClass: listAllSeverityClass(severity),
			Type:          listAllFindingTypeLabel(f),
			RiskType:      listAllFindingRiskType(f),
			Package:       listAllFindingPackageLabel(f),
			Ecosystem:     string(f.Ecosystem),
			Advisory:      listAllAdvisoryLabel(f),
			AdvisoryURL:   listAllAdvisoryURL(f),
			Title:         listAllFindingTitle(f),
			FixedVersion:  f.FixedVersion,
			Source:        f.Source,
			Scope:         meta.Scope,
			Relation:      meta.Relation,
			Via:           meta.Via,
			Flags:         meta.Flags,
		})
	}
	rep.Findings = listAllHTMLFindingSections(findingRows)

	file, err := ioutils.OpenPrivateFile(path)
	if err != nil {
		return fmt.Errorf("html: create file %s: %w", path, err)
	}
	if err := listAllHTMLTemplate().Execute(file, rep); err != nil {
		closeSilently(file)
		return fmt.Errorf("html: render list-all report: %w", err)
	}
	return file.Close()
}

func listAllHTMLPackageRows(rows []listAllRow, findings []domain.Finding) []listAllHTMLPackageRow {
	findingStatuses := listAllHTMLFindingStatuses(findings)
	vulnSet := listAllVulnerabilityFindingKeys(findings)

	out := make([]listAllHTMLPackageRow, 0, len(rows))
	for _, row := range rows {
		_, hasVulnerability := vulnSet[row.Ecosystem+"/"+row.Name+"@"+row.Installed]
		vuln := row.Vuln
		if hasVulnerability {
			vuln = "yes"
		}
		status := listAllHTMLPackageStatus(row, findingStatuses)
		installedCopy := listAllHTMLCopyValue(row.Installed)
		installedLabel, installedMessage := listAllHTMLCopyContext("installed", row)
		latestLabel, latestMessage := listAllHTMLCopyContext("latest", row)
		out = append(out, listAllHTMLPackageRow{
			Name:                 row.Name,
			Installed:            listAllHTMLCopyDisplay(row.Installed, installedCopy),
			InstalledCopy:        installedCopy,
			InstalledCopyLabel:   installedLabel,
			InstalledCopyMessage: installedMessage,
			Latest:               listAllHTMLCopyDisplay(row.Latest, row.LatestCopy),
			LatestCopy:           strings.TrimSpace(row.LatestCopy),
			LatestCopyLabel:      latestLabel,
			LatestCopyMessage:    latestMessage,
			Status:               status,
			StatusClass:          listAllHTMLStatusClass(status),
			Ecosystem:            row.Ecosystem,
			Source:               listAllHTMLPackageSource(row),
			Scope:                row.Scope,
			Relation:             row.Relation,
			Technology:           row.Technology,
			Via:                  row.Via,
			Flags:                row.Flags,
			Vuln:                 vuln,
			VulnClass:            listAllHTMLVulnClass(vuln),
		})
	}
	return out
}

func listAllVulnerabilityFindingKeys(findings []domain.Finding) map[string]struct{} {
	keys := make(map[string]struct{})
	for _, finding := range findings {
		if finding.Type == domain.FindingTypeVulnerability {
			keys[listAllFindingKey(finding)] = struct{}{}
		}
	}
	return keys
}

func listAllHTMLPackageInfo(info listAllPackageReport, rows []listAllHTMLPackageRow) listAllPackageReport {
	info.WithUpdates = 0
	info.Vulnerable = 0
	info.Unknown = 0
	for _, row := range rows {
		if row.Status == "Update available" {
			info.WithUpdates++
		}
		if strings.EqualFold(strings.TrimSpace(row.Vuln), "yes") {
			info.Vulnerable++
		}
		if row.Status == "Unknown" {
			info.Unknown++
		}
	}
	return info
}

func listAllHTMLFindingStatuses(findings []domain.Finding) map[string]listAllHTMLFindingState {
	statuses := make(map[string]listAllHTMLFindingState)
	for _, finding := range findings {
		status, rank := listAllHTMLFindingStatus(finding)
		if status == "" {
			continue
		}
		key := listAllFindingKey(finding)
		state := listAllHTMLFindingState{
			Status:          status,
			Rank:            rank,
			HasFixedVersion: strings.TrimSpace(finding.FixedVersion) != "",
		}
		existing, ok := statuses[key]
		if !ok || rank > existing.Rank {
			statuses[key] = state
			continue
		}
		if rank == existing.Rank && state.HasFixedVersion {
			existing.HasFixedVersion = true
			statuses[key] = existing
		}
	}
	return statuses
}

func listAllHTMLFindingStatus(finding domain.Finding) (string, int) {
	if domain.FindingIsInformational(finding) {
		return "Reputation info", 5
	}
	if finding.Type == domain.FindingTypeMalicious {
		return "Malicious", 50
	}
	if strings.EqualFold(strings.TrimSpace(finding.RiskType), "removed_package") {
		return "Removed", 40
	}
	switch finding.Type {
	case domain.FindingTypeSupplyChainRisk:
		return "Supply-chain risk", 30
	case domain.FindingTypeLifecycle:
		return "Lifecycle", 20
	case domain.FindingTypeVulnerability:
		return "Vulnerable", 10
	}
	if strings.TrimSpace(finding.AdvisoryID) != "" || strings.TrimSpace(finding.Source) != "" {
		return "Vulnerable", 10
	}
	return "", 0
}

func listAllHTMLAttentionRows(rows []listAllHTMLPackageRow) []listAllHTMLPackageRow {
	out := make([]listAllHTMLPackageRow, 0)
	for _, row := range rows {
		if row.Status == "Update available" ||
			row.Status == "Malicious" ||
			row.Status == "Removed" ||
			row.Status == "Supply-chain risk" ||
			row.Status == "Lifecycle" ||
			row.Status == "Reputation info" ||
			row.Status == "Vulnerable" ||
			strings.EqualFold(strings.TrimSpace(row.Vuln), "yes") {
			out = append(out, row)
		}
	}
	return out
}

func listAllHTMLPackageStatus(row listAllRow, findingStatuses map[string]listAllHTMLFindingState) string {
	if state := findingStatuses[row.Ecosystem+"/"+row.Name+"@"+row.Installed]; state.Status != "" {
		if state.Status == "Vulnerable" && listAllHTMLVulnerabilityHasUpdatePath(row, state) {
			return "Update available"
		}
		return state.Status
	}
	if strings.EqualFold(strings.TrimSpace(row.Update), "yes") {
		return "Update available"
	}
	if strings.EqualFold(strings.TrimSpace(row.Update), "local") {
		return "Local build"
	}
	if strings.EqualFold(strings.TrimSpace(row.Update), "pinned") {
		return "Digest pinned"
	}
	if strings.EqualFold(strings.TrimSpace(row.Update), "unknown") ||
		strings.EqualFold(strings.TrimSpace(row.Latest), "unknown") {
		return "Unknown"
	}
	return "Up-to-Date"
}

func listAllHTMLVulnerabilityHasUpdatePath(row listAllRow, state listAllHTMLFindingState) bool {
	if strings.EqualFold(strings.TrimSpace(row.Update), "yes") || state.HasFixedVersion {
		return true
	}
	if !strings.EqualFold(strings.TrimSpace(row.Ecosystem), string(domain.EcosystemGitHubActions)) {
		return false
	}
	return listAllHTMLKnownLatestDiffers(row)
}

func listAllHTMLKnownLatestDiffers(row listAllRow) bool {
	latest := strings.TrimSpace(row.Latest)
	installed := strings.TrimSpace(row.Installed)
	if latest == "" || installed == "" || latest == "-" || installed == "-" ||
		strings.EqualFold(latest, "unknown") {
		return false
	}
	return !strings.EqualFold(latest, installed)
}

func listAllHTMLPackageSource(row listAllRow) string {
	source := strings.TrimSpace(row.Source)
	if source != "" {
		return source
	}
	switch {
	case strings.EqualFold(strings.TrimSpace(row.Ecosystem), string(domain.EcosystemDocker)):
		return "docker"
	case listAllRowLooksLikeSBOM(row):
		return "sbom"
	case strings.TrimSpace(row.LockFile) != "":
		return "lockfile"
	default:
		return "-"
	}
}

func listAllCheckedInventorySources(rows []listAllRow) []listAllSourceRow {
	seen := make(map[string]struct{})
	for _, row := range rows {
		lockFile := strings.TrimSpace(row.LockFile)
		if lockFile == "" {
			continue
		}
		kind := listAllInventorySourceKind(row)
		seen[kind+"\x00"+lockFile] = struct{}{}
	}
	out := make([]listAllSourceRow, 0, len(seen))
	for key := range seen {
		kind, path, _ := strings.Cut(key, "\x00")
		out = append(out, listAllSourceRow{Kind: kind, Path: path})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func listAllHTMLDisplaySources(root string, sources []listAllSourceRow) []listAllSourceRow {
	out := make([]listAllSourceRow, 0, len(sources))
	for _, source := range sources {
		source.Path = htmlReportDisplaySourcePath(root, source.Path)
		out = append(out, source)
	}
	return listAllSortAndDedupSources(out)
}

func listAllExplicitSBOMSources(settings scanSettings) []listAllSourceRow {
	if len(settings.SBOMFiles) == 0 {
		return nil
	}
	root, err := filepath.Abs(settings.Path)
	if err != nil {
		root = settings.Path
	}
	out := make([]listAllSourceRow, 0, len(settings.SBOMFiles))
	for _, raw := range settings.SBOMFiles {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		path := raw
		if abs, absErr := filepath.Abs(raw); absErr == nil {
			path = listAllDisplayRelativePath(root, abs)
		}
		out = append(out, listAllSourceRow{Kind: "sbom", Path: filepath.ToSlash(path)})
	}
	return listAllSortAndDedupSources(out)
}

func mergeListAllSourceRows(left, right []listAllSourceRow) []listAllSourceRow {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	out := make([]listAllSourceRow, 0, len(left)+len(right))
	out = append(out, left...)
	out = append(out, right...)
	return listAllSortAndDedupSources(out)
}

func listAllSortAndDedupSources(sources []listAllSourceRow) []listAllSourceRow {
	seen := make(map[string]listAllSourceRow, len(sources))
	for _, source := range sources {
		source.Kind = strings.ToLower(strings.TrimSpace(source.Kind))
		source.Path = strings.TrimSpace(source.Path)
		if source.Kind == "" || source.Path == "" {
			continue
		}
		seen[source.Kind+"\x00"+source.Path] = source
	}
	out := make([]listAllSourceRow, 0, len(seen))
	for _, source := range seen {
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func listAllDisplayRelativePath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return safeHTMLExternalPath(path)
	}
	return rel
}

func listAllInventorySourceKind(row listAllRow) string {
	source := strings.ToLower(strings.TrimSpace(row.Source))
	switch source {
	case "dockerfile", "compose", "docker":
		return "docker"
	case "sbom":
		return "sbom"
	case "lockfile":
		return "lockfile"
	}
	if strings.EqualFold(strings.TrimSpace(row.Ecosystem), string(domain.EcosystemDocker)) {
		return "docker"
	}
	if listAllRowLooksLikeSBOM(row) {
		return "sbom"
	}
	return "lockfile"
}

func listAllRowLooksLikeSBOM(row listAllRow) bool {
	if strings.EqualFold(strings.TrimSpace(row.Scope), "sbom") {
		return true
	}
	path := strings.ToLower(strings.TrimSpace(filepath.ToSlash(row.LockFile)))
	return strings.HasSuffix(path, ".cdx.json") ||
		strings.HasSuffix(path, ".spdx.json") ||
		strings.HasSuffix(path, ".spdx")
}

func listAllRowsByPackage(rows []listAllRow) map[string]listAllRow {
	out := make(map[string]listAllRow, len(rows))
	for _, row := range rows {
		out[row.Ecosystem+"/"+row.Name+"@"+row.Installed] = row
	}
	return out
}

func listAllHTMLCopyDisplay(display, copyValue string) string {
	copyValue = strings.TrimSpace(copyValue)
	if copyValue == "" {
		return display
	}
	if strings.TrimSpace(display) == "" || strings.EqualFold(strings.TrimSpace(display), copyValue) {
		return shortDigest(copyValue)
	}
	return display
}

func listAllHTMLCopyValue(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "sha256:") && len(value) > len("sha256:")+12 {
		return value
	}
	return ""
}

func listAllHTMLCopyContext(field string, row listAllRow) (string, string) {
	field = strings.TrimSpace(field)
	if field == "" {
		field = "value"
	}
	packageName := strings.TrimSpace(row.Name)
	if packageName == "" {
		packageName = "package"
	}
	installed := strings.TrimSpace(row.Installed)
	if installed == "" {
		installed = "unknown version"
	}
	label := fmt.Sprintf("Copy full %s value for %s %s", field, packageName, installed)
	message := fmt.Sprintf("Copied full %s value for %s", field, packageName)
	return label, message
}

func listAllHTMLStatusClass(status string) string {
	if status == "Update available" {
		return "status-update"
	}
	return ""
}

func listAllHTMLVulnClass(vuln string) string {
	if strings.EqualFold(strings.TrimSpace(vuln), "yes") {
		return "vuln-yes"
	}
	return ""
}

func listAllSeverityClass(severity domain.Severity) string {
	switch severity {
	case domain.SeverityCritical:
		return "sev-critical"
	case domain.SeverityHigh:
		return "sev-high"
	case domain.SeverityMedium:
		return "sev-medium"
	case domain.SeverityLow:
		return "sev-low"
	default:
		return "sev-unknown"
	}
}

func listAllFindingKey(f domain.Finding) string {
	return string(f.Ecosystem) + "/" + f.Name + "@" + f.Version
}

func listAllScopeSummaries(report listAllPackageReport) []listAllScopeSummary {
	counts := report.ScopeCounts
	if len(counts) == 0 && len(report.Rows) > 0 {
		counts = make(map[string]int)
		for _, row := range report.Rows {
			if strings.TrimSpace(row.Scope) != "" {
				counts[row.Scope]++
			}
		}
	}
	if len(counts) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(counts))
	order := []string{"runtime", "dev", "ci", "sbom", "build"}
	out := make([]listAllScopeSummary, 0, len(counts))
	for _, scope := range order {
		if count := counts[scope]; count > 0 {
			out = append(out, listAllScopeSummary{Scope: scope, Count: count})
			seen[scope] = struct{}{}
		}
	}
	var rest []string
	for scope, count := range counts {
		if count <= 0 {
			continue
		}
		if _, ok := seen[scope]; !ok {
			rest = append(rest, scope)
		}
	}
	sort.Strings(rest)
	for _, scope := range rest {
		out = append(out, listAllScopeSummary{Scope: scope, Count: counts[scope]})
	}
	return out
}

func listAllOperationalStatus(status string) string {
	status = strings.TrimSpace(status)
	switch status {
	case "", "healthy", "degraded":
		return ""
	default:
		return status
	}
}

func listAllOperationalStatusForResult(result *domain.ScanResult) string {
	if result == nil {
		return ""
	}
	if message := strings.TrimSpace(result.ScanError); message != "" {
		return message
	}
	return listAllOperationalStatus(result.FeedStatus)
}

var listAllFindingSectionDefs = []struct {
	label string
	title string
	class string
}{
	{"Malicious", "Malicious", "s-mal"},
	{"Supply-chain", "Supply-Chain / EOL", "s-sce"},
	{"Vulnerability", "Vulnerabilities", "s-vuln"},
	{"Lifecycle", "Lifecycle warnings", "s-life"},
	{"Reputation info", "Reputation info", "s-life"},
}

func listAllHTMLFindingSections(rows []listAllFindingRow) []listAllFindingSection {
	if len(rows) == 0 {
		return nil
	}
	byType := make(map[string][]listAllFindingRow)
	var other []listAllFindingRow
	for _, row := range rows {
		label := strings.TrimSpace(row.Type)
		if label == "" {
			other = append(other, row)
			continue
		}
		byType[label] = append(byType[label], row)
	}

	sections := make([]listAllFindingSection, 0, len(listAllFindingSectionDefs)+1)
	for _, def := range listAllFindingSectionDefs {
		findings := byType[def.label]
		if len(findings) == 0 {
			continue
		}
		sortListAllFindingRows(findings)
		sections = append(sections, listAllFindingSection{Title: def.title, Class: def.class, Findings: findings})
	}
	if len(other) > 0 {
		sortListAllFindingRows(other)
		sections = append(sections, listAllFindingSection{Title: "Other findings", Class: "s-other", Findings: other})
	}
	return sections
}

func sortListAllFindingRows(rows []listAllFindingRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		left := domain.Severity(rows[i].Severity).Rank()
		right := domain.Severity(rows[j].Severity).Rank()
		if left != right {
			return left > right
		}
		return rows[i].Package < rows[j].Package
	})
}

func listAllFindingTypeLabel(f domain.Finding) string {
	if domain.FindingIsInformational(f) {
		return "Reputation info"
	}
	switch f.Type {
	case domain.FindingTypeMalicious:
		return "Malicious"
	case domain.FindingTypeSupplyChainRisk:
		return "Supply-chain"
	case domain.FindingTypeVulnerability:
		return "Vulnerability"
	case domain.FindingTypeLifecycle:
		return "Lifecycle"
	default:
		return strings.TrimSpace(string(f.Type))
	}
}

func listAllFindingPackageLabel(f domain.Finding) string {
	name := strings.TrimSpace(f.Name)
	if name != "" {
		return name
	}
	version := strings.TrimSpace(f.Version)
	if version != "" {
		return version
	}
	return "-"
}

func listAllFindingRiskType(f domain.Finding) string {
	if risk := strings.TrimSpace(f.RiskType); risk != "" {
		return listAllRiskTypeLabel(risk)
	}
	switch f.Type {
	case domain.FindingTypeMalicious:
		return listAllRiskTypeLabel("malware")
	case domain.FindingTypeVulnerability:
		return listAllRiskTypeLabel("known_vulnerability")
	case domain.FindingTypeLifecycle:
		return listAllRiskTypeLabel("lifecycle")
	case domain.FindingTypeSupplyChainRisk:
		return listAllRiskTypeLabel("supply_chain")
	default:
		return "-"
	}
}

func listAllRiskTypeLabel(risk string) string {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "":
		return "-"
	case "known_vulnerability":
		return "Known vulnerability"
	case "malware":
		return "Malware"
	case "malware_history":
		return "Malware history"
	case "removed_package":
		return "Removed package"
	case "supply_chain":
		return "Supply-chain risk"
	case "lifecycle":
		return "Lifecycle"
	case "eol":
		return "End-of-life"
	case "eol_soon":
		return "End-of-life soon"
	case "security_support_only":
		return "Security support only"
	case "security_support_ended":
		return "Security support ended"
	case "protestware":
		return "Protestware"
	case "typosquatting":
		return "Typosquatting"
	case "other":
		return "Other"
	default:
		return humanizeListAllToken(risk)
	}
}

func humanizeListAllToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '_' || r == '-'
	})
	if len(parts) == 0 {
		return value
	}
	for i, part := range parts {
		part = strings.ToLower(part)
		if part == "" {
			continue
		}
		if i == 0 {
			part = strings.ToUpper(part[:1]) + part[1:]
		}
		parts[i] = part
	}
	return strings.Join(parts, " ")
}

func listAllHTMLWarnings(result *domain.ScanResult, inventoryWarnings []string) []string {
	if result == nil {
		return appendListAllInventoryWarnings(nil, inventoryWarnings)
	}
	var warnings []string
	if strings.TrimSpace(result.FeedStatus) == "degraded" {
		warnings = append(warnings, scanner.DegradedFeedStatusWarning(result.Mode))
	}
	if result.Mode == "local" && result.DBStale {
		if result.DBAgeDays != nil {
			warnings = append(warnings, fmt.Sprintf("Local database last synced %s ago. Results may be incomplete. Update with: packmon db sync.", plural.Count(*result.DBAgeDays, "day", "days")))
		} else {
			warnings = append(warnings, "Local database is stale. Results may be incomplete. Update with: packmon db sync.")
		}
	}
	for _, parseErr := range result.ParseErrors {
		parseErr = strings.TrimSpace(parseErr)
		if parseErr == "" {
			continue
		}
		warnings = append(warnings, "Some dependency inventory could not be evaluated: "+parseErr)
	}
	return appendListAllInventoryWarnings(warnings, inventoryWarnings)
}

func appendListAllInventoryWarnings(warnings, inventoryWarnings []string) []string {
	for _, warning := range inventoryWarnings {
		warning = strings.TrimSpace(warning)
		if warning == "" {
			continue
		}
		warnings = append(warnings, "Some requested package inventory could not be listed: "+warning)
	}
	return warnings
}

func listAllFindingTitle(f domain.Finding) string {
	if strings.EqualFold(strings.TrimSpace(f.RiskType), "malware_history") {
		return "ReversingLabs: malware incident history"
	}
	return f.Title
}

func listAllAdvisoryLabel(f domain.Finding) string {
	return findinglinks.AdvisoryLabel(f)
}

func listAllAdvisoryURL(f domain.Finding) string {
	return findinglinks.AdvisoryURL(f)
}

const listAllHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.DocumentTitle}}</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--heading:#e6edf3;--dim:#8b949e;--crit:#ff7b72;--high:#ffa657;--sev-low:#56d4c4;--success:#7ee787;--success-bg:#0f2d2a;--success-border:#238636;--warning:#ffa657;--warning-bg:#322717;--link:#58a6ff;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;line-height:1.5;}
.wrap{max-width:1600px;margin:0 auto;padding:28px 20px 48px;}
h1{font-size:22px;margin:0;color:var(--heading);overflow-wrap:anywhere;word-break:break-word;}
h2{font-size:16px;margin:26px 0 10px;color:var(--heading);border-bottom:1px solid var(--border);padding-bottom:5px;}
.meta{color:var(--dim);font-size:13px;margin:4px 0 18px;}
.summary{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 22px;}
.badge{border:1px solid var(--border);border-radius:6px;padding:3px 11px;font-size:13px;color:var(--dim);}
.warn{color:var(--warning);border-color:var(--warning);}
.ok{color:var(--success);border-color:var(--success);}
.bad{color:var(--crit);border-color:var(--crit);}
.table-scroll{overflow-x:auto;border:1px solid var(--border);border-radius:6px;background:var(--panel);}
.table-scroll:focus{outline:3px solid var(--link);outline-offset:3px;}
table{width:100%;border-collapse:collapse;background:var(--panel);}
.package-table{min-width:1500px;table-layout:auto;}
.findings-table{table-layout:auto;min-width:1180px;}
th,td{padding:8px 10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;}
th{color:var(--heading);font-size:12px;text-transform:uppercase;}
td{word-break:break-word;overflow-wrap:anywhere;}
.name{min-width:260px;word-break:break-word;overflow-wrap:anywhere;}
.installed,.version{width:260px;min-width:260px;overflow-wrap:anywhere;word-break:break-word;}
.short{white-space:nowrap;min-width:90px;}
.nowrap{white-space:nowrap;}
.source{white-space:nowrap;min-width:105px;}
.package-status{white-space:nowrap;min-width:110px;}
.status-update{color:var(--high);font-weight:700;}
.vuln-col{text-align:center;white-space:nowrap;min-width:64px;}
.vuln-yes{color:var(--crit);font-weight:700;}
.sev{display:inline-block;border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-weight:700;line-height:1.4;}
.sev-critical{color:var(--crit);border-color:var(--crit);}
.sev-high{color:var(--high);border-color:var(--high);}
.sev-medium{color:var(--warning);border-color:var(--warning);}
.sev-low{color:var(--sev-low);border-color:var(--sev-low);}
.sev-unknown{color:var(--dim);}
.findings-table .finding-package{min-width:220px;white-space:nowrap;overflow-wrap:normal;word-break:normal;}
.findings-table .finding-advisory{min-width:190px;white-space:nowrap;overflow-wrap:normal;word-break:normal;}
.findings-table .finding-advisory a{white-space:nowrap;overflow-wrap:normal;word-break:normal;}
.finding-title{min-width:320px;white-space:normal;overflow-wrap:break-word;word-break:normal;}
.finding-fixed{min-width:120px;white-space:nowrap;overflow-wrap:normal;word-break:normal;}
.finding-section{margin:0 0 18px;}
.finding-section h3{font-size:14px;margin:14px 0 8px;color:var(--heading);}
.finding-section h3.s-mal{color:var(--crit);}
.finding-section h3.s-sce{color:var(--warning);}
.finding-section h3.s-vuln{color:var(--heading);}
.finding-section h3.s-life{color:var(--link);}
.finding-section .count{color:var(--dim);font-weight:400;}
a{color:var(--link);text-decoration:none;overflow-wrap:anywhere;word-break:break-word;}
a:hover{text-decoration:underline;}
.copy-value{white-space:nowrap;}
.copy-btn{margin-left:8px;border:1px solid var(--border);border-radius:4px;background:#21262d;color:var(--fg);font:inherit;font-size:12px;min-width:44px;min-height:32px;padding:5px 10px;cursor:pointer;}
.copy-btn:hover{border-color:var(--link);color:var(--link);}
.copy-btn.copy-failed{border-color:var(--crit);color:var(--crit);}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;}
.status{margin:18px 0;padding:14px 16px;background:#321820;border:1px solid var(--crit);border-radius:6px;color:var(--crit);font-size:15px;}
.warning{margin:18px 0;padding:14px 16px;background:var(--warning-bg);border:1px solid var(--warning);border-radius:6px;color:var(--warning);font-size:15px;}
.empty{margin:16px 0;padding:14px 16px;background:var(--success-bg);border:1px solid var(--success-border);border-radius:6px;color:var(--success);font-size:15px;}
.source-list{margin:0;padding:0;list-style:none;border:1px solid var(--border);border-radius:6px;background:var(--panel);}
.source-list li{display:flex;gap:10px;align-items:flex-start;padding:8px 10px;border-bottom:1px solid var(--border);}
.source-list li:last-child{border-bottom:0;}
.source-kind{flex:0 0 90px;color:var(--dim);text-transform:uppercase;font-size:12px;}
.source-path{min-width:0;overflow-wrap:anywhere;word-break:break-word;}
.meta,.footer{overflow-wrap:anywhere;word-break:break-word;}
.footer{border-top:1px solid var(--border);margin-top:28px;padding-top:10px;color:var(--dim);font-size:12px;}
@media (prefers-color-scheme: light){:root{--bg:#ffffff;--panel:#f6f8fa;--border:#d0d7de;--fg:#24292f;--heading:#111827;--dim:#57606a;--crit:#cf222e;--high:#9a6700;--sev-low:#0a7f74;--success:#116329;--success-bg:#dafbe1;--success-border:#2da44e;--warning:#9a6700;--warning-bg:#fff8c5;--link:#0969da;}}
@media print{:root{--bg:#ffffff;--panel:#ffffff;--border:#8c959f;--fg:#111827;--heading:#000000;--dim:#424a53;--crit:#b42318;--high:#8a4600;--sev-low:#006d75;--success:#116329;--success-bg:#ffffff;--success-border:#116329;--warning:#8a4600;--warning-bg:#ffffff;--link:#0645ad;}body{background:#fff;color:#111827;}.wrap{max-width:none;padding:0;}.table-scroll{overflow:visible;border-color:var(--border);}table{min-width:0;}.status,.warning,.empty,.finding-section{break-inside:avoid;page-break-inside:avoid;background:#fff;}a{color:var(--link);}}
</style>
</head>
<body>
<div class="wrap">
<h1>{{.Title}}</h1>
<div class="meta">{{.ReportType}}{{if .Mode}} &middot; {{.Mode}} mode{{end}}{{if .PackageInfo.Target}} &middot; {{.PackageInfo.Target}}{{end}}{{if .PackageInfo.ScannedAt}} &middot; {{.PackageInfo.ScannedAt}}{{end}}</div>
<div class="summary">
<span class="badge">{{count (len .PackageRows) "package" "packages"}}</span>
<span class="badge warn">{{count .PackageInfo.WithUpdates "with update" "with updates"}}</span>
<span class="badge bad">{{count .PackageInfo.Vulnerable "vulnerability" "vulnerabilities"}}</span>
<span class="badge">{{count .PackageInfo.Unknown "unknown" "unknown"}}</span>
{{range .ScopeSummary}}<span class="badge">{{.Scope}} {{.Count}}</span>{{end}}
</div>
{{if .Status}}<div class="status">Scan did not complete: {{.Status}}</div>{{end}}
{{range .Warnings}}<div class="warning">{{.}}</div>{{end}}
<h2>Packages Needing Attention</h2>
{{if .Attention}}
<div class="table-scroll" tabindex="0" role="region" aria-label="Packages needing attention table">
<table class="package-table">
<thead><tr><th class="name">Package</th><th class="installed">Installed</th><th class="version">Latest</th><th class="package-status">Status</th><th class="short">Ecosystem</th><th class="source">Source</th><th class="short">Scope</th><th class="short">Relation</th><th class="short">Technology</th><th class="vuln-col">Vulnerability</th></tr></thead>
<tbody>
{{range .Attention}}<tr><td class="name">{{.Name}}</td><td class="installed">{{if .InstalledCopy}}<span class="copy-value">{{.Installed}}</span><button type="button" class="copy-btn" data-copy="{{.InstalledCopy}}" data-copy-label="{{.InstalledCopyLabel}}" data-copy-message="{{.InstalledCopyMessage}}" aria-label="{{.InstalledCopyLabel}}">Copy</button>{{else}}{{.Installed}}{{end}}</td><td class="version">{{if .LatestCopy}}<span class="copy-value">{{.Latest}}</span><button type="button" class="copy-btn" data-copy="{{.LatestCopy}}" data-copy-label="{{.LatestCopyLabel}}" data-copy-message="{{.LatestCopyMessage}}" aria-label="{{.LatestCopyLabel}}">Copy</button>{{else}}{{.Latest}}{{end}}</td><td class="package-status{{if .StatusClass}} {{.StatusClass}}{{end}}">{{.Status}}</td><td class="short">{{.Ecosystem}}</td><td class="source">{{.Source}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td><td class="short">{{.Technology}}</td><td class="vuln-col{{if .VulnClass}} {{.VulnClass}}{{end}}">{{.Vuln}}</td></tr>{{end}}
</tbody>
</table>
</div>
{{else if and (not .Status) (not .Warnings)}}
<div class="empty">No package status issues requiring attention.</div>
{{end}}
<h2>Security Findings</h2>
{{if .Findings}}
{{range .Findings}}
<div class="finding-section">
<h3 class="{{.Class}}">{{.Title}} <span class="count">({{len .Findings}})</span></h3>
<div class="table-scroll" tabindex="0" role="region" aria-label="Security findings table">
<table class="findings-table">
<thead><tr><th class="short">Severity</th><th class="short">Type</th><th class="short">Risk</th><th class="finding-package">Package</th><th class="short">Ecosystem</th><th class="finding-advisory">Advisory</th><th class="finding-title">Finding</th><th class="finding-fixed">Fix Version</th><th class="short">Source</th><th class="short">Scope</th><th class="short">Relation</th></tr></thead>
<tbody>
{{range .Findings}}<tr><td class="short"><span class="sev {{.SeverityClass}}">{{.Severity}}</span></td><td class="short">{{.Type}}</td><td class="short">{{.RiskType}}</td><td class="finding-package">{{.Package}}</td><td class="short">{{.Ecosystem}}</td><td class="finding-advisory">{{if .AdvisoryURL}}<a href="{{.AdvisoryURL}}" target="_blank" rel="noopener" aria-label="{{.Advisory}} opens in a new tab">{{.Advisory}}<span aria-hidden="true"> &#8599;</span><span class="sr-only"> (opens in a new tab)</span></a>{{else}}{{.Advisory}}{{end}}</td><td class="finding-title">{{.Title}}</td><td class="finding-fixed">{{.FixedVersion}}</td><td class="short">{{.Source}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td></tr>{{end}}
</tbody>
</table>
</div>
</div>
{{end}}
{{else if and (not .Status) (not .Warnings)}}
<div class="empty">No security findings in {{count (len .PackageRows) "package" "packages"}}.</div>
{{end}}
<h2>All Packages</h2>
{{if .PackageRows}}
<div class="table-scroll" tabindex="0" role="region" aria-label="All packages table">
<table class="package-table">
<thead><tr><th class="name">Package</th><th class="installed">Installed</th><th class="version">Latest</th><th class="package-status">Status</th><th class="short">Ecosystem</th><th class="source">Source</th><th class="short">Scope</th><th class="short">Relation</th><th class="short">Technology</th><th class="vuln-col">Vulnerability</th></tr></thead>
<tbody>
{{range .PackageRows}}<tr><td class="name">{{.Name}}</td><td class="installed">{{if .InstalledCopy}}<span class="copy-value">{{.Installed}}</span><button type="button" class="copy-btn" data-copy="{{.InstalledCopy}}" data-copy-label="{{.InstalledCopyLabel}}" data-copy-message="{{.InstalledCopyMessage}}" aria-label="{{.InstalledCopyLabel}}">Copy</button>{{else}}{{.Installed}}{{end}}</td><td class="version">{{if .LatestCopy}}<span class="copy-value">{{.Latest}}</span><button type="button" class="copy-btn" data-copy="{{.LatestCopy}}" data-copy-label="{{.LatestCopyLabel}}" data-copy-message="{{.LatestCopyMessage}}" aria-label="{{.LatestCopyLabel}}">Copy</button>{{else}}{{.Latest}}{{end}}</td><td class="package-status{{if .StatusClass}} {{.StatusClass}}{{end}}">{{.Status}}</td><td class="short">{{.Ecosystem}}</td><td class="source">{{.Source}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td><td class="short">{{.Technology}}</td><td class="vuln-col{{if .VulnClass}} {{.VulnClass}}{{end}}">{{.Vuln}}</td></tr>{{end}}
</tbody>
</table>
</div>
{{else}}
{{if not .Warnings}}
<div class="empty">No packages found.</div>
{{end}}
{{end}}
{{if .Sources}}
<h2>Checked Inventory Sources</h2>
<ul class="source-list">
{{range .Sources}}<li><span class="source-kind">{{.Kind}}</span><span class="source-path">{{.Path}}</span></li>{{end}}
</ul>
{{end}}
<div class="footer">fail-on {{.FailOn}}</div>
<div id="copy-status" class="sr-only" role="status" aria-live="polite"></div>
</div>
<script>
(function(){
  var status=document.getElementById('copy-status');
  function announce(message){
    if(status){status.textContent=message;}
  }
  function resetButton(button){
    var label=button.getAttribute('data-copy-label') || 'Copy full value';
    button.textContent='Copy';
    button.classList.remove('copy-failed');
    button.setAttribute('aria-label',label);
  }
  function showResult(button, ok){
    var label=button.getAttribute('data-copy-label') || 'Copy full value';
    var message=button.getAttribute('data-copy-message') || 'Copied full value';
    if(ok){
      button.textContent='Copied';
      button.setAttribute('aria-label',message);
      announce(message);
    }else{
      button.textContent='Copy failed';
      button.classList.add('copy-failed');
      button.setAttribute('aria-label','Copy failed. '+label);
      announce('Copy failed. Use the visible value or try again.');
    }
    window.setTimeout(function(){resetButton(button);},1600);
  }
  function restoreFocus(button, previous){
    if(button && button.isConnected && button.focus){
      try{button.focus({preventScroll:true});}catch(_){button.focus();}
      return;
    }
    if(previous && previous.focus){
      try{previous.focus({preventScroll:true});}catch(_){previous.focus();}
    }
  }
  function fallbackCopy(value,button){
    var previous=document.activeElement;
    var text=document.createElement('textarea');
    text.value=value;
    text.setAttribute('readonly','');
    text.style.position='fixed';
    text.style.opacity='0';
    document.body.appendChild(text);
    text.select();
    try{return document.execCommand('copy') === true;}catch(_){return false;}finally{document.body.removeChild(text);restoreFocus(button,previous);}
  }
  document.addEventListener('click',function(event){
    var button=event.target.closest ? event.target.closest('[data-copy]') : null;
    if(!button){return;}
    var value=button.getAttribute('data-copy') || '';
    if(!value){return;}
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(value).then(function(){showResult(button,true);},function(){showResult(button,fallbackCopy(value,button));});
      return;
    }
    showResult(button,fallbackCopy(value,button));
  });
})();
</script>
</body>
</html>`
