package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/8linkz/packmon/internal/dockerimage"
	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/parser"
	"github.com/8linkz/packmon/internal/scanner"
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
	Scope      string
	Relation   string
	Flags      string
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
	Via        string
	Flags      string
	Vuln       string
	LockFile   string
}

type listAllHTMLPackageRow struct {
	Name       string
	Installed  string
	Latest     string
	LatestCopy string
	Status     string
	Ecosystem  string
	Source     string
	Scope      string
	Relation   string
	Via        string
	Flags      string
	Vuln       string
}

type listAllHTMLFindingState struct {
	Status          string
	Rank            int
	HasFixedVersion bool
}

type listAllFindingRow struct {
	Severity     string
	Package      string
	Ecosystem    string
	Advisory     string
	AdvisoryURL  string
	Title        string
	FixedVersion string
	Source       string
	Scope        string
	Relation     string
	Via          string
	Flags        string
}

type listAllSourceRow struct {
	Kind string
	Path string
}

type listAllScopeSummary struct {
	Scope string
	Count int
}

type listAllLatest struct {
	Latest     string
	LatestCopy string
	Update     string
	Unknown    bool
}

var resolveDockerImageStatusFn = resolveDockerImageStatus

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
	inventorySettings := settings
	inventorySettings.IncludeDev = true
	packages, err := collectAllPackages(inventorySettings)
	if err != nil {
		return exitCode, err
	}

	packageReport := buildListAllPackageReport(packages, result, settings.Path)
	packageReport.Sources = mergeListAllSourceRows(packageReport.Sources, listAllExplicitSBOMSources(settings))
	htmlWritten := false
	if settings.OutputHTML != "" {
		if err := writeListAllHTML(settings.OutputHTML, settings.TargetName, failOn, result, packageReport); err != nil {
			return exitCode, err
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
	if err := fatalCollectionParseError(collection); err != nil {
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

	dockerRows, dockerErr := collectDockerPackages(absPath, settings)
	if dockerErr != nil {
		fmt.Fprintf(os.Stderr, "warning: docker inventory error: %v\n", dockerErr)
	} else {
		packages = append(packages, dockerRows...)
	}

	return packages, nil
}

func collectDockerPackages(absPath string, settings scanSettings) ([]listAllPackage, error) {
	if !listAllAllowsEcosystem(settings.Ecosystems, domain.EcosystemDocker) {
		return nil, nil
	}
	collection, err := dockerimage.Collect(absPath, settings.MaxDepth)
	if err != nil {
		return nil, err
	}
	for _, parseErr := range collection.ParseErrors {
		fmt.Fprintf(os.Stderr, "warning: docker parse error in %s\n", parseErr)
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
		})
	}
	return rows, nil
}

func listAllAllowsEcosystem(ecosystems []string, eco domain.Ecosystem) bool {
	if len(ecosystems) == 0 {
		return true
	}
	for _, raw := range ecosystems {
		if strings.EqualFold(strings.TrimSpace(raw), string(eco)) {
			return true
		}
	}
	return false
}

func buildListAllPackageReport(packages []listAllPackage, result *domain.ScanResult, scanPath string) listAllPackageReport {
	// Look up latest versions in parallel with a bounded request fan-out and a
	// 60s timeout, exactly like runOutdated.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	latest := make([]listAllLatest, len(packages))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentRegistryRequests)
	for i, pkg := range packages {
		wg.Add(1)
		go func(idx int, p listAllPackage) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			latest[idx] = resolveListAllLatest(ctx, p)
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

	report := listAllPackageReport{
		Target:      scanPath,
		ScannedAt:   time.Now().UTC().Format("2006-01-02 15:04"),
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

		scope := listAllPackageScope(p)
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
			Relation:   listAllPackageRelation(p),
			Via:        strings.Join(p.Via, ", "),
			Flags:      listAllPackageFlags(p),
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

func resolveListAllLatest(ctx context.Context, p listAllPackage) listAllLatest {
	if p.Ecosystem == domain.EcosystemDocker {
		return resolveDockerImageStatusFn(ctx, p)
	}
	return resolvePackageUpdateStatus(ctx, p.Name, p.Version, p.Ecosystem, p.Direct, p.Parents)
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

func resolveDockerImageStatus(ctx context.Context, p listAllPackage) listAllLatest {
	ref, ok := dockerRefFromListAllPackage(p)
	if !ok || strings.HasPrefix(p.Name, "local/") {
		return listAllLatest{Latest: "unknown", Update: "unknown", Unknown: true}
	}
	registryClient := dockerimage.NewRegistryClient(http.DefaultClient)
	remoteDigest, err := registryClient.ResolveDigest(ctx, ref)
	if err != nil || remoteDigest == "" {
		return listAllLatest{Latest: "unknown", Update: "unknown", Unknown: true}
	}
	localDigests := dockerimage.LocalInspector{}.Digests(ctx, []dockerimage.Ref{ref})
	localDigest := localDigests[ref.Name]
	if localDigest == "" {
		return listAllLatest{Latest: shortDigest(remoteDigest), LatestCopy: remoteDigest, Update: "unknown", Unknown: true}
	}
	if localDigest != remoteDigest {
		return listAllLatest{Latest: shortDigest(remoteDigest), LatestCopy: remoteDigest, Update: "yes"}
	}
	return listAllLatest{Latest: shortDigest(remoteDigest), LatestCopy: remoteDigest, Update: "-"}
}

func dockerRefFromListAllPackage(p listAllPackage) (dockerimage.Ref, bool) {
	raw := p.Name + ":" + p.Version
	if strings.Contains(p.Version, ":") {
		raw = p.Name + "@" + p.Version
	}
	return dockerimage.ParseRef(raw)
}

func shortDigest(digest string) string {
	algo, value, ok := strings.Cut(digest, ":")
	if !ok || len(value) <= 12 {
		return digest
	}
	return algo + ":" + value[:12] + ".."
}

func listAllPackageScope(p listAllPackage) string {
	if p.Scope != "" {
		return p.Scope
	}
	switch {
	case p.Ecosystem == domain.EcosystemGitHubActions:
		return "ci"
	case p.SourceType == "sbom":
		return "sbom"
	case p.Dev:
		return "dev"
	default:
		return "runtime"
	}
}

func listAllPackageRelation(p listAllPackage) string {
	if p.Relation != "" {
		return p.Relation
	}
	switch {
	case p.Ecosystem == domain.EcosystemGitHubActions:
		return "workflow"
	case p.Direct:
		return "direct"
	case p.Indirect:
		return "transitive"
	default:
		return "declared"
	}
}

func listAllPackageFlags(p listAllPackage) string {
	if p.Flags != "" {
		return p.Flags
	}
	var flags []string
	if p.Optional {
		flags = append(flags, "optional")
	}
	if p.Peer {
		flags = append(flags, "peer")
	}
	return strings.Join(flags, ", ")
}

func printListAllPackageReport(report listAllPackageReport) {
	// Column widths (header widths as the minimum).
	maxName, maxInst, maxLat, maxUpd, maxEco, maxSource, maxScope, maxRel, maxVia, maxFlags, maxVuln := 7, 9, 6, 6, 9, 6, 5, 8, 3, 5, 4
	for _, r := range report.Rows {
		maxName = maxInt(maxName, len(r.Name))
		maxInst = maxInt(maxInst, len(r.Installed))
		maxLat = maxInt(maxLat, len(r.Latest))
		maxUpd = maxInt(maxUpd, len(r.Update))
		maxEco = maxInt(maxEco, len(r.Ecosystem))
		maxSource = maxInt(maxSource, len(r.Source))
		maxScope = maxInt(maxScope, len(r.Scope))
		maxRel = maxInt(maxRel, len(r.Relation))
		maxVia = maxInt(maxVia, len(r.Via))
		maxFlags = maxInt(maxFlags, len(r.Flags))
		maxVuln = maxInt(maxVuln, len(r.Vuln))
	}

	gap := "  "
	fmtStr := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		maxName, gap, maxInst, gap, maxLat, gap, maxUpd, gap, maxEco, gap, maxSource, gap, maxScope, gap, maxRel, gap, maxVia, gap, maxFlags, gap, maxVuln, gap)

	fmt.Printf(fmtStr, "PACKAGE", "INSTALLED", "LATEST", "UPDATE", "ECOSYSTEM", "SOURCE", "SCOPE", "RELATION", "VIA", "FLAGS", "VULN", "SOURCE FILE")
	for _, r := range report.Rows {
		fmt.Printf(fmtStr, r.Name, r.Installed, r.Latest, r.Update, r.Ecosystem, r.Source, r.Scope, r.Relation, r.Via, r.Flags, r.Vuln, r.LockFile)
	}

	fmt.Printf("\n%d packages (%d with updates, %d vulnerable, %d unknown)\n",
		len(report.Rows), report.WithUpdates, report.Vulnerable, report.Unknown)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var listAllHTMLTemplate = template.Must(template.New("list-all").Parse(listAllHTML))

func writeListAllHTML(path, title string, failOn domain.Severity, result *domain.ScanResult, packages listAllPackageReport) error {
	if err := ensureOutputDir(path); err != nil {
		return fmt.Errorf("prepare HTML output: %w", err)
	}
	if strings.TrimSpace(title) == "" {
		title = "Packmon List-All Report"
	}
	rep := struct {
		Title        string
		Mode         string
		PackageRows  []listAllHTMLPackageRow
		Attention    []listAllHTMLPackageRow
		PackageInfo  listAllPackageReport
		ScopeSummary []listAllScopeSummary
		Findings     []listAllFindingRow
		Sources      []listAllSourceRow
		Status       string
		FailOn       string
	}{
		Title:        title,
		Mode:         result.Mode,
		PackageInfo:  packages,
		ScopeSummary: listAllScopeSummaries(packages),
		Sources:      packages.Sources,
		Status:       listAllOperationalStatus(result.FeedStatus),
		FailOn:       string(failOn),
	}
	rep.PackageRows = listAllHTMLPackageRows(packages.Rows, result.Findings)
	rep.Attention = listAllHTMLAttentionRows(rep.PackageRows)
	rep.PackageInfo = listAllHTMLPackageInfo(rep.PackageInfo, rep.PackageRows)
	if len(rep.Sources) == 0 {
		rep.Sources = listAllCheckedInventorySources(packages.Rows)
	}
	packageMetadata := listAllRowsByPackage(packages.Rows)
	for _, f := range result.Findings {
		meta := packageMetadata[listAllFindingKey(f)]
		rep.Findings = append(rep.Findings, listAllFindingRow{
			Severity:     string(f.Severity),
			Package:      fmt.Sprintf("%s@%s", f.Name, f.Version),
			Ecosystem:    string(f.Ecosystem),
			Advisory:     listAllAdvisoryLabel(f),
			AdvisoryURL:  listAllAdvisoryURL(f),
			Title:        f.Title,
			FixedVersion: f.FixedVersion,
			Source:       f.Source,
			Scope:        meta.Scope,
			Relation:     meta.Relation,
			Via:          meta.Via,
			Flags:        meta.Flags,
		})
	}

	// #nosec G304 -- CLI output path is provided intentionally by the local user.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("html: create file %s: %w", path, err)
	}
	if err := listAllHTMLTemplate.Execute(file, rep); err != nil {
		closeSilently(file)
		return fmt.Errorf("html: render list-all report: %w", err)
	}
	return file.Close()
}

func listAllHTMLPackageRows(rows []listAllRow, findings []domain.Finding) []listAllHTMLPackageRow {
	findingStatuses := listAllHTMLFindingStatuses(findings)

	out := make([]listAllHTMLPackageRow, 0, len(rows))
	for _, row := range rows {
		_, hasFinding := findingStatuses[row.Ecosystem+"/"+row.Name+"@"+row.Installed]
		vuln := row.Vuln
		if hasFinding {
			vuln = "yes"
		}
		out = append(out, listAllHTMLPackageRow{
			Name:       row.Name,
			Installed:  row.Installed,
			Latest:     listAllHTMLCopyDisplay(row.Latest, row.LatestCopy),
			LatestCopy: strings.TrimSpace(row.LatestCopy),
			Status:     listAllHTMLPackageStatus(row, findingStatuses),
			Ecosystem:  row.Ecosystem,
			Source:     listAllHTMLPackageSource(row),
			Scope:      row.Scope,
			Relation:   row.Relation,
			Via:        row.Via,
			Flags:      row.Flags,
			Vuln:       vuln,
		})
	}
	return out
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
	if finding.Type == domain.FindingTypeMalicious {
		return "Malicious", 50
	}
	if strings.EqualFold(strings.TrimSpace(finding.RiskType), "malware_history") {
		return "Malware history", 35
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
			row.Status == "Malware history" ||
			row.Status == "Supply-chain risk" ||
			row.Status == "Lifecycle" ||
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
		return path
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

func listAllAdvisoryLabel(f domain.Finding) string {
	if f.AdvisoryID != "" {
		return f.AdvisoryID
	}
	switch f.Type {
	case domain.FindingTypeMalicious:
		return "MALWARE"
	case domain.FindingTypeSupplyChainRisk:
		if strings.EqualFold(strings.TrimSpace(f.RiskType), "malware_history") {
			return "MALWARE-HISTORY"
		}
		return "SUPPLY-CHAIN"
	case domain.FindingTypeLifecycle:
		return "LIFECYCLE"
	default:
		return ""
	}
}

func listAllAdvisoryURL(f domain.Finding) string {
	advisoryID := strings.TrimSpace(f.AdvisoryID)
	advisoryIDUpper := strings.ToUpper(advisoryID)
	if strings.HasPrefix(advisoryIDUpper, "GHSA-") {
		return "https://github.com/advisories/" + advisoryID
	}
	if strings.HasPrefix(advisoryIDUpper, "CVE-") {
		return "https://nvd.nist.gov/vuln/detail/" + advisoryID
	}
	if strings.HasPrefix(advisoryIDUpper, "RUSTSEC-") {
		return "https://rustsec.org/advisories/" + advisoryID + ".html"
	}
	if strings.HasPrefix(strings.ToLower(advisoryID), "reversinglabs:") ||
		strings.EqualFold(strings.TrimSpace(f.Source), "reversinglabs") {
		if u := listAllSecureSoftwarePackageURL(f.Ecosystem, f.Name); u != "" {
			return u
		}
	}
	if u := listAllSafeHTTPURL(f.URL); u != "" {
		return u
	}
	for _, resource := range f.Resources {
		if u := listAllSafeHTTPURL(resource.URL); u != "" {
			return u
		}
	}
	return ""
}

func listAllSecureSoftwarePackageURL(ecosystem domain.Ecosystem, name string) string {
	ecosystemValue := strings.TrimSpace(string(ecosystem))
	name = strings.TrimSpace(name)
	if ecosystemValue == "" || name == "" {
		return ""
	}
	return "https://secure.software/" + url.PathEscape(ecosystemValue) + "/packages/" + url.PathEscape(name)
}

func listAllSafeHTTPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	return raw
}

func listAllFindingBlocks(f domain.Finding, failOn domain.Severity) bool {
	switch f.Type {
	case domain.FindingTypeMalicious, domain.FindingTypeSupplyChainRisk:
		return true
	}
	return failOn != domain.SeverityNone && f.Severity.Blocks(failOn)
}

const listAllHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Packmon List-All Report</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--dim:#8b949e;--crit:#ff7b72;--high:#ffa657;--low:#56d4c4;--link:#58a6ff;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;line-height:1.5;}
.wrap{max-width:1600px;margin:0 auto;padding:28px 20px 48px;}
h1{font-size:22px;margin:0;color:#e6edf3;}
h2{font-size:16px;margin:26px 0 10px;color:#e6edf3;border-bottom:1px solid var(--border);padding-bottom:5px;}
.meta{color:var(--dim);font-size:13px;margin:4px 0 18px;}
.summary{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 22px;}
.badge{border:1px solid var(--border);border-radius:6px;padding:3px 11px;font-size:13px;color:var(--dim);}
.warn{color:var(--high);border-color:var(--high);}
.ok{color:var(--low);border-color:var(--low);}
.bad{color:var(--crit);border-color:var(--crit);}
.table-scroll{overflow-x:auto;border:1px solid var(--border);border-radius:6px;background:var(--panel);}
table{width:100%;min-width:1500px;border-collapse:collapse;background:var(--panel);}
th,td{padding:8px 10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;}
th{color:#e6edf3;font-size:12px;text-transform:uppercase;}
td{word-break:normal;}
.name{min-width:260px;word-break:break-word;}
.version{white-space:nowrap;min-width:260px;}
.short{white-space:nowrap;min-width:90px;}
.nowrap{white-space:nowrap;}
.source{white-space:nowrap;min-width:105px;}
.finding-package{min-width:360px;word-break:break-word;}
.advisory{min-width:260px;}
a{color:var(--link);text-decoration:none;}
a:hover{text-decoration:underline;}
.copy-value{white-space:nowrap;}
.copy-btn{margin-left:8px;border:1px solid var(--border);border-radius:4px;background:#21262d;color:var(--fg);font:inherit;font-size:12px;padding:1px 7px;cursor:pointer;}
.copy-btn:hover{border-color:var(--link);color:var(--link);}
.status{margin:18px 0;padding:14px 16px;background:#321820;border:1px solid var(--crit);border-radius:6px;color:var(--crit);font-size:15px;}
.empty{margin:16px 0;padding:14px 16px;background:#0f2d2a;border:1px solid var(--low);border-radius:6px;color:var(--low);font-size:15px;}
.source-list{margin:0;padding:0;list-style:none;border:1px solid var(--border);border-radius:6px;background:var(--panel);}
.source-list li{display:flex;gap:10px;align-items:flex-start;padding:8px 10px;border-bottom:1px solid var(--border);}
.source-list li:last-child{border-bottom:0;}
.source-kind{flex:0 0 90px;color:var(--dim);text-transform:uppercase;font-size:12px;}
.source-path{min-width:0;overflow-wrap:anywhere;word-break:break-word;}
.footer{border-top:1px solid var(--border);margin-top:28px;padding-top:10px;color:var(--dim);font-size:12px;}
</style>
</head>
<body>
<div class="wrap">
<h1>Packmon List-All Report</h1>
<div class="meta">{{.Title}}{{if .Mode}} &middot; {{.Mode}} mode{{end}}{{if .PackageInfo.Target}} &middot; {{.PackageInfo.Target}}{{end}}{{if .PackageInfo.ScannedAt}} &middot; {{.PackageInfo.ScannedAt}}{{end}}</div>
<div class="summary">
<span class="badge">{{len .PackageRows}} packages</span>
<span class="badge warn">{{.PackageInfo.WithUpdates}} with updates</span>
<span class="badge bad">{{.PackageInfo.Vulnerable}} vulnerable</span>
<span class="badge">{{.PackageInfo.Unknown}} unknown</span>
{{range .ScopeSummary}}<span class="badge">{{.Scope}} {{.Count}}</span>{{end}}
</div>
{{if .Status}}<div class="status">Scan did not complete: {{.Status}}</div>{{end}}
<h2>Packages Needing Attention</h2>
{{if .Attention}}
<div class="table-scroll">
<table>
<thead><tr><th class="name">Package</th><th class="version">Installed</th><th class="version">Latest</th><th class="short">Status</th><th class="short">Ecosystem</th><th class="source">Source</th><th class="short">Scope</th><th class="short">Relation</th><th class="short">Vuln</th></tr></thead>
<tbody>
{{range .Attention}}<tr><td class="name">{{.Name}}</td><td class="version">{{.Installed}}</td><td class="version">{{if .LatestCopy}}<span class="copy-value">{{.Latest}}</span><button type="button" class="copy-btn" data-copy="{{.LatestCopy}}" aria-label="Copy full value">Copy</button>{{else}}{{.Latest}}{{end}}</td><td class="short">{{.Status}}</td><td class="short">{{.Ecosystem}}</td><td class="source">{{.Source}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td><td class="short">{{.Vuln}}</td></tr>{{end}}
</tbody>
</table>
</div>
{{else if not .Status}}
<div class="empty">No package status issues requiring attention.</div>
{{end}}
<h2>Security Findings</h2>
{{if .Findings}}
<div class="table-scroll">
<table>
<thead><tr><th class="short">Severity</th><th class="finding-package">Package</th><th class="short">Ecosystem</th><th class="advisory nowrap">Advisory</th><th>Finding</th><th>Fix Version</th><th>Source</th><th class="short">Scope</th><th class="short">Relation</th></tr></thead>
<tbody>
{{range .Findings}}<tr><td class="short">{{.Severity}}</td><td class="finding-package">{{.Package}}</td><td class="short">{{.Ecosystem}}</td><td class="advisory nowrap">{{if .AdvisoryURL}}<a href="{{.AdvisoryURL}}" target="_blank" rel="noopener">{{.Advisory}}</a>{{else}}{{.Advisory}}{{end}}</td><td>{{.Title}}</td><td>{{.FixedVersion}}</td><td>{{.Source}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td></tr>{{end}}
</tbody>
</table>
</div>
{{else if not .Status}}
<div class="empty">No security findings in {{len .PackageRows}} packages.</div>
{{end}}
<h2>All Packages</h2>
{{if .PackageRows}}
<div class="table-scroll">
<table>
<thead><tr><th class="name">Package</th><th class="version">Installed</th><th class="version">Latest</th><th class="short">Status</th><th class="short">Ecosystem</th><th class="source">Source</th><th class="short">Scope</th><th class="short">Relation</th><th class="short">Vuln</th></tr></thead>
<tbody>
{{range .PackageRows}}<tr><td class="name">{{.Name}}</td><td class="version">{{.Installed}}</td><td class="version">{{if .LatestCopy}}<span class="copy-value">{{.Latest}}</span><button type="button" class="copy-btn" data-copy="{{.LatestCopy}}" aria-label="Copy full value">Copy</button>{{else}}{{.Latest}}{{end}}</td><td class="short">{{.Status}}</td><td class="short">{{.Ecosystem}}</td><td class="source">{{.Source}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td><td class="short">{{.Vuln}}</td></tr>{{end}}
</tbody>
</table>
</div>
{{else}}
<div class="empty">No packages found.</div>
{{end}}
{{if .Sources}}
<h2>Checked Inventory Sources</h2>
<ul class="source-list">
{{range .Sources}}<li><span class="source-kind">{{.Kind}}</span><span class="source-path">{{.Path}}</span></li>{{end}}
</ul>
{{end}}
<div class="footer">fail-on {{.FailOn}}</div>
</div>
<script>
(function(){
  function fallbackCopy(value){
    var text=document.createElement('textarea');
    text.value=value;
    text.setAttribute('readonly','');
    text.style.position='fixed';
    text.style.opacity='0';
    document.body.appendChild(text);
    text.select();
    try{document.execCommand('copy');}finally{document.body.removeChild(text);}
  }
  document.addEventListener('click',function(event){
    var button=event.target.closest ? event.target.closest('[data-copy]') : null;
    if(!button){return;}
    var value=button.getAttribute('data-copy') || '';
    if(!value){return;}
    var mark=function(){button.textContent='Copied'; window.setTimeout(function(){button.textContent='Copy';},1200);};
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(value).then(mark,function(){fallbackCopy(value); mark();});
      return;
    }
    fallbackCopy(value);
    mark();
  });
})();
</script>
</body>
</html>`
