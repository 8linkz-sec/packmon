package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
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
	Scope      string
	Relation   string
	Flags      string
}

type listAllPackageReport struct {
	Target      string
	ScannedAt   string
	Rows        []listAllRow
	ScopeCounts map[string]int
	WithUpdates int
	Vulnerable  int
	Unknown     int
}

type listAllRow struct {
	Name      string
	Installed string
	Latest    string
	Update    string
	Ecosystem string
	Scope     string
	Relation  string
	Via       string
	Flags     string
	Vuln      string
	LockFile  string
}

type listAllFindingRow struct {
	Severity     string
	Package      string
	Ecosystem    string
	Advisory     string
	FixedVersion string
	Source       string
	Scope        string
	Relation     string
	Via          string
	Flags        string
}

type listAllScopeSummary struct {
	Scope string
	Count int
}

type listAllLatest struct {
	Latest  string
	Update  string
	Unknown bool
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
			Name:      p.Name,
			Installed: p.Version,
			Latest:    latestCol,
			Update:    update,
			Ecosystem: string(p.Ecosystem),
			Scope:     scope,
			Relation:  listAllPackageRelation(p),
			Via:       strings.Join(p.Via, ", "),
			Flags:     listAllPackageFlags(p),
			Vuln:      vuln,
			LockFile:  p.LockFile,
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

	return report
}

func resolveListAllLatest(ctx context.Context, p listAllPackage) listAllLatest {
	if p.Ecosystem == domain.EcosystemDocker {
		return resolveDockerImageStatusFn(ctx, p)
	}
	lat := fetchLatestVersionFn(ctx, p.Ecosystem, p.Name)
	if lat == "" {
		return listAllLatest{Latest: "unknown", Update: "-", Unknown: true}
	}
	if updateAvailable(p.Version, lat, p.Ecosystem) {
		return listAllLatest{Latest: lat, Update: "yes"}
	}
	return listAllLatest{Latest: lat, Update: "-"}
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
		return listAllLatest{Latest: shortDigest(remoteDigest), Update: "unknown", Unknown: true}
	}
	if localDigest != remoteDigest {
		return listAllLatest{Latest: shortDigest(remoteDigest), Update: "yes"}
	}
	return listAllLatest{Latest: shortDigest(remoteDigest), Update: "-"}
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
	return algo + ":" + value[:12]
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
	maxName, maxInst, maxLat, maxUpd, maxEco, maxScope, maxRel, maxVia, maxFlags, maxVuln := 7, 9, 6, 6, 9, 5, 8, 3, 5, 4
	for _, r := range report.Rows {
		maxName = maxInt(maxName, len(r.Name))
		maxInst = maxInt(maxInst, len(r.Installed))
		maxLat = maxInt(maxLat, len(r.Latest))
		maxUpd = maxInt(maxUpd, len(r.Update))
		maxEco = maxInt(maxEco, len(r.Ecosystem))
		maxScope = maxInt(maxScope, len(r.Scope))
		maxRel = maxInt(maxRel, len(r.Relation))
		maxVia = maxInt(maxVia, len(r.Via))
		maxFlags = maxInt(maxFlags, len(r.Flags))
		maxVuln = maxInt(maxVuln, len(r.Vuln))
	}

	gap := "  "
	fmtStr := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		maxName, gap, maxInst, gap, maxLat, gap, maxUpd, gap, maxEco, gap, maxScope, gap, maxRel, gap, maxVia, gap, maxFlags, gap, maxVuln, gap)

	fmt.Printf(fmtStr, "PACKAGE", "INSTALLED", "LATEST", "UPDATE", "ECOSYSTEM", "SCOPE", "RELATION", "VIA", "FLAGS", "VULN", "LOCK FILE")
	for _, r := range report.Rows {
		fmt.Printf(fmtStr, r.Name, r.Installed, r.Latest, r.Update, r.Ecosystem, r.Scope, r.Relation, r.Via, r.Flags, r.Vuln, r.LockFile)
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
		PackageRows  []listAllRow
		PackageInfo  listAllPackageReport
		ScopeSummary []listAllScopeSummary
		Findings     []listAllFindingRow
		FindingsN    int
		Blocking     int
		Status       string
		FailOn       string
	}{
		Title:        title,
		Mode:         result.Mode,
		PackageRows:  packages.Rows,
		PackageInfo:  packages,
		ScopeSummary: listAllScopeSummaries(packages),
		FindingsN:    len(result.Findings),
		Status:       listAllOperationalStatus(result.FeedStatus),
		FailOn:       string(failOn),
	}
	packageMetadata := listAllRowsByPackage(packages.Rows)
	for _, f := range result.Findings {
		meta := packageMetadata[listAllFindingKey(f)]
		rep.Findings = append(rep.Findings, listAllFindingRow{
			Severity:     string(f.Severity),
			Package:      fmt.Sprintf("%s@%s", f.Name, f.Version),
			Ecosystem:    string(f.Ecosystem),
			Advisory:     listAllAdvisoryLabel(f),
			FixedVersion: f.FixedVersion,
			Source:       f.Source,
			Scope:        meta.Scope,
			Relation:     meta.Relation,
			Via:          meta.Via,
			Flags:        meta.Flags,
		})
		if listAllFindingBlocks(f, failOn) {
			rep.Blocking++
		}
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

func listAllRowsByPackage(rows []listAllRow) map[string]listAllRow {
	out := make(map[string]listAllRow, len(rows))
	for _, row := range rows {
		out[row.Ecosystem+"/"+row.Name+"@"+row.Installed] = row
	}
	return out
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
		return "SUPPLY-CHAIN"
	case domain.FindingTypeLifecycle:
		return "LIFECYCLE"
	default:
		return ""
	}
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
table{width:100%;min-width:1600px;border-collapse:collapse;background:var(--panel);}
th,td{padding:8px 10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;}
th{color:#e6edf3;font-size:12px;text-transform:uppercase;}
td{word-break:normal;}
.name{min-width:260px;word-break:break-word;}
.version{white-space:nowrap;min-width:260px;}
.short{white-space:nowrap;min-width:90px;}
.lockfile{min-width:260px;word-break:break-word;}
.finding-package{min-width:360px;word-break:break-word;}
.status{margin:18px 0;padding:14px 16px;background:#321820;border:1px solid var(--crit);border-radius:6px;color:var(--crit);font-size:15px;}
.empty{margin:16px 0;padding:14px 16px;background:#0f2d2a;border:1px solid var(--low);border-radius:6px;color:var(--low);font-size:15px;}
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
<span class="badge">{{.FindingsN}} findings &middot; {{.Blocking}} blocking</span>
{{range .ScopeSummary}}<span class="badge">{{.Scope}} {{.Count}}</span>{{end}}
</div>
{{if .Status}}<div class="status">Scan did not complete: {{.Status}}</div>{{end}}
<h2>Findings</h2>
{{if .Findings}}
<div class="table-scroll">
<table>
<thead><tr><th class="short">Severity</th><th class="finding-package">Package</th><th class="short">Ecosystem</th><th>Advisory</th><th>Fix Version</th><th>Source</th><th class="short">Scope</th><th class="short">Relation</th><th>Via</th><th class="short">Flags</th></tr></thead>
<tbody>
{{range .Findings}}<tr><td class="short">{{.Severity}}</td><td class="finding-package">{{.Package}}</td><td class="short">{{.Ecosystem}}</td><td>{{.Advisory}}</td><td>{{.FixedVersion}}</td><td>{{.Source}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td><td>{{.Via}}</td><td class="short">{{.Flags}}</td></tr>{{end}}
</tbody>
</table>
</div>
{{else if not .Status}}
<div class="empty">No findings in {{len .PackageRows}} packages.</div>
{{end}}
<h2>All Packages</h2>
{{if .PackageRows}}
<div class="table-scroll">
<table>
<thead><tr><th class="name">Package</th><th class="version">Installed</th><th class="version">Latest</th><th class="short">Update</th><th class="short">Ecosystem</th><th class="short">Scope</th><th class="short">Relation</th><th>Via</th><th class="short">Flags</th><th class="short">Vuln</th><th class="lockfile">Lock File</th></tr></thead>
<tbody>
{{range .PackageRows}}<tr><td class="name">{{.Name}}</td><td class="version">{{.Installed}}</td><td class="version">{{.Latest}}</td><td class="short">{{.Update}}</td><td class="short">{{.Ecosystem}}</td><td class="short">{{.Scope}}</td><td class="short">{{.Relation}}</td><td>{{.Via}}</td><td class="short">{{.Flags}}</td><td class="short">{{.Vuln}}</td><td class="lockfile">{{.LockFile}}</td></tr>{{end}}
</tbody>
</table>
</div>
{{else}}
<div class="empty">No packages found.</div>
{{end}}
<div class="footer">fail-on {{.FailOn}}</div>
</div>
</body>
</html>`
