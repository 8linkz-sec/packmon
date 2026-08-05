package main

import (
	"fmt"
	"html/template"
	"strings"
	"sync"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/8linkz-sec/packmon/internal/reporthtml"
	"github.com/8linkz-sec/packmon/internal/scanner"
)

const (
	listAllHTMLCopyConfirmationVisibleMs = "5000"
	maxListAllHTMLReportWarnings         = 5
)

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

type listAllHTMLMessages struct {
	ReportType                         string
	ModeSuffix                         string
	PackageSingular                    string
	PackagePlural                      string
	WithUpdateSingular                 string
	WithUpdatePlural                   string
	VulnerabilitySingular              string
	VulnerabilityPlural                string
	UnknownSingular                    string
	UnknownPlural                      string
	UnknownStatusHint                  string
	StatusPrefix                       string
	PackagesNeedingAttentionHeading    string
	PackagesNeedingAttentionTableLabel string
	PackageColumn                      string
	InstalledColumn                    string
	LatestColumn                       string
	ActionColumn                       string
	TriageColumn                       string
	VulnerabilityColumn                string
	EcosystemLabel                     string
	SourceLabel                        string
	ScopeLabel                         string
	RelationLabel                      string
	NoPackageStatusIssues              string
	PackageAttentionWarnings           string
	SecurityFindingsHeading            string
	SeverityColumn                     string
	AdvisoryColumn                     string
	FindingColumn                      string
	OpenInNewTabAriaLabel              string
	OpenInNewTabScreenReader           string
	NoSecurityFindingsPrefix           string
	NoSecurityFindingsSuffix           string
	SecurityFindingsWarnings           string
	AllPackagesHeading                 string
	AllPackagesTableLabel              string
	StatusColumn                       string
	InventoryDetailsColumn             string
	NoPackagesFound                    string
	NoPackageInventoryRows             string
	CheckedInventorySourcesHeading     string
	CopyButton                         string
	CopyFullValue                      string
	CopiedFullValue                    string
	CopyFailed                         string
	CopyFailedManual                   string
	FullValueManualCopyLabel           string
}

func defaultListAllHTMLMessages() listAllHTMLMessages {
	return listAllHTMLMessages{
		ReportType:            "Packmon List-All Report",
		ModeSuffix:            "mode",
		PackageSingular:       "package",
		PackagePlural:         "packages",
		WithUpdateSingular:    "with update",
		WithUpdatePlural:      "with updates",
		VulnerabilitySingular: "vulnerability",
		VulnerabilityPlural:   "vulnerabilities",
		UnknownSingular:       "unknown",
		UnknownPlural:         "unknown",
		UnknownStatusHint: "Unknown status means the latest version could not be determined " +
			"(offline mode, unreachable registry, or an unsupported/private source); " +
			"security findings for these packages are unaffected. For additional " +
			"reputation and malware-history coverage, configure the server-side " +
			"ReversingLabs Spectra Assure key (PACKMON_REVERSINGLABS_API_KEY).",
		StatusPrefix:                       "Scan did not complete:",
		PackagesNeedingAttentionHeading:    "Packages Needing Attention",
		PackagesNeedingAttentionTableLabel: "Packages needing attention table",
		PackageColumn:                      "Package",
		InstalledColumn:                    "Installed",
		LatestColumn:                       "Latest",
		ActionColumn:                       "Action",
		TriageColumn:                       "Triage",
		VulnerabilityColumn:                "Vulnerability",
		EcosystemLabel:                     "Ecosystem",
		SourceLabel:                        "Source",
		ScopeLabel:                         "Scope",
		RelationLabel:                      "Relation",
		NoPackageStatusIssues:              "No package status issues requiring attention.",
		PackageAttentionWarnings:           "Package attention could not be fully evaluated because report warnings require review.",
		SecurityFindingsHeading:            "Security Findings",
		SeverityColumn:                     "Severity",
		AdvisoryColumn:                     "Advisory",
		FindingColumn:                      "Finding",
		OpenInNewTabAriaLabel:              "%s opens in a new tab",
		OpenInNewTabScreenReader:           " (opens in a new tab)",
		NoSecurityFindingsPrefix:           "No security findings in",
		NoSecurityFindingsSuffix:           ".",
		SecurityFindingsWarnings:           "Security findings could not be confirmed clean because report warnings require review.",
		AllPackagesHeading:                 "All Packages",
		AllPackagesTableLabel:              "All packages table",
		StatusColumn:                       "Status",
		InventoryDetailsColumn:             "Inventory Details",
		NoPackagesFound:                    "No packages found.",
		NoPackageInventoryRows:             "No package inventory rows were available; review the warnings above for coverage gaps.",
		CheckedInventorySourcesHeading:     "Checked Inventory Sources",
		CopyButton:                         "Copy",
		CopyFullValue:                      "Copy full value",
		CopiedFullValue:                    "Copied full value",
		CopyFailed:                         "Copy failed",
		CopyFailedManual:                   "Copy failed. Full value is selected for manual copy.",
		FullValueManualCopyLabel:           "Full value to copy manually",
	}
}

// listAllUnknownStatusHint explains the unknown rows from what actually
// happened during the lookup phase, so a clean run with private packages is
// not mistaken for a lookup problem and vice versa.
func listAllUnknownStatusHint(report listAllPackageReport) string {
	const findingsUnaffected = "security findings for these packages are unaffected."
	const reversingLabsNote = " For additional reputation and malware-history coverage, configure the " +
		"server-side ReversingLabs Spectra Assure key (PACKMON_REVERSINGLABS_API_KEY)."
	if report.Offline {
		return "Unknown status means the latest version was not looked up in offline mode; " +
			findingsUnaffected + reversingLabsNote
	}
	if report.RefusedRequests == 0 && !report.BreakerTripped {
		return "The unknown rows are packages the public registry does not carry (workspace or " +
			"private packages) or sources Packmon intentionally does not query; no action is needed, and " +
			findingsUnaffected + reversingLabsNote
	}
	hint := "Unknown status means the latest version could not be determined; " + findingsUnaffected
	if report.RefusedRequests > 0 {
		hint += fmt.Sprintf(" %d registry requests were refused or failed -- rerun the scan, raise --timeout, or configure a registry mirror.", report.RefusedRequests)
	}
	if report.BreakerTripped {
		hint += fmt.Sprintf(" Lookups were aborted after consecutive registry failures (%d skipped) -- check network connectivity and proxy settings.", report.SkippedRequests)
	}
	return hint + reversingLabsNote
}

var listAllHTMLTemplate = sync.OnceValue(func() *template.Template {
	return template.Must(template.New("list-all").Funcs(template.FuncMap{
		"count":          plural.Count,
		"htmlPackageRow": listAllHTMLPackageView,
	}).Parse(listAllHTML))
})

func writeListAllHTML(path, title string, result *domain.ScanResult, packages listAllPackageReport) error {
	if err := ensureOutputDir(path); err != nil {
		return fmt.Errorf("prepare HTML output: %w", err)
	}
	if strings.TrimSpace(title) == "" {
		title = "Packmon List-All Report"
	}
	sourceRoot := packages.Target
	messages := defaultListAllHTMLMessages()
	messages.UnknownStatusHint = listAllUnknownStatusHint(packages)
	reportType := messages.ReportType
	documentTitle := title
	if title != reportType {
		documentTitle = title + " - " + reportType
	}
	packages.ScannedAtDateTime = reportTimestampDateTime(packages.ScannedAt, packages.ScannedAtDateTime)
	findingStatuses := listAllHTMLFindingStatuses(result.Findings)
	vulnSet := listAllVulnerabilityFindingKeys(result.Findings)
	rep := struct {
		Lang                     string
		Messages                 listAllHTMLMessages
		DocumentTitle            string
		Title                    string
		ReportType               string
		Mode                     string
		PackageRows              []listAllRow
		Attention                []int
		PackageInfo              listAllPackageReport
		ScopeSummary             []listAllScopeSummary
		Findings                 []listAllFindingSection
		Sources                  []listAllSourceRow
		Status                   string
		Warnings                 []string
		FindingStatuses          map[string]listAllHTMLFindingState
		VulnerabilityFindingKeys map[string]struct{}
	}{
		Lang:                     defaultGeneratedHTMLReportLang,
		Messages:                 messages,
		DocumentTitle:            documentTitle,
		Title:                    title,
		ReportType:               reportType,
		Mode:                     string(result.Mode),
		PackageRows:              packages.Rows,
		PackageInfo:              packages,
		ScopeSummary:             listAllScopeSummaries(packages),
		Sources:                  packages.Sources,
		Status:                   listAllOperationalStatusForResult(result),
		Warnings:                 listAllHTMLWarnings(result, packages.Warnings),
		FindingStatuses:          findingStatuses,
		VulnerabilityFindingKeys: vulnSet,
	}
	rep.Attention = listAllHTMLAttentionRows(packages.Rows, findingStatuses, vulnSet)
	rep.PackageInfo = listAllHTMLPackageInfo(rep.PackageInfo, packages.Rows, findingStatuses, vulnSet)
	if len(rep.Sources) == 0 {
		rep.Sources = listAllCheckedInventorySources(packages.Rows)
	}
	rep.PackageInfo.Target = htmlReportDisplayTarget(sourceRoot)
	rep.Sources = listAllHTMLDisplaySources(sourceRoot, rep.Sources)
	rep.Findings = listAllHTMLFindingSections(listAllFindingRows(result.Findings, packages.Rows))

	file, err := ioutils.OpenPrivateFile(path)
	if err != nil {
		return fmt.Errorf("html: create file %s: %w", path, err)
	}
	if err := listAllHTMLTemplate().Execute(file, rep); err != nil {
		ioutils.CloseSilently(file)
		return fmt.Errorf("html: render list-all report: %w", err)
	}
	return file.Close()
}

func listAllHTMLPackageView(row listAllRow, findingStatuses map[string]listAllHTMLFindingState, vulnSet map[string]struct{}) listAllHTMLPackageRow {
	vuln := listAllHTMLPackageVulnerability(row, vulnSet)
	status := listAllHTMLPackageStatus(row, findingStatuses)
	installedCopy := listAllHTMLCopyValue(row.Installed)
	installedLabel, installedMessage := listAllHTMLCopyContext("installed", row)
	latestLabel, latestMessage := listAllHTMLCopyContext("latest", row)
	return listAllHTMLPackageRow{
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
		Via:                  row.Via,
		Flags:                row.Flags,
		Vuln:                 vuln,
		VulnClass:            listAllHTMLVulnClass(vuln),
	}
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

func listAllHTMLPackageInfo(info listAllPackageReport, rows []listAllRow, findingStatuses map[string]listAllHTMLFindingState, vulnSet map[string]struct{}) listAllPackageReport {
	info.WithUpdates = 0
	info.Vulnerable = 0
	info.Unknown = 0
	for _, row := range rows {
		status := listAllHTMLPackageStatus(row, findingStatuses)
		vuln := listAllHTMLPackageVulnerability(row, vulnSet)
		if status == "Update available" {
			info.WithUpdates++
		}
		if strings.EqualFold(strings.TrimSpace(vuln), "yes") {
			info.Vulnerable++
		}
		if status == "Unknown" {
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

func listAllHTMLAttentionRows(rows []listAllRow, findingStatuses map[string]listAllHTMLFindingState, vulnSet map[string]struct{}) []int {
	out := make([]int, 0)
	for i, row := range rows {
		status := listAllHTMLPackageStatus(row, findingStatuses)
		vuln := listAllHTMLPackageVulnerability(row, vulnSet)
		if listAllHTMLStatusNeedsAttention(status) ||
			strings.EqualFold(strings.TrimSpace(vuln), "yes") {
			out = append(out, i)
		}
	}
	return out
}

// listAllHTMLStatusNeedsAttention reports whether a package status represents an
// actionable security or lifecycle finding worth surfacing under "Packages
// Needing Attention": malicious/removed/supply-chain-compromised and
// reputation-flagged malware history ("infected"), a CVE ("Vulnerable"), or
// end-of-life ("Lifecycle"). A merely-outdated package ("Update available" with
// no finding) is NOT an attention item -- that is just an available update.
// Vulnerable packages whose status reads "Update available" because a fix exists
// are still caught via the separate vulnerability set.
func listAllHTMLStatusNeedsAttention(status string) bool {
	return status == "Malicious" ||
		status == "Removed" ||
		status == "Supply-chain risk" ||
		status == "Lifecycle" ||
		status == "Reputation info" ||
		status == "Vulnerable"
}

func listAllHTMLPackageVulnerability(row listAllRow, vulnSet map[string]struct{}) string {
	if _, hasVulnerability := vulnSet[listAllRowFindingKey(row)]; hasVulnerability {
		return "yes"
	}
	return row.Vuln
}

func listAllHTMLPackageStatus(row listAllRow, findingStatuses map[string]listAllHTMLFindingState) string {
	if state := findingStatuses[listAllRowFindingKey(row)]; state.Status != "" {
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

func listAllHTMLDisplaySources(root string, sources []listAllSourceRow) []listAllSourceRow {
	out := make([]listAllSourceRow, 0, len(sources))
	for _, source := range sources {
		source.Path = htmlReportDisplaySourcePath(root, source.Path)
		out = append(out, source)
	}
	return listAllSortAndDedupSources(out)
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

func listAllHTMLFindingSections(rows []listAllFindingRow) []listAllFindingSection {
	return listAllFindingSections(rows)
}

func listAllHTMLWarnings(result *domain.ScanResult, inventoryWarnings []string) []string {
	return limitListAllHTMLWarnings(appendListAllInventoryWarnings(scanner.ReportWarnings(result), inventoryWarnings))
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

func limitListAllHTMLWarnings(warnings []string) []string {
	if len(warnings) <= maxListAllHTMLReportWarnings {
		return warnings
	}
	out := append([]string(nil), warnings[:maxListAllHTMLReportWarnings]...)
	out = append(out, fmt.Sprintf("%d additional warnings were omitted from the top of this report.", len(warnings)-maxListAllHTMLReportWarnings))
	return out
}

const listAllHTML = cliHTMLReportHeadPrefix + cliHTMLReportCSPMeta +
	listAllHTMLHead + listAllHTMLStyle + listAllHTMLBody +
	generatedHTMLReportLocaleScript + listAllHTMLTail

const listAllHTMLHead = `
<title>{{.DocumentTitle}}</title>
<style>
`

const listAllHTMLStyle = `:root{` + reporthtml.DarkBaseThemeCSS +
	`--crit:#ff7b72;--high:#ffa657;--sev-low:#56d4c4;` +
	`--success:#7ee787;--success-bg:#0f2d2a;--success-border:#238636;--warning:#ffa657;` +
	`--warning-bg:#322717;--status-bg:#321820;--button-bg:#21262d;--button-fg:#c9d1d9;` +
	`--link:#58a6ff;` + cliHTMLReportScaleCSS + `}` + cliHTMLReportBaseCSS + `
h2{font-size:var(--report-type-lg);margin:var(--report-space-6) 0 var(--report-space-2);color:var(--heading);border-bottom:1px solid var(--border);padding-bottom:var(--report-space-1);}
.bad{color:var(--crit);border-color:var(--crit);}
.hint{margin:var(--report-space-2) 0 0;color:var(--dim);font-size:var(--report-type-xs);max-width:70rem;}
.table-scroll{overflow-x:auto;border:1px solid var(--border);border-radius:var(--report-radius-md);background:var(--panel);}
.table-scroll:focus{outline:var(--report-focus-ring) solid var(--link);outline-offset:var(--report-focus-offset);}
table{width:100%;border-collapse:collapse;background:var(--panel);}
.package-table{min-width:960px;table-layout:auto;}
.attention-table{min-width:980px;}
.inventory-table{min-width:940px;}
.findings-table{table-layout:auto;min-width:980px;}
th,td{padding:var(--report-space-2) var(--report-space-3);border-bottom:1px solid var(--border);text-align:start;vertical-align:top;}
th{color:var(--heading);font-size:var(--report-type-xs);text-transform:uppercase;}
td{word-break:break-word;overflow-wrap:anywhere;}
.name{min-width:260px;word-break:break-word;overflow-wrap:anywhere;}
.installed,.version{width:250px;min-width:220px;overflow-wrap:anywhere;word-break:break-word;}
.short{white-space:nowrap;min-width:90px;}
.nowrap{white-space:nowrap;}
.source{white-space:nowrap;min-width:105px;}
.package-status{white-space:nowrap;min-width:110px;}
.meta-cell{min-width:170px;max-width:230px;}
.package-meta-list{display:flex;flex-wrap:wrap;gap:var(--report-space-1-5) var(--report-space-3);margin:0;padding:0;}
.package-meta-list div{display:flex;gap:var(--report-space-1);min-width:0;}
.package-meta-list dt{font-weight:700;color:var(--dim);}
.package-meta-list dd{margin:0;overflow-wrap:anywhere;word-break:break-word;}
.status-update{color:var(--high);font-weight:700;}
.vuln-col{text-align:center;white-space:nowrap;min-width:64px;}
.vuln-yes{color:var(--crit);font-weight:700;}
` + `.sev{display:inline-block;border:1px solid var(--border);border-radius:var(--report-radius-sm);` +
	`padding:var(--report-space-0-5) var(--report-space-1-5);font-size:var(--report-type-xs);font-weight:700;line-height:1.3;}` + `
.sev-critical{color:var(--crit);border-color:var(--crit);}
.sev-high{color:var(--high);border-color:var(--high);}
.sev-medium{color:var(--warning);border-color:var(--warning);}
.sev-low{color:var(--sev-low);border-color:var(--sev-low);}
.sev-unknown{color:var(--dim);}
.findings-table .finding-package{min-width:220px;white-space:nowrap;overflow-wrap:normal;word-break:normal;}
.findings-table .finding-advisory{min-width:190px;white-space:nowrap;overflow-wrap:normal;word-break:normal;}
.finding-advisory a{display:inline-flex;align-items:center;min-height:var(--report-touch-target);padding:var(--report-space-1-5) var(--report-space-2);margin:calc(-1 * var(--report-space-1-5)) calc(-1 * var(--report-space-2));white-space:nowrap;overflow-wrap:normal;word-break:normal;}
.finding-title{min-width:320px;white-space:normal;overflow-wrap:break-word;word-break:normal;}
.finding-action{min-width:150px;white-space:nowrap;overflow-wrap:normal;word-break:normal;}
.finding-section{margin:0 0 var(--report-space-5);}
.finding-section h3{font-size:var(--report-type-base);margin:var(--report-space-3) 0 var(--report-space-2);color:var(--heading);}
.finding-section h3.s-mal{color:var(--crit);}
.finding-section h3.s-sce{color:var(--warning);}
.finding-section h3.s-vuln{color:var(--heading);}
.finding-section h3.s-life{color:var(--link);}
.finding-section h3.s-other{color:var(--dim);}
.finding-section .count{color:var(--dim);font-weight:400;}
.inventory-details{margin:var(--report-space-6) 0 0;}
.inventory-details summary{cursor:pointer;color:var(--heading);border-bottom:1px solid var(--border);padding-bottom:var(--report-space-1);font-size:var(--report-type-lg);font-weight:700;}
.inventory-details summary:focus{outline:var(--report-focus-ring) solid var(--link);outline-offset:var(--report-focus-offset);}
.inventory-details .count{color:var(--dim);font-weight:400;}
.inventory-details .table-scroll{margin-top:var(--report-space-3);}
a{color:var(--link);text-decoration:none;overflow-wrap:anywhere;word-break:break-word;}
a:hover{text-decoration:underline;}
` + `.external-link::after{content:"";display:inline-block;inline-size:0.65em;` +
	`block-size:0.65em;margin-inline-start:0.25em;` +
	`border-block-start:1.5px solid currentColor;border-inline-end:1.5px solid currentColor;` +
	`transform:translateY(-0.08em);}` + `
.copy-value{white-space:nowrap;}
.copy-cell{display:inline-flex;align-items:center;white-space:nowrap;max-width:100%;}
` + `.copy-btn{order:-1;margin-inline-end:var(--report-space-2);display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--border);border-radius:var(--report-radius-sm);` +
	`background:var(--button-bg);color:var(--button-fg);` +
	`width:1.4rem;height:1.4rem;padding:0;cursor:pointer;}` +
	`.copy-icon{width:11px;height:11px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;}` +
	`.copy-btn.copied{border-color:var(--success);color:var(--success);}` + `
.copy-btn:hover{border-color:var(--link);color:var(--link);}
.copy-btn:focus-visible{outline:var(--report-focus-ring) solid var(--link);outline-offset:var(--report-space-0-5);border-color:var(--link);}
.copy-btn:active{background:var(--link);border-color:var(--link);color:var(--bg);}
.copy-btn.copy-failed{border-color:var(--crit);color:var(--crit);}
` + `.copy-fallback{margin-inline-start:var(--report-space-2);max-width:min(44rem,100%);` +
	`border:1px solid var(--border);border-radius:var(--report-radius-sm);background:var(--panel);` +
	`color:var(--fg);font:inherit;font-size:var(--report-type-xs);padding:var(--report-space-1) var(--report-space-2);}` + `
.copy-fallback:focus{outline:var(--report-space-0-5) solid var(--link);outline-offset:var(--report-space-0-5);}
.print-copy-value{display:none;}
` + `.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;` +
	`clip:rect(0,0,0,0);white-space:nowrap;border:0;}` + `
` + `.status{margin:var(--report-space-5) 0;padding:var(--report-space-3) var(--report-space-4);background:var(--status-bg);` +
	`border:1px solid var(--crit);border-radius:var(--report-radius-md);color:var(--crit);font-size:var(--report-type-md);}` + `
` + `.warning{margin:var(--report-space-5) 0;padding:var(--report-space-3) var(--report-space-4);background:var(--warning-bg);` +
	`border:1px solid var(--warning);border-radius:var(--report-radius-md);color:var(--warning);` +
	`font-size:var(--report-type-md);}` + `
` + `.empty{margin:var(--report-space-4) 0;padding:var(--report-space-3) var(--report-space-4);background:var(--success-bg);` +
	`border:1px solid var(--success-border);border-radius:var(--report-radius-md);color:var(--success);` +
	`font-size:var(--report-type-md);}` + `
` + `.warning-empty{background:var(--warning-bg);border-color:var(--warning);color:var(--warning);}` + `
` + `.source-list{margin:0;padding:0;list-style:none;border:1px solid var(--border);` +
	`border-radius:var(--report-radius-md);background:var(--panel);}` + `
.source-list li{display:flex;gap:var(--report-space-3);align-items:flex-start;padding:var(--report-space-2) var(--report-space-3);border-bottom:1px solid var(--border);}
.source-list li:last-child{border-bottom:0;}
.source-kind{flex:0 0 90px;color:var(--dim);text-transform:uppercase;font-size:var(--report-type-xs);}
.source-path{min-width:0;overflow-wrap:anywhere;word-break:break-word;}
` + `@supports not (font-size:var(--report-type-base)){body{font-size:0.875rem;}` +
	`h1{font-size:1.375rem;}h2,.inventory-details summary{font-size:1rem;}` +
	`.meta,.badge{font-size:0.8125rem;}` +
	`th,.source-kind,.footer,.copy-btn,.copy-fallback{font-size:0.75rem;}` +
	`.status,.warning,.empty{font-size:0.9375rem;}}` + `
` + `@media (prefers-color-scheme: light){:root{` + reporthtml.LightBaseThemeCSS +
	`--crit:#cf222e;--high:#9a6700;--sev-low:#0a7f74;--success:#116329;--success-bg:#dafbe1;` +
	`--success-border:#2da44e;--warning:#9a6700;--warning-bg:#fff8c5;--status-bg:#ffebe9;` +
	`--button-bg:#f6f8fa;--button-fg:#24292f;--link:#0969da;}}` + `
` + `@media (prefers-contrast: more){:root{--border:CanvasText;--dim:CanvasText;` +
	`}.badge,.table-scroll,.status,.warning,.empty,.source-list{border-width:2px;` +
	`}a{text-decoration:underline;}}` + `
` + `@media (forced-colors: active){:root{` + reporthtml.ForcedColorsBaseThemeCSS +
	`--crit:Highlight;--high:Highlight;--sev-low:Highlight;--success:CanvasText;` +
	`--success-bg:Canvas;--success-border:CanvasText;--warning:CanvasText;` +
	`--warning-bg:Canvas;--status-bg:Canvas;--button-bg:ButtonFace;--button-fg:ButtonText;` +
	`--link:LinkText;}*{forced-color-adjust:auto;` +
	`}.badge,.table-scroll,.status,.warning,.empty,.source-list,` +
	`.copy-btn{border-color:CanvasText;}a{color:LinkText;text-decoration:underline;` +
	`}.table-scroll:focus{outline-color:Highlight;}}` + `
` + `@media print{:root{` + reporthtml.PrintBaseThemeCSS +
	`--crit:#b42318;--high:#8a4600;` +
	`--sev-low:#006d75;--success:#116329;--success-bg:#ffffff;--success-border:#116329;` +
	`--warning:#8a4600;--warning-bg:#ffffff;--status-bg:#ffffff;--button-bg:#ffffff;` +
	`--button-fg:#111827;--link:#0645ad;}body{background:#fff;color:#111827;` +
	`}.wrap{max-width:none;padding:0;}.table-scroll{overflow:visible;` +
	`border-color:var(--border);}table{min-width:0;` +
	`}.package-table,.findings-table{min-width:0;` +
	`}.name,.installed,.version,.short,.source,.package-status,.vuln-col,.findings-table ` +
	`.finding-package,.findings-table .finding-advisory,.finding-action{min-width:0;` +
	`white-space:normal;}.finding-title{min-width:0;}.installed,.version{width:auto;` +
	`}.copy-value{white-space:normal;}.copy-cell{display:inline;white-space:normal;}.copy-btn{display:none;` +
	`}.print-copy-value{display:inline;white-space:normal;overflow-wrap:anywhere;` +
	`word-break:break-word;}.findings-table .finding-advisory a{white-space:normal;` +
	`overflow-wrap:anywhere;word-break:break-word;` +
	`}.status,.warning,.empty,.finding-section{break-inside:avoid;page-break-inside:avoid;` +
	`background:#fff;}a{color:var(--link);}a[href]::after{content:" (" attr(href) ")";` +
	`display:inline;inline-size:auto;block-size:auto;margin-inline-start:0;border:0;` +
	`transform:none;color:var(--dim);overflow-wrap:anywhere;word-break:break-word;}}`

const listAllHTMLBody = `
</style>
</head>
<body>
<main class="wrap">
<h1><bdi dir="auto">{{.Title}}</bdi></h1>
` + `<div class="meta">{{.Messages.ReportType}}{{if .Mode}} &middot;` +
	` <bdi dir="auto">{{.Mode}}</bdi> {{.Messages.ModeSuffix}}{{end}}{{if .PackageInfo.Target}} &middot;` +
	` <bdi dir="auto">{{.PackageInfo.Target}}</bdi>{{end}}{{if .PackageInfo.ScannedAt}}` +
	` &middot; {{if .PackageInfo.ScannedAtDateTime}}<time datetime="{{.PackageInfo.ScannedAtDateTime}}" ` +
	`data-report-time="scanned-at">{{.PackageInfo.ScannedAt}}</time>{{else}}{{.PackageInfo.ScannedAt}}{{end}}{{end}}</div>` + `
<div class="summary">
<span class="badge">{{count (len .PackageRows) .Messages.PackageSingular .Messages.PackagePlural}}</span>
<span class="badge warn">{{count .PackageInfo.WithUpdates .Messages.WithUpdateSingular .Messages.WithUpdatePlural}}</span>
<span class="badge bad">{{count .PackageInfo.Vulnerable .Messages.VulnerabilitySingular .Messages.VulnerabilityPlural}}</span>
<span class="badge">{{count .PackageInfo.Unknown .Messages.UnknownSingular .Messages.UnknownPlural}}</span>
{{range .ScopeSummary}}<span class="badge">{{.Scope}} {{.Count}}</span>{{end}}
</div>
{{if .PackageInfo.Unknown}}<div class="hint"><bdi dir="auto">{{.Messages.UnknownStatusHint}}</bdi></div>{{end}}
{{if .Status}}<div class="status">{{.Messages.StatusPrefix}} <bdi dir="auto">{{.Status}}</bdi></div>{{end}}
{{range .Warnings}}<div class="warning"><bdi dir="auto">{{.}}</bdi></div>{{end}}
<h2>{{.Messages.PackagesNeedingAttentionHeading}}</h2>
{{if .Attention}}
<div class="table-scroll" tabindex="0" role="region" aria-label="{{.Messages.PackagesNeedingAttentionTableLabel}}">
<table class="package-table attention-table">
` + `<thead><tr><th scope="col" class="name">{{.Messages.PackageColumn}}</th><th scope="col" class="installed">{{.Messages.InstalledColumn}}</th>` +
	`<th scope="col" class="version">{{.Messages.LatestColumn}}</th><th scope="col" class="package-status">{{.Messages.ActionColumn}}</th><th scope="col" class="meta-cell">` +
	`{{.Messages.TriageColumn}}</th><th scope="col" class="vuln-col">` +
	`{{.Messages.VulnerabilityColumn}}</th></tr></thead>` + `
<tbody>
` + `{{range .Attention}}{{with htmlPackageRow (index $.PackageRows .) $.FindingStatuses $.VulnerabilityFindingKeys}}<tr><td class="name"><bdi dir="auto">{{.Name}}` +
	`</bdi></td><td class="installed">{{if .InstalledCopy}}` +
	`<span class="copy-cell"><span class="copy-value"><bdi dir="auto">{{.Installed}}` +
	`</bdi></span><button type="button" class="copy-btn" data-copy="{{.InstalledCopy}}` +
	`" data-copy-label="{{.InstalledCopyLabel}}" data-copy-message="{{.InstalledCopyMessage}}` +
	`" aria-label="{{.InstalledCopyLabel}}` +
	`"><svg class="copy-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg></button></span><span class="print-copy-value"><bdi dir="auto">{{.InstalledCopy}}` +
	`</bdi></span>{{else}}<bdi dir="auto">{{.Installed}}</bdi>{{end}}` +
	`</td><td class="version">{{if .LatestCopy}}` +
	`<span class="copy-cell"><span class="copy-value"><bdi dir="auto">{{.Latest}}` +
	`</bdi></span><button type="button" class="copy-btn" data-copy="{{.LatestCopy}}` +
	`" data-copy-label="{{.LatestCopyLabel}}" data-copy-message="{{.LatestCopyMessage}}` +
	`" aria-label="{{.LatestCopyLabel}}"><svg class="copy-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg></button></span><span class="print-copy-value">` +
	`<bdi dir="auto">{{.LatestCopy}}</bdi></span>{{else}}<bdi dir="auto">{{.Latest}}` +
	`</bdi>{{end}}</td><td class="package-status{{if .StatusClass}} {{.StatusClass}}{{end}}` +
	`">{{.Status}}</td><td class="meta-cell"><dl class="package-meta-list"><div><dt>{{$.Messages.EcosystemLabel}}</dt><dd>{{.Ecosystem}}` +
	`</dd></div><div><dt>{{$.Messages.SourceLabel}}</dt><dd><bdi dir="auto">{{.Source}}` +
	`</bdi></dd></div><div><dt>{{$.Messages.ScopeLabel}}</dt><dd>{{.Scope}}</dd></div><div><dt>{{$.Messages.RelationLabel}}</dt><dd>{{.Relation}}` +
	`</dd></div></dl></td><td class="vuln-col{{if .VulnClass}}` +
	` {{.VulnClass}}{{end}}">{{.Vuln}}</td></tr>{{end}}{{end}}` + `
</tbody>
</table>
</div>
{{else if and (not .Status) (not .Warnings)}}
<div class="empty">{{.Messages.NoPackageStatusIssues}}</div>
{{else if .Warnings}}
<div class="empty warning-empty">{{.Messages.PackageAttentionWarnings}}</div>
{{end}}
<h2>{{.Messages.SecurityFindingsHeading}}</h2>
{{if .Findings}}
{{range .Findings}}
<div class="finding-section">
<h3 class="{{.Class}}">{{.Title}} <span class="count">({{len .Findings}})</span></h3>
<div class="table-scroll" tabindex="0" role="region" aria-label="{{.AriaLabel}}">
<table class="findings-table">
` + `<thead><tr><th scope="col" class="short">{{$.Messages.SeverityColumn}}</th><th scope="col" class="finding-package">{{$.Messages.PackageColumn}}</th>` +
	`<th scope="col" class="finding-advisory">{{$.Messages.AdvisoryColumn}}</th><th scope="col" class="finding-title">{{$.Messages.FindingColumn}}</th>` +
	`<th scope="col" class="finding-action">{{$.Messages.ActionColumn}}</th></tr></thead>` + `
<tbody>
` + `{{range .Findings}}<tr class="finding-summary-row"><td class="short">` +
	`<span class="sev {{.SeverityClass}}">{{.Severity}}` +
	`</span></td><td class="finding-package"><bdi dir="auto">{{.Package}}` +
	`</bdi></td><td class="finding-advisory">{{if .AdvisoryURL}}` +
	`<a class="external-link" href="{{.AdvisoryURL}}` +
	`" target="_blank" rel="noopener" aria-label="{{printf $.Messages.OpenInNewTabAriaLabel .Advisory}}"><bdi dir="auto">{{.Advisory}}` +
	`</bdi><span class="sr-only">{{$.Messages.OpenInNewTabScreenReader}}</span></a>{{else}}` +
	`<bdi dir="auto">{{.Advisory}}</bdi>{{end}}` +
	`</td><td class="finding-title"><bdi dir="auto">{{.Title}}` +
	`</bdi></td><td class="finding-action"><bdi dir="auto">{{.Action}}` +
	`</bdi></td></tr>{{end}}` + `
</tbody>
</table>
</div>
</div>
{{end}}
{{else if and (not .Status) (not .Warnings)}}
<div class="empty">{{.Messages.NoSecurityFindingsPrefix}} {{count (len .PackageRows) .Messages.PackageSingular .Messages.PackagePlural}}{{.Messages.NoSecurityFindingsSuffix}}</div>
{{else if .Warnings}}
<div class="empty warning-empty">{{.Messages.SecurityFindingsWarnings}}</div>
{{end}}
{{if .PackageRows}}
<details class="inventory-details">
<summary>{{.Messages.AllPackagesHeading}} <span class="count">({{count (len .PackageRows) .Messages.PackageSingular .Messages.PackagePlural}})</span></summary>
<div class="table-scroll" tabindex="0" role="region" aria-label="{{.Messages.AllPackagesTableLabel}}">
<table class="package-table inventory-table">
` + `<thead><tr><th scope="col" class="name">{{.Messages.PackageColumn}}</th><th scope="col" class="installed">{{.Messages.InstalledColumn}}</th>` +
	`<th scope="col" class="version">{{.Messages.LatestColumn}}</th><th scope="col" class="package-status">{{.Messages.StatusColumn}}</th><th scope="col" class="meta-cell">` +
	`{{.Messages.InventoryDetailsColumn}}</th><th scope="col" class="vuln-col">` +
	`{{.Messages.VulnerabilityColumn}}</th></tr></thead>` + `
<tbody>
` + `{{range .PackageRows}}{{with htmlPackageRow . $.FindingStatuses $.VulnerabilityFindingKeys}}<tr><td class="name"><bdi dir="auto">{{.Name}}` +
	`</bdi></td><td class="installed">{{if .InstalledCopy}}` +
	`<span class="copy-cell"><span class="copy-value"><bdi dir="auto">{{.Installed}}` +
	`</bdi></span><button type="button" class="copy-btn" data-copy="{{.InstalledCopy}}` +
	`" data-copy-label="{{.InstalledCopyLabel}}" data-copy-message="{{.InstalledCopyMessage}}` +
	`" aria-label="{{.InstalledCopyLabel}}` +
	`"><svg class="copy-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg></button></span><span class="print-copy-value"><bdi dir="auto">{{.InstalledCopy}}` +
	`</bdi></span>{{else}}<bdi dir="auto">{{.Installed}}</bdi>{{end}}` +
	`</td><td class="version">{{if .LatestCopy}}` +
	`<span class="copy-cell"><span class="copy-value"><bdi dir="auto">{{.Latest}}` +
	`</bdi></span><button type="button" class="copy-btn" data-copy="{{.LatestCopy}}` +
	`" data-copy-label="{{.LatestCopyLabel}}" data-copy-message="{{.LatestCopyMessage}}` +
	`" aria-label="{{.LatestCopyLabel}}"><svg class="copy-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg></button></span><span class="print-copy-value">` +
	`<bdi dir="auto">{{.LatestCopy}}</bdi></span>{{else}}<bdi dir="auto">{{.Latest}}` +
	`</bdi>{{end}}</td><td class="package-status{{if .StatusClass}} {{.StatusClass}}{{end}}` +
	`">{{.Status}}</td><td class="meta-cell"><dl class="package-meta-list"><div><dt>{{$.Messages.EcosystemLabel}}</dt><dd>{{.Ecosystem}}` +
	`</dd></div><div><dt>{{$.Messages.SourceLabel}}</dt><dd><bdi dir="auto">{{.Source}}` +
	`</bdi></dd></div><div><dt>{{$.Messages.ScopeLabel}}</dt><dd>{{.Scope}}</dd></div><div><dt>{{$.Messages.RelationLabel}}</dt><dd>{{.Relation}}` +
	`</dd></div></dl></td><td class="vuln-col{{if .VulnClass}}` +
	` {{.VulnClass}}{{end}}">{{.Vuln}}</td></tr>{{end}}{{end}}` + `
</tbody>
</table>
</div>
</details>
{{else}}
<h2>{{.Messages.AllPackagesHeading}}</h2>
{{if not .Warnings}}
<div class="empty">{{.Messages.NoPackagesFound}}</div>
{{else}}
<div class="empty warning-empty">{{.Messages.NoPackageInventoryRows}}</div>
{{end}}
{{end}}
{{if .Sources}}
<h2>{{.Messages.CheckedInventorySourcesHeading}}</h2>
<ul class="source-list">
` + `{{range .Sources}}<li><span class="source-kind">{{.Kind}}` +
	`</span><span class="source-path"><bdi dir="auto">{{.Path}}</bdi></span></li>{{end}}` + `
</ul>
{{end}}
<div id="copy-status" class="sr-only" role="status" aria-live="polite"></div>
</main>
<script>
(function(){
  var status=document.getElementById('copy-status');
  var copyConfirmationVisibleMs=` + listAllHTMLCopyConfirmationVisibleMs + `;
  var copyButtonLabel='{{.Messages.CopyButton}}';
  var copyFullValueLabel='{{.Messages.CopyFullValue}}';
  var copiedFullValueMessage='{{.Messages.CopiedFullValue}}';
  var copyFailedLabel='{{.Messages.CopyFailed}}';
  var copyFailedManualMessage='{{.Messages.CopyFailedManual}}';
  var fullValueManualCopyLabel='{{.Messages.FullValueManualCopyLabel}}';
  function announce(message){
    if(status){status.textContent=message;}
  }
  function resetButton(button){
    var label=button.getAttribute('data-copy-label') || copyFullValueLabel;
    button.classList.remove('copied');
    button.classList.remove('copy-failed');
    button.setAttribute('aria-label',label);
  }
  function showResult(button, ok, value){
    var label=button.getAttribute('data-copy-label') || copyFullValueLabel;
    var message=button.getAttribute('data-copy-message') || copiedFullValueMessage;
    if(ok){
      button.classList.remove('copy-failed');
      button.classList.add('copied');
      button.setAttribute('aria-label',message);
      announce(message);
    }else{
      showManualCopy(value,button);
      button.classList.remove('copied');
      button.classList.add('copy-failed');
      button.setAttribute('aria-label',copyFailedManualMessage+' '+label);
      announce(copyFailedManualMessage);
    }
    window.setTimeout(function(){resetButton(button);},copyConfirmationVisibleMs);
  }
  function showManualCopy(value,button){
    if(!button || !button.parentNode){return;}
    var input=button.nextElementSibling;
    if(!(input && input.classList && input.classList.contains('copy-fallback'))){
      input=document.createElement('input');
      input.type='text';
      input.readOnly=true;
      input.className='copy-fallback';
      input.setAttribute('aria-label',fullValueManualCopyLabel);
      button.parentNode.insertBefore(input,button.nextSibling);
    }
    input.value=value || '';
    if(input.focus){
      try{input.focus({preventScroll:true});}catch(_){input.focus();}
    }
    if(input.select){input.select();}
  }
  document.addEventListener('click',function(event){
    var button=event.target.closest ? event.target.closest('[data-copy]') : null;
    if(!button){return;}
    var value=button.getAttribute('data-copy') || '';
    if(!value){return;}
    if(navigator.clipboard && navigator.clipboard.writeText){
` + `      navigator.clipboard.writeText(value).then(function(){showResult(button,true,` +
	`value);},function(){showResult(button,false,value);});` + `
      return;
    }
    showResult(button,false,value);
  });
})();
</script>
`

const listAllHTMLTail = `
</body>
</html>`
