package scanner

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/findinglinks"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/8linkz-sec/packmon/internal/reporthtml"
)

const (
	defaultHTMLReportLang = "en"
	maxHTMLReportWarnings = 5
)

// HTMLWriter renders a scan result as a single self-contained HTML report.
type HTMLWriter struct {
	toolVersion string
}

// NewHTMLWriter creates an HTMLWriter. An empty version becomes "dev".
func NewHTMLWriter(toolVersion string) *HTMLWriter {
	if toolVersion == "" {
		toolVersion = "dev"
	}
	return &HTMLWriter{toolVersion: toolVersion}
}

var htmlReportTemplate = sync.OnceValue(func() *template.Template {
	return template.Must(template.New("report").Funcs(template.FuncMap{
		"count": plural.Count,
	}).Parse(htmlTemplate))
})

// Write renders the scan result as an HTML document to w. title is the report
// heading (repo name); failOn is the configured blocking threshold.
func (hw *HTMLWriter) Write(w io.Writer, title string, failOn domain.Severity, result *domain.ScanResult) error {
	rep := buildReport(title, hw.toolVersion, failOn, result)
	if err := htmlReportTemplate().Execute(w, rep); err != nil {
		return fmt.Errorf("html: render: %w", err)
	}
	return nil
}

// WriteFile renders the HTML report to the given file path.
func (hw *HTMLWriter) WriteFile(path, title string, failOn domain.Severity, result *domain.ScanResult) error {
	f, err := ioutils.OpenPrivateFile(path)
	if err != nil {
		return fmt.Errorf("html: create file %s: %w", path, err)
	}

	if err := hw.Write(f, title, failOn, result); err != nil {
		ioutils.CloseSilently(f)
		return err
	}
	return f.Close()
}

type htmlReport struct {
	Title             string
	Lang              string
	Messages          htmlReportMessages
	Mode              string
	Packages          int
	ScannedAt         string
	ScannedAtDateTime string
	Duration          string
	DurationMS        int64
	Severity          []htmlBadge
	TypeCounts        []htmlBadge
	FindingsTotal     int
	Blocking          int
	Clean             bool
	Status            string
	Warnings          []string
	Sections          []htmlSection
	FooterParts       []string
}

type htmlReportMessages struct {
	ReportType          string
	DocumentTitleSuffix string
	ModeSuffix          string
	PackageSingular     string
	PackagePlural       string
	FindingSingular     string
	FindingPlural       string
	BlockingSingular    string
	BlockingPlural      string
	StatusPrefix        string
	NoFindingsPrefix    string
	NoFindingsSuffix    string
	FindingSections     string
	JumpTo              string
	RiskLabel           string
	CustomRiskPrefix    string
	FixedVersionLabel   string
	SourceLabel         string
}

type htmlBadge struct {
	Label string
	Class string
	Count int
}

type htmlSection struct {
	ID        string
	HeadingID string
	Title     string
	Class     string
	Findings  []htmlFinding
}

type htmlFinding struct {
	Severity     string
	SevSlug      string
	Package      string
	Ecosystem    string
	Advisory     string
	Title        string
	FixedVersion string
	RiskType     string
	RiskLabel    string
	RiskNote     string
	Source       string
	Links        []htmlLink
	Plain        []string
}

type htmlLink struct {
	Label string
	URL   string
}

// sectionDef declares the fixed order and styling of report sections.
type sectionDef struct {
	key   string
	title string
	class string
	id    string
}

var sectionDefs = []sectionDef{
	{key: string(domain.FindingTypeMalicious), title: "Malicious", class: "s-mal", id: "section-malicious"},
	{key: string(domain.FindingTypeSupplyChainRisk), title: "Supply-Chain / EOL", class: "s-sce", id: "section-supply-chain-eol"},
	{key: string(domain.FindingTypeVulnerability), title: "Vulnerabilities", class: "s-vuln", id: "section-vulnerabilities"},
	{key: string(domain.FindingTypeLifecycle), title: "Lifecycle Findings", class: "s-life", id: "section-lifecycle-findings"},
	{key: "reputation_info", title: "Reputation info", class: "s-life", id: "section-reputation-info"},
}

func buildReport(title, toolVersion string, failOn domain.Severity, result *domain.ScanResult) htmlReport {
	rep := buildReportSummary(title, failOn, result)
	rep.Sections = buildReportSections(result.Findings)
	rep.FooterParts = buildReportMetadata(toolVersion, result)
	return rep
}

func buildReportSummary(title string, failOn domain.Severity, result *domain.ScanResult) htmlReport {
	if strings.TrimSpace(title) == "" {
		title = "Packmon Security Report"
	}

	rep := htmlReport{
		Title:         title,
		Lang:          defaultHTMLReportLang,
		Messages:      defaultHTMLReportMessages(),
		Mode:          string(result.Mode),
		Packages:      result.PackagesScanned,
		Duration:      formatDurationMs(result.DurationMs),
		DurationMS:    result.DurationMs,
		FindingsTotal: len(result.Findings),
		Status:        scanOperationalStatusMessage(result),
		Warnings:      htmlReportWarnings(result),
	}
	if !result.ScannedAt.IsZero() {
		rep.ScannedAt = formatReportTimestamp(result.ScannedAt)
		rep.ScannedAtDateTime = formatReportDateTime(result.ScannedAt)
	}
	rep.Severity = buildReportSeverityBadges(result.Findings)
	rep.TypeCounts = buildReportTypeBadges(result.Findings)
	rep.Blocking = countReportBlockingFindings(result.Findings, failOn)
	rep.Clean = result.PackagesScanned > 0 && len(result.Findings) == 0 && rep.Status == "" && len(rep.Warnings) == 0
	return rep
}

func defaultHTMLReportMessages() htmlReportMessages {
	return htmlReportMessages{
		ReportType:          "Packmon Security Report",
		DocumentTitleSuffix: "Packmon Report",
		ModeSuffix:          "mode",
		PackageSingular:     "package",
		PackagePlural:       "packages",
		FindingSingular:     "finding",
		FindingPlural:       "findings",
		BlockingSingular:    "blocking",
		BlockingPlural:      "blocking",
		StatusPrefix:        "Scan did not complete:",
		NoFindingsPrefix:    "No findings in",
		NoFindingsSuffix:    ".",
		FindingSections:     "Finding sections",
		JumpTo:              "Jump to",
		RiskLabel:           "Risk",
		CustomRiskPrefix:    "Custom risk",
		FixedVersionLabel:   "Fixed Version",
		SourceLabel:         "Source",
	}
}

func buildReportSeverityBadges(findings []domain.Finding) []htmlBadge {
	sevOrder := []struct {
		sev   domain.Severity
		label string
		class string
	}{
		{domain.SeverityCritical, "Critical", "b-crit"},
		{domain.SeverityHigh, "High", "b-high"},
		{domain.SeverityMedium, "Medium", "b-med"},
		{domain.SeverityLow, "Low", "b-low"},
	}
	var badges []htmlBadge
	for _, s := range sevOrder {
		n := 0
		for _, f := range findings {
			if domain.NormalizeFindingSeverity(f) == s.sev {
				n++
			}
		}
		if n > 0 {
			badges = append(badges, htmlBadge{Label: s.label, Class: s.class, Count: n})
		}
	}

	// Any finding whose severity is not one of the four ranked levels (e.g.
	// UNKNOWN or empty) is counted under a single "Unknown" badge, so the
	// severity badges always sum to FindingsTotal.
	unknown := 0
	for _, f := range findings {
		if sevSlug(domain.NormalizeFindingSeverity(f)) == "none" {
			unknown++
		}
	}
	if unknown > 0 {
		badges = append(badges, htmlBadge{Label: "Unknown", Class: "b-none", Count: unknown})
	}
	return badges
}

func buildReportTypeBadges(findings []domain.Finding) []htmlBadge {
	var badges []htmlBadge
	for _, def := range sectionDefs {
		n := 0
		for _, f := range findings {
			if htmlFindingSectionKey(f) == def.key {
				n++
			}
		}
		if n > 0 {
			badges = append(badges, htmlBadge{Label: htmlTypeBadgeLabel(def.key, n), Class: "b-dim", Count: n})
		}
	}
	return badges
}

func countReportBlockingFindings(findings []domain.Finding, failOn domain.Severity) int {
	n := 0
	for _, f := range findings {
		if domain.FindingBlocks(f, failOn) {
			n++
		}
	}
	return n
}

func buildReportSections(findings []domain.Finding) []htmlSection {
	var sections []htmlSection
	for _, def := range sectionDefs {
		fs := buildReportSectionFindings(findings, def)
		if len(fs) == 0 {
			continue
		}
		sections = append(sections, htmlSection{
			ID: def.id, HeadingID: def.id + "-heading", Title: def.title, Class: def.class, Findings: fs,
		})
	}
	return sections
}

func buildReportSectionFindings(findings []domain.Finding, def sectionDef) []htmlFinding {
	var fs []htmlFinding
	for _, f := range findings {
		if htmlFindingSectionKey(f) != def.key {
			continue
		}
		fs = append(fs, buildReportFinding(f))
	}
	sort.SliceStable(fs, func(i, j int) bool {
		return domain.Severity(fs[i].Severity).Rank() > domain.Severity(fs[j].Severity).Rank()
	})
	return fs
}

func buildReportFinding(f domain.Finding) htmlFinding {
	links, plain := makeLinks(f)
	severity := domain.NormalizeFindingSeverity(f)
	riskType := strings.TrimSpace(f.RiskType)
	riskLabel, riskNote := htmlRiskTypeDefinition(riskType)
	return htmlFinding{
		Severity:     string(severity),
		SevSlug:      sevSlug(severity),
		Package:      fmt.Sprintf("%s@%s", f.Name, f.Version),
		Ecosystem:    string(f.Ecosystem),
		Advisory:     advisoryLabel(f),
		Title:        f.Title,
		FixedVersion: f.FixedVersion,
		RiskType:     riskType,
		RiskLabel:    riskLabel,
		RiskNote:     riskNote,
		Source:       f.Source,
		Links:        links,
		Plain:        plain,
	}
}

func htmlRiskTypeDefinition(riskType string) (label, note string) {
	switch strings.ToLower(strings.TrimSpace(riskType)) {
	case "malware":
		return "Malware", "Confirmed malicious package or version."
	case "removed_package":
		return "Removed package", "Package was removed from its registry and should be reviewed before use."
	case domain.RiskTypeMalwareHistory:
		return "Malware history", "Historical malware incident or reputation context; review before relying on it."
	case "eol":
		return "End of life", "Release line has reached end of life."
	case "eol_soon":
		return "End of life soon", "Release line is approaching end of life."
	case "security_support_only":
		return "Security support only", "Release line receives security fixes only; general support has ended."
	case "typosquatting":
		return "Typosquatting", "Package name appears intended to impersonate a known package."
	case "supply_chain":
		return "Supply-chain risk", "General package trust or supply-chain compromise signal."
	default:
		return "", ""
	}
}

func buildReportMetadata(toolVersion string, result *domain.ScanResult) []string {
	return footerParts(toolVersion, result)
}

func htmlFindingSectionKey(f domain.Finding) string {
	if domain.FindingIsInformational(f) {
		return "reputation_info"
	}
	return string(f.Type)
}

func operationalStatusMessage(status string) string {
	status = strings.TrimSpace(status)
	switch status {
	case "", string(domain.ScanFeedStatusHealthy), string(domain.ScanFeedStatusDegraded):
		return ""
	default:
		return status
	}
}

func htmlReportWarnings(result *domain.ScanResult) []string {
	warnings := ReportWarnings(result)
	if message := zeroPackageScanDiagnostic(result); message != "" {
		warnings = append(warnings, message)
	}
	return limitHTMLReportWarnings(warnings)
}

func limitHTMLReportWarnings(warnings []string) []string {
	if len(warnings) <= maxHTMLReportWarnings {
		return warnings
	}
	out := append([]string(nil), warnings[:maxHTMLReportWarnings]...)
	out = append(out, fmt.Sprintf("%d additional warnings were omitted from the top of this report.", len(warnings)-maxHTMLReportWarnings))
	return out
}

func makeLinks(f domain.Finding) (links []htmlLink, plain []string) {
	sharedLinks, plain := findinglinks.FindingLinks(f)
	for _, link := range sharedLinks {
		links = append(links, htmlLink{Label: link.Label, URL: link.URL})
	}
	return links, plain
}

func advisoryLabel(f domain.Finding) string {
	return findinglinks.AdvisoryLabel(f)
}

func sevSlug(s domain.Severity) string {
	switch s {
	case domain.SeverityCritical:
		return "crit"
	case domain.SeverityHigh:
		return "high"
	case domain.SeverityMedium:
		return "med"
	case domain.SeverityLow:
		return "low"
	default:
		return "none"
	}
}

func formatDurationMs(ms int64) string {
	if ms <= 0 {
		return ""
	}
	if ms >= 1000 {
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%dms", ms)
}

func formatReportTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func formatReportDateTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func footerParts(toolVersion string, result *domain.ScanResult) []string {
	var parts []string
	if d := formatDurationMs(result.DurationMs); d != "" {
		parts = append(parts, "Scan "+d)
	}
	if result.Mode == domain.ScanModeLocal && result.DBAgeDays != nil {
		note := fmt.Sprintf("DB synced %s ago", plural.Count(*result.DBAgeDays, "day", "days"))
		if result.DBStale {
			note += " (stale)"
		}
		parts = append(parts, note)
	}
	switch result.FeedStatus {
	case "":
	case string(domain.ScanFeedStatusHealthy):
		parts = append(parts, "feeds: healthy")
	case string(domain.ScanFeedStatusDegraded):
		parts = append(parts, "feeds: degraded")
	default:
		parts = append(parts, result.FeedStatus)
	}
	parts = append(parts, "packmon "+toolVersion)
	if result.ScanID != "" {
		parts = append(parts, "scan_id "+result.ScanID)
	}
	if result.ManualAdvisoriesCount > 0 {
		parts = append(parts, plural.Count(result.ManualAdvisoriesCount, "manual advisory", "manual advisories"))
	}
	return parts
}

func htmlTypeBadgeLabel(key string, count int) string {
	switch key {
	case string(domain.FindingTypeMalicious):
		return plural.Word(count, "Malicious package", "Malicious packages")
	case string(domain.FindingTypeSupplyChainRisk):
		return plural.Word(count, "Supply-chain / EOL finding", "Supply-chain / EOL findings")
	case string(domain.FindingTypeVulnerability):
		return plural.Word(count, "Vulnerability", "Vulnerabilities")
	case string(domain.FindingTypeLifecycle):
		return plural.Word(count, "Lifecycle finding", "Lifecycle findings")
	case "reputation_info":
		return plural.Word(count, "Reputation info", "Reputation info")
	default:
		return plural.Word(count, "Finding", "Findings")
	}
}

const htmlReportLocaleScript = `<script>
(function(){
  function reportLocale(){
    if(navigator.languages && navigator.languages.length){return navigator.languages;}
    if(navigator.language){return navigator.language;}
    var lang=document.documentElement.getAttribute('lang');
    return lang || undefined;
  }
  function rememberFallback(node){
    if(node && !node.hasAttribute('data-fallback-text')){
      node.setAttribute('data-fallback-text',node.textContent || '');
    }
  }
  function formatTimes(){
    if(typeof Intl === 'undefined' || !Intl.DateTimeFormat){return;}
    var formatter;
    try{
      formatter=new Intl.DateTimeFormat(reportLocale(),{dateStyle:'medium',timeStyle:'short',timeZoneName:'short'});
    }catch(_){return;}
    document.querySelectorAll('time[data-report-time][datetime]').forEach(function(node){
      var value=node.getAttribute('datetime');
      if(!value){return;}
      var date=new Date(value);
      if(isNaN(date.getTime())){return;}
      rememberFallback(node);
      node.textContent=formatter.format(date);
    });
  }
  function formatDurations(){
    if(typeof Intl === 'undefined' || !Intl.NumberFormat){return;}
    document.querySelectorAll('[data-report-duration][data-duration-ms]').forEach(function(node){
      var ms=Number(node.getAttribute('data-duration-ms'));
      if(!isFinite(ms) || ms <= 0){return;}
      var seconds=ms/1000;
      var unit=ms < 1000 ? 'ms' : 's';
      var value=ms < 1000 ? ms : seconds;
      var digits=ms < 1000 || seconds >= 10 ? 0 : 1;
      var formatter;
      try{
        formatter=new Intl.NumberFormat(reportLocale(),{maximumFractionDigits:digits});
      }catch(_){return;}
      rememberFallback(node);
      node.textContent=formatter.format(value)+' '+unit;
    });
  }
  formatTimes();
  formatDurations();
})();
</script>`

const htmlTemplate = htmlTemplateHead + htmlReportCSS + htmlTemplateBody + htmlReportLocaleScript + htmlTemplateEnd

const htmlTemplateHead = `<!DOCTYPE html>
<html lang="{{.Lang}}" dir="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; ` +
	`script-src 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; ` +
	`object-src 'none'; base-uri 'none'; form-action 'none'">
<title>{{.Title}} - {{.Messages.DocumentTitleSuffix}}</title>
<style>
`

const htmlReportCSS = `:root{` + reporthtml.DarkBaseThemeCSS +
	`--crit:#ff7b72;--high:#ffa657;--med:#e3b341;` +
	`--sev-low:#56d4c4;--success:#7ee787;--success-bg:#0f2d2a;--success-border:#238636;` +
	`--warning-bg:#322717;--status-bg:#321820;--sev-fg:#0d1117;--sev-none-bg:#484f58;` +
	`--sev-none-fg:#ffffff;--risk:#d2a8ff;--fix:#7ee787;--link:#58a6ff;--purple:#d2a8ff;` +
	`--space-1:4px;--space-2:8px;--space-3:12px;--space-4:16px;--space-6:24px;` +
	`--space-8:32px;--space-12:48px;--radius-sm:4px;--radius-md:6px;` +
	`--border-thin:1px;--border-focus:2px;--border-accent:4px;--font-xs:0.75rem;` +
	`--font-sm:0.8125rem;--font-base:0.875rem;--font-md:0.9375rem;` +
	`--font-lg:1rem;--font-xl:1.375rem;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,` +
	`SFMono-Regular,Menlo,Consolas,monospace;font-size:var(--font-base);line-height:1.6;}
.wrap{max-width:920px;margin:0 auto;padding:var(--space-8) var(--space-6) var(--space-12);}
h1{font-size:var(--font-xl);font-weight:800;color:var(--heading);margin:0;overflow-wrap:anywhere;word-break:break-word;}
.meta{color:var(--dim);font-size:var(--font-sm);margin-top:var(--space-1);}
.badges{display:flex;flex-wrap:wrap;gap:var(--space-2);margin:var(--space-4) 0 var(--space-6);}
.badge{border-radius:var(--radius-md);padding:var(--space-1) var(--space-3);font-size:var(--font-sm);border:var(--border-thin) solid var(--border);}
.b-crit{color:var(--crit);border-color:var(--crit);}
.b-high{color:var(--high);border-color:var(--high);}
.b-med{color:var(--med);border-color:var(--med);}
.b-low{color:var(--sev-low);border-color:var(--sev-low);}
.b-none{color:var(--dim);border-color:var(--dim);}
.b-dim{color:var(--dim);}
.report-nav{display:flex;flex-wrap:wrap;align-items:center;gap:var(--space-2);` +
	`margin:0 0 var(--space-6);padding:var(--space-3) 0;border-block:var(--border-thin) solid var(--border);}
.nav-label{color:var(--dim);font-size:var(--font-sm);}
.report-nav a{display:inline-flex;align-items:center;min-block-size:var(--space-8);` +
	`padding:var(--space-1) var(--space-2);border-radius:var(--radius-sm);` +
	`color:var(--link);font-size:var(--font-sm);text-decoration:underline;}
.report-nav a:focus-visible{outline:var(--border-focus) solid var(--link);outline-offset:var(--space-1);}
.report-section{scroll-margin-block-start:var(--space-4);}
h2{font-size:var(--font-lg);font-weight:700;border-bottom:var(--border-thin) solid var(--border);` +
	`padding-bottom:var(--space-2);margin:var(--space-6) 0 0;}
.s-mal{color:var(--crit);}
.s-sce{color:var(--purple);}
.s-vuln{color:var(--high);}
.s-life{color:var(--link);}
.count{color:var(--dim);font-weight:400;font-size:var(--font-sm);}
.finding{margin:var(--space-3) 0;padding:var(--space-3) var(--space-4);background:var(--panel);` +
	`border-inline-start:var(--border-accent) solid var(--border);border-radius:var(--radius-sm);}
.finding>summary{cursor:pointer;outline:none;}
.finding>summary:focus-visible{outline:var(--border-focus) solid var(--link);` +
	`outline-offset:var(--space-1);border-radius:var(--radius-sm);}
.finding-body{margin-top:var(--space-2);}
.f-crit{border-inline-start-color:var(--crit);}
.f-high{border-inline-start-color:var(--high);}
.f-med{border-inline-start-color:var(--med);}
.f-low{border-inline-start-color:var(--sev-low);}
.f-none{border-inline-start-color:var(--sev-none-bg);}
.sev{border-radius:var(--radius-sm);padding:var(--space-1) var(--space-2);font-size:var(--font-xs);font-weight:700;color:var(--sev-fg);line-height:1;}
.sev-crit{background:var(--crit);}
.sev-high{background:var(--high);}
.sev-med{background:var(--med);}
.sev-low{background:var(--sev-low);}
.sev-none{background:var(--sev-none-bg);color:var(--sev-none-fg);}
.pkg{color:var(--heading);font-weight:700;overflow-wrap:anywhere;word-break:break-word;}
.dim{color:var(--dim);}
.risk{color:var(--risk);overflow-wrap:anywhere;word-break:break-word;}
.fix{color:var(--fix);overflow-wrap:anywhere;word-break:break-word;}
.links{margin-top:var(--space-1);color:var(--dim);font-size:var(--font-sm);overflow-wrap:anywhere;word-break:break-word;}
.links a{display:inline-flex;align-items:center;gap:var(--space-1);min-block-size:var(--space-8);` +
	`padding:var(--space-1) var(--space-2);margin-inline:calc(-1 * var(--space-2));border-radius:var(--radius-sm);color:var(--link);` +
	`text-decoration:underline;overflow-wrap:anywhere;word-break:break-word;}
.links a:focus-visible{outline:var(--border-focus) solid var(--link);outline-offset:var(--space-1);}
.external-link-icon{inline-size:1em;block-size:1em;flex:0 0 auto;color:currentColor;}
.meta,.footer{overflow-wrap:anywhere;word-break:break-word;}
.clean{margin:var(--space-6) 0;padding:var(--space-4);background:var(--success-bg);` +
	`border:var(--border-thin) solid var(--success-border);border-radius:var(--radius-md);color:var(--success);font-size:var(--font-md);}
.warning{margin:var(--space-4) 0;padding:var(--space-4);background:var(--warning-bg);` +
	`border:var(--border-thin) solid var(--high);border-radius:var(--radius-md);color:var(--high);font-size:var(--font-md);}
.status{margin:var(--space-6) 0;padding:var(--space-4);background:var(--status-bg);` +
	`border:var(--border-thin) solid var(--crit);border-radius:var(--radius-md);color:var(--crit);font-size:var(--font-md);}
.footer{border-top:var(--border-thin) solid var(--border);margin-top:var(--space-8);padding-top:var(--space-3);color:var(--dim);font-size:var(--font-xs);}
@media (prefers-color-scheme: light){:root{` + reporthtml.LightBaseThemeCSS +
	`--crit:#cf222e;` +
	`--high:#9a6700;--med:#7d4e00;--sev-low:#0a7f74;--success:#116329;` +
	`--success-bg:#dafbe1;--success-border:#2da44e;--warning-bg:#fff8c5;` +
	`--status-bg:#ffebe9;--sev-fg:#ffffff;--sev-none-bg:#6e7781;--sev-none-fg:#ffffff;` +
	`--risk:#8250df;--fix:#116329;--link:#0969da;--purple:#8250df;}}
@media (prefers-contrast: more){:root{--border:CanvasText;--dim:CanvasText;}` +
	`.badge,.finding,.clean,.warning,.status{border-width:2px;}a{text-decoration:underline;}}
@media (forced-colors: active){:root{` + reporthtml.ForcedColorsBaseThemeCSS +
	`--crit:Highlight;--high:Highlight;--med:Highlight;--sev-low:Highlight;` +
	`--success:CanvasText;--success-bg:Canvas;--success-border:CanvasText;--warning-bg:Canvas;` +
	`--status-bg:Canvas;--sev-fg:HighlightText;--sev-none-bg:CanvasText;--sev-none-fg:Canvas;` +
	`--risk:CanvasText;--fix:CanvasText;--link:LinkText;--purple:CanvasText;}` +
	`*{forced-color-adjust:auto;}.badge,.finding,.clean,.warning,.status{border-color:CanvasText;}` +
	`a{color:LinkText;text-decoration:underline;}}
@media print{:root{` + reporthtml.PrintBaseThemeCSS +
	`--crit:#b42318;--high:#8a4600;` +
	`--med:#7d4e00;--sev-low:#006d75;--success:#116329;--success-bg:#ffffff;` +
	`--success-border:#116329;--warning-bg:#ffffff;--status-bg:#ffffff;--sev-fg:#ffffff;` +
	`--sev-none-bg:#424a53;--sev-none-fg:#ffffff;--risk:#6639ba;--fix:#116329;` +
	`--link:#0645ad;--purple:#6639ba;}body{background:#fff;color:#111827;}` +
	`.wrap{max-width:none;padding:0;}.finding,.clean,.warning,.status{break-inside:avoid;` +
	`page-break-inside:avoid;background:#fff;}a{color:var(--link);}a[href]::after{content:" ` +
	`(" attr(href) ")";display:inline;inline-size:auto;block-size:auto;margin-inline-start:0;` +
	`border:0;transform:none;color:var(--dim);overflow-wrap:anywhere;word-break:break-word;}` +
	`.external-link-icon{display:none;}}`

const htmlTemplateBody = `
</style>
</head>
<body>
<main class="wrap">
<h1><bdi dir="auto">{{.Title}}</bdi></h1>
<div class="meta">{{.Messages.ReportType}}{{if .Mode}} &middot; {{.Mode}} {{.Messages.ModeSuffix}}{{end}} ` +
	`&middot; {{count .Packages .Messages.PackageSingular .Messages.PackagePlural}}{{if .ScannedAt}} &middot; ` +
	`<time datetime="{{.ScannedAtDateTime}}" data-report-time="scanned-at">{{.ScannedAt}}</time>{{end}}` +
	`{{if .Duration}} &middot; <span data-duration-ms="{{.DurationMS}}" data-report-duration="scan">{{.Duration}}</span>{{end}}</div>
<div class="badges">
{{range .Severity}}<span class="badge {{.Class}}">{{.Count}} {{.Label}}</span>{{end}}
{{range .TypeCounts}}<span class="badge {{.Class}}">{{.Count}} {{.Label}}</span>{{end}}
<span class="badge b-dim">{{count .FindingsTotal .Messages.FindingSingular .Messages.FindingPlural}} &middot; ` +
	`{{count .Blocking .Messages.BlockingSingular .Messages.BlockingPlural}}</span>
</div>
{{if .Status}}<div class="status">{{.Messages.StatusPrefix}} <bdi dir="auto">{{.Status}}</bdi></div>{{end}}
{{range .Warnings}}<div class="warning"><bdi dir="auto">{{.}}</bdi></div>{{end}}
{{if .Clean}}<div class="clean">{{.Messages.NoFindingsPrefix}} {{count .Packages .Messages.PackageSingular .Messages.PackagePlural}}{{.Messages.NoFindingsSuffix}}</div>{{end}}
{{if .Sections}}
<nav class="report-nav" aria-label="{{.Messages.FindingSections}}">
<span class="nav-label">{{.Messages.JumpTo}}</span>
{{range .Sections}}<a href="#{{.ID}}">{{.Title}} <span class="count">({{len .Findings}})</span></a>{{end}}
</nav>
{{end}}
{{range .Sections}}
<section id="{{.ID}}" class="report-section" aria-labelledby="{{.HeadingID}}">
<h2 id="{{.HeadingID}}" class="{{.Class}}">{{.Title}} <span class="count">({{len .Findings}})</span></h2>
{{range .Findings}}
<details class="finding f-{{.SevSlug}}">
<summary><span class="sev sev-{{.SevSlug}}">{{.Severity}}</span> ` +
	`<span class="pkg"><bdi dir="auto">{{.Package}}</bdi></span> ` +
	`<span class="dim">&middot; <bdi dir="auto">{{.Ecosystem}}</bdi>` +
	`{{if .Advisory}} &middot; <bdi dir="auto">{{.Advisory}}</bdi>{{end}}</span></summary>
<div class="finding-body">
{{if .RiskType}}<div><span class="risk">{{$.Messages.RiskLabel}}: {{if .RiskLabel}}{{.RiskLabel}}{{if .RiskNote}} - {{.RiskNote}}{{end}}{{else}}{{$.Messages.CustomRiskPrefix}} ` +
	`({{.RiskType}}){{end}}</span></div>{{end}}
<div>{{if .Title}}<bdi dir="auto">{{.Title}}</bdi>{{end}}{{if .FixedVersion}} ` +
	`<span class="fix">{{$.Messages.FixedVersionLabel}}: <bdi dir="auto">{{.FixedVersion}}</bdi></span>{{end}}</div>
{{if or .Links .Plain}}<div class="links">{{$.Messages.SourceLabel}}: <bdi dir="auto">{{.Source}}</bdi>` +
	`{{range .Links}} &middot; <a class="external-link" href="{{.URL}}">` +
	`<bdi dir="auto">{{.Label}}</bdi><svg class="external-link-icon" aria-hidden="true" ` +
	`viewBox="0 0 16 16" focusable="false"><path d="M6 4h6v6M12 4 4 12" ` +
	`fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" ` +
	`stroke-linejoin="round"/></svg></a>{{end}}{{range .Plain}} &middot; ` +
	`<bdi dir="auto">{{.}}</bdi>{{end}}</div>{{else if .Source}}` +
	`<div class="links">{{$.Messages.SourceLabel}}: <bdi dir="auto">{{.Source}}</bdi></div>{{end}}
</div>
</details>
{{end}}
</section>
{{end}}
<div class="footer">{{range $i, $p := .FooterParts}}{{if $i}} &middot; {{end}}{{$p}}{{end}}</div>
</main>
`

const htmlTemplateEnd = `
</body>
</html>`
