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
		closeSilently(f)
		return err
	}
	return f.Close()
}

type htmlReport struct {
	Title         string
	Mode          string
	Packages      int
	ScannedAt     string
	Duration      string
	Severity      []htmlBadge
	TypeCounts    []htmlBadge
	FindingsTotal int
	Blocking      int
	Clean         bool
	Status        string
	Warnings      []string
	Sections      []htmlSection
	FooterParts   []string
}

type htmlBadge struct {
	Label string
	Class string
	Count int
}

type htmlSection struct {
	Title    string
	Class    string
	Findings []htmlFinding
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
	typ   domain.FindingType
	title string
	class string
}

var sectionDefs = []sectionDef{
	{domain.FindingTypeMalicious, "Malicious", "s-mal"},
	{domain.FindingTypeSupplyChainRisk, "Supply-Chain / EOL", "s-sce"},
	{domain.FindingTypeVulnerability, "Vulnerabilities", "s-vuln"},
	{domain.FindingTypeLifecycle, "Lifecycle warnings", "s-life"},
}

func buildReport(title, toolVersion string, failOn domain.Severity, result *domain.ScanResult) htmlReport {
	if strings.TrimSpace(title) == "" {
		title = "Packmon Security Report"
	}

	rep := htmlReport{
		Title:         title,
		Mode:          result.Mode,
		Packages:      result.PackagesScanned,
		Duration:      formatDurationMs(result.DurationMs),
		FindingsTotal: len(result.Findings),
		Status:        scanOperationalStatusMessage(result),
		Warnings:      htmlReportWarnings(result),
	}
	rep.Clean = result.PackagesScanned > 0 && len(result.Findings) == 0 && rep.Status == "" && len(rep.Warnings) == 0
	if !result.ScannedAt.IsZero() {
		rep.ScannedAt = formatReportTimestamp(result.ScannedAt)
	}

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
	for _, s := range sevOrder {
		n := 0
		for _, f := range result.Findings {
			if f.Severity == s.sev {
				n++
			}
		}
		if n > 0 {
			rep.Severity = append(rep.Severity, htmlBadge{Label: s.label, Class: s.class, Count: n})
		}
	}

	// Any finding whose severity is not one of the four ranked levels (e.g.
	// UNKNOWN or empty) is counted under a single "Unknown" badge, so the
	// severity badges always sum to FindingsTotal.
	unknown := 0
	for _, f := range result.Findings {
		if sevSlug(f.Severity) == "none" {
			unknown++
		}
	}
	if unknown > 0 {
		rep.Severity = append(rep.Severity, htmlBadge{Label: "Unknown", Class: "b-none", Count: unknown})
	}

	for _, def := range sectionDefs {
		n := 0
		for _, f := range result.Findings {
			if f.Type == def.typ {
				n++
			}
		}
		if n > 0 {
			rep.TypeCounts = append(rep.TypeCounts, htmlBadge{Label: htmlTypeBadgeLabel(def.typ, n), Class: "b-dim", Count: n})
		}
	}

	for _, f := range result.Findings {
		if domain.FindingBlocks(f, failOn) {
			rep.Blocking++
		}
	}

	for _, def := range sectionDefs {
		var fs []htmlFinding
		for _, f := range result.Findings {
			if f.Type != def.typ {
				continue
			}
			links, plain := makeLinks(f)
			fs = append(fs, htmlFinding{
				Severity:     string(f.Severity),
				SevSlug:      sevSlug(f.Severity),
				Package:      fmt.Sprintf("%s@%s", f.Name, f.Version),
				Ecosystem:    string(f.Ecosystem),
				Advisory:     advisoryLabel(f),
				Title:        f.Title,
				FixedVersion: f.FixedVersion,
				RiskType:     f.RiskType,
				Source:       f.Source,
				Links:        links,
				Plain:        plain,
			})
		}
		if len(fs) == 0 {
			continue
		}
		sort.SliceStable(fs, func(i, j int) bool {
			return domain.Severity(fs[i].Severity).Rank() > domain.Severity(fs[j].Severity).Rank()
		})
		rep.Sections = append(rep.Sections, htmlSection{
			Title: def.title, Class: def.class, Findings: fs,
		})
	}

	rep.FooterParts = footerParts(toolVersion, result)
	return rep
}

func operationalStatusMessage(status string) string {
	status = strings.TrimSpace(status)
	switch status {
	case "", "healthy", "degraded":
		return ""
	default:
		return status
	}
}

func htmlReportWarnings(result *domain.ScanResult) []string {
	if result == nil {
		return nil
	}
	var warnings []string
	if strings.TrimSpace(result.FeedStatus) == "degraded" {
		warnings = append(warnings, "Server reports degraded feed status. Some feeds may be outdated.")
	}
	if message := zeroPackageScanDiagnostic(result); message != "" {
		warnings = append(warnings, message)
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
	return warnings
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

func footerParts(toolVersion string, result *domain.ScanResult) []string {
	var parts []string
	if d := formatDurationMs(result.DurationMs); d != "" {
		parts = append(parts, "Scan "+d)
	}
	if result.Mode == "local" && result.DBAgeDays != nil {
		note := fmt.Sprintf("DB synced %s ago", plural.Count(*result.DBAgeDays, "day", "days"))
		if result.DBStale {
			note += " (stale)"
		}
		parts = append(parts, note)
	}
	switch result.FeedStatus {
	case "":
	case "healthy":
		parts = append(parts, "feeds: healthy")
	case "degraded":
		parts = append(parts, "feeds: degraded")
	default:
		parts = append(parts, result.FeedStatus)
	}
	parts = append(parts, "packmon "+toolVersion)
	if result.ScanID != "" {
		parts = append(parts, "scan_id "+result.ScanID)
	}
	if result.ManualCount > 0 {
		parts = append(parts, plural.Count(result.ManualCount, "manual advisory", "manual advisories"))
	}
	return parts
}

func htmlTypeBadgeLabel(typ domain.FindingType, count int) string {
	switch typ {
	case domain.FindingTypeMalicious:
		return plural.Word(count, "Malicious package", "Malicious packages")
	case domain.FindingTypeSupplyChainRisk:
		return plural.Word(count, "Supply-chain / EOL finding", "Supply-chain / EOL findings")
	case domain.FindingTypeVulnerability:
		return plural.Word(count, "Vulnerability", "Vulnerabilities")
	case domain.FindingTypeLifecycle:
		return plural.Word(count, "Lifecycle warning", "Lifecycle warnings")
	default:
		return plural.Word(count, "Finding", "Findings")
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} - Packmon Report</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--heading:#e6edf3;--dim:#8b949e;--crit:#ff7b72;--high:#ffa657;--med:#e3b341;--sev-low:#56d4c4;--success:#7ee787;--success-bg:#0f2d2a;--success-border:#238636;--risk:#d2a8ff;--fix:#7ee787;--link:#58a6ff;--purple:#d2a8ff;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;line-height:1.6;}
.wrap{max-width:920px;margin:0 auto;padding:28px 24px 48px;}
h1{font-size:22px;font-weight:800;color:var(--heading);margin:0;overflow-wrap:anywhere;word-break:break-word;}
.meta{color:var(--dim);font-size:13px;margin-top:4px;}
.badges{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0 24px;}
.badge{border-radius:6px;padding:3px 11px;font-size:13px;border:1px solid var(--border);}
.b-crit{color:var(--crit);border-color:var(--crit);}
.b-high{color:var(--high);border-color:var(--high);}
.b-med{color:var(--med);border-color:var(--med);}
.b-low{color:var(--sev-low);border-color:var(--sev-low);}
.b-none{color:var(--dim);border-color:var(--dim);}
.b-dim{color:var(--dim);}
h2{font-size:16px;font-weight:700;border-bottom:1px solid var(--border);padding-bottom:5px;margin:22px 0 0;}
.s-mal{color:var(--crit);}
.s-sce{color:var(--purple);}
.s-vuln{color:var(--high);}
.s-life{color:var(--link);}
.count{color:var(--dim);font-weight:400;font-size:13px;}
.finding{margin:10px 0;padding:10px 12px;background:var(--panel);border-left:3px solid var(--border);border-radius:5px;}
.f-crit{border-left-color:var(--crit);}
.f-high{border-left-color:var(--high);}
.f-med{border-left-color:var(--med);}
.f-low{border-left-color:var(--sev-low);}
.f-none{border-left-color:#484f58;}
.sev{border-radius:4px;padding:1px 7px;font-size:12px;font-weight:700;color:#0d1117;}
.sev-crit{background:var(--crit);}
.sev-high{background:var(--high);}
.sev-med{background:var(--med);}
.sev-low{background:var(--sev-low);}
.sev-none{background:#484f58;color:#fff;}
.pkg{color:var(--heading);font-weight:700;overflow-wrap:anywhere;word-break:break-word;}
.dim{color:var(--dim);}
.risk{color:var(--risk);overflow-wrap:anywhere;word-break:break-word;}
.fix{color:var(--fix);overflow-wrap:anywhere;word-break:break-word;}
.links{margin-top:4px;color:var(--dim);font-size:13px;overflow-wrap:anywhere;word-break:break-word;}
.links a{color:var(--link);text-decoration:underline;overflow-wrap:anywhere;word-break:break-word;}
.meta,.footer{overflow-wrap:anywhere;word-break:break-word;}
.clean{margin:24px 0;padding:14px 16px;background:var(--success-bg);border:1px solid var(--success-border);border-radius:6px;color:var(--success);font-size:15px;}
.warning{margin:18px 0;padding:14px 16px;background:#322717;border:1px solid var(--high);border-radius:6px;color:var(--high);font-size:15px;}
.status{margin:24px 0;padding:14px 16px;background:#321820;border:1px solid var(--crit);border-radius:6px;color:var(--crit);font-size:15px;}
.footer{border-top:1px solid var(--border);margin-top:28px;padding-top:10px;color:var(--dim);font-size:12px;}
@media (prefers-color-scheme: light){:root{--bg:#ffffff;--panel:#f6f8fa;--border:#d0d7de;--fg:#24292f;--heading:#111827;--dim:#57606a;--crit:#cf222e;--high:#9a6700;--med:#7d4e00;--sev-low:#0a7f74;--success:#116329;--success-bg:#dafbe1;--success-border:#2da44e;--risk:#8250df;--fix:#116329;--link:#0969da;--purple:#8250df;}}
@media print{:root{--bg:#ffffff;--panel:#ffffff;--border:#8c959f;--fg:#111827;--heading:#000000;--dim:#424a53;--crit:#b42318;--high:#8a4600;--med:#7d4e00;--sev-low:#006d75;--success:#116329;--success-bg:#ffffff;--success-border:#116329;--risk:#6639ba;--fix:#116329;--link:#0645ad;--purple:#6639ba;}body{background:#fff;color:#111827;}.wrap{max-width:none;padding:0;}.finding,.clean,.warning,.status{break-inside:avoid;page-break-inside:avoid;background:#fff;}a{color:var(--link);}}
</style>
</head>
<body>
<div class="wrap">
<h1>{{.Title}}</h1>
<div class="meta">Packmon Security Report{{if .Mode}} &middot; {{.Mode}} mode{{end}} &middot; {{count .Packages "package" "packages"}}{{if .ScannedAt}} &middot; {{.ScannedAt}}{{end}}{{if .Duration}} &middot; {{.Duration}}{{end}}</div>
<div class="badges">
{{range .Severity}}<span class="badge {{.Class}}">{{.Count}} {{.Label}}</span>{{end}}
{{range .TypeCounts}}<span class="badge {{.Class}}">{{.Count}} {{.Label}}</span>{{end}}
<span class="badge b-dim">{{count .FindingsTotal "finding" "findings"}} &middot; {{count .Blocking "blocking" "blocking"}}</span>
</div>
{{if .Status}}<div class="status">Scan did not complete: {{.Status}}</div>{{end}}
{{range .Warnings}}<div class="warning">{{.}}</div>{{end}}
{{if .Clean}}<div class="clean">No findings in {{count .Packages "package" "packages"}}.</div>{{end}}
{{range .Sections}}
<h2 class="{{.Class}}">{{.Title}} <span class="count">({{len .Findings}})</span></h2>
{{range .Findings}}
<div class="finding f-{{.SevSlug}}">
<div><span class="sev sev-{{.SevSlug}}">{{.Severity}}</span> <span class="pkg">{{.Package}}</span> <span class="dim">&middot; {{.Ecosystem}}</span>{{if .RiskType}} <span class="risk">&middot; risk: {{.RiskType}}</span>{{end}}</div>
<div>{{if .Advisory}}{{.Advisory}}{{if .Title}} &mdash; {{end}}{{end}}{{.Title}}{{if .FixedVersion}} <span class="fix">Fix: {{.FixedVersion}}</span>{{end}}</div>
{{if or .Links .Plain}}<div class="links">Source: {{.Source}}{{range .Links}} &middot; <a href="{{.URL}}">{{.Label}} &#8599;</a>{{end}}{{range .Plain}} &middot; {{.}}{{end}}</div>{{else if .Source}}<div class="links">Source: {{.Source}}</div>{{end}}
</div>
{{end}}
{{end}}
<div class="footer">{{range $i, $p := .FooterParts}}{{if $i}} &middot; {{end}}{{$p}}{{end}}</div>
</div>
</body>
</html>`
