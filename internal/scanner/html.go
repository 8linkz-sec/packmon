package scanner

import (
	"fmt"
	"html/template"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
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

var htmlReportTemplate = template.Must(template.New("report").Parse(htmlTemplate))

// Write renders the scan result as an HTML document to w. title is the report
// heading (repo name); failOn is the configured blocking threshold.
func (hw *HTMLWriter) Write(w io.Writer, title string, failOn domain.Severity, result *domain.ScanResult) error {
	rep := buildReport(title, hw.toolVersion, failOn, result)
	if err := htmlReportTemplate.Execute(w, rep); err != nil {
		return fmt.Errorf("html: render: %w", err)
	}
	return nil
}

// WriteFile renders the HTML report to the given file path.
func (hw *HTMLWriter) WriteFile(path, title string, failOn domain.Severity, result *domain.ScanResult) error {
	// #nosec G304 -- CLI output path is provided intentionally by the local user.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
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
		Clean:         len(result.Findings) == 0 && !hasOperationalStatus(result.FeedStatus),
		Status:        operationalStatusMessage(result.FeedStatus),
	}
	if !result.ScannedAt.IsZero() {
		rep.ScannedAt = result.ScannedAt.Format("2006-01-02 15:04")
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
			rep.TypeCounts = append(rep.TypeCounts, htmlBadge{Label: def.title, Class: "b-dim", Count: n})
		}
	}

	for _, f := range result.Findings {
		if isAlwaysBlockingFinding(f) || (failOn != domain.SeverityNone && f.Severity.Blocks(failOn)) {
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

func hasOperationalStatus(status string) bool {
	return operationalStatusMessage(status) != ""
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

func makeLinks(f domain.Finding) (links []htmlLink, plain []string) {
	add := func(label, raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if u, err := url.Parse(raw); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			lbl := strings.TrimSpace(label)
			if lbl == "" {
				lbl = u.Host + u.Path
			}
			links = append(links, htmlLink{Label: lbl, URL: raw})
			return
		}
		plain = append(plain, raw)
	}
	add("", f.URL)
	for _, r := range f.Resources {
		add(r.Label, r.URL)
	}
	return links, plain
}

func advisoryLabel(f domain.Finding) string {
	if f.AdvisoryID != "" {
		return f.AdvisoryID
	}
	switch f.Type {
	case domain.FindingTypeMalicious:
		return "MALWARE"
	case domain.FindingTypeSupplyChainRisk:
		return "SUPPLY-CHAIN"
	default:
		return ""
	}
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

func footerParts(toolVersion string, result *domain.ScanResult) []string {
	var parts []string
	if d := formatDurationMs(result.DurationMs); d != "" {
		parts = append(parts, "Scan "+d)
	}
	if result.Mode == "local" && result.DBAgeDays != nil {
		note := fmt.Sprintf("DB synced %d days ago", *result.DBAgeDays)
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
		parts = append(parts, fmt.Sprintf("%d manual advisories", result.ManualCount))
	}
	return parts
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} - Packmon Report</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--dim:#8b949e;--crit:#ff7b72;--high:#ffa657;--med:#e3b341;--low:#56d4c4;--link:#58a6ff;--purple:#d2a8ff;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;line-height:1.6;}
.wrap{max-width:920px;margin:0 auto;padding:28px 24px 48px;}
h1{font-size:22px;font-weight:800;color:#e6edf3;margin:0;}
.meta{color:var(--dim);font-size:13px;margin-top:4px;}
.badges{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0 24px;}
.badge{border-radius:6px;padding:3px 11px;font-size:13px;border:1px solid var(--border);}
.b-crit{color:var(--crit);border-color:var(--crit);}
.b-high{color:var(--high);border-color:var(--high);}
.b-med{color:var(--med);border-color:var(--med);}
.b-low{color:var(--low);border-color:var(--low);}
.b-none{color:var(--dim);border-color:var(--dim);}
.b-dim{color:var(--dim);}
h2{font-size:16px;font-weight:700;border-bottom:1px solid var(--border);padding-bottom:5px;margin:22px 0 0;}
.s-mal{color:var(--crit);}
.s-sce{color:var(--purple);}
.s-vuln{color:var(--high);}
.s-life{color:var(--low);}
.count{color:var(--dim);font-weight:400;font-size:13px;}
.finding{margin:10px 0;padding:10px 12px;background:var(--panel);border-left:3px solid var(--border);border-radius:5px;}
.f-crit{border-left-color:var(--crit);}
.f-high{border-left-color:var(--high);}
.f-med{border-left-color:var(--med);}
.f-low{border-left-color:var(--low);}
.f-none{border-left-color:#484f58;}
.sev{border-radius:4px;padding:1px 7px;font-size:12px;font-weight:700;color:#0d1117;}
.sev-crit{background:var(--crit);}
.sev-high{background:var(--high);}
.sev-med{background:var(--med);}
.sev-low{background:var(--low);}
.sev-none{background:#484f58;color:#fff;}
.pkg{color:#e6edf3;font-weight:700;}
.dim{color:var(--dim);}
.risk{color:var(--low);}
.fix{color:var(--low);}
.links{margin-top:4px;color:var(--dim);font-size:13px;}
.links a{color:var(--link);text-decoration:underline;}
.clean{margin:24px 0;padding:14px 16px;background:#0f2d2a;border:1px solid var(--low);border-radius:6px;color:var(--low);font-size:15px;}
.status{margin:24px 0;padding:14px 16px;background:#321820;border:1px solid var(--crit);border-radius:6px;color:var(--crit);font-size:15px;}
.footer{border-top:1px solid var(--border);margin-top:28px;padding-top:10px;color:var(--dim);font-size:12px;}
</style>
</head>
<body>
<div class="wrap">
<h1>{{.Title}}</h1>
<div class="meta">Packmon Security Report{{if .Mode}} &middot; {{.Mode}} mode{{end}} &middot; {{.Packages}} packages{{if .ScannedAt}} &middot; {{.ScannedAt}}{{end}}{{if .Duration}} &middot; {{.Duration}}{{end}}</div>
<div class="badges">
{{range .Severity}}<span class="badge {{.Class}}">{{.Count}} {{.Label}}</span>{{end}}
{{range .TypeCounts}}<span class="badge {{.Class}}">{{.Count}} {{.Label}}</span>{{end}}
<span class="badge b-dim">{{.FindingsTotal}} findings &middot; {{.Blocking}} blocking</span>
</div>
{{if .Status}}<div class="status">Scan did not complete: {{.Status}}</div>{{end}}
{{if .Clean}}<div class="clean">&#10003; No findings in {{.Packages}} packages.</div>{{end}}
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
