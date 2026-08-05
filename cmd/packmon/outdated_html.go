package main

import (
	"html/template"
	"sync"

	"github.com/8linkz-sec/packmon/internal/reporthtml"
)

var outdatedHTMLTemplate = sync.OnceValue(func() *template.Template {
	return template.Must(template.New("outdated").Parse(outdatedHTML))
})

const outdatedHTML = cliHTMLReportHeadPrefix + cliHTMLReportCSPMeta +
	outdatedHTMLHead + outdatedHTMLStyle + outdatedHTMLBody +
	generatedHTMLReportLocaleScript + outdatedHTMLTail

const outdatedHTMLHead = `
<title>{{.Messages.DocumentTitle}}</title>
<style>
`

const outdatedHTMLStyle = `:root{` + reporthtml.DarkBaseThemeCSS +
	`--warning:#ffa657;--warning-bg:#2d1f0f;` +
	`--success:#7ee787;--success-bg:#0f2d2a;--success-border:#238636;--unknown:#8b949e;` +
	cliHTMLReportScaleCSS + `}` + cliHTMLReportBaseCSS + `
.ok{color:var(--success);border-color:var(--success);}
.unknown{color:var(--unknown);border-color:var(--unknown);}
` + `.provenance-legend{border:1px solid var(--border);border-radius:var(--report-radius-md);` +
	`background:var(--panel);padding:var(--report-space-3);margin:0 0 var(--report-space-3);color:var(--dim);` +
	`font-size:var(--report-type-sm);}` + `
.provenance-legend p{margin:0;overflow-wrap:anywhere;word-break:break-word;}
.provenance-legend strong{color:var(--heading);}
.mobile-list{display:grid;gap:var(--report-space-3);margin:0 0 var(--report-space-3);}
.mobile-card{border:1px solid var(--border);border-radius:var(--report-radius-md);background:var(--panel);padding:var(--report-space-3);}
` + `.mobile-primary{display:flex;flex-wrap:wrap;align-items:flex-start;` +
	`justify-content:space-between;gap:var(--report-space-2);margin:0 0 var(--report-space-3);}` + `
.mobile-primary h2{margin:0;color:var(--heading);font-size:var(--report-type-md);overflow-wrap:anywhere;word-break:break-word;}
` + `.mobile-ecosystem{color:var(--dim);font-size:var(--report-type-xs);border:1px solid var(--border);` +
	`border-radius:var(--report-radius-pill);padding:var(--report-space-0-5) var(--report-space-2);white-space:nowrap;}` + `
.mobile-versions{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:var(--report-space-2);margin:0 0 var(--report-space-3);}
.mobile-versions dt,.detail-grid dt{color:var(--dim);font-size:var(--report-type-2xs);text-transform:uppercase;}
.mobile-versions dd,.detail-grid dd{margin:var(--report-space-0-5) 0 0;overflow-wrap:anywhere;word-break:break-word;}
` + `.mobile-card summary{cursor:pointer;color:var(--heading);font-weight:700;` +
	`min-height:var(--report-touch-target);display:flex;align-items:center;}` + `
.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:var(--report-space-2);margin:var(--report-space-2) 0 0;}
.table-scroll{display:none;overflow-x:auto;border:1px solid var(--border);border-radius:var(--report-radius-md);background:var(--panel);}
.table-scroll:focus{outline:var(--report-focus-ring) solid var(--warning);outline-offset:var(--report-focus-offset);}
table{width:100%;min-width:62rem;border-collapse:collapse;background:var(--panel);}
th,td{padding:var(--report-space-2) var(--report-space-3);border-bottom:1px solid var(--border);text-align:start;vertical-align:top;}
th{color:var(--heading);font-size:var(--report-type-xs);text-transform:uppercase;}
td{overflow-wrap:anywhere;word-break:break-word;}
.name{min-width:260px;overflow-wrap:anywhere;word-break:break-word;}
.version{min-width:260px;overflow-wrap:anywhere;word-break:break-word;}
.ecosystem{white-space:nowrap;min-width:96px;}
.short{white-space:nowrap;min-width:90px;}
.provenance{min-width:260px;}
.table-provenance-list{display:flex;flex-wrap:wrap;gap:var(--report-space-1-5) var(--report-space-3);margin:0;padding:0;}
.table-provenance-list div{display:flex;gap:var(--report-space-1);min-width:0;}
.table-provenance-list dt{font-weight:700;color:var(--dim);}
.table-provenance-list dd{margin:0;overflow-wrap:anywhere;word-break:break-word;}
.lockfile{min-width:260px;overflow-wrap:anywhere;word-break:break-word;}
` + `.empty{margin:var(--report-space-6) 0;padding:var(--report-space-3) var(--report-space-4);background:var(--success-bg);` +
	`border:1px solid var(--success-border);border-radius:var(--report-radius-md);color:var(--success);` +
	`font-size:var(--report-type-md);}` + `
.empty-unknown{background:var(--warning-bg);border-color:var(--warning);color:var(--warning);}
` + `@supports not (font-size:var(--report-type-base)){body{font-size:0.875rem;}` +
	`h1{font-size:1.375rem;}.mobile-primary h2,.empty{font-size:0.9375rem;}` +
	`.meta,.badge,.provenance-legend{font-size:0.8125rem;}` +
	`.mobile-ecosystem,th,.footer{font-size:0.75rem;}` +
	`.mobile-versions dt,.detail-grid dt{font-size:0.6875rem;}}` + `
` + `@media (prefers-color-scheme: light){:root{` + reporthtml.LightBaseThemeCSS +
	`--warning:#9a6700;--warning-bg:#fff8c5;--success:#116329;--success-bg:#dafbe1;` +
	`--success-border:#2da44e;--unknown:#57606a;}}` + `
` + `@media (prefers-contrast: more){:root{--border:CanvasText;--dim:CanvasText;` +
	`}.badge,.provenance-legend,.mobile-card,.table-scroll,.empty{border-width:2px;}}` + `
` + `@media (forced-colors: active){:root{` + reporthtml.ForcedColorsBaseThemeCSS +
	`--warning:CanvasText;--warning-bg:Canvas;--success:CanvasText;--success-bg:Canvas;` +
	`--success-border:CanvasText;--unknown:CanvasText;}*{forced-color-adjust:auto;` +
	`}.badge,.provenance-legend,.mobile-card,.table-scroll,.empty{border-color:CanvasText;` +
	`}.table-scroll:focus{outline-color:Highlight;}}` + `
@media (min-width:900px){.mobile-list{display:none;}.table-scroll{display:block;}}
` + `@media print{:root{` + reporthtml.PrintBaseThemeCSS +
	`--warning:#8a4600;--warning-bg:#ffffff;` +
	`--success:#116329;--success-bg:#ffffff;--success-border:#116329;--unknown:#424a53;` +
	`}body{background:#fff;color:#111827;}.wrap{max-width:none;padding:0;` +
	`}.mobile-list{display:none;}.table-scroll{display:block;overflow:visible;` +
	`border-color:var(--border);}table{min-width:0;table-layout:fixed;` +
	`}.name,.version,.ecosystem,.short,.lockfile{min-width:0;white-space:normal;` +
	`}.provenance{min-width:0;white-space:normal;` +
	`}.empty{break-inside:avoid;page-break-inside:avoid;background:#fff;}}`

const outdatedHTMLBody = `
</style>
</head>
<body>
<main class="wrap">
<h1>{{.Messages.Heading}}</h1>
` + `<div class="meta">{{.Messages.ReportType}} &middot;` +
	` {{.Total}} {{.PackageWord}}{{if .Target}} &middot;` +
	` <bdi dir="auto">{{.Target}}</bdi>{{end}}{{if .ScannedAt}} &middot;` +
	` {{if .ScannedAtDateTime}}<time datetime="{{.ScannedAtDateTime}}" data-report-time="scanned-at">{{.ScannedAt}}</time>` +
	`{{else}}{{.ScannedAt}}{{end}}{{end}}</div>` + `
<div class="summary">
<span class="badge warn">{{len .Outdated}} {{.Messages.OutdatedLabel}}</span>
<span class="badge ok">{{.UpToDate}} {{.Messages.UpToDateLabel}}</span>
<span class="badge unknown">{{.Unknown}} {{.Messages.UnknownLabel}}</span>
</div>
{{if .Outdated}}
<div id="outdated-provenance-legend" class="provenance-legend">
` + `<p><strong>{{.Messages.ProvenanceHeading}}</strong> {{.Messages.ProvenanceDescription}}</p>` + `
</div>
<div class="mobile-list" aria-label="{{.Messages.OutdatedCardsLabel}}">
{{range .Outdated}}<article class="mobile-card">
` + `<div class="mobile-primary"><h2><bdi dir="auto">{{.Name}}` +
	`</bdi></h2><span class="mobile-ecosystem">{{.Ecosystem}}</span></div>` + `
` + `<dl class="mobile-versions"><div><dt>{{$.Messages.InstalledColumn}}</dt><dd><bdi dir="auto">{{.Installed}}` +
	`</bdi></dd></div><div><dt>{{$.Messages.LatestColumn}}</dt><dd><bdi dir="auto">{{.Latest}}` +
	`</bdi></dd></div></dl>` + `
` + `<details><summary>{{$.Messages.ProvenanceSummary}}</summary><dl class="detail-grid"><div><dt>` +
	`{{$.Messages.ScopeLabel}}</dt><dd>{{.Scope}}</dd></div><div><dt>{{$.Messages.RelationLabel}}</dt><dd>{{.Relation}}` +
	`</dd></div><div><dt>{{$.Messages.ViaLabel}}</dt><dd><bdi dir="auto">{{.Via}}</bdi></dd></div><div><dt>{{$.Messages.FlagsLabel}}</dt><dd>{{.Flags}}` +
	`</dd></div><div><dt>{{$.Messages.LockfileColumn}}</dt><dd><bdi dir="auto">{{.LockFile}}` +
	`</bdi></dd></div></dl></details>` + `
</article>{{end}}
</div>
<div class="table-scroll" tabindex="0" role="region" aria-label="{{.Messages.OutdatedTableLabel}}">
<table aria-describedby="outdated-provenance-legend">
` + `<thead><tr><th scope="col" class="name">{{.Messages.PackageColumn}}</th><th scope="col" class="version">{{.Messages.InstalledColumn}}</th>` +
	`<th scope="col" class="version">{{.Messages.LatestColumn}}</th><th scope="col" class="ecosystem">{{.Messages.EcosystemColumn}}</th><th scope="col" class="provenance">{{.Messages.ProvenanceColumn}}</th>` +
	`<th scope="col" class="lockfile">{{.Messages.LockfileColumn}}</th></tr></thead>` + `
<tbody>
` + `{{range .Outdated}}<tr><td class="name"><bdi dir="auto">{{.Name}}` +
	`</bdi></td><td class="version"><bdi dir="auto">{{.Installed}}` +
	`</bdi></td><td class="version"><bdi dir="auto">{{.Latest}}` +
	`</bdi></td><td class="ecosystem">{{.Ecosystem}}</td><td class="provenance"><dl class="table-provenance-list"><div><dt>{{$.Messages.ScopeLabel}}</dt><dd>{{.Scope}}` +
	`</dd></div><div><dt>{{$.Messages.RelationLabel}}</dt><dd>{{.Relation}}</dd></div><div><dt>{{$.Messages.ViaLabel}}</dt><dd><bdi dir="auto">{{.Via}}</bdi>` +
	`</dd></div><div><dt>{{$.Messages.FlagsLabel}}</dt><dd>{{.Flags}}</dd></div></dl></td><td class="lockfile"><bdi dir="auto">{{.LockFile}}</bdi></td></tr>{{end}}` + `
</tbody>
</table>
</div>
{{else}}
<div class="{{.EmptyStateClass}}">{{.EmptyStateMessage}}</div>
{{end}}
<div class="footer">{{.LockFiles}} {{.Messages.LockfilesLabel}} &middot; {{.SBOMFiles}} {{.Messages.SBOMFilesLabel}}</div>
</main>
`

const outdatedHTMLTail = `
</body>
</html>`
