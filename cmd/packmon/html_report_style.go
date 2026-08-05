package main

const cliHTMLReportHeadPrefix = `<!DOCTYPE html>
<html lang="{{.Lang}}" dir="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
`

const cliHTMLReportCSPMeta = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">`

const cliHTMLReportScaleCSS = `--report-type-2xs:0.6875rem;--report-type-xs:0.75rem;` +
	`--report-type-sm:0.8125rem;--report-type-base:0.875rem;--report-type-md:0.9375rem;` +
	`--report-type-lg:1rem;--report-type-xl:1.375rem;--report-space-0-5:0.125rem;` +
	`--report-space-1:0.25rem;--report-space-1-5:0.375rem;--report-space-2:0.5rem;` +
	`--report-space-3:0.75rem;--report-space-4:1rem;--report-space-5:1.25rem;` +
	`--report-space-6:1.5rem;--report-space-7:1.75rem;--report-space-8:3rem;` +
	`--report-radius-sm:0.25rem;--report-radius-md:0.375rem;` +
	`--report-radius-pill:999px;--report-focus-ring:0.1875rem;` +
	`--report-focus-offset:0.1875rem;--report-touch-target:2.75rem;`

const cliHTMLReportBaseCSS = `
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:var(--report-type-base);line-height:1.5;}
.wrap{max-width:1600px;margin:0 auto;padding:var(--report-space-7) var(--report-space-5) var(--report-space-8);}
h1{font-size:var(--report-type-xl);margin:0;color:var(--heading);overflow-wrap:anywhere;word-break:break-word;}
.meta{color:var(--dim);font-size:var(--report-type-sm);margin:var(--report-space-1) 0 var(--report-space-5);}
.summary{display:flex;flex-wrap:wrap;gap:var(--report-space-2);margin:0 0 var(--report-space-6);}
.badge{border:1px solid var(--border);border-radius:var(--report-radius-md);padding:var(--report-space-1) var(--report-space-3);font-size:var(--report-type-sm);color:var(--dim);}
.warn{color:var(--warning);border-color:var(--warning);}
.meta,.footer{overflow-wrap:anywhere;word-break:break-word;}
.footer{border-top:1px solid var(--border);margin-top:var(--report-space-7);padding-top:var(--report-space-3);color:var(--dim);font-size:var(--report-type-xs);}
`
