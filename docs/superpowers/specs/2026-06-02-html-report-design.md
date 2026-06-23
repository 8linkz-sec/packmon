# HTML Scan Report (`--html`) — Design

**Date:** 2026-06-02
**Status:** Approved (brainstorming), ready for implementation plan
**Author:** Packmon

## Goal

Add a `--html <path>` output to `packmon scan` that renders the scan result as a
single, self-contained, visually appealing "mini report" HTML file. The report
is organised thematically (by finding type), mirrors the information shown in
the terminal output, and links each vulnerability / EOL finding to the source it
was derived from.

## Non-Goals

- No interactivity, no JavaScript, no charts/graphs.
- No external assets, fonts, or CDN dependencies (matches the project rule:
  "Web UI assets are served locally from the repo/binary; no CDN runtime deps").
- No new data in the canonical `domain.ScanResult` schema. The report is a pure
  rendering of the existing result.
- Not wired into `--list-packages` / `--outdated`; this is a scan **findings**
  report only.

## CLI Behaviour

- New flag: `packmon scan --html <path>`.
  - The flag name `--html` is used deliberately (user preference), even though
    the existing file outputs are `--output-json` / `--output-sarif` /
    `--output-junit`. Documented as an intentional exception.
- Subject to the **same single-target restriction** as the other file outputs:
  when more than one scan target is given, using `--html` is an error
  (extend the existing guard in `cmd/packmon/scan.go` that today covers
  `--output-json/-sarif/-junit`).
- Works identically in **local** and **remote** mode — it only renders the
  resulting `*domain.ScanResult`.
- **Zero findings:** a clean "all clear" report is still written (green summary +
  "No findings in N packages"). The file is always produced when `--html` is set.
- Path handling and logging mirror the SARIF/JUnit path exactly:
  - Use the existing `ensureOutputDir` helper before writing.
  - Write via `HTMLWriter.WriteFile(path, ...)` with `O_CREATE|O_TRUNC|O_WRONLY`,
    mode `0o600`, and the `#nosec G304` annotation already used by the SARIF
    writer (CLI output path is intentionally user-provided).
  - Do **not** log full absolute paths; surface errors to stderr like the other
    writers.

## Components

### `internal/scanner/html.go` — `HTMLWriter`

Mirrors the structure of `SARIFWriter` / `JUnitWriter` for consistency and
isolation:

```go
type HTMLWriter struct {
    toolVersion string
}

func NewHTMLWriter(toolVersion string) *HTMLWriter      // empty -> "dev"
func (hw *HTMLWriter) Write(w io.Writer, title string, failOn domain.Severity, result *domain.ScanResult) error
func (hw *HTMLWriter) WriteFile(path, title string, failOn domain.Severity, result *domain.ScanResult) error
```

- `title` is the report heading (repo name). The CLI passes the configured repo
  name when available (`scanTarget.Repo.Name`), otherwise the scan target's
  basename (`filepath.Base(path)`, already computed as `targetName` in
  `scan.go`). If both are empty, fall back to `"Packmon Security Report"`.
- Rendering uses Go's **`html/template`** so all dynamic values (package names,
  titles, sources, URLs) are auto-escaped. Untrusted-looking values such as a
  package name containing `<script>` must render inert.
- URLs are additionally validated before being emitted as `href`: only
  `http`/`https` schemes are linked; anything else is rendered as plain text.
- The entire stylesheet is inline in `<head>`. No `<script>`, no external
  `<link>`. The output is a single portable file.

### Wiring in `cmd/packmon/scan.go`

- Add `flagOutputHTML string` bound to `--html`.
- Add `OutputHTML string` to the flags struct and to `scanSettings`.
- Include `--html` in the multi-target guard alongside the other file outputs.
- After the scan, when `settings.OutputHTML != ""`: `ensureOutputDir`, then
  `NewHTMLWriter(version).WriteFile(settings.OutputHTML, title, failOn, result)`,
  with the same stderr and exit-code handling used for SARIF/JUnit.

## Report Structure (Terminal-Dark theme)

Visual direction approved: dark background, monospace, ANSI-style accent colours
(red = critical/high, yellow/amber = medium, cyan = low/EOL, blue = links),
subtle "glow" badges. It reads as a polished version of the terminal output.

**Typography (minimums agreed with user):**
- Body text: **14px** (hard minimum 12px).
- Section headings: **16px**.
- Main title (H1): **~22px**.
- Footer meta: 12px.

**Layout, top to bottom:**

1. **H1 — Repo name** (prominent title), followed by a dim meta line:
   `Packmon Security Report · <mode> mode · <N> packages · <scanned_at> · <duration>`.
2. **Summary badges** — counts by severity (Critical/High/Medium/Low) **and** by
   type (incl. EOL / Lifecycle), plus a "`<findings> findings · <blocking> blocking`"
   chip. Colours match the severity palette.
3. **Findings sections**, in this fixed order; a section is rendered **only when
   it has findings**:
   1. `!!` **Malicious** -- `FindingTypeMalicious`
   2. `!` **Supply-Chain / EOL** -- `FindingTypeSupplyChainRisk` (includes exact
      EOL findings carrying `risk_type=eol`)
   3. `*` **Vulnerabilities** -- `FindingTypeVulnerability`
   4. `~` **Lifecycle warnings** -- `FindingTypeLifecycle` (`eol_soon`,
      `security_support_only`)
   - Within each section, findings are sorted by severity (Critical → Low).
   - Each finding entry shows: severity badge, `name@version`, ecosystem,
     advisory ID / title, fixed version (when present), source name, and the
     **links block**: the primary source link (`Finding.URL`) **plus all
     `Finding.Resources`** as a small link list. EOL → endoflife.date product
     page; vulnerabilities → OSV/GHSA/NVD advisory.
4. **Footer meta line** (mirrors terminal extras): scan duration, local DB age +
   `DBStale` warning (local mode only), `feed_status` warning when degraded,
   packmon version, `scan_id` (small), and `manual_advisories_count` when > 0.

**Grouping is generic over `FindingType`.** The Lifecycle section only appears
once such findings exist, so the report works today (before the SBOM/EOL feature
lands) and is forward-compatible with the
`docs/superpowers/plans/2026-06-02-sbom-eol-import.md` plan that introduces
`FindingTypeLifecycle` and EOL-as-`supply_chain_risk`.

## Error Handling

- Output-directory or file-creation failures are written to stderr and do not
  panic; they follow the existing SARIF/JUnit pattern. If the scan would
  otherwise exit cleanly, the exit code becomes operational; an already non-OK
  scan exit code is preserved.
- `html/template` execution errors are wrapped (`fmt.Errorf("html: ...: %w")`)
  and returned from `Write`.
- Non-`http(s)` URLs degrade to plain text rather than being emitted as links.

## Testing

`internal/scanner/html_test.go`:
- Section presence and **fixed order** (Malicious → Supply-Chain/EOL →
  Vulnerabilities → Lifecycle); empty sections omitted.
- Severity sort within a section.
- Escaping: a finding with `Name` containing `<script>` renders escaped/inert.
- "All clear" report when `len(Findings) == 0` (still produced, green summary,
  "No findings in N packages").
- Links block renders the primary `URL` **and** every `Resources` entry; a
  finding with a non-http URL renders it as text, not a link.
- EOL (`supply_chain_risk` + `risk_type=eol`) lands in the Supply-Chain/EOL
  section; `lifecycle` findings land in the Lifecycle section.
- Title fallback: repo name → target basename → "Packmon Security Report".

`cmd/packmon` (scan flag wiring):
- `--html <path>` produces a file containing the repo title and a known finding.
- Multi-target guard rejects `--html` with more than one target.

## Documentation

- `DESIGN.md` — add `--html` to the output-formats section.
- `README.md` — document `packmon scan --html report.html .` with a one-line
  note on the thematic layout and source links.

## Acceptance Criteria

- `packmon scan --html out.html <target>` writes a single self-contained HTML
  file with no external/CDN assets and no JavaScript.
- The repo name appears as the H1 title; body text ≥ 14px, section headings 16px.
- Findings are grouped by type in the order Malicious → Supply-Chain/EOL →
  Vulnerabilities → Lifecycle, severity-sorted within each section, empty
  sections omitted.
- Every vulnerability and EOL finding shows a link to its source (primary URL +
  any resources).
- A scan with zero findings still produces a clean "all clear" report.
- `--html` is rejected for multi-target scans, consistent with the other file
  outputs.
- Dynamic values are HTML-escaped; non-http(s) URLs are not emitted as links.
