# List-All Technology Tags Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add report-only `angular` and `java` technology tags to `packmon scan --list-all`.

**Architecture:** Keep technology detection local to `cmd/packmon/list_all.go`. The normal scan result, API contracts, SARIF, JUnit, SBOM parsing, and domain models stay unchanged. `list-all` rows compute a display-only `Technology` string and render it in terminal and HTML package tables.

**Tech Stack:** Go, existing Packmon `list-all` report structs/templates, existing `cmd/packmon` tests, Markdown docs.

---

## File Structure

- Modify `cmd/packmon/list_all.go`
  - Add `Technology string` to `listAllRow` and `listAllHTMLPackageRow`.
  - Add a helper such as `listAllPackageTechnologies(p listAllPackage) string`.
  - Populate `Technology` in `buildListAllPackageReportWithOptions`.
  - Preserve `Technology` in `sanitizeListAllTerminalRow`.
  - Render the `TECHNOLOGY` terminal column.
  - Render the `Technology` HTML column in both `Packages Needing Attention` and `All Packages`.
- Modify `cmd/packmon/list_all_test.go`
  - Add failing tests for Angular and Java tag derivation.
  - Add failing terminal and HTML rendering assertions.
- Modify `README.md`
  - Document that list-all reports include a report-only `Technology` column for Angular and Java.
- Modify `DESIGN.md`
  - Document the same behavior as product architecture.

---

### Task 1: Add Failing Technology Derivation Tests

**Files:**
- Modify: `cmd/packmon/list_all_test.go`

- [ ] **Step 1: Add focused helper tests**

Add this test near the other list-all package report tests:

```go
func TestListAllPackageTechnologies(t *testing.T) {
	tests := []struct {
		name string
		pkg  listAllPackage
		want string
	}{
		{
			name: "angular scoped package",
			pkg:  listAllPackage{Name: "@angular/core", Version: "18.2.0", Ecosystem: domain.EcosystemNPM},
			want: "angular",
		},
		{
			name: "legacy angular package",
			pkg:  listAllPackage{Name: "angular", Version: "1.8.3", Ecosystem: domain.EcosystemNPM},
			want: "angular",
		},
		{
			name: "angular dash package",
			pkg:  listAllPackage{Name: "angular-material", Version: "1.2.5", Ecosystem: domain.EcosystemNPM},
			want: "angular",
		},
		{
			name: "non angular npm package has no generic js tag",
			pkg:  listAllPackage{Name: "react", Version: "19.0.0", Ecosystem: domain.EcosystemNPM},
			want: "-",
		},
		{
			name: "maven package is java",
			pkg:  listAllPackage{Name: "org.springframework:spring-core", Version: "6.2.0", Ecosystem: domain.EcosystemMaven},
			want: "java",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := listAllPackageTechnologies(tt.pkg); got != tt.want {
				t.Fatalf("listAllPackageTechnologies(%+v) = %q, want %q", tt.pkg, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the new test and verify it fails**

Run:

```powershell
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go test -count=1 ./cmd/packmon -run TestListAllPackageTechnologies
```

Expected: build failure because `listAllPackageTechnologies` is undefined.

---

### Task 2: Implement Technology Derivation and Row Population

**Files:**
- Modify: `cmd/packmon/list_all.go`

- [ ] **Step 1: Add row fields**

Update the structs:

```go
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
```

```go
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
```

- [ ] **Step 2: Populate `Technology` in report rows**

Inside `buildListAllPackageReportWithOptions`, when appending `listAllRow`, add:

```go
Technology: listAllPackageTechnologies(p),
```

The row literal should include the field between `Relation` and `Via`:

```go
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
```

- [ ] **Step 3: Add the helper**

Add this helper near other list-all row formatting helpers:

```go
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
```

This uses existing imports in `cmd/packmon/list_all.go`: `sort`, `strings`, and `domain` are already imported.

- [ ] **Step 4: Preserve the field in terminal sanitization**

Update `sanitizeListAllTerminalRow`:

```go
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
```

- [ ] **Step 5: Run the helper test and verify it passes**

Run:

```powershell
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go test -count=1 ./cmd/packmon -run TestListAllPackageTechnologies
```

Expected: PASS.

---

### Task 3: Render Technology in Terminal List-All Output

**Files:**
- Modify: `cmd/packmon/list_all.go`
- Modify: `cmd/packmon/list_all_test.go`

- [ ] **Step 1: Add a failing terminal rendering assertion**

Add or extend a focused terminal list-all output test:

```go
func TestPrintListAllPackageReportIncludesTechnologyColumn(t *testing.T) {
	report := listAllPackageReport{
		Rows: []listAllRow{
			{
				Name:       "@angular/core",
				Installed:  "18.2.0",
				Latest:     "18.2.0",
				Update:     "-",
				Ecosystem:  "npm",
				Source:     "lockfile",
				Scope:      "runtime",
				Relation:   "direct",
				Technology: "angular",
				Vuln:       "-",
				LockFile:   "package-lock.json",
			},
			{
				Name:       "org.springframework:spring-core",
				Installed:  "6.2.0",
				Latest:     "6.2.0",
				Update:     "-",
				Ecosystem:  "maven",
				Source:     "lockfile",
				Scope:      "runtime",
				Relation:   "direct",
				Technology: "java",
				Vuln:       "-",
				LockFile:   "pom.xml",
			},
		},
	}

	output := captureStdout(t, func() {
		printListAllPackageReport(report)
	})

	for _, want := range []string{"TECHNOLOGY", "angular", "java"} {
		if !strings.Contains(output, want) {
			t.Fatalf("terminal list-all output missing %q:\n%s", want, output)
		}
	}
}
```

- [ ] **Step 2: Run the terminal rendering test and verify it fails**

Run:

```powershell
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go test -count=1 ./cmd/packmon -run TestPrintListAllPackageReportIncludesTechnologyColumn
```

Expected: FAIL because `TECHNOLOGY` is not printed yet.

- [ ] **Step 3: Add the terminal column**

In `printListAllPackageReport`, add `maxTech` to width calculation:

```go
maxName, maxInst, maxLat, maxUpd, maxEco, maxSource, maxScope, maxRel, maxTech, maxVia, maxFlags, maxVuln := 7, 9, 6, 6, 9, 6, 5, 8, 10, 3, 5, 4
```

Include row widths:

```go
maxTech = maxInt(maxTech, len(r.Technology))
```

Update the format string to include one more column between relation and via:

```go
fmtStr := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
	maxName, gap, maxInst, gap, maxLat, gap, maxUpd, gap, maxEco, gap, maxSource, gap, maxScope, gap, maxRel, gap, maxTech, gap, maxVia, gap, maxFlags, gap, maxVuln, gap)
```

Update the header:

```go
fmt.Printf(fmtStr, "PACKAGE", "INSTALLED", "LATEST", "UPDATE", "ECOSYSTEM", "SOURCE", "SCOPE", "RELATION", "TECHNOLOGY", "VIA", "FLAGS", "VULNERABILITY", "SOURCE FILE")
```

Update each row:

```go
fmt.Printf(fmtStr, r.Name, r.Installed, r.Latest, r.Update, r.Ecosystem, r.Source, r.Scope, r.Relation, r.Technology, r.Via, r.Flags, r.Vuln, r.LockFile)
```

- [ ] **Step 4: Run the terminal rendering test and verify it passes**

Run:

```powershell
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go test -count=1 ./cmd/packmon -run TestPrintListAllPackageReportIncludesTechnologyColumn
```

Expected: PASS.

---

### Task 4: Render Technology in List-All HTML

**Files:**
- Modify: `cmd/packmon/list_all.go`
- Modify: `cmd/packmon/list_all_test.go`

- [ ] **Step 1: Add failing HTML assertions**

Add a focused HTML rendering test:

```go
func TestListAllHTMLIncludesTechnologyColumn(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{
			{
				Name:       "@angular/core",
				Installed:  "18.2.0",
				Latest:     "18.2.0",
				Update:     "-",
				Ecosystem:  "npm",
				Source:     "lockfile",
				Scope:      "runtime",
				Relation:   "direct",
				Technology: "angular",
				Vuln:       "-",
				LockFile:   "package-lock.json",
			},
			{
				Name:       "org.springframework:spring-core",
				Installed:  "6.2.0",
				Latest:     "6.2.0",
				Update:     "-",
				Ecosystem:  "maven",
				Source:     "lockfile",
				Scope:      "runtime",
				Relation:   "direct",
				Technology: "java",
				Vuln:       "-",
				LockFile:   "pom.xml",
			},
		},
	}

	result := &domain.ScanResult{Mode: "local"}
	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{">Technology<", ">angular<", ">java<"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML missing %q:\n%s", want, out)
		}
	}
}
```

- [ ] **Step 2: Run the HTML test and verify it fails**

Run:

```powershell
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go test -count=1 ./cmd/packmon -run TestListAllHTMLIncludesTechnologyColumn
```

Expected: FAIL because the HTML template does not render `Technology`.

- [ ] **Step 3: Copy `Technology` into HTML rows**

In `listAllHTMLPackageRows`, add:

```go
Technology: r.Technology,
```

Place it between `Relation` and `Via` in the `listAllHTMLPackageRow` literal.

- [ ] **Step 4: Update HTML template package tables**

In the `Packages Needing Attention` table header, insert:

```html
<th class="short">Technology</th>
```

between `Relation` and `Vulnerability`.

In the attention row template, insert:

```html
<td class="short">{{.Technology}}</td>
```

between `{{.Relation}}` and `{{.Vuln}}`.

Repeat the same header and row insertion for the `All Packages` table.

- [ ] **Step 5: Run the HTML test and verify it passes**

Run:

```powershell
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go test -count=1 ./cmd/packmon -run TestListAllHTMLIncludesTechnologyColumn
```

Expected: PASS.

---

### Task 5: Documentation Updates

**Files:**
- Modify: `README.md`
- Modify: `DESIGN.md`

- [ ] **Step 1: Update README**

In the "List-All Reports" section of `README.md`, update the package-table sentence to mention the report-only technology column:

```markdown
The package table includes each package's input source (`lockfile`, `sbom`,
`dockerfile`, or `compose`), scope, relation, report-only technology tags
(`angular` for Angular npm packages and `java` for Maven/Gradle rows), and
vulnerability marker.
```

- [ ] **Step 2: Update DESIGN**

In the `--list-all` CLI behavior section of `DESIGN.md`, update the package inventory description:

```markdown
Its package inventory section still lists every detected package by default and
annotates source (`lockfile`, `sbom`, `dockerfile`, `compose`), scope
(`runtime`, `dev`, `ci`, `sbom`, `build`), relation (`direct`,
`transitive`, `workflow`, etc.), report-only technology tags (`angular` for
Angular npm packages and `java` for Maven/Gradle rows), npm `via` roots, and
optional/peer flags.
```

- [ ] **Step 3: Run docs-sensitive tests**

Run:

```powershell
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go test -count=1 ./tests/ci
```

Expected: PASS.

---

### Task 6: Final Verification and Commit

**Files:**
- Verify all modified files.

- [ ] **Step 1: Format Go files**

Run:

```powershell
$files = git diff --name-only -- '*.go'
if ($files) { gofumpt -extra -w $files }
```

Expected: no command output and exit 0.

- [ ] **Step 2: Run focused package tests**

Run:

```powershell
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go test -count=1 ./cmd/packmon ./tests/ci
```

Expected: PASS.

- [ ] **Step 3: Run full local tests if time permits**

Run:

```powershell
$env:GOTMPDIR = (Resolve-Path .\.gotmp).Path
go test -count=1 ./...
```

Expected: PASS.

- [ ] **Step 4: Review diff**

Run:

```powershell
git diff --stat
git diff -- cmd/packmon/list_all.go cmd/packmon/list_all_test.go README.md DESIGN.md
```

Expected: only list-all technology tag code/tests and documentation changes.

- [ ] **Step 5: Commit implementation**

Run:

```powershell
git add cmd/packmon/list_all.go cmd/packmon/list_all_test.go README.md DESIGN.md
$env:PATH = (Resolve-Path .\.build).Path + ';' + $env:PATH
git commit -m "Add list-all technology tags"
```

Expected: commit succeeds. If the Packmon hook warns that the remote server is unreachable and scans against the local database, keep the warning in the final status; do not bypass the hook.

---

## Self-Review

- Spec coverage:
  - Angular npm matching is covered by Task 1.
  - Maven/Gradle-to-Java tagging is covered by Task 1 because Gradle rows use ecosystem `maven`.
  - Terminal and HTML `Technology` rendering is covered by Tasks 3 and 4.
  - No ScanResult/API/SARIF/JUnit/domain changes are included.
  - No `tomcat`, `gpt`, generic `js`, source-code scanning, host inventory, severity, or blocking changes are included.
- Placeholder scan:
  - No `TBD`, `TODO`, or open-ended implementation steps remain.
- Type consistency:
  - The plan consistently uses `Technology string`, `listAllPackageTechnologies`, `listAllRow`, and `listAllHTMLPackageRow`.
