# SBOM And EOL Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SBOM package import and end-of-life lifecycle checks without relying on paid or API-key-required services.

**Architecture:** Treat SBOMs as another local package inventory source and keep vulnerability/EOL decisions in Packmon's normal scan pipeline. Sync endoflife.date data server-side into Packmon's database, export it to local SQLite, and return lifecycle findings through the existing canonical scan result shape.

**Tech Stack:** Go, Cobra CLI, PostgreSQL migrations, SQLite sync, CycloneDX JSON/XML, SPDX JSON, package-url parsing, endoflife.date API v1, existing Packmon feed manager and scanner.

---

## Design Decisions

- SBOM import is inventory input only. A SBOM may contain vulnerability data, but Packmon will not trust it as the primary source of truth in this feature.
- The CLI must support explicit SBOM files via `--sbom <path>`. Auto-discovery can be added later after explicit import is stable.
- SBOM packages are merged with lockfile packages and deduplicated by ecosystem, name, and version.
- Components without a usable version are skipped for vulnerability checks and reported in debug/log output only. The existing checker requires a version to match affected ranges safely.
- PURL is the preferred identity for SBOM packages. Package names without PURLs are imported only when an ecosystem-specific mapping is unambiguous.
- endoflife.date is used as a server-side feed, not as a live per-CLI-run lookup.
- endoflife.date API usage must be best-effort: follow redirects, use ETag/If-None-Match, respect `429`, and never fail scans because the upstream API is unavailable.
- Exact EOL/unsupported matches are represented as `supply_chain_risk` with `risk_type=eol` so they block by existing Packmon rules.
- Non-EOL lifecycle warnings, such as "EOL soon" or "active support ended but security support remains", use a new `lifecycle` finding type with severity-based blocking.
- Lifecycle coverage is intentionally limited to products and release cycles that can be mapped confidently from PURL or a curated mapping. Unknown lifecycle status must not be guessed.

## Source API

Use endoflife.date API v1:

- Base: `https://endoflife.date/api/v1`
- Main sync endpoint: `GET /products/full`
- Fallback/detail endpoint: `GET /products/{product}`
- Optional targeted endpoint: `GET /products/{product}/releases/{release}`
- Response envelope: `schema_version`, `generated_at`, optional `total`, and `result`.
- Full product entries include `identifiers[]` with `{type, id}` and `releases[]`.
- Release entries use the documented v1 names: `name`, `releaseDate`, `isLts`,
  `ltsFrom`, `isEoas`, `eoasFrom`, `isEol`, `eolFrom`,
  `isDiscontinued`, `discontinuedFrom`, `isEoes`, `eoesFrom`,
  `isMaintained`, and `latest`.

Operational behavior:

- No API key.
- No paid service dependency.
- Follow `301`.
- Treat `304` as no-op success using cached data.
- Treat `404` for a product/cycle as unsupported/unknown.
- Treat `429`, `502`, and `503` as feed-degraded and keep existing cached data.

## File Structure

### New Files

- `internal/sbom/sbom.go`
  Defines SBOM format detection, parse entry points, and canonical SBOM package output.
- `internal/sbom/purl.go`
  Parses package URLs and maps PURL coordinates into Packmon `domain.Package`.
- `internal/sbom/cyclonedx.go`
  Parses CycloneDX JSON and XML components.
- `internal/sbom/spdx.go`
  Parses SPDX JSON packages and PURL external references.
- `internal/sbom/*_test.go`
  Unit tests for PURL, CycloneDX, SPDX, and edge cases.
- `internal/scanner/package_collector.go`
  Shared lockfile plus SBOM package collection used by scan, list, list-all, and outdated.
- `internal/lifecycle/models.go`
  Lifecycle status enums, product/release structs, and finding construction helpers.
- `internal/lifecycle/mapping.go`
  Maps package coordinates/PURLs to endoflife.date product slugs and release cycles.
- `internal/lifecycle/mapping_test.go`
  Mapping tests for PURL identifiers and curated fallbacks.
- `internal/feed/endoflife/client.go`
  HTTP client for endoflife.date API v1.
- `internal/feed/endoflife/syncer.go`
  Feed syncer that downloads lifecycle products/releases and stores normalized rows.
- `internal/feed/endoflife/syncer_test.go`
  Client and syncer tests with `httptest.Server`.
- `internal/db/postgres/lifecycle.go`
  PostgreSQL lifecycle upsert/query/export implementation.
- `internal/db/postgres/lifecycle_test.go`
  Unit tests for lifecycle finding construction and query helpers.
- `internal/db/sqlite/lifecycle.go`
  SQLite local lifecycle finding lookup.
- `internal/db/sqlite/lifecycle_test.go`
  SQLite local lifecycle sync/query tests.
- `internal/db/postgres/migrations/007_lifecycle.up.sql`
  PostgreSQL lifecycle schema.
- `internal/db/postgres/migrations/007_lifecycle.down.sql`
  Rollback for lifecycle schema.

### Modified Files

- `internal/domain/models.go`
  Add `FindingTypeLifecycle`.
- `internal/domain/scan.go`
  No required schema break. Keep lifecycle as normal findings.
- `internal/db/db.go`
  Add lifecycle store methods and transfer structs.
- `internal/db/sync.go`
  Add lifecycle rows to local sync export.
- `internal/db/postgres/sync.go`
  Export lifecycle rows.
- `internal/db/sqlite/schema.go`
  Add local lifecycle table and migration.
- `internal/db/sqlite/sync.go`
  Import lifecycle rows from server sync.
- `internal/scanner/scanner.go`
  Use shared package collector and include lifecycle checks in local mode.
- `internal/api/v1/handler.go`
  Include lifecycle findings in `POST /api/v1/check`.
- `internal/api/v1/handler_test.go`
  Add lifecycle check tests.
- `internal/scanner/table.go`
  Render lifecycle findings clearly.
- `internal/scanner/junit.go`
  Include lifecycle details.
- `internal/scanner/sarif.go`
  Include lifecycle details and help URI.
- `cmd/packmon/scan.go`
  Add `--sbom` CLI flag and pass SBOM files to scanner config.
- `cmd/packmon/list_all.go`
  Include SBOM packages in the full package list.
- `cmd/packmon/outdated.go`
  Include SBOM packages in outdated checks.
- `cmd/packmon-server/background.go`
  Register the endoflife.date feed syncer.
- `cmd/packmon-server/background_test.go`
  Assert feed registration and config behavior.
- `internal/config/config.go`
  Add endoflife feed config and env vars.
- `internal/config/feed_settings.go`
  Show endoflife.date in admin feed settings.
- `internal/config/*_test.go`
  Config default/env/admin tests.
- `api/openapi/*.yaml`
  Document `lifecycle` finding type and sync payload changes if the API spec currently enumerates finding types.
- `DESIGN.md`
  Document SBOM input and lifecycle feed behavior.
- `SECURITY.md`
  Document endoflife.date feed trust boundary and rate-limit behavior.
- `README.md`
  Document `--sbom` and lifecycle/EOL coverage.

---

## Task 1: SBOM PURL Mapping Foundation

**Files:**
- Create: `internal/sbom/sbom.go`
- Create: `internal/sbom/purl.go`
- Create: `internal/sbom/purl_test.go`

- [ ] **Step 1: Write failing PURL mapping tests**

Add tests covering every Packmon ecosystem that can be represented by PURL.

```go
func TestPackageFromPURL(t *testing.T) {
	tests := []struct {
		purl string
		want domain.Package
		ok   bool
	}{
		{"pkg:npm/%40scope/name@1.2.3", domain.Package{Name: "@scope/name", Version: "1.2.3", Ecosystem: domain.EcosystemNPM}, true},
		{"pkg:pypi/Django@4.2.11", domain.Package{Name: "Django", Version: "4.2.11", Ecosystem: domain.EcosystemPyPI}, true},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", domain.Package{Name: "org.apache.logging.log4j:log4j-core", Version: "2.17.1", Ecosystem: domain.EcosystemMaven}, true},
		{"pkg:golang/github.com/gin-gonic/gin@v1.9.1", domain.Package{Name: "github.com/gin-gonic/gin", Version: "v1.9.1", Ecosystem: domain.EcosystemGo}, true},
		{"pkg:cargo/serde@1.0.0", domain.Package{Name: "serde", Version: "1.0.0", Ecosystem: domain.EcosystemCargo}, true},
		{"pkg:nuget/Newtonsoft.Json@13.0.3", domain.Package{Name: "Newtonsoft.Json", Version: "13.0.3", Ecosystem: domain.EcosystemNuGet}, true},
		{"pkg:composer/laravel/framework@10.48.0", domain.Package{Name: "laravel/framework", Version: "10.48.0", Ecosystem: domain.EcosystemComposer}, true},
		{"pkg:gem/rails@7.1.3", domain.Package{Name: "rails", Version: "7.1.3", Ecosystem: domain.EcosystemGem}, true},
		{"pkg:pub/http@1.2.1", domain.Package{Name: "http", Version: "1.2.1", Ecosystem: domain.EcosystemPub}, true},
		{"pkg:cocoapods/AFNetworking@4.0.1", domain.Package{Name: "AFNetworking", Version: "4.0.1", Ecosystem: domain.EcosystemCocoaPods}, true},
		{"pkg:swift/github.com/apple/swift-nio@2.66.0", domain.Package{Name: "github.com/apple/swift-nio", Version: "2.66.0", Ecosystem: domain.EcosystemSwiftPM}, true},
		{"pkg:hex/plug@1.15.0", domain.Package{Name: "plug", Version: "1.15.0", Ecosystem: domain.EcosystemHex}, true},
		{"pkg:cran/dplyr@1.1.4", domain.Package{Name: "dplyr", Version: "1.1.4", Ecosystem: domain.EcosystemCRAN}, true},
		{"pkg:deb/debian/curl@7.88.1", domain.Package{}, false},
		{"not-a-purl", domain.Package{}, false},
		{"pkg:npm/lodash", domain.Package{}, false},
	}
	for _, tt := range tests {
		got, ok := PackageFromPURL(tt.purl)
		if ok != tt.ok || got != tt.want {
			t.Fatalf("PackageFromPURL(%q) = %+v, %v; want %+v, %v", tt.purl, got, ok, tt.want, tt.ok)
		}
	}
}
```

- [ ] **Step 2: Run the failing test**

Run:

```powershell
go test -count=1 .\internal\sbom
```

Expected: package does not compile because `internal/sbom` and `PackageFromPURL` do not exist.

- [ ] **Step 3: Implement minimal SBOM and PURL foundation**

Define:

```go
package sbom

import "github.com/8linkz/packmon/internal/domain"

type Package struct {
	Package domain.Package
	PURL    string
	Source  string
}

type ParseResult struct {
	Packages []Package
	Skipped  []SkippedComponent
}

type SkippedComponent struct {
	Name   string
	Reason string
}

func PackageFromPURL(raw string) (domain.Package, bool)
```

Implementation requirements:

- Trim spaces.
- Require `pkg:` prefix.
- Require a non-empty version after `@`.
- Decode percent escapes in namespace/name.
- Map unsupported PURL types to `false`.
- For Maven, compose `namespace:name`.
- For Composer, compose `namespace/name`.
- For SwiftPM, preserve repository-like namespace/name as package name.

- [ ] **Step 4: Run tests**

Run:

```powershell
go test -count=1 .\internal\sbom
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal\sbom\sbom.go internal\sbom\purl.go internal\sbom\purl_test.go
git commit -m "feat: add SBOM PURL package mapping"
```

---

## Task 2: CycloneDX JSON/XML Import

**Files:**
- Create: `internal/sbom/cyclonedx.go`
- Create: `internal/sbom/cyclonedx_test.go`

- [ ] **Step 1: Write failing CycloneDX tests**

Test JSON and XML component parsing with PURL-first identity.

```go
func TestParseCycloneDXJSONPackages(t *testing.T) {
	input := []byte(`{
		"bomFormat":"CycloneDX",
		"specVersion":"1.5",
		"components":[
			{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"},
			{"type":"library","name":"django","version":"4.2.11","purl":"pkg:pypi/django@4.2.11"},
			{"type":"file","name":"README.md","version":"1.0.0"},
			{"type":"library","name":"noversion","purl":"pkg:npm/noversion"}
		]
	}`)
	got, err := ParseCycloneDX(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCycloneDX() error = %v", err)
	}
	want := []domain.Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: domain.EcosystemNPM},
		{Name: "django", Version: "4.2.11", Ecosystem: domain.EcosystemPyPI},
	}
	if !reflect.DeepEqual(domainPackages(got.Packages), want) {
		t.Fatalf("packages = %+v, want %+v", domainPackages(got.Packages), want)
	}
	if len(got.Skipped) != 2 {
		t.Fatalf("skipped = %d, want 2", len(got.Skipped))
	}
}
```

- [ ] **Step 2: Run failing tests**

```powershell
go test -count=1 .\internal\sbom
```

Expected: FAIL because `ParseCycloneDX` is missing.

- [ ] **Step 3: Implement CycloneDX parsing**

Implement:

```go
func ParseCycloneDX(r io.Reader) (*ParseResult, error)
func IsCycloneDXJSON(data []byte) bool
func IsCycloneDXXML(data []byte) bool
```

Implementation requirements:

- Limit reads to 100 MB.
- Support JSON `bomFormat == "CycloneDX"`.
- Support XML root `<bom>`.
- Only import component types `library`, `framework`, `application`, and empty type.
- Prefer `component.purl`.
- Fall back to `name` plus `version` only for unambiguous ecosystems is not allowed in this task; no PURL means skip.
- Preserve skipped reasons for diagnostics.

- [ ] **Step 4: Run tests**

```powershell
go test -count=1 .\internal\sbom
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal\sbom\cyclonedx.go internal\sbom\cyclonedx_test.go
git commit -m "feat: parse CycloneDX SBOM packages"
```

---

## Task 3: SPDX JSON Import

**Files:**
- Create: `internal/sbom/spdx.go`
- Create: `internal/sbom/spdx_test.go`

- [ ] **Step 1: Write failing SPDX tests**

```go
func TestParseSPDXJSONPackages(t *testing.T) {
	input := []byte(`{
		"spdxVersion":"SPDX-2.3",
		"packages":[
			{
				"name":"lodash",
				"versionInfo":"4.17.21",
				"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.21"}]
			},
			{
				"name":"no-purl",
				"versionInfo":"1.0.0",
				"externalRefs":[]
			}
		]
	}`)
	got, err := ParseSPDXJSON(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSPDXJSON() error = %v", err)
	}
	pkgs := domainPackages(got.Packages)
	if len(pkgs) != 1 || pkgs[0].Name != "lodash" || pkgs[0].Version != "4.17.21" || pkgs[0].Ecosystem != domain.EcosystemNPM {
		t.Fatalf("packages = %+v, want lodash npm", pkgs)
	}
	if len(got.Skipped) != 1 {
		t.Fatalf("skipped = %d, want 1", len(got.Skipped))
	}
}
```

- [ ] **Step 2: Run failing tests**

```powershell
go test -count=1 .\internal\sbom
```

Expected: FAIL because `ParseSPDXJSON` is missing.

- [ ] **Step 3: Implement SPDX JSON parsing**

Implement:

```go
func ParseSPDXJSON(r io.Reader) (*ParseResult, error)
func IsSPDXJSON(data []byte) bool
```

Implementation requirements:

- Limit reads to 100 MB.
- Require `spdxVersion` prefix `SPDX-`.
- Iterate `packages`.
- Use `externalRefs[].referenceType == "purl"` case-insensitively.
- Use PURL version as source of truth. Do not combine SPDX `versionInfo` with a versionless PURL.
- Skip `NOASSERTION`, `NONE`, empty names, and missing PURLs.

- [ ] **Step 4: Run tests**

```powershell
go test -count=1 .\internal\sbom
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal\sbom\spdx.go internal\sbom\spdx_test.go
git commit -m "feat: parse SPDX SBOM packages"
```

---

## Task 4: Shared Package Collection With SBOM Files

**Files:**
- Create: `internal/scanner/package_collector.go`
- Create: `internal/scanner/package_collector_test.go`
- Modify: `internal/scanner/scanner.go`
- Modify: `cmd/packmon/scan.go`
- Modify: `cmd/packmon/list_all.go`
- Modify: `cmd/packmon/outdated.go`

- [ ] **Step 1: Write failing collector tests**

Cover lockfile plus SBOM merge and deduplication.

```go
func TestCollectPackagesIncludesExplicitSBOM(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion":3,
		"packages":{"node_modules/lodash":{"version":"4.17.21"}}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sbomPath := filepath.Join(dir, "bom.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{
		"bomFormat":"CycloneDX",
		"components":[{"type":"library","name":"django","version":"4.2.11","purl":"pkg:pypi/django@4.2.11"}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := CollectPackages(CollectConfig{
		Registry: parser.NewRegistry(),
		Root: dir,
		MaxDepth: 2,
		SBOMFiles: []string{sbomPath},
	})
	if err != nil {
		t.Fatalf("CollectPackages() error = %v", err)
	}
	if got.LockFiles != 1 || got.SBOMFiles != 1 {
		t.Fatalf("sources lock=%d sbom=%d, want 1/1", got.LockFiles, got.SBOMFiles)
	}
	if len(got.Packages) != 2 {
		t.Fatalf("packages = %+v, want 2", got.Packages)
	}
}
```

- [ ] **Step 2: Run failing collector test**

```powershell
go test -count=1 .\internal\scanner -run TestCollectPackages
```

Expected: FAIL because collector does not exist.

- [ ] **Step 3: Implement collector**

Define:

```go
type CollectConfig struct {
	Registry   *parser.Registry
	Root       string
	MaxDepth   int
	Ecosystems []string
	SBOMFiles  []string
	IncludeDev bool
}

type PackageCollection struct {
	Packages    []domain.Package
	ParseErrors []string
	LockFiles   int
	SBOMFiles    int
}

func CollectPackages(cfg CollectConfig) (*PackageCollection, error)
```

Implementation requirements:

- Resolve `Root` and each SBOM path to absolute paths.
- Use existing `Walker` for lockfiles.
- Parse SBOM files through `sbom.Parse`.
- Apply ecosystem filter to both lockfile packages and SBOM packages.
- Deduplicate with existing name/version/ecosystem semantics.
- Apply `IncludeDev` after deduplication.
- Return partial results plus parse errors for malformed files.

- [ ] **Step 4: Refactor scanner to use collector**

Replace the local walk/parse block in `Scanner.Run` with `CollectPackages`.

Behavior must remain:

- No lockfiles and no SBOM packages returns clean result.
- All parse errors with zero packages returns exit code 4.
- Partial parse errors with findings keep normal finding exit code.
- `PackagesScanned` counts merged packages.

- [ ] **Step 5: Add CLI `--sbom` flag**

Add a repeatable flag to `packmon scan`:

```go
f.StringArrayVar(&flagSBOMFiles, "sbom", nil, "SBOM file to include as package input (CycloneDX JSON/XML or SPDX JSON); can be repeated")
```

Pass it through `scanSettings` into `scanner.Config.SBOMFiles`.

- [ ] **Step 6: Include SBOM packages in list-all and outdated**

Refactor `collectAllPackages` and `runOutdated` to call `scanner.CollectPackages` instead of independently walking/parsing lockfiles.

- [ ] **Step 7: Run targeted tests**

```powershell
go test -count=1 .\internal\scanner .\cmd\packmon
```

Expected: PASS.

- [ ] **Step 8: Commit**

```powershell
git add internal\scanner\package_collector.go internal\scanner\package_collector_test.go internal\scanner\scanner.go cmd\packmon\scan.go cmd\packmon\list_all.go cmd\packmon\outdated.go
git commit -m "feat: include SBOM packages in scans"
```

---

## Task 5: Lifecycle Finding Model And Output

**Files:**
- Modify: `internal/domain/models.go`
- Modify: `internal/scanner/table.go`
- Modify: `internal/scanner/junit.go`
- Modify: `internal/scanner/sarif.go`
- Modify: `internal/api/v1/handler.go`
- Modify: `internal/api/v1/handler_test.go`
- Modify: `internal/scanner/scanner_test.go`

- [ ] **Step 1: Write failing finding-type tests**

Add tests that assert the new finding type is summarized and severity-gated.
The `isBlocking` test belongs in `internal/api/v1/handler_test.go` because
`isBlocking` is unexported in package `v1`. Do not change `isBlocking` except
to keep lifecycle flowing through the existing severity-threshold path.

```go
func TestLifecycleFindingSummaryAndBlocking(t *testing.T) {
	findings := []domain.Finding{{
		Name: "django", Version: "3.2.25", Ecosystem: domain.EcosystemPyPI,
		Type: domain.FindingTypeLifecycle, Severity: domain.SeverityMedium,
		AdvisoryID: "eol:django:3.2", Title: "Django 3.2 reaches EOL soon",
		RiskType: "eol_soon", Source: "endoflife.date",
	}}
	if !isBlocking(findings, domain.SeverityMedium) {
		t.Fatal("MEDIUM lifecycle finding should block at MEDIUM threshold")
	}
	if isBlocking(findings, domain.SeverityHigh) {
		t.Fatal("MEDIUM lifecycle finding should not block at HIGH threshold")
	}
}
```

In `internal/scanner/scanner_test.go`, add a test in package `scanner` that
asserts `isAlwaysBlockingFinding` returns false for `FindingTypeLifecycle` and
true for `FindingTypeSupplyChainRisk` with `risk_type=eol`.

- [ ] **Step 2: Run failing tests**

```powershell
go test -count=1 .\internal\domain .\internal\scanner .\internal\api\v1
```

Expected: FAIL because `FindingTypeLifecycle` is missing.

- [ ] **Step 3: Add lifecycle finding type**

Add:

```go
FindingTypeLifecycle FindingType = "lifecycle"
```

Render labels:

- table type label: `LIFECYCLE`
- SARIF rule id: finding advisory ID when present, otherwise `lifecycle:<ecosystem>:<name>`
- JUnit failure body includes `Risk Type: <risk_type>` and `Source: endoflife.date`

- [ ] **Step 4: Keep EOL blocking explicit**

Do not change existing always-blocking behavior for malware and supply-chain risk.

Policy:

- `supply_chain_risk` with `risk_type=eol` always blocks.
- `lifecycle` blocks only through severity threshold.
- `NONE` disables severity-threshold blocking but still does not disable `supply_chain_risk`.
- Security-support-only lifecycle findings use `risk_type=security_support_only`
  and severity `LOW`; do not encode them as `HIGH` in tests.

- [ ] **Step 5: Run tests**

```powershell
go test -count=1 .\internal\domain .\internal\scanner .\internal\api\v1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add internal\domain\models.go internal\scanner\table.go internal\scanner\junit.go internal\scanner\sarif.go internal\api\v1\handler.go
git commit -m "feat: add lifecycle finding type"
```

---

## Task 6: Lifecycle Database Schema And Store Methods

**Files:**
- Create: `internal/db/postgres/migrations/007_lifecycle.up.sql`
- Create: `internal/db/postgres/migrations/007_lifecycle.down.sql`
- Create: `internal/db/postgres/lifecycle.go`
- Create: `internal/db/postgres/lifecycle_test.go`
- Modify: `internal/db/db.go`
- Modify: `internal/db/postgres/migrations/migrator.go`
- Modify: `internal/db/postgres/migrations/migrator_test.go`
- Modify: `internal/api/v1/handler_test.go`

- [ ] **Step 1: Write migration tests**

Add expectations that migration version advances to 7 and lifecycle tables exist after migration.
Update `internal/db/postgres/migrations/migrator.go` so
`ExpectedVersion = 7`; otherwise `TestExpectedVersionMatchesHighestEmbeddedMigration`
will fail as soon as `007_lifecycle.*.sql` is embedded.

Expected tables:

```sql
lifecycle_products
lifecycle_releases
lifecycle_package_map
```

- [ ] **Step 2: Create lifecycle migration**

Schema:

```sql
CREATE TABLE lifecycle_products (
    product_slug TEXT PRIMARY KEY,
    -- Display label from endoflife.date result[].label; the API slug lives in product_slug.
    name TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'endoflife.date',
    identifiers JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE lifecycle_releases (
    product_slug TEXT NOT NULL REFERENCES lifecycle_products(product_slug) ON DELETE CASCADE,
    cycle TEXT NOT NULL,
    latest TEXT NOT NULL DEFAULT '',
    release_date DATE,
    is_lts BOOLEAN NOT NULL DEFAULT false,
    lts_from DATE,
    is_eoas BOOLEAN NOT NULL DEFAULT false,
    eoas_from DATE,
    is_eol BOOLEAN NOT NULL DEFAULT false,
    eol_from DATE,
    is_discontinued BOOLEAN NOT NULL DEFAULT false,
    discontinued_from DATE,
    is_eoes BOOLEAN,
    eoes_from DATE,
    is_maintained BOOLEAN NOT NULL DEFAULT false,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (product_slug, cycle)
);

CREATE TABLE lifecycle_package_map (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    product_slug TEXT NOT NULL REFERENCES lifecycle_products(product_slug) ON DELETE CASCADE,
    purl_type TEXT NOT NULL DEFAULT '',
    purl_namespace TEXT NOT NULL DEFAULT '',
    purl_name TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'endoflife.date',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (ecosystem, name, product_slug)
);

CREATE INDEX lifecycle_package_map_lookup_idx ON lifecycle_package_map(ecosystem, name);
```

- [ ] **Step 3: Add DB transfer types and methods**

In `internal/db/db.go`, add:

```go
type LifecycleProduct struct {
	ProductSlug string
	Name        string
	Category    string
	Identifiers json.RawMessage
	Raw         json.RawMessage
	Releases    []LifecycleRelease
	PackageMaps []LifecyclePackageMap
}

type LifecycleRelease struct {
	ProductSlug      string
	Cycle            string
	Latest           string
	ReleaseDate      *time.Time
	IsLTS            bool
	LTSFrom          *time.Time
	IsEOAS           bool
	EOASFrom         *time.Time
	IsEOL            bool
	EOLFrom          *time.Time
	IsDiscontinued   bool
	DiscontinuedFrom *time.Time
	IsEOES           *bool
	EOESFrom         *time.Time
	IsMaintained     bool
	Raw              json.RawMessage
}

type LifecyclePackageMap struct {
	Ecosystem     string
	Name          string
	ProductSlug   string
	PURLType      string
	PURLNamespace string
	PURLName      string
	Source        string
}
```

Store methods:

```go
UpsertLifecycleProducts(ctx context.Context, products []LifecycleProduct) error
FindLifecycleFindingsBatch(ctx context.Context, packages []PackageQuery, now time.Time) ([]domain.Finding, error)
```

Updating `db.Store` means concrete non-embedding test fakes must compile in
the same task. At minimum update `internal/api/v1/handler_test.go`'s
`stubStore` with `UpsertLifecycleProducts` and `FindLifecycleFindingsBatch`.
Most other feed/admin test fakes embed `db.Store` and continue compiling.

- [ ] **Step 4: Implement PostgreSQL upsert and query**

Finding construction rules:

- Find package maps by ecosystem/name.
- Select release cycle with longest prefix match against package version:
  - release cycle `4.2` matches package versions `4.2`, `4.2.0`, `4.2.11`.
  - release cycle `18` matches `18.0.0` and `18.19.1`.
  - if multiple cycles match, longest cycle wins.
- If `is_eol` is true or `eol_from <= now`, return `domain.FindingTypeSupplyChainRisk`, `risk_type=eol`, severity `CRITICAL`.
- If `eol_from` is within 90 days, return `domain.FindingTypeLifecycle`, `risk_type=eol_soon`, severity `MEDIUM`.
- If `is_eoas` is true or `eoas_from <= now`, and the release is not EOL, return `domain.FindingTypeLifecycle`, `risk_type=security_support_only`, severity `LOW`.
- Date comparisons must guard nil dates: a missing `eol_from` or `eoas_from`
  must not panic and must not produce a date-based finding by itself.
- If no cycle matches, return no finding.

- [ ] **Step 5: Run tests**

```powershell
go test -count=1 .\internal\db\postgres .\internal\db\postgres\migrations
```

Expected: PASS. Docker-backed migration tests may require Docker.

- [ ] **Step 6: Commit**

```powershell
git add internal\db\db.go internal\db\postgres\lifecycle.go internal\db\postgres\lifecycle_test.go internal\db\postgres\migrations\007_lifecycle.up.sql internal\db\postgres\migrations\007_lifecycle.down.sql internal\db\postgres\migrations\migrator.go internal\db\postgres\migrations\migrator_test.go internal\api\v1\handler_test.go
git commit -m "feat: store lifecycle release data"
```

---

## Task 7: endoflife.date Feed Syncer

**Files:**
- Create: `internal/feed/endoflife/client.go`
- Create: `internal/feed/endoflife/syncer.go`
- Create: `internal/feed/endoflife/syncer_test.go`
- Modify: `cmd/packmon-server/background.go`
- Modify: `cmd/packmon-server/background_test.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/feed_settings.go`
- Modify: `internal/config/*_test.go`

- [ ] **Step 1: Confirm current API contract and write failing client/syncer tests**

Before writing the syncer, confirm the current v1 OpenAPI and one live response:

```powershell
Invoke-WebRequest -UseBasicParsing -Uri 'https://endoflife.date/docs/api/v1/openapi.yml'
Invoke-RestMethod -Uri 'https://endoflife.date/api/v1/products/full' | Select-Object -Property schema_version,total
```

Expected contract:

- `/products/full` returns `schema_version`, `generated_at`, `total`, and
  `result[]`.
- `result[].identifiers[]` uses `{ "type": "purl", "id": "pkg:..." }`.
- `result[].releases[]` uses `name`, `releaseDate`, `isEoas`, `eoasFrom`,
  `isEol`, `eolFrom`, `isMaintained`, and `latest`.

Then write tests for:

- `GET /api/v1/products/full` is called.
- `If-None-Match` is sent when previous ETag exists in feed metadata.
- `304` records success with zero changes.
- `429` records failure/degraded state and does not delete cached rows.
- product identifiers with PURLs create lifecycle package maps.

- [ ] **Step 2: Implement client**

Client API:

```go
type Client struct {
	BaseURL string
	HTTPClient *http.Client
}

func (c *Client) FetchProductsFull(ctx context.Context, etag string) (ProductsResponse, string, bool, error)
```

`bool` means not-modified.

Requirements:

- Default base URL `https://endoflife.date/api/v1`.
- Timeout from injected client; default 30 seconds.
- `Accept: application/json`.
- `User-Agent: packmon-server/dev`.
- Preserve response ETag.
- Limit response body to 100 MB.

- [ ] **Step 3: Implement syncer**

Syncer:

```go
const FeedName = "endoflife"

func NewSyncer(logger *slog.Logger, opts ...Option) *Syncer
func (s *Syncer) Name() string
func (s *Syncer) Sync(ctx context.Context, store db.Store) (*feed.SyncResult, error)
```

Mapping:

- Parse `schema_version`, `generated_at`, `total`, and `result[]`.
- Parse product slug from `result[].name`, display name from `result[].label`,
  category, identifiers, and releases.
- Parse releases from current v1 fields: `name`, `releaseDate`, `isLts`,
  `ltsFrom`, `isEoas`, `eoasFrom`, `isEol`, `eolFrom`,
  `isDiscontinued`, `discontinuedFrom`, `isEoes`, `eoesFrom`,
  `isMaintained`, and `latest.name`.
- Build package maps from product identifiers where identifier type is `purl`
  and value is stored in `id`.
- Use `sbom.PackageFromPURL` for ecosystem/name extraction.
- Also support curated maps in `internal/lifecycle/mapping.go` for known products whose endoflife.date record lacks PURL identifiers.

- [ ] **Step 4: Add config**

Add fields:

```go
EndOfLifeEnabled bool
EndOfLifeMode FeedMode
EndOfLifeInterval time.Duration
EndOfLifeBaseURL string
```

Defaults:

- `PACKMON_FEED_ENDOFLIFE_ENABLED=true`
- `PACKMON_FEED_ENDOFLIFE_MODE=self`
- `PACKMON_ENDOFLIFE_API_BASE_URL=https://endoflife.date/api/v1`
- default interval inherits `PACKMON_FEED_SYNC_INTERVAL`

Use the existing env naming convention: generic feed knobs keep the
`PACKMON_FEED_<NAME>_*` prefix, while feed-specific API URLs use
`PACKMON_<NAME>_API_BASE_URL`, matching `PACKMON_REVERSINGLABS_API_BASE_URL`.

Reject external mode only if no import endpoint is implemented. If external mode is allowed, add an import endpoint in a later task before exposing it in admin UI.

- [ ] **Step 5: Register feed syncer**

In `cmd/packmon-server/background.go`:

```go
registerFeedSyncer(manager, cfg, "endoflife", newFeedSyncer("endoflife", cfg, store, logger))
```

Add case:

```go
case "endoflife":
	return endoflife.NewSyncer(logger, endoflife.WithBaseURL(cfg.Feeds.EndOfLifeBaseURL))
```

- [ ] **Step 6: Run tests**

```powershell
go test -count=1 .\internal\feed\endoflife .\internal\config .\cmd\packmon-server
```

Expected: PASS.

- [ ] **Step 7: Commit**

```powershell
git add internal\feed\endoflife cmd\packmon-server\background.go cmd\packmon-server\background_test.go internal\config\config.go internal\config\feed_settings.go internal\config\*_test.go
git commit -m "feat: sync endoflife lifecycle feed"
```

---

## Task 8: Lifecycle Findings In API, Remote Scan, And Local SQLite

**Files:**
- Modify: `internal/api/v1/handler.go`
- Modify: `internal/api/v1/handler_test.go`
- Modify: `internal/scanner/scanner.go`
- Modify: `internal/scanner/scanner_test.go`
- Modify: `internal/db/sync.go`
- Modify: `internal/db/postgres/sync.go`
- Create/Modify: `internal/db/sqlite/lifecycle.go`
- Modify: `internal/db/sqlite/schema.go`
- Modify: `internal/db/sqlite/sync.go`
- Modify: `cmd/packmon/local_db.go`

- [ ] **Step 1: Write failing remote API test**

Add a handler test where the store returns one lifecycle finding. Assert:

- result contains vulnerability/malicious/lifecycle findings together.
- summary `by_type.lifecycle == 1`.
- feed status includes endoflife feed status when degraded.

- [ ] **Step 2: Add store method to API handler**

In `collectFindings`, query lifecycle after malicious/reputation:

```go
lifecycle, err := h.store.FindLifecycleFindingsBatch(ctx, queries, time.Now().UTC())
```

Append to all findings.

- [ ] **Step 3: Extend local checker interface**

Add optional interface so old tests can compile with simple stubs:

```go
type LifecycleChecker interface {
	FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error)
}
```

In local mode, if the local checker implements it, append lifecycle findings. If not, skip lifecycle and keep current behavior.

- [ ] **Step 4: Add sync payload**

Do not export pre-computed lifecycle verdicts to SQLite. Export the flattened
package-map x release-cycle cache rows with raw dates and status booleans, then
compute lifecycle findings locally against the current scan time. This avoids
freezing `eol_soon` and `security_support_only` severity at sync time.

In `internal/db/sync.go`:

```go
type SyncLifecycleRelease struct {
	ID               string
	Ecosystem        string
	Name             string
	ProductSlug      string
	ProductLabel     string
	Cycle            string
	Latest           string
	ReleaseDate      *time.Time
	IsLTS            bool
	LTSFrom          *time.Time
	IsEOAS           bool
	EOASFrom         *time.Time
	IsEOL            bool
	EOLFrom          *time.Time
	IsDiscontinued   bool
	DiscontinuedFrom *time.Time
	IsEOES           *bool
	EOESFrom         *time.Time
	IsMaintained     bool
	Withdrawn        bool
}
```

Add `Lifecycle []SyncLifecycleRelease` to `SyncExport`.

In `internal/db/postgres/sync.go`, flatten normalized lifecycle data with:

- join `lifecycle_package_map` to `lifecycle_products`;
- join matching `lifecycle_releases` for every mapped product;
- emit one sync row per ecosystem/name/product/cycle;
- set `ID` to `endoflife:<ecosystem>:<name>:<product_slug>:<cycle>`;
- support ecosystem filtering the same way vulnerability and malicious sync
  exports do.

- [ ] **Step 5: SQLite schema and import**

Create local cache table:

```sql
CREATE TABLE IF NOT EXISTS lifecycle_releases_local (
    id TEXT PRIMARY KEY,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    product_slug TEXT NOT NULL,
    product_label TEXT NOT NULL DEFAULT '',
    cycle TEXT NOT NULL,
    latest TEXT NOT NULL DEFAULT '',
    release_date TEXT,
    is_lts INTEGER NOT NULL DEFAULT 0,
    lts_from TEXT,
    is_eoas INTEGER NOT NULL DEFAULT 0,
    eoas_from TEXT,
    is_eol INTEGER NOT NULL DEFAULT 0,
    eol_from TEXT,
    is_discontinued INTEGER NOT NULL DEFAULT 0,
    discontinued_from TEXT,
    is_eoes INTEGER,
    eoes_from TEXT,
    is_maintained INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS lifecycle_releases_local_lookup_idx ON lifecycle_releases_local(ecosystem, name);
```

SQLite lookup should match by ecosystem/name and release cycle prefix exactly
like PostgreSQL, then construct findings using the same rules:

- `is_eol` or `eol_from <= now` -> blocking `supply_chain_risk`,
  `risk_type=eol`, severity `CRITICAL`.
- `eol_from` within 90 days -> `lifecycle`, `risk_type=eol_soon`,
  severity `MEDIUM`.
- `is_eoas` or `eoas_from <= now`, while not EOL -> `lifecycle`,
  `risk_type=security_support_only`, severity `LOW`.
- Date comparisons must guard nil dates: missing `eol_from` or `eoas_from`
  must not produce a date-based finding unless the corresponding boolean
  status field is true.

- [ ] **Step 6: Run tests**

```powershell
go test -count=1 .\internal\api\v1 .\internal\scanner .\internal\db\sqlite .\cmd\packmon
```

Expected: PASS.

- [ ] **Step 7: Commit**

```powershell
git add internal\api\v1\handler.go internal\api\v1\handler_test.go internal\scanner\scanner.go internal\scanner\scanner_test.go internal\db\sync.go internal\db\postgres\sync.go internal\db\sqlite\lifecycle.go internal\db\sqlite\schema.go internal\db\sqlite\sync.go cmd\packmon\local_db.go
git commit -m "feat: return lifecycle findings in scans"
```

---

## Task 9: CLI Reports For SBOM And Lifecycle

**Files:**
- Modify: `cmd/packmon/scan_command_more_test.go`
- Modify: `cmd/packmon/scan_output_more_test.go`
- Modify: `cmd/packmon/outdated_fetch_test.go`
- Modify: `cmd/packmon/list_all_test.go`
- Modify: `README.md`

- [ ] **Step 1: Add CLI tests**

Test scenarios:

- `packmon scan --sbom bom.cdx.json --mode local` checks SBOM packages.
- `packmon scan --sbom bom.spdx.json --list-packages` prints SBOM packages.
- `packmon scan --sbom bom.cdx.json --outdated` checks latest version for SBOM package.
- `--sbom missing.json` returns operational error.
- malformed SBOM plus no other package returns parser error.

- [ ] **Step 2: Run failing tests**

```powershell
go test -count=1 .\cmd\packmon
```

Expected: FAIL until CLI plumbing is complete.

- [ ] **Step 3: Complete CLI output details**

Requirements:

- List output should show SBOM path in `LOCK FILE` or rename column to `SOURCE FILE`.
- Do not print full absolute paths in persistent logs.
- Terminal warnings should use user-visible relative paths.
- JSON/SARIF/JUnit output should not need a schema break because lifecycle findings are normal findings.

- [ ] **Step 4: Run tests**

```powershell
go test -count=1 .\cmd\packmon
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add cmd\packmon\*_test.go README.md
git commit -m "test: cover SBOM CLI scan flows"
```

---

## Task 10: Documentation And OpenAPI

**Files:**
- Modify: `DESIGN.md`
- Modify: `SECURITY.md`
- Modify: `README.md`
- Modify: `api/openapi/*.yaml`
- Modify: `internal/parser/AGENTS.md` only if parser guidance needs to mention SBOM living outside `internal/parser`
- Modify: `internal/feed/AGENTS.md`

- [ ] **Step 1: Update DESIGN.md**

Add:

- SBOM import is a local package inventory source.
- Supported SBOM formats: CycloneDX JSON/XML and SPDX JSON.
- SBOM embedded vulnerability/VEX data is not authoritative in Packmon scan decisions.
- endoflife.date lifecycle feed is server-side, free/public, no API key.
- EOL exact matches are blocking supply-chain risk findings.
- EOL soon/security-support-only are lifecycle findings.
- Unknown lifecycle status is not a finding.

- [ ] **Step 2: Update SECURITY.md**

Add:

- endoflife.date is an external feed trust boundary.
- API data is parsed and normalized; raw JSON is not exposed to scan clients.
- Rate limits and upstream failures degrade the feed but do not delete cached data.
- No API key or paid service is required.
- CLI clients do not directly sync lifecycle feed data; they consume Packmon server/local SQLite results.

- [ ] **Step 3: Update README.md**

Document:

```powershell
packmon scan --sbom bom.cdx.json .
packmon scan --sbom sbom.spdx.json --list-packages .
packmon scan --sbom bom.cdx.json --outdated .
```

Document lifecycle/EOL caveat:

- EOL is only reported where package coordinates map to an endoflife.date product and release cycle.
- Library packages without official lifecycle metadata may still be vulnerable/outdated but not EOL.

- [ ] **Step 4: Update OpenAPI**

If finding type enum exists, add:

```yaml
- lifecycle
```

If sync payload schema exists, add lifecycle export shape.

- [ ] **Step 5: Run docs/schema tests**

```powershell
go test -count=1 .\internal\api\v1 .\cmd\packmon-server
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add DESIGN.md SECURITY.md README.md api\openapi internal\feed\AGENTS.md internal\parser\AGENTS.md
git commit -m "docs: document SBOM and lifecycle coverage"
```

---

## Task 11: Verification Gate

**Files:**
- No source changes expected unless verification reveals issues.

- [ ] **Step 1: Format**

```powershell
gofumpt -extra -w internal cmd
```

Expected: no command error.

- [ ] **Step 2: Unit tests**

Use temp outside the repo to avoid tests that inspect Git parents:

```powershell
$env:GOTMPDIR = Join-Path $env:TEMP 'packmon-go-tmp'
New-Item -ItemType Directory -Force $env:GOTMPDIR | Out-Null
go test -count=1 ./...
```

Expected: PASS.

- [ ] **Step 3: Race tests**

```powershell
$env:GOTMPDIR = Join-Path $env:TEMP 'packmon-go-tmp'
go test -race -count=1 ./...
```

Expected: PASS.

- [ ] **Step 4: Vet and lint**

```powershell
go vet ./...
golangci-lint run ./...
```

Expected: PASS.

- [ ] **Step 5: Security tooling**

```powershell
govulncheck ./...
gosec ./...
```

Expected: PASS or explicitly document missing local tool.

- [ ] **Step 6: Build binaries**

```powershell
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
```

Expected: PASS.

- [ ] **Step 7: Integration and E2E**

```powershell
$env:PACKMON_TEST_BIN_DIR = ".build"
go test -count=1 -tags integration .\tests\integration
go test -count=1 -tags e2e .\tests\e2e
```

Expected: PASS.

- [ ] **Step 8: Cleanup**

```powershell
Remove-Item -Recurse -Force .build
```

Expected: `.build` removed.

---

## Acceptance Criteria

- `packmon scan --sbom bom.cdx.json .` includes SBOM packages in vulnerability/malware/lifecycle checks.
- `packmon scan --sbom bom.spdx.json --list-packages .` prints detected SBOM packages with ecosystem and version.
- `packmon scan --sbom bom.cdx.json --outdated .` includes SBOM packages in outdated checks when their ecosystem has a latest-version resolver.
- CycloneDX JSON, CycloneDX XML, and SPDX JSON are supported.
- Unsupported or versionless SBOM components do not create false package findings.
- The Packmon server syncs endoflife.date data without an API key.
- endoflife.date `304` is treated as successful no-op.
- endoflife.date `429` or transient 5xx marks the feed degraded and keeps old data.
- Exact EOL lifecycle matches produce a blocking `supply_chain_risk` finding with `risk_type=eol`.
- EOL-soon and support-phase warnings produce `lifecycle` findings.
- Remote and local mode can return lifecycle findings from the same server-synced dataset.
- No client-side local sync talks directly to endoflife.date.
- DESIGN, SECURITY, README, and OpenAPI reflect the new behavior.

## Risk Notes

- SBOM PURL mapping can be wrong if generated SBOMs use non-standard PURLs. Keep unsupported PURLs skipped rather than guessing.
- endoflife.date is product/release-cycle data, not universal package EOL data. Do not market this as "EOL for every dependency."
- Cycle matching is inherently approximate for unusual version schemes. Use longest-prefix matching against known release cycles and return no finding when ambiguous.
- New lifecycle findings may change CI behavior if emitted as blocking supply-chain risk. Keep exact EOL blocking and warning-only lifecycle findings separate.

## Self-Review

- Spec coverage: SBOM import, EOL API sync, local/remote scan behavior, docs, tests, and no-paid-service constraint are covered.
- Placeholder scan: no task depends on an unspecified future implementation; each task names exact files, behaviors, and commands.
- Type consistency: SBOM package output maps to existing `domain.Package`; lifecycle findings use existing `domain.Finding` with one new finding type and existing `supply_chain_risk` for exact EOL.
