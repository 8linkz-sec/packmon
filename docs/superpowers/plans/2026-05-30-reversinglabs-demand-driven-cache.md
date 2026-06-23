# ReversingLabs Demand-Driven Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional ReversingLabs package reputation lookups that are cached internally, refreshed at most once per 24 hours when a package is actually used, and only requested for packages not covered by the other Packmon feeds.

**Architecture:** Keep all ReversingLabs traffic server-side. `/api/v1/check` uses existing feed data and cached ReversingLabs results, then schedules a background lookup only for supported packages that have no non-ReversingLabs findings and whose cache entry is missing or stale. A new ReversingLabs async worker consumes package-wide queue jobs, updates version-specific reputation cache rows, and never blocks scans on ReversingLabs availability.

**Tech Stack:** Go, PostgreSQL migrations, existing `db.Store`, `internal/feed` async worker pattern, Packmon API v1, local SQLite sync, OpenAPI-derived ReversingLabs Community API.

---

## Context And Policy

- ReversingLabs Community API base URL: `https://data.reversinglabs.com/api/oss/community/v2/free`.
- Authentication: `Authorization: Bearer <token>`.
- Free plan batch limit from the API schema: 5 packages per `/find/packages` request. Keep default batch size at 5 and cap configured values at **5** (raising the cap requires a paid plan; values above 5 return HTTP 413 on every request). A higher internal cap may be reintroduced together with explicit paid-plan support.
- Supported ReversingLabs communities: `npm`, `pypi`, `gem`, `nuget`, `vsx`, `psgallery`, `maven`.
- Packmon-supported ecosystems to enable initially: `npm`, `pypi`, `gem`, `nuget`, `maven`.
- Unsupported Packmon ecosystems must be cached as `unsupported` (a terminal status with `next_check_at = NULL`) without making an HTTP call. Due queries must explicitly exclude `status = 'unsupported'`. The scheduler and the worker MUST share one ReversingLabs PURL predicate so a package can never be scheduled that the worker cannot map.
- Mode handling: ReversingLabs supports `self` mode only. There is no external import path (no `feeds/reversinglabs/import` endpoint), so `external` must be rejected at config-load time rather than silently no-op.
- Demand-driven limitation (security): the first `/check` for any package is always a cache miss and returns no ReversingLabs finding; it only *schedules* an async lookup. A malicious or removed package is therefore blocked only on a later scan, after the worker has run (bounded by the rate limit and queue depth). ReversingLabs must not be presented as a synchronous blocking malware gate.
- Default lookup TTL: 24 hours.
- `malicious` remains a malware finding and blocks always.
- `removed` becomes a distinct `supply_chain_risk` finding and blocks always, but must not be labeled as confirmed malware unless the API also returns malware evidence.
- `clean`, `not_found`, `unsupported`, and transient `error` statuses do not create findings.
- Store normalized minimal evidence only; do not persist full ReversingLabs raw reports.

## File Structure

- Modify `internal/domain/models.go`: add the `supply_chain_risk` finding type.
- Modify `internal/api/v1/handler.go`: include cached reputation findings, enqueue stale/missing ReversingLabs checks, make supply-chain risk block, and serialize reputation findings in the `/api/v1/sync` response payload.
- Modify `internal/server/routes.go`: pass ReversingLabs config into the API handler after construction (the live server uses `NewHandlerWithRuntime`, which has no access to `cfg.Feeds`).
- Modify `internal/api/v1/handler_test.go`: cover blocking and enqueue/cache behavior.
- Modify `internal/scanner/scanner.go`: make `supply_chain_risk` block in `hasBlockingFindings` (CLI/local mode).
- Modify `internal/config/config.go`: add ReversingLabs config fields and env parsing.
- Modify `internal/config/feed_settings.go`: expose ReversingLabs in feed settings/admin feed configuration.
- Modify `internal/config/config_test.go`: verify defaults and env parsing.
- Modify `cmd/packmon-server/background.go`: register the ReversingLabs async worker.
- Modify `cmd/packmon-server/feed_config_test.go`, `cmd/packmon-server/admin_pages_test.go`, and `cmd/packmon-server/noop.go`: update feed config/admin test scaffolding.
- Modify `internal/db/db.go`: add reputation cache structs and store methods.
- Create `internal/db/postgres/migrations/004_reversinglabs_reputation.up.sql`.
- Create `internal/db/postgres/migrations/004_reversinglabs_reputation.down.sql`.
- Modify `internal/db/postgres/migrations/migrator.go`: bump `ExpectedVersion` to 4.
- Create `internal/db/postgres/reputation.go`: implement PostgreSQL reputation cache queries.
- Create `internal/db/postgres/reputation_test.go`: cover status mapping queries and TTL scheduling.
- Create `internal/feed/reversinglabs/purl.go`: implement exported `BuildPURL` and `SupportsPackage` helpers shared by the API scheduler and worker.
- Create `internal/feed/reversinglabs/worker.go`: implement async worker and API client.
- Create `internal/feed/reversinglabs/worker_test.go`: cover PURL generation, response classification, rate-limit behavior, and cache updates.
- Modify `internal/db/sync.go`, `internal/db/postgres/sync.go`, `internal/db/sqlite/schema.go`, `internal/db/sqlite/sync.go`, `internal/db/sqlite/store.go`: sync cached blocking ReversingLabs findings and tombstones to local mode. The `/api/v1/sync` HTTP payload (`syncResponsePayload` and the `HandleSync` serialization loops in `internal/api/v1/handler.go`) and the client-side `syncResponse` struct in `internal/db/sqlite/sync.go` MUST also carry the new reputation rows, otherwise exported data never crosses the wire.
- Modify `internal/scanner/scanner.go`, `internal/scanner/scanner_test.go`, `internal/scanner/table.go`, `internal/scanner/table_test.go`, `internal/scanner/sarif.go`, and `internal/scanner/junit.go`: ensure `supply_chain_risk` blocks (in `hasBlockingFindings`) and displays distinctly.
- Modify `internal/api/admin/runtime_config.go` and `internal/web/templates/admin/feeds.html`: hide or disable the `external` mode option for feeds that do not support it.
- Modify `DESIGN.md`: document ReversingLabs as optional server-side demand-driven reputation source.
- Modify `SECURITY.md`: document token handling, no raw report persistence, rate-limit behavior, and external-call boundary.
- Modify `README.md`: document Docker/env configuration and operational behavior.

---

### Task 1: Add Blocking Supply-Chain Finding Semantics

**Files:**
- Modify: `internal/domain/models.go`
- Modify: `internal/api/v1/handler.go`
- Test: `internal/api/v1/handler_test.go`

- [ ] **Step 1: Write the failing blocking test**

Add this test near the existing `isBlocking` tests in `internal/api/v1/handler_test.go`:

```go
func TestIsBlockingSupplyChainRiskAlwaysBlocks(t *testing.T) {
	findings := []domain.Finding{
		{
			Type:     domain.FindingTypeSupplyChainRisk,
			Severity: domain.SeverityLow,
			Source:   "reversinglabs",
		},
	}

	if !isBlocking(findings, domain.SeverityNone) {
		t.Fatal("supply-chain risk findings must block even when vulnerability threshold is NONE")
	}
}
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run:

```powershell
go test -count=1 .\internal\api\v1 -run TestIsBlockingSupplyChainRiskAlwaysBlocks
```

Expected: compile failure because `domain.FindingTypeSupplyChainRisk` is not defined.

- [ ] **Step 3: Add the domain finding type**

In `internal/domain/models.go`, extend the finding type constants:

```go
const (
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeMalicious        FindingType = "malicious"
	FindingTypeSupplyChainRisk  FindingType = "supply_chain_risk"
)
```

Run `gofumpt` later; this snippet intentionally shows the desired semantic addition.

- [ ] **Step 4: Make supply-chain risk block**

In `internal/api/v1/handler.go`, update `isBlocking`:

```go
func isBlocking(findings []domain.Finding, threshold domain.Severity) bool {
	for _, f := range findings {
		if f.Type == domain.FindingTypeMalicious || f.Type == domain.FindingTypeSupplyChainRisk {
			return true
		}
		if threshold == domain.SeverityNone {
			continue
		}
		if f.Severity.Blocks(threshold) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run the focused test**

Run:

```powershell
go test -count=1 .\internal\api\v1 -run TestIsBlockingSupplyChainRiskAlwaysBlocks
```

Expected: PASS.

---

### Task 2: Add ReversingLabs Configuration

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/feed_settings.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write config tests**

Add tests in `internal/config/config_test.go`:

```go
func TestReversingLabsDefaults(t *testing.T) {
	t.Setenv("PACKMON_FEED_REVERSINGLABS_ENABLED", "")
	t.Setenv("PACKMON_FEED_REVERSINGLABS_MODE", "")
	t.Setenv("PACKMON_REVERSINGLABS_API_KEY", "")
	t.Setenv("PACKMON_REVERSINGLABS_API_BASE_URL", "")
	t.Setenv("PACKMON_REVERSINGLABS_LOOKUP_TTL", "")
	t.Setenv("PACKMON_REVERSINGLABS_BATCH_SIZE", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Feeds.ReversingLabsEnabled {
		t.Fatal("ReversingLabs should be disabled by default")
	}
	if cfg.Feeds.ReversingLabsMode != FeedModeSelf {
		t.Fatalf("ReversingLabsMode = %q, want self", cfg.Feeds.ReversingLabsMode)
	}
	if cfg.Feeds.ReversingLabsLookupTTL != 24*time.Hour {
		t.Fatalf("ReversingLabsLookupTTL = %v, want 24h", cfg.Feeds.ReversingLabsLookupTTL)
	}
	if cfg.Feeds.ReversingLabsBatchSize != 5 {
		t.Fatalf("ReversingLabsBatchSize = %d, want 5", cfg.Feeds.ReversingLabsBatchSize)
	}
}

func TestReversingLabsEnv(t *testing.T) {
	t.Setenv("PACKMON_FEED_REVERSINGLABS_ENABLED", "true")
	t.Setenv("PACKMON_FEED_REVERSINGLABS_MODE", "self")
	t.Setenv("PACKMON_REVERSINGLABS_API_KEY", "rl-token")
	t.Setenv("PACKMON_REVERSINGLABS_API_BASE_URL", "https://example.test/community")
	t.Setenv("PACKMON_REVERSINGLABS_LOOKUP_TTL", "12h")
	t.Setenv("PACKMON_REVERSINGLABS_BATCH_SIZE", "3")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Feeds.ReversingLabsEnabled {
		t.Fatal("ReversingLabsEnabled = false, want true")
	}
	if cfg.Feeds.ReversingLabsMode != FeedModeSelf {
		t.Fatalf("ReversingLabsMode = %q, want self", cfg.Feeds.ReversingLabsMode)
	}
	if cfg.Feeds.ReversingLabsAPIKey != "rl-token" {
		t.Fatalf("ReversingLabsAPIKey = %q, want rl-token", cfg.Feeds.ReversingLabsAPIKey)
	}
	if cfg.Feeds.ReversingLabsBaseURL != "https://example.test/community" {
		t.Fatalf("ReversingLabsBaseURL = %q", cfg.Feeds.ReversingLabsBaseURL)
	}
	if cfg.Feeds.ReversingLabsLookupTTL != 12*time.Hour {
		t.Fatalf("ReversingLabsLookupTTL = %v, want 12h", cfg.Feeds.ReversingLabsLookupTTL)
	}
	if cfg.Feeds.ReversingLabsBatchSize != 3 {
		t.Fatalf("ReversingLabsBatchSize = %d, want 3", cfg.Feeds.ReversingLabsBatchSize)
	}
}

// TestReversingLabsRejectsExternalMode asserts external mode is invalid:
// ReversingLabs has no import path, so an enabled external feed would be inert.
func TestReversingLabsRejectsExternalMode(t *testing.T) {
	t.Setenv("PACKMON_FEED_REVERSINGLABS_ENABLED", "true")
	t.Setenv("PACKMON_FEED_REVERSINGLABS_MODE", "external")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want error for ReversingLabs external mode")
	}
}

// TestReversingLabsBatchSizeCappedAtFive asserts the free-plan per-request
// limit is enforced.
func TestReversingLabsBatchSizeCappedAtFive(t *testing.T) {
	t.Setenv("PACKMON_REVERSINGLABS_BATCH_SIZE", "25")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Feeds.ReversingLabsBatchSize != 5 {
		t.Fatalf("ReversingLabsBatchSize = %d, want 5 (capped)", cfg.Feeds.ReversingLabsBatchSize)
	}
}
```

- [ ] **Step 2: Run config tests and confirm failure**

Run:

```powershell
go test -count=1 .\internal\config -run ReversingLabs
```

Expected: compile failure for missing config fields.

- [ ] **Step 3: Add config fields**

In `internal/config/config.go`, extend `FeedsConfig`:

```go
ReversingLabsEnabled bool
ReversingLabsMode    FeedMode
ReversingLabsAPIKey  string
ReversingLabsBaseURL string
ReversingLabsLookupTTL time.Duration
ReversingLabsBatchSize int
```

Before constructing `Config` in `Load()`, parse these env vars:

```go
reversingLabsTTL, err := envDurationOrDefault("PACKMON_REVERSINGLABS_LOOKUP_TTL", 24*time.Hour)
if err != nil {
	return nil, err
}
reversingLabsBatchSize, err := envPositiveIntOrDefault("PACKMON_REVERSINGLABS_BATCH_SIZE", 5)
if err != nil {
	return nil, err
}
// Free-plan /find/packages accepts at most 5 packages per request.
if reversingLabsBatchSize > 5 {
	reversingLabsBatchSize = 5
}
```

After parsing the mode, reject `external` because ReversingLabs has no import
path and would otherwise be an enabled-but-inert feed:

```go
reversingLabsMode := parseFeedMode("PACKMON_FEED_REVERSINGLABS_MODE")
if reversingLabsMode == FeedModeExternal {
	return nil, fmt.Errorf("PACKMON_FEED_REVERSINGLABS_MODE=external is not supported: ReversingLabs is demand-driven and has no import endpoint")
}
```

Then add these `FeedsConfig` assignments:

```go
ReversingLabsEnabled: envBoolOrDefault("PACKMON_FEED_REVERSINGLABS_ENABLED", false),
ReversingLabsMode: reversingLabsMode,
ReversingLabsAPIKey: os.Getenv("PACKMON_REVERSINGLABS_API_KEY"),
ReversingLabsBaseURL: envOrDefault("PACKMON_REVERSINGLABS_API_BASE_URL", "https://data.reversinglabs.com/api/oss/community/v2/free"),
ReversingLabsLookupTTL: reversingLabsTTL,
ReversingLabsBatchSize: reversingLabsBatchSize,
```

- [ ] **Step 4: Expose feed settings**

In `internal/config/feed_settings.go`, add a `reversinglabs` case:

```go
case "reversinglabs":
	return FeedSettings{
		Name:                 "reversinglabs",
		DisplayName:          "ReversingLabs",
		Enabled:              c.Feeds.ReversingLabsEnabled,
		Mode:                 c.Feeds.ReversingLabsMode,
		APIKey:               c.Feeds.ReversingLabsAPIKey,
		RequiresAPIKey:       true,
		SupportsSyncInterval: false,
	}, true
```

Add `"reversinglabs"` after `"socket"` in `FeedSettingsList()`.

In `SetFeedSettings`, add (force `self`, since `external` is unsupported for
ReversingLabs):

```go
case "reversinglabs":
	if mode == FeedModeExternal {
		return fmt.Errorf("reversinglabs does not support external mode")
	}
	c.Feeds.ReversingLabsEnabled = feed.Enabled
	c.Feeds.ReversingLabsMode = FeedModeSelf
	c.Feeds.ReversingLabsAPIKey = strings.TrimSpace(feed.APIKey)
```

- [ ] **Step 5: Run config tests**

Run:

```powershell
go test -count=1 .\internal\config
```

Expected: PASS.

---

### Task 3: Add Reputation Cache Model And Migration

**Files:**
- Modify: `internal/db/db.go`
- Create: `internal/db/postgres/migrations/004_reversinglabs_reputation.up.sql`
- Create: `internal/db/postgres/migrations/004_reversinglabs_reputation.down.sql`
- Modify: `internal/db/postgres/migrations/migrator.go`

- [ ] **Step 1: Add DB structs and store method signatures**

In `internal/db/db.go`, add:

```go
const (
	ReputationSourceReversingLabs = "reversinglabs"
)

type PackageReputation struct {
	Ecosystem     string
	Name          string
	Version       string
	Source        string
	Status        string
	Severity      string
	Summary       string
	Description   string
	ReferenceURLs json.RawMessage
	Evidence      json.RawMessage
	LastCheckedAt *time.Time
	NextCheckAt   *time.Time
	LastError      string
	UpdatedAt      time.Time
}
```

Extend `Store`:

```go
FindReputationFindingsBatch(ctx context.Context, packages []PackageQuery, source string) ([]domain.Finding, error)
MarkPackageReputationDue(ctx context.Context, rep *PackageReputation) (queued bool, err error)
ListDuePackageReputations(ctx context.Context, ecosystem, name, source string, limit int) ([]PackageReputation, error)
UpsertPackageReputation(ctx context.Context, rep *PackageReputation) error
```

- [ ] **Step 2: Create the up migration**

Create `internal/db/postgres/migrations/004_reversinglabs_reputation.up.sql`:

```sql
-- 004_reversinglabs_reputation.up.sql

CREATE TABLE package_reputation_cache (
    id              SERIAL      PRIMARY KEY,
    ecosystem       TEXT        NOT NULL,
    name            TEXT        NOT NULL,
    version         TEXT        NOT NULL,
    source          TEXT        NOT NULL,
    status          TEXT        NOT NULL CHECK (status IN ('pending', 'malicious', 'removed', 'clean', 'not_found', 'unsupported', 'error')),
    severity        TEXT        NOT NULL DEFAULT 'CRITICAL',
    summary         TEXT        NOT NULL DEFAULT '',
    description     TEXT        NOT NULL DEFAULT '',
    reference_urls  JSONB       NOT NULL DEFAULT '[]',
    evidence        JSONB       NOT NULL DEFAULT '{}',
    last_checked_at TIMESTAMPTZ,
    next_check_at   TIMESTAMPTZ,
    last_error      TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(ecosystem, name, version, source)
);

-- No separate lookup index: the UNIQUE(ecosystem, name, version, source)
-- constraint already provides a btree with the exact lookup key, so an
-- additional idx_reputation_lookup would be redundant write overhead.

CREATE INDEX idx_reputation_due
    ON package_reputation_cache(source, ecosystem, name, next_check_at)
    WHERE status IN ('pending', 'error', 'malicious', 'removed', 'clean', 'not_found');
```

- [ ] **Step 3: Create the down migration**

Create `internal/db/postgres/migrations/004_reversinglabs_reputation.down.sql`:

```sql
-- 004_reversinglabs_reputation.down.sql

DROP TABLE IF EXISTS package_reputation_cache;
```

- [ ] **Step 4: Bump migration expected version**

In `internal/db/postgres/migrations/migrator.go`:

```go
const ExpectedVersion = 4
```

- [ ] **Step 5: Run migration package tests**

Run:

```powershell
go test -count=1 .\internal\db\postgres\migrations
```

Expected: PASS.

---

### Task 4: Implement PostgreSQL Reputation Cache Queries

**Files:**
- Create: `internal/db/postgres/reputation.go`
- Test: `internal/db/postgres/reputation_test.go`

- [ ] **Step 1: Write tests for cached finding conversion**

Create unit tests around a small unexported helper named `reputationToFinding` in `internal/db/postgres/reputation.go`:

```go
func TestReputationToFindingMapsRemoved(t *testing.T) {
	rep := db.PackageReputation{
		Ecosystem: "npm",
		Name: "left-pad",
		Version: "1.3.0",
		Source: db.ReputationSourceReversingLabs,
		Status: "removed",
		Severity: "CRITICAL",
		Summary: "ReversingLabs: package version was removed",
	}

	finding, ok := reputationToFinding(rep)
	if !ok {
		t.Fatal("reputationToFinding returned !ok for removed reputation")
	}
	if finding.Type != domain.FindingTypeSupplyChainRisk {
		t.Fatalf("Type = %q, want supply_chain_risk", finding.Type)
	}
	if finding.RiskType != "removed_package" {
		t.Fatalf("RiskType = %q, want removed_package", finding.RiskType)
	}
}

func TestReputationToFindingMapsMalicious(t *testing.T) {
	rep := db.PackageReputation{
		Ecosystem: "pypi",
		Name: "evilpkg",
		Version: "2.0.0",
		Source: db.ReputationSourceReversingLabs,
		Status: "malicious",
		Severity: "CRITICAL",
		Summary: "ReversingLabs: malware detected",
	}

	finding, ok := reputationToFinding(rep)
	if !ok {
		t.Fatal("reputationToFinding returned !ok for malicious reputation")
	}
	if finding.Type != domain.FindingTypeMalicious {
		t.Fatalf("Type = %q, want malicious", finding.Type)
	}
	if finding.RiskType != "malware" {
		t.Fatalf("RiskType = %q, want malware", finding.RiskType)
	}
}

func TestReputationToFindingSkipsClean(t *testing.T) {
	_, ok := reputationToFinding(db.PackageReputation{
		Ecosystem: "gem",
		Name: "cleanpkg",
		Version: "1.0.0",
		Source: db.ReputationSourceReversingLabs,
		Status: "clean",
	})
	if ok {
		t.Fatal("reputationToFinding returned ok for clean reputation")
	}
}
```

- [ ] **Step 2: Implement query methods**

Create `internal/db/postgres/reputation.go` with these methods:

```go
func (s *Store) FindReputationFindingsBatch(ctx context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error)
func (s *Store) MarkPackageReputationDue(ctx context.Context, rep *db.PackageReputation) (bool, error)
func (s *Store) ListDuePackageReputations(ctx context.Context, ecosystem, name, source string, limit int) ([]db.PackageReputation, error)
func (s *Store) UpsertPackageReputation(ctx context.Context, rep *db.PackageReputation) error
```

Mapping rules inside `FindReputationFindingsBatch`:

```go
switch status {
case "malicious":
	f.Type = domain.FindingTypeMalicious
	f.RiskType = "malware"
case "removed":
	f.Type = domain.FindingTypeSupplyChainRisk
	f.RiskType = "removed_package"
default:
	continue
}
```

`MarkPackageReputationDue` must:

- insert a row with `status='pending'`, `next_check_at=NOW()`, and empty evidence when no row exists;
- set `next_check_at=NOW()` only if the existing row is due (`next_check_at IS NULL OR next_check_at <= NOW()`) AND its status is not the terminal `unsupported`;
- never re-queue a row whose status is `unsupported` (return `false`);
- return `true` only when the row is due and a worker should be queued.

Use a single upsert with a conditional `WHERE` so concurrent `/check` requests cannot double-queue (rely on `ON CONFLICT (ecosystem, name, version, source)`); the `queued` result reflects whether this call actually moved the row to due.

`ListDuePackageReputations` must return rows where:

```sql
source = $1
AND ecosystem = $2
AND name = $3
AND status <> 'unsupported'
AND (next_check_at IS NULL OR next_check_at <= NOW())
ORDER BY next_check_at NULLS FIRST, updated_at ASC
LIMIT $4
```

The `status <> 'unsupported'` filter is required: terminal `unsupported` rows are stored with `next_check_at = NULL`, which would otherwise match the `IS NULL` clause and be re-checked forever. This is consistent with `idx_reputation_due`, whose partial `WHERE` already excludes `unsupported`.

`UpsertPackageReputation` must write only normalized fields and set `updated_at=NOW()`.

- [ ] **Step 3: Run PostgreSQL DB tests**

Run:

```powershell
go test -count=1 .\internal\db\postgres -run Reputation
```

Expected: PASS.

---

### Task 5: Schedule ReversingLabs Lookups From `/api/v1/check`

**Files:**
- Modify: `internal/api/v1/handler.go`
- Modify: `internal/server/routes.go`
- Test: `internal/api/v1/handler_test.go`

- [ ] **Step 1: Add handler fields and a setter wired from routes.go**

The live server constructs the handler via `v1.NewHandlerWithRuntime(store, logger, runtime)` (`internal/server/routes.go:21`), which receives a `*config.RuntimeSettings`, NOT a `*config.Config`. `NewHandlerWithConfig` is only used by tests. Wiring ReversingLabs into `NewHandlerWithConfig` would make the feature dead in production. Instead, add an explicit setter and call it from `routes.go`, where `cfg *config.Config` is already in scope (it is a `registerRoutes` parameter).

Extend `Handler`:

```go
reversingLabsEnabled bool
reversingLabsTTL     time.Duration
```

Add an exported setter on `Handler`:

```go
// ConfigureReversingLabs enables demand-driven ReversingLabs scheduling.
// Only "self" mode performs lookups; "external" is rejected at config load.
func (h *Handler) ConfigureReversingLabs(cfg *config.Config) {
	if cfg == nil {
		return
	}
	h.reversingLabsEnabled = cfg.Feeds.ReversingLabsEnabled && cfg.Feeds.ReversingLabsMode == config.FeedModeSelf
	h.reversingLabsTTL = cfg.Feeds.ReversingLabsLookupTTL
}
```

In `internal/server/routes.go`, immediately after the handler is built:

```go
api := v1.NewHandlerWithRuntime(store, logger, runtime)
api.ConfigureReversingLabs(cfg)
```

`NewHandler`, `NewHandlerWithConfig`, and `NewHandlerWithBlockThreshold` keep the feature disabled by default so existing tests stay deterministic. Handler unit tests (Step 2) call `ConfigureReversingLabs` (or set the fields directly) to enable it.

- [ ] **Step 2: Write API handler tests**

Add a test where:

- OSV/GHSA/OpenSSF return no findings for `npm/left-pad@1.3.0`;
- cached ReversingLabs row returns a `supply_chain_risk` finding;
- no non-ReversingLabs finding exists;
- the handler calls `MarkPackageReputationDue` and `EnqueueRefresh` with `Source: "reversinglabs"`.

Use the existing `stubStore` and add fields:

```go
reputationFindings []domain.Finding
markedReputation []db.PackageReputation
queuedJobs []db.RefreshJob
```

Add stub methods matching the new `db.Store` methods.

- [ ] **Step 3: Update collection logic**

Refactor `collectFindings` to:

1. Build `queries`.
2. Fetch vulnerabilities.
3. Fetch malicious findings.
4. Fetch ReversingLabs reputation findings.
5. Append all findings to the response.
6. Schedule ReversingLabs checks only for packages without non-ReversingLabs findings.

Add the ReversingLabs import in `internal/api/v1/handler.go`:

```go
import (
	// existing imports...

	"github.com/8linkz/packmon/internal/feed/reversinglabs"
)
```

Add this local helper near `collectFindings`:

```go
func packageKey(ecosystem, name, version string) string {
	return ecosystem + "\x00" + name + "\x00" + version
}
```

The scheduling helper should look like this:

```go
func (h *Handler) scheduleReversingLabsLookups(ctx context.Context, packages []domain.Package, nonRL map[string]bool) {
	if !h.reversingLabsEnabled {
		return
	}
	for _, pkg := range packages {
		key := packageKey(string(pkg.Ecosystem), pkg.Name, pkg.Version)
		if nonRL[key] {
			continue
		}
		// Same predicate the worker uses to build a PURL (Task 6 Step 4):
		// identical ecosystem set, non-empty version, valid scoped-npm /
		// group:artifact-maven shape. This guarantees a scheduled package is
		// always mappable, so no due row can get stuck pending forever.
		if !reversinglabs.SupportsPackage(string(pkg.Ecosystem), pkg.Name, pkg.Version) {
			// Persist a terminal "unsupported" row (next_check_at = NULL,
			// excluded from the due query) without an HTTP call, per policy.
			if err := h.store.UpsertPackageReputation(ctx, &db.PackageReputation{
				Ecosystem: string(pkg.Ecosystem),
				Name:      pkg.Name,
				Version:   pkg.Version,
				Source:    db.ReputationSourceReversingLabs,
				Status:    "unsupported",
			}); err != nil {
				h.logger.Warn("failed to cache unsupported reputation", "ecosystem", pkg.Ecosystem, "name", pkg.Name, "error", err)
			}
			continue
		}
		rep := &db.PackageReputation{
			Ecosystem: string(pkg.Ecosystem),
			Name:      pkg.Name,
			Version:   pkg.Version,
			Source:    db.ReputationSourceReversingLabs,
			Status:    "pending",
		}
		queued, err := h.store.MarkPackageReputationDue(ctx, rep)
		if err != nil {
			h.logger.Warn("failed to mark ReversingLabs reputation due", "ecosystem", pkg.Ecosystem, "name", pkg.Name, "error", err)
			continue
		}
		if !queued {
			continue
		}
		_, _, err = h.store.EnqueueRefresh(ctx, &db.RefreshJob{
			Ecosystem: string(pkg.Ecosystem),
			Name:      pkg.Name,
			Source:    db.ReputationSourceReversingLabs,
			Priority:  1,
			Status:    "pending",
		})
		if err != nil {
			h.logger.Warn("failed to enqueue ReversingLabs lookup", "ecosystem", pkg.Ecosystem, "name", pkg.Name, "error", err)
		}
	}
}
```

Note `MarkPackageReputationDue` must not re-queue rows whose status is the terminal `unsupported`.

Do not include package versions in `refresh_queue`; the existing queue invariant is package-wide and `EnqueueRefresh` dedups pending jobs per `(ecosystem, name, source)` via `ON CONFLICT DO NOTHING`. The worker will load due versions from `package_reputation_cache`.

- [ ] **Step 4: Run focused API tests**

Run:

```powershell
go test -count=1 .\internal\api\v1 -run "ReversingLabs|SupplyChainRisk|HandleCheck"
```

Expected: PASS.

---

### Task 6: Implement The ReversingLabs Async Worker

**Files:**
- Create: `internal/feed/reversinglabs/worker.go`
- Test: `internal/feed/reversinglabs/worker_test.go`
- Modify: `cmd/packmon-server/background.go`

- [ ] **Step 1: Write worker tests**

Create tests for:

- supported ecosystem mapping: `npm`, `pypi`, `gem`, `nuget`, `maven`;
- a due row the worker cannot map to a PURL (e.g. a stale `pending` row with an empty version or malformed Maven name) is written as terminal `unsupported` WITHOUT an HTTP call and is not re-queued;
- API `429` returns an error so the queue job is marked `error`;
- `identity.removed=true` maps to `removed`;
- classification `Malicious` maps to `malicious`;
- found package without bad signals maps to `clean`;
- API lookup stores `next_check_at = now + ttl`.

Use an `httptest.Server` and a fake store implementing only:

```go
DequeueRefresh(context.Context, string) (*db.RefreshJob, error)
CompleteRefresh(context.Context, int, error) error
ResetStuckJobs(context.Context, string, time.Duration) (int, error)
ListDuePackageReputations(context.Context, string, string, string, int) ([]db.PackageReputation, error)
UpsertPackageReputation(context.Context, *db.PackageReputation) error
```

- [ ] **Step 2: Implement worker constants and constructor**

Create `internal/feed/reversinglabs/worker.go`:

```go
package reversinglabs

const (
	FeedName = db.ReputationSourceReversingLabs
	DefaultBaseURL = "https://data.reversinglabs.com/api/oss/community/v2/free"
	defaultPollInterval = 10 * time.Second
	defaultRateLimitPerHour = 300
	maxResponseSize = 2 << 20
)
```

The worker emits the same telemetry as the Socket.dev worker so the queue stays observable: `telemetry.Default().IncQueueError(FeedName)` on a failed job and `telemetry.Default().AddQueueStuckRecovered(n)` after stuck-job resets (see existing `packmon_queue_error_total` / `packmon_queue_stuck_jobs_recovered_total` metrics). ReversingLabs is an async worker, not a `FeedSyncer`, so it does not appear in `/api/v1/feeds/status`; document this in the admin/feed notes.

Implement:

```go
func NewWorker(store db.Store, apiKey string, logger *slog.Logger, opts ...Option) *Worker
func (w *Worker) Name() string
func (w *Worker) Run(ctx context.Context) error
```

Follow `internal/feed/socket/worker.go` for token bucket, stuck job reset, dequeue, and completion behavior.

- [ ] **Step 3: Implement package processing**

The worker flow for one queue job:

```go
due, err := w.store.ListDuePackageReputations(ctx, job.Ecosystem, job.Name, FeedName, w.batchSize)
if err != nil {
	return err
}
if len(due) == 0 {
	return nil
}

// Defensive split: even though the scheduler only enqueues mappable
// packages, a stale row could be unmappable. Mark those terminal instead
// of looping forever (D2). Mappable rows go to the API.
var mappable []db.PackageReputation
for _, rep := range due {
	if _, ok := BuildPURL(rep.Ecosystem, rep.Name, rep.Version); !ok {
		rep.Status = "unsupported"
		// Terminal: never re-check. Leave NextCheckAt nil and exclude
		// status='unsupported' from the due query / partial index.
		rep.NextCheckAt = nil
		if err := w.store.UpsertPackageReputation(ctx, &rep); err != nil {
			return err
		}
		continue
	}
	mappable = append(mappable, rep)
}
if len(mappable) == 0 {
	return nil
}
results := w.lookupBatch(ctx, mappable)
for i := range results {
	if err := w.store.UpsertPackageReputation(ctx, &results[i]); err != nil {
		return err
	}
}
```

Set `next_check_at` to `now + ttl` for `malicious`, `removed`, `clean`, and `not_found`. For transient API errors, update `last_error` and `next_check_at = now + 1h`; preserve any previous definitive status (`malicious`, `removed`, `clean`, or `not_found`) so a temporary ReversingLabs outage cannot clear a known blocking finding. Use `status='error'` only for rows that have never had a definitive result. The terminal `unsupported` status always uses `next_check_at = NULL` and is excluded from due queries.

- [ ] **Step 4: Implement shared PURL generation**

Create `internal/feed/reversinglabs/purl.go` with these exported helpers:

```go
package reversinglabs

func BuildPURL(ecosystem, name, version string) (string, bool)

func SupportsPackage(ecosystem, name, version string) bool {
	_, ok := BuildPURL(ecosystem, name, version)
	return ok
}
```

Task 5's API scheduler and Task 6's worker must both call this same package-level helper. `internal/parser/maven.go` stores Maven packages as `groupId:artifactId`, so `BuildPURL` must split Maven names on the first `:` and reject names without both sides.

PURL rules:

- `pypi`: `pkg:pypi/<name>@<version>`
- `gem`: `pkg:gem/<name>@<version>`
- `nuget`: `pkg:nuget/<name>@<version>`
- `npm` unscoped: `pkg:npm/<name>@<version>`
- `npm` scoped `@scope/name`: `pkg:npm/%40scope/name@<version>`
- `maven` with Packmon name `group:artifact`: `pkg:maven/<group>/<artifact>@<version>`

Return `false` for unsupported ecosystems, missing versions, empty names, and malformed Maven names.

- [ ] **Step 5: Implement `/find/packages?compact=true` request**

Send a JSON array:

```json
[
  {
    "uuid": "npm:left-pad@1.3.0",
    "purl": "pkg:npm/left-pad@1.3.0"
  }
]
```

Set headers:

```go
req.Header.Set("Authorization", "Bearer "+w.apiKey)
req.Header.Set("Accept", "application/json")
req.Header.Set("Content-Type", "application/json")
req.Header.Set("User-Agent", "packmon-feedsync/1.0")
```

Handle statuses:

- `200`: parse response.
- `401` or `403`: return authentication error mentioning `PACKMON_REVERSINGLABS_API_KEY`.
- `402`: return capacity error and leave queue job errored.
- `413`: lower configured batch size in code path for the next loop by retrying individual entries.
- `429`: drain tokens and return rate-limit error.
- other non-`200`: return unexpected status error.

- [ ] **Step 6: Implement classification mapping**

Normalize into `db.PackageReputation`:

```go
status := "clean"
if hasMaliciousSignal(pkg) {
	status = "malicious"
} else if hasRemovedSignal(pkg) {
	status = "removed"
}
```

Malicious signals:

- package `all_malicious == true`;
- malware assessment `status == "fail"`;
- classification `status == "Malicious"`;
- dependency classification `status == "Malicious"`;
- incident type `malware`.

Removed signals:

- version identity `removed == true`;
- package `was_removed == true`;
- incident type `removal`.

Evidence JSON must contain only selected normalized fields:

```json
{
  "purl": "pkg:npm/left-pad@1.3.0",
  "signals": ["identity.removed"],
  "assessment": "removed",
  "checked_by": "reversinglabs"
}
```

- [ ] **Step 7: Register worker**

In `cmd/packmon-server/background.go`, import the new package and append worker:

```go
if cfg.Feeds.ReversingLabsEnabled && cfg.Feeds.ReversingLabsMode == config.FeedModeSelf {
	workers = append(workers, reversinglabs.NewWorker(
		store,
		cfg.Feeds.ReversingLabsAPIKey,
		logger,
		reversinglabs.WithBaseURL(cfg.Feeds.ReversingLabsBaseURL),
		reversinglabs.WithLookupTTL(cfg.Feeds.ReversingLabsLookupTTL),
		reversinglabs.WithBatchSize(cfg.Feeds.ReversingLabsBatchSize),
	))
}
```

- [ ] **Step 8: Run worker tests**

Run:

```powershell
go test -count=1 .\internal\feed\reversinglabs
```

Expected: PASS.

---

### Task 7: Sync Reputation Findings To Local SQLite

**Files:**
- Modify: `internal/db/sync.go`
- Modify: `internal/db/postgres/sync.go`
- Modify: `internal/api/v1/handler.go` (`/api/v1/sync` HTTP payload)
- Modify: `internal/db/sqlite/sync.go` (`syncResponse` must decode the new `reputation` JSON field)
- Modify: `internal/db/sqlite/schema.go`
- Modify: `internal/db/sqlite/sync.go`
- Modify: `internal/db/sqlite/store.go`
- Test: `internal/db/sqlite/web_test.go` or a new `internal/db/sqlite/sync_reputation_test.go`

- [ ] **Step 1: Add sync DTO**

In `internal/db/sync.go`:

```go
type SyncReputationFinding struct {
	ID        string
	Ecosystem string
	Name      string
	Version   string
	Type      string
	RiskType  string
	Severity  string
	Summary   string
	Withdrawn bool
}
```

Extend `SyncExport`:

```go
Reputation []SyncReputationFinding
```

- [ ] **Step 2: Export reputation findings and tombstones**

In `internal/db/postgres/sync.go`, add `exportSyncReputation`. It must export changed rows with statuses `malicious`, `removed`, `clean`, `not_found`, `unsupported`, and `error` so local SQLite can delete stale blocking rows when the server later learns that a package is clean or unsupported. Do not export `pending`.

Use a stable ID that does not include status:

```go
func reputationSyncID(ecosystem, name, version string) string {
	return fmt.Sprintf("reversinglabs:%s/%s@%s", ecosystem, name, version)
}
```

Mapping:

- `malicious`: `Type="malicious"`, `RiskType="malware"`, `Withdrawn=false`.
- `removed`: `Type="supply_chain_risk"`, `RiskType="removed_package"`, `Withdrawn=false`.
- `clean`, `not_found`, `unsupported`, `error`: `Withdrawn=true`; the SQLite client must delete by ID and ignore empty type/risk/severity fields.

Update `ExportSync` so `Truncated` also accounts for reputation rows:

```go
truncated := opts.Limit > 0 &&
	(len(vulns) == opts.Limit || len(malicious) == opts.Limit || len(reputation) == opts.Limit)
```

This keeps `/api/v1/sync` `has_more` correct when reputation rows fill the page.

- [ ] **Step 2a: Carry reputation rows over the `/api/v1/sync` wire**

`exportSyncReputation` only fills `db.SyncExport.Reputation` in memory. The HTTP endpoint must actually serialize it, otherwise the SQLite client never receives the rows. In `internal/api/v1/handler.go`:

- add a `reputation` array type to `syncResponsePayload` (alongside `vulnerabilities` and `malicious`), e.g.:

```go
type syncReputationResponse struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type"`
	RiskType  string `json:"risk_type"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
	Withdrawn bool   `json:"withdrawn"`
}
```

- in `HandleSync`, initialize `Reputation: make([]syncReputationResponse, 0, len(exported.Reputation))` and append `exported.Reputation` rows into `resp.Reputation` just like the existing `Vulnerabilities`/`Malicious` loops;
- mirror the field in the SQLite client's `syncResponse` struct in `internal/db/sqlite/sync.go` so `resp.Reputation` (Task 7 Step 4) is actually populated from the decoded JSON.

Add a handler-level test asserting `/api/v1/sync` emits a reputation row when the store exports one (extend the existing sync handler test).

- [ ] **Step 3: Add SQLite table**

In `internal/db/sqlite/schema.go`:

```sql
CREATE TABLE IF NOT EXISTS reputation_findings_local (
	id        TEXT PRIMARY KEY,
	ecosystem TEXT NOT NULL,
	name      TEXT NOT NULL,
	version   TEXT NOT NULL,
	type      TEXT NOT NULL,
	risk_type TEXT NOT NULL,
	severity  TEXT NOT NULL DEFAULT 'CRITICAL',
	summary   TEXT
);

CREATE INDEX IF NOT EXISTS idx_rep_eco_name
	ON reputation_findings_local(ecosystem, name);
```

- [ ] **Step 4: Import reputation rows during sync**

In `internal/db/sqlite/sync.go`, process `resp.Reputation` rows. If `Withdrawn` is true, delete by stable `id` and continue without validating type/risk/severity. If `Withdrawn` is false, upsert the row into `reputation_findings_local`. This order is required because tombstone rows intentionally carry only the stable ID plus package identity.

- [ ] **Step 5: Query local reputation findings**

In `internal/db/sqlite/store.go`, extend local finding lookup to query `reputation_findings_local` for exact `ecosystem`, `name`, and `version`, and map rows into `domain.Finding` with `Type` from the stored row.

- [ ] **Step 6: Run local DB tests**

Run:

```powershell
go test -count=1 .\internal\db\sqlite
```

Expected: PASS.

---

### Task 8: Update Admin Feed UI And Noop Store

**Files:**
- Modify: `cmd/packmon-server/noop.go`
- Modify: `cmd/packmon-server/admin_pages_test.go`
- Modify: `cmd/packmon-server/feed_config_test.go`
- Modify: `internal/api/admin/runtime_config.go`
- Modify: `internal/web/templates/admin/feeds.html`
- Modify: `internal/api/admin/handler_test.go` if stubs require new methods

- [ ] **Step 1: Add noop store methods**

In `cmd/packmon-server/noop.go`, implement no-op or in-memory versions of:

```go
FindReputationFindingsBatch(context.Context, []db.PackageQuery, string) ([]domain.Finding, error)
MarkPackageReputationDue(context.Context, *db.PackageReputation) (bool, error)
ListDuePackageReputations(context.Context, string, string, string, int) ([]db.PackageReputation, error)
UpsertPackageReputation(context.Context, *db.PackageReputation) error
```

The noop store can return empty findings, `false` for queue-needed, empty due rows, and nil errors.

- [ ] **Step 2: Update admin feed tests**

Add `"ReversingLabs"` to the feed page expected strings in `cmd/packmon-server/admin_pages_test.go`.

Add feed config expectations in `cmd/packmon-server/feed_config_test.go`:

```go
rl, ok := cfg.FeedSettings("reversinglabs")
if !ok {
	t.Fatal("cfg.FeedSettings(reversinglabs) = !ok")
}
if rl.DisplayName != "ReversingLabs" || !rl.RequiresAPIKey || rl.SupportsSyncInterval {
	t.Fatalf("reversinglabs feed settings = %+v", rl)
}
```

- [ ] **Step 3: Hide invalid external mode for ReversingLabs**

Add a boolean to the admin feed row view model in `internal/api/admin/runtime_config.go`:

```go
SupportsExternalMode bool
```

Populate it as `feed.Name != "reversinglabs"` when building admin feed rows. In `internal/web/templates/admin/feeds.html`, render the `external` option only when the row supports it:

```html
<option value="self" {{if eq .Mode "self"}}selected{{end}}>self</option>
{{if .SupportsExternalMode}}
  <option value="external" {{if eq .Mode "external"}}selected{{end}}>external</option>
{{end}}
```

Add an assertion to `cmd/packmon-server/admin_pages_test.go` that the ReversingLabs feed row is present and does not render an `external` option for that row. Keep the server-side `SetFeedSettings` rejection from Task 2 as the authoritative guard.

- [ ] **Step 4: Run server/admin tests**

Run:

```powershell
go test -count=1 .\cmd\packmon-server .\internal\api\admin
```

Expected: PASS.

---

### Task 9: Update Output Handling For `supply_chain_risk`

**Files:**
- Modify: `internal/scanner/scanner.go` (blocking logic)
- Modify: `internal/scanner/table.go`
- Modify: `internal/scanner/sarif.go`
- Modify: `internal/scanner/junit.go`
- Test: `internal/scanner/table_test.go`
- Test: `internal/scanner/scanner_test.go`

- [ ] **Step 1: Add scanner blocking test**

In `internal/scanner/scanner_test.go`, add:

```go
func TestSupplyChainRiskBlocksEvenWithNoneThreshold(t *testing.T) {
	sc := New(nil, Config{FailOn: domain.SeverityNone})
	findings := []domain.Finding{
		{Type: domain.FindingTypeSupplyChainRisk, Severity: domain.SeverityCritical, Source: "reversinglabs"},
	}
	if !sc.hasBlockingFindings(findings) {
		t.Fatal("supply-chain risk findings must block regardless of vulnerability threshold")
	}
}
```

- [ ] **Step 1a: Make `supply_chain_risk` block in the scanner**

The CLI/local blocking logic lives in `hasBlockingFindings` at `internal/scanner/scanner.go` (around line 355) — NOT in the output renderers. Update it to treat `supply_chain_risk` exactly like `malicious` (always blocking, regardless of `FailOn`):

```go
if f.Type == domain.FindingTypeMalicious || f.Type == domain.FindingTypeSupplyChainRisk {
	return true
}
```

Without this change Step 1's test fails and `packmon scan` in local mode would not block on removed/malicious ReversingLabs findings.

- [ ] **Step 2: Display removed package risk distinctly**

In table/SARIF/JUnit rendering, keep the source as `reversinglabs` and render type `supply_chain_risk`. Do not change the title to say malware unless the finding type is `malicious`.

Expected user-facing title format:

```text
ReversingLabs: package version was removed
```

- [ ] **Step 3: Run scanner tests**

Run:

```powershell
go test -count=1 .\internal\scanner
```

Expected: PASS.

---

### Task 10: Update Documentation

**Files:**
- Modify: `DESIGN.md`
- Modify: `SECURITY.md`
- Modify: `README.md`

- [ ] **Step 1: Update `DESIGN.md`**

Add ReversingLabs to the feed source section as:

```markdown
- ReversingLabs Spectra Assure Community API as an optional demand-driven
  reputation source. The server stores normalized package reputation cache rows
  and refreshes a package version at most once per 24 hours when it appears in a
  check request and no non-ReversingLabs feed already covers it.
```

Document supported ecosystems and the status mapping:

```markdown
`malicious` produces a malware finding. `removed` produces a blocking
`supply_chain_risk` finding. `clean`, `not_found`, `unsupported`, and transient
errors do not produce findings.
```

- [ ] **Step 2: Update `SECURITY.md`**

Add:

```markdown
ReversingLabs API tokens are sensitive feed API keys. They must be stored and
logged under the same rules as VulnCheck, NVD, and Socket.dev keys. Packmon
stores normalized ReversingLabs status/evidence only and must not persist full
raw ReversingLabs reports unless the license terms are explicitly re-reviewed.
ReversingLabs rate-limit, capacity, and network failures degrade the feed but
must not fail scans or delete existing cached data.
```

- [ ] **Step 3: Update `README.md`**

Add Docker/env quick-start:

```markdown
PACKMON_FEED_REVERSINGLABS_ENABLED=false
PACKMON_FEED_REVERSINGLABS_MODE=self
PACKMON_REVERSINGLABS_API_KEY=
PACKMON_REVERSINGLABS_LOOKUP_TTL=24h
PACKMON_REVERSINGLABS_BATCH_SIZE=5
```

Explain that the feature is disabled by default and performs server-side lookups only.

- [ ] **Step 4: Run documentation sanity check**

Run:

```powershell
git diff --check
```

Expected: no whitespace errors. Existing CRLF warnings from unchanged files can be ignored if no new whitespace errors are reported.

---

### Task 11: Full Verification

**Files:**
- All files changed by previous tasks.

- [ ] **Step 1: Format**

Run:

```powershell
gofumpt -extra -w internal cmd
```

Expected: command exits 0. If `gofumpt` is missing, record that and run `gofmt -w` on changed Go files.

- [ ] **Step 2: Run focused package tests**

Run:

```powershell
go test -count=1 .\internal\config .\internal\api\v1 .\internal\feed\reversinglabs .\internal\db\sqlite .\internal\scanner .\cmd\packmon-server
```

Expected: PASS.

- [ ] **Step 3: Run broad tests**

Run:

```powershell
go test -count=1 ./...
```

Expected: PASS.

- [ ] **Step 4: Build binaries**

Run:

```powershell
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
```

Expected: both binaries build.

- [ ] **Step 5: Run tagged tests if infrastructure is available**

Run:

```powershell
$env:PACKMON_TEST_BIN_DIR = ".build"
go test -count=1 -tags integration .\tests\integration
go test -count=1 -tags e2e .\tests\e2e
```

Expected: PASS when local integration/E2E prerequisites are available.

- [ ] **Step 6: Clean build artifacts unless the user wants them kept**

Remove `.build` only after verification output has been recorded:

```powershell
Remove-Item -Recurse -Force .build
```

Expected: `.build` is absent.

---

## Self-Review Notes

- Spec coverage: The plan covers optional API use, internal storage, 24-hour demand-driven refresh, ReversingLabs-only server access, no direct CLI external access, `removed` as blocking supply-chain risk, and minimal normalized evidence persistence.
- Type consistency: `supply_chain_risk` is introduced in `domain.FindingType`, used in API blocking, exported to local sync, stored locally, and rendered as a finding type.
- Queue consistency: The existing `refresh_queue` remains package-wide. Version specificity lives in `package_reputation_cache`.
- Security consistency: Token handling follows existing feed key rules and avoids raw report persistence.
