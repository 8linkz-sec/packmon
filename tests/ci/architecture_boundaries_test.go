package ci

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAPIProductionCodeDoesNotImportServerMiddleware(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	apiRoot := filepath.Join(root, "internal", "api")
	err := filepath.WalkDir(apiRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if value == "github.com/8linkz-sec/packmon/internal/server/middleware" {
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					rel = path
				}
				t.Fatalf("%s imports server middleware; use a neutral request context package", filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk api source: %v", err)
	}
}

func TestAPIV1HandlerTestsDoNotImportServerMiddleware(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	apiRoot := filepath.Join(root, "internal", "api", "v1")
	err := filepath.WalkDir(apiRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		base := filepath.Base(path)
		if d.IsDir() || !strings.HasPrefix(base, "handler") || !strings.HasSuffix(base, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if value == "github.com/8linkz-sec/packmon/internal/server/middleware" {
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					rel = path
				}
				t.Fatalf("%s imports server middleware; use requestctx or local test helpers", filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk api v1 handler tests: %v", err)
	}
}

func TestGoModulePathMatchesCanonicalRepositoryNamespace(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	canonicalModule := "github.com/8linkz-sec/packmon"
	oldModule := "github.com/8linkz" + "/packmon"
	modulePath := "module " + canonicalModule
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- test reads a fixed repository fixture path.
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if !strings.Contains(string(goMod), modulePath+"\n") && !strings.Contains(string(goMod), modulePath+"\r\n") {
		t.Fatalf("go.mod must declare %q", modulePath)
	}

	cmd := exec.Command("git", "ls-files", "--", "*.go")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files *.go: %v", err)
	}
	for _, rel := range strings.Fields(string(out)) {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- rel comes from git ls-files for tracked Go files.
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			t.Fatalf("read %s: %v", rel, err)
		}
		if strings.Contains(string(data), oldModule) {
			t.Fatalf("%s still references old Go module namespace %s", rel, oldModule)
		}
	}
}

func TestAPIV1HandlerUsesConsumerOwnedStoreInterface(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "api", "v1", "handler.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"store                db.Store",
		"func NewHandler(store db.Store",
		"func NewHandlerWithConfig(store db.Store",
		"func NewHandlerWithRuntime(store db.Store",
		"func NewHandlerWithBlockThreshold(store db.Store",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("internal/api/v1 handler still accepts monolithic db.Store via %q", forbidden)
		}
	}
}

func TestAPIV1ReputationSchedulerIsInjected(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "api", "v1", "handler.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		`"github.com/8linkz-sec/packmon/internal/feed/reputation"`,
		"reputation.NewScheduler",
		"reputation.Store",
		"MarkPackageReputationDue(ctx context.Context",
		"UpsertPackageReputation(ctx context.Context",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("internal/api/v1 handler still owns feed reputation scheduler wiring via %q", forbidden)
		}
	}
	for _, want := range []string{
		"type ReputationScheduler interface",
		"func (h *Handler) ConfigureReputationScheduler(scheduler ReputationScheduler)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("internal/api/v1 handler missing injected reputation scheduler boundary %q", want)
		}
	}
}

func TestAPIV1PackageRefreshProviderIsInjected(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "api", "v1", "handler.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		`"github.com/8linkz-sec/packmon/internal/feed/socket"`,
		"socket.SupportsEcosystem",
		"socket.FeedName",
		"socketRefreshEnabled",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("internal/api/v1 handler still owns Socket.dev refresh wiring via %q", forbidden)
		}
	}
	for _, want := range []string{
		"type PackageRefreshProvider interface",
		"func (h *Handler) ConfigurePackageRefreshProvider(provider PackageRefreshProvider)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("internal/api/v1 handler missing injected package refresh boundary %q", want)
		}
	}
}

func TestAPIV1ReversingLabsConfigDoesNotConfigureSocketRefresh(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "api", "v1", "handler.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	text := string(source)
	body := mustFindFunctionBody(t, text, "func (h *Handler) ConfigureReversingLabs")
	for _, forbidden := range []string{
		"SocketEnabled",
		"SocketMode",
		"SocketAPIKey",
		"SocketExcludedNamespaces",
		"PackageRefreshProviderConfig",
		"packageRefresh.Configure",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("ConfigureReversingLabs still configures Socket.dev refresh via %q", forbidden)
		}
	}
	if !strings.Contains(text, "func (h *Handler) ConfigureSocketRefresh(feeds config.FeedsConfig)") {
		t.Fatal("internal/api/v1 handler missing dedicated Socket.dev refresh configuration hook")
	}
}

func TestAPIV1ScanPortsUseAPIPackageLookups(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "api", "v1", "handler.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"db.PackageQuery",
		"db.ReputationSourceReversingLabs",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("internal/api/v1 handler still exposes database scan DTO/constant via %q", forbidden)
		}
	}
	for _, want := range []string{
		"type PackageLookup struct",
		"FindVulnerabilitiesBatch(ctx context.Context, packages []PackageLookup)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("internal/api/v1 handler missing API-owned scan lookup marker %q", want)
		}
	}
}

func TestAPIV1IdempotencyLookupIsExplicitStoreContract(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "api", "v1", "handler.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"type scanLogIdempotencyLookup interface",
		"store.(scanLogIdempotencyLookup)",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("internal/api/v1 idempotency lookup still hidden behind optional assertion %q", forbidden)
		}
	}
	if !strings.Contains(text, "GetScanLogByIdempotencyKey(ctx context.Context, key string) (*db.ScanLogEntry, error)") {
		t.Fatal("internal/api/v1 Store missing explicit idempotency lookup contract")
	}
}

func TestAPIV1SyncExportIsExplicitStoreContract(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "api", "v1", "handler.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"type syncExporter interface",
		"store.(syncExporter)",
		"sync endpoint is not supported by this store",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("internal/api/v1 sync export still hidden behind optional assertion %q", forbidden)
		}
	}
	if !strings.Contains(text, "ExportSync(ctx context.Context, opts db.SyncExportOptions) (*db.SyncExport, error)") {
		t.Fatal("internal/api/v1 Store missing explicit sync export contract")
	}
}

func TestAPIV1SyncExportImplementationLivesOutsideGeneralHandler(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	handlerSource, err := os.ReadFile(filepath.Join(root, "internal", "api", "v1", "handler.go")) // #nosec G304 -- test reads fixed repository source.
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	handlerText := string(handlerSource)
	for _, forbidden := range []string{
		"func parseSyncExportOptions(",
		"func parseSyncCursor(",
		"func (h *Handler) HandleSync(",
		"func syncResponseFromExport(",
		"func syncVulnerabilityResponses(",
		"func syncExportAuditDetails(",
	} {
		if strings.Contains(handlerText, forbidden) {
			t.Fatalf("general API v1 handler still contains sync-export implementation marker %q", forbidden)
		}
	}

	syncText, err := readAPIV1SyncSource(root)
	if err != nil {
		t.Fatalf("read sync export source: %v", err)
	}
	for _, want := range []string{
		"func parseSyncExportOptions(",
		"func parseSyncCursor(",
		"func (h *Handler) HandleSync(",
		"func syncResponseFromExport(",
		"func syncVulnerabilityResponses(",
		"func syncExportAuditDetails(",
	} {
		if !strings.Contains(syncText, want) {
			t.Fatalf("sync export component missing marker %q", want)
		}
	}
}

func TestScannerLocalCheckerPortsUseScannerPackageLookups(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "scanner", "scanner.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read scanner source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"internal/db",
		"db.PackageQuery",
		"db.ReputationSourceReversingLabs",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("internal/scanner scanner ports still expose database DTO/constant via %q", forbidden)
		}
	}
	for _, want := range []string{
		"type PackageLookup struct",
		"FindVulnerabilitiesBatch(ctx context.Context, packages []PackageLookup)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("internal/scanner missing scanner-owned local lookup marker %q", want)
		}
	}
}

func TestAPIV1FeedImportUsesDedicatedWriteStore(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	handlerSource, err := os.ReadFile(filepath.Join(root, "internal", "api", "v1", "handler.go")) // #nosec G304 -- test reads fixed repository source.
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	handlerText := string(handlerSource)
	for _, forbidden := range []string{
		"UpsertVulnerability(ctx context.Context, vuln *db.Vulnerability) error",
		"DeleteVulnerability(ctx context.Context, id string) error",
		"UpsertMaliciousFinding(ctx context.Context, finding *db.MaliciousFinding) error",
		"DeleteMaliciousFinding(ctx context.Context, id string) error",
		"EnrichVulnCheck(ctx context.Context, entries []db.VulnCheckEntry) (int, error)",
		"SetCISAKEV(ctx context.Context, cveIDs []string) (int, error)",
		"ClearCISAKEV(ctx context.Context, cveIDs []string) (int, error)",
		"ReplaceEPSSScores(ctx context.Context, entries []db.EPSSEntry) (int, int, error)",
		"UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error",
	} {
		if strings.Contains(handlerText, forbidden) {
			t.Fatalf("internal/api/v1 Handler.Store still includes feed-import write dependency %q", forbidden)
		}
	}

	feedImportText, err := readAPIV1FeedImportSource(root)
	if err != nil {
		t.Fatalf("read feed import source: %v", err)
	}
	for _, want := range []string{
		"type FeedImportStore interface",
		"func NewFeedImportHandler(store FeedImportStore",
		"func (h *FeedImportHandler) HandleImport",
		"ImportVulnerabilityFeedWithAudit(ctx context.Context",
		"ImportMaliciousFeedWithAudit(ctx context.Context",
		"ImportVulnCheckWithAudit(ctx context.Context",
		"ImportCISAKEVWithAudit(ctx context.Context",
		"ImportEPSSWithAudit(ctx context.Context",
	} {
		if !strings.Contains(feedImportText, want) {
			t.Fatalf("internal/api/v1 feed import component missing %q", want)
		}
	}
}

func TestAPIV1FeedImportVulnerabilityAndMaliciousAuditsAreAtomic(t *testing.T) {
	t.Parallel()

	feedImportText, err := readAPIV1FeedImportSource(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("read feed import source: %v", err)
	}
	for _, forbidden := range []string{
		"type vulnerabilityFeedImporter interface",
		"type maliciousFeedImporter interface",
		"atomicImport  func(",
		"if opts.auditedImport != nil",
		"ImportVulnerabilityFeed(ctx context.Context, feed string",
		"ImportMaliciousFeed(ctx context.Context, feed string",
		"store.(auditedVulnerabilityFeedImporter)",
		"store.(auditedMaliciousFeedImporter)",
	} {
		if strings.Contains(feedImportText, forbidden) {
			t.Fatalf("feed import component still allows split-write or optional audit fallback via %q", forbidden)
		}
	}
	for _, want := range []string{
		"ImportVulnerabilityFeedWithAudit(ctx context.Context",
		"ImportMaliciousFeedWithAudit(ctx context.Context",
		"ImportVulnCheckWithAudit(ctx context.Context",
		"ImportCISAKEVWithAudit(ctx context.Context",
		"ImportEPSSWithAudit(ctx context.Context",
		"auditedImport: h.store.ImportVulnerabilityFeedWithAudit",
		"auditedImport: h.store.ImportMaliciousFeedWithAudit",
		"resp.AuditRecorded = true",
	} {
		if !strings.Contains(feedImportText, want) {
			t.Fatalf("feed import component missing atomic audited import marker %q", want)
		}
	}
}

func TestAPIV1FeedImportEnrichmentAuditsAreAtomic(t *testing.T) {
	t.Parallel()

	feedImportText, err := readAPIV1FeedImportSource(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("read feed import source: %v", err)
	}
	for _, forbidden := range []string{
		"h.store.EnrichVulnCheck(ctx, entries)",
		"h.store.SetCISAKEV(ctx, cveIDs)",
		"h.store.ClearCISAKEV(ctx, cveIDs)",
		"h.store.ReplaceEPSSScores(ctx, entries)",
		"h.applyImportStatus(ctx, feed, req.Status",
	} {
		if strings.Contains(feedImportText, forbidden) {
			t.Fatalf("feed import enrichment path still uses split-write marker %q", forbidden)
		}
	}
	for _, want := range []string{
		"h.store.ImportVulnCheckWithAudit(ctx, feed, entries, status, audit)",
		"h.store.ImportCISAKEVWithAudit(ctx, feed, cveIDs, status, audit)",
		"h.store.ReplaceCISAKEVWithAudit(ctx, feed, cveIDs, status, audit)",
		"h.store.ImportEPSSWithAudit(ctx, feed, entries, status, audit)",
		"AuditRecorded: true",
	} {
		if !strings.Contains(feedImportText, want) {
			t.Fatalf("feed import enrichment path missing atomic audit marker %q", want)
		}
	}
}

func TestAPIV1FeedImportRequestBodiesUseAPILocalDTOs(t *testing.T) {
	t.Parallel()

	text, err := readAPIV1FeedImportSource(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("read feed import source: %v", err)
	}
	start := strings.Index(text, "type vulnerabilityImportRequest struct")
	end := strings.Index(text, "type cisaKEVImportRequest struct")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("could not locate feed import request DTO block")
	}
	requestDTOBlock := text[start:end]
	for _, forbidden := range []string{
		"[]db.Vulnerability",
		"[]db.MaliciousFinding",
		"[]db.EPSSEntry",
		"[]db.VulnCheckEntry",
	} {
		if strings.Contains(requestDTOBlock, forbidden) {
			t.Fatalf("feed import request DTO block still decodes API bodies into persistence type %q", forbidden)
		}
	}
}

func TestAPIV1FeedImportKnownFeedsUseCapabilityDescriptors(t *testing.T) {
	t.Parallel()

	text, err := readAPIV1FeedImportSource(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("read feed import source: %v", err)
	}
	for _, forbidden := range []string{
		"func is" + "KnownFeed(",
		"feedImportDispatch" + "Table = map[string]feedImportDispatch{",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("feed import runtime still has a separate known-feed allowlist marker %q", forbidden)
		}
	}
	for _, want := range []string{
		"feedImportCapabilitiesByName",
		"config.FeedSupportsExternalMode",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("feed import runtime does not derive known feeds from capability metadata marker %q", want)
		}
	}
}

func TestAPIV1FeedImportImplementationLivesOutsideGeneralHandler(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	handlerSource, err := os.ReadFile(filepath.Join(root, "internal", "api", "v1", "handler.go")) // #nosec G304 -- test reads fixed repository source.
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	handlerText := string(handlerSource)
	for _, forbidden := range []string{
		"type vulnerabilityImportRequest struct",
		"type feedSyncStatusInput struct",
		"func (h *FeedImportHandler) importVulnerabilities",
		"func normalizeImportedVulnerability",
		"func validateImportStatusInput",
		"func (h *FeedImportHandler) recordFeedImportAudit",
	} {
		if strings.Contains(handlerText, forbidden) {
			t.Fatalf("general API v1 handler still contains feed-import implementation marker %q", forbidden)
		}
	}

	feedImportText, err := readAPIV1FeedImportSource(root)
	if err != nil {
		t.Fatalf("read feed import source: %v", err)
	}
	for _, want := range []string{
		"type vulnerabilityImportRequest struct",
		"func (h *FeedImportHandler) importVulnerabilities",
		"func normalizeImportedVulnerability",
		"func validateImportStatusInput",
		"func (h *FeedImportHandler) recordFeedImportAudit",
	} {
		if !strings.Contains(feedImportText, want) {
			t.Fatalf("feed import implementation missing marker %q", want)
		}
	}
}

func TestServerRoutesUseDedicatedFeedImportHandler(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "server", "routes.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read routes source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"NewFeedImportHandlerWithConfig",
		"api.ConfigureFeedImportSecret(",
		`api.HandleFeedImport`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("server routes still wire feed import through the legacy API handler facade via %q", forbidden)
		}
	}
	for _, want := range []string{
		"v1.NewFeedImportHandler(",
		"feedImport.ConfigureFeedImportSecret(",
		`mux.HandleFunc("/api/v1/feeds/{feed}/import", feedImport.HandleImport)`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("server routes missing dedicated feed-import wiring marker %q", want)
		}
	}
}

func readAPIV1FeedImportSource(root string) (string, error) {
	var b strings.Builder
	for _, name := range []string{"feed_import.go", "feed_import_model.go"} {
		source, err := os.ReadFile(filepath.Join(root, "internal", "api", "v1", name)) // #nosec G304 -- test reads fixed repository source from a static allowlist.
		if err != nil {
			return "", err
		}
		b.Write(source)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func readAPIV1SyncSource(root string) (string, error) {
	entries, err := os.ReadDir(filepath.Join(root, "internal", "api", "v1"))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "sync") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(filepath.Join(root, "internal", "api", "v1", name)) // #nosec G304 -- test reads fixed repository source from a sync*.go allowlist.
		if err != nil {
			return "", err
		}
		b.Write(source)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func mustFindFunctionBody(t *testing.T, source, signature string) string {
	t.Helper()
	start := strings.Index(source, signature)
	if start < 0 {
		t.Fatalf("missing function signature %q", signature)
	}
	open := strings.Index(source[start:], "{")
	if open < 0 {
		t.Fatalf("missing function body for %q", signature)
	}
	bodyStart := start + open
	depth := 0
	for i := bodyStart; i < len(source); i++ {
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[bodyStart : i+1]
			}
		}
	}
	t.Fatalf("unterminated function body for %q", signature)
	return ""
}

func TestGitFeedSyncersUseSyncStoreOnly(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	for _, rel := range []string{
		"internal/feed/osv/syncer.go",
		"internal/feed/ghsa/syncer.go",
		"internal/feed/malicious/syncer.go",
	} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		source, err := os.ReadFile(path) // #nosec G304 -- test reads fixed repository source from a static allowlist.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(source)
		for _, forbidden := range []string{
			"store  db.Store\n",
			"store   db.Store\n",
			"func NewSyncer(store db.Store",
			"s.store",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s still carries an independent syncer store via %q", rel, forbidden)
			}
		}
	}

	background, err := os.ReadFile(filepath.Join(root, "cmd", "packmon-server", "background.go")) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read background source: %v", err)
	}
	for _, forbidden := range []string{
		"osv.NewSyncer(store",
		"ghsa.NewSyncer(store",
		"malicious.NewSyncer(store",
	} {
		if strings.Contains(string(background), forbidden) {
			t.Fatalf("packmon-server background still passes store into feed syncer constructor via %q", forbidden)
		}
	}
}

func TestReversingLabsWorkerUsesConsumerOwnedStoreInterface(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "feed", "reversinglabs", "worker.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read reversinglabs worker source: %v", err)
	}
	text := string(source)
	if !strings.Contains(text, "type reputationStore interface") {
		t.Fatal("reversinglabs worker must keep a narrow reputationStore interface")
	}
	for _, forbidden := range []string{
		"func NewWorker(store db.Store",
		"func newWorker(store db.Store",
		"store db.Store",
		"store       db.Store",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("reversinglabs worker still accepts monolithic db.Store via %q", forbidden)
		}
	}
}

func TestReversingLabsPURLHelperUsesNeutralPackage(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	for _, rel := range []string{
		"internal/feed/reversinglabs/purl.go",
		"internal/feed/reputation/scheduler.go",
	} {
		source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- test reads fixed repository source from a static allowlist.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(source)
		if strings.Contains(text, "internal/feed/reputation/purl") {
			t.Fatalf("%s still imports scheduler-owned reputation purl helper", rel)
		}
		if !strings.Contains(text, "internal/feed/reputationpurl") {
			t.Fatalf("%s does not import neutral reputationpurl helper", rel)
		}
	}
}

func TestListAllReusesScanPipelinePackageCollection(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "cmd", "packmon", "list_all.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads fixed repository source.
	if err != nil {
		t.Fatalf("read list-all source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"func collectAllPackages(",
		"func collectAllPackagesWithWarnings(",
		"collectAllPackagesWithWarnings(",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("list-all still contains legacy package collection helper %q", forbidden)
		}
	}
	if !strings.Contains(text, "runScanPipeline(ctx, scanSettings)") {
		t.Fatal("list-all scan phase does not reuse the scan pipeline")
	}
	if !strings.Contains(text, "listAllPackagesFromCollection(collection)") {
		t.Fatal("runListAll does not convert the scan pipeline PackageCollection into list-all inventory rows")
	}
}

func TestCLILocalDBCommandsDoNotQuerySQLiteSchema(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "cmd", "packmon", "local_db.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read local_db.go: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"store.DB()",
		"FROM vulnerabilities_local",
		"FROM malicious_local",
		"FROM reputation_findings_local",
		"FROM lifecycle_releases_local",
		"FROM scan_history",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("cmd/packmon/local_db.go still depends on SQLite schema marker %q; move local DB queries behind internal/db/sqlite APIs", forbidden)
		}
	}
}

func TestAdminHandlerUsesConsumerOwnedStoreInterface(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	checks := map[string][]string{
		"internal/api/admin/handler.go": {
			"store           db.Store",
			"func NewAdminHandler(ctx context.Context, store db.Store",
		},
		"internal/api/admin/routes.go": {
			"func RegisterRoutes(ctx context.Context, mux *http.ServeMux, store db.Store",
		},
	}
	for rel, forbidden := range checks {
		path := filepath.Join(root, filepath.FromSlash(rel))
		source, err := os.ReadFile(path) // #nosec G304 -- test reads fixed repository source from a static allowlist.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(source)
		for _, marker := range forbidden {
			if strings.Contains(text, marker) {
				t.Fatalf("%s still accepts monolithic db.Store via %q", rel, marker)
			}
		}
	}
}

func TestAdminAuditedMutationsAreExplicitStoreContract(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	handlerSource, err := os.ReadFile(filepath.Join(root, "internal", "api", "admin", "handler.go")) // #nosec G304 -- test reads fixed repository source.
	if err != nil {
		t.Fatalf("read admin handler source: %v", err)
	}
	handlerText := string(handlerSource)
	for _, want := range []string{
		"type AdminMutationStore interface",
		"AdminMutationStore",
		"CreateAPIKeyWithAudit(ctx context.Context",
		"UpsertSystemSettingsWithAudit(ctx context.Context",
		"ClearQueueWithAudit(ctx context.Context",
	} {
		if !strings.Contains(handlerText, want) {
			t.Fatalf("admin Store missing explicit audited mutation contract marker %q", want)
		}
	}

	pagesSource, err := os.ReadFile(filepath.Join(root, "internal", "api", "admin", "pages.go")) // #nosec G304 -- test reads fixed repository source.
	if err != nil {
		t.Fatalf("read admin pages source: %v", err)
	}
	pagesText := string(pagesSource)
	for _, forbidden := range []string{
		"type audited",
		"h.store.(audited",
		"writeAdminAuditLog(audit)",
	} {
		if strings.Contains(pagesText, forbidden) {
			t.Fatalf("admin audited mutation path still uses optional split-write marker %q", forbidden)
		}
	}

	settingsSource, err := os.ReadFile(filepath.Join(root, "internal", "api", "admin", "settings_forms.go")) // #nosec G304 -- test reads fixed repository source.
	if err != nil {
		t.Fatalf("read admin settings source: %v", err)
	}
	settingsText := string(settingsSource)
	for _, forbidden := range []string{
		`h.auditLog(r, "system_settings_save"`,
		"h.store.UpsertSystemSettings(r.Context(), settings)",
	} {
		if strings.Contains(settingsText, forbidden) {
			t.Fatalf("admin system settings mutation still uses split-write marker %q", forbidden)
		}
	}
	if !strings.Contains(settingsText, "h.store.UpsertSystemSettingsWithAudit") {
		t.Fatal("admin system settings mutation does not use audited store mutation")
	}
}

func TestAuthMiddlewareUsesConsumerOwnedStoreInterface(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "server", "middleware", "auth.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read auth source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"store db.Store",
		"store       db.Store",
		"func Auth(ctx context.Context, logger *slog.Logger, store db.Store",
		"func AuthWithLastUsedUpdater(logger *slog.Logger, store db.Store",
		"func NewAPIKeyLastUsedUpdater(ctx context.Context, logger *slog.Logger, store db.Store",
		"func newAPIKeyLastUsedUpdater(ctx context.Context, logger *slog.Logger, store db.Store",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("auth middleware still accepts monolithic db.Store via %q", forbidden)
		}
	}
}

func TestAuthMiddlewareUsesCredentialViewNotDatabaseAPIKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "server", "middleware", "auth.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read auth source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		`"github.com/8linkz-sec/packmon/internal/db"`,
		"*db.APIKey",
		"FindAPIKeyByHash(ctx context.Context, keyHash string) (*db.APIKey, error)",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("auth middleware still exposes database API-key credential via %q", forbidden)
		}
	}
	if !strings.Contains(text, "FindAPIKeyCredentialByHash(ctx context.Context, keyHash string) (*auth.APIKeyCredential, error)") {
		t.Fatal("auth middleware lookup port must consume the neutral API-key credential view")
	}
}

func TestCLIProductionCodeDoesNotImportServerMiddleware(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	cmdRoot := filepath.Join(root, "cmd", "packmon")
	err := filepath.WalkDir(cmdRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if value == "github.com/8linkz-sec/packmon/internal/server/middleware" {
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					rel = path
				}
				t.Fatalf("%s imports server middleware; use neutral shared HTTP packages", filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk cmd/packmon source: %v", err)
	}
}

func TestReusableSecurityHeadersLiveOutsideServerMiddleware(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "server", "middleware", "securityheaders.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("read securityheaders source: %v", err)
	}
	if strings.Contains(string(source), "func SecurityHeaders(") {
		t.Fatal("reusable SecurityHeaders must live in a neutral shared package, not server middleware")
	}
}

func TestAdminAuthBootstrapUsesConsumerOwnedStoreInterface(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "auth", "auth.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read auth bootstrap source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"store db.Store",
		"func BootstrapAdmin(ctx context.Context, store db.Store",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("admin auth bootstrap still accepts monolithic db.Store via %q", forbidden)
		}
	}
}

func TestMiddlewareDoesNotExposeProductionDeadConvenienceWrappers(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	checks := map[string]string{
		"internal/server/middleware/clientip.go":  "func ClientIPWithTrustedProxies",
		"internal/server/middleware/ratelimit.go": "func RateLimit(ctx context.Context",
	}
	for rel, forbidden := range checks {
		path := filepath.Join(root, filepath.FromSlash(rel))
		source, err := os.ReadFile(path) // #nosec G304 -- test reads fixed repository source from a static allowlist.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("%s exposes production-dead middleware wrapper %q", rel, forbidden)
		}
	}
}

func TestProductionPackagesDoNotExposeTestOnlyDeadCodeWrappers(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	checks := map[string][]string{
		"cmd/packmon/outdated.go": {
			"func runOutdated(",
		},
		"cmd/packmon/list_all.go": {
			"func listAllFindingBlocks(",
		},
		"internal/version/compare.go": {
			"func SplitPrerelease(",
			"func ComparePrerelease(",
			"func IsNumeric(",
			"func ParseLeadingInt(",
		},
		"internal/db/postgres/versioning.go": {
			"func versionAffected(",
			"func compareVersions(",
			"func splitPrerelease(",
			"func versionInRange(",
			"func comparePrerelease(",
			"func isNumeric(",
			"func parseVersionSegment(",
		},
		"internal/api/v1/handler.go": {
			"func NewHandler(store Store,",
			"func NewHandlerWithConfig(",
			"func (h *Handler) HandleRefresh(",
		},
		"internal/sbom/cyclonedx.go": {
			"func ParseCycloneDX(",
		},
		"internal/sbom/spdx.go": {
			"func ParseSPDXJSON(",
		},
		"internal/parser/parser.go": {
			"func (r *Registry) Register(",
			"func (r *Registry) AllParsers(",
			"func (r *Registry) SupportedFiles(",
		},
		"internal/feed/ghsa/syncer.go": {
			"func (s *Syncer) recordSyncSuccessWithCommit(ctx context.Context, start time.Time,",
		},
		"internal/feed/malicious/syncer.go": {
			"func (s *Syncer) recordSyncSuccessWithCommit(ctx context.Context, start time.Time,",
		},
		"internal/feed/osv/syncer.go": {
			"func (s *Syncer) recordSyncSuccess(ctx context.Context, start time.Time,",
		},
		"internal/web/feeds.go": {
			"func feedHealthStatus(",
		},
	}

	for rel, forbiddenMarkers := range checks {
		path := filepath.Join(root, filepath.FromSlash(rel))
		source, err := os.ReadFile(path) // #nosec G304 -- test reads fixed repository source from a static allowlist.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(source)
		for _, marker := range forbiddenMarkers {
			if strings.Contains(text, marker) {
				t.Fatalf("%s still exposes test-only/dead-code wrapper %q", rel, marker)
			}
		}
	}
}

func TestDockerLocalInspectorUsesFixedExecutableBoundary(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "dockerimage", "local.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read docker local inspector source: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"Run(ctx context.Context, name string",
		"exec.CommandContext(ctx, name",
		"runner.Run(ctx, \"docker\"",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("docker local inspector still exposes arbitrary command execution via %q", forbidden)
		}
	}
}

func TestListAllBatchesDockerLocalInspection(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "cmd", "packmon", "list_all.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read list-all source: %v", err)
	}
	text := string(source)
	if !strings.Contains(text, "inspectLocalDockerDigestsFn(ctx, packages)") {
		t.Fatal("list-all package report does not precompute local Docker digests for the report package set")
	}
	for _, forbidden := range []string{
		"return resolveListAllLatestWithLookup(ctx, p, lookup)\n",
		"return resolveDockerImageStatusFn(ctx, p)\n",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("list-all still resolves Docker status through the unbatched path %q", forbidden)
		}
	}
}

func TestReportWritersUsePrivateOutputHelper(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	checks := map[string][]string{
		"cmd/packmon/scan.go": {
			"os.WriteFile(path, data, 0o600)",
		},
		"cmd/packmon/list_all_html.go": {
			"os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)",
		},
		"cmd/packmon/outdated.go": {
			"os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)",
		},
		"internal/scanner/html.go": {
			"os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)",
		},
		"internal/scanner/junit.go": {
			"os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)",
		},
		"internal/scanner/sarif.go": {
			"os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)",
		},
	}

	for rel, forbiddenMarkers := range checks {
		path := filepath.Join(root, filepath.FromSlash(rel))
		source, err := os.ReadFile(path) // #nosec G304 -- test reads fixed repository source from a static allowlist.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(source)
		if !strings.Contains(text, "ioutils.OpenPrivateFile") {
			t.Fatalf("%s does not use ioutils.OpenPrivateFile for report output", rel)
		}
		for _, marker := range forbiddenMarkers {
			if strings.Contains(text, marker) {
				t.Fatalf("%s still writes private reports through direct helper %q", rel, marker)
			}
		}
	}
}

func TestPostgresStoreDoesNotImportAdminAuthForFieldEncryption(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "db", "postgres", "store.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read postgres store source: %v", err)
	}
	if strings.Contains(string(source), `"github.com/8linkz-sec/packmon/internal/auth"`) {
		t.Fatal("postgres store still imports internal/auth for field encryption")
	}
}

func TestConfigDoesNotImportAuthForSessionDefaults(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "internal", "config", "config.go")
	source, err := os.ReadFile(path) // #nosec G304 -- test reads a fixed repository source path.
	if err != nil {
		t.Fatalf("read config source: %v", err)
	}
	text := string(source)
	if strings.Contains(text, `"github.com/8linkz-sec/packmon/internal/auth"`) ||
		strings.Contains(text, "auth.DefaultAdminIdleTimeout") {
		t.Fatal("config still imports auth for the admin idle timeout default")
	}
	if !strings.Contains(text, "DefaultAdminIdleTimeout = 15 * time.Minute") {
		t.Fatal("config must own the default admin idle timeout value")
	}
}

func TestIntegrationHarnessDoesNotPreProbeTCPPorts(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	checks := map[string][]string{
		"cmd/packmon-server/main_entry_test.go": {
			"func freeTCPPort(",
			`net.Listen("tcp", "127.0.0.1:0")`,
			"serverPort := freeTCPPort(t)",
			"metricsPort := freeTCPPort(t)",
		},
		"tests/integration/server_test.go": {
			"func freePort(",
			`net.Listen("tcp", "127.0.0.1:0")`,
		},
		"tests/integration/production_test.go": {
			"freePort(t)",
			`"-p", fmt.Sprintf("%d:5432", dbPort)`,
		},
		"tests/integration/store_test.go": {
			"freePort(t)",
			`"-p", fmt.Sprintf("%d:5432", dbPort)`,
		},
		"internal/db/postgres/migrations/migrator_docker_test.go": {
			"func freeMigrationTestPort(",
			`net.Listen("tcp", "127.0.0.1:0")`,
			`"-p", fmt.Sprintf("%d:5432", port)`,
		},
		"internal/db/postgres/store_docker_test.go": {
			"func freePostgresTestPort(",
			`net.Listen("tcp", "127.0.0.1:0")`,
			`"-p", fmt.Sprintf("%d:5432", port)`,
		},
	}

	for rel, forbiddenMarkers := range checks {
		path := filepath.Join(root, filepath.FromSlash(rel))
		source, err := os.ReadFile(path) // #nosec G304 -- test reads fixed repository test source from a static allowlist.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(source)
		for _, marker := range forbiddenMarkers {
			if strings.Contains(text, marker) {
				t.Fatalf("%s still pre-probes TCP ports via %q", rel, marker)
			}
		}
	}
}

func TestHTTPRuntimeFeedConfigReadsUseSnapshots(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	for _, rel := range []string{
		"internal/server/routes.go",
		"internal/api/v1/handler.go",
	} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		source, err := os.ReadFile(path) // #nosec G304 -- test reads fixed repository source from a static allowlist.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if strings.Contains(string(source), "cfg.Feeds.") {
			t.Fatalf("%s reads mutable cfg.Feeds directly; use cfg.FeedsSnapshot() before configuring runtime handlers", rel)
		}
	}
}

func TestBlackBoxPackmonTestsUseHermeticEnvironment(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	checks := []struct {
		rel       string
		forbidden []string
	}{
		{
			rel: "tests/e2e/cli_smoke_test.go",
			forbidden: []string{
				"exec.Command(packmonBinary(t)",
				"exec.Command(bin,",
			},
		},
		{
			rel: "tests/integration/scan_test.go",
			forbidden: []string{
				`"HOME=" + os.Getenv("HOME")`,
				`"USERPROFILE=" + os.Getenv("USERPROFILE")`,
			},
		},
	}
	for _, check := range checks {
		path := filepath.Join(root, filepath.FromSlash(check.rel))
		data, err := os.ReadFile(path) // #nosec G304 -- test reads fixed repository test files from a static allowlist.
		if err != nil {
			t.Fatalf("read %s: %v", check.rel, err)
		}
		text := string(data)
		for _, forbidden := range check.forbidden {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains non-hermetic black-box test command/env marker %q", check.rel, forbidden)
			}
		}
	}
}
