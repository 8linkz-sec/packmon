package ci

import (
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
		"InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error",
	} {
		if strings.Contains(handlerText, forbidden) {
			t.Fatalf("internal/api/v1 Handler.Store still includes feed-import write dependency %q", forbidden)
		}
	}

	feedImportSource, err := os.ReadFile(filepath.Join(root, "internal", "api", "v1", "feed_import.go")) // #nosec G304 -- test reads fixed repository source.
	if err != nil {
		t.Fatalf("read feed import source: %v", err)
	}
	feedImportText := string(feedImportSource)
	for _, want := range []string{
		"type FeedImportStore interface",
		"func NewFeedImportHandler(store FeedImportStore",
		"func (h *FeedImportHandler) HandleImport",
	} {
		if !strings.Contains(feedImportText, want) {
			t.Fatalf("internal/api/v1 feed import component missing %q", want)
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
	runListAllStart := strings.Index(text, "func runListAll(")
	collectStart := strings.Index(text, "func collectAllPackages(")
	if runListAllStart < 0 || collectStart < 0 || collectStart <= runListAllStart {
		t.Fatalf("could not locate runListAll and collectAllPackages boundaries")
	}
	runListAllBody := text[runListAllStart:collectStart]
	if strings.Contains(runListAllBody, "collectAllPackagesWithWarnings(") {
		t.Fatal("runListAll still walks/parses packages a second time instead of reusing the scan pipeline collection")
	}
	if !strings.Contains(runListAllBody, "listAllPackagesFromCollection(") {
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
		"cmd/packmon/list_all.go": {
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

func TestIntegrationHarnessDoesNotPreProbeTCPPorts(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	checks := map[string][]string{
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
