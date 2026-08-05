package devstore

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoopStoreConcernFilesOwnKeyMethods(t *testing.T) {
	t.Parallel()

	expectedFiles := []string{
		"noop_admin.go",
		"noop_feeds.go",
		"noop_findings.go",
		"noop_refresh_queue.go",
		"noop_scan_logs.go",
		"noop_sync.go",
	}
	for _, name := range expectedFiles {
		if _, err := os.Stat(filepath.Join(".", name)); err != nil {
			t.Errorf("expected noop concern file %s to exist: %v", name, err)
		}
	}

	methodFiles := noopStoreMethodFiles(t)
	for method, wantFile := range map[string]string{
		"FindVulnerabilities":             "noop_findings.go",
		"ImportMaliciousFeed":             "noop_findings.go",
		"ExportSync":                      "noop_sync.go",
		"GetFeedSyncStatus":               "noop_feeds.go",
		"UpsertFeedConfig":                "noop_feeds.go",
		"InsertScanLog":                   "noop_scan_logs.go",
		"DashboardStats":                  "noop_scan_logs.go",
		"CreateAPIKey":                    "noop_admin.go",
		"ChangeAdminPasswordWithAudit":    "noop_admin.go",
		"EnqueueRefresh":                  "noop_refresh_queue.go",
		"UpdateQueueJobPriorityWithAudit": "noop_refresh_queue.go",
	} {
		gotFile, ok := methodFiles[method]
		if !ok {
			t.Errorf("noopStore.%s method was not found", method)
			continue
		}
		if gotFile != wantFile {
			t.Errorf("noopStore.%s lives in %s, want %s", method, gotFile, wantFile)
		}
	}
}

func noopStoreMethodFiles(t *testing.T) map[string]string {
	t.Helper()

	// parser.ParseFile per entry rather than parser.ParseDir: ParseDir is
	// deprecated because it ignores build tags when grouping files into
	// packages. Walking the directory ourselves keeps the same result without
	// pulling in golang.org/x/tools just for a source-layout guard.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.) error = %v", err)
	}

	fset := token.NewFileSet()
	methods := make(map[string]string)
	parsedFiles := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", name, err)
		}
		if file.Name.Name != "devstore" {
			continue
		}
		parsedFiles++

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			if !noopStoreReceiver(fn.Recv.List[0].Type) {
				continue
			}
			methods[fn.Name.Name] = filepath.Base(fset.Position(fn.Pos()).Filename)
		}
	}

	// Guard against an empty harvest passing silently, which would make every
	// method-location assertion below vacuous.
	if parsedFiles == 0 {
		t.Fatal("no devstore source files were parsed")
	}
	return methods
}

func noopStoreReceiver(expr ast.Expr) bool {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name == "Store"
	case *ast.StarExpr:
		ident, ok := value.X.(*ast.Ident)
		return ok && ident.Name == "Store"
	default:
		return false
	}
}
