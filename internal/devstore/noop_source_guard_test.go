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

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(info os.FileInfo) bool {
		return filepath.Ext(info.Name()) == ".go" && !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parser.ParseDir(.) error = %v", err)
	}

	pkg, ok := pkgs["devstore"]
	if !ok {
		t.Fatal("parser.ParseDir(.) did not find package devstore")
	}

	methods := make(map[string]string)
	for _, file := range pkg.Files {
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
